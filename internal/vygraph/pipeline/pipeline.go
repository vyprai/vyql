// Package pipeline is the v3 engine's one internal entry point: a source tree
// plus a v3 knowledge-base directory in, findings and signals out. It wires
// every stage — the four reference frontends and the generic document parser
// into one store, the shared lowering, then lifts, relates, adapters, compile,
// and evaluation by the real solvers. Nothing here is shipped surface; it is
// the library the replay harness (and later the additive CLI output) calls.
package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/vygraph/doc"
	"github.com/vyprai/vyql/internal/vygraph/domains"
	fegolang "github.com/vyprai/vyql/internal/vygraph/frontend/golang"
	fejava "github.com/vyprai/vyql/internal/vygraph/frontend/java"
	fejs "github.com/vyprai/vyql/internal/vygraph/frontend/javascript"
	fepython "github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/lower"
	"github.com/vyprai/vyql/internal/vygraph/solvers/taint"
	"github.com/vyprai/vyql/internal/vygraph/vyql"
)

// Options bound the walk for very large trees.
type Options struct {
	// MaxFilesPerLanguage caps extraction per language (0 = unlimited). The
	// replay driver leaves it unset; the deviation corpus runs set it.
	MaxFilesPerLanguage int
	// MaxJSONBytes skips config JSON above this size (package manifests are
	// data, not contracts). 0 = a 1 MiB default.
	MaxJSONBytes int64
}

// Result carries the evaluator output plus the counts a report wants.
type Result struct {
	Output *vyql.Output
	Graph  *graph.Store
	Files  map[string]int
}

// skipDirs never carry source worth extracting.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
}

// Run extracts and evaluates one source tree against one KB directory.
// Deterministic: the walk is sorted, and every stage below it is a pure
// function of (tree, knowledge base).
func Run(srcDir, kbDir string, opts Options) (*Result, error) {
	schemas := graph.NewSchemas()
	if err := domains.Register(schemas); err != nil {
		return nil, fmt.Errorf("schemas: %w", err)
	}
	g := graph.New(schemas)

	py := fepython.New(g)
	js := fejs.New(g)
	jv := fejava.New(g)
	goFe := fegolang.New(g)
	dp := doc.New(g)
	maxJSON := opts.MaxJSONBytes
	if maxJSON == 0 {
		maxJSON = 1 << 20
	}

	var files []string
	err := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", srcDir, err)
	}
	sort.Strings(files)

	// Collect the extraction work: (relPath, lang, src) tuples in sorted
	// order, filtered by caps. The collection pass is sequential (cheap);
	// the CPU-bound parse+NIR work below runs in parallel.
	type fileWork struct {
		rel  string
		lang string
		src  []byte
	}
	imports := map[string]map[string]string{}
	perLang := map[string]int{}
	var work []fileWork
	for _, path := range files {
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			rel = path
		}
		ext := strings.ToLower(filepath.Ext(path))
		lang := ""
		switch ext {
		case ".py":
			lang = "python"
		case ".js", ".mjs", ".cjs":
			lang = "javascript"
		case ".java":
			lang = "java"
		case ".go":
			lang = "go"
		case ".yaml", ".yml":
			lang = "doc"
		case ".json":
			lang = "doc"
		}
		if lang == "" {
			continue
		}
		if opts.MaxFilesPerLanguage > 0 && perLang[lang] >= opts.MaxFilesPerLanguage && lang != "doc" {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if lang == "doc" && ext == ".json" && int64(len(src)) > maxJSON {
			continue
		}
		work = append(work, fileWork{rel: rel, lang: lang, src: src})
		perLang[lang]++
	}

	// Parallel extraction: each worker gets its own frontend set and store;
	// the CPU-bound tree-sitter parse + NIR walk runs concurrently. After all
	// workers complete, merge into the main store and re-assign order values
	// in sorted (file, line, col) order — determinism is preserved because
	// node IDs are content-derived and threading reads order, which we set.
	workers := runtime.NumCPU()
	if workers > 4 {
		workers = 4
	}
	if workers > len(work) {
		workers = len(work)
	}
	if workers <= 1 {
		// Sequential path (small trees): no goroutine overhead.
		for _, w := range work {
			extractOne(py, js, jv, goFe, dp, w.rel, w.lang, w.src)
		}
	} else {
		type workerResult struct {
			store     *graph.Store
			imports   map[string]map[string]string
			edgeList  []graph.Edge
			labelList []graph.Label
		}
		results := make([]workerResult, workers)
		var wg sync.WaitGroup
		ch := make(chan int, len(work))
		for i := range work {
			ch <- i
		}
		close(ch)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				ws := graph.New(schemas)
				wpy := fepython.New(ws)
				wjs := fejs.New(ws)
				wjv := fejava.New(ws)
				wgo := fegolang.New(ws)
				wdp := doc.New(ws)
				for idx := range ch {
					extractOne(wpy, wjs, wjv, wgo, wdp, work[idx].rel, work[idx].lang, work[idx].src)
				}
				// Collect nodes, edges, labels, and the import table.
				wimp := map[string]map[string]string{}
				for file, mods := range wpy.ImportTable() {
					wimp[file] = mods
				}
				for file, mods := range wjs.ImportTable() {
					if _, ok := wimp[file]; !ok {
						wimp[file] = mods
					}
				}
				for file, mods := range wjv.ImportTable() {
					if _, ok := wimp[file]; !ok {
						wimp[file] = mods
					}
				}
				for file, mods := range wgo.ImportTable() {
					if _, ok := wimp[file]; !ok {
						wimp[file] = mods
					}
				}
				results[id] = workerResult{store: ws, imports: wimp}
			}(w)
		}
		wg.Wait()
		// Merge sequentially in worker order (deterministic).
		for _, r := range results {
			if r.store == nil {
				continue
			}
			for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
				for _, n := range r.store.NodesOfLayer(layer) {
					_ = g.Upsert(n)
				}
			}
			// Edges too: the child/FLOWS/CALLS edges the frontends built
			// during extraction live in the worker store; without them the
			// merged graph has no flow paths at all.
			for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
				for _, n := range r.store.NodesOfLayer(layer) {
					for _, e := range r.store.Out(n.ID, "") {
						_ = g.AddEdge(e)
					}
				}
			}
			for file, mods := range r.imports {
				if existing, ok := imports[file]; !ok {
					imports[file] = mods
				} else {
					for alias, mod := range mods {
						existing[alias] = mod
					}
				}
			}
		}
		// Re-assign order values: walk all code nodes in sorted (file, line,
		// col) order and renumber sequentially — the globally consistent
		// ordering the threading pass reads.
		reorderNodes(g)
	}

	// Shared lowering over the merged import tables.
	for _, table := range []map[string]map[string]string{
		py.ImportTable(), js.ImportTable(), jv.ImportTable(), goFe.ImportTable(),
	} {
		for file, mods := range table {
			if existing, ok := imports[file]; ok {
				for alias, mod := range mods {
					existing[alias] = mod
				}
				continue
			}
			imports[file] = mods
		}
	}
	if err := lower.Run(g, imports); err != nil {
		return nil, fmt.Errorf("lowering: %w", err)
	}

	kb, err := vyql.LoadDirSchemas(kbDir, schemas)
	if err != nil {
		return nil, fmt.Errorf("knowledge base: %w", err)
	}
	if err := vyql.ApplyLifts(kb, g); err != nil {
		return nil, fmt.Errorf("lifts: %w", err)
	}
	if err := vyql.ApplyRelates(kb, g); err != nil {
		return nil, fmt.Errorf("relates: %w", err)
	}
	if err := vyql.ApplyAdapters(kb, g); err != nil {
		return nil, fmt.Errorf("adapters: %w", err)
	}
	prog, err := vyql.Compile(kb)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	out, err := prog.Run(g, vyql.SolverRegistry{"taint": taint.New(kb.Onto)})
	if err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	return &Result{Output: out, Graph: g, Files: perLang}, nil
}

// extractOne dispatches one file to the right frontend.
func extractOne(py *fepython.Frontend, js *fejs.Frontend, jv *fejava.Frontend, goFe *fegolang.Frontend, dp *doc.Parser, rel, lang string, src []byte) {
	switch lang {
	case "python":
		_ = py.Extract(rel, src)
	case "javascript":
		_ = js.Extract(rel, src)
	case "java":
		_ = jv.Extract(rel, src)
	case "go":
		_ = goFe.Extract(rel, src)
	case "doc":
		_ = dp.Extract(rel, src)
	}
}

// reorderNodes re-assigns the order field on all code nodes in sorted (file,
// line, col) order, making the parallel merge deterministic: the threading
// pass reads order values, and this pass guarantees they reflect the sorted
// source layout regardless of which worker emitted the node.
func reorderNodes(g *graph.Store) {
	type nodeKey struct {
		file string
		line int64
		col  int64
		id   string
	}
	var keys []nodeKey
	for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
		for _, n := range g.NodesOfLayer(layer) {
			f, _ := n.Fields.Get("file")
			l, _ := n.Fields.Get("line")
			c, _ := n.Fields.Get("col")
			if f.S == "" {
				continue
			}
			keys = append(keys, nodeKey{file: f.S, line: l.I, col: c.I, id: n.ID})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].file != keys[j].file {
			return keys[i].file < keys[j].file
		}
		if keys[i].line != keys[j].line {
			return keys[i].line < keys[j].line
		}
		return keys[i].col < keys[j].col
	})
	for i, k := range keys {
		if n, ok := g.Node(k.id); ok {
			var f = n.Fields
			f.Set("order", graph.Int(int64(i)))
			n.Fields = f
			_ = g.Upsert(n)
		}
	}
}

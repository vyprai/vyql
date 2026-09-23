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
	"sort"
	"strings"

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

	perLang := map[string]int{}
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
		switch lang {
		case "python":
			err = py.Extract(rel, src)
		case "javascript":
			err = js.Extract(rel, src)
		case "java":
			err = jv.Extract(rel, src)
		case "go":
			err = goFe.Extract(rel, src)
		case "doc":
			err = dp.Extract(rel, src)
		}
		if err != nil {
			continue // one unparseable file never fails the scan
		}
		perLang[lang]++
	}

	// Shared lowering over the merged import tables.
	imports := map[string]map[string]string{}
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

package treesitter

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sync"
	"sync/atomic"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
)

// contentHash is the per-file content fingerprint used as a module's identity for the
// incremental-lowering cache (nir.Module.Hash).
func contentHash(src []byte) string {
	h := sha256.Sum256(src)
	return hex.EncodeToString(h[:])
}

// parseModules parses files concurrently — one tree-sitter parser per worker (parsers are
// not goroutine-safe) — and returns the resulting modules in INPUT ORDER (deterministic
// findings). Each file produces one independent module, so extraction is embarrassingly
// parallel; it was the last single-threaded phase and dominates scan time on large repos.
//
// newParser builds a fresh, language-configured parser. build converts a parsed tree into a
// module (abs = absolute path for key derivation, rel = display path); returning ok=false
// skips the file. Each worker holds only one transient tree at a time, so peak memory grows
// by ~workers trees, not by the whole graph.
func parseModules(
	files []string,
	root string,
	newParser func() *tree_sitter.Parser,
	build func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool),
) []nir.Module {
	return parseModulesBounded(files, root, newParser, nil, nil, build)
}

// parseModulesPreprocess is parseModules with a source-rewriting pass in front
// of the parse; the content key covers the rewritten bytes, exactly what was
// parsed.
func parseModulesPreprocess(
	files []string,
	root string,
	newParser func() *tree_sitter.Parser,
	preprocess func([]byte) []byte,
	build func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool),
) []nir.Module {
	return parseModulesBounded(files, root, newParser, preprocess, nil, build)
}

// parseBound is one file's parse under a resident-memory bound: it parses src
// with p, returning no tree when the bound cancelled the parse and reporting
// whether the bound was what halted it. It is the hook a frontend whose grammar
// can outrun the file it reads passes to parseModulesBounded; every other
// frontend leaves it nil and its parses are untouched.
type parseBound func(p *tree_sitter.Parser, src []byte) (tree *tree_sitter.Tree, halted bool)

// parseUnbounded is the plain parse every frontend that asked for no bound runs.
func parseUnbounded(p *tree_sitter.Parser, src []byte) (*tree_sitter.Tree, bool) {
	return p.Parse(src, nil), false
}

// parseModulesBounded is the one loop the wrappers above feed: parse files
// concurrently, optionally rewriting each file's bytes (preprocess) and
// bounding each parse (bound). A bound parse that is halted returns no tree
// and the file is skipped — the same outcome as a file that cannot be read —
// after the parser is reset, because a halted parse leaves the parser
// mid-document and the next file's parse would resume it instead of starting
// fresh.
func parseModulesBounded(
	files []string,
	root string,
	newParser func() *tree_sitter.Parser,
	preprocess func([]byte) []byte,
	bound parseBound,
	build func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool),
) []nir.Module {
	n := len(files)
	if n == 0 {
		return nil
	}
	mods := make([]nir.Module, n)
	ok := make([]bool, n)
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	// nil unless an explicit cache owner is wired in; all methods are nil-safe. A preprocess pass
	// stays cacheable: the content key below is taken over the preprocessed bytes -- exactly what
	// was parsed -- and the cache's salt folds in the scanner binary, so a changed preprocess
	// function ships with a salt that retires the entries it would have invalidated.
	cache := parsecache.Shared()
	// Prefetch stubs for unchanged files (one batched transaction): an unchanged module resolves
	// to a STUB (identity only, no body) without being read or decoded — the lowerer decodes the
	// body on demand only if it actually needs it. This skips the dominant cost of a warm re-scan
	// (gob-decoding every module whose body the incremental lowerer never even uses). Misses
	// (changed/new files) fall through to read+parse below.
	var stubs map[string]nir.Module
	if cache != nil {
		stubs = cache.PrefetchStubs(root, files)
	}
	var next int64 = -1
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := newParser()
			defer p.Close()
			for {
				i := int(atomic.AddInt64(&next, 1))
				if i >= n {
					return
				}
				// stat fast-path: an unchanged file resolves to a STUB (identity only) without
				// being read or decoded — the lowerer pulls the body on demand if needed.
				if stub, hit := stubs[files[i]]; hit {
					mods[i], ok[i] = stub, true
					continue
				}
				src, err := readFile(files[i])
				if err != nil {
					continue
				}
				if preprocess != nil {
					src = preprocess(src)
				}
				// content-addressed cache: a re-scan of an unchanged file (whose mtime moved, so
				// the stat path missed) still skips the expensive tree-sitter parse. The key
				// folds in root+abs so the cached module's path-derived Key/File are correct.
				var key string
				if cache != nil {
					key = cache.Key(root, files[i], src)
					if m, hit := cache.Get(key); hit {
						mods[i], ok[i] = moduleStub(m, key), true
						cache.PutStat(root, files[i], key, m) // refresh stat→header for next time
						continue
					}
				}
				parse := parseUnbounded
				if bound != nil {
					parse = bound
				}
				tree, halted := parse(p, src)
				if tree == nil {
					// A halted or errored parse leaves the parser holding the
					// partial document; without this the next file's parse
					// would resume it rather than start fresh.
					p.Reset()
					if halted {
						// The halt freed a tree the scan's budget had already
						// paid for; hand those pages back before the next
						// parse, or the resident set stays at this parse's
						// peak for the rest of the scan.
						trimResidentAlloc()
					}
					continue
				}
				m, good := build(src, files[i], relPath(root, files[i]), tree)
				tree.Close()
				if good {
					m.Hash = contentHash(src) // identifies this parse for the incremental-lowering cache
					if cache != nil {
						// Persist completed bodies before publishing the module result. Keeping only an
						// identity stub here makes extraction memory proportional to active workers,
						// rather than to every file parsed so far.
						cache.DeferModuleBodies(&m)
						if cache.PutModule(key, m) {
							mods[i] = moduleStub(m, key)
						} else {
							mods[i] = m
						}
						cache.PutStat(root, files[i], key, m)
					} else {
						mods[i] = m
					}
					ok[i] = true
				}
			}
		}()
	}
	wg.Wait()
	out := make([]nir.Module, 0, n)
	for i := 0; i < n; i++ {
		if ok[i] {
			out = append(out, mods[i])
		}
	}
	return out
}

func moduleStub(m nir.Module, cacheKey string) nir.Module {
	return nir.Module{Key: m.Key, File: m.File, Hash: m.Hash, CacheKey: cacheKey}
}

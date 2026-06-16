package treesitter

import (
	"runtime"
	"sync"
	"sync/atomic"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/extract/parsecache"
)

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
	cache := parsecache.Shared() // nil unless $VYQL_CACHE is set; all methods are nil-safe
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
				src, err := readFile(files[i])
				if err != nil {
					continue
				}
				// content-addressed cache: a re-scan of an unchanged file skips the (expensive)
				// tree-sitter parse entirely. The key folds in root+abs so the cached module's
				// path-derived Key/File are correct for this scan.
				var key string
				if cache != nil {
					key = cache.Key(root, files[i], src)
					if m, hit := cache.Get(key); hit {
						mods[i], ok[i] = m, true
						continue
					}
				}
				tree := p.Parse(src, nil)
				if tree == nil {
					continue
				}
				m, good := build(src, files[i], relPath(root, files[i]), tree)
				tree.Close()
				if good {
					mods[i], ok[i] = m, true
					if cache != nil {
						cache.Put(key, m)
					}
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

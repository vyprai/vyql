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
	return parseModulesPreprocess(files, root, newParser, nil, build)
}

func parseModulesPreprocess(
	files []string,
	root string,
	newParser func() *tree_sitter.Parser,
	preprocess func([]byte) []byte,
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
	cache := parsecache.Shared() // nil unless an explicit cache owner is wired in; all methods are nil-safe
	if preprocess != nil {
		cache = nil
	}
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
						mods[i], ok[i] = m, true
						cache.PutStat(root, files[i], key, m) // refresh stat→header for next time
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
					m.Hash = contentHash(src) // identifies this parse for the incremental-lowering cache
					mods[i], ok[i] = m, true
					if cache != nil {
						cache.Put(key, m)
						cache.PutStat(root, files[i], key, m)
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

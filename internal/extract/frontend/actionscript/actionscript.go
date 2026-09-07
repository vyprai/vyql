package actionscript

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// Extract parses ActionScript files into one NIR Program, one module per file.
//
// A module's key is its DECLARED package plus the file's own name — `package
// happyworm.jPlayer` in `JplayerStatus.as` keys the module `happyworm.jPlayer.
// JplayerStatus` — because that is the name `import happyworm.jPlayer.JplayerStatus`
// in a sibling file writes. Keying off the scan-relative path instead would prefix
// whatever directory the scan started from and resolve nothing.
func Extract(files []string, root string) (nir.Program, error) {
	if len(files) == 0 {
		return nir.Program{SelfName: "this"}, nil
	}
	mods := make([]nir.Module, len(files))
	ok := make([]bool, len(files))
	workers := runtime.GOMAXPROCS(0)
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}
	var next int64 = -1
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&next, 1))
				if i >= len(files) {
					return
				}
				src, err := os.ReadFile(files[i])
				if err != nil {
					continue
				}
				mods[i] = parseModule(src, files[i], relPath(root, files[i]))
				ok[i] = true
			}
		}()
	}
	wg.Wait()
	out := make([]nir.Module, 0, len(files))
	for i := range mods {
		if ok[i] {
			out = append(out, mods[i])
		}
	}
	return nir.Program{SelfName: "this", Modules: out}, nil
}

// parseModule is the whole frontend for one file, exposed separately so a test can
// hand it source directly.
func parseModule(src []byte, abs, rel string) nir.Module {
	p := &parser{src: src, toks: lex(src), file: rel}
	body := p.parseProgram()
	h := sha256.Sum256(src)
	return nir.Module{
		Key:     moduleKey(p.pkg, abs),
		File:    rel,
		Imports: p.imps,
		Body:    body,
		Hash:    hex.EncodeToString(h[:]),
	}
}

// moduleKey builds the dotted name other files import this one by.
func moduleKey(pkg, abs string) string {
	base := strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	if pkg == "" {
		return base
	}
	return pkg + "." + base
}

func relPath(root, f string) string {
	if r, err := filepath.Rel(root, f); err == nil {
		return r
	}
	return f
}

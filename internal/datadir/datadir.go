// Package datadir resolves the VyQL data root — the standalone `vyql/` directory
// (rule packs + ontology + taxonomy) that lives OUTSIDE the Go source tree and is
// loaded from disk at runtime (no go:embed). Resolution order:
//
//  1. Set (the `-data` flag), if the process called it.
//  2. $VYQL_HOME, if set (same override for tools that cannot pass `-data`, such as
//     `go test`).
//  3. the nearest ancestor of the current working directory that contains a
//     valid `vyql/` data directory (covers `go test ./...` from any package and
//     running the binary from within the repo).
//  4. the nearest such ancestor of the executable's directory, following the
//     symlink if there is one (covers an installed binary shipped alongside its
//     `vyql/` data dir, and one linked onto PATH from a package prefix).
//
// The module cache is not consulted. `go install` places only the engine in
// GOBIN; the definitions arrive via `vyql update`, the install script, a release
// archive, Homebrew, Docker, or `-data` / $VYQL_HOME pointing at a downloaded
// bundle. An interactive CLI that needs data and finds none offers to download
// the free channel from dl.vyprsec.ai.
//
// If none is found, Root panics. The CLI turns that into an error and exit 1.
package datadir

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var (
	mu              sync.Mutex
	resolved        bool
	cached          string
	explicit        string   // from Set / -data; wins over env and search
	vyqlSourceCache sync.Map // map[root+kind+rel][]Source
)

// Root returns the absolute path to the VyQL data directory, resolved once.
func Root() string {
	root, ok := Lookup()
	if !ok {
		panic("could not locate the data directory; pass -data or set $VYQL_HOME to the path of your `vyql/` dir " +
			"(containing ontology/concepts/, plus taxonomy/ and packs/)")
	}
	return root
}

// Lookup resolves the data directory and reports whether one was found, without
// panicking when none was.
//
// Printing a command's help is the case that needs it: the help text names the
// available profiles, which means loading them, and a user asking how to run the
// tool should get an answer whether or not the data is in place. Anything that
// needs the data to do its work calls Root instead and fails loudly.
func Lookup() (string, bool) {
	mu.Lock()
	if !resolved {
		cached, resolved = resolve(), true
	}
	root := cached
	mu.Unlock()
	return root, root != ""
}

// Set pins the data directory for this process. The CLI `-data` flag calls it.
// An empty path clears the pin so the next Lookup walks the search path again.
func Set(root string) {
	mu.Lock()
	explicit = strings.TrimSpace(root)
	cached, resolved = "", false
	mu.Unlock()
	vyqlSourceCache.Range(func(key, _ any) bool {
		vyqlSourceCache.Delete(key)
		return true
	})
}

// Reset drops the resolved root and everything read from it, so the next Root
// resolves again. It keeps a Set pin: clearing the pin is Set("").
//
// Building a flag's help text can read the data directory — naming the available
// profiles requires loading them — and that happens while the flags are being
// registered, before any of them are parsed. Resetting after `-data` is applied
// is what makes the flag take effect if something already looked up the root.
func Reset() {
	mu.Lock()
	cached, resolved = "", false
	mu.Unlock()
	vyqlSourceCache.Range(func(key, _ any) bool {
		vyqlSourceCache.Delete(key)
		return true
	})
}

// Read returns the bytes of a file relative to the data root.
func Read(rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(Root(), rel))
}

// MustRead reads a required data file, panicking with context on failure.
func MustRead(rel string) []byte {
	b, err := Read(rel)
	if err != nil {
		panic("missing data file " + rel + " under " + Root() + ": " + err.Error())
	}
	return b
}

// Source is one VyQL source file read from the data directory. Data should be
// treated as read-only; data-directory reads are cached for repeated scans.
type Source struct {
	Name string
	Data []byte
}

// ReadVYQL reads one exact VyQL file relative to the data root.
func ReadVYQL(rel string) ([]Source, error) {
	root := Root()
	rel = filepath.ToSlash(rel)
	key := "file:" + root + ":" + rel
	if cached, ok := vyqlSourceCache.Load(key); ok {
		return cloneSourceHeaders(cached.([]Source)), nil
	}
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return nil, err
	}
	sources := []Source{{Name: rel, Data: b}}
	actual, _ := vyqlSourceCache.LoadOrStore(key, sources)
	return cloneSourceHeaders(actual.([]Source)), nil
}

// ReadVYQLDir reads all .vyql files under a data-directory relative path.
func ReadVYQLDir(rel string) ([]Source, error) {
	dataRoot := Root()
	rel = filepath.ToSlash(rel)
	key := "dir:" + dataRoot + ":" + rel
	if cached, ok := vyqlSourceCache.Load(key); ok {
		return cloneSourceHeaders(cached.([]Source)), nil
	}
	root := filepath.Join(dataRoot, rel)
	var out []Source
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(dataRoot, path)
		if err != nil {
			name = path
		}
		out = append(out, Source{Name: filepath.ToSlash(name), Data: b})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	actual, _ := vyqlSourceCache.LoadOrStore(key, out)
	return cloneSourceHeaders(actual.([]Source)), nil
}

// ReadVYQLDirExcept reads .vyql files under rel while skipping immediate child
// directories by name. It is useful for split v2 trees where a small metadata
// scan should include language bindings but not large generated subtrees.
func ReadVYQLDirExcept(rel string, excludedDirs ...string) ([]Source, error) {
	dataRoot := Root()
	rel = filepath.ToSlash(rel)
	sort.Strings(excludedDirs)
	key := "direxcept:" + dataRoot + ":" + rel + ":" + strings.Join(excludedDirs, ",")
	if cached, ok := vyqlSourceCache.Load(key); ok {
		return cloneSourceHeaders(cached.([]Source)), nil
	}
	excluded := map[string]bool{}
	for _, name := range excludedDirs {
		if name != "" {
			excluded[name] = true
		}
	}
	root := filepath.Join(dataRoot, rel)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []Source
	for _, entry := range entries {
		name := entry.Name()
		childRel := filepath.ToSlash(filepath.Join(rel, name))
		if entry.IsDir() {
			if excluded[name] {
				continue
			}
			child, err := ReadVYQLDir(childRel)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
			continue
		}
		if !strings.HasSuffix(name, ".vyql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		out = append(out, Source{Name: childRel, Data: b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	actual, _ := vyqlSourceCache.LoadOrStore(key, out)
	return cloneSourceHeaders(actual.([]Source)), nil
}

func cloneSourceHeaders(sources []Source) []Source {
	return append([]Source(nil), sources...)
}

func resolve() string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("VYQL_HOME"); env != "" {
		return env
	}
	if wd, err := os.Getwd(); err == nil {
		if d := searchUp(wd); d != "" {
			return d
		}
	}
	if exe, err := os.Executable(); err == nil {
		if d := rootFromExecutable(exe); d != "" {
			return d
		}
	}
	return ""
}

// searchUp walks from start toward the filesystem root, returning the first
// `<ancestor>/vyql` directory that has a recognized data-root layout.
// rootFromExecutable looks for the data directory beside the binary, following
// the symlink if there is one.
//
// A packaged install keeps the binary and its data together and links the
// binary onto PATH: Homebrew links out of the Cellar, and an installer links
// out of its own prefix. os.Executable reports the link's own path on macOS,
// so searching from there finds nothing and the scanner panics at startup with
// its data one resolved hop away.
//
// The link's own directory is searched first: data placed there is the more
// specific answer, and someone put it there on purpose.
func rootFromExecutable(exe string) string {
	if d := searchUp(filepath.Dir(exe)); d != "" {
		return d
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil || resolved == exe {
		return ""
	}
	return searchUp(filepath.Dir(resolved))
}

func searchUp(start string) string {
	dir := start
	for {
		cand := filepath.Join(dir, "vyql")
		if isDataRoot(cand) {
			return cand
		}
		// also accept `start` itself already being the data dir
		if isDataRoot(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func isDataRoot(dir string) bool {
	if !isDir(filepath.Join(dir, "taxonomy")) || !isDir(filepath.Join(dir, "packs")) {
		return false
	}
	return isDir(filepath.Join(dir, "ontology", "concepts"))
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

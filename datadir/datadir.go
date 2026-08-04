// Package datadir resolves the VyQL data root — the standalone `vyql/` directory
// (rule packs + ontology + taxonomy) that lives OUTSIDE the Go source tree and is
// loaded from disk at runtime (no go:embed). Resolution order:
//
//  1. $VYQL_HOME, if set.
//  2. the nearest ancestor of the current working directory that contains a
//     valid `vyql/` data directory (covers `go test ./...` from any package and
//     running the binary from within the repo).
//  3. the nearest such ancestor of the executable's directory (covers an
//     installed binary shipped alongside its `vyql/` data dir).
//  4. the module cache entry this binary was built from (covers `go install`,
//     where the binary lands in GOBIN with nothing beside it -- but the module,
//     data included, is already on disk).
//
// If none is found, Root panics with a message telling the user to set
// $VYQL_HOME — the data is required, never silently empty.
package datadir

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
)

var (
	once            sync.Once
	cached          string
	vyqlSourceCache sync.Map // map[root+kind+rel][]Source
)

// Root returns the absolute path to the VyQL data directory, resolved once.
func Root() string {
	once.Do(func() { cached = resolve() })
	if cached == "" {
		panic("could not locate the data directory; set $VYQL_HOME to the path of your `vyql/` dir " +
			"(containing ontology/concepts/, plus taxonomy/ and packs/)")
	}
	return cached
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
	if env := os.Getenv("VYQL_HOME"); env != "" {
		return env
	}
	if wd, err := os.Getwd(); err == nil {
		if d := searchUp(wd); d != "" {
			return d
		}
	}
	if exe, err := os.Executable(); err == nil {
		if d := searchUp(filepath.Dir(exe)); d != "" {
			return d
		}
	}
	if d := moduleCacheRoot(); d != "" {
		return d
	}
	return ""
}

// moduleCacheRoot finds the data directory inside the module cache entry this
// binary was built from. `go install example.com/x/cmd/y@v1` leaves the binary in
// GOBIN with no data beside it, and the working directory is wherever the user
// happens to be -- so the first three rules all miss, even though the module was
// just downloaded and the data is sitting in the cache.
//
// Returns "" for a locally built binary, whose version reads "(devel)" and which
// has no cache entry to find.
func moduleCacheRoot() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Path == "" {
		return ""
	}
	version := info.Main.Version
	if version == "" || version == "(devel)" {
		return ""
	}
	base := os.Getenv("GOMODCACHE")
	if base == "" {
		if gopath := os.Getenv("GOPATH"); gopath != "" {
			base = filepath.Join(gopath, "pkg", "mod")
		} else if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "go", "pkg", "mod")
		}
	}
	if base == "" {
		return ""
	}
	cand := moduleCachePath(base, info.Main.Path, version)
	if isDataRoot(cand) {
		return cand
	}
	return ""
}

// moduleCachePath builds the data directory's path inside the module cache. Split
// out from the lookup so it can be tested without a binary that was actually go
// install-ed, which is the only way ReadBuildInfo reports a real version.
func moduleCachePath(base, modulePath, version string) string {
	return filepath.Join(base, escapeModulePath(modulePath)+"@"+version, "vyql")
}

// escapeModulePath applies the module cache's case encoding: an upper-case letter
// becomes "!" followed by its lower-case form, so that paths differing only in
// case cannot collide on a case-insensitive filesystem.
func escapeModulePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// searchUp walks from start toward the filesystem root, returning the first
// `<ancestor>/vyql` directory that has a recognized data-root layout.
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

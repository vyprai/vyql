// Package datadir resolves the VyQL data root — the standalone `vyql/` directory
// (rule packs + ontology + taxonomy) that lives OUTSIDE the Go source tree and is
// loaded from disk at runtime (no go:embed). Resolution order:
//
//  1. $VYQL_HOME, if set.
//  2. the nearest ancestor of the current working directory that contains a
//     `vyql/ontology/concepts.json` (covers `go test ./...` from any package and
//     running the binary from within the repo).
//  3. the nearest such ancestor of the executable's directory (covers an
//     installed binary shipped alongside its `vyql/` data dir).
//
// If none is found, Root panics with a message telling the user to set
// $VYQL_HOME — the data is required, never silently empty.
package datadir

import (
	"os"
	"path/filepath"
	"sync"
)

// marker is the relative file whose presence identifies a valid data root.
const marker = "ontology/concepts.vyql"

var (
	once   sync.Once
	cached string
)

// Root returns the absolute path to the VyQL data directory, resolved once.
func Root() string {
	once.Do(func() { cached = resolve() })
	if cached == "" {
		panic("could not locate the data directory; set $VYQL_HOME to the path of your `vyql/` dir " +
			"(containing ontology/concepts.vyql, taxonomy/, packs/)")
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
	return ""
}

// searchUp walks from start toward the filesystem root, returning the first
// `<ancestor>/vyql` directory that contains the marker file.
func searchUp(start string) string {
	dir := start
	for {
		cand := filepath.Join(dir, "vyql")
		if _, err := os.Stat(filepath.Join(cand, marker)); err == nil {
			return cand
		}
		// also accept `start` itself already being the data dir
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

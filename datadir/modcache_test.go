package datadir

import (
	"os"
	"path/filepath"
	"testing"
)

// The module cache encodes an upper-case letter as "!" plus its lower-case form,
// so that module paths differing only in case cannot collide on a
// case-insensitive filesystem. Getting this wrong means a go install-ed binary
// silently fails to find its data.
func TestEscapeModulePath(t *testing.T) {
	cases := map[string]string{
		"github.com/vyprai/vyql":     "github.com/vyprai/vyql",
		"github.com/BurntSushi/toml": "github.com/!burnt!sushi/toml",
		"example.com/Foo/Bar":        "example.com/!foo/!bar",
		"all/lower/case":             "all/lower/case",
	}
	for in, want := range cases {
		if got := escapeModulePath(in); got != want {
			t.Errorf("escapeModulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// The path this builds must be the one `go install` actually populates.
func TestModuleCachePathMatchesLayout(t *testing.T) {
	got := moduleCachePath("/m", "github.com/vyprai/vyql", "v0.1.0")
	want := filepath.Join("/m", "github.com/vyprai/vyql@v0.1.0", "vyql")
	if got != want {
		t.Fatalf("moduleCachePath = %q, want %q", got, want)
	}
}

// A go install-ed binary lands in GOBIN with no vyql/ beside it and runs from
// wherever the user happens to be, so the cwd and executable searches both miss.
// Only the module cache can answer, and if it cannot the user gets a panic rather
// than a scan that quietly finds nothing.
func TestModuleCacheRootFindsAnInstalledLayout(t *testing.T) {
	base := t.TempDir()
	root := moduleCachePath(base, "github.com/vyprai/vyql", "v9.9.9")
	for _, d := range []string{"taxonomy", "packs", filepath.Join("ontology", "concepts")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if !isDataRoot(root) {
		t.Fatal("a directory with taxonomy, packs and ontology/concepts should be a data root")
	}

	// An entry for a different version must not satisfy the lookup.
	other := moduleCachePath(base, "github.com/vyprai/vyql", "v0.0.1")
	if isDataRoot(other) {
		t.Fatal("an unrelated version should not resolve")
	}
}

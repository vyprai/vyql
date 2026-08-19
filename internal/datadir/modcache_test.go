package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDataRoot(t *testing.T, root string) {
	t.Helper()
	for _, d := range []string{"taxonomy", "packs", filepath.Join("ontology", "concepts")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// GOMODCACHE is not a resolution source. searchUp from an empty working
// directory finds nothing even when a valid data root sits under GOMODCACHE.
func TestSearchUpDoesNotFollowGOMODCACHE(t *testing.T) {
	modcache := t.TempDir()
	stale := filepath.Join(modcache, "github.com", "vyprai", "vyql@v9.9.9", "vyql")
	writeDataRoot(t, stale)
	if !isDataRoot(stale) {
		t.Fatal("fixture is not a data root")
	}

	t.Setenv("GOMODCACHE", modcache)
	wd := t.TempDir()
	if got := searchUp(wd); got != "" {
		if strings.Contains(got, modcache) || strings.Contains(got, "vyql@v9.9.9") {
			t.Fatalf("searchUp returned the module-cache data root %q", got)
		}
		t.Fatalf("searchUp returned %q from an empty working directory", got)
	}
}

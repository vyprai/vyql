package datadir

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSearchUpAcceptsSplitV2OntologyLayout(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "vyql")
	for _, dir := range []string{
		filepath.Join(data, "ontology", "concepts"),
		filepath.Join(data, "taxonomy"),
		filepath.Join(data, "packs"),
		filepath.Join(root, "go", "cmd", "vyql"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if got := searchUp(filepath.Join(root, "go", "cmd", "vyql")); got != data {
		t.Fatalf("searchUp returned %q, want %q", got, data)
	}
}

func TestSearchUpRejectsBareConceptsDirectoryWithoutDataRootShape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "vyql", "ontology", "concepts"), 0o755); err != nil {
		t.Fatalf("mkdir concepts: %v", err)
	}
	if got := searchUp(root); got != "" {
		t.Fatalf("searchUp returned %q for incomplete data root", got)
	}
}

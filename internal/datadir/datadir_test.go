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

// A packaged install puts the binary and its data together and links the binary
// onto PATH — which is what Homebrew does from the Cellar, and what any
// `curl | sh` installer does from its own prefix. os.Executable reports the
// symlink's own path on macOS, so searching from there finds nothing and the
// binary panics at startup with the data sitting one resolved hop away.
func TestRootResolvesThroughASymlinkedBinary(t *testing.T) {
	prefix := t.TempDir()
	realDir := filepath.Join(prefix, "vyql_v0.0.0_test", "bin")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The data directory sits beside bin/, exactly as the release archive ships it.
	data := filepath.Join(prefix, "vyql_v0.0.0_test", "vyql")
	for _, sub := range []string{"ontology/concepts", "taxonomy", "packs"} {
		if err := os.MkdirAll(filepath.Join(data, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	realExe := filepath.Join(realDir, "vyql")
	if err := os.WriteFile(realExe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "vyql")
	if err := os.Symlink(realExe, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got := rootFromExecutable(link)
	if got == "" {
		t.Fatal("no data directory found from a symlinked binary")
	}
	want, _ := filepath.EvalSymlinks(data)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != want {
		t.Errorf("resolved to %q, want %q", gotResolved, want)
	}
}

func TestRootFromExecutableStillPrefersDataBesideTheLink(t *testing.T) {
	// If someone places the data next to the link itself, that wins: it is the
	// more specific answer and the one they chose.
	prefix := t.TempDir()
	linkDir := filepath.Join(prefix, "bin")
	beside := filepath.Join(linkDir, "vyql")
	for _, sub := range []string{"ontology/concepts", "taxonomy", "packs"} {
		if err := os.MkdirAll(filepath.Join(beside, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(linkDir, "vyql-bin")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, _ := filepath.EvalSymlinks(rootFromExecutable(exe))
	want, _ := filepath.EvalSymlinks(beside)
	if got != want {
		t.Errorf("resolved to %q, want the data beside the binary at %q", got, want)
	}
}

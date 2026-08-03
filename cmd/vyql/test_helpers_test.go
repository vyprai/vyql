package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "vyql", "ontology", "concepts")); err != nil {
		t.Fatalf("locate repo root from %s: %v", file, err)
	}
	return root
}

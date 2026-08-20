package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// testRepoRoot walks up from this file until it finds go.mod. The data tree is
// not a repo marker: CI (and `go install` users) keep definitions under
// $VYQL_HOME / -data, and the in-repo vyql/ tree is optional.
func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("locate repo root from %s: no ancestor contains go.mod", file)
		}
		dir = parent
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// testRepoRoot walks up from this file until it finds the directory holding the
// runtime data tree. Counting "../.." instead would pin the depth of this package
// below the repository root, which differs between this repository (cmd/ sits
// under go/) and the published one (cmd/ sits at the root).
func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "vyql", "ontology", "concepts")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("locate repo root from %s: no ancestor contains vyql/ontology/concepts", file)
		}
		dir = parent
	}
}

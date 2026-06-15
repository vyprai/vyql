package golang

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNilExprNoPanic guards the Go frontend against nil-expression panics.
// A tagless `switch { }` makes switchStmt pass a nil tag to (*conv).expr, which
// previously dereferenced nil in c.loc(e.Pos()) and panicked (crashed scans of
// go-redis, anubis, and any Go repo using tagless switches). expr now returns an
// empty node for nil input. Regression for that fix.
func TestNilExprNoPanic(t *testing.T) {
	src := `package p

func tagless(x int) string {
	switch {
	case x > 0:
		return "pos"
	default:
		return ""
	}
}

func emptyTagless() {
	switch {
	}
}

func emptyReturn() { return }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	// Must not panic; must extract without error.
	if _, err := ExtractDir(dir); err != nil {
		t.Fatalf("ExtractDir on tagless-switch source: %v", err)
	}
}

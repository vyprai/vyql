package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
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
	if _, err := gofrontend.ExtractDir(dir); err != nil {
		t.Fatalf("ExtractDir on tagless-switch source: %v", err)
	}
}

func TestGoFunctionContextIncludesIndexAndSliceTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mysql.go")
	src := []byte(`package mysql

import "fmt"

func parse(readBuffer []byte) string {
	capabilities := fmt.Sprintf("%08b", uint32(readBuffer[4]))
	return string(capabilities[8]) + string(readBuffer[36:][0])
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:parse") &&
			strings.Contains(tokens, "index:readBuffer:4") &&
			strings.Contains(tokens, "index:capabilities:8") &&
			strings.Contains(tokens, "slice:readBuffer:36:") {
			return
		}
	}
	t.Fatalf("Go function context did not include index/slice tokens; nodes=%#v", nodes)
}

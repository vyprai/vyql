package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// The GENERATED tree-sitter Swift grammar (tree-sitter generate → cgo-wrapped)
// finds a SQLi: CommandLine input concatenated into sqlite3_exec (arg 1).
func TestTreeSitterSwift(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.swift")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractSwift([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.SwiftAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(twoSinkRules)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	vuln := `func h(db: OpaquePointer) {
  let name = CommandLine.arguments[1]
  sqlite3_exec(db, "SELECT * FROM users WHERE name = '" + name + "'", nil, nil, nil)
}`
	if run(vuln) == 0 {
		t.Fatal("expected SQLi (CommandLine → sqlite3_exec), got 0")
	}

	safe := `func h(db: OpaquePointer) {
  sqlite3_exec(db, "SELECT * FROM users", nil, nil, nil)
}`
	if run(safe) != 0 {
		t.Fatal("constant query should be clean, got a finding")
	}
}

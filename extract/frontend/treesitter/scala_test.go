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

// The REAL tree-sitter Scala frontend finds a SQLi (request query string into
// executeQuery) and a command injection (Process with concatenated input).
func TestTreeSitterScala(t *testing.T) {
	src := `object Handler {
  def search(request: Request, stmt: Statement) = {
    val name = request.getQueryString("name")
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
    Process("ping " + name).!
  }
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "H.scala"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := treesitter.ExtractScala([]string{filepath.Join(dir, "H.scala")}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.ScalaAdapters(), nil)
	onto := ontology.Seed()
	decls, _ := parser.Parse(twoSinkRules)
	compiled, _ := engine.CompileRules(decls, onto)
	byRule := map[string]int{}
	for _, cr := range compiled {
		fs, _ := engine.New(onto, g).Evaluate(cr)
		for _, f := range fs {
			byRule[f.RuleID]++
		}
	}
	if byRule["VYQL-INJ-001"] == 0 {
		t.Fatalf("expected SQLi (getQueryString→executeQuery), got %v", byRule)
	}
	if byRule["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected command injection (Process), got %v", byRule)
	}
}

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

// Expansion / Track 2 template breadth: Java server-side template injection (CWE-1336).
// Velocity.evaluate / Pebble getLiteralTemplate evaluate a STRING template, so a tainted
// template arg is SSTI. Constant templates stay clean.
func TestSstiJava(t *testing.T) {
	rule := `
package vypr.injection;
rule Template { meta { id: "VYQL-INJ-008", severity: high } taint code.HttpInput -> code.TemplateRender }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "H.java")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`class H {
  void run(HttpServletRequest request) {
    String tpl = request.getParameter("tpl");
    Velocity.evaluate(ctx, writer, "log", tpl);
  }
}`) == 0 {
		t.Fatal("expected SSTI finding for tainted Velocity template, got 0")
	}
	if scan(`class H {
  void run() {
    Velocity.evaluate(ctx, writer, "log", "static template");
  }
}`) != 0 {
		t.Fatal("a constant Velocity template is clean, got a finding")
	}
}

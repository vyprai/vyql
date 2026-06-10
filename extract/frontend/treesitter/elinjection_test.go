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

const elRule = `
package vypr.injection;
rule ExpressionInjection { meta { id: "VYQL-INJ-016", severity: critical } taint code.HttpInput -> code.ExpressionEval }
`

// Expansion / CWE-917: untrusted data evaluated as a SpEL/OGNL expression (RCE).
func TestExpressionInjectionJava(t *testing.T) {
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
		decls, _ := parser.Parse(elRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`class H {
  void run(HttpServletRequest request, ExpressionParser parser) {
    String q = request.getParameter("q");
    parser.parseExpression(q).getValue();
  }
}`) == 0 {
		t.Fatal("expected SpEL expression-injection finding, got 0")
	}
	if scan(`class H {
  void run(ExpressionParser parser) {
    parser.parseExpression("1 + 1").getValue();
  }
}`) != 0 {
		t.Fatal("a constant expression is clean, got a finding")
	}
}

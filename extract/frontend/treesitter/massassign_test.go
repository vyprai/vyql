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

const massAssignRule = `
package vypr.injection;
rule MassAssignment { meta { id: "VYQL-INJ-012", severity: medium } taint code.HttpInput -> code.MassAssign }
`

// Phase B / CWE-915: untrusted params bulk-bound via Rails update_attributes.
func TestMassAssignRuby(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "u.rb")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractRuby([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.RubyAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(massAssignRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`def update
  user = User.new
  user.update_attributes(params[:user])
end
`) == 0 {
		t.Fatal("expected mass-assignment finding (params into update_attributes), got 0")
	}
	if scan(`def update
  user = User.new
  user.update_attributes(name: "static")
end
`) != 0 {
		t.Fatal("a literal hash (not request params) should be clean, got a finding")
	}
}

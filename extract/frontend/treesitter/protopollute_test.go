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

const protoRule = `
package vypr.injection;
rule PrototypePollution { meta { id: "VYQL-INJ-013", severity: medium } taint code.HttpInput -> code.ProtoPollute }
`

// Phase B / CWE-1321: untrusted object deep-merged into a target (prototype pollution).
func TestPrototypePollutionJS(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.js")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractJavaScript([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JsAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(protoRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`function h(req) {
  _.merge(config, req.body);
}`) == 0 {
		t.Fatal("expected prototype-pollution finding (req.body deep-merged), got 0")
	}
	if scan(`function h(req) {
  _.merge(config, defaults);
}`) != 0 {
		t.Fatal("merging a static object is clean, got a finding")
	}
}

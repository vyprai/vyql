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

// Expansion / Track 2 sink-breadth: Python XPath injection (CWE-643). The XpathQuery
// concept + Xpath rule existed but had NO sinks in any adapter. lxml's tree.xpath(expr)
// compiles a tainted query → injection; a constant XPath stays clean.
func TestXpathInjectionPython(t *testing.T) {
	rule := `
package vypr.injection;
rule Xpath { meta { id: "VYQL-INJ-006", severity: high } taint code.HttpInput -> code.XpathQuery }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "x.py")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPython([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PythonAdapters(), nil)
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

	if scan(`from flask import request
def f(tree):
    uid = request.args.get("uid")
    return tree.xpath("//user[@id='" + uid + "']")`) == 0 {
		t.Fatal("expected XPath-injection finding for tainted lxml xpath, got 0")
	}
	if scan(`def f(tree):
    return tree.xpath("//user[@id='1']")`) != 0 {
		t.Fatal("a constant XPath query is clean, got a finding")
	}
}

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

const redosRule = `
package vypr.dos;
rule ReDoS { meta { id: "VYQL-DOS-001", severity: medium } taint code.HttpInput -> code.RegexCompile }
`

// Phase B / CWE-1333: untrusted data compiled as a regex pattern (ReDoS).
func TestReDoSPython(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.py")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPython([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PythonAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(redosRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`def h():
    pat = request.args['p']
    re.compile(pat)
`) == 0 {
		t.Fatal("expected ReDoS finding (tainted pattern to re.compile), got 0")
	}
	if scan(`def h():
    re.compile("[a-z]+")
`) != 0 {
		t.Fatal("constant regex pattern is safe, got a finding")
	}
}

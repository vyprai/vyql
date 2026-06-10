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

// Expansion / CWE-377: insecure temp-file APIs (predictable name / race). Presence rule —
// tempfile.mktemp (python) / mktemp (C) are weak by use; the safe APIs stay clean.
func TestInsecureTempFile(t *testing.T) {
	rule := `
package vypr.path;
rule InsecureTempFile { meta { id: "VYQL-PATH-003", severity: low } match code.InsecureTempFile as t }
`
	run := func(file, src string, py bool) int {
		dir := t.TempDir()
		p := filepath.Join(dir, file)
		_ = os.WriteFile(p, []byte(src), 0o644)
		var n int
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		if py {
			pr, _ := treesitter.ExtractPython([]string{p}, dir)
			gg, _ := lowering.Lower(pr, true)
			adapters.Apply(gg, frontend.PythonAdapters(), nil)
			for _, cr := range compiled {
				fs, _ := engine.New(onto, gg).Evaluate(cr)
				n += len(fs)
			}
		} else {
			pr, _ := treesitter.ExtractC([]string{p}, dir)
			gg, _ := lowering.Lower(pr, true)
			adapters.Apply(gg, frontend.CAdapters(), nil)
			for _, cr := range compiled {
				fs, _ := engine.New(onto, gg).Evaluate(cr)
				n += len(fs)
			}
		}
		return n
	}

	if run("a.py", "import tempfile\np = tempfile.mktemp()", true) == 0 {
		t.Fatal("expected insecure-temp-file finding for tempfile.mktemp, got 0")
	}
	if run("b.py", "import tempfile\nf = tempfile.NamedTemporaryFile()", true) != 0 {
		t.Fatal("NamedTemporaryFile is safe, should be clean, got a finding")
	}
	if run("c.c", "int main(){ char *p = mktemp(\"/tmp/fooXXXXXX\"); return 0; }", false) == 0 {
		t.Fatal("expected insecure-temp-file finding for C mktemp, got 0")
	}
}

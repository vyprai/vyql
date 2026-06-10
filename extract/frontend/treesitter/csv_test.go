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

const csvRule = `
package vypr.injection;
rule CsvInjection { meta { id: "VYQL-INJ-014", severity: low } taint code.HttpInput -> code.CsvCell }
`

// Phase B / CWE-1236: untrusted data written to a CSV cell (formula injection).
func TestCsvInjectionPython(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "e.py")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPython([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PythonAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(csvRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`def export(writer):
    row = request.args['row']
    writer.writerow(row)
`) == 0 {
		t.Fatal("expected CSV-injection finding (tainted row to writerow), got 0")
	}
	if scan(`def export(writer):
    writer.writerow("static,header")
`) != 0 {
		t.Fatal("a constant CSV row is clean, got a finding")
	}
}

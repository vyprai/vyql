package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

const sqliRule = `
package vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
`

// scanPython writes the given files into a temp dir, parses them with the REAL
// tree-sitter Python frontend, and runs the full pipeline.
func scanPython(t *testing.T, files map[string]string) []*findings.Finding {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	prog, err := treesitter.ExtractPython(paths, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
		t.Fatalf("adapters: %v", err)
	}
	onto := ontology.Seed()
	decls, _ := parser.Parse(sqliRule)
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := engine.New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return fs
}

// The REAL tree-sitter Python frontend finds an interprocedural, cross-file SQLi
// (routes.py reads request input → db.py builds a string query), and reports
// zero on the parameterized version with the SAME rule.
func TestTreeSitterPythonSQLi(t *testing.T) {
	vulnerable := map[string]string{
		"routes.py": `from db import run_query

def login():
    name = request.form['name']
    run_query(name)
`,
		"db.py": `def run_query(value):
    cursor.execute("SELECT * FROM users WHERE name = '" + value + "'")
`,
	}
	vuln := scanPython(t, vulnerable)
	if len(vuln) == 0 {
		t.Fatalf("expected an interprocedural SQLi from real Python source, got 0")
	}
	crosses := false
	for _, f := range vuln {
		if strings.Split(f.Bindings[0].Loc, ":")[0] != strings.Split(f.Bindings[1].Loc, ":")[0] {
			crosses = true
		}
	}
	if !crosses {
		t.Fatalf("finding should cross routes.py -> db.py, got %s -> %s",
			vuln[0].Bindings[0].Loc, vuln[0].Bindings[1].Loc)
	}

	safe := map[string]string{
		"routes.py": `from db import run_query

def login():
    name = request.form['name']
    run_query(name)
`,
		"db.py": `def run_query(value):
    cursor.execute("SELECT * FROM users WHERE name = %s", (value,))
`,
	}
	if got := scanPython(t, safe); len(got) != 0 {
		t.Fatalf("parameterized query should be clean, got %d", len(got))
	}
}

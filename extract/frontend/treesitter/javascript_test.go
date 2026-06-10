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
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

func scanJS(t *testing.T, src string) []*findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "app.js")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{p}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if _, _, err := adapters.Apply(g, frontend.JsAdapters(), nil); err != nil {
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

// The REAL tree-sitter JavaScript frontend finds a SQLi in an Express handler
// (req.query input concatenated into db.query), via string concat and a template
// literal — and reports zero on the parameterized ($1 placeholder) version.
func TestTreeSitterJavaScriptSQLi(t *testing.T) {
	vuln := `const db = require('./db');

app.get('/search', (req, res) => {
    const q = req.query.q;
    db.query("SELECT * FROM products WHERE name = '" + q + "'");
});

app.get('/user', (req, res) => {
    const id = req.params.id;
    db.query(` + "`SELECT * FROM users WHERE id = ${id}`" + `);
});
`
	if got := scanJS(t, vuln); len(got) < 2 {
		t.Fatalf("expected >=2 Express SQLi findings (concat + template), got %d", len(got))
	}

	safe := `const db = require('./db');

app.get('/search', (req, res) => {
    const q = req.query.q;
    db.query("SELECT * FROM products WHERE name = $1", [q]);
});
`
	if got := scanJS(t, safe); len(got) != 0 {
		t.Fatalf("parameterized query should be clean, got %d", len(got))
	}
}

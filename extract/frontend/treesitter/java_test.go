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

func scanJava(t *testing.T, src string) []*findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "Servlet.java")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{p}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, _ := lowering.Lower(prog, true)
	if _, _, err := adapters.Apply(g, frontend.JavaAdapters(), nil); err != nil {
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

// The REAL tree-sitter Java frontend finds a JDBC SQLi: a Servlet reads
// request.getParameter and concatenates it into Statement.executeQuery; the
// parameterized (PreparedStatement placeholder) version is clean.
func TestTreeSitterJavaSQLi(t *testing.T) {
	vuln := `public class Servlet {
  public void doGet(HttpServletRequest request, Statement stmt) throws Exception {
    String name = request.getParameter("name");
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
`
	if got := scanJava(t, vuln); len(got) == 0 {
		t.Fatalf("expected a JDBC SQLi from real Java source, got 0")
	}

	safe := `public class Servlet {
  public void doGet(HttpServletRequest request, Connection conn) throws Exception {
    String name = request.getParameter("name");
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    ps.setString(1, name);
  }
}
`
	if got := scanJava(t, safe); len(got) != 0 {
		t.Fatalf("parameterized PreparedStatement should be clean, got %d", len(got))
	}
}

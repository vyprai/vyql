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

// The GENERATED tree-sitter Perl grammar (tree-sitter generate → cgo-wrapped)
// finds a CGI command injection and a DBI SQLi; constant input is clean.
func TestTreeSitterPerl(t *testing.T) {
	run := func(src string) map[string]int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.pl")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPerl([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PerlAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(`
package vypr.injection;
rule Sql { meta { id: "VYQL-INJ-001", severity: high } taint code.HttpInput -> code.SqlExecution }
rule Command { meta { id: "VYQL-INJ-002", severity: critical } taint code.HttpInput -> code.CommandExecution }
`)
		compiled, _ := engine.CompileRules(decls, onto)
		byRule := map[string]int{}
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			for _, f := range fs {
				byRule[f.RuleID]++
			}
		}
		return byRule
	}

	vuln := run(`sub handler {
  my $name = $cgi->param('name');
  system("ping " . $name);
  my $q = "SELECT * FROM users WHERE name='$name'";
  $dbh->do($q);
}
`)
	if vuln["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected command injection (CGI param → system), got %v", vuln)
	}
	if vuln["VYQL-INJ-001"] == 0 {
		t.Fatalf("expected SQLi (CGI param → DBI do), got %v", vuln)
	}

	safe := run(`sub handler {
  system("ping localhost");
  $dbh->do("SELECT 1");
}
`)
	if len(safe) != 0 {
		t.Fatalf("constant commands should be clean, got %v", safe)
	}
}

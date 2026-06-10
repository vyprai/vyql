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

// The REAL tree-sitter PHP frontend finds a $_GET → mysqli_query SQLi (where the
// query is the SECOND argument) and a $_GET → system command injection;
// mysqli_real_escape_string on the path neutralizes the SQLi.
func TestTreeSitterPHPSQLiAndCommand(t *testing.T) {
	run := func(src string) map[string]int {
		dir := t.TempDir()
		p := filepath.Join(dir, "app.php")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(`
package vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
rule Command {
  meta { id: "VYQL-INJ-002", severity: critical }
  taint code.HttpInput -> code.CommandExecution
  unless sanitized_by core.ShellEscape
}
`)
		compiled, errs := engine.CompileRules(decls, onto)
		if len(errs) != 0 {
			t.Fatalf("compile: %v", errs)
		}
		eng := engine.New(onto, g)
		byRule := map[string]int{}
		for _, cr := range compiled {
			fs, _ := eng.Evaluate(cr)
			for _, f := range fs {
				byRule[f.RuleID]++
			}
		}
		return byRule
	}

	vuln := run(`<?php
function h($conn) {
  $n = $_GET['name'];
  mysqli_query($conn, "SELECT * FROM u WHERE n='" . $n . "'");
  system("ping " . $_GET['host']);
}
`)
	if vuln["VYQL-INJ-001"] == 0 {
		t.Fatalf("expected mysqli_query SQLi (arg1), got %v", vuln)
	}
	if vuln["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected system() command injection, got %v", vuln)
	}

	// mysqli_real_escape_string on the path neutralizes the SQLi
	safe := run(`<?php
function h($conn) {
  $n = mysqli_real_escape_string($conn, $_GET['name']);
  mysqli_query($conn, "SELECT * FROM u WHERE n='" . $n . "'");
}
`)
	if safe["VYQL-INJ-001"] != 0 {
		t.Fatalf("escaped input should be clean, got %v", safe)
	}
}

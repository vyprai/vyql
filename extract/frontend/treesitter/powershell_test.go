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

// The vendored tree-sitter PowerShell grammar (cgo-wrapped) finds code/command
// injection: $env:QUERY_STRING into Invoke-Expression, a param into Start-Process.
func TestTreeSitterPowerShell(t *testing.T) {
	run := func(src string) map[string]int {
		dir := t.TempDir()
		p := filepath.Join(dir, "s.ps1")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPowerShell([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PowerShellAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(bashRules) // INJ-002 Command + INJ-003 CodeEval
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

	vuln := run(`param($target)
$n = $env:QUERY_STRING
Invoke-Expression "ping $n"
Start-Process "cmd.exe" $target
`)
	if vuln["VYQL-INJ-003"] == 0 {
		t.Fatalf("expected Invoke-Expression code injection from $env:QUERY_STRING, got %v", vuln)
	}
	if vuln["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected Start-Process command injection from param, got %v", vuln)
	}

	safe := run(`Invoke-Expression "ping localhost"
Start-Process "cmd.exe" "/c dir"
`)
	if len(safe) != 0 {
		t.Fatalf("constant commands should be clean, got %v", safe)
	}
}

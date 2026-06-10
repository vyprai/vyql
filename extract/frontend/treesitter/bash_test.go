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

const bashRules = `
package vypr.injection;
rule Command { meta { id: "VYQL-INJ-002", severity: critical } taint code.HttpInput -> code.CommandExecution }
rule CodeEval { meta { id: "VYQL-INJ-003", severity: critical } taint code.HttpInput -> code.CodeEval }
`

// The REAL tree-sitter Bash frontend finds a CGI command/code injection: a
// positional param / $QUERY_STRING flows into eval and bash -c.
func TestTreeSitterBash(t *testing.T) {
	run := func(src string) map[string]int {
		dir := t.TempDir()
		p := filepath.Join(dir, "s.sh")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractBash([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.BashAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(bashRules)
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

	vuln := run(`#!/bin/bash
host=$1
cmd="ping $host"
eval "$cmd"
bash -c "$QUERY_STRING"
`)
	if vuln["VYQL-INJ-003"] == 0 {
		t.Fatalf("expected eval code injection from $1, got %v", vuln)
	}
	if vuln["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected bash -c command injection from $QUERY_STRING, got %v", vuln)
	}

	safe := run(`#!/bin/bash
eval "ping localhost"
bash -c "ls -la"
`)
	if len(safe) != 0 {
		t.Fatalf("constant commands should be clean, got %v", safe)
	}
}

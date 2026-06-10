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

const sessionFixRule = `
package vypr.misconfig;
rule SessionFixation { meta { id: "VYQL-CFG-002", severity: medium } taint code.HttpInput -> code.SessionId }
`

// Expansion / CWE-384: a user-controlled value used as the session id.
func TestSessionFixationPHP(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "s.php")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(sessionFixRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`<?php
function login() {
  session_id($_GET['sid']);
}
`) == 0 {
		t.Fatal("expected session-fixation finding (user-controlled session id), got 0")
	}
	if scan(`<?php
function login() {
  session_id("server-generated");
}
`) != 0 {
		t.Fatal("a constant session id is clean, got a finding")
	}
}

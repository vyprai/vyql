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

// Expansion / CWE-93: tainted CRLF in PHP mail() additional-headers arg (index 3) lets an
// attacker inject extra email headers. A constant headers string is clean.
func TestEmailHeaderInjectionPHP(t *testing.T) {
	rule := `
package vypr.injection;
rule EmailHeaderInjection { meta { id: "VYQL-INJ-017", severity: medium } taint code.HttpInput -> code.MailHeaderWrite }
`
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "m.php")
		_ = os.WriteFile(p, []byte(src), 0o644)
		prog, _ := treesitter.ExtractPHP([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.PHPAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(rule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}
	if scan(`<?php $from = $_GET['from']; mail("to@x.com", "subj", "body", "From: " . $from);`) == 0 {
		t.Fatal("expected email-header-injection finding for tainted headers arg, got 0")
	}
	if scan(`<?php mail("to@x.com", "subj", "body", "From: noreply@x.com");`) != 0 {
		t.Fatal("a constant headers string is clean, got a finding")
	}
}

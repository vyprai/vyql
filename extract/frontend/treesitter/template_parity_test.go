package treesitter_test

import (
	"testing"
)

// Language parity B6: PHP server-side template injection (CWE-1336) — Twig
// $twig->createTemplate($source) compiles a string template; tainted source = SSTI.
func TestSstiTwigPHP(t *testing.T) {
	rule := `package vypr.injection;
rule Template { meta { id: "VYQL-INJ-008", severity: high } taint code.HttpInput -> code.TemplateRender }`
	if runPHP(t, `<?php $t = $_GET['t']; $twig->createTemplate($t);`, rule) == 0 {
		t.Fatal("expected SSTI for tainted Twig createTemplate, got 0")
	}
	if runPHP(t, `<?php $twig->createTemplate("<h1>hello</h1>");`, rule) != 0 {
		t.Fatal("a constant template is clean, got a finding")
	}
}

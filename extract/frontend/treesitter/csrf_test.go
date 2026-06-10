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

// Phase B / CWE-352: presence rule — CSRF protection explicitly disabled
// (Spring http.csrf().disable()).
func TestCsrfDisabledJava(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "Sec.java")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractJava([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.JavaAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(`
package vypr.misconfig;
rule CsrfDisabled { meta { id: "VYQL-CFG-001", severity: high } match code.CsrfDisabled as c }
`)
		compiled, errs := engine.CompileRules(decls, onto)
		if len(errs) != 0 {
			t.Fatalf("compile: %v", errs)
		}
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	if scan(`class Sec {
  void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
  }
}`) == 0 {
		t.Fatal("expected CSRF-disabled finding (csrf().disable()), got 0")
	}
	if scan(`class Sec {
  void configure(HttpSecurity http) throws Exception {
    http.csrf().enable();
  }
}`) != 0 {
		t.Fatal("csrf().enable() should be clean, got a finding")
	}
}

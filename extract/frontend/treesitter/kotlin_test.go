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

// The REAL tree-sitter Kotlin frontend finds a command injection in a Spring
// controller: a @RequestParam handler param flows into Runtime.exec; a no-param
// constant call is clean.
func TestTreeSitterKotlin(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "H.kt")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractKotlin([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.KotlinAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(twoSinkRules)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	vuln := `@RestController
class Handler {
  @GetMapping("/ping")
  fun ping(@RequestParam host: String) {
    Runtime.getRuntime().exec("ping " + host)
  }
}`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (@RequestParam → Runtime.exec), got 0")
	}

	safe := `@RestController
class Handler {
  @GetMapping("/ping")
  fun ping() {
    Runtime.getRuntime().exec("ping localhost")
  }
}`
	if run(safe) != 0 {
		t.Fatal("constant command should be clean, got a finding")
	}
}

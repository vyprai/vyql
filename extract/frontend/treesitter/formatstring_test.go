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

const formatStringRule = `
package vypr.injection;
rule FormatString { meta { id: "VYQL-INJ-011", severity: high } taint code.HttpInput -> code.FormatString }
`

// Phase B / CWE-134: untrusted data used as a printf FORMAT argument.
func TestFormatStringC(t *testing.T) {
	scan := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "h.c")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractC([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.CAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(formatStringRule)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	// printf(userInput) — the format string is attacker-controlled.
	if scan(`void h() {
  char *name = getenv("NAME");
  printf(name);
}`) == 0 {
		t.Fatal("expected format-string finding (printf with tainted format), got 0")
	}
	// printf with a constant format and the input as an argument — safe.
	if scan(`void h() {
  char *name = getenv("NAME");
  printf("%s", name);
}`) != 0 {
		t.Fatal("printf with a constant format is safe, got a finding")
	}
}

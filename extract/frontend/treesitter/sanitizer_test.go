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

const commandRule = `
package vypr.injection;
rule Command {
  meta { id: "VYQL-INJ-002", severity: critical }
  taint code.HttpInput -> code.CommandExecution
  unless sanitized_by core.ShellEscape
}
`

// Phase 2 — sanitizer recognition. Input wrapped in shlex.quote (labeled
// core.ShellEscape by the adapter `control` mapping) before reaching os.system is
// neutralized; raw input is not. The control node on the taint path kills the flow.
func TestSanitizerNeutralizesFlow(t *testing.T) {
	src := `def safe():
    x = request.args['q']
    os.system("ping " + shlex.quote(x))

def unsafe():
    y = request.args['q']
    os.system("ping " + y)
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "h.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := treesitter.ExtractPython([]string{filepath.Join(dir, "h.py")}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.PythonAdapters(), nil)

	onto := ontology.Seed()
	decls, _ := parser.Parse(commandRule)
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, _ := engine.New(onto, g).Evaluate(compiled[0])

	// only the unsanitized call fires — the shlex.quote-wrapped one is neutralized
	if len(fs) != 1 {
		t.Fatalf("expected 1 command-injection (unsafe only; shlex.quote neutralizes safe), got %d", len(fs))
	}
}

package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// The inject clause: a Flask route handler's parameters are HttpInput. A
// parameter name (e.g. `req`) reaches a sink in the same function through
// the ParamEntry label → def-flow → name-threading chain.
func TestInjectClauseLabelsHandlerParams(t *testing.T) {
	kbDir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(kbDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", `module inject { provenance trusted }`)
	write("concepts.vyql", `module inject;
concept code.HttpInput : source { taint: [UntrustedData] }
concept code.CommandExecution : sink { vulnerable_to: [CommandInjection] enabled_by: [UntrustedData] }
threat CommandInjection { }
`)
	write("adapters.vyql", `module inject;
adapter web {
  meta { fidelity: syntactic }
  sink code.syntacticPath("subprocess.run") -> code.CommandExecution
  sink code.syntacticPath("os.system") -> code.CommandExecution
}
`)
	write("lifts.vyql", `module inject;
framework flask {
  route on code.func() where decorated_by("flask.route") {
    handler: .name
  }
}
lift code.Entrypoint from framework flask {
  handler: .handler
}
`)
	write("rules.vyql", `module inject;
rule CmdInjection {
  meta { id: "INJ-TEST" severity: critical }
  taint code.HttpInput -> code.CommandExecution -> finding
}
`)

	// The handler parameter `req` is not matched by any syntactic source
	// binding — only the inject clause (via the framework model) labels it.
	// The flow must go: ParamEntry(req) [labeled] → Name(req) → Attr(req.args)
	// → Call(req.args.get) → Name(q) → Format → Call(subprocess.run).
	vulnDir := t.TempDir()
	vulnSrc := `import subprocess
import flask

@flask.route("/exec")
def run_cmd(req):
    q = req.args.get("q")
    result = subprocess.run("echo " + q, shell=True)
    return result
`
	if err := os.WriteFile(filepath.Join(vulnDir, "app.py"), []byte(vulnSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(vulnDir, kbDir, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Output.Findings) == 0 {
		t.Fatalf("handler param must reach the sink via the inject clause:\n%s", res.Output.Render())
	}
	found := false
	for _, f := range res.Output.Findings {
		if f.RuleID == "INJ-TEST" {
			found = true
		}
	}
	if !found {
		t.Fatalf("INJ-TEST must fire:\n%s", res.Output.Render())
	}
}

package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// Interprocedural: source in a Flask handler, sink in a called helper.
// The CALLS expansion connects them: taint from req.args.get flows through
// the execute() call to subprocess.run in the helper.
func TestInterproceduralFlow(t *testing.T) {
	kbDir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(kbDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", `module interp { provenance trusted }`)
	write("concepts.vyql", `module interp;
concept code.HttpInput : source { taint: [UntrustedData] }
concept code.CommandExecution : sink { vulnerable_to: [CommandInjection] enabled_by: [UntrustedData] }
threat CommandInjection { }
`)
	write("adapters.vyql", `module interp;
adapter web {
  meta { fidelity: syntactic }
  source code.syntacticPath("req.args.get") -> code.HttpInput
  sink code.syntacticPath("subprocess.run") -> code.CommandExecution
}
`)
	write("rules.vyql", `module interp;
rule CmdInjection {
  meta { id: "INTERP-001" severity: critical }
  taint code.HttpInput -> code.CommandExecution -> finding
}
`)

	vulnDir := t.TempDir()
	vulnSrc := `import subprocess

def execute(cmd):
    return subprocess.run(cmd, shell=True)

def handler(req):
    q = req.args.get("q")
    result = execute("echo " + q)
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
		t.Fatalf("interprocedural flow must fire (source in handler, sink in helper):\n%s", res.Output.Render())
	}
}

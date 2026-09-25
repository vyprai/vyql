package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

// G2 acceptance: argument-position sink sensitivity. The parameterized shape
// (execute(sql, {"name": q})) routes the tainted value into argument 1 — a
// non-dangerous position — and must not fire. The concatenated shape routes
// it into argument 0 (the SQL string) and must fire.
func TestArgPositionSinkSensitivity(t *testing.T) {
	kbDir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(kbDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", `module argtest { provenance trusted }`)
	write("concepts.vyql", `module argtest;
concept code.HttpInput : source { taint: [UntrustedData] }
concept code.SqlExecution : sink { vulnerable_to: [SqlInjection] enabled_by: [UntrustedData] }
threat SqlInjection { }
`)
	write("adapters.vyql", `module argtest;
adapter web {
  meta { fidelity: syntactic }
  source code.syntacticPath("req.args.get") -> code.HttpInput
  sink code.syntacticPath("session.execute") arg 0 -> code.SqlExecution
}
`)
	write("rules.vyql", `module argtest;
rule SqlInjection {
  meta { id: "ARG-001" severity: high }
  taint code.HttpInput -> code.SqlExecution -> finding
}
`)

	// The vulnerable shape: concatenation into argument 0.
	vulnDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(vulnDir, "app.py"), []byte(`def handler(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = " + q)
    return rows
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(vulnDir, kbDir, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Output.Findings) != 1 {
		t.Fatalf("concatenated shape must fire (arg 0):\n%s", res.Output.Render())
	}

	// The fixed shape: the tainted value routes into argument 1 (the params
	// dict) — not the dangerous string position.
	fixDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixDir, "app.py"), []byte(`def handler(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = :name", {"name": q})
    return rows
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res2, err := Run(fixDir, kbDir, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res2.Output.Findings) != 0 {
		t.Fatalf("parameterized shape must not fire (arg 1 is not dangerous):\n%s", res2.Output.Render())
	}
}

// Without the arg qualifier, both shapes fire (all positions dangerous —
// the pre-G2 behaviour, unchanged for bindings that don't declare arg).
func TestNoArgQualifierFiresBoth(t *testing.T) {
	kbDir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(kbDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", `module argtest { provenance trusted }`)
	write("concepts.vyql", `module argtest;
concept code.HttpInput : source { taint: [UntrustedData] }
concept code.SqlExecution : sink { vulnerable_to: [SqlInjection] enabled_by: [UntrustedData] }
threat SqlInjection { }
`)
	write("adapters.vyql", `module argtest;
adapter web {
  meta { fidelity: syntactic }
  source code.syntacticPath("req.args.get") -> code.HttpInput
  sink code.syntacticPath("session.execute") -> code.SqlExecution
}
`)
	write("rules.vyql", `module argtest;
rule SqlInjection {
  meta { id: "ARG-002" severity: high }
  taint code.HttpInput -> code.SqlExecution -> finding
}
`)

	fixDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixDir, "app.py"), []byte(`def handler(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = :name", {"name": q})
    return rows
`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(fixDir, kbDir, Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The pre-existing flow model already routes the dict-literal path away
	// from the sink (the Pair→Seq→Call chain doesn't child-flow into the
	// dangerous string position the way a direct Name→Call does). The arg
	// qualifier makes this explicit rather than accidental — and critically,
	// it also guards shapes the flow model alone would miss (a direct tainted
	// second argument without the dict indirection).
	if len(res.Output.Findings) > 0 {
		t.Fatalf("unexpected: the pre-existing model fires on the parameterized shape\n%s", res.Output.Render())
	}
}

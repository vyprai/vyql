package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPipelineRunsFixtureEndToEnd(t *testing.T) {
	res, err := Run("testdata/src", "testdata/kb", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Files["python"] != 1 {
		t.Fatalf("python files = %d", res.Files["python"])
	}
	if len(res.Output.Findings) != 1 || res.Output.Findings[0].RuleID != "FULL-INJ-001" {
		t.Fatalf("findings:\n%s", res.Output.Render())
	}
	if len(res.Output.Signals) != 1 || res.Output.Signals[0].RuleID != "FULL-CRYPTO-001" {
		t.Fatalf("signals:\n%s", res.Output.Render())
	}
	proof := res.Output.Findings[0].Proof.Render()
	if !strings.Contains(proof, "FLOWS") {
		t.Fatalf("witness must walk the value substrate:\n%s", proof)
	}
}

func TestPipelineDeterministic(t *testing.T) {
	a, err := Run("testdata/src", "testdata/kb", Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run("testdata/src", "testdata/kb", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Output.Render() != b.Output.Render() {
		t.Fatalf("reruns differ:\n%s\n---\n%s", a.Output.Render(), b.Output.Render())
	}
	if a.Graph.NodeCount() != b.Graph.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", a.Graph.NodeCount(), b.Graph.NodeCount())
	}
}

// Unparseable files never fail the scan; the rest of the tree still extracts.
func TestPipelineToleratesBadFiles(t *testing.T) {
	dir := t.TempDir()
	if err := writeFiles(map[string]string{
		"good.py":  "def f(req):\n    q = req.args.get('q')\n    session.execute('SELECT ' + q)\n",
		"bad.py":   "def broken(:\n",
		"bad.json": "{not json",
	}, dir); err != nil {
		t.Fatal(err)
	}
	res, err := Run(dir, "testdata/kb", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// tree-sitter error recovery means even broken python yields a tree; the
	// contract is that a bad file never fails the scan.
	if res.Files["python"] < 1 || res.Files["doc"] != 0 {
		t.Fatalf("counts = %v (want >=1 python, bad.json skipped)", res.Files)
	}
}

func writeFiles(files map[string]string, dir string) error {
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			return err
		}
	}
	return nil
}

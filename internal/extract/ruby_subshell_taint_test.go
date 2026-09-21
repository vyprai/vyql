package extract_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// The rank-2814 shape, end to end through the Ruby frontend: a wrapper interpolates a
// caller-supplied path into a backtick shell string. The backtick execution lowers to a
// call to Kernel's backtick method whose first argument is the command string, so a sink
// concept attached to that argument — the spelling a definition writes as
// `query pattern callExpr where callee.path ~= "Kernel.`"` with `emit sink … at args[0]`
// — has a node to land on, and the taint reaching the interpolated part completes the
// path instead of ending in a string value nothing consumes.
func TestRubyBacktickCommandArgumentCarriesTaintToTheExecution(t *testing.T) {
	src := "class Pdf\n  def info(file)\n    `pdfinfo -layout #{file} 2>/dev/null`\n  end\nend\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pdf.rb"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, _, err := extract.BuildGraph([]string{dir}, nil, extract.Options{})
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	exec := nodeByCallee(t, g, "Kernel.`")
	n, ok, err := g.GetNode(exec)
	if err != nil || !ok {
		t.Fatalf("no Kernel backtick execution node: %v", err)
	}
	if n.Prop("method") != "`" {
		t.Fatalf("the backtick should lower to Kernel's backtick method, got method=%q", n.Prop("method"))
	}
	sink := n.Prop("arg0")
	if sink == "" {
		t.Fatal("the backtick execution records no command-string argument for a sink to attach to")
	}
	if err := g.AddLabel(sink, usg.Label{Concept: "test.Sink"}); err != nil {
		t.Fatal(err)
	}
	// the parameter is where a caller's tainted path enters the wrapper
	if err := g.AddLabel(rubySubshellParam(t, g, "file", "info"), usg.Label{Concept: "test.Source"}); err != nil {
		t.Fatal(err)
	}

	flows, err := solvers.FindTaintFlows(g,
		map[string]bool{"test.Source": true}, map[string]bool{"test.Sink": true},
		map[string]bool{"test.Kind": true}, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) == 0 {
		t.Fatal("no taint flow from the interpolated parameter into the shell command argument")
	}
}

// rubySubshellParam returns the id of a method parameter node, the entry a caller's
// taint reaches the body through.
func rubySubshellParam(t *testing.T, g usg.Store, name, fn string) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Param")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Prop("name") == name && n.Prop("func") == fn {
			return id
		}
	}
	t.Fatalf("no code.Param %s of %s", name, fn)
	return ""
}

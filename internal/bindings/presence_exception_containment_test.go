package bindings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A call inside a try BODY flows into the try's analysis.exception node, which is how a
// binding states exception containment. The walk that decides this is same-file
// bounded, and a loc-less node fails that bound, so the exception node the lowering
// builds from the try statement's NIR location is load-bearing: without it the fact
// is unreachable and `node.flowTo.path == "analysis.exception"` matches nothing. A
// call in the catch clause does NOT flow into it — the handler is an alternative arm
// of the try (its own region), and an exception raised there is not caught by the try
// that spawned the handler.
func TestPresenceFlowToExceptionLabelsCallsInsideTry(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.test;

binding containedCall {
  query pattern presenceNode where node.kind == "call" and node.flowTo.path == "analysis.exception"
  emit issue custom.ExceptionContainment at node
}
`)
	if err != nil {
		t.Fatalf("compile exception-containment flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))

	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	src := []byte("function run(cmd) {\n" +
		"  try {\n" +
		"    doWork(cmd);\n" +
		"  } catch (e) {\n" +
		"    cleanup(e);\n" +
		"  }\n" +
		"  unrelated(cmd);\n" +
		"}\n")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := store.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]usg.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	marked := map[string]bool{}
	for _, m := range spec.presenceApplicator().Apply(store) {
		marked[byID[m.NodeID].Prop("callee_path")] = true
	}
	if !marked["doWork"] {
		t.Fatalf("calls inside the try body were not labelled as exception-contained: %v", marked)
	}
	if marked["cleanup"] {
		t.Fatalf("call inside the catch clause was labelled as exception-contained: %v", marked)
	}
	if marked["unrelated"] {
		t.Fatalf("call outside the try was labelled as exception-contained: %v", marked)
	}
}

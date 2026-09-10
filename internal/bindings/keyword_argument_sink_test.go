package bindings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A sink whose target is a keyword argument is addressed by the NAME the callee
// documents, so `Delta(delta_path=p)` is reachable by a binding even though the
// call has no positional arguments at all.
func TestV2KwargSinkLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.deepdiff;
binding deepdiffDeltaPath {
  query pattern callExpr where callee.path == "deepdiff.Delta"
  emit sink code.Deserialization at args[delta_path]
}
binding deepdiffDiffCheck {
  query pattern callExpr where callee.path == "deepdiff.Delta"
  emit check core.SerializationIntegrity at args[diff] {
    covers path { from: args[diff] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	if len(sets) != 1 || len(sets[0].Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", sets)
	}
	sink := sets[0].Mappings[0]
	if sink.Kind != "sink_path" || sink.Concept != "code.Deserialization" || sink.Kwarg != "delta_path" || sink.ArgIndex != 0 {
		t.Fatalf("kwarg sink lowering wrong: %+v", sink)
	}
	check := sets[0].Mappings[1]
	if check.Kind != "check_arg" || check.Kwarg != "diff" {
		t.Fatalf("kwarg check lowering wrong: %+v", check)
	}
}

// A keyword target cannot also be a collection target: the name already picks
// one slot, so a collection suffix has nothing to select inside.
func TestV2KwargSinkWithCollectionSuffixIsRejected(t *testing.T) {
	if _, err := compileV2BindingsForTest(`
module bindings.python.deepdiff;
binding deepdiffDeltaPath {
  query pattern callExpr where callee.path == "deepdiff.Delta"
  emit sink code.Deserialization at args[delta_path].collection
}
`); err == nil {
		t.Fatal("a keyword target with a collection suffix compiled")
	}
}

// kwargStore is the graph one Python call lowers to when every argument is
// spelled as a keyword: each argument slot is an Arg node carrying the keyword
// name, and the slot's kind is Seq because a keyword lowers to a key/value pair.
func kwargStore() usg.Store {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "diffSlot", Type: "code.Arg", Props: map[string]string{
		"loc": "app.py:9", "vkind": "Seq", "kwarg": "diff",
	}})
	s.AddNode(usg.Node{ID: "pathSlot", Type: "code.Arg", Props: map[string]string{
		"loc": "app.py:9", "vkind": "Seq", "kwarg": "delta_path",
	}})
	s.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:9", "callee_path": "deepdiff.Delta", "method": "Delta",
		"arg0": "diffSlot", "arg1": "pathSlot",
	}})
	return s
}

func compileDeepdiffDeltaSink(t *testing.T, location string) Applicator {
	t.Helper()
	sets, err := compileV2BindingsForTest(`
module bindings.python.deepdiff;
binding deepdiffDelta {
  query pattern callExpr where callee.path == "deepdiff.Delta"
  emit sink code.Deserialization at ` + location + `
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	return specFromBindingSet(sets[0]).sinkApplicator()
}

func labelsByNode(ms []Mapping) map[string][]string {
	out := map[string][]string{}
	for _, m := range ms {
		out[m.NodeID] = append(out[m.NodeID], m.Concept)
	}
	return out
}

// The named slot carries the label, and nothing else on the call does.
func TestKwargSinkLabelsTheNamedArgumentSlot(t *testing.T) {
	got := labelsByNode(compileDeepdiffDeltaSink(t, "args[delta_path]").Apply(kwargStore()))
	if len(got["pathSlot"]) != 1 || len(got) != 1 {
		t.Fatalf("kwarg sink labels = %v, want only pathSlot", got)
	}
}

// A positional target reads the call's positional slots, which a keyword-only
// call fills with key/value pairs -- so the same call carries no label from a
// positional sink. That is exactly why a binding that needs `delta_path` has to
// be able to spell it.
func TestPositionalSinkLabelsNothingOnAKeywordOnlyCall(t *testing.T) {
	got := labelsByNode(compileDeepdiffDeltaSink(t, "args[0]").Apply(kwargStore()))
	if len(got) != 0 {
		t.Fatalf("positional sink on a keyword-only call labelled %v, want nothing", got)
	}
}

// A call that never passes the named keyword has no such slot, and the sink
// stays silent rather than labelling some other argument.
func TestKwargSinkIsSilentWhenTheKeywordIsAbsent(t *testing.T) {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "onlySlot", Type: "code.Arg", Props: map[string]string{
		"loc": "app.py:9", "vkind": "Seq", "kwarg": "diff",
	}})
	s.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:9", "callee_path": "deepdiff.Delta", "method": "Delta", "arg0": "onlySlot",
	}})
	got := labelsByNode(compileDeepdiffDeltaSink(t, "args[delta_path]").Apply(s))
	if len(got) != 0 {
		t.Fatalf("kwarg sink on a call without that keyword labelled %v, want nothing", got)
	}
}

// A check can be emitted at a named keyword too, and it must neutralise the
// argument it names -- not its neighbour in the argument list.
func TestKwargCheckLabelsOnlyTheNamedArgumentSlot(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.deepdiff;
binding deepdiffDiffCheck {
  query pattern callExpr where callee.path == "deepdiff.Delta"
  emit check core.SerializationIntegrity at args[diff] {
    covers path { from: args[diff] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	got := labelsByNode(specFromBindingSet(sets[0]).checkApplicator().Apply(kwargStore()))
	if len(got["diffSlot"]) != 1 || len(got) != 1 {
		t.Fatalf("kwarg check labels = %v, want only diffSlot", got)
	}
}

// deepdiffGraph lowers the application shape the deepdiff delta binding is about:
// an endpoint applies a delta file the request named, passed by keyword.
func deepdiffGraph(t *testing.T) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "patcher.py")
	src := `import os

from deepdiff import Delta
from flask import Flask, request

app = Flask(__name__)


@app.route("/patch", methods=["POST"])
def patch_state():
    delta_path = request.get_data().decode()
    if not os.path.exists(delta_path):
        return {"error": "no such delta"}, 404
    delta = Delta(delta_path=delta_path)
    return {"state": delta}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The whole chain, from Python source to a sink label: the keyword the call
// spells reaches the binding that names it.
func TestDeepdiffDeltaPathCallCarriesASinkLabel(t *testing.T) {
	g := deepdiffGraph(t)
	got := labelsByNode(compileDeepdiffDeltaSink(t, "args[delta_path]").Apply(g))
	if len(got) == 0 {
		t.Fatal("no sink label on the Delta(delta_path=...) call")
	}
	for node := range got {
		n, ok, err := g.GetNode(node)
		if err != nil || !ok {
			t.Fatalf("labelled node %q is not in the graph", node)
		}
		if n.Prop("kwarg") != "delta_path" {
			t.Fatalf("label landed on %q (kwarg=%q), want the delta_path slot", node, n.Prop("kwarg"))
		}
	}
}

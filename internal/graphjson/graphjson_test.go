package graphjson

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// buildTwoFunctionGraph returns a graph shaped the way lowering actually shapes
// one: a function is the `region` its nodes carry, not a node of its own, and its
// entry and exit are boundary nodes that carry no region and encode the authored
// name in their id.
//
// handler() calls helper(), so there is one call edge to find.
func buildTwoFunctionGraph(t *testing.T) usg.Store {
	t.Helper()
	s := usg.NewInMemStore()
	add := func(n usg.Node) {
		if err := s.AddNode(n); err != nil {
			t.Fatalf("AddNode(%s): %v", n.ID, err)
		}
	}
	edge := func(src, dst, typ string) {
		if err := s.AddEdge(usg.Edge{Src: src, Dst: dst, Type: typ}); err != nil {
			t.Fatalf("AddEdge(%s->%s): %v", src, dst, err)
		}
	}

	// A boundary node's id is the module, a unit separator, the authored name,
	// then the marker; it carries no region of its own, and its loc is the
	// declaration line. This is the shape lowering produces.
	//
	// handler is declared at app.py:4 and calls helper at app.py:6.
	add(usg.Node{ID: "mA\x1fhandler#ret#", Type: "code.Return", Loc: "app.py:4"})
	add(usg.Node{ID: "call1", Type: "code.Call", Loc: "app.py:6", Region: "mA/fn1",
		Props: map[string]string{"callee_path": "helper", "arg0": "arg1"}})
	add(usg.Node{ID: "arg1", Type: "code.Arg", Loc: "app.py:6", Region: "mA/fn1"})
	add(usg.Node{ID: "body1", Type: "code.Const", Loc: "app.py:7", Region: "mA/fn1"})
	edge("body1", "mA\x1fhandler#ret#", "FLOWS")

	// helper is declared at app.py:10 and takes one parameter.
	add(usg.Node{ID: "mA\x1fhelper#ret#", Type: "code.Return", Loc: "app.py:10"})
	add(usg.Node{ID: "mA\x1fhelper#param#x", Type: "code.Param", Loc: "app.py:10"})
	add(usg.Node{ID: "body2", Type: "code.Const", Loc: "app.py:11", Region: "mA/fn2"})
	edge("body2", "mA\x1fhelper#ret#", "FLOWS")
	edge("mA\x1fhelper#param#x", "body2", "FLOWS")

	// The call's argument flows into helper's parameter, and helper's return
	// flows back into the call. Either direction identifies the callee.
	edge("arg1", "mA\x1fhelper#param#x", "FLOWS")
	edge("mA\x1fhelper#ret#", "call1", "FLOWS")

	// A module-level call, outside any function. It has no region, so it is not
	// the source of a call edge between functions.
	add(usg.Node{ID: "call0", Type: "code.Call", Loc: "app.py:1",
		Props: map[string]string{"callee_path": "require"}})
	return s
}

// The document reported no functions and no call edges for every scan, because
// exportFunctions asked for a node type nothing produces and exportCallEdges read
// a property nothing sets. The graph was fully built either way, so the emptiness
// looked like a scan result rather than a projection that could never work.
func TestFunctionsAreExportedFromRegions(t *testing.T) {
	g := buildTwoFunctionGraph(t)
	fns := exportFunctions(g)
	if len(fns) != 2 {
		t.Fatalf("exported %d function(s), want 2: %+v", len(fns), fns)
	}
	byID := map[string]Function{}
	for _, f := range fns {
		byID[f.ID] = f
	}
	handler, ok := byID["mA/fn1"]
	if !ok {
		t.Fatalf("handler missing; got %v", byID)
	}
	if handler.Name != "handler" {
		t.Errorf("handler name = %q, want %q", handler.Name, "handler")
	}
	if handler.File != "app.py" {
		t.Errorf("handler file = %q, want %q", handler.File, "app.py")
	}
	if handler.Module != "mA" {
		t.Errorf("handler module = %q, want %q", handler.Module, "mA")
	}
	// The region spans the nodes inside it, so the first line is the lowest.
	if handler.LineStart != 4 {
		t.Errorf("handler line_start = %d, want 4", handler.LineStart)
	}
}

func TestCallEdgesAreExportedBetweenRegions(t *testing.T) {
	g := buildTwoFunctionGraph(t)
	edges := exportCallEdges(g)
	if len(edges) != 1 {
		t.Fatalf("exported %d call edge(s), want 1: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.FromFunction != "mA/fn1" || e.ToFunction != "mA/fn2" {
		t.Errorf("call edge %s -> %s, want mA/fn1 -> mA/fn2", e.FromFunction, e.ToFunction)
	}
	if e.CallLine == nil || *e.CallLine != 6 {
		t.Errorf("call line = %v, want 6", e.CallLine)
	}
}

// A module-level call has no enclosing function, so it cannot be one end of an
// edge between functions. It must not invent one.
func TestModuleLevelCallIsNotACallEdge(t *testing.T) {
	g := buildTwoFunctionGraph(t)
	for _, e := range exportCallEdges(g) {
		if e.FromFunction == "" || e.ToFunction == "" {
			t.Errorf("call edge with an empty end: %+v", e)
		}
	}
}

// The count travels in the document, and reporting zero next to a populated
// function list is the contradiction that made the empty payload hard to spot.
func TestCodeMapCountsMatchTheDocument(t *testing.T) {
	doc := Build(buildTwoFunctionGraph(t), nil, nil, ".", "test")
	if doc.CodeMap.FunctionCount != len(doc.Functions) {
		t.Errorf("code_map.function_count = %d, functions = %d",
			doc.CodeMap.FunctionCount, len(doc.Functions))
	}
	if doc.CodeMap.FunctionCount == 0 {
		t.Error("function_count is 0 for a graph with two functions")
	}
}

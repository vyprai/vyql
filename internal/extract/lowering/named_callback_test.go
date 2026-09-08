package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// namedCallbackProgram is the shape a CLI launcher writes: the argument list is escaped by
// handing a NAMED helper to Array.prototype.map — the callback is a first-class function
// reference, not a lambda written at the call site — and the escaped list is spawned.
//
//	function escapeCmdArgs(cmdArgs) { return cmdArgs.replace(/(["^&|<>])/g, "^$1") }
//	function launch(file) { spawn(cmd, [file].map(escapeCmdArgs), {shell: true}) }
//
// escaped decides whether the helper transforms its parameter or hands it straight back, which
// is the only difference between the vulnerable and the fixed revision.
func namedCallbackProgram(escaped bool) nir.Program {
	var body nir.Expr = nir.Name{ID: "cmdArgs", Loc: "launch.js:2"}
	if escaped {
		body = nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "cmdArgs", Loc: "launch.js:2"}, Attr: "replace", Path: "cmdArgs.replace", Loc: "launch.js:2"},
			Args:   []nir.Expr{nir.Const{Value: "([\"^&|<>])", Loc: "launch.js:2"}, nir.Const{Value: "^$1", Loc: "launch.js:2"}},
			Path:   "cmdArgs.replace", Method: "replace", Loc: "launch.js:2",
		}
	}
	return nir.Program{Modules: []nir.Module{{
		Key:  "launch.js",
		File: "launch.js",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "escapeCmdArgs", Loc: "launch.js:1", Params: []string{"cmdArgs"}, Body: []nir.Stmt{
				nir.Return{Value: body},
			}},
			nir.FuncDef{Name: "launch", Loc: "launch.js:5", Params: []string{"file"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"args"}, Decl: true, Loc: "launch.js:6",
					Value: nir.Seq{Parts: []nir.Expr{nir.Name{ID: "file", Loc: "launch.js:6"}}, Loc: "launch.js:6"}},
				nir.Assign{Targets: []string{"cmdArgs"}, Decl: true, Loc: "launch.js:7", Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "args", Loc: "launch.js:7"}, Attr: "map", Path: "args.map", Loc: "launch.js:7"},
					Args:   []nir.Expr{nir.Name{ID: "escapeCmdArgs", Loc: "launch.js:7"}},
					Path:   "args.map", Method: "map", Loc: "launch.js:7",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "spawn", Loc: "launch.js:8"},
					Args:   []nir.Expr{nir.Name{ID: "cmdArgs", Loc: "launch.js:8"}},
					Path:   "spawn", Method: "spawn", Loc: "launch.js:8",
				}},
			}},
		},
	}}}
}

// A callback handed over as a first-class function reference has its body on the flow: the
// receiver's elements reach its parameter, so a control written inside it — the escape helper's
// `replace` — is a node the taint passes through and can be neutralized at.
func TestNamedCallbackReferenceCarriesTaintIntoItsBody(t *testing.T) {
	g, err := Lower(namedCallbackProgram(true), true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "file")
	cbParam := findNodeID(t, g, "code.Param", "func", "escapeCmdArgs", "name", "cmdArgs")
	replace := callNodeByPath(t, g, "cmdArgs.replace")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "launch.js:8")

	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[cbParam] {
		t.Error("the mapped element did not reach the named callback's parameter")
	}
	if !reachable[replace.ID] {
		t.Error("the mapped element did not reach the control inside the callback's body")
	}
	if !reachable[sinkArg] {
		t.Error("the callback's return did not reach the sink")
	}

	// The control is on the path, not beside it: crediting `cmdArgs.replace` as a neutralizer
	// clears the flow, which is what tells an escaping revision from a non-escaping one.
	label(t, g, src, "test.Source")
	label(t, g, sinkArg, "test.Sink")
	flows := taintFlows(t, g, nil)
	if len(flows) != 1 {
		t.Fatalf("want one uncredited flow to the spawn argument, got %d", len(flows))
	}
	label(t, g, replace.ID, "test.Escape")
	if flows := taintFlows(t, g, map[string]bool{"test.Escape": true}); len(flows) != 0 {
		t.Fatalf("a control inside the callback body did not neutralize the flow, got %d flows", len(flows))
	}
}

// The result of `arr.map(fn)` is what fn RETURNS, so a named callback that drops its parameter
// leaves the mapped list clean. Without the body on the flow the receiver's taint jumped
// straight to the call result and no in-body transform could ever be seen.
func TestNamedCallbackResultComesFromTheCallbackReturn(t *testing.T) {
	prog := namedCallbackProgram(true)
	// escapeCmdArgs returns a constant instead of anything derived from its parameter.
	fn := prog.Modules[0].Body[0].(nir.FuncDef)
	fn.Body = []nir.Stmt{nir.Return{Value: nir.Const{Value: "--", Loc: "launch.js:2"}}}
	prog.Modules[0].Body[0] = fn

	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "file")
	cbParam := findNodeID(t, g, "code.Param", "func", "escapeCmdArgs", "name", "cmdArgs")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "launch.js:8")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[cbParam] {
		t.Error("the mapped element did not reach the named callback's parameter")
	}
	if reachable[sinkArg] {
		t.Error("the receiver's taint reached the sink without passing through the callback's return")
	}
}

// A method whose result is the receiver's own elements keeps its direct receiver→result edge:
// `arr.filter(pred)` returns elements of arr, whatever pred returns.
func TestNamedCallbackKeepsReceiverResultEdgeForFilter(t *testing.T) {
	prog := namedCallbackProgram(true)
	fn := prog.Modules[0].Body[0].(nir.FuncDef)
	fn.Body = []nir.Stmt{nir.Return{Value: nir.Const{Value: "true", Loc: "launch.js:2"}}}
	prog.Modules[0].Body[0] = fn
	launch := prog.Modules[0].Body[1].(nir.FuncDef)
	mapAssign := launch.Body[1].(nir.Assign)
	mapCall := mapAssign.Value.(nir.Call)
	mapCall.Callee = nir.Attr{Base: nir.Name{ID: "args", Loc: "launch.js:7"}, Attr: "filter", Path: "args.filter", Loc: "launch.js:7"}
	mapCall.Path, mapCall.Method = "args.filter", "filter"
	mapAssign.Value = mapCall
	launch.Body[1] = mapAssign
	prog.Modules[0].Body[1] = launch

	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "file")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "launch.js:8")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Error("filter dropped the receiver's taint; its result is the receiver's own elements")
	}
}

func label(t *testing.T, g usg.Store, nodeID, concept string) {
	t.Helper()
	if err := g.AddLabel(nodeID, usg.Label{Concept: concept}); err != nil {
		t.Fatal(err)
	}
}

func taintFlows(t *testing.T, g usg.Store, kills map[string]bool) []solvers.TaintFlow {
	t.Helper()
	flows, err := solvers.FindTaintFlows(g,
		map[string]bool{"test.Source": true}, map[string]bool{"test.Sink": true},
		map[string]bool{"test.Kind": true}, kills, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return flows
}

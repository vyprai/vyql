package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// closureCallbackProgram is the shape an event pipeline writes: the escaping helper is handed
// over as a function-valued parameter, and the parameter is invoked from a function NESTED
// `depth` levels below the one that received it.
//
//	function escapeCmdArgs(cmdArgs) { return cmdArgs.replace(/(["^&|<>])/g, "^$1") }
//	function run(escape, file) {
//	  function mid() {                   // the extra level, depth 2
//	    function inner() { return escape(file) }
//	    return inner()
//	  }
//	  return mid()
//	}
//	function launch(file) { return run(escapeCmdArgs, file) }
//
// Each nested function captures `escape` through a lexical binding promoted out of the
// enclosing scope, which is where the parameter identity is lost.
func closureCallbackProgram(depth int) nir.Program {
	invocation := []nir.Stmt{
		nir.Return{Value: nir.Call{
			Callee: nir.Name{ID: "escape", Loc: "launch.js:3"},
			Args:   []nir.Expr{nir.Name{ID: "file", Loc: "launch.js:3"}},
			Path:   "escape", Loc: "launch.js:3",
		}},
	}
	// wrap the invocation in `depth` nested function declarations, each calling the one below
	for i := 0; i < depth; i++ {
		name, ret := "inner", nir.Name{ID: "escape", Loc: "launch.js:3"}
		if i > 0 {
			name, ret = "mid", nir.Name{ID: "inner", Loc: "launch.js:3"}
		}
		invocation = []nir.Stmt{
			nir.FuncDef{Name: name, Loc: "launch.js:3", Body: invocation},
			nir.Return{Value: nir.Call{Callee: ret, Path: "inner", Loc: "launch.js:4"}},
		}
	}
	return nir.Program{Modules: []nir.Module{{
		Key:  "launch.js",
		File: "launch.js",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "escapeCmdArgs", Loc: "launch.js:1", Params: []string{"cmdArgs"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "cmdArgs", Loc: "launch.js:1"}, Attr: "replace", Path: "cmdArgs.replace", Loc: "launch.js:1"},
					Args:   []nir.Expr{nir.Const{Value: "([\"^&|<>])", Loc: "launch.js:1"}, nir.Const{Value: "^$1", Loc: "launch.js:1"}},
					Path:   "cmdArgs.replace", Method: "replace", Loc: "launch.js:1",
				}},
			}},
			nir.FuncDef{Name: "run", Loc: "launch.js:2", Params: []string{"escape", "file"}, Body: invocation},
			nir.FuncDef{Name: "launch", Loc: "launch.js:6", Params: []string{"file"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Call{
					Callee: nir.Name{ID: "run", Loc: "launch.js:6"},
					Args:   []nir.Expr{nir.Name{ID: "escapeCmdArgs", Loc: "launch.js:6"}, nir.Name{ID: "file", Loc: "launch.js:6"}},
					Path:   "run", Loc: "launch.js:6",
				}},
			}},
		},
	}}}
}

// A parameter call written inside a nested closure reaches the function bound to that
// parameter: the closure's capture is a lexical stand-in for the caller's parameter, not a
// different name, so the dispatch a parameter call gets at the top level still fires. Without
// it the call is unresolved, the helper's body stays off the flow, and a control written
// inside it (`cmdArgs.replace`) can neither carry the taint nor neutralize it.
func TestCallbackParamInvokedInNestedClosureReachesItsTarget(t *testing.T) {
	for _, depth := range []int{1, 2} {
		t.Run("depth"+string(rune('0'+depth)), func(t *testing.T) {
			g, err := Lower(closureCallbackProgram(depth), true)
			if err != nil {
				t.Fatal(err)
			}
			src := findNodeID(t, g, "code.Param", "func", "launch", "name", "file")
			cbParam := findNodeID(t, g, "code.Param", "func", "escapeCmdArgs", "name", "cmdArgs")
			replace := callNodeByPath(t, g, "cmdArgs.replace")
			sinkArg := findNodeID(t, g, "code.Arg", "loc", "launch.js:4")

			reachable, err := usg.BFS(g, src, "FLOWS", 40)
			if err != nil {
				t.Fatal(err)
			}
			if !reachable[cbParam] {
				t.Error("the argument did not reach the parameter bound to the callback held in the closure")
			}
			if !reachable[replace.ID] {
				t.Error("the argument did not reach the control inside the callback's body")
			}
			if !reachable[sinkArg] {
				t.Error("the callback's return did not reach the enclosing call")
			}

			// The control is on the path, not beside it: crediting `cmdArgs.replace` as a
			// neutralizer clears the flow, which is what tells an escaping revision from a
			// non-escaping one.
			label(t, g, src, "test.Source")
			label(t, g, sinkArg, "test.Sink")
			if flows := taintFlows(t, g, nil); len(flows) != 1 {
				t.Fatalf("want one uncredited flow into the nested closure's call, got %d", len(flows))
			}
			label(t, g, replace.ID, "test.Escape")
			if flows := taintFlows(t, g, map[string]bool{"test.Escape": true}); len(flows) != 0 {
				t.Fatalf("a control inside the callback body did not neutralize the flow, got %d flows", len(flows))
			}
		})
	}
}

package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// higherOrderCall builds `handler(input) { apply(<cb>, <second>) }` — one call taking a
// callback plus a second argument, which is the shape every higher-order helper has.
func higherOrderCall(cb nir.Lambda, second nir.Expr) nir.Program {
	return nir.Program{Modules: []nir.Module{{Key: "app.js", File: "app.js", Body: []nir.Stmt{
		nir.FuncDef{Name: "handler", Params: []string{"input"}, Loc: "app.js:1", Body: []nir.Stmt{
			nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "apply", Loc: "app.js:2"},
				Args:   []nir.Expr{cb, second},
				Path:   "apply", Method: "apply", Loc: "app.js:2",
			}},
		}},
	}}}}
}

// sinkCallback is `v => db.query(v)`: a callback whose parameter is consumed by a call
// inside its own body, which is where the value a higher-order call hands it is used.
func sinkCallback() nir.Lambda {
	return nir.Lambda{Params: []string{"v"}, Loc: "app.js:2", Body: []nir.Stmt{
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "db", Loc: "app.js:3"}, Attr: "query", Path: "db.query", Loc: "app.js:3"},
			Args:   []nir.Expr{nir.Name{ID: "v", Loc: "app.js:3"}},
			Path:   "db.query", Method: "query", Loc: "app.js:3",
		}},
	}}
}

// callArg returns the Arg slot at index i of the call with the given callee path.
func callArg(t *testing.T, g usg.Store, calleePath string, i int) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Prop("callee_path") == calleePath {
			if arg := n.Prop(usg.ArgPropKey(i)); arg != "" {
				return arg
			}
			t.Fatalf("call %s has no arg%d", calleePath, i)
		}
	}
	t.Fatalf("no call to %s", calleePath)
	return ""
}

// A callback passed to a call is invoked BY THE CALLEE with what that call was given, so a
// value handed to the call alongside it reaches the callback's parameter — and through it
// every sink inside the callback's body. Without this the body is reachable only through
// what it captured, and the value is followed only where the call's own return carries it.
func TestHigherOrderCallArgumentReachesCallbackBody(t *testing.T) {
	g, err := Lower(higherOrderCall(sinkCallback(), nir.Name{ID: "input", Loc: "app.js:2"}), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "input")
	sink := callArg(t, g, "db.query", 0)
	reachable, err := usg.BFS(g, src, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sink] {
		t.Fatal("the argument handed to a higher-order call did not reach the callback's body")
	}
}

// A callback passed alongside another callback is not a value either of them is invoked
// with — it is the callee's business, not data — so no edge is drawn between them.
func TestHigherOrderCallDoesNotFeedOneCallbackToAnother(t *testing.T) {
	other := nir.Lambda{Params: []string{"w"}, Loc: "app.js:2", Body: []nir.Stmt{
		nir.ExprStmt{Value: nir.Name{ID: "w", Loc: "app.js:2"}},
	}}
	g, err := Lower(higherOrderCall(sinkCallback(), other), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "w")
	sink := callArg(t, g, "db.query", 0)
	reachable, err := usg.BFS(g, src, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sink] {
		t.Fatal("a sibling callback argument was routed into the other callback's parameter")
	}
}

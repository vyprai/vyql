package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// inPlaceProgram is one function that passes `subject` to a mutator alongside an
// unrelated second argument, then reads `subject` again at a later call.
func inPlaceProgram(effects []nir.CallEffect) nir.Program {
	return nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:   "handler",
				Params: []string{"subject", "other"},
				Loc:    "app.py:1",
				Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee:  nir.Name{ID: "scrub", Loc: "app.py:2"},
						Path:    "scrub",
						Method:  "scrub",
						Loc:     "app.py:2",
						Args:    []nir.Expr{nir.Name{ID: "subject", Loc: "app.py:2"}, nir.Name{ID: "other", Loc: "app.py:2"}},
						Effects: effects,
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "app.py:3"},
						Path:   "sink",
						Method: "sink",
						Loc:    "app.py:3",
						Args:   []nir.Expr{nir.Name{ID: "subject", Loc: "app.py:3"}},
					}},
				},
			},
		},
	}}}
}

// An in-place mutation re-binds its destination to the call's ARGUMENT SLOT, so
// the later read of the same variable is a successor of the slot the call wrote
// through rather than a sibling of it off their shared definition. That is what
// puts a concept a binding labelled at the argument on the later read's path;
// without it a check applied to a variable discharges only its own use of it.
func TestInPlaceEffectRoutesALaterReadThroughTheMutatedArgument(t *testing.T) {
	g, err := Lower(inPlaceProgram([]nir.CallEffect{{DestArg: 0, SourceArg: 0, InPlace: true}}), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	subject := findNodeID(t, g, "code.Param", "name", "subject")
	other := findNodeID(t, g, "code.Param", "name", "other")
	mutated := argNodeInto(t, g, "app.py:2", subject)
	read := findNodeID(t, g, "code.Arg", "loc", "app.py:3")

	reachable, err := usg.BFS(g, mutated, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[read] {
		t.Fatal("the later read is not downstream of the argument the call mutated")
	}
	// The value the variable already carried still reaches the read: re-binding
	// re-routes the flow, it does not cut it.
	if reachable, err = usg.BFS(g, subject, "FLOWS", 20); err != nil {
		t.Fatal(err)
	} else if !reachable[read] {
		t.Fatal("re-binding lost the value the mutated variable already carried")
	}
	// And it re-binds to the slot, not to the call: a sibling argument's value
	// does not become part of what the mutated variable holds.
	if reachable, err = usg.BFS(g, other, "FLOWS", 20); err != nil {
		t.Fatal(err)
	} else if reachable[read] {
		t.Fatal("re-binding joined the call's other arguments into the mutated variable")
	}
}

// Without the effect the two reads are siblings: the call's own argument leads
// nowhere but the call.
func TestWithoutAnInPlaceEffectTheReadsStaySiblings(t *testing.T) {
	g, err := Lower(inPlaceProgram(nil), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	subject := findNodeID(t, g, "code.Param", "name", "subject")
	mutated := argNodeInto(t, g, "app.py:2", subject)
	read := findNodeID(t, g, "code.Arg", "loc", "app.py:3")

	reachable, err := usg.BFS(g, mutated, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[read] {
		t.Fatal("an unannotated call must not chain a later read through its argument")
	}
}

// argNodeInto returns the code.Arg node at loc whose value came from src.
func argNodeInto(t *testing.T, g usg.Store, loc, src string) string {
	t.Helper()
	edges, err := g.OutEdges(src, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edges {
		n, ok, err := g.GetNode(e.Dst)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Type == "code.Arg" && n.Prop("loc") == loc {
			return n.ID
		}
	}
	t.Fatalf("no code.Arg at %s fed by %s", loc, src)
	return ""
}

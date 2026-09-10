package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// keywordCall is one call whose arguments are all spelled as keywords, the way a
// caller passes to a constructor that documents `f(diff=None, delta_path=None)`.
func keywordCall() nir.Program {
	return nir.Program{Modules: []nir.Module{{Key: "app", File: "app.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "handler", Params: []string{"payload"}, Loc: "app.py:1", Body: []nir.Stmt{
			nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "Delta", Loc: "app.py:2"},
				Path:   "Delta", Method: "Delta", Loc: "app.py:2",
				Args: []nir.Expr{
					nir.Pair{Key: "diff", Value: nir.Name{ID: "payload", Loc: "app.py:2"}, Loc: "app.py:2"},
					nir.Pair{Key: "raise_errors", Value: nir.Const{Loc: "app.py:2", Value: "True"}, Loc: "app.py:2"},
				},
			}},
		}},
	}}}}
}

// A keyword argument's slot names the keyword, so a sink can address the
// argument the callee documents instead of the position it happens to occupy at
// one call site. Without the name the slot is only a structured value -- the
// pair is lowered as a Seq-kind argument, which scalar sinks skip -- and a call
// that passes everything by keyword carries no sink label at all.
func TestKeywordArgumentSlotCarriesItsName(t *testing.T) {
	g, err := Lower(keywordCall(), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Prop("callee_path") != "Delta" {
			continue
		}
		calls++
		for slot, want := range map[int]string{0: "diff", 1: "raise_errors"} {
			arg := n.Prop(usg.ArgPropKey(slot))
			if arg == "" {
				t.Fatalf("call has no arg%d slot", slot)
			}
			an, ok, err := g.GetNode(arg)
			if err != nil || !ok {
				t.Fatalf("arg%d slot %q is not in the graph", slot, arg)
			}
			if got := an.Prop("kwarg"); got != want {
				t.Fatalf("arg%d kwarg = %q, want %q (props=%v)", slot, got, want, an.Props)
			}
		}
	}
	if calls != 1 {
		t.Fatalf("expected one Delta call, got %d", calls)
	}
}

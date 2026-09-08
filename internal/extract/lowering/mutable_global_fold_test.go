package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// mutableGlobalProgram is a file that declares a flag, gates a call on it in one function,
// and writes it from another — the shape of a runtime-configurable feature switch. `writes`
// says whether the second function exists; without it the flag really is a constant.
//
// The `if` arm calls `sink(input)` and the `else` arm calls `safe(input)`, so which arms
// survive lowering is readable from the calls that ended up in the graph.
func mutableGlobalProgram(init nir.Expr, cond nir.Expr, writes bool) nir.Program {
	body := []nir.Stmt{
		nir.Assign{Targets: []string{"debugMode"}, Value: init, Loc: "app.c:1"},
		nir.FuncDef{Name: "handle", Params: []string{"input"}, Loc: "app.c:3", Body: []nir.Stmt{
			nir.If{
				Cond: cond,
				Then: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.c:5"},
					Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app.c:5"}},
					Path:   "sink", Method: "sink", Loc: "app.c:5",
				}}},
				Else: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "safe", Loc: "app.c:7"},
					Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app.c:7"}},
					Path:   "safe", Method: "safe", Loc: "app.c:7",
				}}},
			},
		}},
	}
	if writes {
		body = append(body, nir.FuncDef{Name: "enableDebug", Loc: "app.c:10", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"debugMode"}, Value: nir.Const{Value: "true", Loc: "app.c:11"}, Loc: "app.c:11"},
		}})
	}
	return nir.Program{Modules: []nir.Module{{Key: "app.c", File: "app.c", Body: body}}}
}

// calleePaths returns the callee path of every call node in the graph.
func calleePaths(t *testing.T, g usg.Store) map[string]bool {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			out[n.Prop("callee_path")] = true
		}
	}
	return out
}

// A module-level variable another function in the same file writes is not a constant, so its
// declaration-site initializer must not fold a branch that reads it. Folding does not merely
// lose precision: the arm the fold disagrees with is never lowered, so the calls inside it are
// absent from the graph entirely and no binding or rule can see them — on the vulnerable and
// the fixed revision alike. `static int debugMode = 0;` plus an `enable_debug()` elsewhere in
// the file is the shape; the flag reads false at its declaration and true at runtime.
func TestMutableModuleGlobalDoesNotFoldBranch(t *testing.T) {
	for _, tc := range []struct {
		name string
		init nir.Expr
		cond nir.Expr
	}{
		{
			name: "boolean flag",
			init: nir.Const{Value: "false", Loc: "app.c:1"},
			cond: nir.Name{ID: "debugMode", Loc: "app.c:4"},
		},
		{
			name: "integer flag compared",
			init: nir.Const{Value: "0", Loc: "app.c:1"},
			cond: nir.BinOp{
				Op:    "==",
				Left:  nir.Name{ID: "debugMode", Loc: "app.c:4"},
				Right: nir.Const{Value: "1", Loc: "app.c:4"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := Lower(mutableGlobalProgram(tc.init, tc.cond, true), true)
			if err != nil {
				t.Fatalf("lower: %v", err)
			}
			defer g.Close()
			paths := calleePaths(t, g)
			if !paths["sink"] {
				t.Error("the taken arm of a branch gated by a mutable global was folded away")
			}
			if !paths["safe"] {
				t.Error("the untaken arm of a branch gated by a mutable global was folded away")
			}
		})
	}
}

// The refusal is scoped to globals the module actually writes: a top-level initializer nobody
// overwrites still folds, so this does not turn off constant folding for every file.
func TestUnwrittenModuleGlobalStillFoldsBranch(t *testing.T) {
	g, err := Lower(mutableGlobalProgram(
		nir.Const{Value: "false", Loc: "app.c:1"},
		nir.Name{ID: "debugMode", Loc: "app.c:4"},
		false,
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	defer g.Close()
	paths := calleePaths(t, g)
	if paths["sink"] {
		t.Error("a branch gated by a global the file never writes did not fold")
	}
	if !paths["safe"] {
		t.Error("the surviving arm of a folded branch is missing")
	}
}

// Const-propagation inside ONE function body is unaffected: the write and the read are on the
// same path, in order, so the fold is a fact about that path rather than about the file.
func TestLocalWriteBeforeBranchStillFolds(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{Key: "app.c", File: "app.c", Body: []nir.Stmt{
		nir.Assign{Targets: []string{"debugMode"}, Value: nir.Const{Value: "false", Loc: "app.c:1"}, Loc: "app.c:1"},
		nir.FuncDef{Name: "handle", Params: []string{"input"}, Loc: "app.c:3", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"debugMode"}, Value: nir.Const{Value: "true", Loc: "app.c:4"}, Loc: "app.c:4"},
			nir.If{
				Cond: nir.Name{ID: "debugMode", Loc: "app.c:5"},
				Then: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.c:6"},
					Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app.c:6"}},
					Path:   "sink", Method: "sink", Loc: "app.c:6",
				}}},
				Else: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "safe", Loc: "app.c:8"},
					Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app.c:8"}},
					Path:   "safe", Method: "safe", Loc: "app.c:8",
				}}},
			},
		}},
	}}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	defer g.Close()
	paths := calleePaths(t, g)
	if !paths["sink"] {
		t.Error("a branch folded on a value written earlier in the same body lost the taken arm")
	}
	if paths["safe"] {
		t.Error("a branch folded on a value written earlier in the same body kept the dead arm")
	}
}

// A declaration inside a body introduces that body's own binding, so a language whose
// frontend marks declarations does not lose the module constant to a shadowing local.
func TestShadowingLocalDeclarationDoesNotDisqualifyGlobal(t *testing.T) {
	stmts := []nir.Stmt{
		nir.Assign{Targets: []string{"debugMode"}, Value: nir.Const{Value: "false", Loc: "app.js:1"}, Decl: true, Loc: "app.js:1"},
		nir.FuncDef{Name: "other", Loc: "app.js:3", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"debugMode"}, Value: nir.Const{Value: "true", Loc: "app.js:4"}, Decl: true, Loc: "app.js:4"},
		}},
	}
	if got := (&lowerer{}).moduleMutatedGlobals(stmts); len(got) != 0 {
		t.Errorf("moduleMutatedGlobals = %v, want empty: a shadowing declaration is not a write", got)
	}
	stmts[1].(nir.FuncDef).Body[0] = nir.Assign{
		Targets: []string{"debugMode"}, Value: nir.Const{Value: "true", Loc: "app.js:4"}, Loc: "app.js:4",
	}
	if got := (&lowerer{}).moduleMutatedGlobals(stmts); !got["debugMode"] {
		t.Errorf("moduleMutatedGlobals = %v, want debugMode: a bare assignment in a body is a write", got)
	}
}

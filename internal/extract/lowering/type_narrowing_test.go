package lowering

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// narrowUse builds module "use": f(h) { if (h instanceof <typ>) sink(h) else other(h) } —
// one read inside the narrowed arm and one outside it.
func narrowUse(hash, typ string) nir.Module {
	return nir.Module{Key: "use", File: "Use.java", Hash: hash, Body: []nir.Stmt{
		nir.FuncDef{Name: "f", Params: []string{"h"}, Loc: "Use.java:1", Body: []nir.Stmt{
			nir.If{Loc: "Use.java:2",
				Cond: nir.BinOp{Op: "instanceof",
					Left:  nir.Name{ID: "h", Loc: "Use.java:2"},
					Right: nir.Const{Value: typ, Loc: "Use.java:2"}},
				Then: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "readObject", Loc: "Use.java:3"}, Path: "readObject", Method: "readObject",
					Args: []nir.Expr{nir.Name{ID: "h", Loc: "Use.java:3"}}, Loc: "Use.java:3"}}},
				Else: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "skip", Loc: "Use.java:5"}, Path: "skip", Method: "skip",
					Args: []nir.Expr{nir.Name{ID: "h", Loc: "Use.java:5"}}, Loc: "Use.java:5"}}},
			},
		}},
	}}
}

// declType builds module "types" declaring one class of the given visibility.
func declType(hash, name string, exported bool) nir.Module {
	return nir.Module{Key: "types", File: "Types.java", Hash: hash, Body: []nir.Stmt{
		nir.ClassDef{Name: name, Exported: exported, Loc: "Types.java:1"},
	}}
}

// typeNarrowingGuardTokens returns the str_args of the (single) type-narrowing guard.
func typeNarrowingGuardTokens(t *testing.T, g usg.Store) string {
	t.Helper()
	id := findNodeID(t, g, "code.Call", "callee_path", "analysis.guard.type_narrowing")
	n, ok, err := g.GetNode(id)
	if err != nil || !ok {
		t.Fatalf("guard node %q vanished: %v %v", id, ok, err)
	}
	return n.Prop("str_args")
}

// An instanceof narrowing emits the guard relation: a type_narrowing call on the tested
// value's path through the NARROWED arm, carrying the checked type and the registry's
// visibility fact for it, and typing in-arm reads as the checked type.
func TestTypeNarrowingIfBoundsBranchReadsThroughGuard(t *testing.T) {
	g, err := Lower(prog(declType("t1", "PkgPrivateHeader", false), narrowUse("u1", "PkgPrivateHeader")), true)
	if err != nil {
		t.Fatal(err)
	}
	if toks := typeNarrowingGuardTokens(t, g); !strings.Contains(toks, "type=PkgPrivateHeader") ||
		!strings.Contains(toks, "visibility=non_public") {
		t.Fatalf("guard tokens = %q, want type=PkgPrivateHeader and visibility=non_public", toks)
	}
	guard := findNodeID(t, g, "code.Call", "callee_path", "analysis.guard.type_narrowing")
	if n, ok, _ := g.GetNode(guard); !ok || n.Prop("decl_type") != "PkgPrivateHeader" {
		t.Fatalf("guard decl_type missing: narrowed reads must resolve as the checked type")
	}
	// on-path in the narrowed arm: param -> guard -> sink arg; the other arm's read is
	// not routed through the guard.
	param := findNodeID(t, g, "code.Param", "name", "h")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "Use.java:3")
	elseArg := findNodeID(t, g, "code.Arg", "loc", "Use.java:5")
	fromParam, err := usg.BFS(g, param, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromParam[guard] {
		t.Fatalf("guard not reachable from the narrowed value")
	}
	fromGuard, err := usg.BFS(g, guard, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromGuard[sinkArg] {
		t.Fatalf("narrowed-arm sink argument not reachable through the guard")
	}
	if fromGuard[elseArg] {
		t.Fatalf("other-arm read routed through the narrowing guard")
	}
}

// A bare class name declared by more than one module has no single visibility fact to
// attribute; the token says unknown rather than guessing.
func TestTypeNarrowingAmbiguousClassNameWithholdsVisibility(t *testing.T) {
	g, err := Lower(prog(
		nir.Module{Key: "types", File: "Types.java", Hash: "t1", Body: []nir.Stmt{
			nir.ClassDef{Name: "Dup", Loc: "Types.java:1"}}},
		nir.Module{Key: "types2", File: "Types2.java", Hash: "t2", Body: []nir.Stmt{
			nir.ClassDef{Name: "Dup", Exported: true, Loc: "Types2.java:1"}}},
		nir.Module{Key: "use", File: "Use.java", Hash: "u1", Body: []nir.Stmt{
			nir.FuncDef{Name: "f", Params: []string{"h"}, Loc: "Use.java:1", Body: []nir.Stmt{
				nir.If{Loc: "Use.java:2",
					Cond: nir.BinOp{Op: "instanceof",
						Left:  nir.Name{ID: "h", Loc: "Use.java:2"},
						Right: nir.Const{Value: "Dup", Loc: "Use.java:2"}},
					Then: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "readObject", Loc: "Use.java:3"}, Path: "readObject", Method: "readObject",
						Args: []nir.Expr{nir.Name{ID: "h", Loc: "Use.java:3"}}, Loc: "Use.java:3"}}},
				},
			}},
		}}), true)
	if err != nil {
		t.Fatal(err)
	}
	if toks := typeNarrowingGuardTokens(t, g); !strings.Contains(toks, "visibility=unknown") {
		t.Fatalf("guard tokens = %q, want visibility=unknown for an ambiguous class name", toks)
	}
}

// The visibility fact lives in pass 1: a module whose body lowering READS it (its
// instanceof guard tokens) must re-lower when another module's declaration flips
// visibility, exactly as a signature move forces it. The equivalence gate fails if the
// fingerprint omits the fact or the pass-1 delta fails to replay it.
func TestTypeNarrowingVisibilityChangeInvalidatesBodyCache(t *testing.T) {
	v1 := prog(declType("t1", "GuardedHeader", false), narrowUse("u1", "GuardedHeader"))
	v2 := prog(declType("t2", "GuardedHeader", true), narrowUse("u1", "GuardedHeader"))
	cache := memDelta{}
	_ = lowerInc(t, v1, cache)
	got := snapshot(t, lowerInc(t, v2, cache))
	want := snapshot(t, lowerFull(t, v2))
	if got != want {
		t.Fatalf("incremental graph != full graph after a visibility flip\n--- incremental ---\n%s\n--- full ---\n%s", got, want)
	}
	if toks := typeNarrowingGuardTokens(t, lowerFull(t, v2)); !strings.Contains(toks, "visibility=public") {
		t.Fatalf("guard tokens = %q, want visibility=public after the flip", toks)
	}
}

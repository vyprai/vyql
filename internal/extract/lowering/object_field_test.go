package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// The shapes below are the ones a property write and a property read are split across two
// calls by. A field slot is per (object node, field name), and the object the callee mutates
// has to be recognised as the object the caller later reads.

// fieldWrite is `<base>.<field> = <value>` in the form every frontend emits it: a call with no
// method on the member access, carrying the assigned value as its only argument.
func fieldWrite(base nir.Expr, path, field string, value nir.Expr, loc string) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: base, Attr: field, Path: path, Loc: loc},
		Args:   []nir.Expr{value},
		Path:   path, Loc: loc,
	}}
}

func thisExpr(loc string) nir.Expr { return nir.Name{ID: "this", Loc: loc} }

// sinkCall is a call to an unresolved external function, so its argument node is a stable
// stand-in for "the value reached a sink here".
func sinkCall(arg nir.Expr, loc string) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "render", Loc: loc},
		Args:   []nir.Expr{arg},
		Path:   "render", Method: "render", Loc: loc,
	}}
}

func reachesArg(t *testing.T, g usg.Store, from, argLoc string) bool {
	t.Helper()
	reachable, err := usg.BFS(g, from, "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := g.NodesOfType("code.Arg")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Loc == argLoc && reachable[id] {
			return true
		}
	}
	return false
}

// holderClass is `class Holder { <ctor>(v) { this.<wf> = v } render() { render(this.<rf>) } }`.
func holderClass(ctorName, writeField, readField string) nir.Stmt {
	return nir.ClassDef{Name: "Holder", Loc: "h.js:1", Body: []nir.Stmt{
		nir.FuncDef{Name: ctorName, Params: []string{"v"}, Loc: "h.js:2", Body: []nir.Stmt{
			fieldWrite(thisExpr("h.js:3"), "this."+writeField, writeField, nir.Name{ID: "v", Loc: "h.js:3"}, "h.js:3"),
		}},
		nir.FuncDef{Name: "render", Loc: "h.js:4", Body: []nir.Stmt{
			sinkCall(nir.Attr{Base: thisExpr("h.js:5"), Attr: readField, Path: "this." + readField, Loc: "h.js:5"}, "h.js:5"),
		}},
	}}
}

func TestFieldWrittenByAConstructorReachesAMethodThatReadsIt(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			holderClass("constructor", "p", "p"),
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.js:6", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"h"}, Decl: true, Loc: "h.js:7", Value: nir.Call{
					Callee: nir.Name{ID: "Holder", Loc: "h.js:7"},
					Args:   []nir.Expr{nir.Name{ID: "q", Loc: "h.js:7"}},
					Path:   "Holder", Method: "Holder", Loc: "h.js:7",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "h.js:8"}, Attr: "render", Path: "h.render", Loc: "h.js:8"},
					Path:   "h.render", Method: "render", Loc: "h.js:8",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.js:5") {
		t.Fatal("a value the constructor stored on a field did not reach the method that reads that field")
	}
}

func TestFieldWrittenByOneMethodReachesAnotherMethodThatReadsIt(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			holderClass("store", "p", "p"),
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.js:6", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"h"}, Decl: true, Type: "Holder", Loc: "h.js:7",
					Value: nir.Const{Loc: "h.js:7"}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "h.js:8"}, Attr: "store", Path: "h.store", Loc: "h.js:8"},
					Args:   []nir.Expr{nir.Name{ID: "q", Loc: "h.js:8"}},
					Path:   "h.store", Method: "store", Loc: "h.js:8",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "h.js:9"}, Attr: "render", Path: "h.render", Loc: "h.js:9"},
					Path:   "h.render", Method: "render", Loc: "h.js:9",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.js:5") {
		t.Fatal("a value one method stored on a field did not reach the sibling method that reads it")
	}
}

// A sibling field is the precision half of the same mechanism: sharing `this` across a class's
// methods must not make every field of it one slot. Same program as the constructor case,
// with the reading method reading a DIFFERENT field.
func TestASiblingFieldStaysCleanAcrossMethods(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			holderClass("constructor", "written", "other"),
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.js:6", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"h"}, Decl: true, Loc: "h.js:7", Value: nir.Call{
					Callee: nir.Name{ID: "Holder", Loc: "h.js:7"},
					Args:   []nir.Expr{nir.Name{ID: "q", Loc: "h.js:7"}},
					Path:   "Holder", Method: "Holder", Loc: "h.js:7",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "h.js:8"}, Attr: "render", Path: "h.render", Loc: "h.js:8"},
					Path:   "h.render", Method: "render", Loc: "h.js:8",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.js:5") {
		t.Fatal("a read of a DIFFERENT field of the same object saw the written field's slot")
	}
}

// The caller holds a plain object, one call fills a property on it and a second reads that
// property back. Neither function has the object's field in hand when its own body is lowered.
func TestAPropertyFilledThroughAParameterReachesTheCallersLaterRead(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "fill", Params: []string{"o", "v"}, Loc: "h.js:1", Body: []nir.Stmt{
				fieldWrite(nir.Name{ID: "o", Loc: "h.js:2"}, "o.p", "p", nir.Name{ID: "v", Loc: "h.js:2"}, "h.js:2"),
			}},
			nir.FuncDef{Name: "read", Params: []string{"o"}, Loc: "h.js:3", Body: []nir.Stmt{
				nir.Return{Value: nir.Attr{Base: nir.Name{ID: "o", Loc: "h.js:4"}, Attr: "p", Path: "o.p", Loc: "h.js:4"}},
			}},
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.js:5", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"o"}, Decl: true, Loc: "h.js:6", Value: nir.Seq{Loc: "h.js:6"}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "fill", Loc: "h.js:7"},
					Args:   []nir.Expr{nir.Name{ID: "o", Loc: "h.js:7"}, nir.Name{ID: "q", Loc: "h.js:7"}},
					Path:   "fill", Method: "fill", Loc: "h.js:7",
				}},
				sinkCall(nir.Call{
					Callee: nir.Name{ID: "read", Loc: "h.js:8"},
					Args:   []nir.Expr{nir.Name{ID: "o", Loc: "h.js:8"}},
					Path:   "read", Method: "read", Loc: "h.js:8",
				}, "h.js:8"),
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.js:8") {
		t.Fatal("a property one call filled on the caller's object did not reach the call that reads it back")
	}
}

// Resolving the constructor must not cost the wrapper-object approximation: the object a
// construction yields still carries what was passed to it, whatever the constructor stores.
func TestConstructorArgumentsStillTaintTheConstructedObject(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Holder", Loc: "h.js:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "constructor", Params: []string{"v"}, Loc: "h.js:2", Body: []nir.Stmt{
					fieldWrite(thisExpr("h.js:3"), "this.p", "p", nir.Name{ID: "v", Loc: "h.js:3"}, "h.js:3"),
				}},
			}},
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.js:4", Body: []nir.Stmt{
				sinkCall(nir.Call{
					Callee: nir.Name{ID: "Holder", Loc: "h.js:5"},
					Args:   []nir.Expr{nir.Name{ID: "q", Loc: "h.js:5"}},
					Path:   "Holder", Method: "Holder", Loc: "h.js:5",
				}, "h.js:5"),
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.js:5") {
		t.Fatal("the object a resolved constructor builds does not carry the argument it was given")
	}
}

// A bare member written with an operator — Ruby's `@x ||= v`, the memoization idiom — is the
// same member write `x = v` is. The plain spelling stores into the node a read of the member
// resolves to; the operator spelling has to store there too, or a memoizing writer in one
// method and a reader in a sibling stay two unrelated bindings.
func TestAMemberWrittenThroughAnOperatorReachesTheMethodThatReadsIt(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.rb",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Holder", Members: []string{"@p"}, Loc: "h.rb:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "store", Params: []string{"v"}, Loc: "h.rb:2", Body: []nir.Stmt{
					nir.AugAssign{Target: "@p", Value: nir.Name{ID: "v", Loc: "h.rb:3"}, Loc: "h.rb:3"},
				}},
				nir.FuncDef{Name: "render", Loc: "h.rb:4", Body: []nir.Stmt{
					sinkCall(nir.Name{ID: "@p", Loc: "h.rb:5"}, "h.rb:5"),
				}},
			}},
			nir.FuncDef{Name: "go", Params: []string{"q"}, Loc: "h.rb:6", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "store", Loc: "h.rb:7"},
					Args:   []nir.Expr{nir.Name{ID: "q", Loc: "h.rb:7"}},
					Path:   "store", Method: "store", Loc: "h.rb:7",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "q"), "h.rb:5") {
		t.Fatal("a member one method wrote through an operator did not reach the sibling method that reads it")
	}
}

// Materializing a slot for a field READ must not make the record claim it models the object's
// writes: an element-sensitive subscript read concludes an unlisted key is CLEAN, and that
// holds only for a container every write to which was seen.
func TestAReadMaterializedSlotDoesNotMakeAContainerLookFullyWritten(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key: "h", File: "h.js",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "each", Params: []string{"items", "i"}, Loc: "h.js:1", Body: []nir.Stmt{
				// a plain field read on the parameter, which materializes a slot for "length"
				nir.ExprStmt{Value: nir.Attr{Base: nir.Name{ID: "items", Loc: "h.js:2"}, Attr: "length", Path: "items.length", Loc: "h.js:2"}},
				// a dynamic-key read of the same object: it must still carry the object's taint
				sinkCall(nir.Index{
					Base: nir.Name{ID: "items", Loc: "h.js:3"},
					Key:  nir.Name{ID: "i", Loc: "h.js:3"},
					Path: "items", Loc: "h.js:3",
				}, "h.js:3"),
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !reachesArg(t, g, findNodeID(t, g, "code.Param", "name", "items"), "h.js:3") {
		t.Fatal("a dynamic-key read stopped carrying the container's own taint after a field read materialized a slot")
	}
}

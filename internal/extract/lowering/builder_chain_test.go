package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// javaChainedAppend builds the NIR the Java frontend emits for
// `sb.append(c).append(tainted);` — an append whose receiver is the Call of the
// first append, not a plain name.
func javaChainedAppend(loc string, arg nir.Expr) nir.Call {
	first := nir.Call{
		Callee: nir.Attr{
			Base: nir.Name{ID: "sb", Loc: loc},
			Attr: "append",
			Path: "sb.append",
			Loc:  loc,
		},
		Path:   "sb.append",
		Method: "append",
		Loc:    loc,
		Args:   []nir.Expr{nir.Name{ID: "prefix", Loc: loc}},
	}
	return nir.Call{
		Callee: nir.Attr{Base: first, Attr: "append", Path: "sb.append.append", Loc: loc},
		Path:   "sb.append.append",
		Method: "append",
		Loc:    loc,
		Args:   []nir.Expr{arg},
	}
}

// TestChainedBuilderAppendFoldsIntoBaseVariable: a fluent mutator statement
// `sb.append(c).append(tainted)` mutates the variable at the chain's base, so a
// later `sb.toString()` must read the tainted builder — the write must not stop
// at the intermediate call-result node of the first link.
func TestChainedBuilderAppendFoldsIntoBaseVariable(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "App",
		File: "App.java",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:   "handler",
				Params: []string{"tainted", "prefix"},
				Loc:    "App.java:1",
				Body: []nir.Stmt{
					nir.Assign{Targets: []string{"sb"}, Type: "StringBuilder", Decl: true, Value: nir.Call{
						Callee: nir.Name{ID: "StringBuilder", Loc: "App.java:2"},
						Path:   "StringBuilder",
						Method: "StringBuilder",
						Loc:    "App.java:2",
					}},
					nir.ExprStmt{Value: javaChainedAppend("App.java:3", nir.Name{ID: "tainted", Loc: "App.java:3"})},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "execute", Loc: "App.java:4"},
						Path:   "execute",
						Method: "execute",
						Loc:    "App.java:4",
						Args: []nir.Expr{nir.Call{
							Callee: nir.Attr{
								Base: nir.Name{ID: "sb", Loc: "App.java:4"},
								Attr: "toString",
								Path: "sb.toString",
								Loc:  "App.java:4",
							},
							Path:   "sb.toString",
							Method: "toString",
							Loc:    "App.java:4",
						}},
					}},
				},
			},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	tainted := findNodeID(t, g, "code.Param", "name", "tainted")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "App.java:4")
	reachable, err := usg.BFS(g, tainted, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("chained append did not fold its argument into the builder variable; sb.toString() read a clean builder")
	}
}

// TestChainedAppendThroughNonMutatorDoesNotFold: only a chain made entirely of
// receiver mutators writes the base — a link that merely READS its receiver
// (`q.describe(x).append(tainted)`) must not taint q.
func TestChainedAppendThroughNonMutatorDoesNotFold(t *testing.T) {
	chain := nir.Call{
		Callee: nir.Attr{
			Base: nir.Call{
				Callee: nir.Attr{
					Base: nir.Name{ID: "q", Loc: "App.java:3"},
					Attr: "describe",
					Path: "q.describe",
					Loc:  "App.java:3",
				},
				Path:   "q.describe",
				Method: "describe",
				Loc:    "App.java:3",
				Args:   []nir.Expr{nir.Name{ID: "prefix", Loc: "App.java:3"}},
			},
			Attr: "append",
			Path: "q.describe.append",
			Loc:  "App.java:3",
		},
		Path:   "q.describe.append",
		Method: "append",
		Loc:    "App.java:3",
		Args:   []nir.Expr{nir.Name{ID: "tainted", Loc: "App.java:3"}},
	}
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "App",
		File: "App.java",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:   "handler",
				Params: []string{"tainted", "prefix"},
				Loc:    "App.java:1",
				Body: []nir.Stmt{
					nir.Assign{Targets: []string{"q"}, Type: "Query", Decl: true, Value: nir.Call{
						Callee: nir.Name{ID: "Query", Loc: "App.java:2"},
						Path:   "Query",
						Method: "Query",
						Loc:    "App.java:2",
					}},
					nir.ExprStmt{Value: chain},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "execute", Loc: "App.java:4"},
						Path:   "execute",
						Method: "execute",
						Loc:    "App.java:4",
						Args: []nir.Expr{nir.Call{
							Callee: nir.Attr{
								Base: nir.Name{ID: "q", Loc: "App.java:4"},
								Attr: "toString",
								Path: "q.toString",
								Loc:  "App.java:4",
							},
							Path:   "q.toString",
							Method: "toString",
							Loc:    "App.java:4",
						}},
					}},
				},
			},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	tainted := findNodeID(t, g, "code.Param", "name", "tainted")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "App.java:4")
	reachable, err := usg.BFS(g, tainted, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sinkArg] {
		t.Fatalf("append chained through a non-mutator link folded tainted into the base variable")
	}
}

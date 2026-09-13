package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// A `$this->render($req)` call inside a PHP class body dispatches on the implicit receiver's
// type. The receiver is spelled `$this` at the call site while the body scopes key the
// implicit receiver's type under the language-independent `this` (the merged multi-language
// Program drops the per-language SelfName, see the FuncDef arm), so the lookup under the
// receiver's own spelling found nothing and the call fell to the unique-method-name fallback —
// which refuses when a second unrelated class declares the same name. The call then resolves
// to nothing: the argument never reaches the callee's parameter and the callee's return value
// stops at the function's return node instead of flowing to the call site.
func TestThisReceiverCallResolvesThroughTheImplicitReceiverType(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "app/Controller.php",
		File: "app/Controller.php",
		Body: []nir.Stmt{
			// the unrelated second declaration of the name, which is what defeats the
			// unique-method-name fallback the unresolved call would otherwise take
			nir.ClassDef{Name: "Renderer", Loc: "app/Controller.php:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Loc: "app/Controller.php:2", Params: []string{"tpl"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "tpl", Loc: "app/Controller.php:2"}},
				}},
			}},
			nir.ClassDef{Name: "Controller", Loc: "app/Controller.php:5", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Loc: "app/Controller.php:6", Params: []string{"tpl"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "tpl", Loc: "app/Controller.php:6"}},
				}},
				nir.FuncDef{Name: "handle", Loc: "app/Controller.php:9", Params: []string{"req"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"out"}, Decl: true, Loc: "app/Controller.php:10", Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: "app/Controller.php:10"}, Attr: "render", Path: "$this.render", Loc: "app/Controller.php:10"},
						Args:   []nir.Expr{nir.Name{ID: "req", Loc: "app/Controller.php:10"}},
						Path:   "$this.render", Method: "render", Loc: "app/Controller.php:10",
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "echo", Loc: "app/Controller.php:11"},
						Args:   []nir.Expr{nir.Name{ID: "out", Loc: "app/Controller.php:11"}},
						Path:   "echo", Method: "echo", Loc: "app/Controller.php:11",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	arg := findNodeID(t, g, "code.Arg", "loc", "app/Controller.php:10")
	ownParam := inheritedParamNode(t, g, "Controller", "render", "tpl")
	otherParam := inheritedParamNode(t, g, "Renderer", "render", "tpl")
	ownReturn := findNodeID(t, g, "code.Return", "loc", "app/Controller.php:6")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app/Controller.php:11")

	fromArg, err := usg.BFS(g, arg, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromArg[ownParam] {
		t.Fatalf("the argument never reached the enclosing class's own render declaration")
	}
	if fromArg[otherParam] {
		t.Fatalf("the argument reached the unrelated Renderer declaration of the same name")
	}

	fromCalleeParam, err := usg.BFS(g, ownParam, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromCalleeParam[sinkArg] {
		t.Fatalf("the callee's tainted value stopped at the function return instead of flowing to the call site")
	}
	if !fromCalleeParam[ownReturn] {
		t.Fatalf("the callee's parameter never reached the callee's own return node")
	}
}

// The same receiver spelling, with the method declared only on a BASE class: the typed route
// walks the base chain, so a `$this->find($req)` call still reaches the inherited body even
// though an unrelated class's same-named declaration vetoes the name-keyed fallback.
func TestThisReceiverCallResolvesAnInheritedDeclaration(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "app/Repo.php",
		File: "app/Repo.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "BaseRepo", Loc: "app/Repo.php:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "find", Loc: "app/Repo.php:2", Params: []string{"id"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "id", Loc: "app/Repo.php:2"}},
				}},
			}},
			// the unrelated second declaration of the name
			nir.ClassDef{Name: "Cache", Loc: "app/Repo.php:5", Body: []nir.Stmt{
				nir.FuncDef{Name: "find", Loc: "app/Repo.php:6", Params: []string{"key"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "key", Loc: "app/Repo.php:6"}},
				}},
			}},
			nir.ClassDef{Name: "UserRepo", Bases: []string{"BaseRepo"}, Loc: "app/Repo.php:9", Body: []nir.Stmt{
				nir.FuncDef{Name: "show", Loc: "app/Repo.php:10", Params: []string{"req"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"row"}, Decl: true, Loc: "app/Repo.php:11", Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: "app/Repo.php:11"}, Attr: "find", Path: "$this.find", Loc: "app/Repo.php:11"},
						Args:   []nir.Expr{nir.Name{ID: "req", Loc: "app/Repo.php:11"}},
						Path:   "$this.find", Method: "find", Loc: "app/Repo.php:11",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	arg := findNodeID(t, g, "code.Arg", "loc", "app/Repo.php:11")
	inheritedParam := inheritedParamNode(t, g, "BaseRepo", "find", "id")
	otherParam := inheritedParamNode(t, g, "Cache", "find", "key")

	reachable, err := usg.BFS(g, arg, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[inheritedParam] {
		t.Fatalf("the argument never reached the base class's inherited find declaration")
	}
	if reachable[otherParam] {
		t.Fatalf("the argument reached the unrelated Cache declaration of the same name")
	}
}

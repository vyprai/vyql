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

// The resolution a self receiver wins must never take a flow the unresolved call had. `wrap`
// is declared on the enclosing class — returning a literal, so the body contributes no taint
// — AND on a second unrelated class, so the unique-method-name fallback refuses. The
// unresolved call carried the conservative arg→result edge, which is what carried the
// argument to the consumer; the resolved call must keep that edge while ADDING the body. A
// dispatch that drops the edge when the body resolves — a full typed dispatch — silences the
// argument the moment the receiver's own body transforms it, which is the regression this
// rework exists to rule out.
func TestThisReceiverCallKeepsTheUnresolvedCallResultEdge(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "app/Util.php",
		File: "app/Util.php",
		Body: []nir.Stmt{
			// the unrelated second declaration of the name, which is what defeats the
			// unique-method-name fallback
			nir.ClassDef{Name: "Other", Loc: "app/Util.php:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "wrap", Loc: "app/Util.php:2", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "v", Loc: "app/Util.php:2"}},
				}},
			}},
			nir.ClassDef{Name: "Host", Loc: "app/Util.php:5", Body: []nir.Stmt{
				nir.FuncDef{Name: "wrap", Loc: "app/Util.php:6", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Value: "constant", Loc: "app/Util.php:6"}},
				}},
				nir.FuncDef{Name: "run", Loc: "app/Util.php:9", Params: []string{"input"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"out"}, Decl: true, Loc: "app/Util.php:10", Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: "app/Util.php:10"}, Attr: "wrap", Path: "$this.wrap", Loc: "app/Util.php:10"},
						Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app/Util.php:10"}},
						Path:   "$this.wrap", Method: "wrap", Loc: "app/Util.php:10",
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "echo", Loc: "app/Util.php:11"},
						Args:   []nir.Expr{nir.Name{ID: "out", Loc: "app/Util.php:11"}},
						Path:   "echo", Method: "echo", Loc: "app/Util.php:11",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	arg := findNodeID(t, g, "code.Arg", "loc", "app/Util.php:10")
	ownParam := inheritedParamNode(t, g, "Host", "wrap", "v")
	otherParam := inheritedParamNode(t, g, "Other", "wrap", "v")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app/Util.php:11")

	fromArg, err := usg.BFS(g, arg, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromArg[ownParam] {
		t.Fatalf("the argument never reached the receiver's own wrap body")
	}
	if fromArg[otherParam] {
		t.Fatalf("the argument reached the unrelated Other declaration of the same name")
	}
	if !fromArg[sinkArg] {
		t.Fatalf("resolving the call dropped the conservative arg→result edge the unresolved call carried: the argument no longer reaches the consumer")
	}
}

// A declaration with no body of its own on the receiver's class — an interface or abstract
// method — is the one shape the self-receiver route must NOT answer additively: the
// implementors' param and return nodes are shared across every call site of the name, so
// routing a shared return into this call result would merge taint from other sites into it.
// It keeps the reach-only discipline instead: the argument reaches the implementor's body
// and the call result keeps the conservative edge the unresolved call had.
func TestThisReceiverAbstractDeclarationStaysReachOnly(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "app/Dao.php",
		File: "app/Dao.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Dao", Loc: "app/Dao.php:1", Body: []nir.Stmt{
				// no body: the abstract declaration the self-receiver route resolves on
				nir.FuncDef{Name: "wrap", Loc: "app/Dao.php:2", Params: []string{"v"}},
				nir.FuncDef{Name: "run", Loc: "app/Dao.php:3", Params: []string{"input"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"out"}, Decl: true, Loc: "app/Dao.php:4", Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: "app/Dao.php:4"}, Attr: "wrap", Path: "$this.wrap", Loc: "app/Dao.php:4"},
						Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app/Dao.php:4"}},
						Path:   "$this.wrap", Method: "wrap", Loc: "app/Dao.php:4",
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "echo", Loc: "app/Dao.php:5"},
						Args:   []nir.Expr{nir.Name{ID: "out", Loc: "app/Dao.php:5"}},
						Path:   "echo", Method: "echo", Loc: "app/Dao.php:5",
					}},
				}},
			}},
			nir.ClassDef{Name: "UserDao", Bases: []string{"Dao"}, Loc: "app/Dao.php:8", Body: []nir.Stmt{
				nir.FuncDef{Name: "wrap", Loc: "app/Dao.php:9", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "v", Loc: "app/Dao.php:9"}},
				}},
			}},
			// the unrelated second declaration of the name, which is what defeats the
			// unique-method-name fallback
			nir.ClassDef{Name: "Other", Loc: "app/Dao.php:12", Body: []nir.Stmt{
				nir.FuncDef{Name: "wrap", Loc: "app/Dao.php:13", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "v", Loc: "app/Dao.php:13"}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	arg := findNodeID(t, g, "code.Arg", "loc", "app/Dao.php:4")
	implParam := inheritedParamNode(t, g, "UserDao", "wrap", "v")
	otherParam := inheritedParamNode(t, g, "Other", "wrap", "v")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app/Dao.php:5")

	fromArg, err := usg.BFS(g, arg, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromArg[implParam] {
		t.Fatalf("the argument never reached the implementor's wrap body")
	}
	if fromArg[otherParam] {
		t.Fatalf("the argument reached the unrelated Other declaration of the same name")
	}
	if !fromArg[sinkArg] {
		t.Fatalf("the reach-only resolution dropped the conservative arg→result edge the unresolved call carried")
	}

	fromImplParam, err := usg.BFS(g, implParam, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if fromImplParam[sinkArg] {
		t.Fatalf("the implementor's shared return node merged into this call result — reach-only bodies must not flow back")
	}
}

// A `$this->helper()` whose name is declared exactly once must keep the resolution the
// unique-method-name fallback has always given it — the argument reaches the one
// declaration's parameter and that body's return reaches the call result — with no change
// in how the call is dispatched.
func TestThisReceiverCallStillResolvesANameUniqueDeclaration(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "app/Host.php",
		File: "app/Host.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Helper", Loc: "app/Host.php:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "aid", Loc: "app/Host.php:2", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "v", Loc: "app/Host.php:2"}},
				}},
			}},
			nir.ClassDef{Name: "Host", Loc: "app/Host.php:5", Body: []nir.Stmt{
				nir.FuncDef{Name: "run", Loc: "app/Host.php:6", Params: []string{"input"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"out"}, Decl: true, Loc: "app/Host.php:7", Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: "app/Host.php:7"}, Attr: "aid", Path: "$this.aid", Loc: "app/Host.php:7"},
						Args:   []nir.Expr{nir.Name{ID: "input", Loc: "app/Host.php:7"}},
						Path:   "$this.aid", Method: "aid", Loc: "app/Host.php:7",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	arg := findNodeID(t, g, "code.Arg", "loc", "app/Host.php:7")
	helperParam := inheritedParamNode(t, g, "Helper", "aid", "v")
	callResult := findNodeID(t, g, "code.Call", "loc", "app/Host.php:7")

	fromArg, err := usg.BFS(g, arg, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromArg[helperParam] {
		t.Fatalf("the argument never reached the one aid declaration")
	}
	fromHelperParam, err := usg.BFS(g, helperParam, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromHelperParam[callResult] {
		t.Fatalf("the unique declaration's return never reached the call result")
	}
}

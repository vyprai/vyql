package lowering

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// A method call on a receiver of a known type dispatches through the receiver's whole
// inheritance chain. The walk used to stop after one level of bases, so a method declared only
// on a grandparent left the call to the name-keyed fallbacks -- and a name declared more than
// once (here: the base class and an unrelated class both declare setValues, the shape every
// plugin framework's entity and validation classes produce) resolves to nothing. The call then
// keeps no argument mapping and the value never reaches the inherited body.
func TestMethodCallDispatchesToADeclarationTwoLevelsUpTheBaseChain(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "validation.php",
		File: "validation.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "ValidationBase", Loc: "validation.php:2", Body: []nir.Stmt{
				nir.FuncDef{Name: "setValues", Loc: "validation.php:3", Params: []string{"values"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Loc: "validation.php:3", Value: "base"}},
				}},
			}},
			nir.ClassDef{Name: "ValidationMiddle", Bases: []string{"ValidationBase"}, Loc: "validation.php:5"},
			nir.ClassDef{Name: "EntityExistsValidation", Bases: []string{"ValidationMiddle"}, Loc: "validation.php:6", Body: []nir.Stmt{
				nir.FuncDef{Name: "validate", Loc: "validation.php:7", Params: []string{"value"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "value", Loc: "validation.php:7"}},
				}},
			}},
			// the unrelated second declaration of the same short name, which is what defeats
			// the unique-method-name fallback the unresolved call would otherwise take
			nir.ClassDef{Name: "Entity", Loc: "validation.php:9", Body: []nir.Stmt{
				nir.FuncDef{Name: "setValues", Loc: "validation.php:10", Params: []string{"values"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Loc: "validation.php:10", Value: "entity"}},
				}},
			}},
			nir.FuncDef{Name: "entry", Loc: "validation.php:12", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"v1"}, Value: nir.Call{
					Callee: nir.Name{ID: "EntityExistsValidation", Loc: "validation.php:13"},
					Path:   "EntityExistsValidation", Method: "EntityExistsValidation", Loc: "validation.php:13", IsCtor: true,
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "v1", Loc: "validation.php:14"}, Attr: "setValues", Path: "v1.setValues", Loc: "validation.php:14"},
					Args:   []nir.Expr{nir.Name{ID: "payload", Loc: "validation.php:14"}},
					Path:   "v1.setValues", Method: "setValues", Loc: "validation.php:14",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	inheritedParam := inheritedParamNode(t, g, "ValidationBase", "setValues", "values")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[inheritedParam] {
		t.Fatalf("the argument never reached the grandparent's inherited setValues parameter")
	}
}

// The nearest declaration wins: a base that declares the method shadows what a higher ancestor
// declares, so the call resolves to the override the receiver would actually run and not to
// both bodies.
func TestMethodCallDispatchesToTheNearestInheritedDeclaration(t *testing.T) {
	prog := nir.Program{SelfName: "this", Modules: []nir.Module{{
		Key:  "validation.php",
		File: "validation.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "ValidationBase", Loc: "validation.php:2", Body: []nir.Stmt{
				nir.FuncDef{Name: "setValues", Loc: "validation.php:3", Params: []string{"values"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Loc: "validation.php:3", Value: "base"}},
				}},
			}},
			nir.ClassDef{Name: "ValidationChild", Bases: []string{"ValidationBase"}, Loc: "validation.php:5", Body: []nir.Stmt{
				nir.FuncDef{Name: "setValues", Loc: "validation.php:6", Params: []string{"values"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Loc: "validation.php:6", Value: "child"}},
				}},
			}},
			nir.ClassDef{Name: "EntityExistsValidation", Bases: []string{"ValidationChild"}, Loc: "validation.php:8"},
			nir.FuncDef{Name: "entry", Loc: "validation.php:10", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"v1"}, Value: nir.Call{
					Callee: nir.Name{ID: "EntityExistsValidation", Loc: "validation.php:11"},
					Path:   "EntityExistsValidation", Method: "EntityExistsValidation", Loc: "validation.php:11", IsCtor: true,
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "v1", Loc: "validation.php:12"}, Attr: "setValues", Path: "v1.setValues", Loc: "validation.php:12"},
					Args:   []nir.Expr{nir.Name{ID: "payload", Loc: "validation.php:12"}},
					Path:   "v1.setValues", Method: "setValues", Loc: "validation.php:12",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	overrideParam := inheritedParamNode(t, g, "ValidationChild", "setValues", "values")
	shadowedParam := inheritedParamNode(t, g, "ValidationBase", "setValues", "values")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[overrideParam] {
		t.Fatalf("the argument never reached the overriding declaration, which is the body that runs")
	}
	if reachable[shadowedParam] {
		t.Fatalf("the argument reached the shadowed ancestor declaration as well")
	}
}

// inheritedParamNode returns the parameter node of `class.method` named `param`, matched by the
// stable signature id so the two same-named declarations of a method are told apart.
func inheritedParamNode(t *testing.T, g usg.Store, class, method, param string) string {
	t.Helper()
	suffix := class + "." + method + "#param#" + param
	ids, err := g.NodesOfType("code.Param")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if strings.HasSuffix(id, suffix) {
			return id
		}
	}
	t.Fatalf("no parameter node %s", suffix)
	return ""
}

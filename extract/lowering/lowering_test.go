package lowering

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func TestCollectValTokensDescendsIntoFormat(t *testing.T) {
	var toks []string
	collectValTokens(nir.Format{
		Parts: []nir.Expr{
			nir.Const{Value: "prefix="},
			nir.Const{Value: "http://example.com"},
		},
	}, "", &toks)

	for _, tok := range toks {
		if tok == "http://example.com" {
			return
		}
	}
	t.Fatalf("expected formatted literal token, got %#v", toks)
}

func TestLowerMaterializesImportNodes(t *testing.T) {
	g, err := Lower(nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Imports: []nir.Import{{
			Local: "yaml", Module: "yaml", IsModule: true,
		}},
	}}}, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Import")
	if len(ids) != 1 {
		t.Fatalf("import node count = %d, want 1", len(ids))
	}
	n, _, _ := g.GetNode(ids[0])
	if n.Prop("module") != "yaml" || n.Prop("local") != "yaml" || n.Prop("package") != "yaml" {
		t.Fatalf("import props wrong: %+v", n.Props)
	}
}

func TestLowerStampsReceiverTypeFromParamTypes(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.js",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Service", Body: []nir.Stmt{
				nir.FuncDef{Name: "clean", Params: []string{"x"}, Body: []nir.Stmt{nir.Return{Value: nir.Name{ID: "x", Loc: "app.js:1"}}}, Loc: "app.js:1"},
			}, Loc: "app.js:1"},
			nir.FuncDef{Name: "handler", Params: []string{"svc"}, ParamTypes: map[string]string{"svc": "Service"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "svc", Loc: "app.js:3"}, Attr: "clean", Path: "svc.clean", Loc: "app.js:3"},
					Args:   []nir.Expr{nir.Const{Loc: "app.js:3"}},
					Path:   "svc.clean", Method: "clean", Loc: "app.js:3",
				}},
			}, Loc: "app.js:2"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "svc.clean" {
			if got := n.Prop("recv_type"); got != "Service" {
				t.Fatalf("recv_type = %q, want Service", got)
			}
			return
		}
	}
	t.Fatalf("svc.clean call not found")
}

func TestLowerAnnotatedReturnCreatesSyntheticCall(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Decorators: []string{"decorator_method:get"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Name{ID: "body", Loc: "app.py:2"}},
			}, Loc: "app.py:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.function.return" &&
			n.Prop("arg0") != "" &&
			strings.Contains(n.Prop("str_args"), "decorator_method:get") {
			return
		}
	}
	t.Fatalf("annotated return synthetic call not found")
}

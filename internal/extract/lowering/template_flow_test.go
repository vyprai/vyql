package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

func templateProgram(template nir.Expr) nir.Program {
	return nir.Program{Modules: []nir.Module{{Key: "app", File: "app.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "page", Params: []string{"safe", "tainted", "request", "template_text"}, Loc: "app.py:1", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"template"}, Loc: "app.py:2", Value: nir.Call{
				Callee: nir.Attr{Base: nir.Name{ID: "engine", Loc: "app.py:2"}, Attr: "from_string", Path: "engine.from_string", Loc: "app.py:2"},
				Args:   []nir.Expr{template}, Path: "engine.from_string", Method: "from_string", Loc: "app.py:2",
			}},
			nir.Return{Value: nir.Call{
				Callee: nir.Attr{Base: nir.Name{ID: "template", Loc: "app.py:3"}, Attr: "render", Path: "template.render", Loc: "app.py:3"},
				Args: []nir.Expr{
					nir.Seq{Loc: "app.py:3", Parts: []nir.Expr{
						nir.Pair{Key: "name", Value: nir.Name{ID: "safe", Loc: "app.py:3"}, Loc: "app.py:3"},
						nir.Pair{Key: "unused", Value: nir.Name{ID: "tainted", Loc: "app.py:3"}, Loc: "app.py:3"},
					}},
					nir.Name{ID: "request", Loc: "app.py:3"},
				}, Path: "template.render", Method: "render", Loc: "app.py:3",
			}},
		}},
	}}}}
}

func TestStaticTemplateRenderFlowsOnlyReferencedContextKeys(t *testing.T) {
	g, err := Lower(templateProgram(nir.Const{Value: "Hello {{ name }}", Loc: "app.py:2"}), true)
	if err != nil {
		t.Fatal(err)
	}
	render := findNodeID(t, g, "code.Call", "callee_path", "template.render")
	safe := findNodeID(t, g, "code.Param", "name", "safe")
	tainted := findNodeID(t, g, "code.Param", "name", "tainted")
	safeReach, _ := usg.BFS(g, safe, "FLOWS", 32)
	taintedReach, _ := usg.BFS(g, tainted, "FLOWS", 32)
	if !safeReach[render] || taintedReach[render] {
		t.Fatalf("safe=%v tainted=%v", safeReach[render], taintedReach[render])
	}
}

func TestDynamicTemplateRenderKeepsWholeContextConservative(t *testing.T) {
	g, err := Lower(templateProgram(nir.Name{ID: "template_text", Loc: "app.py:2"}), true)
	if err != nil {
		t.Fatal(err)
	}
	render := findNodeID(t, g, "code.Call", "callee_path", "template.render")
	tainted := findNodeID(t, g, "code.Param", "name", "tainted")
	reachable, _ := usg.BFS(g, tainted, "FLOWS", 32)
	if !reachable[render] {
		t.Fatal("dynamic template lost conservative context flow")
	}
}

func TestTemplateRenderRequestArgumentIsMetadataNotDirectOutput(t *testing.T) {
	g, err := Lower(templateProgram(nir.Const{Value: "Hello {{ name }}", Loc: "app.py:2"}), true)
	if err != nil {
		t.Fatal(err)
	}
	render := findNodeID(t, g, "code.Call", "callee_path", "template.render")
	request := findNodeID(t, g, "code.Param", "name", "request")
	reachable, _ := usg.BFS(g, request, "FLOWS", 32)
	if reachable[render] {
		t.Fatal("request metadata flowed directly into rendered output")
	}
}

func TestUntrackedRenderMethodKeepsNormalFallbackFlow(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{Key: "app", File: "app.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "page", Params: []string{"renderer", "value", "metadata"}, Body: []nir.Stmt{
			nir.Return{Value: nir.Call{
				Callee: nir.Attr{Base: nir.Name{ID: "renderer"}, Attr: "render", Path: "renderer.render"},
				Args:   []nir.Expr{nir.Name{ID: "value"}, nir.Name{ID: "metadata"}},
				Path:   "renderer.render", Method: "render", Loc: "app.py:3",
			}},
		}},
	}}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	render := findNodeID(t, g, "code.Call", "callee_path", "renderer.render")
	metadata := findNodeID(t, g, "code.Param", "name", "metadata")
	reachable, _ := usg.BFS(g, metadata, "FLOWS", 32)
	if !reachable[render] {
		t.Fatal("untracked render method lost normal fallback flow")
	}
}

func TestStaticTemplateRenderDynamicContextKeyStaysConservative(t *testing.T) {
	prog := templateProgram(nir.Const{Value: "Hello {{ name }}", Loc: "app.py:2"})
	fn := prog.Modules[0].Body[0].(nir.FuncDef)
	ret := fn.Body[1].(nir.Return)
	render := ret.Value.(nir.Call)
	context := render.Args[0].(nir.Seq)
	context.Parts = []nir.Expr{nir.Pair{
		Key: "context_key", DynamicKey: true,
		Value: nir.Name{ID: "tainted", Loc: "app.py:3"}, Loc: "app.py:3",
	}}
	render.Args[0] = context
	ret.Value = render
	fn.Body[1] = ret
	prog.Modules[0].Body[0] = fn
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	renderNode := findNodeID(t, g, "code.Call", "callee_path", "template.render")
	tainted := findNodeID(t, g, "code.Param", "name", "tainted")
	reachable, _ := usg.BFS(g, tainted, "FLOWS", 32)
	if !reachable[renderNode] {
		t.Fatal("dynamic context key lost conservative flow")
	}
}

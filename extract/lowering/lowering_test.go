package lowering

import (
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

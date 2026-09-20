package bindings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// vueRenderDomPropsInnerHtml is the shipped binding for the render-function
// half of Vue's markup write (vyql/bindings/javascript/
// vue_render_dom_props_inner_html.vyql), verbatim: the data object of a
// createElement/h call carrying the framework's own domProps and innerHTML key
// names is a markup write. A v-html directive in a single-file component's
// template compiles to exactly that shape, so the binding must anchor on the
// directive once the frontend lowers it.
const vueRenderDomPropsInnerHTML = `
module bindings.javascript.vue_render_dom_props_inner_html;
binding vueRenderDomPropsInnerHtml {
  query pattern callExpr where callee.method in ["createElement", "h"] and args.any.literal contains "domProps" and args.any.literal contains "innerHTML"
  emit sink code.HtmlRender at args[1].collection
}
`

// vueComponentWithTaintedGetter hands the directive a value the script taints
// itself: the bound method reads the store state and returns it, the collapsed
// form of krayin's component (the computed getter inlined into the reader).
const vueComponentWithTaintedGetter = `<template>
    <td v-html="getRowContent(row[column.index])"></td>
</template>
<script>
    export default {
        methods: {
            getRowContent: function (content) {
                var data = this.$store.state.tableData.records.data
                return data
            }
        }
    }
</script>
`

func vueLoweredComponent(t *testing.T) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "table-body.vue")
	if err := os.WriteFile(path, []byte(vueComponentWithTaintedGetter), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func vueHTMLRenderSinkApplicator(t *testing.T) Applicator {
	t.Helper()
	sets, err := compileV2BindingsForTest(vueRenderDomPropsInnerHTML)
	if err != nil {
		t.Fatalf("compile vue render domProps binding: %v", err)
	}
	return specFromBindingSet(sets[0]).sinkApplicator()
}

// The directive's compiled form carries the sink: the shipped binding anchors
// code.HtmlRender on the createElement data object the frontend lowers the
// v-html directive into, at the directive's own line.
func TestVueTemplateVHTMLDirectiveCarriesTheRenderSink(t *testing.T) {
	g := vueLoweredComponent(t)
	got := labelsByNode(vueHTMLRenderSinkApplicator(t).Apply(g))
	if len(got) == 0 {
		t.Fatal("no HtmlRender sink on the .vue component's v-html directive")
	}
	for node, concepts := range got {
		n, ok, err := g.GetNode(node)
		if err != nil || !ok {
			t.Fatalf("labelled node %q is not in the graph", node)
		}
		for _, concept := range concepts {
			if concept != "code.HtmlRender" {
				t.Fatalf("node %q labelled %q, want only code.HtmlRender", node, concept)
			}
		}
		if n.Prop("loc") != "table-body.vue:2" {
			t.Fatalf("sink landed at %q, want the directive's line table-body.vue:2", n.Prop("loc"))
		}
	}
}

// The bound expression is wired into the sink position: the call the directive
// names flows to the node the sink labels, so taint that reaches the call's
// result reaches the markup write. This is the half the graph was missing
// entirely — before the frontend lowered directives, no path from the script
// into the template existed at all.
func TestVueTemplateVHTMLSinkReceivesTheBoundExpression(t *testing.T) {
	g := vueLoweredComponent(t)
	got := labelsByNode(vueHTMLRenderSinkApplicator(t).Apply(g))
	if len(got) == 0 {
		t.Fatal("no HtmlRender sink on the .vue component's v-html directive")
	}
	// The directive's expression call, at the directive's own line.
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var callID string
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "getRowContent" && n.Prop("loc") == "table-body.vue:2" {
			callID = n.ID
			break
		}
	}
	if callID == "" {
		t.Fatal("the directive's getRowContent(...) call is not in the graph")
	}
	reach := map[string]bool{callID: true}
	frontier := []string{callID}
	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		edges, err := g.OutEdges(cur, "FLOWS")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range edges {
			if reach[e.Dst] {
				continue
			}
			reach[e.Dst] = true
			frontier = append(frontier, e.Dst)
		}
	}
	for node := range got {
		if !reach[node] {
			n, _, _ := g.GetNode(node)
			t.Fatalf("sink at %s (%s) is not reachable from the directive's bound expression", n.Prop("loc"), n.Type)
		}
	}
}

package domains

import (
	"os"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/doc"
	"github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/lower"
	"github.com/vyprai/vyql/internal/vygraph/solvers/taint"
	"github.com/vyprai/vyql/internal/vygraph/vyql"
)

// The knowledge base: lifts from doc (iac.Resource from a Deployment, and a
// programmatic OpenAPI lift exercising the same substrate), the anchor relate
// by ref, and the declared-vs-enforced conformance rule — an ordinary rule
// over the anchor edge, per the design.
const crossKB = `module cross {
  version "0.1.0"
  provenance reviewed
}
concept code.AuthenticationCheck : guard { defends: [BrokenAccess] }
threat BrokenAccess { }

lift iac.Resource from doc where kind == "Deployment" {
  kind: .kind
  name: .metadata.name
}
framework flask {
  route on code.func() where decorated_by("flask.route") {
    method: "GET"
    path:   "/users"
    handler: .name
  }
}
lift code.Entrypoint from framework flask {
  httpMethod: .method
  httpPath:   .path
  handler:    .handler
}
rule DeclaredAuthNotEnforced {
  meta { id: "XA-001" severity: high }
  match (r: api.Operation) -[:anchor]-> (h: code.Entrypoint) -> finding
    unless guarded_by code.AuthenticationCheck
}
`

// buildDomainNodes lifts api.Operation/SecurityRequirement/requires from the
// parsed OpenAPI doc tree — the same doc.* substrate walk a lift performs;
// programmatic here because the OpenAPI paths/methods shape is a nested map
// keyed by dynamic path strings (a pattern-matcher concern, Phase 5 breadth).
func buildDomainNodes(g *graph.Store, file string) {
	addOp := func(method, path string, sec []string) {
		id := "op:" + method + ":" + path
		var f graph.Fields
		f.Set("method", graph.Str(method))
		f.Set("path", graph.Str(path))
		_ = g.Upsert(graph.Node{ID: id, Type: "api.Operation", Layer: graph.LayerHigh, Fields: f,
			Prov: graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: graph.TrustReviewed}})
		for _, scheme := range sec {
			var sf graph.Fields
			sf.Set("scheme", graph.Str(scheme))
			sid := "sec:" + id + ":" + scheme
			_ = g.Upsert(graph.Node{ID: sid, Type: "api.SecurityRequirement", Layer: graph.LayerHigh, Fields: sf,
				Prov: graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: graph.TrustReviewed}})
			_ = g.AddEdge(graph.Edge{ID: "req:" + id + ":" + scheme, Type: "requires", From: id, To: sid,
				Prov: graph.Provenance{Producer: "relate", Build: graph.BuildRelated, Trust: graph.TrustReviewed}})
		}
	}
	// Walk the parsed tree: paths.<path>.<method> with optional security.
	paths := docFind(g, file, "paths")
	if paths.ID == "" {
		return
	}
	for _, pe := range g.Out(paths.ID, "child") {
		pk, _ := pe.Fields.Get("key")
		pathNode, _ := g.Node(pe.To)
		for _, me := range g.Out(pathNode.ID, "child") {
			mk, _ := me.Fields.Get("key")
			var sec []string
			if sn := docFind(g, file, "paths."+pk.S+"."+mk.S+".security"); sn.ID != "" {
				for _, se := range g.Out(sn.ID, "child") {
					schemeNode, _ := g.Node(se.To)
					for _, ke := range g.Out(schemeNode.ID, "child") {
						kf, _ := ke.Fields.Get("key")
						sec = append(sec, kf.S)
					}
				}
			}
			addOp(mk.S, pk.S, sec)
		}
	}
}

func docFind(g *graph.Store, file, path string) graph.Node {
	for _, typ := range []string{"doc.Map", "doc.Seq"} {
		for _, n := range g.NodesOfType(typ) {
			if v, ok := n.Fields.Get("path"); ok && v.S == path {
				if f, ok := n.Fields.Get("file"); ok && f.S == file {
					return n
				}
			}
		}
	}
	return graph.Node{}
}

const anchorRelate = `module cross;
relate anchor from api.Operation to code.Entrypoint by ref .path == code.Entrypoint.httpPath
`

func buildGraph(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)

	// The artifacts: OpenAPI + Deployment through the generic doc parser.
	dp := doc.New(g)
	if src, err := os.ReadFile("testdata/cross/openapi.json"); err == nil {
		if err := dp.Extract("openapi.json", src); err != nil {
			t.Fatal(err)
		}
	}
	if src, err := os.ReadFile("testdata/cross/deployment.yaml"); err == nil {
		if err := dp.Extract("deployment.yaml", src); err != nil {
			t.Fatal(err)
		}
	}

	// The code side: the Python handler.
	psrc, err := os.ReadFile("testdata/cross/handler.py")
	if err != nil {
		t.Fatal(err)
	}
	fe := python.New(g)
	if err := fe.Extract("handler.py", psrc); err != nil {
		t.Fatal(err)
	}
	if err := lower.Run(g, fe.Imports); err != nil {
		t.Fatal(err)
	}
	return g
}

func crossProgram(t *testing.T, g *graph.Store) *vyql.Program {
	t.Helper()
	kbFiles := []*vyql.File{}
	for _, src := range []string{crossKB, anchorRelate} {
		f, err := vyql.Parse(src)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		kbFiles = append(kbFiles, f)
	}
	kbs := graph.NewSchemas()
	if err := Register(kbs); err != nil {
		t.Fatal(err)
	}
	kb, berrs := vyql.KBFromFiles(kbFiles, kbs)
	if len(berrs) > 0 {
		t.Fatalf("KBFromFiles: %v", berrs)
	}
	// Entrypoints from the framework model first.
	if err := vyql.ApplyLifts(kb, g); err != nil {
		t.Fatalf("ApplyLifts: %v", err)
	}
	// Domain nodes from the doc substrate, then the anchor join.
	buildDomainNodes(g, "openapi.json")
	if err := vyql.ApplyRelates(kb, g); err != nil {
		t.Fatalf("ApplyRelates: %v", err)
	}
	prog, err := vyql.Compile(kb)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return prog
}

func TestDocLiftsIacResource(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	src, _ := os.ReadFile("testdata/cross/deployment.yaml")
	if err := doc.New(g).Extract("deployment.yaml", src); err != nil {
		t.Fatal(err)
	}
	f, err := vyql.Parse(crossKB)
	if err != nil {
		t.Fatal(err)
	}
	kbs := graph.NewSchemas()
	if err := Register(kbs); err != nil {
		t.Fatal(err)
	}
	kb, _ := vyql.KBFromFiles([]*vyql.File{f}, kbs)
	if err := vyql.ApplyLifts(kb, g); err != nil {
		t.Fatal(err)
	}
	res := g.NodesOfType("iac.Resource")
	if len(res) != 1 {
		t.Fatalf("iac.Resources = %d, want 1", len(res))
	}
	if v, _ := res[0].Fields.Get("name"); v.S != "web" {
		t.Fatalf("name = %q", v.S)
	}
	if v, _ := res[0].Fields.Get("kind"); v.S != "Deployment" {
		t.Fatalf("kind = %q", v.S)
	}
	if _, ok := g.Backing(res[0].ID); !ok {
		t.Fatal("the lifted resource must back its doc origin")
	}
}

func TestAnchorJoinsDeclaredOperationsToHandlers(t *testing.T) {
	g := buildGraph(t)
	prog := crossProgram(t, g)
	_ = prog

	// api.Operation /users:get anchors the /users entrypoint; /health:get has
	// a handler path but no implementing function (no entrypoint) — no anchor.
	eps := g.NodesOfType("code.Entrypoint")
	if len(eps) != 1 {
		t.Fatalf("entrypoints = %d", len(eps))
	}
	anchored := g.Out("op:get:/users", "anchor")
	if len(anchored) != 1 || anchored[0].To != eps[0].ID {
		t.Fatalf("anchor edges = %+v", anchored)
	}
	if ops := g.Out("op:get:/health", "anchor"); len(ops) != 0 {
		t.Fatalf("unimplemented operation must not anchor: %+v", ops)
	}
	// The declared security is present on /users and absent on /health.
	if req := g.Out("op:get:/users", "requires"); len(req) != 1 {
		t.Fatalf("/users requires = %+v", req)
	}
	if req := g.Out("op:get:/health", "requires"); len(req) != 0 {
		t.Fatalf("/health requires = %+v", req)
	}
}

func TestDeclaredVsEnforcedFiresAndSuppresses(t *testing.T) {
	g := buildGraph(t)
	prog := crossProgram(t, g)
	out, err := prog.Run(g, vyql.SolverRegistry{"taint": taint.New(prog.KB.Onto)})
	if err != nil {
		t.Fatal(err)
	}

	// /users declares adminAuth on both get and delete; each anchored
	// operation lacks enforcement — two findings. /health declares nothing
	// and is not matched.
	if len(out.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (XA-001):\n%s", len(out.Findings), out.Render())
	}
	f := out.Findings[0]
	if f.RuleID != "XA-001" {
		t.Fatalf("rule = %s", f.RuleID)
	}

	// Adding the guard to the anchored handler suppresses the finding.
	g2 := buildGraph(t)
	prog2 := crossProgram(t, g2)
	eps := g2.NodesOfType("code.Entrypoint")
	if err := g2.AddLabel(graph.Label{Target: eps[0].ID, Concept: "code.AuthenticationCheck",
		Confidence: 1, Prov: graph.Provenance{Producer: "binding:cross", Build: graph.BuildLabeled, Trust: graph.TrustReviewed}}); err != nil {
		t.Fatal(err)
	}
	out2, err := prog2.Run(g2, vyql.SolverRegistry{"taint": taint.New(prog2.KB.Onto)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out2.Findings) != 0 {
		t.Fatalf("a guarded anchored handler must not fire:\n%s", out2.Render())
	}
}

func TestCrossPipelineDeterministic(t *testing.T) {
	g1 := buildGraph(t)
	r1 := crossProgram(t, g1)
	out1, _ := r1.Run(g1, vyql.SolverRegistry{"taint": taint.New(r1.KB.Onto)})
	g2 := buildGraph(t)
	r2 := crossProgram(t, g2)
	out2, _ := r2.Run(g2, vyql.SolverRegistry{"taint": taint.New(r2.KB.Onto)})
	if out1.Render() != out2.Render() {
		t.Fatalf("cross-pipeline reruns differ:\n%s\n---\n%s", out1.Render(), out2.Render())
	}
	if !strings.Contains(out1.Render(), "XA-001") {
		t.Fatal("render must name the conformance rule")
	}
}

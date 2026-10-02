package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// stubTaint walks FLOWS edges on the low graph. Phase 2 replaces it with the real
// summary-based solver that bridges via backs; the point here is that the engine only
// sees the contract.
type stubTaint struct{}

func (stubTaint) Name() string { return "taint" }

func (stubTaint) Solve(g *graph.Store, in solver.Input) ([]solver.Result, error) {
	want := map[string]bool{}
	for _, t := range in.Targets {
		want[t] = true
	}
	var out []solver.Result
	for _, src := range in.Sources {
		var path []solver.Step
		cur := src
		for {
			edges := g.Out(cur, "FLOWS")
			if len(edges) == 0 {
				break
			}
			e := edges[0]
			path = append(path, solver.Step{From: e.From, To: e.To, Via: "FLOWS"})
			cur = e.To
			if want[cur] {
				out = append(out, solver.Flow{Src: src, Dst: cur, Path: path})
				break
			}
		}
	}
	return out, nil
}

func TestToyEndToEndProducesFindingWithProof(t *testing.T) {
	schemas := graph.NewSchemas()
	for _, ts := range []*graph.TypeSchema{
		{Type: "code.Call", Layer: graph.LayerLow,
			Fields: []graph.FieldSpec{{Name: "callee", Kind: graph.KindString}},
			Key:    []string{"callee"}},
		{Type: "FLOWS", Layer: graph.LayerLow, Fields: nil, Key: nil},
	} {
		if err := schemas.Register(ts); err != nil {
			t.Fatal(err)
		}
	}

	g := graph.New(schemas)
	mk := func(id, callee string) {
		var f graph.Fields
		f.Set("callee", graph.Str(callee))
		if err := g.AddNode(graph.Node{ID: id, Type: "code.Call", Layer: graph.LayerLow, Fields: f}); err != nil {
			t.Fatal(err)
		}
	}
	mk("n1", "request.query")
	mk("n2", "fmt.Sprintf")
	mk("n3", "db.Exec")
	for _, e := range []graph.Edge{
		{ID: "e1", Type: "FLOWS", From: "n1", To: "n2"},
		{ID: "e2", Type: "FLOWS", From: "n2", To: "n3"},
	} {
		if err := g.AddEdge(e); err != nil {
			t.Fatal(err)
		}
	}

	onto := ontology.New()
	_ = onto.Add(ontology.Concept{Name: "UntrustedData", Kinds: []ontology.Kind{ontology.KindSource}})
	_ = onto.Add(ontology.Concept{Name: "HttpInput", Kinds: []ontology.Kind{ontology.KindSource},
		Refines: "UntrustedData", Taint: []string{"UntrustedData"}})
	_ = onto.Add(ontology.Concept{Name: "SqlExecution", Kinds: []ontology.Kind{ontology.KindSink},
		VulnerableTo: []string{"Injection"}, EnabledBy: []string{"UntrustedData"}})

	// Adapters put meaning on structure. The rule below never names a node type.
	if err := g.AddLabel(graph.Label{Target: "n1", Concept: "HttpInput", Confidence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLabel(graph.Label{Target: "n3", Concept: "SqlExecution", Confidence: 1}); err != nil {
		t.Fatal(err)
	}

	eng := New(g, onto)
	eng.Register(stubTaint{})

	// The rule references CONCEPTS only — and a lattice parent at that, so the
	// ontology's IsA has to do real work to bind n1.
	got, err := eng.Evaluate(Rule{
		ID: "TOY-001", SourceConcept: "UntrustedData", SinkConcept: "SqlExecution", Solver: "taint",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != "TOY-001" || f.Source != "n1" || f.Target != "n3" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Proof == nil {
		t.Fatal("a finding must carry a rebuildable proof tree")
	}
	rendered := f.Proof.Render()
	for _, want := range []string{"n1", "n2", "n3", "FLOWS"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("proof %q missing %q", rendered, want)
		}
	}
}

func TestEvaluateErrorsOnUnknownSolverAndConcept(t *testing.T) {
	g := graph.New(graph.NewSchemas())
	onto := ontology.New()
	eng := New(g, onto)
	if _, err := eng.Evaluate(Rule{ID: "R", SourceConcept: "A", SinkConcept: "B", Solver: "nope"}); err == nil {
		t.Fatal("an unregistered solver must error")
	}
	eng.Register(stubTaint{})
	if _, err := eng.Evaluate(Rule{ID: "R", SourceConcept: "A", SinkConcept: "B", Solver: "taint"}); err == nil {
		t.Fatal("a rule naming an undefined concept must error")
	}
}

package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/risk"
	"github.com/vyprai/vyql/usg"
)

func evalOne(t *testing.T, src string, s usg.Store) int {
	t.Helper()
	onto := runtimeTestOntology()
	decls, err := parseV2DefinitionsForTest(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := New(onto, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return len(fs)
}

func runtimeTestOntology() *ontology.Ontology {
	onto := contextTestOntology()
	onto.Add(ontology.Concept{Name: "Link", Package: "custom", Kind: "asset"})
	onto.Add(ontology.Concept{Name: "Indicator", Package: "custom", Kind: "asset"})
	onto.Add(ontology.Concept{Name: "Process", Package: "custom", Kind: "asset"})
	onto.Add(ontology.Concept{
		Name:                    "ObservedLink",
		Package:                 "custom",
		Kind:                    "fact",
		ContextConfirmDstProp:   "dst",
		ContextConfirmFlagProp:  "observed",
		ContextConfirmFlagValue: "yes",
		ContextConfirmLabel:     "confirmed by runtime",
	})
	return onto
}

func TestRuntimeLinkToLabeledTarget(t *testing.T) {
	rule := `
module test;
rule LinkToLabeledTarget {
  meta { id: "TEST-RUNTIME-004", severity: high }
  query concept as c where c.concept == custom.Link
    references concept as dst where dst.concept == custom.Indicator and dst.id == c.dst
    select c
}
`
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "marked", Type: "custom.Endpoint"})
	s.AddLabel("marked", usg.Label{Concept: "custom.Indicator"})
	s.AddNode(usg.Node{ID: "plain", Type: "custom.Endpoint"})
	s.AddNode(usg.Node{ID: "link1", Type: "custom.Link", Props: map[string]string{"dst": "marked"}})
	s.AddLabel("link1", usg.Label{Concept: "custom.Link"})
	s.AddNode(usg.Node{ID: "link2", Type: "custom.Link", Props: map[string]string{"dst": "plain"}})
	s.AddLabel("link2", usg.Label{Concept: "custom.Link"})

	if n := evalOne(t, rule, s); n != 1 {
		t.Fatalf("link rule should fire once, got %d", n)
	}
}

func TestRuntimePropertyDrift(t *testing.T) {
	rule := `
module test;
rule PropertyDrift {
  meta { id: "TEST-RUNTIME-003", severity: high }
  issue custom.Process as p
  where p.image not in [expectedA, expectedB]
}
`
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "proc1", Type: "custom.Process", Props: map[string]string{"image": "unexpected"}})
	s.AddLabel("proc1", usg.Label{Concept: "custom.Process"})
	s.AddNode(usg.Node{ID: "proc2", Type: "custom.Process", Props: map[string]string{"image": "expectedA"}})
	s.AddLabel("proc2", usg.Label{Concept: "custom.Process"})

	if n := evalOne(t, rule, s); n != 1 {
		t.Fatalf("drift should fire once, got %d", n)
	}
}

func TestRuntimeConfirmationEscalatesRisk(t *testing.T) {
	onto := runtimeTestOntology()
	if edge, err := onto.Get("custom.Edge"); err == nil {
		edge.ContextReachLabel = "internet-reachable"
	}
	decls, _ := parseV2DefinitionsForTest(flowRule)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	build := func(observed bool) usg.Store {
		s := usg.NewInMemStore()
		s.AddNode(usg.Node{ID: "svc", Type: "custom.Service", Props: map[string]string{"loc": "svc"}})
		s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "flow:1"}})
		s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "flow:2", "endpoint": "svc"}})
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddLabel("q", usg.Label{Concept: "custom.Target"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
		s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge", Props: map[string]string{"loc": "edge"}})
		s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
		s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "svc", Props: map[string]string{"rule": "edge-svc"}})
		if observed {
			s.AddNode(usg.Node{ID: "observed", Type: "custom.Observation",
				Props: map[string]string{"dst": "svc", "observed": "yes", "evidence_ref": "observed://example"}})
			s.AddLabel("observed", usg.Label{Concept: "custom.ObservedLink"})
		}
		return s
	}

	score := func(observed bool) risk.Score {
		fs, err := New(onto, build(observed)).Evaluate(compiled[0])
		if err != nil || len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d err=%v", len(fs), err)
		}
		return risk.Prioritize(fs[0])
	}

	planned := score(false)
	confirmed := score(true)

	if confirmed.Total <= planned.Total {
		t.Fatalf("runtime confirmation should escalate priority: confirmed=%d planned=%d", confirmed.Total, planned.Total)
	}
	if !strings.Contains(confirmed.Render(), "confirmed by runtime") {
		t.Fatalf("confirmed finding should cite runtime evidence:\n%s", confirmed.Render())
	}
}

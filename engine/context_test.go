package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

func contextTestOntology() *ontology.Ontology {
	onto := addFlowConcepts(ontology.New())
	onto.Add(ontology.Concept{
		Name:                   "Edge",
		Package:                "custom",
		Kind:                   "exposure",
		ContextReachSource:     "true",
		ContextReachLabel:      "edge-reachable",
		ContextReachTargetProp: "endpoint",
	})
	onto.Add(ontology.Concept{
		Name:                   "Asset",
		Package:                "custom",
		Kind:                   "asset",
		ContextAssetTargetProp: "asset",
		ContextAssetLabel:      "target asset {target} holds [{kinds}]",
	})
	return onto
}

func buildContextGraph(exposed, important bool) usg.Store {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "svc", Type: "custom.Service", Props: map[string]string{"loc": "svc"}})
	s.AddNode(usg.Node{ID: "asset", Type: "custom.Asset", Props: map[string]string{"loc": "asset"}})
	if important {
		s.AddLabel("asset", usg.Label{Concept: "custom.Asset", Detail: map[string]string{"asset_kinds": "custom.Important"}})
	}
	s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "flow:1"}})
	s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "flow:2", "endpoint": "svc", "asset": "asset"}})
	s.AddLabel("in", usg.Label{Concept: "custom.Input"})
	s.AddLabel("q", usg.Label{Concept: "custom.Target"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	if exposed {
		s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge", Props: map[string]string{"loc": "edge"}})
		s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
		s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "svc", Props: map[string]string{"rule": "edge-svc"}})
	}
	return s
}

func TestCrossDomainContext(t *testing.T) {
	onto := contextTestOntology()
	decls, err := parseV2DefinitionsForTest(flowRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	eval := func(exposed, important bool) []string {
		fs, err := New(onto, buildContextGraph(exposed, important)).Evaluate(compiled[0])
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(fs))
		}
		return fs[0].Context
	}

	ctx1 := eval(true, true)
	hasExposure, hasAsset := false, false
	for _, c := range ctx1 {
		if strings.Contains(c, "edge-reachable") {
			hasExposure = true
		}
		if strings.Contains(c, "custom.Important") {
			hasAsset = true
		}
	}
	if !hasExposure {
		t.Fatalf("exposed+important: exposure context missing: %v", ctx1)
	}
	if !hasAsset {
		t.Fatalf("exposed+important: asset context missing: %v", ctx1)
	}
	if !strings.Contains(strings.Join(ctx1, " "), "edge-svc") {
		t.Fatalf("exposure context should name the reach rule: %v", ctx1)
	}

	if ctx2 := eval(false, false); len(ctx2) != 0 {
		t.Fatalf("unexposed and unmarked: expected no context, got %v", ctx2)
	}
}

func TestCrossDomainContextReachSourceComesFromOntology(t *testing.T) {
	src := `
module custom;
concept PublicEdge : exposure {
  context_reach_source: true
  context_reach_label: "public-edge-reachable"
  context_reach_target_prop: endpoint
}
concept PublicEdgeObservation : observation {
  context_confirm_dst_prop: target
  context_confirm_flag_prop: observed
  context_confirm_flag_value: yes
  context_confirm_label: "confirmed by public edge observation"
}
concept Input : source { taint: [custom.Taint] }
concept Target : sink { vulnerable_to: [custom.Condition] }
module t;
rule Flow {
  taint custom.Input -> custom.Target
}
`
	onto := ontology.New()
	cs, err := ontology.LoadConceptText(src)
	if err != nil {
		t.Fatalf("load concepts: %v", err)
	}
	for _, c := range cs {
		onto.Add(c)
	}
	decls, _ := parseV2DefinitionsForTest(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge"})
	s.AddLabel("edge", usg.Label{Concept: "custom.PublicEdge"})
	s.AddNode(usg.Node{ID: "svc", Type: "runtime.Service"})
	s.AddNode(usg.Node{ID: "in", Type: "code.Call", Props: map[string]string{"loc": "h:1"}})
	s.AddLabel("in", usg.Label{Concept: "custom.Input"})
	s.AddNode(usg.Node{ID: "sink", Type: "code.Call", Props: map[string]string{"loc": "h:2", "endpoint": "svc"}})
	s.AddLabel("sink", usg.Label{Concept: "custom.Target"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "sink"})
	s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "svc", Props: map[string]string{"rule": "edge-rule", "proto": "tcp", "port": "443"}})
	s.AddNode(usg.Node{ID: "obs", Type: "custom.Observation", Props: map[string]string{"target": "svc", "observed": "yes"}})
	s.AddLabel("obs", usg.Label{Concept: "custom.PublicEdgeObservation"})

	fs, err := New(onto, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if len(fs[0].Context) == 0 || !strings.Contains(fs[0].Context[0], "public-edge-reachable") {
		t.Fatalf("context should use ontology reach-source label, got %v", fs[0].Context)
	}
	if !strings.Contains(fs[0].Context[0], "confirmed by public edge observation") {
		t.Fatalf("context should use ontology confirmation label, got %v", fs[0].Context)
	}
}

package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// buildContextGraph mirrors case_10's graph(): the SAME code subgraph (in->q
// SQLi) with optional cloud exposure (internet -> svc) and a PII database, so the
// finding's cross-domain context changes with where the code is deployed.
func buildContextGraph(exposed, pii bool) usg.Store {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "svc", Type: "cloud.Container", Props: map[string]string{"loc": "svc"}})
	s.AddNode(usg.Node{ID: "db", Type: "cloud.Database", Props: map[string]string{"loc": "db"}})
	if pii {
		s.AddLabel("db", usg.Label{Concept: "cloud.Database", Detail: map[string]string{"asset_kinds": "data.Pii"}})
	}
	s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "h.py:1"}})
	s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "h.py:2", "service": "svc", "database": "db"}})
	s.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
	s.AddLabel("q", usg.Label{Concept: "code.SqlExecution"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	if exposed {
		s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet", Props: map[string]string{"loc": "0.0.0.0/0"}})
		s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
		s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "svc",
			Props: map[string]string{"rule": "sg-pub:443", "proto": "tcp", "port": "443"}})
	}
	return s
}

// Mirrors poc/cases/case_10_context.py — identical SQLi rule + identical code
// subgraph, different cloud/asset context => different finding context. Exposure
// (internet-reachable service) and asset (PII database) lines appear on the
// finding only when the deployment warrants; otherwise the finding stands with
// empty context (same vulnerability, lower priority).
func TestCrossDomainContext(t *testing.T) {
	onto := ontology.Seed()
	decls, err := parser.Parse(sqliRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	eval := func(exposed, pii bool) []string {
		fs, err := New(onto, buildContextGraph(exposed, pii)).Evaluate(compiled[0])
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("expected exactly 1 finding, got %d", len(fs))
		}
		return fs[0].Context
	}

	// exposed + PII => both context lines
	ctx1 := eval(true, true)
	hasExposure, hasAsset := false, false
	for _, c := range ctx1 {
		if strings.Contains(c, "internet-reachable") {
			hasExposure = true
		}
		if strings.Contains(c, "Pii") {
			hasAsset = true
		}
	}
	if !hasExposure {
		t.Fatalf("exposed+PII: exposure context missing: %v", ctx1)
	}
	if !hasAsset {
		t.Fatalf("exposed+PII: asset context missing: %v", ctx1)
	}
	// the exposure witness names the permitting SG rule
	if !strings.Contains(strings.Join(ctx1, " "), "sg-pub:443") {
		t.Fatalf("exposure context should name the SG rule: %v", ctx1)
	}

	// internal + non-PII => still a finding, but no context lines (lower priority)
	if ctx2 := eval(false, false); len(ctx2) != 0 {
		t.Fatalf("internal & non-PII: expected no context, got %v", ctx2)
	}
}

func TestCrossDomainContextReachSourceComesFromOntology(t *testing.T) {
	src := `
module custom;
concept PublicEdge : exposure {
  context_reach_source: true
  context_reach_label: "public-edge-reachable"
}
module code;
concept Input : source { taint: [taint.UntrustedData] }
concept Sink : sink { vulnerable_to: [injection.SqlInjection] }
module t;
rule Flow {
  taint code.Input -> code.Sink
}
`
	onto := ontology.Seed()
	cs, err := ontology.LoadConceptText(src)
	if err != nil {
		t.Fatalf("load concepts: %v", err)
	}
	for _, c := range cs {
		onto.Add(c)
	}
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge"})
	s.AddLabel("edge", usg.Label{Concept: "custom.PublicEdge"})
	s.AddNode(usg.Node{ID: "svc", Type: "runtime.Service"})
	s.AddNode(usg.Node{ID: "in", Type: "code.Call", Props: map[string]string{"loc": "h:1"}})
	s.AddLabel("in", usg.Label{Concept: "code.Input"})
	s.AddNode(usg.Node{ID: "sink", Type: "code.Call", Props: map[string]string{"loc": "h:2", "service": "svc"}})
	s.AddLabel("sink", usg.Label{Concept: "code.Sink"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "sink"})
	s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "svc", Props: map[string]string{"rule": "edge-rule", "proto": "tcp", "port": "443"}})

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
}

package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestCompileLoweredV2Rule(t *testing.T) {
	decls, err := parser.ParseV2Runtime(`
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}
`)
	if err != nil {
		t.Fatalf("ParseV2Runtime: %v", err)
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) > 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(compiled))
	}
	cr := compiled[0]
	if cr.Rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("qualified name = %q", cr.Rule.QualifiedName())
	}
	if !cr.KillControls["core.SqlParameterization"] {
		t.Fatalf("coveredBy check did not become a kill control: %+v", cr.KillControls)
	}
}

func TestLoweredV2ConfidenceClauseFiltersFindings(t *testing.T) {
	decls, err := parser.ParseV2Runtime(`
module rules.review;
rule HighConfidenceReview {
  issue custom.Review as r
  with confidence >= high
}
`)
	if err != nil {
		t.Fatalf("ParseV2Runtime: %v", err)
	}
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Review", Package: "custom", Kind: "issue"})
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "low", Type: "code.Call"})
	store.AddLabel("low", usg.Label{Concept: "custom.Review", Provenance: usg.Provenance{Confidence: "low"}})
	if got, err := New(onto, store).Evaluate(compiled[0]); err != nil {
		t.Fatalf("evaluate low: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("low-confidence finding passed v2 floor: %+v", got)
	}

	store.AddNode(usg.Node{ID: "high", Type: "code.Call"})
	store.AddLabel("high", usg.Label{Concept: "custom.Review", Provenance: usg.Provenance{Confidence: "high"}})
	got, err := New(onto, store).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate high: %v", err)
	}
	if len(got) != 1 || got[0].Bindings[0].NodeID != "high" {
		t.Fatalf("high-confidence finding did not pass v2 floor: %+v", got)
	}
}

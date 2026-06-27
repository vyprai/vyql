package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestToyEndToEndSlice(t *testing.T) {
	onto := solverContractOntology()
	s := buildToyGraph(t)

	rules := `
module test;
rule FirstFlow {
  meta { id: "TEST-FLOW-001", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.path coveredBy custom.Transform
}
rule SecondFlow {
  meta { id: "TEST-FLOW-002", severity: critical }
  taint custom.Input -> custom.OtherTarget as sink
  unless sink.path coveredBy custom.OtherTargetTransform
}

rule ReachAsset {
  meta { id: "TEST-REACH-003", severity: critical }
  reach custom.Edge -> custom.Asset
  where holdsAssetKind(custom.Asset, [custom.Important])
}

rule ActorCapability {
  meta { id: "TEST-ASSUME-004", severity: critical }
  assume custom.Actor -> custom.Capability
}
rule ComposedMatch {
  meta { id: "TEST-MATCH-005", severity: critical }
  issue custom.WorkItem as w
  where reach(custom.Edge, w.workload) and assume(w, custom.Capability)
}
`
	decls, err := parser.ParseRuntime(rules)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile errors: %v", errs)
	}
	if len(compiled) != 5 {
		t.Fatalf("expected 5 compiled rules, got %d", len(compiled))
	}

	eng := New(onto, s)
	byID := map[string]int{}
	bindingProvenanceSeen := false
	negationEvidenceSeen := false
	for _, cr := range compiled {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range fs {
			byID[f.RuleID]++
			// every finding must carry a non-empty proof tree: solver witness
			// for flow rules, or where-clause context for match rules.
			if len(f.Witness) == 0 && len(f.Context) == 0 {
				t.Fatalf("%s: finding has empty proof tree (no witness or context)", f.RuleID)
			}
			if f.Render() == "" {
				t.Fatalf("%s: empty render", f.RuleID)
			}
			for _, b := range f.Bindings {
				if b.LabelProvenance != "" {
					bindingProvenanceSeen = true
				}
			}
			for _, ne := range f.NegationEvidence {
				if !ne.Satisfied && ne.Detail != "" {
					negationEvidenceSeen = true
				}
			}
		}
	}

	want := map[string]int{
		"TEST-FLOW-001":   1,
		"TEST-FLOW-002":   1,
		"TEST-REACH-003":  1,
		"TEST-ASSUME-004": 1,
		"TEST-MATCH-005":  1,
	}
	for id, n := range want {
		if byID[id] != n {
			t.Fatalf("rule %s: expected %d finding(s), got %d", id, n, byID[id])
		}
	}
	if !bindingProvenanceSeen {
		t.Fatal("no finding carried label provenance from the adapter layer")
	}
	if !negationEvidenceSeen {
		t.Fatal("no finding carried negation evidence for an unsatisfied unless-clause")
	}

	flowFindings, _ := eng.Evaluate(compiled[0])
	render := flowFindings[0].Render()
	if !strings.Contains(render, "taint path:") {
		t.Fatalf("flow render should show the taint path:\n%s", render)
	}
}

func buildToyGraph(t *testing.T) usg.Store {
	t.Helper()
	s := usg.NewInMemStore()

	for _, n := range []struct{ id, loc string }{
		{"input", "flow/input:10"},
		{"target", "flow/target:42"},
		{"otherTarget", "flow/other-target:8"},
	} {
		s.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "input", Dst: "target"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "input", Dst: "otherTarget"})

	flowAdapter := adapters.Adapter{
		Name: "test.flow", Technology: "test", Specificity: 2,
		Fidelity: "resolved", Confidence: "high",
		Apply: func(usg.Store) []adapters.Mapping {
			return []adapters.Mapping{
				{NodeID: "input", Concept: "custom.Input"},
				{NodeID: "target", Concept: "custom.Target"},
				{NodeID: "otherTarget", Concept: "custom.OtherTarget"},
			}
		},
	}
	if _, _, err := adapters.Apply(s, []adapters.Adapter{flowAdapter}, nil); err != nil {
		t.Fatal(err)
	}

	s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge", Props: map[string]string{"loc": "edge"}})
	s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
	s.AddNode(usg.Node{ID: "hop", Type: "custom.Hop"})
	s.AddNode(usg.Node{ID: "workload", Type: "custom.Workload", Props: map[string]string{"loc": "workload"}})
	s.AddNode(usg.Node{ID: "asset", Type: "custom.Asset", Props: map[string]string{"loc": "asset"}})
	s.AddLabel("asset", usg.Label{Concept: "custom.Asset", Detail: map[string]string{"asset_kinds": "custom.Important"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "hop", Props: map[string]string{"rule": "edge-hop"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "hop", Dst: "workload", Props: map[string]string{"rule": "hop-workload"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "workload", Dst: "asset", Props: map[string]string{"rule": "workload-asset"}})

	s.AddNode(usg.Node{ID: "actor", Type: "custom.Actor", Props: map[string]string{"loc": "actor"}})
	s.AddLabel("actor", usg.Label{Concept: "custom.Actor"})
	s.AddNode(usg.Node{ID: "capability", Type: "custom.Capability", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("capability", usg.Label{Concept: "custom.Capability"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "actor", Dst: "capability", Props: map[string]string{"ability": "actor-capability"}})

	s.AddNode(usg.Node{ID: "workItem", Type: "custom.WorkItem", Props: map[string]string{"loc": "work-item", "workload": "workload"}})
	s.AddLabel("workItem", usg.Label{Concept: "custom.WorkItem"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "workItem", Dst: "capability", Props: map[string]string{"ability": "workitem-capability"}})

	return s
}

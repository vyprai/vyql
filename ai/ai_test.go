package ai

import (
	"testing"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/usg"
)

func testStore(t *testing.T) usg.Store {
	t.Helper()
	g := usg.NewInMemStore()
	_ = g.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{"loc": "a.py:1", "region": "/fn1"}})
	_ = g.AddNode(usg.Node{ID: "sink", Type: "code.Call", Props: map[string]string{"loc": "a.py:3", "region": "/fn1"}})
	_ = g.AddNode(usg.Node{ID: "mid", Type: "code.Arg", Props: map[string]string{"loc": "a.py:2", "region": "/fn1"}})
	_ = g.AddLabel("mid", usg.Label{Concept: "code.HttpInput"})
	_ = g.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "mid"})
	_ = g.AddEdge(usg.Edge{Type: "FLOWS", Src: "mid", Dst: "sink"})
	return g
}

func sampleFinding() *findings.Finding {
	return &findings.Finding{
		RuleID:      "VYQL-INJ-001",
		WitnessKind: "taint",
		Witness:     []string{"src", "mid", "sink"},
		Bindings: []findings.Binding{
			{Name: "source", NodeID: "src", Concept: "code.HttpInput", Loc: "a.py:1"},
			{Name: "sink", NodeID: "sink", Concept: "code.SqlExecution", Loc: "a.py:3"},
		},
		NegationEvidence: []findings.NegationEvidence{{Clause: "sanitized_by core.SqlParameterization"}},
	}
}

func TestBuildEvidencePack(t *testing.T) {
	g := testStore(t)
	p := BuildEvidencePack(g, sampleFinding())

	if p.Hotspot != "sink" {
		t.Errorf("hotspot = %q, want sink (the last binding)", p.Hotspot)
	}
	if p.RuleID != "VYQL-INJ-001" {
		t.Errorf("ruleID = %q", p.RuleID)
	}
	if len(p.Witness) != 3 {
		t.Errorf("witness = %v, want 3 hops", p.Witness)
	}
	if len(p.Bindings) != 2 {
		t.Errorf("bindings = %d, want 2", len(p.Bindings))
	}
	// the FLOWS neighbour `mid` (adjacent to both src and sink) must appear, with its region.
	var foundMid bool
	for _, n := range p.Neighbors {
		if n.NodeID == "mid" {
			foundMid = true
			if n.Region != "/fn1" {
				t.Errorf("neighbour mid region = %q, want /fn1", n.Region)
			}
		}
	}
	if !foundMid {
		t.Errorf("expected `mid` in the grounded neighbourhood, got %v", p.Neighbors)
	}
	if len(p.Negations) != 1 {
		t.Errorf("negations = %v, want the sanitizer clause", p.Negations)
	}
}

func TestStubReasonerYieldsNothing(t *testing.T) {
	g := testStore(t)
	out, err := Analyze(g, []*findings.Finding{sampleFinding()}, StubReasoner{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("stub reasoner must emit no findings, got %d", len(out))
	}
}

func TestScriptedReasonerGroundedFinding(t *testing.T) {
	g := testStore(t)
	r := ScriptedReasoner{ByHotspot: map[string][]Hypothesis{
		"sink": {
			{Title: "tenant-isolation bypass", Rationale: "request id flows cross-tenant",
				WitnessRef: []string{"src", "mid", "sink"}, Confidence: "medium"},
			{Title: "ungrounded guess", Rationale: "no witness"}, // must be dropped
		},
	}}
	out, err := Analyze(g, []*findings.Finding{sampleFinding()}, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 GROUNDED ai finding (the ungrounded one dropped), got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "VYQL-AI-001" || f.WitnessKind != "ai" {
		t.Errorf("ai finding shape wrong: %+v", f)
	}
	if len(f.Witness) != 3 {
		t.Errorf("ai finding must carry the deterministic witness, got %v", f.Witness)
	}
	if f.Bindings[0].Loc != "a.py:3" {
		t.Errorf("hotspot loc = %q, want the sink loc a.py:3", f.Bindings[0].Loc)
	}
}

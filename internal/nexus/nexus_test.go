package nexus

import (
	"encoding/json"
	"testing"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/resultpolicy"
)

func TestNexusEmitAndValidate(t *testing.T) {
	f := &findings.Finding{
		RuleID: "VYQL-INJ-001", Severity: "high", Confidence: "high", WitnessKind: "taint",
		Witness: []string{"in", "q"},
		Bindings: []findings.Binding{
			{Name: "source", NodeID: "in", Concept: "code.HttpInput", Loc: "a.go:1"},
			{Name: "sink", NodeID: "q", Concept: "code.SqlExecution", Loc: "a.go:2"},
		},
		NegationEvidence: []findings.NegationEvidence{{Clause: "path_covered_by core.SqlParameterization", Satisfied: false}},
	}
	doc := ToNexus([]*findings.Finding{f}, "0.1.0", "1.4.0")
	if p := Validate(doc); len(p) != 0 {
		t.Fatalf("nexus doc should validate, got %v", p)
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("nexus not JSON-serializable: %v", err)
	}
	fs := doc["findings"].([]any)
	nf := fs[0].(map[string]any)
	if nf["fingerprint"] != resultpolicy.Fingerprint(f) {
		t.Fatalf("nexus fingerprint mismatch")
	}
	if len(nf["bindings"].([]any)) != 2 {
		t.Fatalf("nexus should carry both bindings")
	}
}

func TestNexusValidateBad(t *testing.T) {
	if len(Validate(map[string]any{"schemaVersion": "0.0"})) == 0 {
		t.Fatal("validator should reject a bad nexus doc")
	}
}

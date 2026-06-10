package sarif

import (
	"encoding/json"
	"testing"

	"github.com/vyprai/vyql/findings"
)

func sampleFinding() *findings.Finding {
	return &findings.Finding{
		RuleID:      "VYQL-INJ-001",
		Severity:    "high",
		WitnessKind: "taint",
		Confidence:  "high",
		Witness:     []string{"in", "interp", "q"},
		Bindings: []findings.Binding{
			{Name: "source", NodeID: "in", Concept: "code.HttpInput", Loc: "orders.js:12", LabelProvenance: "code.HttpInput by javascript.express@resolved"},
			{Name: "sink", NodeID: "q", Concept: "code.SqlExecution", Loc: "orders.js:14"},
		},
		NegationEvidence: []findings.NegationEvidence{
			{Clause: "sanitized_by core.SqlParameterization", Satisfied: false, Detail: "none found anywhere on flows"},
		},
	}
}

func TestEmitAndValidate(t *testing.T) {
	doc := ToSARIF([]*findings.Finding{sampleFinding()},
		"0.1.0", map[string]map[string]any{"VYQL-INJ-001": {"cwe": []string{"CWE_89"}}})

	if problems := ValidateSARIF(doc); len(problems) != 0 {
		t.Fatalf("SARIF should validate, got: %v", problems)
	}

	// round-trips through JSON
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("SARIF not JSON-serializable: %v", err)
	}

	run := doc["runs"].([]any)[0].(map[string]any)
	res := run["results"].([]any)[0].(map[string]any)
	if res["level"] != "error" {
		t.Fatalf("high severity should map to error, got %v", res["level"])
	}
	fp := res["partialFingerprints"].(map[string]any)["vyqlFingerprint/v1"]
	if fp != sampleFinding().Fingerprint() {
		t.Fatalf("SARIF fingerprint mismatch: %v", fp)
	}
	if _, ok := res["codeFlows"]; !ok {
		t.Fatal("taint finding should carry a codeFlow")
	}
	if _, ok := res["locations"]; !ok {
		t.Fatal("finding should carry a sink location")
	}
}

func TestValidateCatchesBadDoc(t *testing.T) {
	bad := map[string]any{"version": "1.0", "runs": []any{}}
	if len(ValidateSARIF(bad)) == 0 {
		t.Fatal("validator should reject a malformed SARIF doc")
	}
}

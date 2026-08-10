package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/resultpolicy"
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
			{Clause: "path_covered_by core.SqlParameterization", Satisfied: false, Detail: "none found anywhere on flows"},
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
	fp := res["partialFingerprints"].(map[string]any)["vyqlFingerprint/v2"]
	if fp != resultpolicy.Fingerprint(sampleFinding()) {
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

// T9.1 — the SARIF 2.1.0 schema-required shape: version, $schema, a tool driver with a
// rules array, and each result carrying a ruleId. The CWE travels on the rule metadata.
func TestSARIFSchemaShape(t *testing.T) {
	doc := ToSARIF([]*findings.Finding{sampleFinding()},
		"0.1.0", map[string]map[string]any{"VYQL-INJ-001": {"cwe": []string{"CWE_89"}}})

	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("SARIF doc missing $schema")
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("tool.driver.rules missing/empty: %v", driver["rules"])
	}
	// the result references a rule by id.
	res := run["results"].([]any)[0].(map[string]any)
	if res["ruleId"] != "VYQL-INJ-001" {
		t.Errorf("result.ruleId = %v, want VYQL-INJ-001", res["ruleId"])
	}
	// the CWE metadata is carried somewhere on the emitted rule object.
	foundCWE := false
	for _, r := range rules {
		if blob, err := json.Marshal(r); err == nil && strings.Contains(string(blob), "CWE") {
			foundCWE = true
		}
	}
	if !foundCWE {
		t.Error("rule metadata does not carry the CWE")
	}
}

// The rule descriptor is a consumed contract, not decoration: benchmark scorers read
// a finding's weakness class from here instead of parsing vyql/packs, and GitHub code
// scanning ranks by security-severity. Emitting a bare {id, name} — which this did
// until the metadata was wired through — silently costs both.
func TestRuleDescriptorPublishesCWEAndSeverity(t *testing.T) {
	doc := ToSARIF([]*findings.Finding{sampleFinding()}, "0.1.0",
		map[string]map[string]any{
			"VYQL-INJ-001": {"cwe": []string{"CWE_89", "CWE-79"}, "severity": "critical"},
		})
	rules := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule descriptor, got %d", len(rules))
	}
	rule := rules[0].(map[string]any)
	props, ok := rule["properties"].(map[string]any)
	if !ok {
		t.Fatal("rule descriptor carries no properties — scorers cannot read its CWE")
	}

	// tags carry both the bare id and the taxonomy path, and normalise the CWE_nnn
	// spelling rule metadata uses to the CWE-nnn spelling consumers expect.
	tags := props["tags"].([]string)
	want := []string{"CWE-89", "external/cwe/cwe-089", "CWE-79", "external/cwe/cwe-079"}
	if strings.Join(tags, ",") != strings.Join(want, ",") {
		t.Errorf("tags = %v, want %v", tags, want)
	}
	if props["security-severity"] != "9.3" {
		t.Errorf("security-severity = %v, want 9.3 for critical", props["security-severity"])
	}
	if lvl := rule["defaultConfiguration"].(map[string]any)["level"]; lvl != "error" {
		t.Errorf("level = %v, want error for critical", lvl)
	}
	if problems := ValidateSARIF(doc); len(problems) != 0 {
		t.Fatalf("enriched document should still validate, got: %v", problems)
	}
}

// A rule with no metadata must still produce a well-formed descriptor rather than
// half-populated properties.
func TestRuleDescriptorWithoutMetaStaysValid(t *testing.T) {
	doc := ToSARIF([]*findings.Finding{sampleFinding()}, "0.1.0", nil)
	rule := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if _, hasCWE := (rule["properties"].(map[string]any))["cwe"]; hasCWE {
		t.Error("no rule metadata was supplied, so no cwe should be claimed")
	}
	// severity still comes off the finding itself
	if rule["defaultConfiguration"].(map[string]any)["level"] != "error" {
		t.Error("level should fall back to the finding's own severity")
	}
	if problems := ValidateSARIF(doc); len(problems) != 0 {
		t.Fatalf("should validate, got: %v", problems)
	}
}

// A result and its rule descriptor must file the same finding at the same level. Two mappings
// used to exist and they disagreed on "low": the result came out "note" while the rule defaulted
// to "warning", so one document contradicted itself and a consumer filtering on either field saw
// a different set. Every severity is checked, not just the one that broke.
func TestResultAndRuleDescriptorAgreeOnLevel(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		f := sampleFinding()
		f.Severity = sev
		doc := ToSARIF([]*findings.Finding{f}, "0.1.0",
			map[string]map[string]any{f.RuleID: {"severity": sev}})
		run := doc["runs"].([]any)[0].(map[string]any)

		result := run["results"].([]any)[0].(map[string]any)
		rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
		ruleLevel := rule["defaultConfiguration"].(map[string]any)["level"]

		if result["level"] != ruleLevel {
			t.Errorf("severity %q: result level %v but rule defaultConfiguration level %v",
				sev, result["level"], ruleLevel)
		}
	}
}

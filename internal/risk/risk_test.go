package risk

import (
	"os"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/parser"
)

// mkFinding derives the typed facts from the context lines a case supplies, so the cases keep
// reading as prose while exercising the fields the priority model now scores. The derivation
// lives here, in the fixture: recognising a rendered label is a test concern, and having it in
// the production path is exactly what this change removed.
func mkFinding(severity, confidence string, context []string) *findings.Finding {
	var facts findings.ContextFacts
	for _, c := range context {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "internet-reachable") {
			facts.InternetReachable, facts.ReachWitness = true, c
		}
		if strings.Contains(lower, "confirmed by runtime") {
			facts.RuntimeConfirmed, facts.ConfirmWitness = true, c
		}
		if strings.Contains(lower, "holds [") {
			facts.HoldsAsset, facts.AssetWitness = true, c
		}
	}
	return &findings.Finding{
		RuleID: "VYQL-INJ-001", Severity: severity, Confidence: confidence, WitnessKind: "taint",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "h.py:1"},
			{Name: "sink", Concept: "code.SqlExecution", Loc: "h.py:2"},
		},
		Context: context,
		Facts:   facts,
	}
}

func TestPriorityPolicyLoadedFromV2(t *testing.T) {
	m := conf()
	if got := m.severityWeight("high"); got != 3 {
		t.Fatalf("high severity weight = %d, want 3", got)
	}
	if got := m.factorWeight("controlPressure"); got != -1 {
		t.Fatalf("controlPressure weight = %d, want -1", got)
	}
	if got := m.factorWeight("confidenceLow"); got != -2 {
		t.Fatalf("confidenceLow weight = %d, want -2", got)
	}
}

func TestLegacyRiskJSONIsNotAPrioritySource(t *testing.T) {
	if _, err := datadir.Read("risk.json"); err == nil || !os.IsNotExist(err) {
		t.Fatalf("risk priority must be authored as policy priority default, not risk.json; read error = %v", err)
	}
}

// An internet-reachable PII finding outranks the same finding deployed
// internally; every factor carries a witness; the combination is monotonic.
func TestPriorityBands(t *testing.T) {
	exposedPII := mkFinding("high", "high", []string{
		"svc is internet-reachable (via sg-pub:443)",
		"sink database db holds [data.Pii]",
	})
	internal := mkFinding("high", "high", nil)

	hi := Prioritize(exposedPII)
	lo := Prioritize(internal)

	// exposed+PII (sev3+exp2+asset2=7 => P1) must be strictly more urgent than
	// internal (sev3=3 => P2). Lower band number = more urgent.
	if !moreUrgent(hi.Band, lo.Band) {
		t.Fatalf("exposed+PII should outrank internal: %s vs %s", hi.Band, lo.Band)
	}
	if hi.Total <= lo.Total {
		t.Fatalf("exposed+PII total (%d) should exceed internal (%d)", hi.Total, lo.Total)
	}

	// every factor carries a witness
	for _, f := range hi.Factors {
		if strings.TrimSpace(f.Witness) == "" {
			t.Fatalf("factor %q has no witness", f.Name)
		}
	}
	// the exposure factor names the SG-rule witness (carried from context)
	if !strings.Contains(hi.Render(), "sg-pub:443") {
		t.Fatalf("exposure factor should carry the reach witness:\n%s", hi.Render())
	}
}

// Adding a factor (exposure) must never make a finding LESS urgent (monotonic ⊕).
func TestMonotonic(t *testing.T) {
	base := Prioritize(mkFinding("medium", "high", nil))
	withExposure := Prioritize(mkFinding("medium", "high",
		[]string{"svc is internet-reachable (via sg-pub:443)"}))
	if withExposure.Total < base.Total {
		t.Fatalf("exposure must not reduce priority: %d < %d", withExposure.Total, base.Total)
	}
	if bandNum(withExposure.Band) > bandNum(base.Band) {
		t.Fatalf("exposure must not raise the band number: %s vs %s", withExposure.Band, base.Band)
	}
}

// Low derivation confidence discounts priority; runtime-confirmed exposure raises
// it. Both are witness-backed factors.
func TestConfidenceAndRuntimeConfirmation(t *testing.T) {
	lowConf := Prioritize(mkFinding("high", "low", nil))
	highConf := Prioritize(mkFinding("high", "high", nil))
	if lowConf.Total >= highConf.Total {
		t.Fatalf("low confidence should discount priority: %d >= %d", lowConf.Total, highConf.Total)
	}

	observed := Prioritize(mkFinding("high", "high",
		[]string{"svc is internet-reachable (via sg-pub:443) — confirmed by runtime traffic"}))
	planned := Prioritize(mkFinding("high", "high",
		[]string{"svc is internet-reachable (via sg-pub:443)"}))
	if observed.Total <= planned.Total {
		t.Fatalf("runtime-confirmed exposure should outweigh planned-only: %d <= %d", observed.Total, planned.Total)
	}
}

func TestPriorityUsesAuthoredWhenExpressions(t *testing.T) {
	m := model{
		Severity: map[string]int{"default": 1, "high": 3},
		Factors: map[string]priorityFactor{
			"exposure": {Weight: 5, When: parser.V2RefExpr{Name: "finding.exploitSignal"}},
		},
		FactorOrder: []string{"exposure"},
		Bands: []struct {
			Band string
			Min  int
		}{{Band: "P1", Min: 8}, {Band: "P2", Min: 3}, {Band: "P4", Min: 0}},
	}

	internetOnly := mkFinding("high", "high", []string{"svc is internet-reachable (via sg-pub:443)"})
	if got := prioritizeWithModel(internetOnly, m); got.Total != 3 || hasFactor(got, "exposure") {
		t.Fatalf("factor should follow authored when expression, not its name: %+v", got)
	}

	withAdvisory := mkFinding("high", "high", nil)
	withAdvisory.Bindings[0].LabelProvenance = "npm advisory GHSA-xxxx"
	got := prioritizeWithModel(withAdvisory, m)
	if got.Total != 8 || !hasFactor(got, "exposure") {
		t.Fatalf("authored exploitSignal predicate should trigger exposure factor: %+v", got)
	}
	if !strings.Contains(got.Render(), "GHSA-xxxx") {
		t.Fatalf("factor witness should come from the predicate evidence:\n%s", got.Render())
	}
}

func TestPriorityPolicyNumericComparisons(t *testing.T) {
	when := parser.V2BinaryExpr{
		Left:  parser.V2RefExpr{Name: "finding.bindingCount"},
		Op:    ">=",
		Right: parser.V2LiteralExpr{Value: 2},
	}
	if err := validatePriorityRuntimeExpr(when); err != nil {
		t.Fatalf("validate numeric priority expression: %v", err)
	}
	m := model{
		Severity: map[string]int{"default": 1, "high": 3},
		Factors: map[string]priorityFactor{
			"multiBinding": {Weight: 4, When: when},
		},
		FactorOrder: []string{"multiBinding"},
		Bands: []struct {
			Band string
			Min  int
		}{{Band: "P1", Min: 7}, {Band: "P4", Min: 0}},
	}

	twoBindings := mkFinding("high", "high", nil)
	got := prioritizeWithModel(twoBindings, m)
	if got.Total != 7 || !hasFactor(got, "multiBinding") || !strings.Contains(got.Render(), "bindings: 2") {
		t.Fatalf("numeric bindingCount factor did not fire with witness: %+v\n%s", got, got.Render())
	}

	oneBinding := mkFinding("high", "high", nil)
	oneBinding.Bindings = oneBinding.Bindings[:1]
	got = prioritizeWithModel(oneBinding, m)
	if got.Total != 3 || hasFactor(got, "multiBinding") {
		t.Fatalf("numeric bindingCount factor fired unexpectedly: %+v", got)
	}
}

// PrioritizeAll orders most-urgent first.
func TestPrioritizeAllOrdering(t *testing.T) {
	fs := []*findings.Finding{
		mkFinding("low", "high", nil),
		mkFinding("critical", "high", []string{
			"svc is internet-reachable (via sg-pub:443)", "sink database db holds [data.Pii]"}),
		mkFinding("medium", "high", nil),
	}
	scores := PrioritizeAll(fs)
	if scores[0].Band != "P0" {
		t.Fatalf("the critical exposed+PII finding should sort first as P0, got %s (total %d)", scores[0].Band, scores[0].Total)
	}
	for i := 1; i < len(scores); i++ {
		if scores[i-1].Total < scores[i].Total {
			t.Fatalf("scores not sorted most-urgent first: %v", scores)
		}
	}
}

func moreUrgent(a, b string) bool { return bandNum(a) < bandNum(b) }
func hasFactor(s Score, name string) bool {
	for _, f := range s.Factors {
		if f.Name == name {
			return true
		}
	}
	return false
}

func bandNum(b string) int {
	if len(b) == 2 && b[0] == 'P' {
		return int(b[1] - '0')
	}
	return 9
}

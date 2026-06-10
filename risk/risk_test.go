package risk

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/findings"
)

func mkFinding(severity, confidence string, context []string) *findings.Finding {
	return &findings.Finding{
		RuleID: "VYQL-INJ-001", Severity: severity, Confidence: confidence, WitnessKind: "taint",
		Bindings: []findings.Binding{
			{Name: "source", Concept: "code.HttpInput", Loc: "h.py:1"},
			{Name: "sink", Concept: "code.SqlExecution", Loc: "h.py:2"},
		},
		Context: context,
	}
}

// docs/17 v1: an internet-reachable PII finding outranks the same finding
// deployed internally; every factor carries a witness; the combination is
// monotonic.
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
func bandNum(b string) int {
	if len(b) == 2 && b[0] == 'P' {
		return int(b[1] - '0')
	}
	return 9
}

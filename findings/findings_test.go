package findings

// Finding fingerprint stability. The fingerprint
// is content-anchored (rule id + binding name/location) so equivalent findings collapse
// and survive line drift elsewhere — and is deterministic across runs.

import "testing"

func mk(rule string, bindings ...Binding) *Finding {
	return &Finding{RuleID: rule, Bindings: bindings}
}

func TestFingerprintStability(t *testing.T) {
	a := mk("VYQL-INJ-001", Binding{Name: "sink", Loc: "app.py:42"})
	b := mk("VYQL-INJ-001", Binding{Name: "sink", Loc: "app.py:42"})

	// deterministic: same finding → same fingerprint, every time.
	if a.Fingerprint() != a.Fingerprint() {
		t.Fatal("fingerprint is not deterministic across calls")
	}
	// equivalent findings collapse to the same fingerprint.
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("equivalent findings have different fingerprints: %s vs %s", a.Fingerprint(), b.Fingerprint())
	}
	// a 16-hex-char fingerprint.
	if len(a.Fingerprint()) != 16 {
		t.Errorf("fingerprint should be 16 hex chars, got %d (%q)", len(a.Fingerprint()), a.Fingerprint())
	}

	// different rule, different location, or different binding → different fingerprint.
	diff := []*Finding{
		mk("VYQL-INJ-002", Binding{Name: "sink", Loc: "app.py:42"}),   // rule differs
		mk("VYQL-INJ-001", Binding{Name: "sink", Loc: "app.py:43"}),   // location differs
		mk("VYQL-INJ-001", Binding{Name: "source", Loc: "app.py:42"}), // binding name differs
		mk("VYQL-INJ-001"), // no bindings
	}
	for i, d := range diff {
		if d.Fingerprint() == a.Fingerprint() {
			t.Errorf("case %d: distinct finding collapsed to the same fingerprint", i)
		}
	}
}

package engine

import (
	"strings"
	"testing"
)

// Cyclic negation rejected, valid programs ordered.
func TestStratify(t *testing.T) {
	// valid: finding :- taint, NOT suppressed ; suppressed :- sanitizer
	strata, err := Stratify(
		[]string{"finding", "taint", "suppressed", "sanitizer"},
		[]Dep{{"finding", "taint", "pos"}, {"finding", "suppressed", "neg"}, {"suppressed", "sanitizer", "pos"}},
	)
	if err != nil {
		t.Fatalf("valid program wrongly rejected: %v", err)
	}
	order := map[string]int{}
	for i, layer := range strata {
		for _, p := range layer {
			order[p] = i
		}
	}
	if order["suppressed"] > order["finding"] {
		t.Fatalf("suppressed must be stratified before finding: %v", strata)
	}

	// mutual negation -> rejected
	if _, err := Stratify([]string{"p", "q"}, []Dep{{"p", "q", "neg"}, {"q", "p", "neg"}}); err == nil ||
		!strings.Contains(err.Error(), "not stratifiable") {
		t.Fatalf("mutual negation should be rejected, got %v", err)
	}

	// self-negation -> rejected
	if _, err := Stratify([]string{"p"}, []Dep{{"p", "p", "neg"}}); err == nil {
		t.Fatal("self-negation should be rejected")
	}

	// positive recursion -> accepted
	if _, err := Stratify([]string{"reach", "edge"}, []Dep{{"reach", "edge", "pos"}, {"reach", "reach", "pos"}}); err != nil {
		t.Fatalf("positive recursion wrongly rejected: %v", err)
	}
}

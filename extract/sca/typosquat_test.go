package sca

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

func TestFlagTyposquats(t *testing.T) {
	g := usg.NewInMemStore()
	deps := []Dep{
		{"requests", "2.31.0"}, // popular — clean
		{"request", "1.0.0"},   // edit-1 of "requests" (deletion) — squat
		{"flesk", "1.0.0"},     // edit-1 of "flask" (substitution) — squat
		{"colourama", "0.1"},   // known-malicious — flagged
		{"my-internal-lib", "1.0.0"}, // no near match — clean
	}
	if err := BuildSBOM(g, deps, nil); err != nil {
		t.Fatal(err)
	}
	n, err := FlagTyposquats(g, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, id := range hasConcept(t, g, "sbom.SuspiciousDependency") {
		nd, _, _ := g.GetNode(id)
		flagged[nd.Prop("name")] = true
	}
	if n != 3 {
		t.Errorf("expected 3 suspicious deps, got %d (%v)", n, flagged)
	}
	for _, want := range []string{"request", "flesk", "colourama"} {
		if !flagged[want] {
			t.Errorf("expected %q flagged suspicious", want)
		}
	}
	for _, clean := range []string{"requests", "my-internal-lib"} {
		if flagged[clean] {
			t.Errorf("%q should be clean, was flagged", clean)
		}
	}
}

func TestEditDistanceLE1(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"flask", "flask", false}, // identical → distance 0, not ≤1-AND-≥1
		{"flask", "flesk", true},  // one substitution
		{"requests", "request", true}, // one deletion
		{"request", "requests", true}, // one insertion
		{"flask", "flax", false},  // two edits
		{"abc", "xyz", false},     // many
	}
	for _, c := range cases {
		// editDistanceLE1 reports distance EXACTLY in {1} for equal-length (sub) and
		// {1} for off-by-one; identical strings return false (diff==1 required).
		if got := editDistanceLE1(c.a, c.b); got != c.want {
			t.Errorf("editDistanceLE1(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestFlagTyposquatsUnknownEcoOnlyMalicious(t *testing.T) {
	g := usg.NewInMemStore()
	// an unknown ecosystem has no popular list → typosquat detection is off, but the
	// (empty) malicious list also matches nothing, so nothing is flagged.
	_ = BuildSBOM(g, []Dep{{"request", "1.0.0"}}, nil)
	n, err := FlagTyposquats(g, "cargo")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("unknown eco should flag nothing, got %d", n)
	}
}

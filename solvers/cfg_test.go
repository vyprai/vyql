package solvers

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

// Structural dominance on the region/order encoding the lowering emits (B1.3).
func TestDominatesRegion(t *testing.T) {
	cases := []struct {
		name                   string
		gReg, gOrd, sReg, sOrd string
		want                   bool
	}{
		// straight-line: guard before sink in the same region dominates.
		{"straightline-before", "/fn1", "3", "/fn1", "7", true},
		{"straightline-after", "/fn1", "9", "/fn1", "4", false},
		// guard in the enclosing region, sink nested under it → dominates.
		{"enclosing-dominates-nested", "/fn1", "2", "/fn1/if5.t", "6", true},
		// guard inside one branch does NOT dominate code after the branch (sibling region).
		{"branch-guard-not-after", "/fn1/if5.t", "4", "/fn1", "9", false},
		// guard in the THEN branch does NOT dominate a sink in the ELSE branch.
		{"then-not-else", "/fn1/if5.t", "4", "/fn1/if5.e", "6", false},
		// guard before a nested sink in the same branch → dominates.
		{"same-branch-before", "/fn1/if5.t", "4", "/fn1/if5.t/loop8", "9", true},
		// different functions never dominate (disjoint roots).
		{"cross-function", "/fn1", "2", "/fn2", "3", false},
		// segment-boundary safety: "/fn1" must not be treated as an ancestor of "/fn10".
		{"no-prefix-bleed", "/fn1", "2", "/fn10", "9", false},
		// missing CFG metadata (unconverted frontend) → not decidable → false.
		{"no-metadata", "", "1", "", "2", false},
	}
	for _, c := range cases {
		if got := dominatesRegion(c.gReg, c.gOrd, c.sReg, c.sOrd); got != c.want {
			t.Errorf("%s: dominatesRegion(%q@%s, %q@%s) = %v, want %v",
				c.name, c.gReg, c.gOrd, c.sReg, c.sOrd, got, c.want)
		}
	}
}

// Reaches: a can reach b iff order(a)<order(b) and regions are comparable (not siblings).
func TestReachesRegion(t *testing.T) {
	cases := []struct {
		rA, oA, rB, oB string
		want           bool
	}{
		{"/fn1", "2", "/fn1", "5", true},
		{"/fn1", "5", "/fn1", "2", false},
		{"/fn1", "2", "/fn1/if3.t", "6", true},
		{"/fn1/if3.t", "2", "/fn1", "6", true},
		{"/fn1/if3.t", "2", "/fn1/if3.e", "6", false},
		{"/fn1", "2", "/fn2", "6", false},
		{"", "1", "", "2", false},
	}
	for _, c := range cases {
		if got := reachesRegion(c.rA, c.oA, c.rB, c.oB); got != c.want {
			t.Errorf("reachesRegion(%q@%s -> %q@%s) = %v, want %v", c.rA, c.oA, c.rB, c.oB, got, c.want)
		}
	}
}

// An inline callback ("#") runs somewhere after the code that passes it, so an
// order rule can sequence across it — but it must not gain the dominance a "/"
// nesting would confer, or a guard inside a callback would suppress findings in
// the code around it.
func TestInlineCallbackRegionSequencesButDoesNotDominate(t *testing.T) {
	const outer, callback = "/fn1", "/fn1#fn2"

	reaches := []struct {
		rA, oA, rB, oB string
		want           bool
	}{
		{callback, "2", outer, "6", true},                 // check in a callback, use after it
		{outer, "2", callback, "6", true},                 // and the other way round
		{callback, "6", outer, "2", false},                // order still decides direction
		{"/fn1#fn2#fn3", "2", outer, "9", true},           // through two levels of nesting
		{"/fn1#fn2", "2", "/fn1/if3.t", "6", true},        // callback and a branch of its owner
		{"/fn4#fn5", "2", "/fn1#fn2", "6", false},         // callbacks of unrelated functions
		{"/fn1/if3.t#fn4", "2", "/fn1/if3.e", "6", false}, // owners are disjoint branches
	}
	for _, c := range reaches {
		if got := reachesRegion(c.rA, c.oA, c.rB, c.oB); got != c.want {
			t.Errorf("reachesRegion(%q@%s -> %q@%s) = %v, want %v", c.rA, c.oA, c.rB, c.oB, got, c.want)
		}
	}

	if dominatesRegion(outer, "2", callback, "6") {
		t.Error("a function must not dominate the body of a callback it passes")
	}
	if dominatesRegion(callback, "2", outer, "6") {
		t.Error("a callback body must not dominate the function that passes it")
	}
	if postDominatesRegion(outer, "6", callback, "2") {
		t.Error("code after a callback is passed must not post-dominate the callback body")
	}
}

func TestReachesFallsBackToSameFileSourceOrderWithoutRegions(t *testing.T) {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "first", Type: "code.Call", Loc: "app.swift:10", Order: 10, HasOrder: true})
	s.AddNode(usg.Node{ID: "second", Type: "code.Call", Loc: "app.swift:20", Order: 20, HasOrder: true})
	s.AddNode(usg.Node{ID: "other", Type: "code.Call", Loc: "other.swift:30", Order: 30, HasOrder: true})

	if !Reaches(s, "first", "second") {
		t.Fatalf("same-file source-order fallback should reach later node")
	}
	if Reaches(s, "second", "first") {
		t.Fatalf("same-file source-order fallback must preserve ordering")
	}
	if Reaches(s, "first", "other") {
		t.Fatalf("source-order fallback must not cross files without structured regions")
	}
}

// PostDominates: release runs on every path from alloc to exit (leak = its negation).
func TestPostDominatesRegion(t *testing.T) {
	cases := []struct {
		rRel, oRel, rAlloc, oAlloc string
		want                       bool
	}{
		{"/fn1", "5", "/fn1", "2", true},              // release after alloc, same region
		{"/fn1", "5", "/fn1/if3.t", "2", true},        // alloc nested, release after the branch
		{"/fn1/if3.t", "5", "/fn1", "2", false},       // release nested → conditionally skipped → leak
		{"/fn1/if3.e", "5", "/fn1/if3.t", "2", false}, // sibling branch → leak
		{"/fn1", "2", "/fn1", "5", false},             // release before alloc
		{"", "1", "", "2", false},                     // no metadata
	}
	for _, c := range cases {
		if got := postDominatesRegion(c.rRel, c.oRel, c.rAlloc, c.oAlloc); got != c.want {
			t.Errorf("postDominatesRegion(rel %q@%s, alloc %q@%s) = %v, want %v",
				c.rRel, c.oRel, c.rAlloc, c.oAlloc, got, c.want)
		}
	}
}

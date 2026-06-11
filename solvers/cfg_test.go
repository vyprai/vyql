package solvers

import "testing"

// Structural dominance on the region/order encoding the lowering emits (B1.3).
func TestDominatesRegion(t *testing.T) {
	cases := []struct {
		name                       string
		gReg, gOrd, sReg, sOrd     string
		want                       bool
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

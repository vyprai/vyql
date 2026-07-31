package treesitter

import "testing"

func TestHasNestedBacktrackingQuantifier(t *testing.T) {
	cases := []struct {
		want bool
		name string
		pat  string
	}{
		// A repeat nested in a repeat is the trigger, and the report stands unless
		// the body is an alternation that leaves the engine no choice.
		{true, "repeat over a repeat", `(a+)+$`},
		{true, "repeat over a nullable repeat", `(a*)*$`},
		{true, "trailing repeat meets the next iteration", `(a+b*)+$`},
		{true, "single-branch body offers nothing to select between", `(a+b)+$`},
		{true, "single-branch body, repeat away from the seam", `(ab+)+$`},
		{true, "unrolled comment loop without a guard", `\/\*[^*]*\*+([^/*][^*]*\*+)*\/`},

		// Withdrawn: each input character selects exactly one branch.
		{false, "disjoint branches", `^\{((?:,|\{,+\})+)\}`},
		{false, "negative lookahead declines the terminator", `\/\*([^*]|\*(?!\/))*\*\/`},

		// Never triggered: no repeat nested inside the repeat.
		{false, "no repeat in the body", `(abc)+$`},
		{false, "no nesting at all", `^\d+$`},
		{false, "alternation without a nested repeat", `(a|ab)*$`},

		// The pairs the CVE fixtures turn on.
		{true, "rank266 overlapping comma branches", `^\{(,+(?:(\{,+\})*),*|,*(?:(\{,+\})*),+)\}`},
		{false, "rank266 disjoint comma branches", `^\{((?:,|\{,+\})+)\}`},
		{true, "rank435 unbounded comment body", `^(\s|\/\*.*?\*\/)*[\[\(\w]`},
		{false, "rank435 bounded comment body", `^(\s|\/\*([^*]|\*(?!\/))*?\*\/)*[\[\(\w]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasNestedBacktrackingQuantifier(c.pat); got != c.want {
				t.Errorf("hasNestedBacktrackingQuantifier(%q) = %v, want %v", c.pat, got, c.want)
			}
		})
	}
}

package regexambig

import "testing"

func TestAmbiguous(t *testing.T) {
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
		{false, "mandatory literal delimits each iteration", `(a+b)+$`},
		{false, "mandatory literal leads each iteration", `(ab+)+$`},
		{true, "unrolled comment loop without a guard", `\/\*[^*]*\*+([^/*][^*]*\*+)*\/`},

		// Withdrawn: a mandatory literal the repeats cannot match pins each iteration.
		{false, "literal separator, class excludes it", `(/[A-Z0-9_-]+)+$`},
		{false, "dotted labels, class excludes the dot", `[^@.]+(?:\.[^@.]+)*$`},
		{true, "same shape but the separator is optional", `(/?[A-Z0-9_-]+)+$`},
		{true, "same shape but the class admits the dot", `[^@]+(?:\.[^@]+)*$`},

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

		// The run-split's second consumer may sit at the head of an unquantified
		// group's branch, where the class is wider than the run's character.
		{true, "run split through an alternation branch", `&#0*((?:\d+)|(?:x[a-fA-F0-9]+));`},
		{false, "one consumer after the prefix is dropped", `&#((?:\d+)|(?:x[a-fA-F0-9]+));`},
		{true, "run split through a nested group head", `0*((\d+))`},
		{false, "branch heads on another character", `&#0*((?:x\d+)|(?:x[a-f]+));`},
		{false, "branch continues with a single char", `&#0*((?:\d)|(?:x[0-9a-f]+));`},
		{false, "wide first repeat stays ordinary", `\s*((?:\s+)|(?:x\d+));`},
		{false, "universal consumer is not a run split", `0*((?:.*)|(?:y\d+));`},
		{false, "repeated group head is not a run-split consumer", ` +(?<path>(?:[^\"]|\\"|\\.)*?)(?: +\S*)?`},

		// Adjacent repeats: two unbounded repeats over an intersecting alphabet with
		// nothing mandatory between them divide a run of that alphabet, and on
		// failure every division is retried. The hapi/content header literals are
		// the shape — a whitespace run beside a dot run, and a class run that ends
		// one grouping beside an optional dot run that starts the next.
		{true, "whitespace run beside a dot run", `^\s*form-data\s*(?:;\s*(.+))?$`},
		{true, "class run ending a grouping beside an optional dot run", `^([^\/\s]+\/[^\s;]+)(.*)?$`},
		{true, "digit run divided around an optional decimal point", `^(?:[0-9]*\.?[0-9]*)$`},
		{false, "a bare pair the sequence ends on stays linear", `\w+\s*\w+`},
		{true, "cookie pair regex splits a space run between repeats", `^(([^=;]+))\s*=\s*([^\n\r\0]*)`},
		{false, "bounding the space run keeps the parse linear", `^(([^=;]+))\s{0,256}=\s{0,256}([^\n\r\0]*)`},
		{false, "the attribute delimiter idiom stays ordinary", `class\s*=\s*['"]`},
		{false, "the fix makes the dot run exclude the separator", `^\s*form-data\s*(?:;\s*(\S.*))?$`},
		{false, "the fix makes the tail a bounded run", `^([^\/\s]+\/[^\s;]+)([ \t;][^\r\n]*)?$`},
		{false, "the fix makes the decimal suffix one grouping", `(?:[0-9]*(\.[0-9]*)?)`},

		// Withdrawn: a repeat that matches everything is not a run to divide, and
		// alphabets that do not intersect leave each division forced.
		{false, "dot run beside a whitespace run stays ordinary", `.*\s*$`},
		{false, "disjoint alphabets pin each division", `\s*[a-z]+\s*$`},
		{false, "ceilinged repeats divide a run one way", `^(\d{4})(\d{2})(\d{2})$`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Ambiguous(c.pat); got != c.want {
				t.Errorf("Ambiguous(%q) = %v, want %v", c.pat, got, c.want)
			}
		})
	}
}

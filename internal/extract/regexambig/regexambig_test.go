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

		// An atomic group (?>…) walls its interior off from backtracking: once it
		// has matched, the engine can neither re-enter it nor accept a shorter
		// match from it, so a repeat the loop around it could re-split in the
		// plain spelling cannot be re-split at all. The rank2203 pair is the
		// addressable VARNAME constant — a run of name characters the outer loop
		// divides exponentially in the plain spelling and only ever consumes
		// whole once the run is atomic.
		{true, "rank2203 plain nested name run", `^(?:(?:(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+)(?:\.?(?:(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+))*)$`},
		{false, "rank2203 atomic nested name run", `^(?:(?>(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+)(?:\.?(?>(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+))*)$`},
		{false, "atomic group over a repeat", `(?>a+)+$`},
		{false, "atomic group over an alternation of repeats", `(?>a+|b+)+$`},
		{false, "nested repeat behind an atomic group", `(?>(?:a+)+)+$`},

		// The separator that delimits a loop's iterations pins them even when
		// the loop's own atoms carry no repeat: the rank2203 varspec list wraps
		// its digit repeat inside an optional group, and the comma that leads
		// each iteration is still the only place a comma can come from. A
		// nested repeat that CAN match the separator leaves the boundary free.
		{false, "separator delimits iterations, the repeat nested in a group", `^(?:,x(\*|:\d+)?)+$`},
		{true, "nested repeat that matches the separator keeps the report", `^(?:,(\d,+))+$`},

		// A separator pins the boundary BETWEEN iterations and says nothing about
		// a division INSIDE one. The rank2887 semver grammar dots its segments —
		// the `.` is a true separator — yet each segment's identifier branch is
		// `[\da-z-]*[a-z-][\da-z-]*`: a mandatory member flanked by two runs over
		// the same characters, whose position slides because either run can
		// donate the member its character. The free choice is the member's
		// place, and the loop multiplies it across segments. The strand reaches
		// the pair through the nullable material around it: the `\b` at the end
		// of the grammar fails after any division, and nothing mandatory stands
		// between the two to disconnect them.
		{true, "rank2887 semver grammar, identifier member slides", `(?<=^v?|\sv?)(?:(?:0|[1-9]\d*)\.){2}(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|[\da-z-]*[a-z-][\da-z-]*)(?:\.(?:0|[1-9]\d*|[\da-z-]*[a-z-][\da-z-]*))*)?(?:\+[\da-z-]+(?:\.[\da-z-]+)*)?\b`},
		{true, "sliding member between flanking runs", `^[\da-z-]*[a-z-][\da-z-]*!`},
		{false, "a separator outside the runs' alphabet still pins", `^[\da-z-]*,[\da-z-]*!`},
		{false, "atomic flanking run does not slide", `^(?>[\da-z-]*)[a-z-][\da-z-]*!`},
		{false, "possessive member between flanking runs does not slide", `^[\da-z-]*[\da-z-]++[\da-z-]*!`},

		// The member only slides when BOTH flanking runs could donate its
		// character. Material one run can absorb but the other cannot is pinned:
		// exactly one placement of it matches, so the engine walks the input
		// linearly instead of re-splitting the run. The rank1111 fix admits the
		// dot in its domain class but excludes it from the TLD class, and the
		// rank2894 fix makes the value run possessive so it keeps what it took.
		{false, "rank1111 fixed literal, dot outside the tld class", `^([a-zA-Z0-9_.\-+])+@[a-zA-Z0-9-.]+\.[a-zA-Z0-9-]{2,}$`},
		{false, "rank2894 possessive value run pins the pair", `<([^>]*\srel\s*=\s*['"]?([^'" >]++)[^>]*)>`},

		// A negated class admits nearly every character, so the shared-alphabet
		// test cannot distinguish a slid division from a pinned one over it:
		// the slide is not a signal there. This is the canonical safe email
		// shape — wide negated runs, literal separators — whose four
		// RealVuln findings motivated the complement guard.
		{false, "negated runs around literal separators stay pinned (email)", `^[^@\s]+@[^@\s]+\.[^@\s]+$`},
		{false, "negated run pair around one literal separator", `^[^@\s]+\.[^@\s]+$`},

		// The atomic wall is opaque from outside in every reading direction: a
		// repeat buried in an atomic group is not a consumer an enclosing
		// division can compete for, whether the walk arrives from the nesting
		// report, the adjacent pair, or the run split.
		{false, "atomic interior is not a run the outside competes for", `(?>(a+)+)(a+)$`},
		{true, "plain interior is such a run", `(?:(a+)+)(a+)$`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Ambiguous(c.pat); got != c.want {
				t.Errorf("Ambiguous(%q) = %v, want %v", c.pat, got, c.want)
			}
		})
	}
}

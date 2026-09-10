package treesitter

import "testing"

func TestJsRegexAtomsCarryAnyKeyAndGroupBodies(t *testing.T) {
	dot := jsRegexAtoms(".*")
	if len(dot) != 1 || dot[0].key != regexAtomKey(".") || dot[0].quant != '*' {
		t.Fatalf("jsRegexAtoms(%q) = %#v, want one any-character repeat", ".*", dot)
	}
	atoms := jsRegexAtoms(`([^\/\s]+\/[^\s;]+)(.*)?`)
	if len(atoms) != 2 || !atoms[1].group || atoms[1].body != `.*` {
		t.Fatalf("jsRegexAtoms(%q) = %#v, want the optional group to carry its body",
			`([^\/\s]+\/[^\s;]+)(.*)?`, atoms)
	}
}

// The adjacency has to be readable off the runs the atoms start and end with, so a
// repeat one grouping over still counts as a neighbour and the pair behind the
// hapi/content header literals answers true. The fixed literals answer false: the
// fix makes the dot run exclude the separator, and bounds the trailing params run.
func TestHasAmbiguousAdjacentRegexQuantifiers(t *testing.T) {
	cases := []struct {
		name string
		pat  string
		want bool
	}{
		{"whitespace run beside a dot run", `^\s*form-data\s*(?:;\s*(.+))?$`, true},
		{"class run ending a grouping beside an optional dot run", `^([^\/\s]+\/[^\s;]+)(.*)?$`, true},
		{"digit run divided around an optional decimal point", `^(?:[0-9]*\.?[0-9]*){1}$`, true},
		{"a grouping's run beside the whitespace run overlaps", `^(\s+)\s*=`, true},
		{"bounding the space run keeps the parse linear", `^(([^=;]+))\s{0,256}=\s{0,256}([^\n\r\0]*)`, false},
		{"the fixed disposition excludes the separator", `^\s*form-data\s*(?:;\s*(\S.*))?$`, false},
		{"the fixed content-type bounds the params run", `^([^\/\s]+\/[^\s;]+)([ \t;][^\r\n]*)?$`, false},
		{"the fixed numberRx groups the decimal suffix", `^(?:[0-9]*(\.[0-9]*)?){1}$`, false},
		{"a dot run ahead of the repeat stays ordinary", `.*\s*$`, false},
		{"ceilinged repeats divide a run one way", `^(\d{4})(\d{2})(\d{2})$`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasAmbiguousAdjacentRegexQuantifiers(c.pat); got != c.want {
				t.Errorf("hasAmbiguousAdjacentRegexQuantifiers(%q) = %v, want %v", c.pat, got, c.want)
			}
		})
	}
}

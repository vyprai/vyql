package frontend

import "testing"

func TestOutputAlphabet(t *testing.T) {
	cases := []struct {
		name, pattern, repl string
		global              bool
		wantBounded         bool
		excludesSlash       bool
		excludesMarkupChars bool
	}{
		{"allowlist path segment chars", "/[^a-zA-Z0-9_.-]/g", "_", false, true, true, true},
		{"allowlist alnum only", "/[^a-z0-9]/g", "", false, true, true, true},
		{"allowlist keeps slash", `/[^a-z0-9/]/g`, "_", false, true, false, true},
		{"raw pattern, declared global (re.sub)", "[^a-zA-Z0-9]", "_", true, true, true, true},
		{"raw pattern, NOT global -> unbounded", "[^a-zA-Z0-9]", "_", false, false, false, false},
		{"single-char blocklist (positive class)", "/</g", "&lt;", false, false, false, false},
		{"non-global JS replace (first only)", "/[^a-z]/", "_", false, false, false, false},
		{"alternation, not a class", "/foo|bar/g", "", false, false, false, false},
		{"word-class escape", `/[^\w.-]/g`, "_", false, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alpha, bounded := outputAlphabet(c.pattern, c.repl, c.global)
			if bounded != c.wantBounded {
				t.Fatalf("bounded=%v want %v (alpha=%q)", bounded, c.wantBounded, alpha)
			}
			if !bounded {
				return
			}
			if got := alphabetExcludes(alpha, `/\`); got != c.excludesSlash {
				t.Errorf("excludesSlash=%v want %v (alpha=%q)", got, c.excludesSlash, alpha)
			}
			if got := alphabetExcludes(alpha, `<>&"'`); got != c.excludesMarkupChars {
				t.Errorf("excludesMarkupChars=%v want %v (alpha=%q)", got, c.excludesMarkupChars, alpha)
			}
		})
	}
}

package frontend

import "testing"

func TestOutputAlphabet(t *testing.T) {
	cases := []struct {
		name, pattern, repl string
		global              bool
		wantBounded         bool
		excludesPath        bool // alphabet excludes / and \  (path-traversal safe)
		excludesHTML        bool // alphabet excludes < > & " '
	}{
		{"owasp safePathSegment", "/[^a-zA-Z0-9_.-]/g", "_", false, true, true, true},
		{"allowlist alnum only", "/[^a-z0-9]/g", "", false, true, true, true},
		{"allowlist keeps slash (unsafe for path)", `/[^a-z0-9/]/g`, "_", false, true, false, true},
		{"raw pattern, declared global (re.sub)", "[^a-zA-Z0-9]", "_", true, true, true, true},
		{"raw pattern, NOT global -> unbounded", "[^a-zA-Z0-9]", "_", false, false, false, false},
		{"escapeHtml blocklist (positive class)", "/</g", "&lt;", false, false, false, false},
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
			if got := alphabetExcludes(alpha, `/\`); got != c.excludesPath {
				t.Errorf("excludesPath=%v want %v (alpha=%q)", got, c.excludesPath, alpha)
			}
			if got := alphabetExcludes(alpha, `<>&"'`); got != c.excludesHTML {
				t.Errorf("excludesHTML=%v want %v (alpha=%q)", got, c.excludesHTML, alpha)
			}
		})
	}
}

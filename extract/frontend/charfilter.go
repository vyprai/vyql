package frontend

import "strings"

// charfilter.go — GENERAL output-alphabet analysis for character-filtering replaces.
// The engine reasons about a `replace(pattern, repl)`; which methods ARE filters and
// which characters are dangerous per threat live in vyql data (the `filter` adapter
// directive and the `dangerous_chars` concept attribute). This file is the language-
// agnostic math: given a pattern + replacement, what can the OUTPUT contain, and is
// that set provably bounded?
//
// Only the SOUND case is bounded: a GLOBAL replace whose entire pattern is a single
// negated character class `[^…]`. Then output ⊆ (kept class chars) ∪ (replacement
// chars) — an allowlist. Everything else (positive class, alternation, capture groups,
// non-global) is unbounded: vyql cannot prove it neutralizes, so it never suppresses.

// outputAlphabet returns the set of characters the output of replace(pattern, repl) can
// contain (as a string of distinct runes) and whether that set is provably bounded.
func outputAlphabet(pattern, repl string, forceGlobal bool) (alphabet string, bounded bool) {
	pattern = normalizeLit(pattern)
	inner, flags, hadDelim := stripRegexDelims(pattern)
	// Global? An always-global filter (gsub / replaceAll / re.sub / preg_replace —
	// declared `global` in the adapter) replaces every match. Otherwise, only a delimited
	// literal carrying the `g` flag (JS .replace(/…/g)) is global; without it just the
	// first match is replaced and the tail of the string is unbounded.
	if !forceGlobal && hadDelim && !strings.Contains(flags, "g") {
		return "", false
	}
	if !forceGlobal && !hadDelim {
		// a raw pattern with no delimiters and no global guarantee — can't prove global.
		return "", false
	}
	cls, ok := wholeNegatedClass(inner)
	if !ok {
		return "", false
	}
	set := expandClass(cls)
	for _, r := range repl {
		set[r] = true
	}
	var b strings.Builder
	for r := range set {
		b.WriteRune(r)
	}
	return b.String(), true
}

// alphabetExcludes reports whether every rune of `dangerous` is absent from `alphabet`
// — i.e. a bounded output over `alphabet` can never contain a dangerous character.
func alphabetExcludes(alphabet, dangerous string) bool {
	for _, d := range dangerous {
		if strings.ContainsRune(alphabet, d) {
			return false
		}
	}
	return true
}

// normalizeLit strips a string-literal prefix (Python r''/b''/u''/f'') and surrounding
// quotes from a pattern token, so a pattern captured as a string (re.sub) reads the same
// as a regex literal. A `/…/` regex literal (no prefix, not quoted) passes through.
func normalizeLit(p string) string {
	i := 0
	for i < len(p) && ((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z')) {
		i++
	}
	if i > 0 && i < len(p) && (p[i] == '\'' || p[i] == '"' || p[i] == '`') {
		p = p[i:]
	}
	if len(p) >= 2 {
		if q := p[0]; (q == '\'' || q == '"' || q == '`') && p[len(p)-1] == q {
			p = p[1 : len(p)-1]
		}
	}
	return p
}

// stripRegexDelims peels a `/INNER/FLAGS` regex literal into (INNER, FLAGS, true). A
// pattern that is not delimited (a raw pattern string, e.g. Python's r'[^x]') returns
// (pattern, "", false).
func stripRegexDelims(p string) (inner, flags string, had bool) {
	if len(p) < 2 || p[0] != '/' {
		return p, "", false
	}
	last := strings.LastIndexByte(p, '/')
	if last == 0 {
		return p, "", false
	}
	return p[1:last], p[last+1:], true
}

// wholeNegatedClass returns the class body of a pattern that is exactly one negated
// character class `[^BODY]`, optionally followed by a `*`/`+`/`?` quantifier.
func wholeNegatedClass(p string) (string, bool) {
	p = strings.TrimRight(p, "+*?")
	if len(p) < 4 || !strings.HasPrefix(p, "[^") || p[len(p)-1] != ']' {
		return "", false
	}
	body := p[2 : len(p)-1]
	// a nested unescaped ']' would mean this isn't a single trailing-]-terminated class
	if strings.Contains(body, "[") {
		return "", false
	}
	return body, true
}

// expandClass expands a character-class body into the concrete set of runes it matches,
// handling ranges (a-z), the common escapes (\w \d \s), and escaped/literal chars.
func expandClass(body string) map[rune]bool {
	set := map[rune]bool{}
	rs := []rune(body)
	addRange := func(lo, hi rune) {
		for c := lo; c <= hi; c++ {
			set[c] = true
		}
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' && i+1 < len(rs) {
			switch n := rs[i+1]; n {
			case 'w':
				addRange('a', 'z')
				addRange('A', 'Z')
				addRange('0', '9')
				set['_'] = true
			case 'd':
				addRange('0', '9')
			case 's':
				for _, w := range " \t\n\r\f\v" {
					set[w] = true
				}
			default:
				set[n] = true // escaped literal (\. \- \\ …)
			}
			i++
			continue
		}
		if i+2 < len(rs) && rs[i+1] == '-' && rs[i+2] != ']' { // a-z range
			addRange(c, rs[i+2])
			i += 2
			continue
		}
		set[c] = true
	}
	return set
}

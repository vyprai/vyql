package frontend

import "strings"

// charfilter.go — GENERAL character-effect analysis for character-filtering replaces.
// The engine reasons about a `replace(pattern, repl)`; which methods ARE filters
// and which character sets matter live in VyQL data. This file is the language-
// agnostic math: given a pattern + replacement, what can be proven about the output?
//
// One SOUND case is bounded: a GLOBAL replace whose entire pattern is a single
// negated character class `[^…]`. Then output ⊆ (kept class chars) ∪ (replacement
// chars) — an allowlist. Another SOUND case is a GLOBAL replace whose entire pattern
// is a single positive character class `[…]`; then the characters matched by that
// class, minus any characters reintroduced by the replacement, are absent afterward.
// Everything else (alternation, capture groups, non-global) is unproven: vyql cannot
// prove it neutralizes, so it never suppresses.

// outputAlphabet returns the set of characters the output of replace(pattern, repl) can
// contain (as a string of distinct runes) and whether that set is provably bounded.
func outputAlphabet(pattern, repl string, forceGlobal bool) (alphabet string, bounded bool) {
	alphabet, bounded, _ = replaceCharEffects(pattern, repl, forceGlobal)
	return alphabet, bounded
}

func replaceCharEffects(pattern, repl string, forceGlobal bool) (alphabet string, bounded bool, removed string) {
	pattern = normalizeLit(pattern)
	inner, flags, hadDelim := stripRegexDelims(pattern)
	// Global? An always-global filter (gsub / replaceAll / re.sub / preg_replace —
	// declared `global` in the adapter) replaces every match. Otherwise, only a delimited
	// literal carrying the `g` flag (JS .replace(/…/g)) is global; without it just the
	// first match is replaced and the tail of the string is unbounded.
	if !forceGlobal && hadDelim && !strings.Contains(flags, "g") {
		return "", false, ""
	}
	if !forceGlobal && !hadDelim {
		// a raw pattern with no delimiters and no global guarantee — can't prove global.
		return "", false, ""
	}
	if cls, ok := wholeNegatedClass(inner); ok {
		set := expandClass(cls)
		for r := range replacementRunes(repl) {
			set[r] = true
		}
		return runeSetString(set), true, ""
	}
	if cls, ok := wholePositiveClass(inner); ok {
		set := expandClass(cls)
		for r := range replacementRunes(repl) {
			delete(set, r)
		}
		return "", false, runeSetString(set)
	}
	return "", false, ""
}

// alphabetExcludes reports whether every rune of excluded is absent from alphabet.
func alphabetExcludes(alphabet, excluded string) bool {
	for _, r := range excluded {
		if strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

// normalizeLit strips a string-literal prefix (Python r”/b”/u”/f”) and surrounding
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

// wholePositiveClass returns the class body of a pattern that is exactly one positive
// character class `[BODY]`, optionally followed by a `*`/`+`/`?` quantifier.
func wholePositiveClass(p string) (string, bool) {
	p = strings.TrimRight(p, "+*?")
	if len(p) < 3 || !strings.HasPrefix(p, "[") || strings.HasPrefix(p, "[^") || p[len(p)-1] != ']' {
		return "", false
	}
	body := p[1 : len(p)-1]
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
			case 'n':
				set['\n'] = true
			case 'r':
				set['\r'] = true
			case 't':
				set['\t'] = true
			case 'f':
				set['\f'] = true
			case 'v':
				set['\v'] = true
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

func replacementRunes(repl string) map[rune]bool {
	return expandReplacement(normalizeLit(repl))
}

func expandReplacement(s string) map[rune]bool {
	set := map[rune]bool{}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\\' && i+1 < len(rs) {
			switch n := rs[i+1]; n {
			case 'n':
				set['\n'] = true
			case 'r':
				set['\r'] = true
			case 't':
				set['\t'] = true
			case 'f':
				set['\f'] = true
			case 'v':
				set['\v'] = true
			default:
				set[n] = true
			}
			i++
			continue
		}
		set[rs[i]] = true
	}
	return set
}

func runeSetString(set map[rune]bool) string {
	var b strings.Builder
	for r := range set {
		b.WriteRune(r)
	}
	return b.String()
}

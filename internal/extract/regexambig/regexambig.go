// Package regexambig decides whether a regular expression can backtrack
// catastrophically. It is a leaf package so every frontend and the lowering can
// share one answer instead of each approximating it.
package regexambig

import "strings"

const regexAnalysisMaxDepth = 12

// regexCharSet is the set of bytes an atom can match, as a 256-bit set.
type regexCharSet [4]uint64

func (s *regexCharSet) add(b byte) { s[b>>6] |= 1 << (b & 63) }

func (s *regexCharSet) addRange(lo, hi byte) {
	for c := int(lo); c <= int(hi); c++ {
		s.add(byte(c))
	}
}

func (s *regexCharSet) union(o regexCharSet) {
	for i := range s {
		s[i] |= o[i]
	}
}

func (s regexCharSet) complement() regexCharSet {
	var out regexCharSet
	for i := range out {
		out[i] = ^s[i]
	}
	return out
}

func (s regexCharSet) intersects(o regexCharSet) bool {
	for i := range s {
		if s[i]&o[i] != 0 {
			return true
		}
	}
	return false
}

func (s regexCharSet) empty() bool {
	for i := range s {
		if s[i] != 0 {
			return false
		}
	}
	return true
}

func (s regexCharSet) subsetOf(o regexCharSet) bool {
	for i := range s {
		if s[i]&^o[i] != 0 {
			return false
		}
	}
	return true
}

func regexAnySet() regexCharSet {
	var out regexCharSet
	for i := range out {
		out[i] = ^uint64(0)
	}
	return out
}

func regexSingleSet(b byte) regexCharSet {
	var out regexCharSet
	out.add(b)
	return out
}

func regexEscapeSet(c byte) regexCharSet {
	var out regexCharSet
	switch c {
	case 'd':
		out.addRange('0', '9')
	case 'D':
		return regexEscapeSet('d').complement()
	case 'w':
		out.addRange('a', 'z')
		out.addRange('A', 'Z')
		out.addRange('0', '9')
		out.add('_')
	case 'W':
		return regexEscapeSet('w').complement()
	case 's':
		for _, b := range []byte{' ', '\t', '\n', '\r', '\f', '\v'} {
			out.add(b)
		}
	case 'S':
		return regexEscapeSet('s').complement()
	case 'b', 'B', 'A', 'z', 'Z', 'G', 'p', 'P', 'k', 'u', 'x', 'c':
		// zero-width anchors and constructs carrying their own operand; the set
		// is not determined here, so claim everything and keep the report.
		return regexAnySet()
	default:
		out.add(regexEscapeLiteral(c))
	}
	return out
}

func regexEscapeLiteral(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'f':
		return '\f'
	case 'v':
		return '\v'
	case '0':
		return 0
	}
	return c
}

func isRegexClassEscape(c byte) bool {
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		return true
	}
	return false
}

// regexClassSet reads the inside of a [...] class.
func regexClassSet(body string) regexCharSet {
	neg := strings.HasPrefix(body, "^")
	if neg {
		body = body[1:]
	}
	var out regexCharSet
	for i := 0; i < len(body); {
		var lo byte
		switch {
		case body[i] == '\\' && i+1 < len(body):
			if isRegexClassEscape(body[i+1]) {
				out.union(regexEscapeSet(body[i+1]))
				i += 2
				continue
			}
			lo = regexEscapeLiteral(body[i+1])
			i += 2
		default:
			lo = body[i]
			i++
		}
		if i+1 < len(body) && body[i] == '-' {
			hi := body[i+1]
			if hi == '\\' && i+2 < len(body) {
				hi = regexEscapeLiteral(body[i+2])
				i += 3
			} else {
				i += 2
			}
			if lo <= hi {
				out.addRange(lo, hi)
			} else {
				out.add(lo)
				out.add(hi)
			}
			continue
		}
		out.add(lo)
	}
	if neg {
		return out.complement()
	}
	return out
}

// regexAtom is one element of a regex sequence: what it can match, how often, and
// — for a group — the source of its body so the analysis can descend.
type regexAtom struct {
	set      regexCharSet
	quant    byte // 0, '?', '*' or '+'
	group    bool
	body     string
	look     byte // 0, '=' for a positive lookaround, '!' for a negative one
	nullable bool
}

// regexGroupInner strips a group's leading construct marker and reports whether
// the group is a lookaround, which matches without consuming input.
func regexGroupInner(inner string) (string, byte) {
	switch {
	case strings.HasPrefix(inner, "?:"):
		return inner[2:], 0
	case strings.HasPrefix(inner, "?="):
		return inner[2:], '='
	case strings.HasPrefix(inner, "?!"):
		return inner[2:], '!'
	case strings.HasPrefix(inner, "?<="):
		return inner[3:], '='
	case strings.HasPrefix(inner, "?<!"):
		return inner[3:], '!'
	case strings.HasPrefix(inner, "?P<"): // Python named group
		if close := strings.IndexByte(inner, '>'); close >= 0 {
			return inner[close+1:], 0
		}
	case strings.HasPrefix(inner, "?P="): // Python named backreference
		return "", 0
	case strings.HasPrefix(inner, "?<"):
		if close := strings.IndexByte(inner, '>'); close >= 0 {
			return inner[close+1:], 0
		}
	}
	return inner, 0
}

// regexAtomsOf splits one alternation branch into its atoms, left to right.
func regexAtomsOf(seq string, depth int) []regexAtom {
	if depth > regexAnalysisMaxDepth {
		return nil
	}
	var out []regexAtom
	for i := 0; i < len(seq); {
		var a regexAtom
		switch {
		case seq[i] == '\\' && i+1 < len(seq):
			a.set = regexEscapeSet(seq[i+1])
			i += 2
		case seq[i] == '[':
			end := regexCharClassEnd(seq, i)
			if end <= i {
				i++
				continue
			}
			a.set = regexClassSet(seq[i+1 : end])
			i = end + 1
		case seq[i] == '(':
			end := regexGroupEnd(seq, i)
			if end <= i {
				i++
				continue
			}
			a.group = true
			a.body, a.look = regexGroupInner(seq[i+1 : end])
			i = end + 1
		case seq[i] == '.':
			a.set = regexAnySet()
			i++
		case strings.IndexByte("^$|*+?{})]", seq[i]) >= 0:
			i++
			continue
		default:
			a.set = regexSingleSet(seq[i])
			i++
		}
		quant, next := jsRegexQuantifier(seq, i)
		if quant != 0 && next < len(seq) {
			switch seq[next] {
			case '?': // lazy: still backtracks, just from the other end
				next++
			case '+': // possessive: cannot give back what it matched
				quant, next = 0, next+1
			}
		}
		a.quant, i = quant, next
		a.nullable = quant == '*' || quant == '?'
		if a.group {
			var bodyNullable bool
			a.set, bodyNullable = regexFirstSetOf(a.body, depth+1)
			a.nullable = a.nullable || bodyNullable || a.look != 0
		}
		out = append(out, a)
	}
	return out
}

// regexFirstSetOf returns the characters an alternation can begin with, and
// whether it can match nothing at all.
func regexFirstSetOf(alt string, depth int) (regexCharSet, bool) {
	if depth > regexAnalysisMaxDepth {
		return regexAnySet(), true
	}
	var out regexCharSet
	nullable := false
	for _, branch := range splitTopLevelRegexBranches(alt) {
		set, n := regexFirstSetOfAtoms(regexAtomsOf(branch, depth+1))
		out.union(set)
		nullable = nullable || n
	}
	return out, nullable
}

func regexFirstSetOfAtoms(atoms []regexAtom) (regexCharSet, bool) {
	var out regexCharSet
	for _, a := range atoms {
		if a.look != 0 {
			continue
		}
		out.union(a.set)
		if !a.nullable {
			return out, false
		}
	}
	return out, true
}

// Ambiguous reports a quantifier nested inside a repeat,
// unless the repeat's body is demonstrably unambiguous. The report stands on the
// nesting alone, as it always has; the analysis below only withdraws it, so a
// pattern whose shape cannot be reasoned about keeps its finding.
func Ambiguous(pat string) bool {
	return regexAltHasAmbiguousRepeat(pat, 0)
}

func regexAltHasAmbiguousRepeat(alt string, depth int) bool {
	if depth > regexAnalysisMaxDepth {
		return false
	}
	for _, branch := range splitTopLevelRegexBranches(alt) {
		atoms := regexAtomsOf(branch, depth+1)
		if regexSplitsOneCharRun(atoms) {
			return true
		}
		for _, a := range atoms {
			if !a.group {
				continue
			}
			if isBacktrackingRepeat(a.quant) && regexBodyHasRepeat(a.body) &&
				!regexLoopBodyDisambiguated(a.body, depth+1) {
				return true
			}
			if regexAltHasAmbiguousRepeat(a.body, depth+1) {
				return true
			}
		}
	}
	return false
}

// regexBodyHasRepeat is the original trigger: a `*` or `+` anywhere inside the
// repeated group, so the group iterates over something that already repeats.
func regexBodyHasRepeat(body string) bool {
	for i := 0; i < len(body); i++ {
		if isRegexQuantifier(body[i]) && !isEscaped(body, i) && !isPossessiveQuantifier(body, i) {
			return true
		}
	}
	return false
}

// regexLoopBodyDisambiguated reports a repeat whose body leaves the engine no
// choice: an alternation of branches that begin with different characters, none
// of which can match nothing, and none of which is ambiguous on its own. Each
// input character then selects exactly one branch, so there is no split to retry.
// A single-branch body is never disambiguated this way — there is nothing to
// select between, and the nesting report stands.
func regexLoopBodyDisambiguated(body string, depth int) bool {
	if depth > regexAnalysisMaxDepth {
		return false
	}
	branches := splitTopLevelRegexBranches(body)
	if len(branches) < 2 {
		// A single-branch body still leaves no choice when it carries a mandatory
		// literal separator the repeats cannot produce: `(/[A-Z0-9_-]+)+` must start
		// every iteration at a `/`, and the class excludes it, so the boundaries are
		// forced. Without such a separator — `([^/*][^*]*\*+)*` — nothing pins them
		// and the nesting report stands.
		return regexBodyHasLiteralSeparator(body, depth)
	}
	sets := make([]regexCharSet, len(branches))
	var loopFirst regexCharSet
	for i, branch := range branches {
		set, nullable := regexFirstSetOf(branch, depth+1)
		if nullable {
			return false
		}
		sets[i] = set
		loopFirst.union(set)
	}
	for i := range sets {
		for j := i + 1; j < len(sets); j++ {
			if sets[i].intersects(sets[j]) {
				return false
			}
		}
	}
	for _, branch := range branches {
		if regexBranchAmbiguous(regexAtomsOf(branch, depth+1), loopFirst, depth) {
			return false
		}
	}
	return true
}

// regexBranchAmbiguous looks for a repeat inside one branch that competes with
// what follows it. A repeat at the end of the branch competes with the next
// iteration instead, which is what makes `(a+)+` explode while `(a+b)+` stays
// linear.
func regexBranchAmbiguous(atoms []regexAtom, loopFirst regexCharSet, depth int) bool {
	for i, a := range atoms {
		if a.look != 0 {
			continue
		}
		if a.group && isBacktrackingRepeat(a.quant) && regexBodyHasRepeat(a.body) &&
			!regexLoopBodyDisambiguated(a.body, depth+1) {
			return true
		}
		if !isBacktrackingRepeat(a.quant) {
			continue
		}
		cont, nullable := regexFirstSetOfAtoms(atoms[i+1:])
		if nullable {
			cont.union(loopFirst)
		}
		if cont.empty() {
			continue
		}
		if regexRepeatOverlapsContinuation(a, atoms[i+1:], cont, depth) {
			return true
		}
	}
	return false
}

func regexRepeatOverlapsContinuation(a regexAtom, rest []regexAtom, cont regexCharSet, depth int) bool {
	if !a.group {
		return a.set.intersects(cont)
	}
	for _, branch := range splitTopLevelRegexBranches(a.body) {
		atoms := regexAtomsOf(branch, depth+1)
		head, _ := regexFirstSetOfAtoms(atoms)
		if !head.intersects(cont) || regexBranchGuardExcludes(atoms, rest, depth) {
			continue
		}
		return true
	}
	return false
}

// regexBranchGuardExcludes recognises a branch closed by a negative lookahead
// that the continuation satisfies, so the two cannot both match at one position.
// This is the unrolled-loop idiom that makes a C-comment regex linear:
// `\/\*([^*]|\*(?!\/))*\*\/` — the `\*(?!\/)` branch declines the `*` that starts
// the trailing `\*\/`.
func regexBranchGuardExcludes(branch, rest []regexAtom, depth int) bool {
	if len(branch) < 2 || branch[0].look != 0 || branch[1].look != '!' || len(rest) < 2 {
		return false
	}
	guard, _ := regexFirstSetOf(branch[1].body, depth+1)
	next, _ := regexFirstSetOfAtoms(rest[1:])
	return !next.empty() && next.subsetOf(guard)
}

func isEscaped(s string, i int) bool {
	esc := false
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		esc = !esc
	}
	return esc
}

func isRegexQuantifier(b byte) bool {
	return b == '+' || b == '*'
}

func isPossessiveQuantifier(s string, i int) bool {
	return i+1 < len(s) && s[i+1] == '+'
}

func splitTopLevelRegexBranches(pat string) []string {
	var out []string
	start := 0
	depth := 0
	inClass := false
	for i := 0; i < len(pat); i++ {
		if isEscaped(pat, i) {
			continue
		}
		switch pat[i] {
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		case '|':
			if !inClass && depth == 0 {
				out = append(out, pat[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, pat[start:])
	return out
}

func regexCharClassEnd(pat string, start int) int {
	for i := start + 1; i < len(pat); i++ {
		if pat[i] == ']' && !isEscaped(pat, i) {
			return i
		}
	}
	return -1
}

func regexGroupEnd(pat string, start int) int {
	depth := 0
	inClass := false
	for i := start; i < len(pat); i++ {
		if isEscaped(pat, i) {
			continue
		}
		switch pat[i] {
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func jsRegexQuantifier(pat string, start int) (byte, int) {
	if start >= len(pat) {
		return 0, start
	}
	switch pat[start] {
	case '*', '+', '?':
		return pat[start], start + 1
	case '{':
		end := strings.IndexByte(pat[start:], '}')
		if end < 0 {
			return 0, start
		}
		body := strings.ReplaceAll(strings.TrimSpace(pat[start+1:start+end]), " ", "")
		next := start + end + 1
		switch body {
		case "1":
			return 0, next
		case "0,1":
			return '?', next
		default:
			return '*', next
		}
	default:
		return 0, start
	}
}

func isBacktrackingRepeat(q byte) bool {
	return q == '*' || q == '+'
}

// regexBodyHasLiteralSeparator reports a mandatory single-character literal in the
// body that none of its repeated atoms can match. Such a character can only come
// from that position, so each iteration is delimited and the repeat is unambiguous.
func regexBodyHasLiteralSeparator(body string, depth int) bool {
	atoms := regexAtomsOf(body, depth+1)
	var repeats regexCharSet
	for _, a := range atoms {
		if a.look == 0 && isBacktrackingRepeat(a.quant) {
			repeats.union(a.set)
		}
	}
	if repeats.empty() {
		return false
	}
	for _, a := range atoms {
		if a.look != 0 || a.group || a.quant != 0 || a.nullable {
			continue // must be mandatory and a plain atom
		}
		if regexSetSize(a.set) == 1 && !a.set.intersects(repeats) {
			return true
		}
	}
	return false
}

// regexSetSize counts the members of a character set.
func regexSetSize(s regexCharSet) int {
	n := 0
	for _, w := range s {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}

// regexSplitsOneCharRun reports two repeats over the SAME single character separated
// only by material that can match nothing. A run of that character can then be split
// between them at any point, and every split is retried on failure — the shape behind
// `,+(?:…)*,*`. Restricted to single-character sets: two repeats over a wide class
// (`\s*…\s*`) are ordinary, and flagging those reports most real-world regexes.
func regexSplitsOneCharRun(atoms []regexAtom) bool {
	for i, a := range atoms {
		if a.look != 0 || !isBacktrackingRepeat(a.quant) || regexSetSize(a.set) != 1 {
			continue
		}
		for j := i + 1; j < len(atoms); j++ {
			b := atoms[j]
			if b.look != 0 {
				continue
			}
			if isBacktrackingRepeat(b.quant) && regexSetSize(b.set) == 1 && b.set.intersects(a.set) {
				return true
			}
			if !b.nullable {
				break // something mandatory separates them
			}
		}
	}
	return false
}

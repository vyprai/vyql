package lowering

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

var pythonIterationConstants = map[string]string{
	"string.lowercase":       "abcdefghijklmnopqrstuvwxyz",
	"string.ascii_lowercase": "abcdefghijklmnopqrstuvwxyz",
	"string.uppercase":       "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"string.ascii_uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"string.digits":          "0123456789",
}

func (l *lowerer) staticIterationString(expr nir.Expr, sc *scope) (string, bool) {
	switch value := expr.(type) {
	case nir.Const:
		return l.constStrVal(value, sc)
	case nir.Attr:
		text, ok := pythonIterationConstants[value.Path]
		return text, ok
	case nir.Thru:
		return l.staticIterationString(value.Inner, sc)
	case nir.Pair:
		return l.staticIterationString(value.Value, sc)
	case nir.Format:
		var b strings.Builder
		for _, part := range value.Parts {
			text, ok := l.staticIterationString(part, sc)
			if !ok {
				return "", false
			}
			b.WriteString(text)
		}
		return b.String(), true
	}
	return "", false
}

func (l *lowerer) constIterationValues(expr nir.Expr, sc *scope) ([]string, bool) {
	switch value := expr.(type) {
	case nir.Name:
		values, ok := sc.iter[value.ID]
		return append([]string(nil), values...), ok
	case nir.Seq:
		out := make([]string, 0, len(value.Parts))
		for _, part := range value.Parts {
			text, ok := l.staticIterationString(part, sc)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		text, ok := l.staticIterationString(expr, sc)
		if !ok {
			return nil, false
		}
		out := make([]string, 0, len([]rune(text)))
		for _, r := range text {
			out = append(out, string(r))
		}
		return out, true
	}
}

// cloneIterationFacts copies an iteration-facts map for a branch.
//
// It copies the map's key/slice-header pairs and NOT the backing arrays, because the
// values are immutable once stored: every write assigns a freshly built slice and nothing
// appends into one in place. Copying the arrays too duplicated the bulk of the data on
// every branch, and the lowerer clones these maps up to five times per `if` and once per
// switch case — quadratic in the number of branches in a function, which is how a single
// large generated file could exhaust memory.
func cloneIterationFacts(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	maps.Copy(out, in)
	return out
}

func stableIterationFacts(states ...map[string][]string) map[string][]string {
	out := map[string][]string{}
	if len(states) == 0 {
		return out
	}
	for name, values := range states[0] {
		stable := true
		for _, state := range states[1:] {
			if !slices.Equal(values, state[name]) {
				stable = false
				break
			}
		}
		if stable {
			out[name] = values // immutable once stored; see cloneIterationFacts
		}
	}
	return out
}

func rejectedClass(values []string) string {
	set := map[rune]bool{}
	for _, value := range values {
		rs := []rune(value)
		if len(rs) == 1 {
			set[rs[0]] = true
		}
	}
	chars := make([]rune, 0, len(set))
	for r := range set {
		chars = append(chars, r)
	}
	sort.Slice(chars, func(i, j int) bool { return chars[i] < chars[j] })
	var b strings.Builder
	b.WriteByte('[')
	for _, r := range chars {
		if r == '[' {
			continue
		}
		if strings.ContainsRune(`\-]^`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte(']')
	return b.String()
}

func (l *lowerer) characterRejectionCall(id, loc, pattern string) string {
	arg := l.node("Arg", loc, map[string]string{"vkind": "Analysis"})
	l.flow(id, arg)
	call := l.node("Call", loc, map[string]string{
		"callee_path": "analysis.validation.character_rejection",
		"method":      "character_rejection",
		"arg0":        arg,
		"lit0":        pattern,
		"lit1":        "",
	})
	l.flow(arg, call)
	return call
}

func (l *lowerer) applyValidation(st nir.Validation, sc *scope) {
	if st.Kind != "character_rejection" || sc.node[st.Target] == "" {
		return
	}
	values, ok := l.constIterationValues(st.Evidence, sc)
	if !ok {
		return
	}
	pattern := rejectedClass(values)
	if pattern == "[]" {
		return
	}
	reachable, err := usg.BFS(l.g, sc.node[st.Target], "FLOWS", 128)
	if err != nil {
		return
	}
	for name, node := range sc.node {
		if node != "" && reachable[node] {
			sc.node[name] = l.characterRejectionCall(node, st.Loc, pattern)
		}
	}
}

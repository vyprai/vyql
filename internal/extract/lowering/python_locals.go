package lowering

// Python's locals() returns a snapshot of the calling scope itself: a dict whose entries are
// the function's own bindings at the call. The lowerer models it as two facts about one call
// result — the scope's bindings flow INTO the result, and the result's slots ARE those
// bindings — so a value that reaches a sink only by being read back out of the snapshot keeps
// the taint it already had, while a reader that names a slot reads that slot alone. Nothing
// here makes a local a source: a clean scope still builds a clean snapshot.
//
// The scope a nested function lowers against already holds the bindings it captures, so its
// snapshot carries them too — the same over-approximation the closure capture itself makes.

import (
	"regexp"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// pyFormatMappingKeyRE matches the mapping form of a %-format conversion, `%(key)s` — key
// between parentheses, flags/width/conversion after it. Positional `%s` names no key.
var pyFormatMappingKeyRE = regexp.MustCompile(`%\(([^()]+)\)`)

// pySnapshotSlot is the binding locals() snapshots for a name in scope, or "" when the name is
// the lowerer's own bookkeeping rather than a binding: the function's return node is parked in
// the scope under "__ret__", and no snapshot holds it.
func pySnapshotSlot(sc *scope, name string) string {
	if name == "__ret__" {
		return ""
	}
	return sc.node[name]
}

// isLocalsSnapshot reports whether a call is Python's no-argument locals() builtin. A `locals`
// the program declares itself resolves to that function and keeps its own dataflow.
func (l *lowerer) isLocalsSnapshot(call nir.Call, sc *scope) bool {
	if moduleTech(l.curFile) != "python" || call.Path != "locals" || len(call.Args) != 0 {
		return false
	}
	targets, _ := l.resolveTargets(call.Callee, sc)
	return len(targets) == 0
}

// lowerLocalsSnapshot records what a locals() call evaluates to. Every binding in scope flows
// into the result — the whole-dict read, `str(locals())` or a positional `"%s" % locals()` —
// and the result is a tracked container whose slots are those bindings, so a reader that names
// one (`locals()["key"]`) is element-sensitive rather than whole-scope.
func (l *lowerer) lowerLocalsSnapshot(result string, sc *scope) {
	ci := l.cinfo(result)
	for name := range sc.node {
		node := pySnapshotSlot(sc, name)
		if node == "" {
			continue
		}
		ci.elems[name] = node
		l.flow(node, result)
	}
}

// localsFormatOperand recognises `"<…>%(key)s<…>" % locals()` inside a NIR Format and returns
// the operand's part index together with the keys the template names. It returns -1 when the
// format does not name its keys — the template is not a compile-time string, or the operand is
// a positional conversion — where flowing the whole snapshot is the only sound reading.
func (l *lowerer) localsFormatOperand(f nir.Format, sc *scope) (int, []string) {
	if moduleTech(l.curFile) != "python" || len(f.Parts) != 2 {
		return -1, nil
	}
	operand := -1
	for i, p := range f.Parts {
		call, ok := p.(nir.Call)
		if !ok || !l.isLocalsSnapshot(call, sc) {
			continue
		}
		if operand >= 0 {
			return -1, nil
		}
		operand = i
	}
	if operand < 0 {
		return -1, nil
	}
	template, ok := l.constStrVal(f.Parts[1-operand], sc)
	if !ok {
		return -1, nil
	}
	keys := pyFormatMappingKeys(template)
	if len(keys) == 0 {
		return -1, nil
	}
	return operand, keys
}

// flowLocalsSlots ties one snapshot slot to n for each key the template names, and reports
// whether every key named a binding. A key a snapshot does not hold raises KeyError at
// runtime, so the caller keeps the whole-snapshot flow rather than guess at that slot.
func (l *lowerer) flowLocalsSlots(keys []string, n string, sc *scope) bool {
	if len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		node := pySnapshotSlot(sc, key)
		if node == "" {
			return false
		}
		l.flow(node, n)
	}
	return true
}

// pyFormatMappingKeys lists the keys a %-format template reads out of its mapping, once each
// in first-mention order. `%%` escapes the percent and names no key.
func pyFormatMappingKeys(template string) []string {
	var keys []string
	seen := map[string]bool{}
	for _, at := range pyFormatMappingKeyRE.FindAllStringSubmatchIndex(template, -1) {
		if at[0] > 0 && template[at[0]-1] == '%' {
			continue
		}
		key := template[at[2]:at[3]]
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys
}

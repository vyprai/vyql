// Receiver types read off a module global. The lowerer stamps `recv_type` on a method call
// whose receiver was built by a known constructor; this file carries the fact for the case
// where the receiver is a MODULE-LEVEL variable of a JavaScript module -- the spelling that
// language writes everywhere (`const q = new AV.Query('Todo'); … q.get(k)` at the top of the
// file).
//
// Such a name resolves to the module's one slot node rather than to the construction that
// filled it, so the stamp a plain local already gets never reaches the call: recvType reads
// the slot, and a slot carries no callee path to look a constructor up by. A binding's
// receiver-type route was therefore dead at module scope in exactly the language that writes
// its setup there. collectGlobalCtorTypes records what every write of the global built it
// from, under the same all-writes-agree discipline collectFieldCtorTypes applies to a class
// field, and the call site reads it beside that route.
//
// One indirection more is expressible, and the constructor table alone cannot express it: a
// global can hold the CLASS a factory returned (`const Todo = AV.Object.extend('Todo')`,
// typed by a binding's fact about `AV.Object.extend`), and the instances are then made
// through that name -- `new Todo()`. The type recorded for the global therefore also answers
// for a construction whose callee names it.
//
// Go resolves its package-level names to slots too, and is deliberately left out: recording
// Go receiver types is its own tracked gap, and a type this route stamped on a package-level
// var would move every Go score for a change no rank asked this one to carry.

package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// globalCtorConflict marks a module global whose writes do not all name the same constructor.
// It is distinct from an absent entry: absent means no write of that global was seen, conflict
// means writes were seen and they do not agree.
const globalCtorConflict = "\x00"

// globalCtorKey is the key a module's own top-level variable is recorded under. A module
// global is file-scoped, so the namespace -- not the module key -- is what separates one
// file's `q` from another's.
func globalCtorKey(ns, name string) string {
	return ns + "\x1f" + name
}

// globalCtorWrite is one write to a module-level variable the collection pass walked past. The
// construction on the right-hand side names a class or a binding-declared constructor another
// file's declarations may be needed to resolve, so the write is held until every module is
// registered and reduced then, the same reason the field writes are held.
type globalCtorWrite struct {
	ns, modkey, name string
	value            nir.Expr
}

// collectGlobalCtorTypes folds every write to a module-level variable of a JS-like module
// into one constructor type per global. It runs after registration, so a write's construction
// resolves against the complete class table, and before any body is lowered, so a call lowered
// long before the write that fills the global still sees the type. It walks the program's NIR,
// which is present for every module whether or not its lowered body came from the incremental
// cache.
func (l *lowerer) collectGlobalCtorTypes() {
	var writes []globalCtorWrite
	for _, m := range l.prog.Modules {
		if !isJSLikeModule(m.File) {
			continue
		}
		body := l.bodyOf(m)
		top := map[string]bool{}
		for _, name := range topLevelAssignedNames(body.Body) {
			top[name] = true
		}
		if len(top) == 0 {
			continue
		}
		ns := ModuleNS(m)
		l.curModule, l.curNS, l.curFile = m.Key, ns, m.File
		writes = append(writes, l.noteGlobalCtorWrites(ns, m.Key, top, body.Body, false)...)
	}
	l.resolveGlobalCtorTypes(writes)
}

// noteGlobalCtorWrites records the writes that reach a module's slot for one of its own
// top-level names. A declaration inside a body is that body's binding rather than a write to
// the module's variable -- the same line the assignment lowering draws between them -- and
// control flow at the top level stays top level.
func (l *lowerer) noteGlobalCtorWrites(ns, modkey string, top map[string]bool, stmts []nir.Stmt, nested bool) []globalCtorWrite {
	var out []globalCtorWrite
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.Assign:
			if nested && st.Decl || st.Value == nil {
				continue
			}
			for _, t := range st.Targets {
				if top[t] {
					out = append(out, globalCtorWrite{ns, modkey, t, st.Value})
				}
			}
		case nir.BodyRef:
			if st.Summarized {
				out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Summary.Declarations, nested)...)
			} else {
				l.eachDeferred(st, func(chunk []nir.Stmt) {
					out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, chunk, nested)...)
				})
			}
		case nir.FuncDef:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Body, true)...)
		case nir.ClassDef:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Body, true)...)
		case nir.Block:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Stmts, nested)...)
		case nir.If:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Then, nested)...)
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Else, nested)...)
		case nir.Loop:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Body, nested)...)
		case nir.Switch:
			for _, arm := range st.Cases {
				out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, arm, nested)...)
			}
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Default, nested)...)
		case nir.Try:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Body, nested)...)
			for _, h := range st.Handlers {
				out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, h, nested)...)
			}
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Finally, nested)...)
		case nir.Defer:
			out = append(out, l.noteGlobalCtorWrites(ns, modkey, top, st.Body, nested)...)
		}
	}
	return out
}

// resolveGlobalCtorTypes reduces the recorded writes to one type per global. Every write seen
// must be a construction and all of them must agree: one write the constructor table and the
// class table do not name, one holding a parameter or a literal, or two building different
// types, each leaves the global untyped -- the receiver may be any of them at the read. It is
// the discipline recvMergeCtorType applies to a control-flow merge, applied to the slot a
// module-level read draws its value from.
//
// The writes are reduced twice. The first fold reads only what a write's own callee names; the
// second may also read the type another global was recorded with, which is how a construction
// through a factory-returned class (`new Todo()`) is typed. Settling the direct types first is
// what keeps that indirection independent of the order the writes were walked in.
func (l *lowerer) resolveGlobalCtorTypes(writes []globalCtorWrite) {
	direct := map[string]string{}
	for _, w := range writes {
		l.curModule, l.curNS = w.modkey, w.ns
		noteGlobalCtorVote(direct, globalCtorKey(w.ns, w.name), l.directCtorType(w.value))
	}
	for _, w := range writes {
		l.curModule, l.curNS = w.modkey, w.ns
		t := l.directCtorType(w.value)
		if t == "" {
			t = l.chainedGlobalCtorType(w.value, direct)
		}
		noteGlobalCtorVote(l.globalCtorTypes, globalCtorKey(w.ns, w.name), t)
	}
}

// noteGlobalCtorVote folds one write's type into a global's entry. The first write records
// what it built -- "" when it built nothing a constructor names -- and a later write that
// disagrees, in either direction, marks the global conflicted for good.
func noteGlobalCtorVote(table map[string]string, key, t string) {
	cur, seen := table[key]
	if !seen {
		table[key] = t
		return
	}
	if cur != globalCtorConflict && cur != t {
		table[key] = globalCtorConflict
	}
}

// directCtorType is ctorTypeOfExpr without the module-global indirection: what the value's own
// callee names, and nothing else.
func (l *lowerer) directCtorType(e nir.Expr) string {
	call, ok := e.(nir.Call)
	if !ok {
		return ""
	}
	if t, ok := l.resolveCtor(call.Callee); ok {
		return t[1]
	}
	return l.ctorTypes[call.Path]
}

// chainedGlobalCtorType returns the type a construction through a module global's own name
// builds, read from table: the global holds the class a factory returned -- itself typed by
// the constructor table -- so constructing through it builds what the factory handed back. A
// dotted or subscripted callee is not a global's name and is left alone.
func (l *lowerer) chainedGlobalCtorType(e nir.Expr, table map[string]string) string {
	call, ok := e.(nir.Call)
	if !ok {
		return ""
	}
	nm, ok := call.Callee.(nir.Name)
	if !ok || nm.ID == "" || strings.ContainsAny(nm.ID, ".[") {
		return ""
	}
	if t, ok := table[globalCtorKey(l.curNS, nm.ID)]; ok && t != "" && t != globalCtorConflict {
		return t
	}
	return ""
}

// globalCtorType returns the type every write of one module global built it from, or "" when
// the writes disagree, name no constructor, or were never seen.
func (l *lowerer) globalCtorType(ns, name string) string {
	if t, ok := l.globalCtorTypes[globalCtorKey(ns, name)]; ok && t != globalCtorConflict {
		return t
	}
	return ""
}

// receiverGlobalCtorType returns the type a method call's receiver was built with when the
// receiver names one of the enclosing module's own top-level variables: the name resolves to
// the module's slot node rather than to the construction that filled it, so nothing the
// construction carried reached the call. The receiver must BE that slot -- a local or
// parameter of the same name shadows the global, and its own node is what the call is made on.
func (l *lowerer) receiverGlobalCtorType(base nir.Expr, recvNode string) string {
	if len(l.globalCtorTypes) == 0 {
		return ""
	}
	nm, ok := base.(nir.Name)
	if !ok {
		return ""
	}
	if slot := l.moduleGlobalSlot(nm.ID); slot == "" || slot != recvNode {
		return ""
	}
	return l.globalCtorType(l.curNS, nm.ID)
}

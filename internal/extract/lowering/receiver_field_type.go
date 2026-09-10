// Receiver types read off a class field. The lowerer stamps `recv_type` on a method call whose
// receiver was built by a known constructor; this file carries the fact for the case where the
// receiver is a PROPERTY of a class rather than a plain local holding the construction's
// result -- the shape every framework-written class has, where the object is built in one
// method and reached as `$this->field` in another.

package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// fieldCtorConflict marks a field whose writes do not all name the same constructor. It is
// distinct from an absent entry: absent means no write of that field was seen, conflict means
// writes were seen and they do not agree.
const fieldCtorConflict = "\x00"

// fieldCtorWrite is one class-field write the collection pass walked past. The construction on
// its right-hand side names a class another file declares far more often than not -- a
// controller builds its model, a script builds its connection -- so the write is held until
// every module is registered and resolved then, the same reason the write itself is collected
// in a pass that runs before any body is lowered.
type fieldCtorWrite struct {
	modkey, cls, field string
	value              nir.Expr
}

// collectFieldCtorTypes folds every class-field write in the program into one constructor type
// per field. It runs after registration, so the class a write constructs resolves against the
// complete class table, and before any body is lowered, so a read lowered long before the
// write that fills its field still sees the type. It walks the program's NIR, which is present
// for every module whether or not its lowered body came from the incremental cache.
func (l *lowerer) collectFieldCtorTypes() {
	for _, m := range l.prog.Modules {
		l.curModule, l.curNS, l.curFile = m.Key, ModuleNS(m), m.File
		l.noteFieldCtorTypes(m.Key, "", l.bodyOf(m).Body)
	}
	l.resolveFieldCtorTypes()
}

func (l *lowerer) noteFieldCtorTypes(modkey, cls string, stmts []nir.Stmt) {
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.Assign:
			l.noteFieldCtorAssign(modkey, cls, st)
		case nir.ExprStmt:
			l.noteFieldCtorCall(modkey, cls, st.Value)
		case nir.BodyRef:
			if st.Summarized {
				l.noteFieldCtorTypes(modkey, cls, st.Summary.Declarations)
			} else {
				l.eachDeferred(st, func(chunk []nir.Stmt) { l.noteFieldCtorTypes(modkey, cls, chunk) })
			}
		case nir.ClassDef:
			l.noteFieldCtorTypes(modkey, st.Name, st.Body)
		case nir.FuncDef:
			l.noteFieldCtorTypes(modkey, declClass(cls, st), st.Body)
		case nir.Block:
			l.noteFieldCtorTypes(modkey, cls, st.Stmts)
		case nir.If:
			l.noteFieldCtorTypes(modkey, cls, st.Then)
			l.noteFieldCtorTypes(modkey, cls, st.Else)
		case nir.Loop:
			l.noteFieldCtorTypes(modkey, cls, st.Body)
		case nir.Switch:
			for _, arm := range st.Cases {
				l.noteFieldCtorTypes(modkey, cls, arm)
			}
			l.noteFieldCtorTypes(modkey, cls, st.Default)
		case nir.Try:
			l.noteFieldCtorTypes(modkey, cls, st.Body)
			for _, h := range st.Handlers {
				l.noteFieldCtorTypes(modkey, cls, h)
			}
			l.noteFieldCtorTypes(modkey, cls, st.Finally)
		case nir.Defer:
			l.noteFieldCtorTypes(modkey, cls, st.Body)
		}
	}
}

// noteFieldCtorAssign records a member-write assignment: a bare name the class declares as a
// member (`field = v`, the spelling Java and C# resolve to the field), or a member written
// through the implicit self (`this.field = v`, `self.field = v`). A declaration introduces a
// local, not a write to the field, so one is skipped -- the same rule the lowering applies
// when it decides where a bare member write lands.
func (l *lowerer) noteFieldCtorAssign(modkey, cls string, st nir.Assign) {
	if cls == "" || st.Decl || st.Value == nil {
		return
	}
	for _, t := range st.Targets {
		if field, ok := l.declaredFieldTarget(modkey, cls, t); ok {
			l.fieldCtorWrites = append(l.fieldCtorWrites, fieldCtorWrite{modkey, cls, field, st.Value})
		}
	}
}

// noteFieldCtorCall records the spelling PHP lowers `$this->field = v` to: a call with no
// method on the accessed property, whose first argument is the value stored. The conditions
// mirror the branch that lowers such a call into a field store, so the two can never disagree
// about which statements are writes.
func (l *lowerer) noteFieldCtorCall(modkey, cls string, e nir.Expr) {
	if cls == "" {
		return
	}
	call, ok := e.(nir.Call)
	if !ok || call.Method != "" || len(call.Args) == 0 {
		return
	}
	attr, ok := call.Callee.(nir.Attr)
	if !ok || attr.Attr == "" || !isSelfName(attr.Base, l.selfName) {
		return
	}
	l.fieldCtorWrites = append(l.fieldCtorWrites, fieldCtorWrite{modkey, cls, attr.Attr, call.Args[0]})
}

// declaredFieldTarget reports the field an assignment target names on the enclosing class. A
// bare name is taken only when the class declares it as a member -- anything else could be a
// local -- while a dotted one is taken on the strength of its self base alone.
func (l *lowerer) declaredFieldTarget(modkey, cls, target string) (string, bool) {
	if target == "" || cls == "" {
		return "", false
	}
	if !strings.Contains(target, ".") {
		if l.directMembers[modkey+"::"+cls][target] {
			return target, true
		}
		return "", false
	}
	base, field, ok := splitFieldTarget(target)
	if !ok || strings.Contains(field, ".") || !isSelfNameID(base, l.selfName) {
		return "", false
	}
	return field, true
}

// isSelfName reports whether e names the implicit receiver of the enclosing method: `$this`,
// `this`, or whatever spelling the language's frontend records as the self parameter.
func isSelfName(e nir.Expr, selfName string) bool {
	nm, ok := e.(nir.Name)
	if !ok {
		return false
	}
	return isSelfNameID(nm.ID, selfName)
}

func isSelfNameID(id, selfName string) bool {
	return id == "$this" || id == "this" || (selfName != "" && id == selfName)
}

// resolveFieldCtorTypes reduces the recorded writes to one type per field. Every write seen
// must be a construction and all of them must agree: one write the constructor table and the
// class table do not name, one holding a parameter or a literal, or two building different
// types, each leaves the field untyped -- the receiver may be any of them at the read. It is
// the discipline recvMergeCtorType applies to a control-flow merge, applied to the field slot
// a property read draws its value from.
func (l *lowerer) resolveFieldCtorTypes() {
	for _, w := range l.fieldCtorWrites {
		// resolveCtor keys off the module under resolution; the writes are held per module.
		l.curModule = w.modkey
		key := w.modkey + "::" + w.cls + "\x1f" + w.field
		cur, seen := l.fieldCtorTypes[key]
		if seen && cur == fieldCtorConflict {
			continue
		}
		t := l.ctorTypeOfExpr(w.value)
		switch {
		case !seen:
			l.fieldCtorTypes[key] = t
		case cur != t:
			l.fieldCtorTypes[key] = fieldCtorConflict
		}
	}
	l.fieldCtorWrites = nil
}

// ctorTypeOfExpr returns the type a construction returns: a class the scan declares, or the
// type name a binding's ReceiverType fact records for the callee path. Anything else reports
// "", which is no evidence of a type rather than evidence of a different one.
func (l *lowerer) ctorTypeOfExpr(e nir.Expr) string {
	call, ok := e.(nir.Call)
	if !ok {
		return ""
	}
	if t, ok := l.resolveCtor(call.Callee); ok {
		return t[1]
	}
	return l.ctorTypes[call.Path]
}

// receiverFieldCtorType returns the type a method call's receiver was built with when the
// receiver names a field of a class the scan declares -- `$this->field` read directly, or as
// the base of the call's own property access in `$this->field->method()`. collectFieldCtorTypes
// recorded what every write of that field built it from.
func (l *lowerer) receiverFieldCtorType(base nir.Expr, sc *scope) string {
	if len(l.fieldCtorTypes) == 0 {
		return ""
	}
	attr, ok := base.(nir.Attr)
	if !ok {
		return ""
	}
	nm, ok := attr.Base.(nir.Name)
	if !ok {
		return ""
	}
	modkey, cls := "", ""
	if isSelfName(nm, l.selfName) {
		modkey, cls = l.curModule, l.curClass
	} else if t, ok := sc.typ[nm.ID]; ok {
		modkey, cls = t[0], t[1]
	}
	return l.fieldCtorType(modkey, cls, attr.Attr)
}

// fieldCtorType returns the type every write of one class field built it from, or "" when the
// writes disagree or name no constructor. A class that writes nothing of its own may still be
// holding a field its base built: the lookup walks the declared bases and stops at the first
// class that declares the field itself, which is the one whose write answers for it.
func (l *lowerer) fieldCtorType(modkey, cls, field string) string {
	if cls == "" || field == "" {
		return ""
	}
	visited := map[string]bool{}
	for {
		if t, ok := l.fieldCtorTypes[modkey+"::"+cls+"\x1f"+field]; ok {
			if t == fieldCtorConflict {
				return ""
			}
			return t
		}
		if visited[cls] || len(visited) >= 8 {
			return ""
		}
		visited[cls] = true
		if l.directMembers[modkey+"::"+cls][field] {
			return "" // declared here, never built here: it holds whatever was assigned, untyped
		}
		next := ""
		for _, b := range l.classBaseNames[modkey+"::"+cls] {
			if short := shortClassName(b); l.classQual[modkey+"::"+short] {
				next = short
				break
			}
		}
		if next == "" {
			return ""
		}
		cls = next
	}
}

// Interprocedural pairing of a function-typed constructor parameter with the argument a
// construction site supplies for it. `constructor(exec) { this.exec = exec }` -- spelled
// `constructor(private exec: Fn) {}` in TypeScript, whose implicit store the frontend emits
// like the hand-written one -- binds a function value into a class field, and a later
// `this.exec(name, args)` in another method dispatches into that value. Name-keyed call
// resolution cannot answer that dispatch (the field is not a declared method), and the value
// the field holds is only decided at the construction site, which is usually in a different
// file than the class. The two halves are joined on one node per (class, field), minted
// before any body is lowered with a name-derived id in the class's own file namespace -- the
// discipline the class's `this` node and the signature nodes follow -- so whichever half
// lowers first, in whatever module order, and whatever the incremental cache replays, both
// address the same node.

package lowering

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ctorParamField pairs one constructor parameter with the field the constructor stores it
// into: `this.<field> = <param>` while the object is being built.
type ctorParamField struct{ param, field string }

// collectCtorParamFields records, per class, the constructor parameters whose values the
// constructor stores into a `this.<field>`, and mints the per-(class, field) node the
// pairing's two halves are joined on. It runs after registration and before any body is
// lowered -- the same placement as collectFieldCtorTypes, for the same reason: the fact
// joins sites in different modules, so it must be settled program-wide before either is
// lowered, and the NIR walk covers cached modules too. Minting the join node here is what
// makes the pairing order-independent: neither half creates it, both only look it up.
func (l *lowerer) collectCtorParamFields() {
	for _, m := range l.prog.Modules {
		l.curModule, l.curNS, l.curFile = m.Key, ModuleNS(m), m.File
		l.noteCtorParamFields(m.Key, "", l.bodyOf(m).Body)
	}
}

func (l *lowerer) noteCtorParamFields(modkey, cls string, stmts []nir.Stmt) {
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.BodyRef:
			if st.Summarized {
				l.noteCtorParamFields(modkey, cls, st.Summary.Declarations)
			} else {
				l.eachDeferred(st, func(chunk []nir.Stmt) { l.noteCtorParamFields(modkey, cls, chunk) })
			}
		case nir.ClassDef:
			l.noteCtorParamFields(modkey, st.Name, st.Body)
		case nir.FuncDef:
			inner := declClass(cls, st)
			if isConstructorName(st.Name, inner) {
				l.noteCtorFieldStores(modkey, inner, st)
			}
			l.noteCtorParamFields(modkey, inner, st.Body)
		case nir.Block:
			l.noteCtorParamFields(modkey, cls, st.Stmts)
		case nir.If:
			l.noteCtorParamFields(modkey, cls, st.Then)
			l.noteCtorParamFields(modkey, cls, st.Else)
		case nir.Loop:
			l.noteCtorParamFields(modkey, cls, st.Body)
		case nir.Try:
			l.noteCtorParamFields(modkey, cls, st.Body)
			l.noteCtorParamFields(modkey, cls, st.Finally)
		}
	}
}

// noteCtorFieldStores pairs each top-level `this.<field> = <param>` store of a constructor
// with the parameter it stores, and mints the per-(class, field) join node in the class's
// own file namespace.
func (l *lowerer) noteCtorFieldStores(modkey, cls string, fn nir.FuncDef) {
	var pairs []ctorParamField
	for _, s := range fn.Body {
		field, val := ctorFieldStore(s, l.selfName)
		if field == "" {
			continue
		}
		nm, ok := val.(nir.Name)
		if !ok {
			continue
		}
		for _, p := range fn.Params {
			if p == nm.ID {
				pairs = append(pairs, ctorParamField{param: p, field: field})
			}
		}
	}
	if len(pairs) == 0 {
		return
	}
	qual := modkey + "::" + cls
	l.ctorParamFields[qual] = append(l.ctorParamFields[qual], pairs...)
	for _, pf := range pairs {
		key := qual + "\x1f" + pf.field
		if l.ctorFieldArgs[key] != "" {
			continue
		}
		l.ctorFieldArgs[key] = l.nodeWithID(sigID(l.curNS, cls, "ctorarg", pf.field), "Name", fn.Loc,
			map[string]string{"class": cls, "name": pf.field})
	}
}

// ctorFieldStore returns the field and the stored value of a `this.<field> = v` statement,
// in either spelling the frontends lower member writes to -- the JS/TS/PHP path call and the
// dotted assignment. ("", nil) when the statement is not one.
func ctorFieldStore(s nir.Stmt, selfName string) (string, nir.Expr) {
	switch st := s.(type) {
	case nir.ExprStmt:
		call, ok := st.Value.(nir.Call)
		if !ok || call.Method != "" || len(call.Args) != 1 {
			return "", nil
		}
		attr, ok := call.Callee.(nir.Attr)
		if !ok || attr.Attr == "" || !isSelfName(attr.Base, selfName) {
			return "", nil
		}
		return attr.Attr, call.Args[0]
	case nir.Assign:
		if st.Decl || len(st.Targets) != 1 {
			return "", nil
		}
		base, field, ok := splitFieldTarget(st.Targets[0])
		if !ok || strings.Contains(field, ".") || !isSelfNameID(base, selfName) {
			return "", nil
		}
		return field, st.Value
	}
	return "", nil
}

// flowCtorFieldArgs routes the arguments of an unresolved `this.<field>(...)` call into the
// per-(class, field) node the function literals injected at the class's construction sites
// are fed from -- the call's real callee when the field holds a function value bound at
// construction. Pure addition: the call keeps every edge it had as an unresolved call, so
// nothing that resolves today changes.
func (l *lowerer) flowCtorFieldArgs(call nir.Call, args []string) {
	// Method is empty on the member-WRITE lowering (`this.<field> = v` is a path call with no
	// method), so requiring it keeps the store's own value out of the dispatch's channel.
	if len(args) == 0 || call.Method == "" || l.curClass == "" {
		return
	}
	attr, ok := call.Callee.(nir.Attr)
	if !ok || attr.Attr == "" || !isSelfName(attr.Base, l.selfName) {
		return
	}
	hub := l.ctorFieldArgs[l.curModule+"::"+l.curClass+"\x1f"+attr.Attr]
	if hub == "" {
		return
	}
	for _, a := range args {
		l.flow(a, hub)
	}
}

// pairCtorFieldArgs joins a construction site with the `this.<field>(...)` dispatches of the
// class it builds. For each constructor parameter the constructor stores into a field, the
// argument this site passes for it -- when it is a function literal -- is a body the class's
// own methods call through that field; feed it from the field's join node, so the arguments
// of every such dispatch reach the literal's parameters. Without the pairing the literal has
// no caller at all: no name resolves to it. Position fidelity is dropped the way the
// dynamic-callback dispatch drops it (see flowValueToAllParams) -- several sites may inject
// different literals of different arities into the same field.
func (l *lowerer) pairCtorFieldArgs(target *funcInfo, recv string, argVals []string) {
	if !target.ctor || len(argVals) == 0 {
		return
	}
	qual := target.module + "::" + target.cls
	pairs := l.ctorParamFields[qual]
	if len(pairs) == 0 {
		return
	}
	offset := l.paramOffset(target, recv)
	for _, pf := range pairs {
		hub := l.ctorFieldArgs[qual+"\x1f"+pf.field]
		if hub == "" {
			continue
		}
		for i := offset; i < len(target.paramNames); i++ {
			if target.paramNames[i] != pf.param || i-offset >= len(argVals) {
				continue
			}
			for _, p := range l.lambdaParams[argVals[i-offset]] {
				l.flow(hub, p)
			}
		}
	}
}

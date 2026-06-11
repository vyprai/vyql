// Package lowering is the shared, language-AGNOSTIC tier (docs/20): it lowers
// NIR into a Universal Security Graph, owning the function/class registries,
// per-file import tables, the type map (self, constructors, class/static
// receivers), call resolution (import -> type -> guarded unique-name fallback),
// and dataflow construction (scopes, assignments, FLOWS edges).
//
// None of this is duplicated per language. A frontend's only job is to translate
// its parser's tree into NIR; resolution and dataflow live here, once. This is
// what lets the project add a language — or swap a parser (tree-sitter, native,
// LSP/SCIP) — without touching resolution or rules. Ported from
// poc/extract/lowering.py; the algorithm is docs/10 §"Call resolution"
// generalized over NIR.
package lowering

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

type funcInfo struct {
	paramNames []string
	params     map[string]string // name -> param node id
	ret        string            // return node id
	module     string
	cls        string
	name       string
}

type importEntry struct {
	kind   string // "mod" or "sym"
	module string
	symbol string // for "sym"
}

type lowerer struct {
	prog           nir.Program
	selfName       string
	resolveImports bool
	ctorTypes      map[string]string // constructor callee-path -> returned type name
	g              usg.Store
	ctr            int

	funcQual     map[string]*funcInfo         // "modkey::qual" -> info
	funcShort    map[string][]*funcInfo       // short name -> infos
	classQual    map[string]bool              // "modkey::Class"
	classDefs    map[string][]string          // bare class name -> modules that define it
	classFields  map[string]map[string]string // "modkey::Class" -> field -> declared class type
	importTables map[string]map[string]importEntry

	curModule string
	curClass  string // "" = none
}

// scope holds variable -> node bindings and variable -> (module, class) types.
type scope struct {
	node map[string]string
	typ  map[string][2]string
}

func newScope() *scope {
	return &scope{node: map[string]string{}, typ: map[string][2]string{}}
}

func (s *scope) clone() *scope {
	c := newScope()
	for k, v := range s.node {
		c.node[k] = v
	}
	for k, v := range s.typ {
		c.typ[k] = v
	}
	return c
}

// Lower lowers a Program into a fresh in-memory USG. When resolveImports is
// false, calls resolve by SHORT NAME (the over-connecting baseline that case 16
// contrasts against).
func Lower(prog nir.Program, resolveImports bool) (usg.Store, error) {
	return LowerTyped(prog, resolveImports, nil)
}

// LowerTyped is Lower with a constructor→type table (callee path of a
// constructor → the type it returns, e.g. "sql.Open" → "sql.DB"). A receiver
// assigned from a known constructor lets the lowering stamp `recv_type` on its
// method calls, which type-constrained sink adapters use for precision.
func LowerTyped(prog nir.Program, resolveImports bool, ctorTypes map[string]string) (usg.Store, error) {
	l := &lowerer{
		prog:           prog,
		selfName:       prog.Self(),
		resolveImports: resolveImports,
		ctorTypes:      ctorTypes,
		g:              usg.NewInMemStore(),
		funcQual:       map[string]*funcInfo{},
		funcShort:      map[string][]*funcInfo{},
		classQual:      map[string]bool{},
		classDefs:      map[string][]string{},
		classFields:    map[string]map[string]string{},
		importTables:   map[string]map[string]importEntry{},
	}
	if err := l.run(); err != nil {
		return nil, err
	}
	return l.g, nil
}

// --- graph helpers ------------------------------------------------------

func (l *lowerer) nid(prefix string) string {
	l.ctr++
	return prefix + "#" + strconv.Itoa(l.ctr)
}

func (l *lowerer) node(kind, loc string, props map[string]string) string {
	id := l.nid(kind)
	p := map[string]string{"loc": loc}
	for k, v := range props {
		p[k] = v
	}
	l.g.AddNode(usg.Node{ID: id, Type: "code." + kind, Props: p})
	return id
}

func (l *lowerer) flow(a, b string) {
	if a == "" || b == "" {
		return
	}
	if _, ok, _ := l.g.GetNode(a); !ok {
		return
	}
	if _, ok, _ := l.g.GetNode(b); !ok {
		return
	}
	l.g.AddEdge(usg.Edge{Type: "FLOWS", Src: a, Dst: b})
}

// --- entry --------------------------------------------------------------

func (l *lowerer) run() error {
	for _, m := range l.prog.Modules {
		l.importTables[m.Key] = importTable(m)
		l.register(m.Key, m.Body, "")
	}
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass = m.Key, ""
		l.block(m.Body, newScope())
	}
	return nil
}

func importTable(m nir.Module) map[string]importEntry {
	out := map[string]importEntry{}
	for _, imp := range m.Imports {
		if imp.IsModule {
			out[imp.Local] = importEntry{kind: "mod", module: imp.Module}
		} else {
			out[imp.Local] = importEntry{kind: "sym", module: imp.Module, symbol: imp.Symbol}
		}
	}
	return out
}

// --- pass 1: registration ----------------------------------------------

func (l *lowerer) register(modkey string, stmts []nir.Stmt, cls string) {
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.ClassDef:
			l.classQual[modkey+"::"+st.Name] = true
			l.classDefs[st.Name] = appendUniq(l.classDefs[st.Name], modkey)
			// record field -> declared class type (for cross-file method resolution
			// on field receivers, e.g. Spring `@Autowired UserService svc; svc.m()`).
			for _, bs := range st.Body {
				if a, ok := bs.(nir.Assign); ok && a.Type != "" && len(a.Targets) == 1 {
					if l.classFields[modkey+"::"+st.Name] == nil {
						l.classFields[modkey+"::"+st.Name] = map[string]string{}
					}
					l.classFields[modkey+"::"+st.Name][a.Targets[0]] = a.Type
				}
			}
			l.register(modkey, st.Body, st.Name)
		case nir.FuncDef:
			prefix := ""
			if cls != "" {
				prefix = cls + "."
			}
			qual := modkey + "::" + prefix + st.Name
			params := map[string]string{}
			var order []string
			for _, p := range st.Params {
				params[p] = l.node("Param", st.Loc, map[string]string{"name": p, "func": st.Name})
				order = append(order, p)
			}
			info := &funcInfo{
				paramNames: order,
				params:     params,
				ret:        l.node("Return", st.Loc, map[string]string{"func": st.Name}),
				module:     modkey, cls: cls, name: st.Name,
			}
			l.funcQual[qual] = info
			l.funcShort[st.Name] = append(l.funcShort[st.Name], info)
		}
	}
}

// --- pass 2: statements ------------------------------------------------

func (l *lowerer) block(stmts []nir.Stmt, sc *scope) {
	for _, s := range stmts {
		l.stmt(s, sc)
	}
}

func (l *lowerer) stmt(s nir.Stmt, sc *scope) {
	switch st := s.(type) {
	case nir.ClassDef:
		prev := l.curClass
		l.curClass = st.Name
		l.block(st.Body, newScope())
		l.curClass = prev
	case nir.FuncDef:
		prefix := ""
		if l.curClass != "" {
			prefix = l.curClass + "."
		}
		qual := l.curModule + "::" + prefix + st.Name
		info := l.funcQual[qual]
		inner := newScope()
		if info != nil {
			for name, id := range info.params {
				inner.node[name] = id
			}
			inner.node["__ret__"] = info.ret
		}
		if l.curClass != "" && len(st.Params) > 0 && st.Params[0] == l.selfName {
			inner.typ[l.selfName] = [2]string{l.curModule, l.curClass}
		}
		// seed enclosing-class field receivers so `field.method()` resolves
		for fld, typ := range l.classFields[l.curModule+"::"+l.curClass] {
			if cm, ok := l.classModule(typ, l.importTables[l.curModule]); ok {
				inner.typ[fld] = [2]string{cm, typ}
			}
		}
		l.block(st.Body, inner)
	case nir.Assign:
		val := l.eval(st.Value, sc)
		var typ [2]string
		hasTyp := false
		if call, ok := st.Value.(nir.Call); ok {
			if t, ok := l.resolveCtor(call.Callee); ok {
				typ, hasTyp = t, true
			}
		}
		if !hasTyp && st.Type != "" { // declared type (no/foreign RHS), e.g. Spring DI field
			if cm, ok := l.classModule(st.Type, l.importTables[l.curModule]); ok {
				typ, hasTyp = [2]string{cm, st.Type}, true
			}
		}
		for _, t := range st.Targets {
			sc.node[t] = val
			if hasTyp {
				sc.typ[t] = typ
			}
		}
	case nir.AugAssign:
		n := l.node("Concat", st.Loc, nil)
		l.flow(l.eval(st.Value, sc), n)
		l.flow(sc.node[st.Target], n)
		sc.node[st.Target] = n
	case nir.Return:
		l.flow(l.eval(st.Value, sc), sc.node["__ret__"])
	case nir.ExprStmt:
		l.eval(st.Value, sc)
	case nir.Block:
		l.block(st.Stmts, sc)
	}
}

// --- expressions --------------------------------------------------------

func (l *lowerer) eval(e nir.Expr, sc *scope) string {
	switch ex := e.(type) {
	case nil:
		return ""
	case nir.Name:
		if v, ok := sc.node[ex.ID]; ok && v != "" {
			return v
		}
		return l.node("Const", ex.Loc, nil)
	case nir.Const:
		return l.node("Const", ex.Loc, nil)
	case nir.Thru:
		return l.eval(ex.Inner, sc)
	case nir.Attr:
		base := l.eval(ex.Base, sc)
		// `method` carries the attribute NAME (last segment) so `source method "ssn"`
		// matches a field read like `user.ssn` regardless of receiver. Golden-neutral
		// (the NIR golden serializes callee_path, not method).
		n := l.node("Attr", ex.Loc, map[string]string{"callee_path": ex.Path, "method": ex.Attr})
		l.flow(base, n)
		return n
	case nir.Index:
		base := l.eval(ex.Base, sc)
		n := l.node("Subscript", ex.Loc, map[string]string{"callee_path": ex.Path})
		l.flow(base, n)
		return n
	case nir.Call:
		return l.evalCall(ex, sc)
	case nir.Format:
		n := l.node("Format", ex.Loc, nil)
		for _, p := range ex.Parts {
			l.flow(l.eval(p, sc), n)
		}
		return n
	case nir.Seq:
		n := l.node("Seq", ex.Loc, nil)
		for _, p := range ex.Parts {
			l.flow(l.eval(p, sc), n)
		}
		return n
	case nir.Pair:
		// A named entry's value carries the taint; the key is metadata used only
		// by value-matching. Lower to the value so taint still flows (e.g. an
		// object property holding user input).
		return l.eval(ex.Value, sc)
	case nir.Lambda:
		inner := newScope()
		for _, p := range ex.Params {
			inner.node[p] = l.node("Param", ex.Loc, map[string]string{"name": p})
		}
		l.block(ex.Body, inner)
		return l.node("Func", ex.Loc, nil)
	}
	return l.node("Const", "?:0", nil)
}

// collectValTokens walks an argument expression and accumulates literal value
// tokens for named-value matching (`val`/`nval`). For each literal it emits the
// bare value, and — when it sits under a key (a kwarg, dict/object/hash entry, or
// struct field) — also a "key=value" token. Lists/objects are walked so nested
// literals are reached, e.g. jwt(algorithms=["none"]) yields "none" and
// "algorithms=none"; requests.get(url, verify=False) yields "False" and
// "verify=False". Frontends that don't emit nir.Pair simply contribute bare values.
func collectValTokens(e nir.Expr, key string, out *[]string) {
	switch ex := e.(type) {
	case nir.Const:
		if v := unquoteLit(ex.Value); v != "" {
			*out = append(*out, v)
			if key != "" {
				*out = append(*out, key+"="+v) // e.g. verify=False, algorithms=none
			}
		}
	case nir.Pair:
		collectValTokens(ex.Value, ex.Key, out)
	case nir.Seq:
		for _, p := range ex.Parts {
			collectValTokens(p, key, out) // inherit key so list elements pair with it
		}
	case nir.Thru:
		collectValTokens(ex.Inner, key, out)
	}
}

// unquoteLit strips one matching pair of surrounding string-literal delimiters
// (" ' `) so a key/value token reads `algorithms=none`, not `algorithms="none"`.
// Leaves bare literals (booleans, numbers, already-stripped text) untouched.
func unquoteLit(s string) string {
	if len(s) >= 2 {
		q := s[0]
		if (q == '"' || q == '\'' || q == '`') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// nirKind returns a short tag for an expression's NIR shape (Thru unwrapped),
// recorded on Arg slots so adapters can reason about an argument's form.
func nirKind(e nir.Expr) string {
	switch ex := e.(type) {
	case nir.Thru:
		return nirKind(ex.Inner)
	case nir.Format:
		return "Format"
	case nir.Seq:
		return "Seq"
	case nir.Pair:
		// A keyword/hash/struct entry is a collection-shaped arg, like Seq — sinks must
		// treat it as a safe parameterized condition (e.g. Rails where(id: params[:id])),
		// NOT a raw value. Value-matching still sees it via str_args, and taint still
		// flows through eval(Pair)->eval(Value); only arg-slot sink selection is affected.
		return "Seq"
	case nir.Const:
		return "Const"
	case nir.Call:
		return "Call"
	case nir.Name:
		return "Name"
	case nir.Attr:
		return "Attr"
	case nir.Index:
		return "Index"
	case nir.Lambda:
		return "Lambda"
	}
	return ""
}

// recvType returns the inferred type of a receiver node if it was produced by a
// known constructor call (its callee path is in the constructor→type table).
func (l *lowerer) recvType(nodeID string) string {
	if len(l.ctorTypes) == 0 || nodeID == "" {
		return ""
	}
	if n, ok, _ := l.g.GetNode(nodeID); ok {
		return l.ctorTypes[n.Prop("callee_path")]
	}
	return ""
}

func (l *lowerer) evalCall(call nir.Call, sc *scope) string {
	// Each argument SLOT is a distinct program point at the call site (an Arg
	// node), flowing from the argument value. This gives sinks the correct
	// location (the call, not where the value was defined) and lets an adapter
	// label an arg position as a sink even when the value is itself a source —
	// e.g. yaml.load(request_input).
	var args []string
	var valToks []string // literal value tokens for value-matching sinks (`val`/`nval`)
	for _, a := range call.Args {
		av := l.eval(a, sc)
		// Record the argument's NIR kind on the slot, so sink adapters can
		// distinguish a raw-SQL string position (Format/Const/Name/…) from a
		// collection literal (Seq — e.g. Rails `where(id: params[:id])`, which is
		// a safe hash condition, not a raw query).
		an := l.node("Arg", call.Loc, map[string]string{"vkind": nirKind(a)})
		l.flow(av, an)
		args = append(args, an)
		collectValTokens(a, "", &valToks)
	}
	// A bare call to a `from mod import sym` alias is matched by adapters under its
	// resolved dotted path, so imported sinks/sanitizers (e.g. `escape` from
	// `markupsafe.escape`, `system` from `os.system`) are recognized.
	calleePath := call.Path
	if l.resolveImports {
		if nm, ok := call.Callee.(nir.Name); ok {
			if imp, ok := l.importTables[l.curModule][nm.ID]; ok && imp.kind == "sym" {
				calleePath = imp.module + "." + imp.symbol
			}
		}
	}
	props := map[string]string{"callee_path": calleePath, "method": call.Method}
	if len(valToks) > 0 {
		props["str_args"] = strings.Join(valToks, "\x00")
	}
	for i, a := range args { // arg0, arg1, … so sinks can target a non-first arg
		props["arg"+strconv.Itoa(i)] = a
	}
	// resolve the receiver once; if it was assigned from a known constructor,
	// stamp recv_type so type-constrained sink adapters can reason about it.
	var recvNode string
	if attr, ok := call.Callee.(nir.Attr); ok {
		recvNode = l.eval(attr.Base, sc)
		if t := l.recvType(recvNode); t != "" {
			props["recv_type"] = t
		}
	}
	result := l.node("Call", call.Loc, props)
	if recvNode != "" { // receiver taint (chained calls)
		l.flow(recvNode, result)
	}
	for _, a := range args {
		l.flow(a, result)
	}
	for _, target := range l.resolveTargets(call.Callee, sc) {
		for i, a := range args {
			if i < len(target.paramNames) {
				l.flow(a, target.params[target.paramNames[i]])
			}
		}
		l.flow(target.ret, result)
	}
	return result
}

// --- call resolution (shared; docs/10 §"Call resolution") -------------

func (l *lowerer) resolveTargets(callee nir.Expr, sc *scope) []*funcInfo {
	if !l.resolveImports {
		var name string
		switch c := callee.(type) {
		case nir.Attr:
			name = c.Attr
		case nir.Name:
			name = c.ID
		}
		return l.funcShort[name]
	}
	imports := l.importTables[l.curModule]
	switch c := callee.(type) {
	case nir.Name:
		nm := c.ID
		if imp, ok := imports[nm]; ok && imp.kind == "sym" {
			if f := l.funcQual[imp.module+"::"+imp.symbol]; f != nil {
				return []*funcInfo{f}
			}
		}
		if f := l.funcQual[l.curModule+"::"+nm]; f != nil {
			return []*funcInfo{f}
		}
		infos := l.funcShort[nm]
		if len(infos) == 1 { // guarded fallback
			return infos
		}
		return nil
	case nir.Attr:
		// `new T().method()` — receiver is a constructor call; resolve T's method.
		baseExpr := c.Base
		if thru, ok := baseExpr.(nir.Thru); ok {
			baseExpr = thru.Inner
		}
		if call, ok := baseExpr.(nir.Call); ok {
			if t, ok := l.resolveCtor(call.Callee); ok {
				if m := l.funcQual[t[0]+"::"+t[1]+"."+c.Attr]; m != nil {
					return []*funcInfo{m}
				}
			}
			return nil
		}
		base, isName := baseExpr.(nir.Name)
		if !isName {
			return nil
		}
		obj, attr := base.ID, c.Attr
		if imp, ok := imports[obj]; ok && imp.kind == "mod" { // module.func
			if f := l.funcQual[imp.module+"::"+attr]; f != nil {
				return []*funcInfo{f}
			}
		}
		if cm, ok := l.classModule(obj, imports); ok { // Class.method (static)
			if m := l.funcQual[cm+"::"+obj+"."+attr]; m != nil {
				return []*funcInfo{m}
			}
		}
		if typ, ok := sc.typ[obj]; ok { // instance/self method
			if m := l.funcQual[typ[0]+"::"+typ[1]+"."+attr]; m != nil {
				return []*funcInfo{m}
			}
		}
	}
	return nil
}

// classModule returns the module key a class name resolves to (ok=false if it
// is not a known class). "" is a valid module key (e.g. Ruby global namespace).
func (l *lowerer) classModule(name string, imports map[string]importEntry) (string, bool) {
	if l.classQual[l.curModule+"::"+name] {
		return l.curModule, true
	}
	if imp, ok := imports[name]; ok && imp.kind == "sym" && l.classQual[imp.module+"::"+imp.symbol] {
		return imp.module, true
	}
	// Cross-module fallback: a class referenced without an import (e.g. Java
	// same-package classes). Only when EXACTLY ONE module defines that name, to
	// avoid wrongly linking same-named classes in unrelated files.
	if mods := l.classDefs[name]; len(mods) == 1 {
		return mods[0], true
	}
	return "", false
}

// appendUniq appends s to xs if not already present.
func appendUniq(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func (l *lowerer) resolveCtor(callee nir.Expr) ([2]string, bool) {
	imports := l.importTables[l.curModule]
	switch c := callee.(type) {
	case nir.Name:
		if cm, ok := l.classModule(c.ID, imports); ok {
			return [2]string{cm, c.ID}, true
		}
	case nir.Attr:
		if base, ok := c.Base.(nir.Name); ok {
			if imp, ok := imports[base.ID]; ok && imp.kind == "mod" && l.classQual[imp.module+"::"+c.Attr] {
				return [2]string{imp.module, c.Attr}, true
			}
		}
	}
	return [2]string{}, false
}

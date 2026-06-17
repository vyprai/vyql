// Package lowering is the shared, language-AGNOSTIC tier (docs/20): it lowers
// NIR into the shared graph, owning the function/class registries,
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
	paramNames    []string
	params        map[string]string // name -> param node id
	paramTypes    map[string]string // name -> declared/inferred receiver type
	ret           string            // return node id
	module        string
	cls           string
	name          string
	resultEntries []nir.ResultEntry
	abstract      bool   // an interface/abstract method (empty body) — dispatch to concrete impls
	selfNode      string // stable `this` node for a method (alias target for the receiver); "" if none
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
	modCtr         map[string]int // per-module node-id counter (stable, module-local ids)

	funcQual      map[string]*funcInfo         // "modkey::qual" -> info
	funcShort     map[string][]*funcInfo       // short name -> infos
	classQual     map[string]bool              // "modkey::Class"
	classDefs     map[string]map[string]bool   // bare class name -> SET of modules that define it
	classFields   map[string]map[string]string // "modkey::Class" -> field -> declared class type
	importTables  map[string]map[string]importEntry
	moduleGlobals map[string]map[string]string // JS/TS module-level binding name -> stable slot node

	// inheritance-aware implicit-`this` member resolution (populated by frontends that set
	// ClassDef.Members/Bases — currently C#). directMembers: "modkey::Class" -> declared member
	// set; classBaseNames: "modkey::Class" -> base SHORT names; membersOfShort: short class name
	// -> union of declared members (for resolving inherited members by name across files).
	directMembers  map[string]map[string]bool
	classBaseNames map[string][]string
	membersOfShort map[string]map[string]bool
	allMembersMemo map[string]map[string]bool // memoized transitive member set per "modkey::Class"

	curModule     string   // resolution key (may be "" for languages with a flat namespace, e.g. PHP)
	curNS         string   // per-FILE node-id namespace (unique even when curModule is "") — see ModuleNS
	curClass      string   // "" = none
	curDecorators []string // syntax annotations/decorators on the enclosing function

	// B1 structured-CFG metadata. `region` is the current control-region path, namespaced by
	// module key (e.g. "app/utils.go/fn3/loop5"); every node is stamped with it plus a
	// per-module monotonic `order`. For goto-free structured control flow this encodes the
	// dominator tree directly: G dominates S iff region(G) is an ancestor of region(S) and
	// order(G) < order(S) (see solvers.Dominates). order and the branch counter are MODULE-
	// LOCAL (keyed by curModule) and regions are module-namespaced, so a module's CFG metadata
	// is deterministic from its own content alone — the same whether it is lowered in
	// isolation (incremental) or alongside others (full). Pure metadata until a rule reads it.
	region    string
	modOrder  map[string]int
	modBranch map[string]int

	// container element-sensitivity: per-container-node taint of individual constant
	// keys/indices, so `m.put("kB", tainted); m.get("kA")` reads a clean element rather
	// than the whole (over-approximated) container. Keyed by container node id.
	containers map[string]*containerInfo

	// lambdaParams maps a lowered function-value node (a passed callback) to its parameter
	// node ids, so a higher-order call (arr.map(cb), p.then(cb)) can route the receiver's
	// taint into the callback's parameters.
	lambdaParams map[string][]string

	// p1, when non-nil, captures the symbol-table contributions of the module currently being
	// registered (pass 1), so they can be cached and replayed without re-reading the module's
	// NIR. nil on the full (non-incremental) path — zero cost there.
	p1 *pass1Delta
	// parseCache, when set (incremental path), lets bodyOf decode a stub module's full NIR on
	// demand from the parse cache. nil on the full path.
	parseCache DeltaCache
}

type containerInfo struct {
	elems   map[string]string // constant key/index -> element node id holding that slot's taint
	dirty   bool              // a write with a NON-constant key happened (any key may be tainted)
	nextIdx int               // append counter for add()/append()/push()
}

// inRegion lowers f inside a nested control region (then/else/loop/case/handler).
func (l *lowerer) inRegion(seg string, f func()) {
	save := l.region
	l.region = save + "/" + seg
	f()
	l.region = save
}

func (l *lowerer) nextBranch() string {
	l.modBranch[l.curNS]++
	return strconv.Itoa(l.modBranch[l.curNS])
}

// mutatorMethods add a value into their receiver (collection/builder), so the receiver
// inherits the value's taint. Append/write cover StringBuilder/Writer; add/put/push/offer/
// set/insert cover List/Map/Deque/Set.
var mutatorMethods = map[string]bool{
	"append": true, "insert": true, "write": true, "add": true, "addAll": true,
	"addElement": true, "addFirst": true, "addLast": true, "push": true, "offer": true,
	"offerFirst": true, "offerLast": true, "put": true, "putAll": true, "putIfAbsent": true,
	"set": true, "enqueue": true,
	// C#/.NET PascalCase collection mutators (case differs from the lowercase JS/Java/Python
	// names above, so they were unrecognised → C# collections never inherited element taint).
	"Add": true, "AddRange": true, "Insert": true, "InsertRange": true, "Append": true,
	"Push": true, "Enqueue": true, "TryAdd": true, "AddFirst": true, "AddLast": true,
	"AddParameter": true, "AddOrUpdateParameter": true, "Set": true,
	// __setitem__ models a subscript store `container[k] = v` (frontends lower it to this
	// synthetic call) so the container inherits the stored value's taint.
	"__setitem__": true,
}

// keyedMutators map a key/value position: `m.put(key, val)` / `list.set(i, val)`.
var keyedMutators = map[string]bool{"put": true, "putIfAbsent": true, "set": true}

// elementCallbackMethods invoke their callback with a value derived from the receiver
// (array element / resolved promise value), so the receiver's taint flows into the
// callback's first parameter.
var elementCallbackMethods = map[string]bool{
	"forEach": true, "map": true, "filter": true, "find": true, "findIndex": true,
	"some": true, "every": true, "flatMap": true, "then": true, "catch": true, "finally": true,
	// C#/.NET LINQ (and ForEach) invoke their lambda with each element of the receiver, so
	// route the receiver's (element) taint into the lambda's first param.
	"Select": true, "SelectMany": true, "Where": true, "ForEach": true, "GroupBy": true,
	"OrderBy": true, "OrderByDescending": true, "ThenBy": true, "First": true, "FirstOrDefault": true,
	"Single": true, "SingleOrDefault": true, "Last": true, "LastOrDefault": true, "Any": true,
	"All": true, "Count": true, "TakeWhile": true, "SkipWhile": true, "Aggregate": true,
	"DistinctBy": true, "MaxBy": true, "MinBy": true, "ToDictionary": true, "ToLookup": true,
}

// selfPassingMethods invoke their lambda WITH THE RECEIVER as the argument (C# fluent helpers
// `obj.With/Also/Tap(x => …)`, Kotlin scope functions `apply/also/let/run`), so the lambda's
// first parameter aliases the receiver.
var selfPassingMethods = map[string]bool{
	"With": true, "Also": true, "Apply": true, "Tap": true, "Let": true, "Pipe": true,
	"also": true, "apply": true, "let": true, "run": true, "with": true,
}

// appendMutators add at the next sequence index: `list.add(val)` / `sb.append(val)`.
var appendMutators = map[string]bool{
	"add": true, "append": true, "push": true, "offer": true, "offerFirst": true,
	"offerLast": true, "addFirst": true, "addLast": true, "addElement": true, "enqueue": true,
	// C#/.NET PascalCase single-element appenders.
	"Add": true, "Append": true, "Push": true, "Enqueue": true, "AddFirst": true,
	"AddLast": true, "AddParameter": true, "AddOrUpdateParameter": true,
}

// containerInvalidate handles a container method that may shift/invalidate element slots.
// It models precisely ONLY unambiguous by-index removals on a clean (non-dirty) container —
// `pop(constInt)` (Python, by index) and a Java/C#-receiver `remove(constInt)` (List.remove
// by index; Python's remove is by-value, so it's excluded by language) — and `clear()`.
// Everything else (by-value remove, sort/reverse, dynamic index, …) marks the container
// dirty, so later keyed reads fall back to the whole container. Never produces a false negative.
func (l *lowerer) containerInvalidate(call nir.Call, recv string, sc *scope) {
	ci := l.containers[recv]
	if ci == nil || ci.dirty {
		return
	}
	ext := ""
	if n, ok, _ := l.g.GetNode(recv); ok {
		loc := n.Prop("loc")
		if i := strings.LastIndexByte(loc, ':'); i >= 0 {
			loc = loc[:i]
		}
		if i := strings.LastIndexByte(loc, '.'); i >= 0 {
			ext = loc[i:]
		}
	}
	pyRemoveByValue := ext == ".py" // Python list.remove(x) removes by VALUE, not index
	switch {
	case call.Method == "clear":
		ci.elems = map[string]string{}
		ci.nextIdx = 0
	case call.Method == "pop" && len(call.Args) == 1: // list.pop(i) — by index (Python)
		if idx, ok := l.constInt(call.Args[0], sc); ok {
			l.shiftDown(ci, int(idx))
			return
		}
		ci.dirty = true
	case call.Method == "remove" && len(call.Args) == 1 && !pyRemoveByValue: // List.remove(int) — by index
		if idx, ok := l.constInt(call.Args[0], sc); ok {
			l.shiftDown(ci, int(idx))
			return
		}
		ci.dirty = true
	default:
		ci.dirty = true
	}
}

// shiftDown removes element slot `removed` and shifts every higher integer index down by one
// (non-integer keys — map entries — are untouched), mirroring List.remove(i)/pop(i).
func (l *lowerer) shiftDown(ci *containerInfo, removed int) {
	ne := make(map[string]string, len(ci.elems))
	for k, v := range ci.elems {
		idx, err := strconv.Atoi(k)
		if err != nil {
			ne[k] = v // non-integer (map) key — unaffected
			continue
		}
		switch {
		case idx < removed:
			ne[k] = v
		case idx == removed: // dropped
		default:
			ne[strconv.Itoa(idx-1)] = v
		}
	}
	ci.elems = ne
	if ci.nextIdx > removed {
		ci.nextIdx--
	}
}

// modeledContainerMethod reports whether the lowering precisely tracks a container method's
// effect on its element slots. Any OTHER method on a tracked container (remove/insert/sort/
// clear/pop/… — anything that may shift or invalidate keys/indices) marks it dirty so later
// keyed reads conservatively fall back to the whole container (sound — never a false negative).
func modeledContainerMethod(m string) bool {
	return m == "get" || m == "__setitem__" || keyedMutators[m] || appendMutators[m]
}

// cinfo returns (creating if needed) the element-taint record for a container node.
func (l *lowerer) cinfo(node string) *containerInfo {
	ci := l.containers[node]
	if ci == nil {
		ci = &containerInfo{elems: map[string]string{}}
		l.containers[node] = ci
	}
	return ci
}

// elemNode returns the synthetic node holding container[key]'s taint (created on first use).
func (l *lowerer) elemNode(container, key, loc string) string {
	ci := l.cinfo(container)
	if id := ci.elems[key]; id != "" {
		return id
	}
	id := l.node("Elem", loc, nil)
	ci.elems[key] = id
	return id
}

// constKey resolves a subscript/argument expression to a constant key string (a string or
// integer literal, or a const-propagated variable), used to disambiguate container slots.
func (l *lowerer) constKey(e nir.Expr, sc *scope) (string, bool) {
	switch v := e.(type) {
	case nir.Const:
		if s := unquoteLit(v.Value); s != "" {
			return s, true
		}
	case nir.Name:
		if cv := sc.cnst[v.ID]; cv != "" {
			return cv, true
		}
	}
	return "", false
}

// constInt evaluates an integer-constant expression (literals, const-propagated int vars,
// and integer arithmetic), returning ok=false if any operand isn't a compile-time integer.
// Used to fold opaque branch conditions; integer division/modulo use Go (== Java/C) truncation.
func (l *lowerer) constInt(e nir.Expr, sc *scope) (int64, bool) {
	parse := func(s string) (int64, bool) {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		return n, err == nil
	}
	switch v := e.(type) {
	case nir.Const:
		return parse(v.Value)
	case nir.Name:
		if cv := sc.cnst[v.ID]; cv != "" {
			return parse(cv)
		}
	case nir.Thru:
		return l.constInt(v.Inner, sc)
	case nir.BinOp:
		a, ok1 := l.constInt(v.Left, sc)
		b, ok2 := l.constInt(v.Right, sc)
		if !ok1 || !ok2 {
			return 0, false
		}
		switch v.Op {
		case "+":
			return a + b, true
		case "-":
			return a - b, true
		case "*":
			return a * b, true
		case "/":
			if b != 0 {
				return a / b, true
			}
		case "%":
			if b != 0 {
				return a % b, true
			}
		}
	case nir.Format:
		// `a + b` lowers to Format (concat-or-arithmetic); integer addition when both sides
		// are integer constants (a string concat fails constInt on its parts and is ignored).
		if len(v.Parts) == 2 {
			if a, ok1 := l.constInt(v.Parts[0], sc); ok1 {
				if b, ok2 := l.constInt(v.Parts[1], sc); ok2 {
					return a + b, true
				}
			}
		}
	}
	return 0, false
}

// constStrVal evaluates a string/char-valued constant expression — a literal, a
// const-propagated variable, or `s.charAt(i)` on a constant string — used to fold a
// switch subject so the matching case can be selected. Returns ok=false otherwise.
func (l *lowerer) constStrVal(e nir.Expr, sc *scope) (string, bool) {
	switch v := e.(type) {
	case nir.Const:
		s := unquoteLit(v.Value)
		return s, s != ""
	case nir.Name:
		if cv := sc.cnst[v.ID]; cv != "" {
			return cv, true
		}
	case nir.Thru:
		return l.constStrVal(v.Inner, sc)
	case nir.Index:
		if base, ok := l.constStrVal(v.Base, sc); ok { // s[i] on a constant string
			if idx, ok := l.constInt(v.Key, sc); ok && idx >= 0 && int(idx) < len(base) {
				return string(base[idx]), true
			}
		}
		// array-literal index: ['sha1'][0]  → the i-th element if constant.
		if seq, ok := l.seqOf(v.Base); ok {
			if idx, ok := l.constInt(v.Key, sc); ok && idx >= 0 && int(idx) < len(seq) {
				return l.constStrVal(seq[idx], sc)
			}
		}
	case nir.Attr:
		// object-literal property: { name: 'md5' }.name  → the matching pair's value.
		if seq, ok := l.seqOf(v.Base); ok {
			for _, p := range seq {
				if pr, ok := p.(nir.Pair); ok && pr.Key == v.Attr {
					return l.constStrVal(pr.Value, sc)
				}
			}
		}
	case nir.Call:
		if v.Method == "charAt" && len(v.Args) == 1 {
			if attr, ok := v.Callee.(nir.Attr); ok {
				if base, ok := l.constStrVal(attr.Base, sc); ok {
					if idx, ok := l.constInt(v.Args[0], sc); ok && idx >= 0 && int(idx) < len(base) {
						return string(base[idx]), true
					}
				}
			}
		}
	}
	return "", false
}

// constBool evaluates a boolean-constant expression (comparisons of integer/string
// constants, !/&&/||, and true/false). Returns ok=false when not compile-time constant —
// the caller then keeps both branches (sound, never prunes a live branch).
// seqOf returns the elements of an array/object literal expression (peeling Thru).
func (l *lowerer) seqOf(e nir.Expr) ([]nir.Expr, bool) {
	switch v := e.(type) {
	case nir.Seq:
		return v.Parts, true
	case nir.Thru:
		return l.seqOf(v.Inner)
	}
	return nil, false
}

func (l *lowerer) constBool(e nir.Expr, sc *scope) (bool, bool) {
	switch v := e.(type) {
	case nir.Thru:
		return l.constBool(v.Inner, sc)
	case nir.Const:
		switch v.Value {
		case "true", "True":
			return true, true
		case "false", "False":
			return false, true
		}
	case nir.Name:
		switch sc.cnst[v.ID] {
		case "true", "True":
			return true, true
		case "false", "False":
			return false, true
		}
	case nir.Unary:
		if v.Op == "!" || v.Op == "not" {
			if b, ok := l.constBool(v.Operand, sc); ok {
				return !b, true
			}
		}
	case nir.BinOp:
		switch v.Op {
		case "&&", "and":
			if a, ok1 := l.constBool(v.Left, sc); ok1 {
				if b, ok2 := l.constBool(v.Right, sc); ok2 {
					return a && b, true
				}
			}
		case "||", "or":
			if a, ok1 := l.constBool(v.Left, sc); ok1 {
				if b, ok2 := l.constBool(v.Right, sc); ok2 {
					return a || b, true
				}
			}
		case ">", "<", ">=", "<=", "==", "!=":
			if a, ok1 := l.constInt(v.Left, sc); ok1 {
				if b, ok2 := l.constInt(v.Right, sc); ok2 {
					switch v.Op {
					case ">":
						return a > b, true
					case "<":
						return a < b, true
					case ">=":
						return a >= b, true
					case "<=":
						return a <= b, true
					case "==":
						return a == b, true
					case "!=":
						return a != b, true
					}
				}
			}
			if v.Op == "==" || v.Op == "!=" { // string/char constant equality
				if sa, oka := l.constKey(v.Left, sc); oka {
					if sb, okb := l.constKey(v.Right, sc); okb {
						eq := sa == sb
						if v.Op == "!=" {
							eq = !eq
						}
						return eq, true
					}
				}
			}
		}
	}
	return false, false
}

// containerRead resolves an element-sensitive read of recv[key] into result. Returns false
// when it can't (non-constant key, or recv was never written as a container) so the caller
// falls back to the conservative whole-container flow. A constant key that was never written
// (and no dynamic write happened) reads CLEAN — this is the precision win.
func (l *lowerer) containerRead(recv, result string, keyExpr nir.Expr, sc *scope) bool {
	ci := l.containers[recv]
	if ci == nil {
		return false
	}
	key, ok := l.constKey(keyExpr, sc)
	if !ok {
		return false // dynamic key — any slot could be read
	}
	switch {
	case ci.dirty:
		// a shift/invalidating op happened — slot taint is unreliable, read the whole
		// container (sound) even if a stale element node still exists for this key.
		l.flow(recv, result)
	case ci.elems[key] != "":
		l.flow(ci.elems[key], result)
	}
	// neither dirty nor a known tainted slot → clean (the precision win)
	return true
}

// containerWrite records an element-sensitive write into recv and keeps the whole container
// tainted (for whole-container reads / dynamic-key gets). Recognised keyed/append mutators
// taint a specific slot; any other mutator marks the container dirty (unknown slot).
func (l *lowerer) containerWrite(call nir.Call, args []string, recv string, sc *scope) {
	switch {
	case keyedMutators[call.Method] && len(args) == 2:
		// map.put(key, val) / list.set(i, val) — EXACTLY two args. Other arities (e.g.
		// configparser.set(section, key, val)) fall through to the sound default.
		l.flow(args[1], recv)
		if key, ok := l.constKey(call.Args[0], sc); ok {
			l.flow(args[1], l.elemNode(recv, key, call.Loc))
		} else {
			l.cinfo(recv).dirty = true
		}
	case call.Method == "__setitem__" && len(args) >= 1:
		// synthetic subscript store, args = [value, key]
		l.flow(args[0], recv)
		if len(call.Args) >= 2 {
			if key, ok := l.constKey(call.Args[1], sc); ok {
				l.flow(args[0], l.elemNode(recv, key, call.Loc))
				return
			}
		}
		l.cinfo(recv).dirty = true
	case appendMutators[call.Method] && len(args) == 1:
		// list.add(val) / sb.append(val) — EXACTLY one arg (a 2-arg add(i, e) is an insert
		// that shifts indices, handled by the sound default below).
		l.flow(args[0], recv)
		ci := l.cinfo(recv)
		l.flow(args[0], l.elemNode(recv, strconv.Itoa(ci.nextIdx), call.Loc))
		ci.nextIdx++
	default:
		// bulk / wrong-arity / unknown mutator (putAll/addAll/insert/configparser.set/…):
		// every arg taints the container and any constant slot may now be tainted — mark
		// dirty so later keyed reads fall back to the whole container (sound, never an FN).
		for _, a := range args {
			l.flow(a, recv)
		}
		l.cinfo(recv).dirty = true
	}
}

// constStr returns the string value of a literal expression (unquoted), or "".
func constStr(e nir.Expr) string {
	if c, ok := e.(nir.Const); ok {
		return unquoteLit(c.Value)
	}
	return ""
}

// propConst const-folds a config-property read — `props.getProperty("key" [, default])` —
// to the bundled property value (or the literal default when the key is unset). Only
// `getProperty` is resolved: user-input readers (getParameter/getHeader/…) must stay
// tainted sources, never folded to constants. Returns ("", false) when undeterminable.
func (l *lowerer) propConst(e nir.Expr) (string, bool) {
	call, ok := e.(nir.Call)
	if !ok || call.Method != "getProperty" || len(call.Args) == 0 {
		return "", false
	}
	key := constStr(call.Args[0])
	if key == "" {
		return "", false
	}
	if v, ok := l.prog.Properties[key]; ok {
		return v, true
	}
	if len(call.Args) >= 2 { // fall back to the inline default argument, if literal
		if d := constStr(call.Args[1]); d != "" {
			return d, true
		}
	}
	return "", false
}

func cloneStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mergeBindings reconciles variable bindings after branches (flow-sensitive JOIN): a
// variable reassigned in any branch becomes a Phi flowing from every branch's value AND the
// pre-branch value (a branch may not execute). A variable tainted on ANY path therefore
// stays tainted past the join — last-write-wins, which silently dropped taint from a sibling
// branch, is gone. Straight-line reassignment (e.g. x = sanitize(x)) is NOT a branch and is
// unaffected, so sanitizers still work.
func (l *lowerer) mergeBindings(sc *scope, before map[string]string, branches []map[string]string) {
	changed := map[string]bool{}
	for _, br := range branches {
		for v, n := range br {
			if before[v] != n {
				changed[v] = true
			}
		}
	}
	for v := range changed {
		phi := l.node("Phi", "?:0", nil)
		srcs := map[string]bool{}
		for _, br := range branches {
			val := br[v]
			if val == "" {
				val = before[v]
			}
			if val != "" {
				srcs[val] = true
			}
		}
		if before[v] != "" {
			srcs[before[v]] = true // the branch(es) may not run — keep the pre-branch value
		}
		for s := range srcs {
			l.flow(s, phi)
		}
		sc.node[v] = phi
		delete(sc.cnst, v) // a merged value is no longer a known constant
	}
}

// scope holds variable -> node bindings and variable -> (module, class) types.
type scope struct {
	node map[string]string
	typ  map[string][2]string
	cnst map[string]string // variable -> its string-constant value (lightweight const-prop)
}

func newScope() *scope {
	return &scope{node: map[string]string{}, typ: map[string][2]string{}, cnst: map[string]string{}}
}

func (s *scope) clone() *scope {
	c := newScope()
	for k, v := range s.node {
		c.node[k] = v
	}
	for k, v := range s.typ {
		c.typ[k] = v
	}
	for k, v := range s.cnst {
		c.cnst[k] = v
	}
	return c
}

type analysisEventSpec struct {
	path   string
	method string
}

var (
	analysisFunctionReturn = analysisEventSpec{path: "analysis.function.return", method: "return"}
	analysisFunctionResult = analysisEventSpec{path: "analysis.function.result", method: "result"}
	analysisParameterEntry = analysisEventSpec{path: "analysis.parameter.entry", method: "entry"}
)

func (l *lowerer) functionReturnAnalysisEvent(id, loc string, contextTokens []string) {
	if id == "" || len(contextTokens) == 0 {
		return
	}
	// Lowering records only structural return evidence. Adapter data decides whether
	// the event has any domain meaning.
	valToks := append([]string{}, contextTokens...)
	n, ok, _ := l.g.GetNode(id)
	if ok {
		if loc == "" {
			loc = n.Loc
		}
		if path := n.Prop("callee_path"); path != "" {
			valToks = append(valToks, path)
			if last := lastPathSegment(path); last != "" && last != path {
				valToks = append(valToks, last)
			}
		}
		if method := n.Prop("method"); method != "" {
			valToks = append(valToks, method)
		}
	}
	if loc == "" {
		loc = "?:0"
	}
	arg := l.node("Arg", loc, map[string]string{"vkind": "Return"})
	l.flow(id, arg)
	props := map[string]string{
		"callee_path": analysisFunctionReturn.path,
		"method":      analysisFunctionReturn.method,
		"arg0":        arg,
	}
	if len(valToks) > 0 {
		props["str_args"] = strings.Join(valToks, "\x00")
	}
	call := l.node("Call", loc, props)
	l.flow(arg, call)
}

func (l *lowerer) parameterEntry(paramNode, loc string, tokens []string) {
	if paramNode == "" || len(tokens) == 0 {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	props := map[string]string{
		"callee_path": analysisParameterEntry.path,
		"method":      analysisParameterEntry.method,
		"str_args":    strings.Join(tokens, "\x00"),
	}
	call := l.node("Call", loc, props)
	l.flow(call, paramNode)
}

func (l *lowerer) syntheticCall(path, method, id, loc string, valToks ...string) string {
	if id == "" {
		return ""
	}
	n, ok, _ := l.g.GetNode(id)
	if ok && loc == "" {
		loc = n.Loc
	}
	if loc == "" {
		loc = "?:0"
	}
	arg := l.node("Arg", loc, map[string]string{"vkind": "Analysis"})
	l.flow(id, arg)
	props := map[string]string{
		"callee_path": path,
		"method":      method,
		"arg0":        arg,
	}
	if len(valToks) > 0 {
		props["str_args"] = strings.Join(valToks, "\x00")
	}
	call := l.node("Call", loc, props)
	l.flow(arg, call)
	return call
}

func (l *lowerer) guardObservation(path, method, observed, loc string, valToks ...string) string {
	if observed == "" {
		return ""
	}
	n, ok, _ := l.g.GetNode(observed)
	if ok && loc == "" {
		loc = n.Loc
	}
	if loc == "" {
		loc = "?:0"
	}
	props := map[string]string{"callee_path": path, "method": method}
	if len(valToks) > 0 {
		props["str_args"] = strings.Join(valToks, "\x00")
	}
	call := l.node("Call", loc, props)
	l.flow(observed, call)
	in, _ := l.g.InEdges(observed, "FLOWS")
	for _, ed := range in {
		l.flow(ed.Src, call)
	}
	return call
}

func lastPathSegment(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 || i == len(path)-1 {
		return path
	}
	return path[i+1:]
}

func isPathResolveParents(expr nir.Expr) bool {
	attr, ok := expr.(nir.Attr)
	if !ok || attr.Attr != "parents" {
		return false
	}
	return strings.HasSuffix(attr.Path, ".resolve.parents")
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
	l := newLowerer(prog, resolveImports, ctorTypes)
	if err := l.run(); err != nil {
		return nil, err
	}
	return l.g, nil
}

// newLowerer builds a fresh lowerer with all maps initialised. Shared by LowerTyped and the
// incremental lowerer.
func newLowerer(prog nir.Program, resolveImports bool, ctorTypes map[string]string) *lowerer {
	return &lowerer{
		prog:           prog,
		selfName:       prog.Self(),
		resolveImports: resolveImports,
		ctorTypes:      ctorTypes,
		g:              newGraphStore(0),
		modCtr:         map[string]int{},
		modOrder:       map[string]int{},
		modBranch:      map[string]int{},
		funcQual:       map[string]*funcInfo{},
		funcShort:      map[string][]*funcInfo{},
		classQual:      map[string]bool{},
		classDefs:      map[string]map[string]bool{},
		classFields:    map[string]map[string]string{},
		importTables:   map[string]map[string]importEntry{},
		moduleGlobals:  map[string]map[string]string{},
		containers:     map[string]*containerInfo{},
		lambdaParams:   map[string][]string{},
		directMembers:  map[string]map[string]bool{},
		classBaseNames: map[string][]string{},
		membersOfShort: map[string]map[string]bool{},
		allMembersMemo: map[string]map[string]bool{},
	}
}

// --- graph helpers ------------------------------------------------------

// nid mints a node id that is STABLE per module: a module-local counter, namespaced by the
// module key. So a node's id depends only on its own module's content and processing order,
// not on global cross-module ordering — the prerequisite for reusing an unchanged module's
// lowered sub-graph (incremental dataflow). Distinct module keys can never collide.
func (l *lowerer) nid(prefix string) string {
	l.modCtr[l.curNS]++
	return l.curNS + "\x1f" + prefix + "#" + strconv.Itoa(l.modCtr[l.curNS])
}

// ModuleNS is a module's per-FILE node-id namespace: the file path (unique per file) so node
// ids stay file-local and stable even for languages whose resolution Key is "" (PHP, Ruby,
// …). Cross-module references use the resolution Key; node ids use this.
func ModuleNS(m nir.Module) string {
	if m.File != "" {
		return m.File
	}
	return m.Key
}

func (l *lowerer) node(kind, loc string, props map[string]string) string {
	return l.nodeWithID(l.nid(kind), kind, loc, props)
}

// nodeWithID creates a node with an explicit id — used for signature nodes (Param/Return)
// whose ids are NAME-derived (sigID) so they survive a body edit and remain valid targets for
// cross-module call edges from other (possibly cached) modules.
func (l *lowerer) nodeWithID(id, kind, loc string, props map[string]string) string {
	ord := l.modOrder[l.curNS]
	l.modOrder[l.curNS]++
	// loc/region/order live inline on the Node; props (the freshly-built extras map, often empty)
	// becomes Props directly — nil/empty when there are no extras, so most nodes carry no map.
	var extras map[string]string
	if len(props) > 0 {
		extras = props
	}
	l.g.AddNode(usg.Node{ID: id, Type: "code." + kind, Loc: loc, Region: l.region,
		Order: int32(ord), HasOrder: true, Props: extras})
	return id
}

// sigID is the stable, name-derived id of a function's signature node (a Param or Return).
// Independent of the function body and of other modules, so cross-module references to it
// stay valid when the body changes or another module is reused from cache.
func sigID(modkey, qual, kind, name string) string {
	return modkey + "\x1f" + qual + "#" + kind + "#" + name
}

func (l *lowerer) flow(a, b string) {
	if a == "" || b == "" {
		return
	}
	if !l.exists(a) || !l.exists(b) {
		return
	}
	l.g.AddEdge(usg.Edge{Type: "FLOWS", Src: a, Dst: b})
}

// exists is an existence-only check; on a disk-backed store it uses Has (no detail decode) so the
// build never reads node payload back from disk.
func (l *lowerer) exists(id string) bool {
	if h, ok := l.g.(interface{ Has(string) bool }); ok {
		return h.Has(id)
	}
	_, ok, _ := l.g.GetNode(id)
	return ok
}

// --- entry --------------------------------------------------------------

func (l *lowerer) run() error {
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		l.importTables[m.Key] = importTable(m)
		for _, imp := range m.Imports {
			l.importNode(m, imp)
		}
		l.register(m.Key, m.Body, "")
	}
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		l.block(m.Body, l.moduleScope(m))
	}
	return nil
}

func (l *lowerer) moduleScope(m nir.Module) *scope {
	sc := newScope()
	if !isJSLikeModule(m.File) {
		return sc
	}
	globals := l.moduleGlobals[ModuleNS(m)]
	if globals == nil {
		globals = map[string]string{}
		l.moduleGlobals[ModuleNS(m)] = globals
	}
	for _, name := range topLevelAssignedNames(m.Body) {
		slot := globals[name]
		if slot == "" {
			slot = l.nodeWithID(sigID(l.curNS, "__module", "var", name), "Name", m.File,
				map[string]string{"callee_path": name, "method": name, "module_global": "true"})
			globals[name] = slot
		}
		sc.node[name] = slot
	}
	return sc
}

func isJSLikeModule(file string) bool {
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} {
		if strings.HasSuffix(file, ext) {
			return true
		}
	}
	return false
}

func topLevelAssignedNames(stmts []nir.Stmt) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range stmts {
		a, ok := s.(nir.Assign)
		if !ok {
			continue
		}
		for _, t := range a.Targets {
			if t == "" || strings.ContainsAny(t, ".[") || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func (l *lowerer) moduleGlobalSlot(name string) string {
	if globals := l.moduleGlobals[l.curNS]; globals != nil {
		return globals[name]
	}
	return ""
}

func (l *lowerer) importNode(m nir.Module, imp nir.Import) {
	props := map[string]string{
		"local":   imp.Local,
		"module":  imp.Module,
		"package": importPackageRoot(imp.Module),
	}
	if imp.Symbol != "" {
		props["symbol"] = imp.Symbol
	}
	if imp.IsModule {
		props["is_module"] = "true"
	} else {
		props["is_module"] = "false"
	}
	l.node("Import", m.File, props)
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

func importPackageRoot(module string) string {
	module = strings.TrimSpace(module)
	if module == "" {
		return ""
	}
	if strings.HasPrefix(module, "@") {
		parts := strings.Split(module, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	if i := strings.IndexByte(module, '/'); i > 0 {
		return module[:i]
	}
	return module
}

// makeFuncInfo creates a function's signature nodes (Param/Return) with stable, name-derived
// ids and returns its funcInfo. Shared by pass-1 registration and the pass-2 nested-function
// fallback so both mint identical, body-independent signature ids — the anchor cross-module
// call edges (and reused modules) point at.
func (l *lowerer) makeFuncInfo(modkey, cls string, st nir.FuncDef) *funcInfo {
	prefix := ""
	if cls != "" {
		prefix = cls + "."
	}
	rel := prefix + st.Name // module-relative qualified name
	// signature node ids use the per-FILE namespace (curNS), so they are file-local and stable
	// even when the resolution key (modkey) is shared ("") across files.
	ns := l.curNS
	params := map[string]string{}
	order := make([]string, 0, len(st.Params))
	for _, p := range st.Params {
		props := map[string]string{"name": p, "func": st.Name}
		if typ := st.ParamTypes[p]; typ != "" {
			props["decl_type"] = typ
		}
		if st.Exported {
			// public-API parameter: a library entry point (see ParamSourceAdapter).
			props["exported"] = "true"
		}
		params[p] = l.nodeWithID(sigID(ns, rel, "param", p), "Param", st.Loc, props)
		order = append(order, p)
	}
	fi := &funcInfo{
		paramNames: order,
		params:     params,
		paramTypes: st.ParamTypes,
		ret:        l.nodeWithID(sigID(ns, rel, "ret", ""), "Return", st.Loc, map[string]string{"func": st.Name}),
		module:     modkey, cls: cls, name: st.Name,
		resultEntries: st.ResultEntries,
		// an empty body marks an interface/abstract method: a call typed to it must dispatch
		// to the concrete implementations (whose bodies carry the taint).
		abstract: len(st.Body) == 0,
	}
	// A method (no explicit self param[0]) gets a STABLE `this` node, so the receiver at every
	// call site can be ALIASED to it (field mutations via this reach the receiver object —
	// object-sensitivity for fluent/builder mutators). Languages with an explicit self param
	// (Python/Go) keep param[0]; this is the C#-style implicit-this case.
	if cls != "" && (len(order) == 0 || order[0] != l.selfName) {
		fi.selfNode = l.nodeWithID(sigID(ns, rel, "self", ""), "Param", st.Loc, map[string]string{"name": "this", "func": st.Name})
	}
	return fi
}

// --- pass 1: registration ----------------------------------------------

// aliasReceiverSelf makes a method's stable `this` node share the receiver's container info, so
// a field mutation via `this` inside the method (this.X = …) reaches the RECEIVER object the
// method was called on, and vice versa (object-sensitivity for fluent/builder mutators like
// `req.AddParameter(p) => this.With(x => x.Parameters.Add(p))`). Merge-and-repoint, so it is
// independent of whether the call site or the callee body is lowered first.
func (l *lowerer) aliasReceiverSelf(recv, self string) {
	if recv == "" || self == "" {
		return
	}
	rc := l.cinfo(recv)
	if sc := l.containers[self]; sc != nil && sc != rc {
		for k, slot := range sc.elems {
			if slot == "" {
				continue
			}
			if rc.elems[k] == "" {
				rc.elems[k] = slot
			} else if rc.elems[k] != slot {
				l.flow(slot, rc.elems[k])
				l.flow(rc.elems[k], slot)
			}
		}
		if sc.dirty {
			rc.dirty = true
		}
	}
	l.containers[self] = rc // future this.X / recv.X accesses share the same slots
}

// classMemberSet returns the transitive data-member names of "modkey::Class": its declared
// members plus those inherited from base classes (resolved by short name across files, so an
// inherited property like RequestHeaders' `Parameters` from ParametersCollection<T> is included).
// Memoized; cycle-safe.
func (l *lowerer) classMemberSet(modkey, class string) map[string]bool {
	qual := modkey + "::" + class
	if m, ok := l.allMembersMemo[qual]; ok {
		return m
	}
	out := map[string]bool{}
	l.allMembersMemo[qual] = out // mark in-progress (cycle guard)
	for m := range l.directMembers[qual] {
		out[m] = true
	}
	for _, base := range l.classBaseNames[qual] {
		// resolve the base by short name: union the declared members of every class with that
		// name, and recurse through that class's own bases where it is defined.
		for m := range l.membersOfShort[base] {
			out[m] = true
		}
		for bq := range l.directMembers {
			if strings.HasSuffix(bq, "::"+base) {
				bmod := strings.TrimSuffix(bq, "::"+base)
				for m := range l.classMemberSet(bmod, base) {
					out[m] = true
				}
			}
		}
	}
	return out
}

func (l *lowerer) register(modkey string, stmts []nir.Stmt, cls string) {
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.ClassDef:
			l.classQual[modkey+"::"+st.Name] = true
			if l.classDefs[st.Name] == nil {
				l.classDefs[st.Name] = map[string]bool{}
			}
			l.classDefs[st.Name][modkey] = true
			if l.p1 != nil {
				l.p1.ClassQual = append(l.p1.ClassQual, modkey+"::"+st.Name)
				l.p1.ClassDefs = append(l.p1.ClassDefs, st.Name)
			}
			// inheritance-aware implicit-this: record declared members (by qual + by short name)
			// and base names, so a bare member ref in a method resolves to `this.<member>`.
			if len(st.Members) > 0 {
				qual := modkey + "::" + st.Name
				if l.directMembers[qual] == nil {
					l.directMembers[qual] = map[string]bool{}
				}
				if l.membersOfShort[st.Name] == nil {
					l.membersOfShort[st.Name] = map[string]bool{}
				}
				for _, m := range st.Members {
					l.directMembers[qual][m] = true
					l.membersOfShort[st.Name][m] = true
				}
			}
			if len(st.Bases) > 0 {
				l.classBaseNames[modkey+"::"+st.Name] = st.Bases
			}
			// record field -> declared class type (for cross-file method resolution
			// on field receivers, e.g. Spring `@Autowired UserService svc; svc.m()`).
			for _, bs := range st.Body {
				if a, ok := bs.(nir.Assign); ok && a.Type != "" && len(a.Targets) == 1 {
					if l.classFields[modkey+"::"+st.Name] == nil {
						l.classFields[modkey+"::"+st.Name] = map[string]string{}
					}
					l.classFields[modkey+"::"+st.Name][a.Targets[0]] = a.Type
					if l.p1 != nil {
						l.p1.ClassFields = append(l.p1.ClassFields, cfGob{modkey + "::" + st.Name, a.Targets[0], a.Type})
					}
				}
			}
			l.register(modkey, st.Body, st.Name)
		case nir.FuncDef:
			prefix := ""
			if cls != "" {
				prefix = cls + "."
			}
			qual := modkey + "::" + prefix + st.Name
			info := l.makeFuncInfo(modkey, cls, st)
			l.funcQual[qual] = info
			l.funcShort[st.Name] = append(l.funcShort[st.Name], info)
			if l.p1 != nil {
				l.p1.Funcs = append(l.p1.Funcs, fiGob{
					Qual: qual, Short: st.Name, ParamNames: info.paramNames, Params: info.params,
					ParamTypes: info.paramTypes, Ret: info.ret, Module: info.module, Cls: info.cls,
					Name: info.name, ResultEntries: info.resultEntries, Abstract: info.abstract,
				})
			}
			// recurse into the body to register NESTED LOCAL FUNCTIONS (C# local functions, JS
			// inner function declarations) so a FORWARD reference — `coll.ForEach(x => Helper(x));
			// … void Helper(...) {}` (RestSharp AddHeaders) — resolves regardless of declaration order.
			l.register(modkey, st.Body, cls)
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
		if info == nil {
			info = l.makeFuncInfo(l.curModule, l.curClass, st)
			l.funcQual[qual] = info
			l.funcShort[st.Name] = append(l.funcShort[st.Name], info)
		}
		// closure capture: a nested function sees the enclosing scope's bindings, so a free
		// variable's taint flows into the body. Params are reseeded below, shadowing.
		inner := sc.clone()
		if info != nil {
			for name, id := range info.params {
				inner.node[name] = id
				if typ := info.paramTypes[name]; typ != "" {
					if cm, ok := l.classModule(typ, l.importTables[l.curModule]); ok {
						inner.typ[name] = [2]string{cm, typ}
					}
				}
			}
			inner.node["__ret__"] = info.ret
		}
		if info != nil {
			for _, pe := range st.ParamEntries {
				if paramNode := info.params[pe.Param]; paramNode != "" {
					l.parameterEntry(paramNode, st.Loc, pe.Tokens)
				}
			}
		}
		if l.curClass != "" && len(st.Params) > 0 && st.Params[0] == l.selfName {
			inner.typ[l.selfName] = [2]string{l.curModule, l.curClass}
		}
		// languages with no explicit self param (C#) still need a STABLE `this` node per method
		// so `this.Field` writes/reads — and inheritance-aware implicit-`this` member refs —
		// connect within the method and escape via `return this`. Synthesize one when the class
		// has known members (i.e. the frontend opted into member resolution).
		// implicit-this is C#-gated (only C# populates ClassDef.Members); C#'s self keyword is
		// "this" (the merged multi-language Program loses per-language SelfName), so key on "this".
		// Use the STABLE funcInfo.selfNode so call sites can alias the receiver to it.
		if l.curClass != "" && inner.node["this"] == "" && info != nil && info.selfNode != "" &&
			len(l.classMemberSet(l.curModule, l.curClass)) > 0 {
			inner.node["this"] = info.selfNode
			inner.typ["this"] = [2]string{l.curModule, l.curClass}
		}
		// seed enclosing-class field receivers so `field.method()` resolves
		for fld, typ := range l.classFields[l.curModule+"::"+l.curClass] {
			if cm, ok := l.classModule(typ, l.importTables[l.curModule]); ok {
				inner.typ[fld] = [2]string{cm, typ}
			}
		}
		// each function gets a distinct region ROOT, so structural dominance never spans
		// functions (cross-function flows fall back to presence semantics — conservative).
		saveRegion := l.region
		l.region = l.curNS + "/fn" + l.nextBranch()
		saveDecorators := l.curDecorators
		l.curDecorators = st.Decorators
		l.block(st.Body, inner)
		l.curDecorators = saveDecorators
		l.region = saveRegion
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
		cv := constStr(st.Value)
		if cv == "" { // config read folded to its real value (e.g. getProperty("hashAlg1") -> "MD5")
			if pv, ok := l.propConst(st.Value); ok {
				cv = pv
			}
		}
		if cv == "" { // foldable string/char value (e.g. switchTarget = "ABC".charAt(1) -> "B")
			if sv, ok := l.constStrVal(st.Value, sc); ok {
				cv = sv
			}
		}
		for _, t := range st.Targets {
			localDecl := st.Decl && l.region != ""
			if slot := l.moduleGlobalSlot(t); slot != "" && !localDecl {
				l.flow(val, slot)
				sc.node[t] = slot
				if hasTyp {
					sc.typ[t] = typ
				}
				if cv != "" {
					sc.cnst[t] = cv // x = "literal"
				} else {
					delete(sc.cnst, t) // reassigned to a non-constant → value unknown
				}
				continue
			}
			sc.node[t] = val
			if hasTyp {
				sc.typ[t] = typ
			}
			if cv != "" {
				sc.cnst[t] = cv // x = "literal"
			} else {
				delete(sc.cnst, t) // reassigned to a non-constant → value unknown
			}
		}
	case nir.AugAssign:
		n := l.node("Concat", st.Loc, nil)
		l.flow(l.eval(st.Value, sc), n)
		l.flow(sc.node[st.Target], n)
		if slot := l.moduleGlobalSlot(st.Target); slot != "" {
			l.flow(n, slot)
			sc.node[st.Target] = slot
			delete(sc.cnst, st.Target)
			return
		}
		sc.node[st.Target] = n
	case nir.Return:
		rv := l.eval(st.Value, sc)
		l.flow(rv, sc.node["__ret__"])
		// escape direction of cross-method field taint: returning an object whose field was
		// tainted (`h.X = src; return h`) flows each tainted slot into the ret node, so the
		// caller's result (ret → result edge) carries it and a later `o.X` read connects.
		// Edge-based → order-independent; only fires when slots exist.
		if ci := l.containers[rv]; ci != nil {
			for _, slot := range ci.elems {
				if slot != "" {
					l.flow(slot, sc.node["__ret__"])
				}
			}
		}
		l.functionReturnAnalysisEvent(rv, "", l.curDecorators)
	case nir.ExprStmt:
		callNode := l.eval(st.Value, sc)
		// receiver-mutating ("builder"/accumulator) taint: a stdlib builder method
		// (strings.Builder.WriteString, bytes.Buffer.Write…) or a C string-accumulator
		// (g_string_append*, strcat/strncat) folds its args INTO the object you later read
		// back. Model it as a taint-join on that variable (like `x += …`): the variable
		// gains the call's taint. Without this, `b.WriteString(x); b.String()` loses it.
		// This is stdlib accumulator semantics.
		if call, ok := st.Value.(nir.Call); ok && callNode != "" {
			if v := mutatedVar(call); v != "" {
				n := l.node("Concat", call.Loc, nil)
				if cur := sc.node[v]; cur != "" {
					l.flow(cur, n) // preserve the builder's existing taint (`var b` may be unbound)
				}
				l.flow(callNode, n) // call node carries its args' taint
				sc.node[v] = n
				delete(sc.cnst, v)
			}
		}
	case nir.Block:
		l.block(st.Stmts, sc)
	// Structured control flow (B1). Until the CFG lowering lands (B1.2), these flatten
	// like the frontends did before. l.eval is nil-safe, so a frontend that captured the
	// condition (python evaluated it) stays byte-identical, and one that did NOT (go) sets
	// Cond=nil and the eval is a no-op — each frontend keeps its exact prior node set.
	case nir.If:
		condNode := l.eval(st.Cond, sc)
		if pat, name, ok := unsoundContainmentGuard(st.Cond); ok && condNode != "" {
			observed := condNode
			if name != "" && sc.node[name] != "" {
				observed = sc.node[name]
			}
			l.guardObservation("analysis.guard.containment_check", "containment_check", observed, "", pat)
		}
		// opaque-predicate pruning: a compile-time-constant condition has a dead branch that
		// never executes — lower ONLY the live branch (no Phi join), so `if (const) x = src();
		// else x = "safe";` doesn't taint x from the dead arm. Only fires when the whole
		// condition is constant, so a live branch is never dropped.
		if live, ok := l.constBool(st.Cond, sc); ok {
			if live {
				l.block(st.Then, sc)
			} else {
				l.block(st.Else, sc)
			}
			return
		}
		b := l.nextBranch()
		before := cloneStrMap(sc.node)
		l.inRegion("if"+b+".t", func() { l.block(st.Then, sc) })
		thenB := cloneStrMap(sc.node)
		sc.node = cloneStrMap(before)
		l.inRegion("if"+b+".e", func() { l.block(st.Else, sc) })
		elseB := cloneStrMap(sc.node)
		sc.node = before
		l.mergeBindings(sc, before, []map[string]string{thenB, elseB})
	case nir.Loop:
		l.eval(st.Cond, sc)
		before := cloneStrMap(sc.node)
		l.inRegion("loop"+l.nextBranch(), func() { l.block(st.Body, sc) })
		bodyB := cloneStrMap(sc.node)
		sc.node = before
		l.mergeBindings(sc, before, []map[string]string{bodyB})
	case nir.Switch:
		subject := l.eval(st.Subject, sc)
		// constant subject → lower only the matching case (or default), like if/ternary
		// pruning. `switch ("ABC".charAt(1)) { case 'A': x=src(); case 'B': x="safe"; }` runs
		// only case 'B'. Requires the frontend to have captured case labels.
		if len(st.Labels) == len(st.Cases) && len(st.Cases) > 0 {
			if subj, ok := l.constStrVal(st.Subject, sc); ok {
				matched := -1
				for i, labs := range st.Labels {
					for _, lab := range labs {
						if lv, ok := l.constStrVal(lab, sc); ok && lv == subj {
							matched = i
						}
					}
				}
				if matched >= 0 {
					l.block(st.Cases[matched], sc)
				} else {
					l.block(st.Default, sc)
				}
				return
			}
		}
		for _, labs := range st.Labels {
			for _, lab := range labs {
				l.flow(subject, l.eval(lab, sc))
			}
		}
		b := l.nextBranch()
		before := cloneStrMap(sc.node)
		var branches []map[string]string
		for i, c := range st.Cases {
			sc.node = cloneStrMap(before)
			l.inRegion("sw"+b+".c"+strconv.Itoa(i), func() { l.block(c, sc) })
			branches = append(branches, cloneStrMap(sc.node))
		}
		sc.node = cloneStrMap(before)
		l.inRegion("sw"+b+".d", func() { l.block(st.Default, sc) })
		branches = append(branches, cloneStrMap(sc.node))
		sc.node = before
		l.mergeBindings(sc, before, branches)
	case nir.Try:
		b := l.nextBranch()
		l.inRegion("try"+b, func() { l.block(st.Body, sc) })
		for i, h := range st.Handlers {
			l.inRegion("try"+b+".h"+strconv.Itoa(i), func() { l.block(h, sc) })
		}
		l.inRegion("try"+b+".f", func() { l.block(st.Finally, sc) })
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
		// inheritance-aware implicit-`this`: a bare identifier that is a (declared or inherited)
		// member of the enclosing class — and is NOT a local/param (checked above) — refers to
		// this.<member>. Resolve to the STABLE this-field SLOT so reads AND mutations connect and
		// the taint escapes via `return this`. (Static-type refs like File/Console aren't members,
		// so they stay untouched — sink matching is preserved.)
		if l.curClass != "" {
			if self := sc.node["this"]; self != "" && l.classMemberSet(l.curModule, l.curClass)[ex.ID] {
				return l.elemNode(self, ex.ID, ex.Loc)
			}
		}
		return l.node("Name", ex.Loc, map[string]string{"callee_path": ex.ID, "method": ex.ID})
	case nir.Const:
		return l.node("Const", ex.Loc, nil)
	case nir.Thru:
		return l.eval(ex.Inner, sc)
	case nir.Attr:
		base := l.eval(ex.Base, sc)
		// `method` carries the attribute NAME (last segment) so `source method "ssn"`
		// matches a field read like `user.ssn` regardless of receiver. Golden-neutral
		// (the NIR golden serializes callee_path, not method).
		props := map[string]string{"callee_path": ex.Path, "method": ex.Attr}
		if t := l.recvType(base); t != "" {
			props["recv_type"] = t
		}
		n := l.node("Attr", ex.Loc, props)
		l.flow(base, n)
		// field-sensitive read: if obj.field was written element-sensitively (directly or via
		// an alias sharing this base node), pull that slot's taint too.
		if ci := l.containers[base]; ci != nil && ci.elems[ex.Attr] != "" {
			l.flow(ci.elems[ex.Attr], n)
		}
		return n
	case nir.Index:
		base := l.eval(ex.Base, sc)
		key := l.eval(ex.Key, sc)
		n := l.node("Subscript", ex.Loc, map[string]string{"callee_path": ex.Path + ".__subscript", "method": "[]", "arg0": key})
		l.flow(key, n)
		// element-sensitive: `lst[0]` after `lst.add(p); lst.add("safe")` reads slot 0 only.
		if !l.containerRead(base, n, ex.Key, sc) {
			l.flow(base, n)
		}
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
		props := map[string]string{"callee_path": "__object_literal"}
		var valToks []string
		collectValTokens(ex, "", &valToks)
		collectKeyPathTokens(ex.KeyPath, &valToks)
		if len(valToks) > 0 {
			props["str_args"] = strings.Join(valToks, "\x00")
		}
		n := l.node("Seq", ex.Loc, props)
		for _, p := range ex.Parts {
			l.flow(l.eval(p, sc), n)
		}
		return n
	case nir.BinOp:
		left := l.eval(ex.Left, sc)
		right := l.eval(ex.Right, sc)
		leftArg := l.node("Arg", ex.Loc, map[string]string{"vkind": nirKind(ex.Left)})
		rightArg := l.node("Arg", ex.Loc, map[string]string{"vkind": nirKind(ex.Right)})
		l.flow(left, leftArg)
		l.flow(right, rightArg)
		method := binopMethod(ex.Op)
		n := l.node("BinOp", ex.Loc, map[string]string{"op": ex.Op, "callee_path": "__binop." + method, "method": method, "arg0": leftArg, "arg1": rightArg})
		l.flow(leftArg, n)
		l.flow(rightArg, n)
		l.flow(left, n)
		l.flow(right, n)
		if ex.Op == "in" && isPathResolveParents(ex.Right) {
			l.syntheticCall("analysis.path.access_check", "access_check", n, ex.Loc, "path.resolve.parents")
		}
		return n
	case nir.Unary:
		operand := l.eval(ex.Operand, sc)
		method := unaryMethod(ex.Op)
		n := l.node("Unary", ex.Loc, map[string]string{"op": ex.Op, "callee_path": "__unary." + method, "method": method, "arg0": operand})
		l.flow(operand, n)
		return n
	case nir.Ternary:
		// `cond ? then : else` — prune the dead arm when the condition is a compile-time
		// constant; otherwise both arms flow (over-approximation).
		cond := l.eval(ex.Cond, sc)
		if live, ok := l.constBool(ex.Cond, sc); ok {
			if live {
				if isMissingTernaryArm(ex.Then) {
					return cond
				}
				return l.eval(ex.Then, sc)
			}
			return l.eval(ex.Else, sc)
		}
		// Allowlist-membership guard: `LIT_SET.includes(x) ? x : default`. The true arm
		// returns a value provably drawn from a CONSTANT set (the selected value cannot escape
		// that fixed set), so x's taint does NOT survive into the result — a SOUND kill, not
		// an assumption. FN-safe: fires only when the tested value and the then-arm are the
		// same variable and the receiver is a literal of constants.
		if v, ok := allowlistMembershipVar(ex.Cond); ok {
			if tn, ok := ex.Then.(nir.Name); ok && tn.ID == v {
				n := l.node("Phi", ex.Loc, nil)
				l.flow(l.eval(ex.Else, sc), n) // only the bounded default arm carries through
				return n
			}
		}
		n := l.node("Phi", ex.Loc, nil)
		if isMissingTernaryArm(ex.Then) {
			l.flow(cond, n)
		} else {
			l.flow(l.eval(ex.Then, sc), n)
		}
		l.flow(l.eval(ex.Else, sc), n)
		return n
	case nir.Pair:
		// A named entry's value carries the taint; the key is metadata used only
		// by value-matching. Lower to the value so taint still flows (e.g. an
		// object property holding user input).
		return l.eval(ex.Value, sc)
	case nir.Lambda:
		// closure capture: the lambda body sees the enclosing scope (free vars carry taint);
		// params are reseeded fresh, shadowing. A sink inside an inline callback (res.format
		// thunk, .then, event handler) thus fires with the captured taint.
		inner := sc.clone()
		var paramNodes []string
		paramByName := map[string]string{}
		for _, p := range ex.Params {
			props := map[string]string{"name": p}
			if typ := ex.ParamTypes[p]; typ != "" {
				props["decl_type"] = typ
			}
			pn := l.node("Param", ex.Loc, props)
			paramByName[p] = pn
			inner.node[p] = pn
			if typ := ex.ParamTypes[p]; typ != "" {
				if cm, ok := l.classModule(typ, l.importTables[l.curModule]); ok {
					inner.typ[p] = [2]string{cm, typ}
				}
			}
			paramNodes = append(paramNodes, pn)
		}
		for _, pe := range ex.ParamEntries {
			if paramNode := paramByName[pe.Param]; paramNode != "" {
				l.parameterEntry(paramNode, ex.Loc, pe.Tokens)
			}
		}
		l.block(ex.Body, inner)
		fn := l.node("Func", ex.Loc, nil)
		l.lambdaParams[fn] = paramNodes // for higher-order callback dispatch
		return fn
	}
	return l.node("Const", "?:0", nil)
}

func binopMethod(op string) string {
	switch op {
	case "+":
		return "add"
	case "-":
		return "sub"
	case "*":
		return "mul"
	case "/":
		return "div"
	case "%":
		return "mod"
	case "<<":
		return "shl"
	case ">>":
		return "shr"
	case "==":
		return "eq"
	case "!=":
		return "ne"
	case "<":
		return "lt"
	case "<=":
		return "le"
	case ">":
		return "gt"
	case ">=":
		return "ge"
	case "&&":
		return "and"
	case "||":
		return "or"
	}
	if op == "" {
		return "op"
	}
	return strings.NewReplacer(".", "_", "/", "div", "%", "mod", "*", "mul", "+", "add", "-", "sub").Replace(op)
}

func unaryMethod(op string) string {
	switch op {
	case "*":
		return "deref"
	case "&":
		return "addr"
	case "!":
		return "not"
	case "-":
		return "neg"
	case "+":
		return "pos"
	}
	if op == "" {
		return "op"
	}
	return strings.NewReplacer(".", "_", "/", "div", "%", "mod", "*", "deref", "+", "pos", "-", "neg").Replace(op)
}

func isMissingTernaryArm(e nir.Expr) bool {
	c, ok := e.(nir.Const)
	return ok && c.Loc == "?:0" && c.Value == ""
}

// allowlistMembershipVar recognizes a constant-set membership test — `["a","b"].includes(x)`,
// `.contains(x)`, `.has(x)` — over a LITERAL set of constants, returning the tested variable.
// Such a guard, when it gates the same variable in a ternary, bounds the value to the fixed
// allowlist (sound). The receiver must be a literal Seq of Consts so the checked value cannot
// influence the set.
func allowlistMembershipVar(cond nir.Expr) (string, bool) {
	switch c := cond.(type) {
	case nir.Call:
		// method form: `["a","b"].includes(x)` / `.contains(x)` / `.has(x)` (JS/Java/C#…)
		switch c.Method {
		case "includes", "contains", "has":
		default:
			return "", false
		}
		if len(c.Args) != 1 {
			return "", false
		}
		arg, ok := c.Args[0].(nir.Name)
		if !ok {
			return "", false
		}
		at, ok := c.Callee.(nir.Attr)
		if !ok {
			return "", false
		}
		return constSeqVar(at.Base, arg.ID)
	case nir.BinOp:
		// operator form: `x in ("a","b")` (Python/Ruby membership). Left is the tested
		// variable, Right is the literal set.
		if c.Op != "in" {
			return "", false
		}
		arg, ok := c.Left.(nir.Name)
		if !ok {
			return "", false
		}
		return constSeqVar(c.Right, arg.ID)
	}
	return "", false
}

// unsoundContainmentGuard recognizes a substring/containment BLOCKLIST guard condition —
// `'<const>' in <var>` / `<const> not in <var>` (Python/Ruby) — which filters by rejecting a
// bad substring and cannot be proven complete. It deliberately does NOT match the allowlist
// shape `<var> in <literal-set>` (that is the sound membership ternary): here the constant is
// the LEFT operand (the needle) and the variable the right (the haystack).
func unsoundContainmentGuard(cond nir.Expr) (string, string, bool) {
	b, ok := cond.(nir.BinOp)
	if !ok || (b.Op != "in" && b.Op != "not in") {
		return "", "", false
	}
	if _, lc := b.Left.(nir.Const); !lc {
		return "", "", false
	}
	rn, ok := b.Right.(nir.Name)
	if !ok {
		return "", "", false
	}
	return b.Op + " <const>", rn.ID, true
}

// constSeqVar confirms set is a fixed literal set of constants and returns varID,true. A set
// is either a collection literal (`[a,b]`, JS/Python) or a JVM constant-set factory call
// (`Arrays.asList(a,b)`, `List.of(a,b)`, `Set.of(a,b)`) — in every case with all-constant
// elements, so the checked value cannot influence the membership domain.
func constSeqVar(set nir.Expr, varID string) (string, bool) {
	switch s := set.(type) {
	case nir.Seq:
		if len(s.Parts) == 0 || !allConst(s.Parts) {
			return "", false
		}
		return varID, true
	case nir.Call:
		if len(s.Args) == 0 || !constSetFactory(s.Path, s.Method) || !allConst(s.Args) {
			return "", false
		}
		return varID, true
	}
	return "", false
}

func allConst(xs []nir.Expr) bool {
	for _, x := range xs {
		if _, ok := x.(nir.Const); !ok {
			return false
		}
	}
	return true
}

// constSetFactory matches the standard JVM immutable-collection constructors. `of` is matched
// only on a List/Set/Map receiver path so an unrelated `Foo.of(...)` is not mistaken for a set.
func constSetFactory(path, method string) bool {
	switch method {
	case "asList", "newHashSet", "newArrayList", "singletonList":
		return true
	case "of", "copyOf":
		return strings.HasSuffix(path, "List."+method) || strings.HasSuffix(path, "Set."+method) ||
			strings.HasSuffix(path, "Map."+method) || path == method
	}
	return false
}

// collectValTokens walks an argument expression and accumulates literal value
// tokens for named-value matching (`val`/`nval`). For each literal it emits the
// bare value, and — when it sits under a key (a kwarg, dict/object/hash entry, or
// struct field) — also a "key=value" token. Lists/objects are walked so nested
// literals are reached, e.g. jwt(algorithms=["none"]) yields "none" and
// "algorithms=none"; requests.get(url, verify=False) yields "False" and
// "verify=False". Pair keys are also emitted on their own so adapters can
// recognize structured-field sinks even when the field value is non-literal
// (`{ hypertext: userInput }`). Frontends that don't emit nir.Pair simply
// contribute bare values.
// recvMutators are stdlib accumulator METHODS whose receiver gains the args' taint
// (strings.Builder / bytes.Buffer in Go, StringBuilder/StringBuffer in Java/Kotlin/C#).
var recvMutators = map[string]bool{
	"WriteString": true, "WriteByte": true, "WriteRune": true, "Write": true,
	"append": true, "push": true, // StringBuilder.append / list-ish builders
}

// argMutators are C/stdlib accumulator FUNCTIONS whose first argument (the destination)
// gains the other args' taint (g_string_append*, strcat/strncat, …).
var argMutators = map[string]bool{
	"strcat": true, "strncat": true, "strlcat": true,
	"g_string_append": true, "g_string_append_printf": true, "g_string_append_len": true,
	"g_string_prepend": true, "g_string_insert": true,
}

// mutatedVar returns the variable a builder/accumulator call mutates (so taint can be
// joined onto it): the receiver of a recvMutator method, or arg0 of an argMutator function.
func mutatedVar(call nir.Call) string {
	if recvMutators[call.Method] {
		if at, ok := call.Callee.(nir.Attr); ok {
			if nm, ok := at.Base.(nir.Name); ok {
				return nm.ID
			}
		}
	}
	if argMutators[lastDot(call.Path)] && len(call.Args) > 0 {
		if nm, ok := call.Args[0].(nir.Name); ok {
			return nm.ID
		}
	}
	return ""
}

func lastDot(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i+1:]
	}
	return p
}

func collectKeyPathTokens(path []string, out *[]string) {
	if len(path) == 0 {
		return
	}
	for _, p := range path {
		if p != "" {
			*out = append(*out, p)
		}
	}
	*out = append(*out, strings.Join(path, "/"))
	*out = append(*out, strings.Join(path, "."))
}

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
		if ex.Key != "" {
			*out = append(*out, ex.Key)
		}
		collectValTokens(ex.Value, ex.Key, out)
	case nir.Seq:
		for _, p := range ex.Parts {
			collectValTokens(p, key, out) // inherit key so list elements pair with it
		}
	case nir.Format:
		for _, p := range ex.Parts {
			collectValTokens(p, key, out)
		}
	case nir.Call:
		collectValTokens(ex.Callee, key, out)
		for _, a := range ex.Args {
			collectValTokens(a, key, out)
		}
	case nir.Name:
		// enum / named constant arg (QSslSocket::VerifyNone, SSL_VERIFY_NONE, DES,
		// Algorithm.none). Value-matched marks/sinks key off these symbolic values, not
		// just string literals, so capture the identifier for `val`/`nval` matching.
		if ex.ID != "" {
			*out = append(*out, ex.ID)
			if key != "" {
				*out = append(*out, key+"="+ex.ID)
			}
		}
	case nir.Attr:
		// a qualified constant like Foo::Bar / pkg.CONST — match on the dotted path and leaf.
		if ex.Path != "" {
			*out = append(*out, ex.Path)
		}
		if ex.Attr != "" {
			*out = append(*out, ex.Attr)
			if key != "" {
				*out = append(*out, key+"="+ex.Attr)
			}
		}
		collectValTokens(ex.Base, key, out)
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
	if nodeID == "" {
		return ""
	}
	if n, ok, _ := l.g.GetNode(nodeID); ok {
		for _, key := range []string{"recv_type", "decl_type", "type"} {
			if t := n.Prop(key); t != "" {
				return t
			}
		}
		if len(l.ctorTypes) > 0 {
			return l.ctorTypes[n.Prop("callee_path")]
		}
	}
	return ""
}

func (l *lowerer) evalCall(call nir.Call, sc *scope) string {
	// Each argument SLOT is a distinct program point at the call site (an Arg
	// node), flowing from the argument value. This gives sinks the correct
	// location (the call, not where the value was defined) and lets an adapter
	// label an arg position as a sink even when the value is itself a source —
	// e.g. call(input_value).
	var args []string
	var argVals []string // the eval'd value node per arg (a Func node for a callback)
	var valToks []string // literal value tokens for value-matching sinks (`val`/`nval`)
	for _, a := range call.Args {
		av := l.eval(a, sc)
		argVals = append(argVals, av)
		// Record the argument's NIR kind on the slot, so sink adapters can
		// distinguish a string-building position (Format/Const/Name/...) from a
		// collection literal (Seq).
		an := l.node("Arg", call.Loc, map[string]string{"vkind": nirKind(a)})
		l.flow(av, an)
		args = append(args, an)
		collectValTokens(a, "", &valToks)
		// value-flow: fold a const-propped variable, an array-literal index (['sha1'][0]),
		// or an object-literal property ({name:'md5'}.name) to its string so it value-matches
		// like the inline literal — `getInstance(algo)`, `createHash(['sha1'][0])`, etc.
		if sv, ok := l.constStrVal(a, sc); ok {
			valToks = append(valToks, sv)
		}
	}
	// A bare call to a `from mod import sym` alias is matched by adapters under its
	// resolved dotted path, so imported sinks/sanitizers (e.g. `escape` from
	// `markupsafe.escape`, `system` from `os.system`) are recognized.
	calleePath := call.Path
	if l.resolveImports {
		if nm, ok := call.Callee.(nir.Name); ok {
			if imp, ok := l.importTables[l.curModule][nm.ID]; ok {
				switch imp.kind {
				case "sym":
					calleePath = imp.module + "." + imp.symbol
				case "mod":
					// a default-export module called directly: f = require('escape-html'); f(x)
					// resolves to the module's own path so module-named sinks/controls match.
					calleePath = imp.module
				}
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
	// per-arg literal value (first literal token) — lets a `filter` directive read the
	// regex pattern (arg0) and replacement (arg1) of a replace(pattern, repl) call.
	for i, a := range call.Args {
		var toks []string
		collectValTokens(a, "", &toks)
		if len(toks) > 0 {
			props["lit"+strconv.Itoa(i)] = toks[0]
		}
	}
	// resolve the receiver once; if it was assigned from a known constructor,
	// stamp recv_type so type-constrained sink adapters can reason about it.
	var recvNode string
	if attr, ok := call.Callee.(nir.Attr); ok {
		recvNode = l.eval(attr.Base, sc)
		if recvNode != "" {
			props["recv"] = recvNode
		}
		if t := l.recvType(recvNode); t != "" {
			props["recv_type"] = t
		}
	}
	result := l.node("Call", call.Loc, props)
	if recvNode != "" { // receiver taint (chained calls)
		// a container get with a CONSTANT key reads only that slot (element-sensitive), so
		// `m.put("kB", p); m.get("kA")` stays clean. Anything else flows the whole receiver
		// (chained-call taint / dynamic key — over-approximation).
		if !(call.Method == "get" && len(call.Args) == 1 && l.containerRead(recvNode, result, call.Args[0], sc)) {
			l.flow(recvNode, result)
		}
		// a collection/builder MUTATOR taints its receiver from the added value, so a
		// later read or a sink fed the whole container sees the taint (e.g.
		// list.add(param); ProcessBuilder(list)). Element-sensitive per constant key.
		if mutatorMethods[call.Method] {
			l.containerWrite(call, args, recvNode, sc)
			// `base.field.add(v)` — the receiver is a member access, so the mutator taints a
			// transient Attr read node, not the FIELD SLOT. Also route the added value(s) into
			// elemNode(base, field) so a later `base.field` read (or an aliased receiver) sees
			// the mutation, not just chained reads off this exact expression.
			if outer, ok := call.Callee.(nir.Attr); ok {
				if inner, ok := outer.Base.(nir.Attr); ok && inner.Attr != "" {
					slot := l.elemNode(l.eval(inner.Base, sc), inner.Attr, call.Loc)
					for _, a := range args {
						l.flow(a, slot)
					}
				}
			}
		} else if ci := l.containers[recvNode]; ci != nil && !modeledContainerMethod(call.Method) {
			l.containerInvalidate(call, recvNode, sc) // precise index-shift where unambiguous, else dirty
		}
		// field write `obj.field = v` (the frontend models it as a Method-less call on the
		// base): store into the per-field slot so a read of obj.field — or of an ALIAS that
		// shares obj's node (const a = obj; a.field = v) — sees the taint. Field-sensitive:
		// sibling fields stay clean.
		if call.Method == "" && len(args) > 0 {
			if attr, ok := call.Callee.(nir.Attr); ok && attr.Attr != "" {
				l.flow(args[0], l.elemNode(recvNode, attr.Attr, call.Loc))
			}
		}
		// higher-order callback dispatch: `recv.forEach(cb)` / `arr.map(cb)` / `p.then(cb)`
		// invoke cb with a value derived from the receiver, so route the receiver's taint into
		// the callback's first parameter (cb's body was lowered with that param node, so the
		// existing edges carry it onward). FN-safe over-approximation.
		if elementCallbackMethods[call.Method] {
			for _, av := range argVals {
				if ps := l.lambdaParams[av]; len(ps) > 0 {
					l.flow(recvNode, ps[0])
				}
			}
		}
		// self-passing scope functions (`recv.With/Also/Apply/Tap/Let(x => …)` — C# fluent
		// helpers, Kotlin scope functions) invoke the lambda WITH THE RECEIVER, so the lambda's
		// param IS the receiver: alias them so a field mutation via the param (`x.Field = …`)
		// reaches the receiver object. The closure already captured the outer scope.
		if selfPassingMethods[call.Method] && recvNode != "" {
			for _, av := range argVals {
				if ps := l.lambdaParams[av]; len(ps) > 0 {
					l.aliasReceiverSelf(recvNode, ps[0])
				}
			}
		}
	}
	// Interprocedural taint. An arg routed into a RESOLVED local function flows through that
	// function's body (arg → param → … → ret → result), so a sanitizer applied INSIDE the
	// callee is honoured — `bar = my_wrapper(p)` where my_wrapper escapes p is clean. Only an
	// arg NOT mapped to any resolved param keeps the conservative direct `arg → result` edge
	// (unknown/library callee, or a vararg beyond the param list), preserving recall there.
	targets := l.resolveTargets(call.Callee, sc)
	mapped := make([]bool, len(args))
	for _, target := range targets {
		for i, a := range args {
			if i < len(target.paramNames) {
				pnode := target.params[target.paramNames[i]]
				l.flow(a, pnode)
				// cross-method object identity: C# objects are reference types, so a field
				// mutation inside the callee (`p.field = …` / `p.list.Add(…)`) is visible to the
				// CALLER's object. Share the container (field slots) between the arg and the param
				// — bidirectional, so both the callee reading the arg's existing field taint AND
				// the caller seeing the callee's mutations work. Only fires when the arg carries
				// field/element slots (an object/collection), so scalars are unaffected.
				if l.containers[argVals[i]] != nil {
					l.aliasReceiverSelf(argVals[i], pnode)
				}
				mapped[i] = true
			}
		}
		l.flow(target.ret, result)
		// object-sensitivity: alias the receiver with the callee's stable `this` node so field
		// mutations performed via `this` inside the method reach the receiver object (and reads
		// of the receiver's fields are visible inside the method). Enables fluent/builder
		// mutators (`req.AddParameter(p)` whose body does `this.Parameters.Add(p)`).
		if recvNode != "" && target.selfNode != "" {
			l.aliasReceiverSelf(recvNode, target.selfNode)
		}
		for _, entry := range target.resultEntries {
			if len(entry.Tokens) > 0 {
				result = l.syntheticCall(analysisFunctionResult.path, analysisFunctionResult.method, result, call.Loc, entry.Tokens...)
			}
		}
	}
	for i, a := range args {
		if !mapped[i] {
			l.flow(a, result)
		}
	}
	// wrapper-object taint: `new T(taintedArg)` builds an object that CONTAINS its args, so the
	// constructed object (result) carries each arg's taint — even when the ctor body is resolved
	// (args mapped to params). Lets a tainted value wrapped in an object propagate through it
	// (e.g. RestSharp `new HeaderParameter(name, value)`). FN-safe over-approximation.
	if call.IsCtor {
		for _, av := range argVals {
			l.flow(av, result)
		}
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
		// a bare call inside a class resolves to the enclosing class's own method (e.g. a
		// `private static String doSomething(...)` called as `doSomething(...)`). Without this
		// the call is unresolved and the conservative arg→result edge over-taints the result.
		if l.curClass != "" {
			if f := l.funcQual[l.curModule+"::"+l.curClass+"."+nm]; f != nil {
				return []*funcInfo{f}
			}
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
				if m.abstract {
					// interface/abstract method — the concrete runtime target is unknown, so
					// don't route through this empty body (which would sink the taint). Return
					// unresolved: the conservative direct arg→result edge then carries taint
					// through the call (over-approximate, recall-safe), while concrete callees
					// still route through their real body so in-body sanitizers are honoured.
					return nil
				}
				return []*funcInfo{m}
			}
		}
		// Cross-file fallback: the receiver type is unresolved (common with dynamically-typed
		// `$this->getIp()` / `obj.helper()` where the helper lives in another file), but the
		// method name is UNIQUE across the whole program. Route through it so a tainted return
		// value connects to the call result — the canonical interprocedural-across-files miss.
		// The uniqueness guard avoids mis-resolving same-named methods on different types.
		if infos := l.funcShort[c.Attr]; len(infos) == 1 {
			return infos
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
		for m := range mods {
			return m, true
		}
	}
	return "", false
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
		// qualified dotted constructor `pkg.mod.ClassName(...)` (a nested attribute, so the
		// base isn't a simple module Name) — resolve by the class name (the last segment)
		// when exactly one module defines it.
		if cm, ok := l.classModule(c.Attr, imports); ok {
			return [2]string{cm, c.Attr}, true
		}
	}
	return [2]string{}, false
}

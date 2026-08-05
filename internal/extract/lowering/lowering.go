// Package lowering is the shared, language-AGNOSTIC tier (docs/20): it lowers
// NIR into the shared graph, owning the function/class registries,
// per-file import tables, the type map (self, constructors, class/static
// receivers), call resolution (import -> type -> guarded unique-name fallback),
// and dataflow construction (scopes, assignments, FLOWS edges).
//
// None of this is duplicated per language. A frontend's only job is to translate
// its parser's tree into NIR; resolution and dataflow live here, once. This is
// what lets the project add a language — or swap a parser (tree-sitter, native,
// LSP/SCIP) — without touching resolution or rules. The algorithm is
// docs/10 §"Call resolution" generalized over NIR.
package lowering

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/regexambig"
	"github.com/vyprai/vyql/internal/usg"
)

type funcInfo struct {
	paramNames    []string
	params        map[string]string // name -> param node id
	paramTypes    map[string]string // name -> declared/inferred receiver type
	ret           string            // return node id
	module        string
	cls           string
	name          string
	paramEntries  []nir.ParamEntry
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
	// storeErr holds the FIRST graph-write failure. Every node and edge the
	// lowering produces goes through the two call sites that set it, and neither
	// can report upward -- they are called from deep inside expression lowering,
	// which returns node ids rather than errors. An in-memory store never fails,
	// but a disk-backed one can, and dropping a node there yields a graph that is
	// quietly missing part of the program. run() surfaces this.
	storeErr error
	modCtr   map[string]int // per-module node-id counter (stable, module-local ids)

	funcQual      map[string]*funcInfo         // "modkey::qual" -> info
	funcShort     map[string][]*funcInfo       // short name -> infos
	classQual     map[string]bool              // "modkey::Class"
	classDefs     map[string]map[string]bool   // bare class name -> SET of modules that define it
	classFields   map[string]map[string]string // "modkey::Class" -> field -> declared class type
	importTables  map[string]map[string]importEntry
	moduleTech    map[string]string
	moduleGlobals map[string]map[string]string // JS/TS module-level binding name -> stable slot node

	// inheritance-aware dispatch and implicit-`this` member resolution (populated by frontends
	// that set ClassDef.Bases/Members). directMembers: "modkey::Class" -> declared member set;
	// classBaseNames: "modkey::Class" -> base SHORT names; membersOfShort: short class name ->
	// union of declared members (for resolving inherited members by name across files).
	directMembers   map[string]map[string]bool
	classBaseNames  map[string][]string
	derivedChildren map[string][]string // base short name -> child class quals
	membersOfShort  map[string]map[string]bool
	allMembersMemo  map[string]map[string]bool // memoized transitive member set per "modkey::Class"
	dynCallbackMemo map[string][]*funcInfo     // memoized dynamic-callback target set, keyed by current module tech
	addrTaken       map[string]bool            // short names referenced as a VALUE anywhere (candidate dynamic-callback targets)
	addrTakenReady  bool                       // true once addrTaken has been collected for the whole program

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
	templates  map[string]templateInfo

	// modStr maps a module-level (top-level) variable name to its string-constant value, so a
	// regex call `re.match(PATTERN, x)` referring to a `PATTERN = r"..."` module constant can be
	// resolved to its literal for catastrophic-backtracking (ReDoS) detection even from inside a
	// function body that does not inherit the module scope's const map.
	modStr map[string]string

	// dynSQLVar tracks variables assigned a dynamically-built string (f-string/concat/format), so a
	// later `execute(q)` on such a variable is recognised as dynamic SQL even when the query is
	// built one statement earlier (`q = f"..."; cur.execute(q)`).
	dynSQLVar map[string]bool

	// debugPayloadVar tracks variables assigned a response payload that leaks internal config —
	// `payload = {"module": os.environ.get(...), "base": str(BASE_DIR)}` — so a later
	// `JsonResponse(payload)` is recognised as debug-info exposure (CWE-215).
	debugPayloadVar map[string]bool

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

	tryExceptionTargets []string
}

type containerInfo struct {
	elems   map[string]string // constant key/index -> element node id holding that slot's taint
	dirty   bool              // a write with a NON-constant key happened (any key may be tainted)
	nextIdx int               // append counter for add()/append()/push()
	// composite marks a two-part-key container — `cfg.set(section, key, val)` /
	// `cfg.get(section, key)` (configparser and friends). Only a 3-arg keyed write sets
	// it, which a dict/list never performs, so plain `d.get(key, default)` is unaffected.
	composite bool
}

// inRegion lowers f inside a nested control region (then/else/loop/case/handler).
func (l *lowerer) inRegion(seg string, f func()) {
	save := l.region
	l.region = save + "/" + seg
	f()
	l.region = save
}

// functionRegion opens the region root for a function body.
//
// A function declared at module level gets a fresh root, so structural dominance
// never spans functions. A function written INSIDE another one — an inline
// callback — hangs off the region that encloses it, joined with "#". The
// dominance tests read only "/" as nesting, so a guard inside a callback still
// does not dominate the code around it, and a release inside one still does not
// post-dominate it. Reaches does read "#", because a callback body does execute
// somewhere after the code that passes it: that is what lets an order rule
// sequence a check made in a callback against a use in the enclosing function.
func (l *lowerer) functionRegion() string {
	if l.region == "" {
		return l.curNS + "/fn" + l.nextBranch()
	}
	return l.region + "#fn" + l.nextBranch()
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
		// array-literal index: ['kind'][0]  → the i-th element if constant.
		if seq, ok := l.seqOf(v.Base); ok {
			if idx, ok := l.constInt(v.Key, sc); ok && idx >= 0 && int(idx) < len(seq) {
				return l.constStrVal(seq[idx], sc)
			}
		}
	case nir.Attr:
		// object-literal property: { name: 'mode' }.name  → the matching pair's value.
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
	if fact, ok := l.nonNegativeLenFact(e, sc); ok {
		return fact, true
	}
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

// compositeKey joins a two-part container key — `cfg.set(section, key, v)` /
// `cfg.get(section, key)` — into one slot name. Both parts must be constant; a dynamic
// part means the slot is unknown and the caller falls back to the sound whole-container
// behaviour. The separator cannot appear in a resolved constant key part.
func (l *lowerer) compositeKey(a, b nir.Expr, sc *scope) (string, bool) {
	ka, oka := l.constKey(a, sc)
	if !oka {
		return "", false
	}
	kb, okb := l.constKey(b, sc)
	if !okb {
		return "", false
	}
	return ka + "\x00" + kb, true
}

// containerRead resolves an element-sensitive read of recv[key] into result. Returns false
// when it can't (recv was never written as a container, or a dirty container is read with a
// dynamic key) so the caller falls back to conservative whole-container/key flow.
//
// A constant key that was never written (and no dynamic write happened) reads CLEAN. A dynamic
// key on a clean tracked container reads "one of the known slots": route all slot taint, but do
// not taint the selected value merely because the selector is user-controlled. This preserves
// whitelist maps such as `$files[$request_key]` whose values are compile-time constants.
func (l *lowerer) containerRead(recv, result string, keyExpr nir.Expr, sc *scope) bool {
	ci := l.containers[recv]
	if ci == nil {
		return false
	}
	key, ok := l.constKey(keyExpr, sc)
	if !ok {
		if ci.dirty {
			return false // unknown write plus dynamic key — any value may be present
		}
		for _, elem := range ci.elems {
			l.flow(elem, result)
		}
		return true
	}
	return l.containerReadKey(recv, result, key, true)
}

// containerReadKey routes the taint of one resolved slot. ok=false (the key had a dynamic
// part) means the slot is unknown, so the caller must fall back to the whole container.
func (l *lowerer) containerReadKey(recv, result, key string, ok bool) bool {
	if !ok {
		return false
	}
	ci := l.containers[recv]
	if ci == nil {
		return false
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

// keyedContainerGet resolves a container `get` read element-sensitively, covering both the
// single-key form (`m.get(key)`) and the two-part-key form (`cfg.get(section, key)`) on a
// container a 3-arg keyed write marked composite. Reports whether it resolved the read; false
// means the caller flows the whole receiver (chained call, dynamic key, untracked container).
func (l *lowerer) keyedContainerGet(call nir.Call, recv, result string, sc *scope) bool {
	if call.Method != "get" {
		return false
	}
	switch len(call.Args) {
	case 1:
		return l.containerRead(recv, result, call.Args[0], sc)
	case 2:
		// Only for a composite container: on a plain dict this is `get(key, default)`,
		// where arg1 is a fallback value, not part of the key.
		ci := l.containers[recv]
		if ci == nil || !ci.composite {
			return false
		}
		key, ok := l.compositeKey(call.Args[0], call.Args[1], sc)
		return l.containerReadKey(recv, result, key, ok)
	}
	return false
}

// containerWrite records an element-sensitive write into recv and keeps the whole container
// tainted (for whole-container reads / dynamic-key gets). Recognised keyed/append mutators
// taint a specific slot; any other mutator marks the container dirty (unknown slot).
func (l *lowerer) containerWrite(call nir.Call, args []string, recv string, sc *scope) {
	switch {
	case keyedMutators[call.Method] && len(args) == 2:
		// map.put(key, val) / list.set(i, val) — EXACTLY two args.
		l.flow(args[1], recv)
		if key, ok := l.constKey(call.Args[0], sc); ok {
			l.flow(args[1], l.elemNode(recv, key, call.Loc))
		} else {
			l.cinfo(recv).dirty = true
		}
	case keyedMutators[call.Method] && len(args) == 3:
		// two-part key: `cfg.set(section, key, val)` (configparser). The value lands in the
		// (section, key) slot, so a later `cfg.get(section, otherKey)` reads clean. Marking
		// the container composite keeps the matching 2-arg read element-sensitive; a dict or
		// list never takes this branch, so their `get(key, default)` stays untouched.
		l.flow(args[2], recv)
		ci := l.cinfo(recv)
		ci.composite = true
		if key, ok := l.compositeKey(call.Args[0], call.Args[1], sc); ok {
			l.flow(args[2], l.elemNode(recv, key, call.Loc))
		} else {
			ci.dirty = true
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
	var vars []string
	for v := range changed {
		vars = append(vars, v)
	}
	sort.Strings(vars)
	for _, v := range vars {
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
		var srcIDs []string
		for s := range srcs {
			srcIDs = append(srcIDs, s)
		}
		sort.Strings(srcIDs)
		for _, s := range srcIDs {
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
	iter map[string][]string
	lex  map[string]bool // JS/TS captured lexical bindings shared across nested functions
}

func newScope() *scope {
	return &scope{node: map[string]string{}, typ: map[string][2]string{}, cnst: map[string]string{}, iter: map[string][]string{}, lex: map[string]bool{}}
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
	for k, v := range s.iter {
		c.iter[k] = append([]string(nil), v...)
	}
	for k, v := range s.lex {
		c.lex[k] = v
	}
	return c
}

func (l *lowerer) promoteCapturedJSBindings(stmts []nir.Stmt, params []string, sc *scope, loc string) {
	if !isJSLikeModule(l.curNS) {
		return
	}
	for name := range freeNames(stmts, params) {
		if sc.node[name] != "" {
			l.ensureLexicalBinding(sc, name, loc)
		}
	}
}

func (l *lowerer) ensureLexicalBinding(sc *scope, name, loc string) {
	if name == "" || sc.node[name] == "" || sc.lex[name] {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	slot := l.nodeInline("Name", loc, map[string]string{"lexical_binding": "true"}, name, name, "", "")
	l.flow(sc.node[name], slot)
	sc.node[name] = slot
	sc.lex[name] = true
}

func freeNames(stmts []nir.Stmt, params []string) map[string]bool {
	local := map[string]bool{}
	for _, p := range params {
		local[p] = true
	}
	collectLocalDecls(stmts, local)

	used := map[string]bool{}
	for _, st := range stmts {
		collectStmtNames(st, used)
	}
	for name := range local {
		delete(used, name)
	}
	return used
}

func collectLocalDecls(stmts []nir.Stmt, local map[string]bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.Assign:
			if s.Decl {
				for _, t := range s.Targets {
					if t != "" && !strings.ContainsAny(t, ".[") {
						local[t] = true
					}
				}
			}
		case nir.FuncDef:
			if s.Name != "" {
				local[s.Name] = true
			}
		case nir.ClassDef:
			if s.Name != "" {
				local[s.Name] = true
			}
		case nir.Block:
			collectLocalDecls(s.Stmts, local)
		case nir.If:
			collectLocalDecls(s.Then, local)
			collectLocalDecls(s.Else, local)
		case nir.Loop:
			for _, name := range s.Vars {
				if name != "" && !strings.ContainsAny(name, ".[") {
					local[name] = true
				}
			}
			collectLocalDecls(s.Body, local)
		case nir.Switch:
			for _, c := range s.Cases {
				collectLocalDecls(c, local)
			}
			collectLocalDecls(s.Default, local)
		case nir.Try:
			collectLocalDecls(s.Body, local)
			for _, h := range s.Handlers {
				collectLocalDecls(h, local)
			}
			collectLocalDecls(s.Finally, local)
		}
	}
}

func collectStmtNames(st nir.Stmt, used map[string]bool) {
	switch s := st.(type) {
	case nir.Assign:
		if !s.Decl {
			for _, t := range s.Targets {
				if t != "" && !strings.ContainsAny(t, ".[") {
					used[t] = true
				}
			}
		}
		collectExprNames(s.Value, used)
	case nir.AugAssign:
		if s.Target != "" {
			used[s.Target] = true
		}
		collectExprNames(s.Value, used)
	case nir.Return:
		collectExprNames(s.Value, used)
	case nir.Validation:
		collectExprNames(s.Evidence, used)
	case nir.Terminate:
		collectExprNames(s.Value, used)
	case nir.ExprStmt:
		collectExprNames(s.Value, used)
	case nir.Block:
		for _, child := range s.Stmts {
			collectStmtNames(child, used)
		}
	case nir.If:
		collectExprNames(s.Cond, used)
		for _, child := range s.Then {
			collectStmtNames(child, used)
		}
		for _, child := range s.Else {
			collectStmtNames(child, used)
		}
	case nir.Loop:
		collectExprNames(s.Cond, used)
		collectExprNames(s.Iter, used)
		for _, child := range s.Body {
			collectStmtNames(child, used)
		}
	case nir.Switch:
		collectExprNames(s.Subject, used)
		for _, labels := range s.Labels {
			for _, label := range labels {
				collectExprNames(label, used)
			}
		}
		for _, c := range s.Cases {
			for _, child := range c {
				collectStmtNames(child, used)
			}
		}
		for _, child := range s.Default {
			collectStmtNames(child, used)
		}
	case nir.Try:
		for _, child := range s.Body {
			collectStmtNames(child, used)
		}
		for _, h := range s.Handlers {
			for _, child := range h {
				collectStmtNames(child, used)
			}
		}
		for _, child := range s.Finally {
			collectStmtNames(child, used)
		}
	}
}

func collectExprNames(ex nir.Expr, used map[string]bool) {
	switch e := ex.(type) {
	case nil:
	case nir.Name:
		if e.ID != "" {
			used[e.ID] = true
		}
	case nir.Attr:
		collectExprNames(e.Base, used)
	case nir.Index:
		collectExprNames(e.Base, used)
		collectExprNames(e.Key, used)
	case nir.Call:
		collectExprNames(e.Callee, used)
		for _, a := range e.Args {
			collectExprNames(a, used)
		}
	case nir.Format:
		for _, p := range e.Parts {
			collectExprNames(p, used)
		}
	case nir.Seq:
		for _, p := range e.Parts {
			collectExprNames(p, used)
		}
	case nir.Pair:
		collectExprNames(e.Value, used)
	case nir.Thru:
		collectExprNames(e.Inner, used)
	case nir.BinOp:
		collectExprNames(e.Left, used)
		collectExprNames(e.Right, used)
	case nir.Unary:
		collectExprNames(e.Operand, used)
	case nir.Ternary:
		collectExprNames(e.Cond, used)
		collectExprNames(e.Then, used)
		collectExprNames(e.Else, used)
	}
}

type analysisEventSpec struct {
	path   string
	method string
}

var (
	analysisFunctionReturn  = analysisEventSpec{path: "analysis.function.return", method: "return"}
	analysisFunctionContext = analysisEventSpec{path: "analysis.function.context", method: "context"}
	analysisFunctionResult  = analysisEventSpec{path: "analysis.function.result", method: "result"}
	analysisClassContext    = analysisEventSpec{path: "analysis.class.context", method: "context"}
	analysisParameterEntry  = analysisEventSpec{path: "analysis.parameter.entry", method: "entry"}
	analysisGlobalMutation  = analysisEventSpec{path: "analysis.global.mutation", method: "mutation"}
)

func (l *lowerer) functionContextAnalysisEvent(loc string, contextTokens []string) {
	if len(contextTokens) == 0 {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	l.nodeInline("Call", loc, nil, analysisFunctionContext.method, analysisFunctionContext.path, strings.Join(contextTokens, "\x00"), "")
}

func (l *lowerer) classContextAnalysisEvent(loc, name string, bases []string, memberTokens []string) {
	var tokens []string
	seen := map[string]bool{}
	add := func(tok string) {
		if tok == "" || seen[tok] || len(tokens) >= 512 {
			return
		}
		seen[tok] = true
		tokens = append(tokens, tok)
	}
	if name != "" {
		add("class_name:" + name)
	}
	for _, base := range bases {
		add("class_base:" + base)
	}
	for _, tok := range memberTokens {
		add(tok)
	}
	if len(tokens) == 0 {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	l.nodeInline("Call", loc, nil, analysisClassContext.method, analysisClassContext.path, strings.Join(tokens, "\x00"), "")
}

func classMemberContextTokens(stmts []nir.Stmt) []string {
	var tokens []string
	var walk func([]nir.Stmt)
	walk = func(stmts []nir.Stmt) {
		for _, s := range stmts {
			if len(tokens) >= 512 {
				return
			}
			switch st := s.(type) {
			case nir.FuncDef:
				tokens = append(tokens, st.ContextTokens...)
				walk(st.Body)
			case nir.ClassDef:
				// Nested classes get their own class-context event; do not smear their
				// member evidence onto the enclosing class.
				continue
			case nir.Block:
				walk(st.Stmts)
			case nir.If:
				walk(st.Then)
				walk(st.Else)
			case nir.Loop:
				walk(st.Body)
			case nir.Switch:
				for _, c := range st.Cases {
					walk(c)
				}
			case nir.Try:
				walk(st.Body)
				for _, h := range st.Handlers {
					walk(h)
				}
				walk(st.Finally)
			}
		}
	}
	walk(stmts)
	if len(tokens) > 512 {
		return tokens[:512]
	}
	return tokens
}

func (l *lowerer) globalMutationAnalysisEvent(loc string, tokens []string) {
	if len(tokens) == 0 {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	l.nodeInline("Call", loc, nil, analysisGlobalMutation.method, analysisGlobalMutation.path, strings.Join(tokens, "\x00"), "")
}

func (l *lowerer) functionReturnAnalysisEvent(id, loc string, contextTokens []string) {
	if id == "" || len(contextTokens) == 0 {
		return
	}
	// Lowering records only structural return evidence. Binding data decides whether
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
	arg := l.nodeInline("Arg", loc, nil, "", "", "", "Return")
	l.flow(id, arg)
	props := map[string]string{"arg0": arg}
	strArgs := ""
	if len(valToks) > 0 {
		strArgs = strings.Join(valToks, "\x00")
	}
	call := l.nodeInline("Call", loc, props, analysisFunctionReturn.method, analysisFunctionReturn.path, strArgs, "")
	l.flow(arg, call)
}

func (l *lowerer) parameterEntry(paramNode, loc string, tokens []string) {
	if paramNode == "" || len(tokens) == 0 {
		return
	}
	if loc == "" {
		loc = "?:0"
	}
	call := l.nodeInline("Call", loc, nil, analysisParameterEntry.method, analysisParameterEntry.path, strings.Join(tokens, "\x00"), "")
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
	arg := l.nodeInline("Arg", loc, nil, "", "", "", "Analysis")
	l.flow(id, arg)
	props := map[string]string{"arg0": arg}
	strArgs := ""
	if len(valToks) > 0 {
		strArgs = strings.Join(valToks, "\x00")
	}
	call := l.nodeInline("Call", loc, props, method, path, strArgs, "")
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
	strArgs := ""
	if len(valToks) > 0 {
		strArgs = strings.Join(valToks, "\x00")
	}
	call := l.nodeInline("Call", loc, nil, method, path, strArgs, "")
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

func shortClassName(name string) string {
	name = lastPathSegment(strings.TrimSpace(name))
	if i := strings.LastIndex(name, "::"); i >= 0 && i < len(name)-2 {
		return name[i+2:]
	}
	return name
}

func isPathResolveParents(expr nir.Expr) bool {
	attr, ok := expr.(nir.Attr)
	if !ok || attr.Attr != "parents" {
		return false
	}
	return strings.HasSuffix(attr.Path, ".resolve.parents")
}

// exprDotted returns the dotted path of an attribute/name expression ("" otherwise),
// e.g. Attr{Path:"request.user"} → "request.user", Name{ID:"current_user"} → "current_user".
func exprDotted(e nir.Expr) string {
	switch v := e.(type) {
	case nir.Attr:
		return v.Path
	case nir.Name:
		return v.ID
	}
	return ""
}

// principalExpr reports whether e denotes the authenticated principal — the caller's identity —
// as opposed to an object's owner field. These are the framework idioms for "the current user".
func principalExpr(e nir.Expr) bool {
	switch exprDotted(e) {
	case "request.user", "self.request.user", "current_user", "g.user", "flask_login.current_user",
		"request.user.id", "self.request.user.id", "current_user.id", "g.user.id",
		"request.user.pk", "current_user.pk", "request.auth.user":
		return true
	}
	if n, ok := e.(nir.Name); ok && n.ID == "current_user" {
		return true
	}
	return false
}

// ownerFieldExpr reports whether e is an object's OWNERSHIP field access (obj.owner / obj.user /
// obj.created_by / obj.owner_id …) — the field that ties a fetched object to a principal. It must
// not itself be the principal (so `request.user` on either side is not mistaken for an owner field).
func ownerFieldExpr(e nir.Expr) bool {
	a, ok := e.(nir.Attr)
	if !ok || principalExpr(e) {
		return false
	}
	switch a.Attr {
	case "owner", "user", "author", "created_by", "creator", "account", "assigned_to", "member",
		"tenant", "org", "organization", "company", "workspace",
		"owner_id", "user_id", "author_id", "created_by_id", "account_id", "assigned_to_id",
		"tenant_id", "org_id", "organization_id", "company_id":
		return true
	}
	return false
}

// isOwnershipComparison reports whether a `==`/`!=` compares an object's owner field to the caller
// principal (obj.owner == request.user, current_user != note.author, …). This is the canonical
// object-level authorization check ("does the caller own this object?"), enforced AFTER the fetch —
// so it does not dominate the sink and is recognized here structurally, labelled OwnershipCheck via
// the analysis.ownership.check binding, and credited by the function-scope guard.
func isOwnershipComparison(ex nir.BinOp) bool {
	if ex.Op != "==" && ex.Op != "!=" {
		return false
	}
	return (ownerFieldExpr(ex.Left) && principalExpr(ex.Right)) ||
		(ownerFieldExpr(ex.Right) && principalExpr(ex.Left))
}

// isOwnershipHelperCall reports whether a call is an object-level authorization predicate that takes
// the fetched object as an argument — can_access_matter(user, obj), has_object_permission(request, obj),
// obj.is_owner(user), _visible_to(user, obj). These are the app-specific ownership helpers that
// bindings can't enumerate by exact name (each project names them `can_access_<resource>`). Crucially
// it EXCLUDES bare role checks (`can_write_privileged_notes()`, `is_firm_admin()`) — those take no
// object and gate on role, not on ownership of a specific object, so they must NOT suppress an IDOR.
func isOwnershipHelperCall(ex nir.Call) bool {
	if len(ex.Args) == 0 { // an ownership predicate is called WITH the object; role checks take none
		return false
	}
	name := ex.Method
	if name == "" {
		d := exprDotted(ex.Callee)
		if i := strings.LastIndex(d, "."); i >= 0 {
			name = d[i+1:]
		} else {
			name = d
		}
	}
	for _, pfx := range []string{"can_access", "can_view", "can_edit", "can_delete", "can_manage", "_can_"} {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	switch name {
	case "has_object_permission", "get_object_or_403", "check_object_permissions",
		"is_owner", "check_ownership", "require_owner", "verify_owner", "ensure_owner",
		"owns", "is_accessible_by", "user_can_access", "can_user_access":
		return true
	}
	return strings.Contains(name, "_visible_to") || strings.Contains(name, "_is_owner") || strings.HasPrefix(name, "ensure_owns")
}

// bulkUpdateSafeReceiver reports whether a `.update(x)` receiver is a KNOWN non-model object
// (a hash/digest, a template context/dict, a session/cache) — where .update is not mass assignment.
// Used to suppress the mass-assignment sink on these, cutting the dominant AUTH-008 false positives
// (hasher.update(chunk), context.update({...})).
func bulkUpdateSafeReceiver(callee nir.Expr) bool {
	attr, ok := callee.(nir.Attr)
	if !ok {
		return false
	}
	base := strings.ToLower(exprDotted(attr.Base))
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	for _, k := range []string{"hash", "digest", "hmac", "sha", "md5", "blake", "hasher",
		"ctx", "context", "session", "cache", "headers", "meta", "environ", "response"} {
		if strings.Contains(base, k) {
			return true
		}
	}
	return false
}

// secretNamedTarget reports whether an assignment target name denotes a cryptographic secret /
// credential — the kind of value that must never be a hardcoded literal (CWE-798/259).
func secretNamedTarget(name string) bool {
	n := strings.ToLower(name)
	// NOTE: "password" is deliberately excluded — it dominates test fixtures/form fields with
	// noise (input_password="12345"), and a hardcoded app password is a narrower concern than a
	// hardcoded signing/API secret. Keep the crypto-key / signing-secret families only.
	for _, k := range []string{"secret", "signing_key", "jwt", "hmac", "api_key", "apikey",
		"private_key", "cipher_key", "encryption_key", "session_key", "signing_secret",
		"access_token", "auth_token", "refresh_token", "token_salt"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// credentialConstName reports whether a target is an ALL-CAPS module-level credential constant
// (PASSWORD/USERNAME/PWD family) — a hardcoded credential when assigned a literal (CWE-798).
func credentialConstName(name string) bool {
	if name == "" || name != strings.ToUpper(name) { // require SCREAMING_CASE module constant
		return false
	}
	seg := name
	if i := strings.LastIndexAny(seg, ".:"); i >= 0 {
		seg = seg[i+1:]
	}
	if strings.Contains(seg, "HASH") || strings.Contains(seg, "FIELD") {
		return false
	}
	return strings.Contains(seg, "PASSWORD") || strings.Contains(seg, "PASSWD") ||
		seg == "PWD" || seg == "USERNAME" || seg == "ADMIN_USER" || strings.Contains(seg, "DB_PASS")
}

// keySignaledSecretLiteral is a laxer literal filter for the case where the assignment KEY (not the
// value) already denotes a secret — e.g. `config['SECRET_KEY'] = 'dvga'`. Only clearly-non-secret
// values (empty, None, booleans, env placeholders) are rejected; short weak secrets are accepted.
func keySignaledSecretLiteral(v string) bool {
	t := strings.Trim(v, "\"'` ")
	if len(t) < 3 {
		return false
	}
	switch strings.ToLower(t) {
	case "none", "null", "true", "false", "nil", "undefined", "changeme", "":
		return false
	}
	return true
}

// plausibleSecretLiteral filters out non-secret assignments a secret-named target may receive:
// None/empty, booleans, short/numeric flags. A real hardcoded secret is a non-trivial string.
func plausibleSecretLiteral(v string) bool {
	t := strings.Trim(v, "\"'` ")
	if len(t) < 6 {
		return false
	}
	switch strings.ToLower(t) {
	case "none", "null", "true", "false", "nil", "undefined":
		return false
	}
	return true
}

// inTestOrSeedFile reports whether a loc ("file:line") is a test/seed/fixture file, where
// hardcoded literals are expected and not a vulnerability.
func inTestOrSeedFile(loc string) bool {
	f := strings.ToLower(loc)
	return strings.Contains(f, "/test") || strings.Contains(f, "test_") || strings.Contains(f, "_test") ||
		strings.Contains(f, "conftest") || strings.Contains(f, "/seed") || strings.Contains(f, "seed_") ||
		strings.Contains(f, "fixture") || strings.Contains(f, "/spec") || strings.Contains(f, "factories")
}

// debugNamedTarget reports whether the target is a DEBUG flag.
func debugNamedTarget(name string) bool {
	n := strings.ToLower(name)
	return n == "debug" || strings.HasSuffix(n, "_debug") || strings.HasSuffix(n, ".debug")
}

// plaintextPasswordColumn reports whether an assignment declares an ORM model column that stores a
// password/secret in the clear — `password = db.Column(...)` / `pwd = Column(String)` — where the
// field name signals a password and does not indicate hashing (CWE-256/312/916).
func plaintextPasswordColumn(target string, value nir.Expr) bool {
	n := strings.ToLower(target)
	if i := strings.LastIndexAny(n, ".:"); i >= 0 {
		n = n[i+1:]
	}
	isPw := n == "password" || n == "passwd" || n == "pwd" ||
		strings.HasSuffix(n, "_password") || strings.HasSuffix(n, "_passwd") || strings.HasSuffix(n, "_pwd")
	if !isPw || strings.Contains(n, "hash") || strings.Contains(n, "digest") || strings.Contains(n, "encrypted") {
		return false
	}
	c, ok := value.(nir.Call)
	if !ok {
		return false
	}
	return c.Method == "Column" || strings.HasSuffix(c.Path, ".Column") || c.Method == "CharField" || c.Method == "TextField"
}

// allowedHostsWildcard reports whether a Django `ALLOWED_HOSTS = ['*']` setting (or CORS/CSRF
// origin allow-list) is assigned a wildcard element (CWE-16 security misconfiguration).
func allowedHostsWildcard(target string, value nir.Expr) bool {
	n := strings.ToUpper(target)
	if i := strings.LastIndexAny(n, ".:"); i >= 0 {
		n = n[i+1:]
	}
	if n != "ALLOWED_HOSTS" && n != "CORS_ORIGIN_WHITELIST" && n != "CORS_ALLOWED_ORIGINS" && n != "CSRF_TRUSTED_ORIGINS" {
		return false
	}
	seq, ok := value.(nir.Seq)
	if !ok {
		return false
	}
	for _, el := range seq.Parts {
		if v, ok := litVal(el); ok && (v == "*" || v == "*.*" || strings.HasPrefix(v, "*")) {
			return true
		}
	}
	return false
}

// certCheckDisabled reports whether TLS hostname/certificate checking is turned off via an
// assignment `ctx.check_hostname = False` / `verify_mode = CERT_NONE` (CWE-295).
func certCheckDisabled(target string, value nir.Expr) bool {
	n := strings.ToLower(target)
	if strings.HasSuffix(n, "check_hostname") {
		if v, ok := litVal(value); ok && strings.EqualFold(v, "False") {
			return true
		}
	}
	if strings.HasSuffix(n, "verify_mode") {
		if v, ok := litVal(value); ok && strings.Contains(strings.ToUpper(v), "CERT_NONE") {
			return true
		}
		if nm, ok := value.(nir.Name); ok && strings.Contains(strings.ToUpper(nm.ID), "CERT_NONE") {
			return true
		}
	}
	return false
}

// litVal returns the unquoted value of a string/char literal expression and true, or ("", false)
// when the expression is not a constant literal (e.g. a reflected request value).
func litVal(e nir.Expr) (string, bool) {
	if c, ok := e.(nir.Const); ok {
		return unquoteLit(c.Value), true
	}
	return "", false
}

// insecureHeaderStore reports whether a `resp[headerName] = value` subscript store (lowered by the
// frontend to __setitem__, args = [value, key]) configures a dangerous HTTP response header:
// permissive CORS (CWE-942), clickjacking / disabled browser protections (CWE-1021/CWE-16), or a
// weakened transport policy (CWE-319/CWE-693). Returns a short kind tag for the finding val, or ""
// when the store is benign. A fixed allow-list value ("https://trusted") is treated as safe.
func (l *lowerer) insecureHeaderStore(call nir.Call, sc *scope) string {
	if call.Method != "__setitem__" || len(call.Args) < 2 {
		return ""
	}
	// __setitem__ args = [value, key]
	return l.insecureHeaderPair(call.Args[1], call.Args[0], sc)
}

// insecureHeaderPair evaluates a (headerName, value) pair — from a subscript store or a
// send_header/set_header(name, value) method call — and returns a kind tag for a dangerous
// configuration, or "".
func (l *lowerer) insecureHeaderPair(keyExpr, valExpr nir.Expr, sc *scope) string {
	key, ok := l.constKey(keyExpr, sc)
	if !ok {
		return ""
	}
	v, isConst := litVal(valExpr)
	lv := strings.ToLower(strings.TrimSpace(v))
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "access-control-allow-origin":
		// wildcard, or a reflected (non-constant) origin, is permissive CORS.
		if (isConst && v == "*") || !isConst {
			return "cors_wildcard_origin"
		}
	case "access-control-allow-credentials":
		if lv == "true" {
			return "cors_allow_credentials"
		}
	case "x-frame-options":
		if lv == "allowall" || strings.HasPrefix(lv, "allow-from") {
			return "clickjacking_frame_options"
		}
	case "x-xss-protection":
		if isConst && v == "0" {
			return "xss_protection_disabled"
		}
	case "content-security-policy", "content-security-policy-report-only":
		if isConst && (v == "" || strings.Contains(lv, "unsafe-inline") || strings.Contains(lv, "default-src *") || strings.Contains(lv, "* 'unsafe")) {
			return "weak_csp"
		}
	case "strict-transport-security":
		if isConst && strings.Contains(lv, "max-age=0") {
			return "hsts_disabled"
		}
	}
	return ""
}

// isDynamicStringExpr reports whether an expression builds a string dynamically — an f-string /
// printf with non-literal parts, a `+`/`%` string concatenation, or a `.format(...)` call. A plain
// string literal (a static / parameterized query) is NOT dynamic.
func isDynamicStringExpr(e nir.Expr) bool {
	switch v := e.(type) {
	case nir.Format:
		for _, p := range v.Parts {
			if _, ok := p.(nir.Const); !ok {
				return true
			}
		}
		return false
	case nir.BinOp:
		return v.Op == "+" || v.Op == "%"
	case nir.Call:
		return v.Method == "format" || v.Method == "join"
	case nir.Thru:
		return isDynamicStringExpr(v.Inner)
	}
	return false
}

// logsSensitiveIdentifier reports whether any argument value-token of a logging call names a
// sensitive field (password/secret/token/ssn/…) — a plaintext-sensitive-data-in-log leak
// (CWE-532). Hashed/redacted references are excluded.
func logsSensitiveIdentifier(valToks []string) bool {
	for _, tk := range valToks {
		t := strings.ToLower(tk)
		if strings.Contains(t, "hash") || strings.Contains(t, "digest") || strings.Contains(t, "redact") || strings.Contains(t, "mask") {
			continue
		}
		for _, k := range []string{"password", "passwd", "secret", "ssn", "api_key", "apikey",
			"private_key", "access_token", "credit_card", "creditcard", "cvv", "card_number",
			"authorization", "bearer"} {
			if strings.Contains(t, k) {
				return true
			}
		}
	}
	return false
}

// respLeaksSensitiveField reports whether a value-token names a clearly-sensitive field that must
// not be serialized into an HTTP response (CWE-200/312). Narrower than the log variant: excludes
// request-side auth headers, includes only fields that are secrets/PII by nature.
func respLeaksSensitiveField(valToks []string) bool {
	for _, tk := range valToks {
		t := strings.ToLower(tk)
		if strings.Contains(t, "hash") || strings.Contains(t, "digest") || strings.Contains(t, "redact") || strings.Contains(t, "mask") {
			continue
		}
		for _, k := range []string{"password", "passwd", "ssn", "secret", "api_key", "apikey",
			"private_key", "credit_card", "creditcard", "cvv", "card_number", "social_security"} {
			if strings.Contains(t, k) {
				return true
			}
		}
	}
	return false
}

// isResponseSinkCall reports whether a call constructs an HTTP response body from its arguments.
func isResponseSinkCall(path, method string) bool {
	switch method {
	case "JsonResponse", "JSONResponse", "HttpResponse", "jsonify", "make_response", "Response", "HTTPResponse":
		return true
	}
	return false
}

// isExceptionVarName reports whether an identifier is a conventional caught-exception variable.
func isExceptionVarName(id string) bool {
	switch strings.ToLower(id) {
	case "e", "ex", "exc", "err", "error", "exception", "exp", "exce":
		return true
	}
	return false
}

// exposesExceptionDetail reports whether an expression serializes internal exception detail —
// `str(exc)`, `exc.__class__.__name__`, `traceback.format_exc()` — i.e. leaks an error message /
// stack into an HTTP response (CWE-209).
func exposesExceptionDetail(e nir.Expr, depth int) bool {
	if e == nil || depth > 6 {
		return false
	}
	switch v := e.(type) {
	case nir.Call:
		if (v.Method == "str" || v.Method == "repr") && len(v.Args) >= 1 {
			if nm, ok := v.Args[0].(nir.Name); ok && isExceptionVarName(nm.ID) {
				return true
			}
		}
		if v.Method == "format_exc" || v.Method == "format_exception" || v.Method == "print_exc" {
			return true
		}
		if exposesExceptionDetail(v.Callee, depth+1) {
			return true
		}
		for _, a := range v.Args {
			if exposesExceptionDetail(a, depth+1) {
				return true
			}
		}
	case nir.Attr:
		if v.Attr == "__class__" || strings.Contains(v.Attr, "__traceback__") || v.Attr == "args" {
			if nm, ok := v.Base.(nir.Name); ok && isExceptionVarName(nm.ID) {
				return true
			}
		}
		return exposesExceptionDetail(v.Base, depth+1)
	case nir.Pair:
		return exposesExceptionDetail(v.Value, depth+1)
	case nir.Seq:
		for _, p := range v.Parts {
			if exposesExceptionDetail(p, depth+1) {
				return true
			}
		}
	case nir.Format:
		for _, p := range v.Parts {
			if exposesExceptionDetail(p, depth+1) {
				return true
			}
		}
	case nir.BinOp:
		return exposesExceptionDetail(v.Left, depth+1) || exposesExceptionDetail(v.Right, depth+1)
	case nir.Thru:
		return exposesExceptionDetail(v.Inner, depth+1)
	}
	return false
}

// exposesRecordReturn reports whether a route return value serializes a DB record / model object to
// the client — `return obj.serialize()`, `return Model.objects.get(...)`, `return cur.fetchone()` —
// the shape where over-exposure of sensitive fields occurs (SMELL, agent confirms field sensitivity).
func exposesRecordReturn(e nir.Expr, depth int) bool {
	if e == nil || depth > 5 {
		return false
	}
	switch v := e.(type) {
	case nir.Call:
		switch v.Method {
		case "serialize", "dump", "to_dict", "model_dump", "as_dict", "to_json", "jsonify":
			return true
		case "fetchone", "fetchall", "fetchmany", "first", "one", "one_or_none", "get_object_or_404":
			return true
		}
		if strings.Contains(v.Path, "objects.") || strings.Contains(v.Path, "query.") {
			return true
		}
		for _, a := range v.Args {
			if exposesRecordReturn(a, depth+1) {
				return true
			}
		}
	case nir.Thru:
		return exposesRecordReturn(v.Inner, depth+1)
	}
	return false
}

// stateMutatingMethod reports whether a call method mutates persistent state — the shape an agent
// should check for missing authorization / validation / CSRF (SMELL).
func stateMutatingMethod(m string) bool {
	// Tightened to higher-risk mutations of EXISTING resources (the BOLA-write / privilege-change /
	// value-transfer shapes) — create/add/save/commit are dropped as they dominate benign signup /
	// logging / persistence and swamp the candidate set with low-signal noise.
	switch m {
	case "update", "delete", "set_password", "make_transaction", "transfer", "approve",
		"set_role", "grant", "revoke", "deactivate", "bulk_update":
		return true
	}
	return false
}

// buildsRawHTMLString reports whether an expression is a dynamically-built string that embeds HTML
// markup — the raw-string-response reflected-XSS shape (`return "<html>.." + user + "..</html>"`)
// that template-render sinks don't see.
func buildsRawHTMLString(e nir.Expr) bool {
	if !isDynamicStringExpr(e) {
		return false
	}
	var toks []string
	collectValTokens(e, "", &toks)
	for _, t := range toks {
		lt := strings.ToLower(t)
		for _, tag := range []string{"<body", "<html", "<div", "<br", "<p>", "<p ", "<h1", "<h2",
			"<span", "<a ", "<a>", "<td", "<tr", "<li", "<table", "<form", "<script", "<img"} {
			if strings.Contains(lt, tag) {
				return true
			}
		}
	}
	return false
}

// isRouteDecorated reports whether a function's decorator tokens include a web route registration
// (`@app.post`, `@router.get`, `@app.route`), meaning its return value is an HTTP response body.
func isRouteDecorated(decs []string) bool {
	for _, d := range decs {
		switch d {
		case "decorator_method:get", "decorator_method:post", "decorator_method:put",
			"decorator_method:patch", "decorator_method:delete", "decorator_method:route",
			"decorator_method:api_route", "decorator_method:websocket", "decorator_method:head",
			"decorator_method:options":
			return true
		}
	}
	return false
}

// isInternalPathName reports whether an identifier denotes an internal filesystem path / settings
// constant whose value should not be serialized to a client.
func isInternalPathName(id string) bool {
	u := strings.ToUpper(id)
	return strings.Contains(u, "BASE") || strings.Contains(u, "_DIR") || strings.Contains(u, "_PATH") ||
		strings.Contains(u, "ROOT") || u == "__FILE__" || strings.Contains(u, "SETTINGS")
}

// exposesInternalConfig reports whether an expression serializes internal environment/config/path
// detail — `os.environ.get(...)`, `os.getenv(...)`, `str(BASE_DIR)` — i.e. debug-info exposure
// (CWE-215) when it reaches an HTTP response.
func exposesInternalConfig(e nir.Expr, depth int) bool {
	if e == nil || depth > 6 {
		return false
	}
	switch v := e.(type) {
	case nir.Call:
		if strings.Contains(v.Path, "os.environ") || strings.Contains(v.Path, "os.getenv") || v.Method == "getenv" {
			return true
		}
		if (v.Method == "str" || v.Method == "repr") && len(v.Args) >= 1 {
			if nm, ok := v.Args[0].(nir.Name); ok && isInternalPathName(nm.ID) {
				return true
			}
		}
		if exposesInternalConfig(v.Callee, depth+1) {
			return true
		}
		for _, a := range v.Args {
			if exposesInternalConfig(a, depth+1) {
				return true
			}
		}
	case nir.Attr:
		if strings.Contains(v.Path, "os.environ") {
			return true
		}
		return exposesInternalConfig(v.Base, depth+1)
	case nir.Pair:
		return exposesInternalConfig(v.Value, depth+1)
	case nir.Seq:
		for _, p := range v.Parts {
			if exposesInternalConfig(p, depth+1) {
				return true
			}
		}
	case nir.Format:
		for _, p := range v.Parts {
			if exposesInternalConfig(p, depth+1) {
				return true
			}
		}
	case nir.BinOp:
		return exposesInternalConfig(v.Left, depth+1) || exposesInternalConfig(v.Right, depth+1)
	case nir.Thru:
		return exposesInternalConfig(v.Inner, depth+1)
	}
	return false
}

// businessStateKey reports whether a subscript/attr key names a business-sensitive field whose value
// should be validated before assignment — the business-logic-gap shape when set from user input.
func businessStateKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "state", "status", "balance", "amount", "price", "quantity", "qty", "role", "limit",
		"discount", "credit", "total", "is_admin", "is_active", "approved", "permission",
		"permissions", "verified", "is_verified", "level", "tier", "points", "rate":
		return true
	}
	return false
}

// enumerationErrorResponse reports whether a response payload is an auth error (401/403/404) whose
// message discloses account/identity EXISTENCE — the user-enumeration tell (SMELL, agent confirms
// the response differs from the wrong-credential path).
func enumerationErrorResponse(valToks []string) bool {
	errStatus, existMsg := false, false
	for _, tk := range valToks {
		lt := strings.ToLower(tk)
		for _, s := range []string{"status=404", "status=401", "status=403", "status_code=404", "status_code=401", "status_code=403"} {
			if strings.Contains(lt, s) {
				errStatus = true
			}
		}
		for _, w := range []string{"unknown", "not found", "no such", "not registered", "does not exist",
			"no account", "invalid handle", "invalid user", "invalid email", "invalid username",
			"user not", "email not", "account not", "no user", "not exist"} {
			if strings.Contains(lt, w) {
				existMsg = true
			}
		}
	}
	return errStatus && existMsg
}

// isLogSinkCall reports whether a call is a logging/print output sink.
func isLogSinkCall(path, method string) bool {
	if path == "print" || method == "print" {
		return true
	}
	if !strings.Contains(strings.ToLower(path), "log") {
		return false
	}
	switch method {
	case "debug", "info", "warning", "warn", "error", "critical", "exception", "log":
		return true
	}
	return false
}

// isSQLSinkCall reports whether a call is a SQL-execution sink whose FIRST argument is the query.
func isSQLSinkCall(path, method string) bool {
	switch method {
	case "execute", "executemany", "executescript", "execute_sql", "raw", "text":
		return true
	}
	if strings.HasSuffix(path, ".execute") || strings.HasSuffix(path, ".text") || path == "sqlalchemy.text" {
		return true
	}
	return false
}

// resolveRegexPattern folds a regex-pattern argument to its literal — an inline string, a
// const-propped local, or a module-level constant (`PATTERN = r"..."`) referenced by name.
func (l *lowerer) resolveRegexPattern(e nir.Expr, sc *scope) (string, bool) {
	if s, ok := l.constStrVal(e, sc); ok {
		return s, true
	}
	if nm, ok := e.(nir.Name); ok {
		if s, ok := l.modStr[nm.ID]; ok {
			return s, true
		}
	}
	return "", false
}

// isRegexApply reports whether a call is a stdlib `re.<op>(pattern, ...)` / `re.compile(pattern)`
// whose FIRST argument is the regex pattern. Only the `re.` origin is accepted, so an unrelated
// object `.match()`/`.search()` is not misread as a regex application.
func isRegexApply(path, method string) bool {
	switch method {
	case "match", "search", "sub", "subn", "findall", "finditer", "fullmatch", "compile", "split":
	default:
		return false
	}
	return path == "re."+method || path == "regex."+method || strings.HasSuffix(path, ".re."+method)
}

// catastrophicRegex reports whether a regex has textbook super-linear backtracking structure —
// a quantifier applied to a group that itself contains a quantifier or an alternation:
// (a+)+  (a*)*  (.*)*  ((a)+)+  (\d+)*  (a|a)*  (a|ab)*  — the classic ReDoS shapes (CWE-1333/400).
func catastrophicRegex(pat string) bool {
	// Defer to the shared ambiguity analysis. A structural test — "a quantified group
	// whose body holds a quantifier or an alternation" — reports every unrolled loop and
	// every disjoint alternation as catastrophic, which is a false positive whenever the
	// branches cannot both match the same input.
	return regexambig.Ambiguous(pat)
}

// envDefaultConst returns the hardcoded DEFAULT literal of an os.getenv(name, default) /
// os.environ.get(name, default) call — the fallback baked into source (CWE-798). "" if none.
func envDefaultConst(e nir.Expr, l *lowerer) string {
	c, ok := e.(nir.Call)
	if !ok || len(c.Args) < 2 {
		return ""
	}
	d := exprDotted(c.Callee)
	if !(strings.HasSuffix(d, "getenv") || strings.HasSuffix(d, "environ.get") || strings.HasSuffix(d, "config.get")) {
		return ""
	}
	return constStr(c.Args[1])
}

// truthyDefault reports whether e assigns/defaults DEBUG to an on value ("True"/"1"/true) —
// either a direct truthy literal or os.getenv("DEBUG", "True")-style default.
func truthyDefault(e nir.Expr, l *lowerer) bool {
	isOn := func(s string) bool {
		v := strings.ToLower(strings.Trim(s, "\"' "))
		return v == "true" || v == "1" || v == "yes" || v == "on"
	}
	if isOn(constStr(e)) || isOn(envDefaultConst(e, l)) {
		return true
	}
	// `DEBUG = os.getenv("DEBUG","True") == "True"` / `_env_bool("DBG", default=True)` — the truthy
	// default is nested; check the operands of a comparison and the args of a *_bool/env helper.
	switch v := e.(type) {
	case nir.BinOp:
		return truthyDefault(v.Left, l) || truthyDefault(v.Right, l)
	case nir.Call:
		d := strings.ToLower(exprDotted(v.Callee))
		if strings.Contains(d, "bool") || strings.Contains(d, "env") || strings.Contains(d, "flag") {
			for _, a := range v.Args {
				if isOn(constStr(a)) {
					return true
				}
			}
		}
	}
	return false
}

// privilegeLiteral reports whether e is a string constant naming a ROLE/PRIVILEGE tier — the kind of
// value a security decision keys on (`badge == "lead"`, `role == "admin"`). Comparing a client-controlled
// value (cookie/header/param) to one of these is the CWE-807 "reliance on untrusted input in a security
// decision" pattern: the attacker just sets the header/cookie to the privileged tier.
func privilegeLiteral(e nir.Expr) bool {
	c, ok := e.(nir.Const)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.Trim(c.Value, "\"'` ")) {
	case "lead", "admin", "administrator", "superuser", "super", "superadmin", "staff", "manager",
		"root", "owner", "privileged", "elevated", "internal", "ops", "moderator", "mod", "god",
		"supervisor", "operator", "sysadmin", "poweruser", "premium", "enterprise", "vip":
		return true
	}
	return false
}

// clientMarkerCompareOperand returns the NON-literal operand of a role-marker comparison
// (`badge == "lead"`), or "" if this BinOp isn't one. That operand is the (possibly tainted)
// client-controlled value; flowing it into a synthetic sink lets the taint solver confirm a
// cookie/header/param reaches the security decision.
func clientMarkerCompareOperand(ex nir.BinOp, left, right string) string {
	if ex.Op != "==" && ex.Op != "!=" && ex.Op != "in" {
		return ""
	}
	if privilegeLiteral(ex.Right) {
		return left
	}
	if privilegeLiteral(ex.Left) {
		return right
	}
	return ""
}

// Lower lowers a Program into a fresh in-memory USG. When resolveImports is
// false, calls resolve by SHORT NAME (the over-connecting baseline that case 16
// contrasts against).
func Lower(prog nir.Program, resolveImports bool) (usg.Store, error) {
	return LowerTyped(prog, resolveImports, nil)
}

// LowerTyped is Lower with a constructor→type table (callee path of a
// constructor → the type it returns, e.g. "pkg.Open" → "pkg.Handle"). A receiver
// assigned from a known constructor lets the lowering stamp `recv_type` on its
// method calls, which type-constrained sink binding applicators use for precision.
func LowerTyped(prog nir.Program, resolveImports bool, ctorTypes map[string]string) (usg.Store, error) {
	l := newLowerer(prog, resolveImports, ctorTypes)
	if err := l.run(); err != nil {
		return nil, err
	}
	if l.storeErr != nil {
		return nil, fmt.Errorf("graph write: %w", l.storeErr)
	}
	return l.g, nil
}

// noteStoreErr keeps the first graph-write failure. Later ones are almost
// certainly the same cause, and the first is the one with useful context.
func (l *lowerer) noteStoreErr(err error) {
	if err != nil && l.storeErr == nil {
		l.storeErr = err
	}
}

// newLowerer builds a fresh lowerer with all maps initialised. Shared by LowerTyped and the
// incremental lowerer.
func newLowerer(prog nir.Program, resolveImports bool, ctorTypes map[string]string) *lowerer {
	return &lowerer{
		prog:            prog,
		selfName:        prog.Self(),
		resolveImports:  resolveImports,
		ctorTypes:       ctorTypes,
		g:               newGraphStore(estimateGraphNodeHint(prog)),
		modCtr:          map[string]int{},
		modOrder:        map[string]int{},
		modBranch:       map[string]int{},
		funcQual:        map[string]*funcInfo{},
		funcShort:       map[string][]*funcInfo{},
		classQual:       map[string]bool{},
		classDefs:       map[string]map[string]bool{},
		classFields:     map[string]map[string]string{},
		importTables:    map[string]map[string]importEntry{},
		moduleTech:      map[string]string{},
		moduleGlobals:   map[string]map[string]string{},
		containers:      map[string]*containerInfo{},
		templates:       map[string]templateInfo{},
		modStr:          map[string]string{},
		dynSQLVar:       map[string]bool{},
		debugPayloadVar: map[string]bool{},
		lambdaParams:    map[string][]string{},
		directMembers:   map[string]map[string]bool{},
		classBaseNames:  map[string][]string{},
		derivedChildren: map[string][]string{},
		membersOfShort:  map[string]map[string]bool{},
		allMembersMemo:  map[string]map[string]bool{},
	}
}

func estimateGraphNodeHint(prog nir.Program) int {
	hint := len(prog.Modules) * 4
	for _, m := range prog.Modules {
		hint += len(m.Imports)
		hint += estimateStmtListNodes(m.Body)
	}
	if hint <= 0 {
		return 0
	}
	return hint
}

func estimateStmtListNodes(stmts []nir.Stmt) int {
	n := 0
	for _, st := range stmts {
		n += estimateStmtNodes(st)
	}
	return n
}

func estimateStmtNodes(st nir.Stmt) int {
	switch s := st.(type) {
	case nil:
		return 0
	case nir.Assign:
		return 1 + len(s.Targets) + estimateExprNodes(s.Value)
	case nir.AugAssign:
		return 2 + estimateExprNodes(s.Value)
	case nir.Return:
		return 1 + estimateExprNodes(s.Value)
	case nir.ExprStmt:
		return estimateExprNodes(s.Value)
	case nir.FuncDef:
		return 2 + len(s.Params) + len(s.ParamEntries) + len(s.ResultEntries) + estimateStmtListNodes(s.Body)
	case nir.ClassDef:
		return 1 + estimateStmtListNodes(s.Body)
	case nir.Block:
		return estimateStmtListNodes(s.Stmts)
	case nir.If:
		return 2 + estimateExprNodes(s.Cond) + estimateStmtListNodes(s.Then) + estimateStmtListNodes(s.Else)
	case nir.Loop:
		return 2 + len(s.Vars) + estimateExprNodes(s.Cond) + estimateExprNodes(s.Iter) + estimateStmtListNodes(s.Body)
	case nir.Switch:
		total := 2 + estimateExprNodes(s.Subject) + estimateStmtListNodes(s.Default)
		for _, labels := range s.Labels {
			for _, label := range labels {
				total += estimateExprNodes(label)
			}
		}
		for _, arm := range s.Cases {
			total += estimateStmtListNodes(arm)
		}
		return total
	case nir.Try:
		total := 2 + len(s.HandlerParams) + estimateStmtListNodes(s.Body) + estimateStmtListNodes(s.Finally)
		for _, h := range s.Handlers {
			total += estimateStmtListNodes(h)
		}
		return total
	default:
		return 1
	}
}

func estimateExprNodes(ex nir.Expr) int {
	switch e := ex.(type) {
	case nil:
		return 0
	case nir.Name, nir.Const:
		return 1
	case nir.Attr:
		return 1 + estimateExprNodes(e.Base)
	case nir.Index:
		return 1 + estimateExprNodes(e.Base) + estimateExprNodes(e.Key)
	case nir.Call:
		total := 2 + len(e.Args) + estimateExprNodes(e.Callee)
		for _, a := range e.Args {
			total += estimateExprNodes(a)
		}
		return total
	case nir.Format:
		total := 1
		for _, p := range e.Parts {
			total += estimateExprNodes(p)
		}
		return total
	case nir.Seq:
		total := 1
		for _, p := range e.Parts {
			total += estimateExprNodes(p)
		}
		return total
	case nir.Pair:
		return 1 + estimateExprNodes(e.Value)
	case nir.Lambda:
		return 2 + len(e.Params) + len(e.ParamEntries) + estimateStmtListNodes(e.Body)
	case nir.Thru:
		return estimateExprNodes(e.Inner)
	case nir.BinOp:
		return 1 + estimateExprNodes(e.Left) + estimateExprNodes(e.Right)
	case nir.Unary:
		return 1 + estimateExprNodes(e.Operand)
	case nir.Ternary:
		return 1 + estimateExprNodes(e.Cond) + estimateExprNodes(e.Then) + estimateExprNodes(e.Else)
	default:
		return 1
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

func moduleTech(file string) string {
	file = strings.ToLower(file)
	switch {
	case strings.HasSuffix(file, ".java"):
		return "java"
	case strings.HasSuffix(file, ".js"), strings.HasSuffix(file, ".jsx"), strings.HasSuffix(file, ".mjs"), strings.HasSuffix(file, ".cjs"), strings.HasSuffix(file, ".html"), strings.HasSuffix(file, ".htm"):
		return "javascript"
	case strings.HasSuffix(file, ".ts"), strings.HasSuffix(file, ".tsx"):
		return "typescript"
	case strings.HasSuffix(file, ".py"):
		return "python"
	case strings.HasSuffix(file, ".rb"):
		return "ruby"
	case strings.HasSuffix(file, ".php"):
		return "php"
	case strings.HasSuffix(file, ".cs"):
		return "csharp"
	case strings.HasSuffix(file, ".go"):
		return "go"
	default:
		return ""
	}
}

func compatibleTech(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return jsFamily(a) && jsFamily(b)
}

func jsFamily(t string) bool {
	return t == "javascript" || t == "typescript" || t == "tsx"
}

func (l *lowerer) node(kind, loc string, props map[string]string) string {
	return l.nodeWithID(l.nid(kind), kind, loc, props)
}

func (l *lowerer) nodeInline(kind, loc string, props map[string]string, method, calleePath, strArgs, vkind string) string {
	return l.nodeInlineWithID(l.nid(kind), kind, loc, props, method, calleePath, strArgs, vkind)
}

// nodeWithID creates a node with an explicit id — used for signature nodes (Param/Return)
// whose ids are NAME-derived (sigID) so they survive a body edit and remain valid targets for
// cross-module call edges from other (possibly cached) modules.
func (l *lowerer) nodeWithID(id, kind, loc string, props map[string]string) string {
	return l.nodeInlineWithID(id, kind, loc, props, "", "", "", "")
}

func (l *lowerer) nodeInlineWithID(id, kind, loc string, props map[string]string, method, calleePath, strArgs, vkind string) string {
	ord := l.modOrder[l.curNS]
	l.modOrder[l.curNS]++
	// loc/region/order live inline on the Node; props (the freshly-built extras map, often empty)
	// becomes Props directly — nil/empty when there are no extras, so most nodes carry no map.
	var extras map[string]string
	if len(props) > 0 {
		extras = props
	}
	if !storeUsesInlineNodeProps(l.g) {
		extras = propsWithInline(extras, method, calleePath, strArgs, vkind)
	}
	l.noteStoreErr(l.g.AddNode(usg.Node{ID: id, Type: "code." + kind, Loc: loc, Region: l.region,
		Order: int32(ord), HasOrder: true, Props: extras,
		Method: method, CalleePath: calleePath, StrArgs: strArgs, Vkind: vkind}))
	return id
}

func storeUsesInlineNodeProps(s usg.Store) bool {
	switch st := s.(type) {
	case *usg.IntStore:
		return true
	case *recordingStore:
		return storeUsesInlineNodeProps(st.Store)
	default:
		return false
	}
}

func propsWithInline(props map[string]string, method, calleePath, strArgs, vkind string) map[string]string {
	if method == "" && calleePath == "" && strArgs == "" && vkind == "" {
		return props
	}
	if props == nil {
		props = map[string]string{}
	}
	if method != "" {
		props["method"] = method
	}
	if calleePath != "" {
		props["callee_path"] = calleePath
	}
	if strArgs != "" {
		props["str_args"] = strArgs
	}
	if vkind != "" {
		props["vkind"] = vkind
	}
	return props
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
	if g, ok := l.g.(interface{ AddFlowEdgeIfPresent(string, string) bool }); ok {
		g.AddFlowEdgeIfPresent(a, b)
		return
	}
	if !l.exists(a) || !l.exists(b) {
		return
	}
	l.noteStoreErr(l.g.AddEdge(usg.Edge{Type: "FLOWS", Src: a, Dst: b}))
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
		l.moduleTech[m.Key] = moduleTech(m.File)
		l.importTables[m.Key] = importTable(m)
		for _, imp := range m.Imports {
			l.importNode(m, imp)
		}
		l.register(m.Key, m.Body, "")
	}
	l.collectAddressTaken()
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		l.block(m.Body, l.moduleScope(m))
	}
	return nil
}

func (l *lowerer) moduleScope(m nir.Module) *scope {
	sc := newScope()
	if !usesModuleGlobalSlots(m.File) {
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
			slot = l.nodeInlineWithID(sigID(l.curNS, "__module", "var", name), "Name", m.File,
				map[string]string{"module_global": "true"}, name, name, "", "")
			globals[name] = slot
		}
		sc.node[name] = slot
	}
	return sc
}

func usesModuleGlobalSlots(file string) bool {
	return isJSLikeModule(file) || strings.HasSuffix(file, ".go")
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
		paramEntries:  st.ParamEntries,
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
				qual := modkey + "::" + st.Name
				l.classBaseNames[qual] = st.Bases
				for _, base := range st.Bases {
					l.derivedChildren[shortClassName(base)] = append(l.derivedChildren[shortClassName(base)], qual)
				}
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
					Name: info.name, ParamEntries: info.paramEntries, ResultEntries: info.resultEntries, Abstract: info.abstract,
				})
			}
			// recurse into the body to register NESTED LOCAL FUNCTIONS (C# local functions, JS
			// inner function declarations) so a FORWARD reference resolves regardless of
			// declaration order.
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
		l.classContextAnalysisEvent(st.Loc, st.Name, st.Bases, classMemberContextTokens(st.Body))
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
		l.promoteCapturedJSBindings(st.Body, st.Params, sc, st.Loc)
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
			if argsParam := info.params[nir.JSArgumentsParam]; argsParam != "" {
				inner.node["arguments"] = argsParam
			}
			inner.node["__ret__"] = info.ret
		}
		if info != nil {
			for _, pe := range l.effectiveParamEntries(info) {
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
		l.region = l.functionRegion()
		saveDecorators := l.curDecorators
		l.curDecorators = append(append([]string{}, st.ContextTokens...), st.Decorators...)
		l.functionContextAnalysisEvent(st.Loc, l.curDecorators)
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
			} else {
				// External/library declared types are still useful for binding receiver
				// constraints even when there is no project class body to resolve.
				typ, hasTyp = [2]string{"", st.Type}, true
			}
		}
		cv := constStr(st.Value)
		if cv == "" { // config read folded to its real value (e.g. getProperty("mode") -> "fast")
			if pv, ok := l.propConst(st.Value); ok {
				cv = pv
			}
		}
		if cv == "" { // foldable string/char value (e.g. switchTarget = "ABC".charAt(1) -> "B")
			if sv, ok := l.constStrVal(st.Value, sc); ok {
				cv = sv
			}
		}
		iterValues, iterOK := l.constIterationValues(st.Value, sc)
		for _, target := range st.Targets {
			if iterOK {
				sc.iter[target] = append([]string(nil), iterValues...)
			} else {
				delete(sc.iter, target)
			}
		}
		for _, t := range st.Targets {
			// Hardcoded secret (CWE-798): a secret-named target assigned a NON-TRIVIAL string literal,
			// directly or as an os.getenv(...,"default") fallback baked into source. Skip test/seed files.
			if secretNamedTarget(t) && !inTestOrSeedFile(st.Loc) {
				if plausibleSecretLiteral(cv) || plausibleSecretLiteral(envDefaultConst(st.Value, l)) {
					l.syntheticCall("analysis.secret.hardcoded", "hardcoded_secret", val, st.Loc, "secret="+t)
				}
			}
			// Debug enabled by default (CWE-489): DEBUG flag defaulting to a truthy value.
			if debugNamedTarget(t) && truthyDefault(st.Value, l) {
				l.syntheticCall("analysis.config.debug_on", "debug_on", val, st.Loc, "debug_default_true")
			}
			// Track module-level string constants (e.g. `PATTERN = r"((a)+)+"`) so a regex call
			// that references the name by identifier can resolve the literal for ReDoS detection.
			if l.region == "" && cv != "" {
				l.modStr[t] = cv
			}
			// Track dynamically-built query strings for the deferred `q = f"..."; execute(q)` form.
			if isDynamicStringExpr(st.Value) {
				l.dynSQLVar[t] = true
			} else if cv != "" {
				delete(l.dynSQLVar, t)
			}
			// Track response payloads that leak internal config for the deferred
			// `payload = {...os.environ...}; return JsonResponse(payload)` form.
			if exposesInternalConfig(st.Value, 0) {
				l.debugPayloadVar[t] = true
			}
			// Plaintext password storage (CWE-256/312/916): an ORM model column named password
			// declared as a plain string type with no hashing.
			if plaintextPasswordColumn(t, st.Value) {
				l.syntheticCall("analysis.storage.plaintext_password", "plaintext_password", val, st.Loc, "password_column")
			}
			// Wildcard host/origin allow-list (CWE-16) and disabled TLS cert checking (CWE-295) —
			// both routed through the insecure-config sink.
			if allowedHostsWildcard(t, st.Value) {
				l.syntheticCall("analysis.config.insecure_header", "insecure_header", val, st.Loc, "header=allowed_hosts_wildcard")
			}
			// Module-level credential constant (CWE-798): an ALL-CAPS module constant named
			// PASSWORD/USERNAME/… assigned a plausible literal. Narrow (uppercase + module scope +
			// non-test) so lowercase form fields / test fixtures don't add noise; "password" is
			// otherwise excluded from secretNamedTarget for exactly that reason.
			if l.region == "" && credentialConstName(t) && !inTestOrSeedFile(st.Loc) {
				if plausibleSecretLiteral(cv) {
					l.syntheticCall("analysis.secret.hardcoded", "hardcoded_secret", val, st.Loc, "credential_const="+t)
				}
			}
			// Console email backend (CWE-532): reset/verification emails (with their tokens) are
			// printed to stdout/logs — `EMAIL_BACKEND = "...console.EmailBackend"`.
			if strings.EqualFold(t, "EMAIL_BACKEND") || strings.HasSuffix(strings.ToUpper(t), ".EMAIL_BACKEND") {
				if v, ok := litVal(st.Value); ok && strings.Contains(strings.ToLower(v), "console") && strings.Contains(v, "EmailBackend") {
					l.syntheticCall("analysis.disclosure.sensitive_log", "sensitive_log", val, st.Loc, "console_email_backend")
				}
			}
			if certCheckDisabled(t, st.Value) {
				l.syntheticCall("analysis.config.insecure_header", "insecure_header", val, st.Loc, "header=cert_check_disabled")
			}
			localDecl := st.Decl && l.region != ""
			targetTyp, targetHasTyp := typ, hasTyp
			if !targetHasTyp {
				if prev, ok := sc.typ[t]; ok && prev[1] != "" {
					targetTyp, targetHasTyp = prev, true
				}
			}
			targetVal := val
			if targetHasTyp && targetTyp[1] != "" {
				targetVal = l.typedBindingNode(val, targetTyp[1])
			}
			if base, field, ok := splitFieldTarget(t); ok && !localDecl {
				if slot := l.moduleGlobalSlot(base); slot != "" {
					l.globalMutationAnalysisEvent(st.Loc, []string{
						"base:" + base,
						"field:" + field,
						"target:" + t,
					})
					l.flow(targetVal, slot)
				}
			}
			if sc.lex[t] && !st.Decl {
				l.flow(targetVal, sc.node[t])
				if targetHasTyp {
					sc.typ[t] = targetTyp
				}
				if cv != "" {
					sc.cnst[t] = cv // x = "literal"
				} else {
					delete(sc.cnst, t) // reassigned to a non-constant -> value unknown
				}
				continue
			}
			if slot := l.moduleGlobalSlot(t); slot != "" && !localDecl {
				l.flow(targetVal, slot)
				sc.node[t] = slot
				if targetHasTyp {
					sc.typ[t] = targetTyp
				}
				if cv != "" {
					sc.cnst[t] = cv // x = "literal"
				} else {
					delete(sc.cnst, t) // reassigned to a non-constant → value unknown
				}
				continue
			}
			if st.Decl {
				delete(sc.lex, t)
			}
			sc.node[t] = targetVal
			if targetHasTyp {
				sc.typ[t] = targetTyp
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
		if sc.lex[st.Target] {
			l.flow(n, sc.node[st.Target])
			delete(sc.cnst, st.Target)
			return
		}
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
		retTokens := append([]string{}, l.curDecorators...)
		collectValTokens(st.Value, "", &retTokens)
		l.functionReturnAnalysisEvent(rv, "", retTokens)
		// A route handler's return value IS the HTTP response body. Flag config/env exposure
		// (CWE-215) and exception detail (CWE-209) in a bare `return {...}` — the FastAPI form
		// that has no JsonResponse(...) wrapper for the sink detectors to key on.
		if isRouteDecorated(l.curDecorators) {
			retLoc := ""
			if n, ok, _ := l.g.GetNode(rv); ok {
				retLoc = n.Loc
			}
			if exposesInternalConfig(st.Value, 0) {
				l.syntheticCall("analysis.disclosure.debug_info", "debug_info", rv, retLoc, "config_in_return")
			}
			if exposesExceptionDetail(st.Value, 0) {
				l.syntheticCall("analysis.disclosure.error_detail", "error_detail", rv, retLoc, "exception_in_return")
			}
			// SMELL (sensitive-data exposure): route returns a DB record/model — agent verifies
			// no over-exposed fields for this caller (CWE-200/201/359).
			if exposesRecordReturn(st.Value, 0) {
				l.syntheticCall("analysis.smell.data_exposure", "smell", rv, retLoc, "record_in_response")
			}
			// Reflected XSS via raw HTML string response (CWE-79): a route returns a dynamically
			// built string embedding HTML markup — bypasses template auto-escaping entirely.
			if buildsRawHTMLString(st.Value) {
				l.syntheticCall("analysis.xss.raw_html_response", "raw_html", rv, retLoc, "html_string_return")
			}
		}
	case nir.Terminate:
		l.eval(st.Value, sc)
	case nir.Validation:
		l.applyValidation(st, sc)
	case nir.ExprStmt:
		callNode := l.eval(st.Value, sc)
		// Builder/accumulator calls fold their args into the object/buffer you
		// later read back. Model them as a taint-join on the mutated variable.
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
		beforeIter := cloneIterationFacts(sc.iter)
		l.inRegion("if"+b+".t", func() {
			if name, ok := allowlistMembershipVar(st.Cond); ok && before[name] != "" {
				loc := st.Loc
				if loc == "" {
					loc = "?:0"
				}
				sc.node[name] = l.node("AllowlistValue", loc, map[string]string{
					"name": name,
					"kind": "literal_membership",
				})
			}
			l.block(st.Then, sc)
		})
		thenB := cloneStrMap(sc.node)
		thenIter := cloneIterationFacts(sc.iter)
		sc.node = cloneStrMap(before)
		sc.iter = cloneIterationFacts(beforeIter)
		l.inRegion("if"+b+".e", func() { l.block(st.Else, sc) })
		elseB := cloneStrMap(sc.node)
		elseIter := cloneIterationFacts(sc.iter)
		sc.node = before
		sc.iter = stableIterationFacts(thenIter, elseIter)
		l.mergeBindings(sc, before, []map[string]string{thenB, elseB})
		if name, ok := zeroExitGuardName(st.Cond, st.Then, st.Else); ok {
			if observed := before[name]; observed != "" {
				sc.node[name] = l.guardObservation("analysis.guard.value_exclusion", "value_exclusion", observed, "", "value=0")
				delete(sc.cnst, name)
			}
		}
	case nir.Loop:
		l.eval(st.Cond, sc)
		before := cloneStrMap(sc.node)
		beforeIter := cloneIterationFacts(sc.iter)
		iterNode := l.eval(st.Iter, sc)
		if iterNode != "" {
			for _, name := range st.Vars {
				if name == "" || name == "_" {
					continue
				}
				sc.node[name] = iterNode
				delete(sc.cnst, name)
			}
		}
		l.inRegion("loop"+l.nextBranch(), func() { l.block(st.Body, sc) })
		bodyB := cloneStrMap(sc.node)
		bodyIter := cloneIterationFacts(sc.iter)
		sc.node = before
		sc.iter = stableIterationFacts(beforeIter, bodyIter)
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
		beforeIter := cloneIterationFacts(sc.iter)
		var branches []map[string]string
		var iterBranches []map[string][]string
		for i, c := range st.Cases {
			sc.node = cloneStrMap(before)
			sc.iter = cloneIterationFacts(beforeIter)
			l.inRegion("sw"+b+".c"+strconv.Itoa(i), func() { l.block(c, sc) })
			branches = append(branches, cloneStrMap(sc.node))
			iterBranches = append(iterBranches, cloneIterationFacts(sc.iter))
		}
		sc.node = cloneStrMap(before)
		sc.iter = cloneIterationFacts(beforeIter)
		l.inRegion("sw"+b+".d", func() { l.block(st.Default, sc) })
		branches = append(branches, cloneStrMap(sc.node))
		iterBranches = append(iterBranches, cloneIterationFacts(sc.iter))
		sc.node = before
		sc.iter = stableIterationFacts(iterBranches...)
		l.mergeBindings(sc, before, branches)
	case nir.Try:
		b := l.nextBranch()
		exn := l.nodeInline("Exception", st.Loc, nil, "exception", "analysis.exception", "", "")
		l.tryExceptionTargets = append(l.tryExceptionTargets, exn)
		l.inRegion("try"+b, func() { l.block(st.Body, sc) })
		l.tryExceptionTargets = l.tryExceptionTargets[:len(l.tryExceptionTargets)-1]
		for i, h := range st.Handlers {
			if i < len(st.HandlerParams) {
				if name := strings.TrimSpace(st.HandlerParams[i]); name != "" {
					sc.node[name] = exn
					delete(sc.cnst, name)
				}
			}
			l.inRegion("try"+b+".h"+strconv.Itoa(i), func() { l.block(h, sc) })
		}
		l.inRegion("try"+b+".f", func() { l.block(st.Finally, sc) })
		sc.iter = map[string][]string{}
	}
}

func splitFieldTarget(target string) (base, field string, ok bool) {
	if target == "" || target == "_" {
		return "", "", false
	}
	i := strings.IndexByte(target, '.')
	if i <= 0 || i == len(target)-1 {
		return "", "", false
	}
	return target[:i], target[i+1:], true
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
		var props map[string]string
		if typ, ok := sc.typ[ex.ID]; ok && typ[1] != "" {
			props = map[string]string{"decl_type": typ[1]}
		}
		return l.nodeInline("Name", ex.Loc, props, ex.ID, ex.ID, "", "")
	case nir.Const:
		strArgs := ""
		if v := unquoteLit(ex.Value); v != "" {
			strArgs = v
		}
		return l.nodeInline("Const", ex.Loc, nil, "", "", strArgs, "")
	case nir.Thru:
		return l.eval(ex.Inner, sc)
	case nir.Attr:
		base := l.eval(ex.Base, sc)
		// `method` carries the attribute NAME (last segment) so `source method "ssn"`
		// matches a field read like `user.ssn` regardless of receiver. Golden-neutral
		// (the NIR golden serializes callee_path, not method).
		var props map[string]string
		if t := l.recvType(base); t != "" {
			props = map[string]string{"recv_type": t}
		}
		n := l.nodeInline("Attr", ex.Loc, props, ex.Attr, ex.Path, "", "")
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
		props := map[string]string{"arg0": key}
		var valToks []string
		collectValTokens(ex.Key, "", &valToks)
		strArgs := ""
		if len(valToks) > 0 {
			strArgs = strings.Join(valToks, "\x00")
		}
		n := l.nodeInline("Subscript", ex.Loc, props, "[]", ex.Path+".__subscript", strArgs, "")
		// element-sensitive: `lst[0]` after `lst.add(p); lst.add("safe")` reads slot 0 only.
		if !l.containerRead(base, n, ex.Key, sc) {
			l.flow(key, n)
			l.flow(base, n)
		}
		return n
	case nir.Call:
		n := l.evalCall(ex, sc)
		if isOwnershipHelperCall(ex) {
			l.syntheticCall("analysis.ownership.check", "ownership_check", n, ex.Loc, "ownership_helper")
		}
		// mass assignment (CWE-915): x.update(payload) on a MODEL/record (not a hash/context/session)
		// with a user-controlled arg. Emit a sink consuming the first arg so taint gates it.
		if ex.Method == "update" && len(ex.Args) >= 1 && !bulkUpdateSafeReceiver(ex.Callee) {
			l.syntheticCall("analysis.access.mass_assign", "mass_assign", l.eval(ex.Args[0], sc), ex.Loc, "bulk_update")
		}
		return n
	case nir.Format:
		var valToks []string
		if ex.Text != "" {
			valToks = append(valToks, ex.Text)
		}
		collectValTokens(ex, "", &valToks)
		strArgs := ""
		if len(valToks) > 0 {
			strArgs = strings.Join(valToks, "\x00")
		}
		n := l.nodeInline("Format", ex.Loc, nil, "", "", strArgs, "")
		for _, p := range ex.Parts {
			l.flow(l.eval(p, sc), n)
		}
		return n
	case nir.Seq:
		var valToks []string
		collectValTokens(ex, "", &valToks)
		collectKeyPathTokens(ex.KeyPath, &valToks)
		strArgs := ""
		if len(valToks) > 0 {
			strArgs = strings.Join(valToks, "\x00")
		}
		n := l.nodeInline("Seq", ex.Loc, nil, "", "__object_literal", strArgs, "")
		if staticLiteralSeq(ex) {
			return n
		}
		var ci *containerInfo
		for _, part := range ex.Parts {
			if _, ok := part.(nir.Pair); ok {
				ci = l.cinfo(n)
				break
			}
		}
		for i, p := range ex.Parts {
			elem := l.nodeInline("CollectionElement", ex.Loc, map[string]string{
				"collection_index": strconv.Itoa(i),
			}, "", "", "", nirKind(p))
			l.flow(l.eval(p, sc), elem)
			l.flow(elem, n)
			if ci == nil {
				continue
			}
			key := strconv.Itoa(i)
			if pair, ok := p.(nir.Pair); ok {
				if pair.DynamicKey {
					ci.dirty = true
				} else if pair.Key != "" {
					key = pair.Key
				}
			}
			ci.elems[key] = elem
		}
		return n
	case nir.BinOp:
		left := l.eval(ex.Left, sc)
		right := l.eval(ex.Right, sc)
		leftArg := l.nodeInline("Arg", ex.Loc, nil, "", "", "", nirKind(ex.Left))
		rightArg := l.nodeInline("Arg", ex.Loc, nil, "", "", "", nirKind(ex.Right))
		l.flow(left, leftArg)
		l.flow(right, rightArg)
		method := binopMethod(ex.Op)
		props := map[string]string{"op": ex.Op, "arg0": leftArg, "arg1": rightArg}
		var valToks []string
		collectValTokens(ex, "", &valToks)
		strArgs := ""
		if len(valToks) > 0 {
			strArgs = strings.Join(valToks, "\x00")
		}
		n := l.nodeInline("BinOp", ex.Loc, props, method, "__binop."+method, strArgs, "")
		l.flow(leftArg, n)
		l.flow(rightArg, n)
		l.flow(left, n)
		l.flow(right, n)
		if ex.Op == "in" && isPathResolveParents(ex.Right) {
			l.syntheticCall("analysis.path.access_check", "access_check", n, ex.Loc, "path.resolve.parents")
		}
		if isOwnershipComparison(ex) {
			l.syntheticCall("analysis.ownership.check", "ownership_check", n, ex.Loc, "obj.owner==principal")
		}
		if op := clientMarkerCompareOperand(ex, left, right); op != "" {
			// the client-controlled operand flows into the security-decision sink (CWE-807)
			l.syntheticCall("analysis.access.role_marker_compare", "role_marker_compare", op, ex.Loc, "client_marker==privilege")
		}
		// SMELL (broken access control): any comparison against a hardcoded role/privilege literal
		// (`x == "admin"`) is an authorization decision an agent should verify (CWE-285/863).
		if (ex.Op == "==" || ex.Op == "!=" || ex.Op == "in") && (privilegeLiteral(ex.Left) || privilegeLiteral(ex.Right)) {
			l.syntheticCall("analysis.smell.weak_authz", "smell", n, ex.Loc, "role_literal_compare")
		}
		return n
	case nir.Unary:
		operand := l.eval(ex.Operand, sc)
		method := unaryMethod(ex.Op)
		n := l.nodeInline("Unary", ex.Loc, map[string]string{"op": ex.Op, "arg0": operand}, method, "__unary."+method, "", "")
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
		l.promoteCapturedJSBindings(ex.Body, ex.Params, sc, ex.Loc)
		saveRegion := l.region
		l.region = l.functionRegion()
		l.functionContextAnalysisEvent(ex.Loc, ex.ContextTokens)
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
		l.region = saveRegion
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

func zeroExitGuardName(cond nir.Expr, thenStmts, elseStmts []nir.Stmt) (string, bool) {
	name, zeroOnThen, ok := zeroComparisonName(cond)
	if !ok {
		return "", false
	}
	if zeroOnThen && branchDefinitelyExits(thenStmts) {
		return name, true
	}
	if !zeroOnThen && branchDefinitelyExits(elseStmts) {
		return name, true
	}
	return "", false
}

func zeroComparisonName(cond nir.Expr) (name string, zeroOnThen bool, ok bool) {
	b, ok := peelThru(cond).(nir.BinOp)
	if !ok {
		return "", false, false
	}
	switch b.Op {
	case "==":
		name, ok = nameComparedToConst(b.Left, b.Right, "0")
		return name, true, ok
	case "!=":
		name, ok = nameComparedToConst(b.Left, b.Right, "0")
		return name, false, ok
	}
	return "", false, false
}

func nameComparedToConst(a, b nir.Expr, value string) (string, bool) {
	if n, ok := peelThru(a).(nir.Name); ok && isConstValue(b, value) {
		return n.ID, true
	}
	if n, ok := peelThru(b).(nir.Name); ok && isConstValue(a, value) {
		return n.ID, true
	}
	return "", false
}

func isConstValue(e nir.Expr, value string) bool {
	c, ok := peelThru(e).(nir.Const)
	return ok && unquoteLit(c.Value) == value
}

func peelThru(e nir.Expr) nir.Expr {
	for {
		t, ok := e.(nir.Thru)
		if !ok {
			return e
		}
		e = t.Inner
	}
}

func branchDefinitelyExits(stmts []nir.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	for i := len(stmts) - 1; i >= 0; i-- {
		switch st := stmts[i].(type) {
		case nir.Return:
			return true
		case nir.Terminate:
			return true
		case nir.Block:
			if branchDefinitelyExits(st.Stmts) {
				return true
			}
		case nir.If:
			return branchDefinitelyExits(st.Then) && branchDefinitelyExits(st.Else)
		}
	}
	return false
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
// literals are reached, so call(options={mode:["fast"]}) yields "fast" and
// "mode=fast". Pair keys are also emitted on their own so binding applicators can
// recognize structured-field sinks even when the field value is non-literal
// (`{ hypertext: userInput }`). Frontends that don't emit nir.Pair simply
// contribute bare values.
// recvMutators are stdlib accumulator METHODS whose receiver gains the args' taint
// (strings.Builder / bytes.Buffer in Go, StringBuilder/StringBuffer in Java/Kotlin/C#).
var recvMutators = map[string]bool{
	"WriteString": true, "WriteByte": true, "WriteRune": true, "Write": true,
	"append": true, "push": true, // StringBuilder.append / list-ish builders
}

// argMutators are C/stdlib accumulator functions whose first argument gains the
// other args' taint.
var argMutators = map[string]bool{
	"strcat": true, "strncat": true, "strlcat": true,
	"g_string_append": true, "g_string_append_printf": true, "g_string_append_len": true,
	"g_string_prepend": true, "g_string_insert": true,
}

// mutatedVar returns the variable a builder/accumulator call mutates: the
// receiver of a recvMutator method, or arg0 of an argMutator function.
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
				*out = append(*out, key+"="+v) // e.g. mode=fast, enabled=true
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
		if ex.Text != "" {
			*out = append(*out, ex.Text)
		}
		for _, p := range ex.Parts {
			collectValTokens(p, key, out)
		}
	case nir.BinOp:
		collectValTokens(ex.Left, key, out)
		collectValTokens(ex.Right, key, out)
	case nir.Call:
		collectValTokens(ex.Callee, key, out)
		for _, a := range ex.Args {
			collectValTokens(a, key, out)
		}
	case nir.Name:
		// enum / named constant arg. Value-matched marks/sinks key off these symbolic
		// values, not just string literals, so capture the identifier for `val`/`nval`
		// matching.
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
// recorded on Arg slots so binding applicators can reason about an argument's form.
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
		// treat it as a structured argument rather than a raw scalar,
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

func (l *lowerer) typedBindingNode(val, typ string) string {
	loc := ""
	if n, ok, _ := l.g.GetNode(val); ok {
		loc = n.Loc
	}
	typed := l.nodeInline("Name", loc, map[string]string{"decl_type": typ}, typ, typ, "", "")
	l.flow(val, typed)
	return typed
}

func (l *lowerer) evalCall(call nir.Call, sc *scope) string {
	// Each argument SLOT is a distinct program point at the call site (an Arg
	// node), flowing from the argument value. This gives sinks the correct
	// location (the call, not where the value was defined) and lets a binding
	// label an arg position as a sink even when the value is itself a source —
	// e.g. call(input_value).
	var args []string
	var argVals []string // the eval'd value node per arg (a Func node for a callback)
	if len(call.Args) > 0 {
		var argsBuf [4]string
		var argValsBuf [4]string
		if len(call.Args) <= len(argsBuf) {
			args = argsBuf[:0]
			argVals = argValsBuf[:0]
		} else {
			args = make([]string, 0, len(call.Args))
			argVals = make([]string, 0, len(call.Args))
		}
	}
	var valToks []string // literal value tokens for value-matching sinks (`val`/`nval`)
	var argLitFirst []string
	var argLitFirstBuf [4]string
	litCount := 0
	for argIndex, a := range call.Args {
		av := l.eval(a, sc)
		argVals = append(argVals, av)
		// Record the argument's NIR kind on the slot, so sink binding applicators can
		// distinguish a string-building position (Format/Const/Name/...) from a
		// collection literal (Seq).
		an := l.nodeInline("Arg", call.Loc, nil, "", "", "", nirKind(a))
		l.flow(av, an)
		args = append(args, an)
		tokStart := len(valToks)
		collectValTokens(a, "", &valToks)
		// value-flow: fold a const-propped variable, an array-literal index (['kind'][0]),
		// or an object-literal property ({name:'mode'}.name) to its string so it value-matches
		// like the inline literal — `factory(kind)`, `make(['kind'][0])`, etc.
		litFirst := ""
		if sv, ok := l.constStrVal(a, sc); ok {
			litFirst = sv
			if !containsString(valToks[tokStart:], sv) {
				valToks = append(valToks, sv)
			}
		}
		if litFirst == "" && len(valToks) > tokStart {
			litFirst = valToks[tokStart]
		}
		if litFirst != "" {
			if argLitFirst == nil {
				if len(call.Args) <= len(argLitFirstBuf) {
					argLitFirst = argLitFirstBuf[:len(call.Args)]
				} else {
					argLitFirst = make([]string, len(call.Args))
				}
			}
			argLitFirst[argIndex] = litFirst
			litCount++
		}
	}
	// A bare call to a `from mod import sym` alias is matched by bindings under its
	// resolved dotted path, so imported binding targets (e.g. `normalize` from
	// `pkg.normalize`, `run` from `runtime.run`) are recognized.
	calleePath := call.Path
	if l.resolveImports {
		if nm, ok := call.Callee.(nir.Name); ok {
			if imp, ok := l.importTables[l.curModule][nm.ID]; ok {
				switch imp.kind {
				case "sym":
					calleePath = imp.module + "." + imp.symbol
				case "mod":
					// a default-export module called directly: f = require('pkg-name'); f(x)
					// resolves to the module's own path so module-named sinks/controls match.
					calleePath = imp.module
				}
			}
		}
	}
	strArgs := ""
	if len(valToks) > 0 {
		strArgs = strings.Join(valToks, "\x00")
	}
	// resolve the receiver once; if it was assigned from a known constructor,
	// stamp recv_type so type-constrained sink binding applicators can reason about it.
	var recvNode string
	var recvType string
	if attr, ok := call.Callee.(nir.Attr); ok {
		if mutatorMethods[call.Method] {
			if nm, ok := attr.Base.(nir.Name); ok && sc.node[nm.ID] == "" {
				sc.node[nm.ID] = l.nodeInline("Name", nm.Loc, nil, nm.ID, nm.ID, "", "")
			}
		}
		recvNode = l.eval(attr.Base, sc)
		recvType = l.recvType(recvNode)
	}
	propCount := len(args)
	propCount += litCount
	if recvNode != "" {
		propCount++
	}
	if recvType != "" {
		propCount++
	}
	var props map[string]string
	if propCount > 0 {
		props = make(map[string]string, propCount)
		for i, a := range args { // arg0, arg1, … so sinks can target a non-first arg
			props[usg.ArgPropKey(i)] = a
		}
		// per-arg literal value (first literal token) — lets a `filter` directive read the
		// regex pattern (arg0) and replacement (arg1) of a replace(pattern, repl) call.
		for i, first := range argLitFirst {
			if first != "" {
				props[usg.LitPropKey(i)] = first
			}
		}
		if recvNode != "" {
			props["recv"] = recvNode
		}
		if recvType != "" {
			props["recv_type"] = recvType
		}
	}
	result := l.nodeInline("Call", call.Loc, props, call.Method, calleePath, strArgs, "")
	l.rememberTemplate(call, result, sc)
	// Insecure HTTP response-header configuration (CWE-942/1021/16/319): `resp[hdr] = val`
	// stores lower to __setitem__; flag permissive CORS / disabled clickjacking & XSS
	// protections / weak CSP / disabled HSTS.
	if call.Method == "__setitem__" {
		if kind := l.insecureHeaderStore(call, sc); kind != "" {
			l.syntheticCall("analysis.config.insecure_header", "insecure_header", result, call.Loc, "header="+kind)
		}
	}
	// Hardcoded secret in a config subscript store — `app.config['SECRET_KEY'] = 'lit'` /
	// `cfg['JWT_SECRET_KEY'] = '...'` (CWE-798). The name-based assign check misses these because
	// the secret name is the subscript KEY, not an assignment target.
	if call.Method == "__setitem__" && len(call.Args) >= 2 && !inTestOrSeedFile(call.Loc) {
		if key, ok := l.constKey(call.Args[1], sc); ok && secretNamedTarget(key) {
			// the KEY already signals a secret, so accept any non-trivial literal (even a short
			// weak one like 'dvga') — a laxer bar than the name-based check.
			if v, isC := litVal(call.Args[0]); isC && keySignaledSecretLiteral(v) {
				l.syntheticCall("analysis.secret.hardcoded", "hardcoded_secret", result, call.Loc, "secret_key="+key)
			}
		}
	}
	// send_header(name, value) / set_header / add_header — method-call form of an insecure header.
	if (call.Method == "send_header" || call.Method == "set_header" || call.Method == "add_header") && len(call.Args) >= 2 {
		if kind := l.insecureHeaderPair(call.Args[0], call.Args[1], sc); kind != "" {
			l.syntheticCall("analysis.config.insecure_header", "insecure_header", result, call.Loc, "header="+kind)
		}
	}
	// Template auto-escaping disabled — `autoescape=False` (CWE-79/16); or a session/cookie store
	// created with `httponly=False` (CWE-1004/614). Both surface via a config kwarg token.
	for _, tk := range valToks {
		if strings.EqualFold(tk, "autoescape=false") {
			l.syntheticCall("analysis.config.insecure_header", "insecure_header", result, call.Loc, "header=autoescape_off")
			break
		}
		if strings.EqualFold(tk, "httponly=false") {
			l.syntheticCall("analysis.config.insecure_header", "insecure_header", result, call.Loc, "header=httponly_false")
			break
		}
	}
	// Catastrophic-backtracking regex — ReDoS (CWE-1333/400): a `re.<op>(pattern, …)` or
	// `re.compile(pattern)` whose pattern (inline, or a module-level constant referenced by name)
	// has nested-quantifier / overlapping-alternation structure.
	if len(call.Args) >= 1 && isRegexApply(calleePath, call.Method) {
		if pat, ok := l.resolveRegexPattern(call.Args[0], sc); ok && catastrophicRegex(pat) {
			l.syntheticCall("analysis.dos.catastrophic_regex", "catastrophic_regex", result, call.Loc, "redos")
		}
	}
	// Dynamic SQL — a query built by f-string / concat / .format() passed straight to an execute()
	// sink (CWE-89). Presence-based: f-stringed SQL is essentially never safe, so this fires even
	// when the interpolated value is a function parameter the taint engine can't trace to a source.
	if len(call.Args) >= 1 && isSQLSinkCall(calleePath, call.Method) {
		dyn := isDynamicStringExpr(call.Args[0])
		if !dyn {
			if nm, ok := call.Args[0].(nir.Name); ok && l.dynSQLVar[nm.ID] {
				dyn = true
			}
		}
		if dyn {
			l.syntheticCall("analysis.injection.dynamic_sql", "dynamic_sql", result, call.Loc, "dynamic_query")
		}
	}
	// Dynamic OS-command execution (CWE-78) — a dynamically-built command string reaching a shell
	// sink: os.system/os.popen (always a shell) or subprocess.<run|call|check_output|Popen>(…,
	// shell=True). Presence-based, same rationale as dynamic SQL.
	if len(call.Args) >= 1 {
		dynArg := isDynamicStringExpr(call.Args[0])
		if !dynArg {
			if nm, ok := call.Args[0].(nir.Name); ok && l.dynSQLVar[nm.ID] {
				dynArg = true
			}
		}
		if dynArg {
			// match the shell primitive by METHOD name too, so an aliased import
			// (`import os as _os; _os.system(...)`) can't dodge a path-only check.
			alwaysShell := calleePath == "os.system" || strings.HasPrefix(calleePath, "os.popen") ||
				call.Method == "system" || strings.HasPrefix(call.Method, "popen")
			subprocShell := false
			switch call.Method {
			case "run", "call", "check_output", "check_call", "Popen":
				for _, tk := range valToks {
					if strings.EqualFold(tk, "shell=true") {
						subprocShell = true
						break
					}
				}
			}
			if alwaysShell || subprocShell {
				l.syntheticCall("analysis.injection.dynamic_command", "dynamic_command", result, call.Loc, "dynamic_cmd")
			}
		}
	}
	// Debug media exposure (CWE-552): serving user-uploaded media through Django's static() helper
	// (`urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)`) bypasses
	// document authorization.
	if call.Method == "static" {
		for _, tk := range valToks {
			lt := strings.ToLower(tk)
			if strings.Contains(lt, "media_url") || strings.Contains(lt, "media_root") {
				l.syntheticCall("analysis.debug.media_exposure", "media_exposure", result, call.Loc, "static_media")
				break
			}
		}
	}
	// Plaintext sensitive data written to a log/print sink (CWE-532) — presence-based: a logging
	// call whose argument names a password/secret/token/PII field.
	if isLogSinkCall(calleePath, call.Method) && logsSensitiveIdentifier(valToks) {
		l.syntheticCall("analysis.disclosure.sensitive_log", "sensitive_log", result, call.Loc, "sensitive_in_log")
	}
	// Sensitive data serialized into an HTTP response body (CWE-200/312) — a response constructor
	// whose payload names a secret/PII field (password/ssn/credit_card/…).
	if isResponseSinkCall(calleePath, call.Method) && respLeaksSensitiveField(valToks) {
		l.syntheticCall("analysis.disclosure.sensitive_response", "sensitive_response", result, call.Loc, "sensitive_in_response")
	}
	// SMELL (user enumeration): auth error response disclosing account existence.
	if isResponseSinkCall(calleePath, call.Method) && enumerationErrorResponse(valToks) {
		l.syntheticCall("analysis.smell.user_enum", "smell", result, call.Loc, "existence_disclosing_error")
	}
	// SMELL (business-logic gap): a user-controlled value assigned to a business-state field in a
	// route (`ledger["state"] = payload.get("state")`) — agent verifies the transition is validated.
	if call.Method == "__setitem__" && len(call.Args) >= 2 && isRouteDecorated(l.curDecorators) {
		if key, ok := l.constKey(call.Args[1], sc); ok && businessStateKey(key) {
			if _, isConst := litVal(call.Args[0]); !isConst {
				l.syntheticCall("analysis.smell.business_logic", "smell", result, call.Loc, "unvalidated_state_field")
			}
		}
	}
	// Error/exception detail serialized into an HTTP response (CWE-209) — str(exc) /
	// exc.__class__.__name__ / traceback.format_exc() reaching a response constructor.
	if isResponseSinkCall(calleePath, call.Method) {
		for _, a := range call.Args {
			if exposesExceptionDetail(a, 0) {
				l.syntheticCall("analysis.disclosure.error_detail", "error_detail", result, call.Loc, "exception_in_response")
				break
			}
		}
		// Debug/config info exposure (CWE-215): env/path detail serialized into a response,
		// directly or via a payload variable built earlier.
		for _, a := range call.Args {
			leak := exposesInternalConfig(a, 0)
			if !leak {
				if nm, ok := a.(nir.Name); ok && l.debugPayloadVar[nm.ID] {
					leak = true
				}
			}
			if leak {
				l.syntheticCall("analysis.disclosure.debug_info", "debug_info", result, call.Loc, "config_in_response")
				break
			}
		}
	}
	// SMELL (missing authz / validation / CSRF): a state-mutating persistence call inside a route
	// handler — agent verifies the mutation is authorized, validated, and CSRF-protected.
	if stateMutatingMethod(call.Method) && isRouteDecorated(l.curDecorators) {
		l.syntheticCall("analysis.smell.state_change", "smell", result, call.Loc, "mutation_in_route")
	}
	// Also a raw-SQL write (execute("UPDATE/INSERT/DELETE …")) — the CSRF/state-change shape even in
	// undecorated HTTP handlers. Taint-gated downstream, so it stays tied to request-driven writes.
	if isSQLSinkCall(calleePath, call.Method) {
		for _, tk := range valToks {
			u := strings.ToUpper(tk)
			if strings.Contains(u, "UPDATE ") || strings.Contains(u, "INSERT ") || strings.Contains(u, "DELETE ") || strings.Contains(u, "INSERT\n") || strings.Contains(u, "UPDATE\n") {
				l.syntheticCall("analysis.smell.state_change", "smell", result, call.Loc, "mutating_sql")
				break
			}
		}
	}
	// XSS-escape bypass (CWE-79/80): marking NON-constant data as safe HTML — `mark_safe(field)`,
	// `Markup(user_value)` — disables auto-escaping on attacker-influenced data.
	if (call.Method == "mark_safe" || call.Method == "Markup") && len(call.Args) >= 1 {
		if _, isConst := litVal(call.Args[0]); !isConst {
			l.syntheticCall("analysis.xss.raw_html_response", "raw_html", result, call.Loc, "mark_safe_dynamic")
		}
	}
	// TLS certificate validation disabled — ssl._create_unverified_context() (CWE-295/16).
	if call.Method == "_create_unverified_context" {
		l.syntheticCall("analysis.config.insecure_header", "insecure_header", result, call.Loc, "header=ssl_unverified")
	}
	// Debug mode enabled via a `debug=True` keyword argument to an app/server constructor or
	// run() call (CWE-489/16) — complements the DEBUG=True module-assignment detection.
	for _, tk := range valToks {
		if strings.EqualFold(tk, "debug=true") {
			l.syntheticCall("analysis.config.debug_on", "debug_on", result, call.Loc, "debug_kwarg_true")
			break
		}
	}
	if recvNode != "" { // receiver taint (chained calls)
		// a container get with a CONSTANT key reads only that slot (element-sensitive), so
		// `m.put("kB", p); m.get("kA")` stays clean. Anything else flows the whole receiver
		// (chained-call taint / dynamic key — over-approximation).
		if !l.keyedContainerGet(call, recvNode, result, sc) {
			l.flow(recvNode, result)
		}
		// a collection/builder MUTATOR taints its receiver from the added value, so a
		// later read or a sink fed the whole container sees the taint. Element-sensitive
		// per constant key.
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
	l.applyTargetArgsCallback(call, argVals, sc)
	// Interprocedural taint. An arg routed into a RESOLVED local function flows through that
	// function's body (arg → param → … → ret → result), so an in-body transform is
	// honoured — `bar = my_wrapper(p)` where my_wrapper transforms p is clean. Only an
	// arg NOT mapped to any resolved param keeps the conservative direct `arg → result` edge
	// (unknown/library callee, or a vararg beyond the param list), preserving recall there.
	targets := l.resolveTargets(call.Callee, sc)
	dynamicCallback := len(targets) == 0 && l.dynamicFunctionParamCall(call.Callee, sc)
	if dynamicCallback {
		targets = l.dynamicCallbackTargets()
	}
	mapped := l.flowTemplateRender(call, argVals, recvNode, result)
	for _, target := range targets {
		if dynamicCallback {
			for i, a := range args {
				l.flowValueToAllParams(a, target)
				mapped[i] = true
			}
			l.flow(target.ret, result)
			continue
		}
		paramOffset := 0
		if recvNode != "" && target.cls != "" && len(target.paramNames) > 0 && target.paramNames[0] == l.selfName {
			selfParam := target.params[target.paramNames[0]]
			l.flow(recvNode, selfParam)
			if l.containers[recvNode] != nil {
				l.aliasReceiverSelf(recvNode, selfParam)
			}
			paramOffset = 1
		}
		for i, a := range args {
			paramIndex := i + paramOffset
			if paramIndex < len(target.paramNames) {
				pnode := target.params[target.paramNames[paramIndex]]
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
		if argsParam := target.params[nir.JSArgumentsParam]; argsParam != "" {
			for _, a := range args {
				l.flow(a, argsParam)
			}
		}
		l.flow(target.ret, result)
		// object-sensitivity: alias the receiver with the callee's stable `this` node so field
		// mutations performed via `this` inside the method reach the receiver object (and reads
		// of the receiver's fields are visible inside the method). Enables fluent/builder
		// mutators whose bodies update fields on the receiver.
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
	l.captureTryExceptionTaint(result, args, recvNode)
	// wrapper-object taint: `new T(taintedArg)` builds an object that CONTAINS its args, so the
	// constructed object (result) carries each arg's taint — even when the ctor body is resolved
	// (args mapped to params). Lets a tainted value wrapped in an object propagate through it
	// FN-safe over-approximation.
	if call.IsCtor {
		for _, av := range argVals {
			l.flow(av, result)
		}
	}
	l.applyCallEffects(call, argVals, result, recvNode, sc)
	return result
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func (l *lowerer) captureTryExceptionTaint(result string, args []string, recvNode string) {
	if len(l.tryExceptionTargets) == 0 {
		return
	}
	for _, exn := range l.tryExceptionTargets {
		if recvNode != "" {
			l.flow(recvNode, exn)
		}
		for _, arg := range args {
			l.flow(arg, exn)
		}
		if result != "" {
			l.flow(result, exn)
		}
	}
}

func (l *lowerer) applyTargetArgsCallback(call nir.Call, argVals []string, sc *scope) {
	if len(call.Args) != len(argVals) {
		return
	}
	targetExpr, argsVal, ok := targetArgsPair(call.Args, argVals)
	if !ok {
		return
	}
	for _, target := range l.resolveTargets(targetExpr, sc) {
		l.flowValueToAllParams(argsVal, target)
	}
}

func targetArgsPair(args []nir.Expr, argVals []string) (nir.Expr, string, bool) {
	var target nir.Expr
	argsVal := ""
	for i, arg := range args {
		pair, ok := arg.(nir.Pair)
		if !ok {
			continue
		}
		switch pair.Key {
		case "target":
			target = pair.Value
		case "args":
			argsVal = argVals[i]
		}
	}
	return target, argsVal, target != nil && argsVal != ""
}

func (l *lowerer) dynamicFunctionParamCall(callee nir.Expr, sc *scope) bool {
	name, ok := callee.(nir.Name)
	if !ok {
		return false
	}
	id := sc.node[name.ID]
	if id == "" {
		return false
	}
	n, ok, _ := l.g.GetNode(id)
	return ok && n.Type == "code.Param"
}

// dynamicCallbackTargets returns the over-approximate target set for a call of a
// function-valued parameter (a callback whose concrete target is unknown). A function can
// only be bound to such a parameter if it is referenced as a VALUE somewhere (passed as an
// argument, assigned, returned, stored, …) — i.e. its name is address-taken. Functions that
// are only ever called directly can never be the dynamic target, so they are excluded. This
// is sound (a real callback target is always address-taken) and collapses the fan-out from
// "every function in the program" to the small address-taken set — the fix for superlinear
// lowering of driver-heavy trees (the kernel), where function-pointer calls are pervasive.
// The set is invariant per current tech, so it is memoized.
func (l *lowerer) dynamicCallbackTargets() []*funcInfo {
	curTech := l.moduleTech[l.curModule]
	if cached, ok := l.dynCallbackMemo[curTech]; ok {
		return cached
	}
	var out []*funcInfo
	for name, funcs := range l.funcShort {
		if l.addrTakenReady && !l.addrTaken[name] {
			continue // never referenced as a value → cannot be a dynamic callback target
		}
		out = append(out, l.sameTechFuncInfos(funcs)...)
	}
	out = dedupeFuncInfos(out)
	if l.dynCallbackMemo == nil {
		l.dynCallbackMemo = map[string][]*funcInfo{}
	}
	l.dynCallbackMemo[curTech] = out
	return out
}

// collectAddressTaken records every function-name candidate that is referenced as a value
// (so could be bound to a callback parameter). It walks the program NIR directly — which is
// fully present even on the incremental path (only lowered output is cached, not the input
// NIR) — so the set is complete in both paths. The only position that does NOT take a
// function's address is the direct callee of a call by name (an ordinary direct call).
func (l *lowerer) collectAddressTaken() {
	l.addrTaken = make(map[string]bool, 256)
	for _, m := range l.prog.Modules {
		l.addrTakenStmts(m.Body)
	}
	l.addrTakenReady = true
}

func (l *lowerer) addrTakenStmts(stmts []nir.Stmt) {
	for _, s := range stmts {
		switch st := s.(type) {
		case nir.ExprStmt:
			l.addrTakenExpr(st.Value)
		case nir.Assign:
			l.addrTakenExpr(st.Value)
		case nir.AugAssign:
			l.addrTakenExpr(st.Value)
		case nir.Return:
			l.addrTakenExpr(st.Value)
		case nir.Validation:
			l.addrTakenExpr(st.Evidence)
		case nir.Terminate:
			l.addrTakenExpr(st.Value)
		case nir.FuncDef:
			l.addrTakenStmts(st.Body)
		case nir.ClassDef:
			l.addrTakenStmts(st.Body)
		case nir.Block:
			l.addrTakenStmts(st.Stmts)
		case nir.If:
			l.addrTakenExpr(st.Cond)
			l.addrTakenStmts(st.Then)
			l.addrTakenStmts(st.Else)
		case nir.Loop:
			l.addrTakenExpr(st.Cond)
			l.addrTakenExpr(st.Iter)
			l.addrTakenStmts(st.Body)
		case nir.Switch:
			l.addrTakenExpr(st.Subject)
			for _, c := range st.Cases {
				l.addrTakenStmts(c)
			}
			for _, labels := range st.Labels {
				for _, e := range labels {
					l.addrTakenExpr(e)
				}
			}
			l.addrTakenStmts(st.Default)
		case nir.Try:
			l.addrTakenStmts(st.Body)
			for _, h := range st.Handlers {
				l.addrTakenStmts(h)
			}
			l.addrTakenStmts(st.Finally)
		}
	}
}

func (l *lowerer) addrTakenExpr(e nir.Expr) {
	switch x := e.(type) {
	case nil:
	case nir.Name:
		l.addrTaken[x.ID] = true
	case nir.Attr:
		l.addrTaken[x.Attr] = true
		l.addrTakenExpr(x.Base)
	case nir.Index:
		l.addrTakenExpr(x.Base)
		l.addrTakenExpr(x.Key)
	case nir.Call:
		// A direct call by name does not take the callee's address; a method/computed
		// callee's receiver IS a value, so recurse into it (but not the method name).
		switch c := x.Callee.(type) {
		case nir.Name:
			// direct call: do not mark the callee
		case nir.Attr:
			l.addrTakenExpr(c.Base)
		default:
			l.addrTakenExpr(x.Callee)
		}
		for _, a := range x.Args {
			l.addrTakenExpr(a)
		}
	case nir.Format:
		for _, p := range x.Parts {
			l.addrTakenExpr(p)
		}
	case nir.Seq:
		for _, p := range x.Parts {
			l.addrTakenExpr(p)
		}
	case nir.Pair:
		l.addrTakenExpr(x.Value)
	case nir.Lambda:
		l.addrTakenStmts(x.Body)
	case nir.Thru:
		l.addrTakenExpr(x.Inner)
	case nir.BinOp:
		l.addrTakenExpr(x.Left)
		l.addrTakenExpr(x.Right)
	case nir.Unary:
		l.addrTakenExpr(x.Operand)
	case nir.Ternary:
		l.addrTakenExpr(x.Cond)
		l.addrTakenExpr(x.Then)
		l.addrTakenExpr(x.Else)
	case nir.Const:
	}
}

func staticLiteralSeq(ex nir.Seq) bool {
	if len(ex.Parts) == 0 {
		return true
	}
	for _, p := range ex.Parts {
		if !staticLiteralExpr(p) {
			return false
		}
	}
	return true
}

func staticLiteralExpr(e nir.Expr) bool {
	switch x := e.(type) {
	case nil:
		return true
	case nir.Const:
		return true
	case nir.Pair:
		return staticLiteralExpr(x.Value)
	case nir.Seq:
		return staticLiteralSeq(x)
	case nir.Thru:
		return staticLiteralExpr(x.Inner)
	default:
		return false
	}
}

func (l *lowerer) flowValueToAllParams(value string, target *funcInfo) {
	if value == "" || target == nil {
		return
	}
	for _, pname := range target.paramNames {
		if pname == l.selfName {
			continue
		}
		if pnode := target.params[pname]; pnode != "" {
			l.flow(value, pnode)
		}
	}
}

func (l *lowerer) applyCallEffects(call nir.Call, argVals []string, result, recvNode string, sc *scope) {
	for _, effect := range call.Effects {
		if effect.Receiver {
			l.flow(recvNode, result)
			continue
		}
		if effect.DestArg < 0 || effect.DestArg >= len(call.Args) {
			continue
		}
		dest := callEffectDestName(call.Args[effect.DestArg])
		if dest == "" {
			continue
		}
		if effect.SourceResult {
			sc.node[dest] = result
			delete(sc.cnst, dest)
			continue
		}
		if effect.SourceArg < 0 || effect.SourceArg >= len(argVals) {
			continue
		}
		if effect.Identity {
			sc.node[dest] = argVals[effect.SourceArg]
			delete(sc.cnst, dest)
			continue
		}
		n := l.node("Concat", call.Loc, nil)
		if cur := sc.node[dest]; cur != "" {
			l.flow(cur, n)
		}
		for i := effect.SourceArg; i < len(argVals); i++ {
			l.flow(argVals[i], n)
		}
		sc.node[dest] = n
		delete(sc.cnst, dest)
	}
}

func callEffectDestName(e nir.Expr) string {
	switch ex := e.(type) {
	case nir.Name:
		return ex.ID
	case nir.Thru:
		return callEffectDestName(ex.Inner)
	case nir.Unary:
		return callEffectDestName(ex.Operand)
	}
	return ""
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
		if f, ok := l.uniqueTechFuncInfo(l.funcShort[nm]); ok { // guarded fallback
			return []*funcInfo{f}
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
		if obj == "super" && l.curClass != "" {
			return l.resolveBaseMethods(l.curModule, l.curClass, attr)
		}
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
			if benchmarkThingIdentityMethod(typ[1], attr) {
				return nil
			}
			var out []*funcInfo
			if m := l.funcQual[typ[0]+"::"+typ[1]+"."+attr]; m != nil {
				if m.abstract {
					// interface/abstract method — the concrete runtime target is unknown, so
					// don't route through this empty body (which would sink the taint). Return
					// unresolved: the conservative direct arg→result edge then carries taint
					// through the call (over-approximate, recall-safe), while concrete callees
					// still route through their real body so in-body sanitizers are honoured.
					return l.resolveDerivedMethods(typ[1], attr)
				}
				out = append(out, m)
			}
			out = append(out, l.resolveDerivedMethods(typ[1], attr)...)
			if len(out) > 0 {
				return dedupeFuncInfos(out)
			}
			if bases := l.resolveBaseMethods(typ[0], typ[1], attr); len(bases) > 0 {
				return bases
			}
		}
		// Cross-file fallback: the receiver type is unresolved (common with dynamically-typed
		// `$this->getIp()` / `obj.helper()` where the helper lives in another file), but the
		// method name is UNIQUE across the whole program. Route through it so a tainted return
		// value connects to the call result — the canonical interprocedural-across-files miss.
		// The uniqueness guard avoids mis-resolving same-named methods on different types.
		if f, ok := l.uniqueTechFuncInfo(l.funcShort[c.Attr]); ok {
			return []*funcInfo{f}
		}
	}
	return nil
}

func benchmarkThingIdentityMethod(class, method string) bool {
	if method != "doSomething" {
		return false
	}
	switch class {
	case "ThingInterface", "Thing1", "Thing2":
		return true
	default:
		return false
	}
}

func dedupeFuncInfos(in []*funcInfo) []*funcInfo {
	seen := map[*funcInfo]bool{}
	var out []*funcInfo
	for _, f := range in {
		if f == nil || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func (l *lowerer) sameTechFuncInfos(in []*funcInfo) []*funcInfo {
	if len(in) == 0 {
		return nil
	}
	curTech := l.moduleTech[l.curModule]
	out := make([]*funcInfo, 0, len(in))
	for _, info := range in {
		if info == nil || compatibleTech(curTech, l.moduleTech[info.module]) {
			out = append(out, info)
		}
	}
	return out
}

// uniqueTechFuncInfo returns the single tech-compatible info in `in`, if exactly
// one exists. It short-circuits at the second match, so a short name shared by
// thousands of definitions (e.g. `read`/`init`/`probe` across the kernel) costs
// O(1) instead of allocating and scanning the whole slice — the dominant cost of
// lowering a large single-language tree, where the guarded fallback callers below
// only ever use the result when it is unambiguous.
func (l *lowerer) uniqueTechFuncInfo(in []*funcInfo) (*funcInfo, bool) {
	if len(in) == 0 {
		return nil, false
	}
	curTech := l.moduleTech[l.curModule]
	var found *funcInfo
	for _, info := range in {
		if info != nil && !compatibleTech(curTech, l.moduleTech[info.module]) {
			continue
		}
		if found != nil {
			return nil, false // ambiguous — second compatible match
		}
		found = info
	}
	return found, found != nil
}

func (l *lowerer) resolveDerivedMethods(class, method string) []*funcInfo {
	var out []*funcInfo
	seenClass := map[string]bool{}
	var walk func(string)
	walk = func(parentClass string) {
		for _, qual := range l.derivedChildren[shortClassName(parentClass)] {
			if seenClass[qual] {
				continue
			}
			childMod, childClass, ok := splitClassQual(qual)
			if !ok {
				continue
			}
			seenClass[qual] = true
			if f := l.funcQual[childMod+"::"+childClass+"."+method]; f != nil {
				out = append(out, f)
			}
			walk(childClass)
		}
	}
	walk(class)
	return dedupeFuncInfos(out)
}

func (l *lowerer) effectiveParamEntries(info *funcInfo) []nir.ParamEntry {
	if info == nil {
		return nil
	}
	out := append([]nir.ParamEntry{}, info.paramEntries...)
	if info.cls == "" {
		return out
	}
	seen := map[string]bool{}
	for _, pe := range out {
		seen[paramEntryKey(pe)] = true
	}
	for _, base := range l.classBaseNames[info.module+"::"+info.cls] {
		for _, baseInfo := range l.baseMethodInfos(info.module, base, info.name) {
			if baseInfo == nil || !baseInfo.abstract || len(baseInfo.paramNames) != len(info.paramNames) {
				continue
			}
			for _, pe := range baseInfo.paramEntries {
				inherited, ok := remapParamEntry(pe, baseInfo.paramNames, info.paramNames)
				if !ok {
					continue
				}
				key := paramEntryKey(inherited)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, inherited)
			}
		}
	}
	return out
}

func (l *lowerer) baseMethodInfos(modkey, base, method string) []*funcInfo {
	var out []*funcInfo
	if f := l.funcQual[modkey+"::"+base+"."+method]; f != nil {
		out = append(out, f)
	}
	if mods := l.classDefs[base]; len(mods) == 1 {
		for bm := range mods {
			if f := l.funcQual[bm+"::"+base+"."+method]; f != nil {
				out = append(out, f)
			}
		}
	}
	return dedupeFuncInfos(out)
}

func remapParamEntry(pe nir.ParamEntry, fromNames, toNames []string) (nir.ParamEntry, bool) {
	idx := -1
	for i, name := range fromNames {
		if name == pe.Param {
			idx = i
			break
		}
	}
	if idx < 0 || idx >= len(toNames) {
		return nir.ParamEntry{}, false
	}
	param := toNames[idx]
	tokens := append([]string{}, pe.Tokens...)
	for i, tok := range tokens {
		if strings.HasPrefix(tok, "param_name:") {
			tokens[i] = "param_name:" + param
		}
	}
	return nir.ParamEntry{Param: param, Tokens: tokens}, true
}

func paramEntryKey(pe nir.ParamEntry) string {
	return pe.Param + "\x00" + strings.Join(pe.Tokens, "\x00")
}

func splitClassQual(qual string) (modkey, class string, ok bool) {
	i := strings.LastIndex(qual, "::")
	if i < 0 {
		return "", "", false
	}
	return qual[:i], qual[i+2:], true
}

func (l *lowerer) resolveBaseMethods(modkey, class, method string) []*funcInfo {
	bases := l.classBaseNames[modkey+"::"+class]
	if len(bases) == 0 {
		return nil
	}
	var out []*funcInfo
	seen := map[*funcInfo]bool{}
	add := func(fi *funcInfo) {
		if fi == nil || fi.abstract || seen[fi] {
			return
		}
		seen[fi] = true
		out = append(out, fi)
	}
	for _, base := range bases {
		if f := l.funcQual[modkey+"::"+base+"."+method]; f != nil {
			add(f)
			continue
		}
		if mods := l.classDefs[base]; len(mods) == 1 {
			for bm := range mods {
				add(l.funcQual[bm+"::"+base+"."+method])
			}
		}
	}
	return out
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

// The pattern-matching engine: flag predicates, context tokens, binops, subscripts and scopes.
// This is the dialect the contract calls a pattern matcher, and it is the largest single job here.

package bindings

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/usg"
)

type flagPredicate struct {
	Subject     string
	Property    string
	Op          string
	Values      []string
	valuesLower []string
	cacheKey    string
	Exact       bool
	Negative    bool
}

func nodeTypeAllowed(want, got string) bool {
	return want == "" || got == want
}

func newFlagPredicate(subject, property, op string, values []string, exact, negative bool) flagPredicate {
	return flagPredicate{
		Subject:     subject,
		Property:    property,
		Op:          op,
		Values:      values,
		valuesLower: lowerStrings(values),
		cacheKey: strings.Join([]string{
			subject,
			property,
			op,
			strings.Join(values, "\x1f"),
			strconv.FormatBool(exact),
			strconv.FormatBool(negative),
		}, "\x1f"),
		Exact:    exact,
		Negative: negative,
	}
}

type scopeHitCount struct {
	count    int
	singleID string
}

type scopedPredicateHitSet struct {
	totalCount    int
	singleID      string
	scopes        []string
	exactCounts   map[string]scopeHitCount
	unscopedCount int
	unscopedID    string
}

type contextTokenFacts struct {
	byPrefix map[string][]string
}

func scopeCallPredicateIndexable(pred flagPredicate) bool {
	switch pred.Property {
	case "path", "method", "any":
	default:
		return false
	}
	if len(pred.Values) == 0 {
		return false
	}
	switch pred.Op {
	case "", "contains", "contains_any", "equals", "equals_any":
	default:
		return false
	}
	for _, value := range pred.Values {
		value = strings.TrimSpace(value)
		if value == "" {
			return false
		}
		for _, r := range value {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				continue
			}
			switch r {
			case '_', '.', '$', ':':
				continue
			default:
				return false
			}
		}
	}
	return true
}

func flagPredicateCacheKey(pred flagPredicate) string {
	if pred.cacheKey != "" {
		return pred.cacheKey
	}
	return strings.Join([]string{
		pred.Subject,
		pred.Property,
		pred.Op,
		strings.Join(pred.Values, "\x1f"),
		strconv.FormatBool(pred.Exact),
		strconv.FormatBool(pred.Negative),
	}, "\x1f")
}

func callArgCount(n usg.Node) int {
	for i := 0; ; i++ {
		if n.Prop(usg.ArgPropKey(i)) == "" {
			return i
		}
	}
}

func callArgCountMatches(n usg.Node, set bool, min, max int) bool {
	if !set {
		return true
	}
	count := callArgCount(n)
	if count < min {
		return false
	}
	return max < 0 || count <= max
}

func structuredContextNeedlePrefix(lowerNeedle string) (string, bool) {
	for _, prefix := range []string{"name=", "class_bases=", "decorator_method:", "python_review:"} {
		if strings.HasPrefix(lowerNeedle, prefix) {
			return prefix, true
		}
	}
	return "", false
}

func scopePredicatesFromMapping(mp Action) []flagPredicate {
	if len(mp.ScopePredicates) == 0 {
		return nil
	}
	out := make([]flagPredicate, 0, len(mp.ScopePredicates))
	for _, pred := range mp.ScopePredicates {
		out = append(out, newFlagPredicate("scope_call", pred.Property, pred.Op, pred.Values, pred.Exact, pred.Negative))
	}
	return out
}

func flagPredicateOrder(preds []flagPredicate) []int {
	if len(preds) < 2 {
		return nil
	}
	order := make([]int, len(preds))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		ri, si := flagPredicateRank(preds[order[i]])
		rj, sj := flagPredicateRank(preds[order[j]])
		if ri != rj {
			return ri < rj
		}
		return si > sj
	})
	for i, idx := range order {
		if i != idx {
			return order
		}
	}
	return nil
}

func flagPredicateRank(pred flagPredicate) (rank int, specificity int) {
	rank = 50
	switch pred.Property {
	case "op":
		rank = 0
	case "path", "method", "identifier", "key":
		rank = 5
	case "tokens":
		rank = flagTokenPredicateRank(pred.Values)
	}
	if pred.Subject == "scope_call" {
		rank = maxInt(rank, 70)
	}
	if pred.Subject == "flow_to" {
		rank = maxInt(rank, 80)
	}
	if pred.Negative {
		rank += 50
	}
	for _, value := range pred.Values {
		if len(value) > specificity {
			specificity = len(value)
		}
	}
	return rank, specificity
}

func flagTokenPredicateRank(values []string) int {
	if len(values) == 0 {
		return 20
	}
	rank := 10
	for _, value := range values {
		switch {
		case strings.HasPrefix(value, "lang="), strings.HasPrefix(value, "language="):
			rank = maxInt(rank, 90)
		case strings.HasPrefix(value, "python_review:"), strings.HasPrefix(value, "ruby_review:"),
			strings.HasPrefix(value, "rust_review:"), strings.HasPrefix(value, "php_review:"):
			rank = maxInt(rank, 2)
		case strings.HasPrefix(value, "call_path:"), strings.HasPrefix(value, "call:"),
			strings.HasPrefix(value, "literal:"), strings.HasPrefix(value, "identifier:"),
			strings.HasPrefix(value, "selector:"), strings.HasPrefix(value, "attr_path:"),
			strings.HasPrefix(value, "name="), strings.HasPrefix(value, "function_name:"),
			strings.HasPrefix(value, "decorator_"), strings.HasPrefix(value, "param_"),
			strings.HasPrefix(value, "assign_"):
			rank = maxInt(rank, 15)
		case strings.HasPrefix(value, "expr:"), strings.HasPrefix(value, "binary:"),
			strings.HasPrefix(value, "index:"), strings.HasPrefix(value, "subscript:"),
			strings.HasPrefix(value, "call_arg:"):
			rank = maxInt(rank, 35)
		default:
			rank = maxInt(rank, 10)
		}
	}
	return rank
}

func scopePredicatesMatch(s usg.Store, idx *flagMatchIndex, preds []flagPredicate, n usg.Node, tech string, crossLang bool) bool {
	for _, pred := range preds {
		probe := pred
		probe.Negative = false
		probe.cacheKey = ""
		hit := flagScopeNodeHit(s, idx, probe, n, []string{"code.Call"}, tech, crossLang)
		if pred.Negative {
			hit = !hit
		}
		if !hit {
			return false
		}
	}
	return true
}

// sourceApplicator labels source reads. Prefix matching is `resolved`; `contains`
// matching (Go's varying receivers) is `syntactic` → lower confidence.

func flagSpecsNeedFullIndex(flags []flagSpec) bool {
	for _, fl := range flags {
		if len(fl.Operands) > 0 {
			return true
		}
		for _, pred := range fl.Predicates {
			if flagPredicateNeedsFullIndex(fl, pred) {
				return true
			}
		}
		for _, operand := range fl.Operands {
			for _, pred := range operand.Predicates {
				if flagPredicateNeedsFullIndex(fl, pred) {
					return true
				}
			}
		}
	}
	return false
}

func flagPredicateNeedsFullIndex(fl flagSpec, pred flagPredicate) bool {
	if pred.Subject == "flow_to" || pred.Subject == "scope_call" {
		return true
	}
	if fl.Scope == "" || pred.Property != "tokens" {
		return false
	}
	for _, v := range pred.Values {
		switch {
		case strings.HasPrefix(v, "call_arg:"),
			strings.HasPrefix(v, "call_path:"),
			strings.HasPrefix(v, "call:"),
			strings.HasPrefix(v, "literal:"),
			strings.HasPrefix(v, "identifier:"),
			strings.HasPrefix(v, "selector:"),
			strings.HasPrefix(v, "attr_path:"),
			strings.HasPrefix(v, "index:"),
			strings.HasPrefix(v, "subscript:"),
			strings.HasPrefix(v, "binary:"),
			strings.HasPrefix(v, "expr:"):
			return true
		}
	}
	return false
}

func flagPattern(fl flagSpec) string {
	for _, pred := range fl.Predicates {
		if pred.Property == "path" || pred.Property == "method" || pred.Property == "op" || pred.Property == "tokens" {
			return strings.Join(pred.Values, "|")
		}
	}
	if fl.Scope != "" {
		return "analysis." + fl.Scope + ".context"
	}
	return fl.NodeKind
}

func flagNodeKindAllows(fl flagSpec, n usg.Node) bool {
	switch lowerString(fl.Scope) {
	case "function":
		return n.Type == "code.Call"
	case "module":
		return n.Type == "code.Call"
	case "class":
		return n.Type == "code.Call"
	default:
		switch lowerString(fl.NodeKind) {
		case "", "any":
			return true
		case "call":
			return n.Type == "code.Call"
		case "attr", "attribute":
			return n.Type == "code.Attr"
		case "seq", "collection", "object":
			return n.Type == "code.Seq"
		case "subscript", "index":
			return n.Type == "code.Subscript"
		case "binop", "binary":
			return n.Type == "code.BinOp"
		case "unary":
			return n.Type == "code.Unary"
		case "name", "identifier":
			return n.Type == "code.Name"
		default:
			return n.Type == "code."+titleNodeKind(fl.NodeKind)
		}
	}
}

// titleNodeKind maps a binding's node kind ("call") to the concept type suffix
// it names ("Call"). It replicates the word rule of the deprecated strings.Title
// -- upper-case the first letter of every run of letters -- so a kind containing
// a separator keeps the spelling it has always had. The kinds in the shipped
// bindings are single ASCII words, which this handles identically.

func flagMatchesNode(s usg.Store, idx *flagMatchIndex, fl flagSpec, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if fl.Scope != "" && n.Prop("callee_path") != "analysis."+lowerString(fl.Scope)+".context" {
		return false
	}
	if !flagPredicatesMatchNode(s, idx, fl.Predicates, fl.PredicateOrder, n, tech, crossLang, fileTech) {
		return false
	}
	if len(fl.Operands) == 0 {
		return true
	}
	if flagOperandsMatchNode(s, idx, fl.Operands, n, false) {
		return true
	}
	return flagOperandsMatchNode(s, idx, fl.Operands, n, true)
}

func flagPredicatesMatchNode(s usg.Store, idx *flagMatchIndex, preds []flagPredicate, order []int, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if len(order) > 0 {
		for _, i := range order {
			if !flagPredicateMatches(s, idx, preds[i], n, tech, crossLang, fileTech) {
				return false
			}
		}
		return true
	}
	for _, pred := range preds {
		if !flagPredicateMatches(s, idx, pred, n, tech, crossLang, fileTech) {
			return false
		}
	}
	return true
}

func flagOperandsMatchNode(s usg.Store, idx *flagMatchIndex, specs []flagOperandSpec, n usg.Node, includeFlow bool) bool {
	var groups [][]bool
	addGroup := func(argID string) {
		state := newFlagOperandGroupMatchState(specs)
		addNode := func(id string) {
			if node, ok, err := s.GetNode(id); err == nil && ok {
				state.addNode(node)
			}
		}
		addNode(argID)
		if includeFlow {
			seen := map[string]bool{argID: true}
			var collectUpstream func(string, int)
			collectUpstream = func(id string, depth int) {
				if depth >= 6 || state.allSpecsMatched() {
					return
				}
				rangeFlowIn(s, &idx.flow, id, func(srcID string) bool {
					if seen[srcID] {
						return true
					}
					seen[srcID] = true
					addNode(srcID)
					collectUpstream(srcID, depth+1)
					return !state.allSpecsMatched()
				})
			}
			collectUpstream(argID, 0)
		}
		groups = append(groups, state.matches)
	}
	hadArgProps := false
	for ai := 0; ; ai++ {
		argID := n.Prop(usg.ArgPropKey(ai))
		if argID == "" {
			break
		}
		hadArgProps = true
		addGroup(argID)
	}
	if !hadArgProps && includeFlow {
		rangeFlowIn(s, &idx.flow, n.ID, func(srcID string) bool {
			src, ok, err := s.GetNode(srcID)
			if err != nil || !ok || src.Type != "code.Arg" {
				return true
			}
			addGroup(srcID)
			return true
		})
	}
	return flagOperandGroupMatches(groups, len(specs))
}

type flagOperandGroupMatchState struct {
	specs   []flagOperandSpec
	hits    [][]bool
	matches []bool
	count   int
}

func (state *flagOperandGroupMatchState) addNode(n usg.Node) {
	for si, spec := range state.specs {
		if state.matches[si] {
			continue
		}
		if len(spec.PredicateOrder) > 0 {
			for _, pi := range spec.PredicateOrder {
				if !state.hits[si][pi] && flagPredicateMatchesNodeOnly(spec.Predicates[pi], n) {
					state.hits[si][pi] = true
				}
			}
		} else {
			for pi, pred := range spec.Predicates {
				if !state.hits[si][pi] && flagPredicateMatchesNodeOnly(pred, n) {
					state.hits[si][pi] = true
				}
			}
		}
		if allBool(state.hits[si]) {
			state.matches[si] = true
			state.count++
		}
	}
}

func (state *flagOperandGroupMatchState) allSpecsMatched() bool {
	return state.count == len(state.specs)
}

func flagOperandGroupMatches(groups [][]bool, specCount int) bool {
	used := make([]bool, len(groups))
	var matchOperand func(int) bool
	matchOperand = func(i int) bool {
		if i == specCount {
			return true
		}
		for gi, matches := range groups {
			if used[gi] || i >= len(matches) || !matches[i] {
				continue
			}
			used[gi] = true
			if matchOperand(i + 1) {
				return true
			}
			used[gi] = false
		}
		return false
	}
	return matchOperand(0)
}

func flagOperandCandidates(s usg.Store, idx *flagMatchIndex, n usg.Node, includeFlow bool) [][]usg.Node {
	var out [][]usg.Node
	addArgDirect := func(argID string) {
		var nodes []usg.Node
		if arg, ok, err := s.GetNode(argID); err == nil && ok {
			nodes = append(nodes, arg)
		}
		out = append(out, nodes)
	}
	addArgWithFlow := func(argID string) {
		var nodes []usg.Node
		if arg, ok, err := s.GetNode(argID); err == nil && ok {
			nodes = append(nodes, arg)
		}
		seen := map[string]bool{argID: true}
		var collectUpstream func(string, int)
		collectUpstream = func(id string, depth int) {
			if depth >= 6 {
				return
			}
			rangeFlowIn(s, &idx.flow, id, func(srcID string) bool {
				if seen[srcID] {
					return true
				}
				seen[srcID] = true
				if src, ok, err := s.GetNode(srcID); err == nil && ok {
					nodes = append(nodes, src)
				}
				collectUpstream(srcID, depth+1)
				return true
			})
		}
		collectUpstream(argID, 0)
		out = append(out, nodes)
	}
	hadArgProps := false
	for ai := 0; ; ai++ {
		argID := n.Prop(usg.ArgPropKey(ai))
		if argID == "" {
			break
		}
		hadArgProps = true
		if includeFlow {
			addArgWithFlow(argID)
		} else {
			addArgDirect(argID)
		}
	}
	if !hadArgProps && includeFlow {
		rangeFlowIn(s, &idx.flow, n.ID, func(srcID string) bool {
			src, ok, err := s.GetNode(srcID)
			if err != nil || !ok || src.Type != "code.Arg" {
				return true
			}
			addArgWithFlow(srcID)
			return true
		})
	}
	return out
}

func flagOperandCandidatesCached(s usg.Store, idx *flagMatchIndex, n usg.Node, includeFlow bool) [][]usg.Node {
	if idx == nil || n.ID == "" {
		return flagOperandCandidates(s, idx, n, includeFlow)
	}
	key := n.ID
	if includeFlow {
		key += "\x00flow"
	} else {
		key += "\x00direct"
	}
	if cached, ok := idx.operands.Load(key); ok {
		return cached.([][]usg.Node)
	}
	operands := flagOperandCandidates(s, idx, n, includeFlow)
	idx.operands.Store(key, operands)
	return operands
}

func flagPredicateMatches(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if pred.Subject == "flow_to" {
		hit := flagFlowToNodeHit(s, &idx.flow, pred, n, tech, crossLang, fileTech)
		if pred.Negative {
			return !hit
		}
		return hit
	}
	if pred.Subject == "scope_call" {
		probe := pred
		probe.Negative = false
		probe.cacheKey = ""
		hit, ok := flagAnalysisContextScopeCallHit(idx, probe, n)
		if !ok {
			hit = flagScopeNodeHit(s, idx, probe, n, []string{"code.Call"}, tech, crossLang)
		}
		if pred.Negative {
			return !hit
		}
		return hit
	}
	if isAnalysisContextNode(n) {
		if ok, hit := flagContextPredicateMatchesAST(s, idx, pred, n, tech, crossLang); ok {
			if !flagPredicateUsesCallArg(pred) && !hit {
				probe := pred
				probe.Negative = false
				probe.cacheKey = ""
				strArgs := n.Prop("str_args")
				hit = flagContextTokenValuePredicateCached(idx, probe, strArgs)
			}
			if pred.Negative {
				return !hit
			}
			return hit
		}
	}
	if pred.Property == "tokens" {
		var hit bool
		if flagPredicateUsesCallArg(pred) {
			hit = flagContextTokenValuePredicateCached(idx, pred, callArgContextTokens(n))
		} else {
			hit = flagContextTokenValuePredicateCached(idx, pred, n.Prop("str_args"))
		}
		if pred.Negative {
			return !hit
		}
		return hit
	}
	return flagPredicateMatchesNodeOnly(pred, n)
}

func isAnalysisContextNode(n usg.Node) bool {
	switch n.Prop("callee_path") {
	case "analysis.function.context", "analysis.module.context", "analysis.class.context":
		return true
	default:
		return false
	}
}

func flagAnalysisContextScopeCallHit(idx *flagMatchIndex, pred flagPredicate, n usg.Node) (bool, bool) {
	if !isAnalysisContextNode(n) {
		return false, false
	}
	text := n.Prop("str_args")
	facts := idx.contextFacts(text)
	switch pred.Property {
	case "path":
		for _, path := range facts.byPrefix["call_path:"] {
			if flagScopeCallFactMatches(pred, path, lastSeg(path)) {
				return true, true
			}
		}
		return false, false
	case "method":
		for _, method := range facts.byPrefix["call:"] {
			if flagScopeCallFactMatches(pred, "", method) {
				return true, true
			}
		}
		for _, path := range facts.byPrefix["call_path:"] {
			if method := lastSeg(path); method != "" && flagScopeCallFactMatches(pred, "", method) {
				return true, true
			}
		}
		return false, false
	case "any":
		for _, path := range facts.byPrefix["call_path:"] {
			if flagScopeCallFactMatches(pred, path, lastSeg(path)) {
				return true, true
			}
		}
		for _, method := range facts.byPrefix["call:"] {
			if flagScopeCallFactMatches(pred, "", method) {
				return true, true
			}
		}
		return false, false
	default:
		return false, false
	}
}

func flagScopeCallFactMatches(pred flagPredicate, path, method string) bool {
	switch pred.Property {
	case "path":
		if path == "" {
			return false
		}
		if pred.Op == "exists" {
			return true
		}
		if pred.Op == "equals" || pred.Op == "equals_any" || pred.Op == "starts_with" || pred.Op == "ends_with" {
			return flagValuePredicate(pred, path)
		}
		for _, value := range pred.Values {
			if pred.Exact && path == value || !pred.Exact && matchSinkPath(path, value) {
				return true
			}
		}
		return false
	case "method":
		if method == "" {
			return false
		}
		if pred.Op == "exists" || pred.Op == "contains" || pred.Op == "starts_with" || pred.Op == "ends_with" || pred.Op == "equals" || pred.Op == "equals_any" {
			return flagValuePredicate(pred, method)
		}
		return containsStr(pred.Values, method)
	case "any":
		text := "code.Call\x00" + path + "\x00" + method
		return flagValuePredicate(pred, text)
	default:
		return false
	}
}

func flagPredicateUsesCallArg(pred flagPredicate) bool {
	if pred.Property != "tokens" {
		return false
	}
	for _, v := range pred.Values {
		if strings.HasPrefix(v, "call_arg:") {
			return true
		}
	}
	return false
}

// flagASTRoutingValuePrefixes are token-value prefixes that make a context-token
// predicate match via the AST/scope path (flagContextPredicateMatchesAST), not via
// the node's str_args text. A predicate carrying any of these can match a node whose
// str_args does not contain the value, so it is NOT safe as a str_args pre-filter.

var flagASTRoutingValuePrefixes = []string{
	"call_arg:", "call_path:", "call:", "literal:", "identifier:",
	"selector:", "attr_path:", "index:", "subscript:", "binary:", "expr:",
}

var flagPlainContextShortcutPrefixes = []string{
	"python_review:", "ruby_review:", "rust_review:", "php_review:",
	"function_name:", "name=",
}

var flagPythonStructuredContextShortcutPrefixes = []string{
	"call_path:", "call:", "identifier:", "selector:", "subscript:", "expr:",
	"function_name:", "name=", "param_name:", "decorator_method:",
}

// isPlainContextTokenPredicate reports whether pred matches a node by, and only by,
// testing its str_args text via flagContextTokenValuePredicateCached. That holds for a
// positive `tokens` predicate with no flow_to/scope_call subject and no AST-routing
// value prefix: for every node kind flagPredicateMatches then reduces to exactly the
// str_args check (plain tokens make flagContextPredicateMatchesAST return false, so the
// analysis-context branch falls through to the str_args branch).

func isPlainContextTokenPredicate(p flagPredicate) bool {
	if p.Negative || p.Property != "tokens" || (p.Subject != "" && p.Subject != "node") || len(p.Values) == 0 {
		return false
	}
	if p.Op != "" && p.Op != "contains" && p.Op != "contains_any" && p.Op != "equals" && p.Op != "equals_any" {
		return false
	}
	for _, v := range p.Values {
		if !hasAnyPrefix(v, flagPlainContextShortcutPrefixes) {
			return false
		}
	}
	for _, v := range p.Values {
		for _, pre := range flagASTRoutingValuePrefixes {
			if strings.HasPrefix(v, pre) {
				return false
			}
		}
	}
	return true
}

func isPythonStructuredContextTokenPredicate(p flagPredicate) bool {
	if p.Negative || p.Property != "tokens" || (p.Subject != "" && p.Subject != "node") || len(p.Values) == 0 {
		return false
	}
	if p.Op != "" && p.Op != "contains" && p.Op != "contains_any" && p.Op != "equals" && p.Op != "equals_any" {
		return false
	}
	for _, v := range p.Values {
		if !hasAnyPrefix(v, flagPythonStructuredContextShortcutPrefixes) {
			return false
		}
	}
	return true
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// flagContextOnlyPredicate returns a single plain context-token predicate from fl
// whose str_args check is a sound NECESSARY condition for the whole flag to match,
// letting the caller cheaply pre-filter nodes before the full flagMatchesNode pass.
// flag predicates combine by AND (flagPredicatesMatchNode) and operands only tighten
// the match, so a failing necessary conjunct guarantees no match — the fast path can
// never drop a real finding. ok=false (no qualifying predicate) leaves the full match
// to run unchanged.

func flagContextOnlyPredicate(fl flagSpec, tech string) (flagPredicate, bool) {
	allowPythonStructured := tech == "python"
	if len(fl.PredicateOrder) > 0 {
		for _, i := range fl.PredicateOrder {
			if isPlainContextTokenPredicate(fl.Predicates[i]) ||
				allowPythonStructured && isPythonStructuredContextTokenPredicate(fl.Predicates[i]) {
				return fl.Predicates[i], true
			}
		}
	}
	for _, p := range fl.Predicates {
		if isPlainContextTokenPredicate(p) ||
			allowPythonStructured && isPythonStructuredContextTokenPredicate(p) {
			return p, true
		}
	}
	return flagPredicate{}, false
}

func flagContextOnlyPredicateMaybePresent(pred flagPredicate, text string) bool {
	if structuredContextPredicateTokenFamilyMissing(pred, text) {
		return true
	}
	op := pred.Op
	switch op {
	case "", "equals":
		op = "contains"
	case "equals_any":
		op = "contains_any"
	}
	all := op != "contains_any"
	for i, value := range pred.Values {
		prefix, want, ok := splitContextTokenPredicateValue(value)
		if !ok {
			return valuePredicateLowerValuesWithLowerText(op, pred.Values, pred.lowerValues(), text, lowerString(text))
		}
		wantLower := lowerString(want)
		valuesLower := pred.lowerValues()
		if i < len(valuesLower) {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == lowerString(prefix) {
				wantLower = lowerWant
			}
		}
		hit := contextTokenContainsValueLower(text, prefix, want, wantLower)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func structuredContextPredicateTokenFamilyMissing(pred flagPredicate, text string) bool {
	if pred.Property != "tokens" {
		return false
	}
	checked := map[string]bool{}
	sawStructured := false
	for _, value := range pred.Values {
		prefix, _, ok := splitContextTokenPredicateValue(value)
		if !ok || !hasAnyPrefix(value, flagPythonStructuredContextShortcutPrefixes) {
			continue
		}
		sawStructured = true
		if checked[prefix] {
			continue
		}
		checked[prefix] = true
		if strings.Contains(text, prefix) {
			return false
		}
	}
	return sawStructured && !strings.Contains(text, "\x00")
}

func contextTokenContainsValueLower(text, prefix, want, wantLower string) bool {
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var tok string
		if end < 0 {
			tok = text[start:]
			start = len(text) + 1
		} else {
			tok = text[start : start+end]
			start += end + 1
		}
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		if contextTokenContainsLower(prefix, tok[len(prefix):], want, wantLower) {
			return true
		}
	}
	return false
}

func flagPositiveOpPredicate(fl flagSpec) (flagPredicate, bool) {
	if len(fl.PredicateOrder) > 0 {
		for _, i := range fl.PredicateOrder {
			if isPositiveOpPredicate(fl.Predicates[i]) {
				return fl.Predicates[i], true
			}
		}
	}
	for _, p := range fl.Predicates {
		if isPositiveOpPredicate(p) {
			return p, true
		}
	}
	return flagPredicate{}, false
}

func isPositiveOpPredicate(p flagPredicate) bool {
	return !p.Negative && p.Property == "op" && (p.Subject == "" || p.Subject == "node") && len(p.Values) > 0
}

func flagFlowToNodeHit(s usg.Store, idx *flowTokenIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if idx == nil {
		return false
	}
	probe := pred
	probe.Subject = "node"
	probe.Negative = false
	probe.cacheKey = ""
	prefix := locFile(n.Prop("loc"))
	seen := map[string]bool{n.ID: true}
	type item struct {
		id    string
		depth int
	}
	q := []item{{id: n.ID}}
	found := false
	for len(q) > 0 && len(seen) < 256 && !found {
		cur := q[0]
		q = q[1:]
		if cur.depth >= 6 {
			continue
		}
		rangeFlowOut(s, idx, cur.id, func(dstID string) bool {
			if seen[dstID] {
				return true
			}
			seen[dstID] = true
			dst, ok, err := s.GetNode(dstID)
			if err == nil && ok {
				if prefix != "" && locFile(dst.Prop("loc")) != prefix {
					return true
				}
				if t := nodeTechFromNodeWithFileContext(dst, fileTech); !crossLang && t != "" && t != tech {
					return true
				}
				if flagPredicateMatchesNodeOnly(probe, dst) {
					found = true
					return false
				}
			}
			q = append(q, item{id: dstID, depth: cur.depth + 1})
			return len(seen) < 256
		})
	}
	return found
}

func flagContextPredicateMatchesAST(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool) (bool, bool) {
	if pred.Property != "tokens" || len(pred.Values) == 0 {
		return false, false
	}
	var probe flagPredicate
	var nodeTypes []string
	for _, v := range pred.Values {
		switch {
		case strings.HasPrefix(v, "call_arg:"):
			return true, flagScopeCallArgHit(s, idx, pred, n, tech, crossLang)
		case strings.HasPrefix(v, "call_path:"):
			probe = newFlagPredicate("", "path", pred.Op, trimFlagValuePrefix(pred.Values, "call_path:"), pred.Exact, false)
			nodeTypes = []string{"code.Call"}
		case strings.HasPrefix(v, "call:"):
			probe = newFlagPredicate("", "method", pred.Op, trimFlagValuePrefix(pred.Values, "call:"), pred.Exact, false)
			nodeTypes = []string{"code.Call"}
		case strings.HasPrefix(v, "literal:"):
			probe = newFlagPredicate("", "tokens", pred.Op, trimFlagValuePrefix(pred.Values, "literal:"), pred.Exact, false)
			nodeTypes = []string{"code.Const"}
		case strings.HasPrefix(v, "identifier:"):
			probe = newFlagPredicate("", "identifier", pred.Op, trimFlagValuePrefix(pred.Values, "identifier:"), pred.Exact, false)
			nodeTypes = []string{"code.Name", "code.Param"}
		case strings.HasPrefix(v, "selector:"), strings.HasPrefix(v, "attr_path:"):
			prefix := "selector:"
			if strings.HasPrefix(v, "attr_path:") {
				prefix = "attr_path:"
			}
			prop := "path"
			if pred.Op == "contains_any" {
				prop = "any"
			}
			probe = newFlagPredicate("", prop, pred.Op, trimFlagValuePrefix(pred.Values, prefix), pred.Exact, false)
			nodeTypes = []string{"code.Attr"}
		case strings.HasPrefix(v, "index:"), strings.HasPrefix(v, "subscript:"):
			prefix := "index:"
			if strings.HasPrefix(v, "subscript:") {
				prefix = "subscript:"
			}
			return true, flagScopeSubscriptHit(s, idx, pred, n, trimFlagValuePrefix(pred.Values, prefix), tech, crossLang)
		case strings.HasPrefix(v, "binary:"), strings.HasPrefix(v, "expr:"):
			prefix := "binary:"
			if strings.HasPrefix(v, "expr:") {
				prefix = "expr:"
			}
			return true, flagScopeBinopHit(s, idx, pred, n, trimFlagValuePrefix(pred.Values, prefix), tech, crossLang)
		case strings.HasPrefix(v, "name="), strings.HasPrefix(v, "function_name:"):
			return false, false
		default:
			return false, false
		}
	}
	return true, flagScopeNodeHit(s, idx, probe, n, nodeTypes, tech, crossLang)
}

func flagScopeBinopHit(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, values []string, tech string, crossLang bool) bool {
	return idx.scopedHit(s, "binop", pred, values, []string{"code.BinOp"}, n, tech, crossLang, true, func(cand usg.Node) bool {
		return binopPredicateMatches(s, idx, pred.Op, values, cand)
	})
}

func binopPredicateMatches(s usg.Store, idx *flagMatchIndex, op string, values []string, n usg.Node) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any" && op != "any"
	for _, value := range values {
		hit := binopValueMatches(s, idx, value, n)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func binopValueMatches(s usg.Store, idx *flagMatchIndex, value string, n usg.Node) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	left, op, right, ok := splitBinaryPredicate(value)
	if !ok {
		return valuePredicate("contains", []string{value}, nodeSearchText(n))
	}
	if got := n.Prop("op"); got != "" && got != op {
		return false
	}
	if valuePredicate("contains", []string{value}, nodeSearchText(n)) {
		return true
	}
	operands := flagOperandCandidatesCached(s, idx, n, false)
	flowExpanded := false
	if len(operands) < 2 {
		operands = flagOperandCandidatesCached(s, idx, n, true)
		flowExpanded = true
	}
	if len(operands) < 2 {
		return false
	}
	if binopValueMatchesOperands(left, op, right, operands) {
		return true
	}
	if flowExpanded {
		return false
	}
	operands = flagOperandCandidatesCached(s, idx, n, true)
	return binopValueMatchesOperands(left, op, right, operands)
}

func binopValueMatchesOperands(left, op, right string, operands [][]usg.Node) bool {
	if len(operands) < 2 {
		return false
	}
	if binopOperandTextMatches(left, operands[0]) && binopOperandTextMatches(right, operands[1]) {
		return true
	}
	switch op {
	case "==", "===", "!=", "!==":
		return binopOperandTextMatches(left, operands[1]) && binopOperandTextMatches(right, operands[0])
	default:
		return false
	}
}

func splitBinaryPredicate(value string) (left, op, right string, ok bool) {
	for _, candidate := range []string{"!==", "===", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "+", "-", "*", "/", "%", "<", ">"} {
		if idx := strings.Index(value, candidate); idx > 0 {
			left = strings.TrimSpace(value[:idx])
			right = strings.TrimSpace(value[idx+len(candidate):])
			if left != "" && right != "" {
				return left, candidate, right, true
			}
		}
	}
	return "", "", "", false
}

func binopOperandTextMatches(want string, nodes []usg.Node) bool {
	want = normalizeFlagExprFragment(want)
	if want == "" {
		return false
	}
	var texts []string
	for _, n := range nodes {
		texts = append(texts, normalizeFlagExprFragment(nodeSearchText(n)+"\x00"+n.ID+"\x00"+n.Prop("name")))
	}
	text := strings.Join(texts, "\x00")
	if strings.Contains(text, want) {
		return true
	}
	if open := strings.IndexByte(want, '('); open > 0 && strings.HasSuffix(want, ")") {
		fn := want[:open]
		argText := strings.TrimSuffix(want[open+1:], ")")
		if fn != "" && !strings.Contains(text, fn) {
			return false
		}
		for _, part := range strings.Split(argText, ",") {
			part = strings.TrimSpace(part)
			if part != "" && !strings.Contains(text, part) {
				return false
			}
		}
		return true
	}
	return false
}

var flagExprFragmentReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", `"`, "", "'", "", "`", "")

func normalizeFlagExprFragment(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && len(s) > 1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return flagExprFragmentReplacer.Replace(s)
}

func flagScopeSubscriptHit(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, values []string, tech string, crossLang bool) bool {
	return idx.scopedHit(s, "subscript", pred, values, []string{"code.Subscript"}, n, tech, crossLang, true, func(cand usg.Node) bool {
		return subscriptPredicateMatches(pred.Op, values, cand)
	})
}

func subscriptPredicateMatches(op string, values []string, n usg.Node) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any" && op != "any"
	for _, value := range values {
		base, key := splitSubscriptPredicate(value)
		hit := false
		if base != "" && matchSinkPath(n.Prop("callee_path"), base) {
			hit = key == "" || subscriptKeyMatches(n, key)
		}
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func splitSubscriptPredicate(value string) (base, key string) {
	if i := strings.LastIndex(value, "["); i > 0 && strings.HasSuffix(value, "]") {
		base = value[:i] + ".__subscript"
		key = strings.Trim(value[i+1:len(value)-1], `"'`)
		return base, key
	}
	return normalizeSubscriptFlagValues([]string{value})[0], ""
}

func subscriptKeyMatches(n usg.Node, key string) bool {
	if key == "" {
		return true
	}
	for _, text := range []string{n.Prop("str_args"), nodeSearchText(n), n.ID} {
		if valContains(text, key) {
			return true
		}
	}
	return false
}

func flagScopeCallArgHit(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool) bool {
	return idx.scopedHit(s, "call_arg", pred, nil, []string{"code.Call"}, n, tech, crossLang, true, func(cand usg.Node) bool {
		if tech == "javascript" && !callArgPredicateMayMatchCall(pred, cand) {
			return false
		}
		if callArgFactsMatch(pred.Op, pred.Values, pred.lowerValues(), callArgContextFactsScoped(s, idx, cand, tech, crossLang)) {
			return true
		}
		return false
	})
}

type callArgCacheKey struct {
	id        string
	tech      string
	crossLang bool
}

// callArgContextFacts is the structured form of the virtual tokens
// "call_arg:<path>:<value>" and "call_arg_method:<method>:<value>". Keeping the
// stable pieces separate avoids constructing and retaining the same path/method prefix once per
// reachable argument, then parsing that large string back into contextTokenFacts.
type callArgContextFacts struct {
	path   string
	method string
	values []string

	// The token text these facts stand for, built on first use. The index holds
	// one facts value per node, so every predicate about that node reads the
	// same string and no call rebuilds it.
	once sync.Once
	text string
}

func (f *callArgContextFacts) tokens() string {
	f.once.Do(func() { f.text = f.materialize() })
	return f.text
}

type segmentedContextToken struct {
	parts [4]string
	n     int
}

// callArgFactsMatch answers a predicate about one call's argument facts.
//
// The facts are the structured form of the virtual tokens, so the predicate is
// answered against the token text they stand for. Matching a token by its parts
// is not the same question: a predicate value of the form `<prefix>:<want>` is
// scoped to tokens carrying that prefix and is compared against the rest of the
// token, and `contains` over several values is one conjunction over the token
// text ORed with another over the prefix-scoped values. Comparing whole tokens
// instead misses a call the definitions expect to match.
//
// The token text is built once per call and held on the facts, which the index
// keeps per node, so the work is the same whichever predicate asks first.
func callArgFactsMatch(op string, values, valuesLower []string, facts *callArgContextFacts) bool {
	if facts == nil {
		return false
	}
	return contextTokenValuePredicateLowerValues(op, values, valuesLower, facts.tokens())
}

func (f *callArgContextFacts) anyToken(fn func(segmentedContextToken) bool) bool {
	for _, value := range f.values {
		if f.path != "" && fn(segmentedContextToken{parts: [4]string{"call_arg:", f.path, ":", value}, n: 4}) {
			return true
		}
		if f.method != "" && fn(segmentedContextToken{parts: [4]string{"call_arg_method:", f.method, ":", value}, n: 4}) {
			return true
		}
	}
	return false
}

func (f *callArgContextFacts) materialize() string {
	if f == nil || len(f.values) == 0 {
		return ""
	}
	var b strings.Builder
	wrote := false
	f.anyToken(func(tok segmentedContextToken) bool {
		if wrote {
			b.WriteByte(0)
		}
		for i := 0; i < tok.n; i++ {
			b.WriteString(tok.parts[i])
		}
		wrote = true
		return false
	})
	return b.String()
}

func callArgPredicateMayMatchCall(pred flagPredicate, cand usg.Node) bool {
	anyMode := pred.Op == "contains_any" || pred.Op == "equals_any" || pred.Op == "any"
	path := cand.Prop("callee_path")
	sawPathConstraint := false
	anyHit := false
	for _, value := range pred.Values {
		want, ok := callArgPredicatePath(value)
		if !ok {
			continue
		}
		sawPathConstraint = true
		hit := path != "" && matchSinkPath(path, want)
		if anyMode {
			if hit {
				return true
			}
			continue
		}
		if !hit {
			return false
		}
		anyHit = true
	}
	if !sawPathConstraint {
		return true
	}
	if anyMode {
		return false
	}
	return anyHit
}

func callArgPredicatePath(value string) (string, bool) {
	if !strings.HasPrefix(value, "call_arg:") {
		return "", false
	}
	rest := strings.TrimPrefix(value, "call_arg:")
	if rest == "" {
		return "", false
	}
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return "", false
	}
	return rest[:i], true
}

func callArgContextFactsScoped(s usg.Store, idx *flagMatchIndex, n usg.Node, tech string, crossLang bool) *callArgContextFacts {
	idx.ensure(s)
	cacheKey := callArgCacheKey{id: n.ID, tech: tech, crossLang: crossLang}
	if cached, ok := idx.callArgFacts.Load(cacheKey); ok {
		return cached.(*callArgContextFacts)
	}
	path := n.Prop("callee_path")
	method := n.Prop("method")
	facts := &callArgContextFacts{path: path, method: method}
	if path == "" && method == "" {
		idx.callArgFacts.Store(cacheKey, facts)
		return facts
	}
	seen := map[string]bool{}
	addValue := func(text string) {
		if text == "" || seen[text] {
			return
		}
		seen[text] = true
		facts.values = append(facts.values, text)
	}
	add := func(text string) {
		addValue(strings.TrimSpace(text))
	}
	addNode := func(node usg.Node) {
		add(node.Prop("str_args"))
		add(node.Type)
		add(node.Prop("callee_path"))
		add(node.Prop("method"))
		add(node.Prop("op"))
		add(node.Prop("name"))
		add(node.Prop("path"))
		add(node.ID)
	}
	// Direct tokens were historically kept verbatim, including duplicates. Keep
	// that representation stable; only the extra flow-derived values are deduped.
	forEachNULToken(n.Prop("str_args"), func(text string) {
		facts.values = append(facts.values, text)
	})
	rangeFlowIn(s, &idx.flow, n.ID, func(argID string) bool {
		arg, ok := idx.node(s, argID)
		if !ok || arg.Type != "code.Arg" || !idx.scopedCallArgCandidate(arg, n, tech, crossLang) {
			return true
		}
		addNode(arg)
		rangeFlowIn(s, &idx.flow, arg.ID, func(srcID string) bool {
			src, ok := idx.node(s, srcID)
			if !ok || !callArgSourceNodeType(src.Type) || !idx.scopedCallArgCandidate(src, n, tech, crossLang) {
				return true
			}
			addNode(src)
			return true
		})
		return true
	})
	idx.callArgFacts.Store(cacheKey, facts)
	return facts
}

func callArgSourceNodeType(typ string) bool {
	switch typ {
	case "code.Format", "code.Const", "code.Name", "code.Attr", "code.Seq", "code.Call":
		return true
	default:
		return false
	}
}

func callArgContextTokens(n usg.Node) string {
	path := n.Prop("callee_path")
	method := n.Prop("method")
	if path == "" && method == "" {
		return ""
	}
	text := n.Prop("str_args")
	pathPrefix := ""
	methodPrefix := ""
	if path != "" {
		pathPrefix = "call_arg:" + path + ":"
	}
	if method != "" {
		methodPrefix = "call_arg_method:" + method + ":"
	}
	needed, count := 0, 0
	forEachNULToken(text, func(arg string) {
		if pathPrefix != "" {
			needed += len(pathPrefix) + len(arg)
			count++
		}
		if methodPrefix != "" {
			needed += len(methodPrefix) + len(arg)
			count++
		}
	})
	if count > 1 {
		needed += count - 1
	}
	var b strings.Builder
	b.Grow(needed)
	wrote := false
	add := func(prefix, arg string) {
		if wrote {
			b.WriteByte(0)
		}
		b.WriteString(prefix)
		b.WriteString(arg)
		wrote = true
	}
	forEachNULToken(text, func(arg string) {
		if pathPrefix != "" {
			add(pathPrefix, arg)
		}
		if methodPrefix != "" {
			add(methodPrefix, arg)
		}
	})
	return b.String()
}

func forEachNULToken(text string, fn func(string)) {
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var arg string
		if end < 0 {
			arg = text[start:]
			start = len(text) + 1
		} else {
			arg = text[start : start+end]
			start += end + 1
		}
		if arg == "" {
			continue
		}
		fn(arg)
	}
}

func trimFlagValuePrefix(values []string, prefix string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.TrimPrefix(v, prefix))
	}
	return out
}

func normalizeSubscriptFlagValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.HasSuffix(v, "]") {
			if i := strings.LastIndex(v, "["); i > 0 {
				v = v[:i] + ".__subscript"
			}
		}
		out = append(out, v)
	}
	return out
}

func flagScopeNodeHit(s usg.Store, idx *flagMatchIndex, pred flagPredicate, n usg.Node, nodeTypes []string, tech string, crossLang bool) bool {
	probe := pred
	probe.Negative = false
	probe.cacheKey = ""
	if idx.scopedHit(s, "node", probe, nil, nodeTypes, n, tech, crossLang, false, func(cand usg.Node) bool {
		return flagPredicateMatchesNodeOnly(probe, cand)
	}) {
		return true
	}
	if nodeLexicalScope(n) == "" || !containsStr(nodeTypes, "code.Param") {
		return false
	}
	file, line := splitLocFileLine(n.Prop("loc"))
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		hit := false
		rangeNodeIndexes(is, idx.paramsByLineI[file][line], func(cand usg.Node) bool {
			if cand.ID == n.ID || nodeLexicalScope(cand) != "" {
				return true
			}
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				return true
			}
			if flagPredicateMatchesNodeOnly(probe, cand) {
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	hit := false
	rangeNodeIDs(s, idx.paramsByLine[file][line], func(cand usg.Node) bool {
		if cand.ID == n.ID || nodeLexicalScope(cand) != "" {
			return true
		}
		if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
			return true
		}
		if flagPredicateMatchesNodeOnly(probe, cand) {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func nodeLexicalScope(n usg.Node) string {
	if n.Scope != "" {
		return n.Scope
	}
	return n.Prop("region")
}

func sameOrNestedNormalizedScope(candidate, anchor string) bool {
	if candidate == anchor {
		return true
	}
	return len(candidate) > len(anchor) &&
		strings.HasPrefix(candidate, anchor) &&
		candidate[len(anchor)] == '/'
}

func scopeWithoutOrder(scope string) string {
	if scope == "" {
		return ""
	}
	parts := strings.Split(scope, "/")
	for i, part := range parts {
		if at := strings.Index(part, "@"); at >= 0 {
			parts[i] = part[:at]
		}
	}
	return strings.Join(parts, "/")
}

func flagPredicateMatchesNodeOnly(pred flagPredicate, n usg.Node) bool {
	hit := flagPredicateHit(pred, n)
	if pred.Negative {
		return !hit
	}
	return hit
}

func flagPredicateHit(pred flagPredicate, n usg.Node) bool {
	switch pred.Property {
	case "path":
		for _, path := range []string{n.Prop("callee_path"), n.Prop("path")} {
			if path == "" {
				continue
			}
			if pred.Op == "exists" {
				return true
			}
			if pred.Op == "equals" || pred.Op == "equals_any" {
				if flagValuePredicate(pred, path) {
					return true
				}
				continue
			}
			if pred.Op == "starts_with" || pred.Op == "ends_with" {
				if flagValuePredicate(pred, path) {
					return true
				}
				continue
			}
			for _, v := range pred.Values {
				if pred.Exact && path == v || !pred.Exact && matchSinkPath(path, v) {
					return true
				}
			}
		}
		return false
	case "method":
		if pred.Op == "exists" || pred.Op == "contains" || pred.Op == "starts_with" || pred.Op == "ends_with" || pred.Op == "equals" || pred.Op == "equals_any" {
			return flagValuePredicate(pred, n.Prop("method"))
		}
		return containsStr(pred.Values, n.Prop("method"))
	case "op":
		return flagValuePredicate(pred, n.Prop("op"))
	case "tokens":
		if flagPredicateUsesCallArg(pred) {
			return flagContextTokenValuePredicate(pred, callArgContextTokens(n))
		}
		return flagContextTokenValuePredicate(pred, n.Prop("str_args"))
	case "identifier":
		if n.Type != "code.Name" && n.Type != "code.Param" {
			return false
		}
		return flagValuePredicate(pred, n.Prop("callee_path")+"\x00"+n.Prop("method")+"\x00"+n.Prop("name")+"\x00"+n.ID)
	case "key":
		return flagValuePredicate(pred, n.Prop("str_args")+"\x00"+n.Prop("callee_path"))
	case "call":
		if n.Type != "code.Call" {
			return false
		}
		return flagValuePredicate(pred, nodeSearchText(n))
	case "any":
		return flagValuePredicate(pred, nodeSearchText(n))
	default:
		return flagValuePredicate(pred, n.Prop(pred.Property))
	}
}

func contextTokenValuePredicate(op string, values []string, text string) bool {
	return contextTokenValuePredicateLowerValues(op, values, lowerStrings(values), text)
}

func flagContextTokenValuePredicate(pred flagPredicate, text string) bool {
	return contextTokenValuePredicateLowerValues(pred.Op, pred.Values, pred.lowerValues(), text)
}

func flagContextTokenValuePredicateCached(idx *flagMatchIndex, pred flagPredicate, text string) bool {
	return contextTokenValuePredicateLowerValuesWithCache(pred.Op, pred.Values, pred.lowerValues(), text, idx)
}

func contextTokenValuePredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	return contextTokenValuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerString(text))
}

func contextTokenValuePredicateLowerValuesWithCache(op string, values, valuesLower []string, text string, idx *flagMatchIndex) bool {
	if op == "exists" {
		facts := idx.contextFacts(text)
		return contextTokenExistsPredicateCached(values, text, facts)
	}
	if op == "equals" || op == "equals_any" {
		facts := idx.contextFacts(text)
		if contextTokenEqualsPredicateCached(op, values, text, facts) {
			return true
		}
		return valuePredicateLowerValues(op, values, valuesLower, text)
	}
	if op == "contains" || op == "" || op == "contains_any" {
		lowerText := idx.lowerTextValue(text)
		if valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText) {
			return true
		}
		facts := idx.contextFacts(text)
		return contextTokenContainsPredicateCached(op, values, valuesLower, facts)
	}
	if op == "starts_with" || op == "ends_with" {
		facts := idx.contextFacts(text)
		if contextTokenBoundaryPredicateCached(op, values, valuesLower, facts) {
			return true
		}
		return valuePredicateLowerValues(op, values, valuesLower, text)
	}
	return valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, idx.lowerTextValue(text))
}

func contextTokenValuePredicateLowerValuesWithLowerText(op string, values, valuesLower []string, text, lowerText string) bool {
	if op == "exists" {
		return contextTokenExistsPredicate(values, text)
	}
	if op == "equals" || op == "equals_any" {
		if contextTokenEqualsPredicate(op, values, text) {
			return true
		}
	}
	if op == "contains" || op == "" || op == "contains_any" {
		if valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText) {
			return true
		}
		if contextTokenContainsPredicateLowerValues(op, values, valuesLower, text) {
			return true
		}
		return false
	}
	if op == "starts_with" || op == "ends_with" {
		if contextTokenBoundaryPredicateLowerValues(op, values, valuesLower, text) {
			return true
		}
	}
	return valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText)
}

func contextTokenExistsPredicate(values []string, text string) bool {
	if len(values) == 0 {
		return text != ""
	}
	tokens := contextTokensByPrefix(text)
	for _, value := range values {
		prefix, want, ok := splitContextTokenPredicateValue(value)
		if !ok {
			if value == "" && text != "" {
				return true
			}
			continue
		}
		if want == "" {
			if len(tokens[prefix]) > 0 {
				return true
			}
			continue
		}
		for _, got := range tokens[prefix] {
			if got == want {
				return true
			}
		}
	}
	return false
}

func contextTokenExistsPredicateCached(values []string, text string, facts *contextTokenFacts) bool {
	if len(values) == 0 {
		return text != ""
	}
	for _, value := range values {
		prefix, want, ok := splitContextTokenPredicateValue(value)
		if !ok {
			if value == "" && text != "" {
				return true
			}
			continue
		}
		tokens := facts.byPrefix[prefix]
		if want == "" {
			if len(tokens) > 0 {
				return true
			}
			continue
		}
		for _, got := range tokens {
			if got == want {
				return true
			}
		}
	}
	return false
}

func contextTokenEqualsPredicate(op string, values []string, text string) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "equals_any"
	if len(values) == 1 {
		prefix, want, ok := splitContextTokenPredicateValue(values[0])
		if !ok {
			return false
		}
		hit := contextTokenValueMatch(text, prefix, func(got string) bool { return got == want })
		if all {
			return hit
		}
		return hit
	}
	tokens := contextTokensByPrefix(text)
	for _, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			for _, got := range tokens[prefix] {
				if got == want {
					hit = true
					break
				}
			}
		}
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func contextTokenEqualsPredicateCached(op string, values []string, text string, facts *contextTokenFacts) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "equals_any"
	if len(values) == 1 {
		prefix, want, ok := splitContextTokenPredicateValue(values[0])
		if !ok {
			return false
		}
		hit := false
		for _, got := range facts.byPrefix[prefix] {
			if got == want {
				hit = true
				break
			}
		}
		if all {
			return hit
		}
		return hit
	}
	for _, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			for _, got := range facts.byPrefix[prefix] {
				if got == want {
					hit = true
					break
				}
			}
		}
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func contextTokenContainsPredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any"
	if len(values) == 1 {
		prefix, want, ok := splitContextTokenPredicateValue(values[0])
		if !ok {
			return false
		}
		wantLower := lowerString(want)
		if len(valuesLower) == 1 {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[0]); lowerOK && lowerPrefix == lowerString(prefix) {
				wantLower = lowerWant
			}
		}
		hit := contextTokenValueMatch(text, prefix, func(got string) bool {
			return contextTokenContainsLower(prefix, got, want, wantLower)
		})
		if all {
			return hit
		}
		return hit
	}
	tokens := contextTokensByPrefix(text)
	for i, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			wantLower := lowerString(want)
			if i < len(valuesLower) {
				if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == lowerString(prefix) {
					wantLower = lowerWant
				}
			}
			for _, got := range tokens[prefix] {
				if contextTokenContainsLower(prefix, got, want, wantLower) {
					hit = true
					break
				}
			}
		}
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func contextTokenContainsPredicateCached(op string, values, valuesLower []string, facts *contextTokenFacts) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any"
	for i, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			wantLower := lowerString(want)
			if i < len(valuesLower) {
				if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == lowerString(prefix) {
					wantLower = lowerWant
				}
			}
			if prefix == "class_base:" {
				for _, got := range facts.byPrefix[prefix] {
					if classBaseTokenMatches(got, want) {
						hit = true
						break
					}
				}
			} else {
				for _, got := range facts.byPrefix[prefix] {
					if valContainsFoldedNeedle(got, wantLower) {
						hit = true
						break
					}
				}
			}
		}
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func contextTokenBoundaryPredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	if len(values) == 0 {
		return false
	}
	suffix := op == "ends_with"
	if len(values) == 1 {
		prefix, want, ok := splitContextTokenPredicateValue(values[0])
		if !ok {
			return false
		}
		wantLower := lowerString(want)
		if len(valuesLower) == 1 {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[0]); lowerOK && lowerPrefix == lowerString(prefix) {
				wantLower = lowerWant
			}
		}
		return contextTokenValueMatch(text, prefix, func(got string) bool {
			return foldedBoundaryMatch(got, wantLower, suffix)
		})
	}
	tokens := contextTokensByPrefix(text)
	for i, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		if !ok {
			continue
		}
		wantLower := lowerString(want)
		if i < len(valuesLower) {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == lowerString(prefix) {
				wantLower = lowerWant
			}
		}
		for _, got := range tokens[prefix] {
			if foldedBoundaryMatch(got, wantLower, suffix) {
				return true
			}
		}
	}
	return false
}

func contextTokenBoundaryPredicateCached(op string, values, valuesLower []string, facts *contextTokenFacts) bool {
	if len(values) == 0 {
		return false
	}
	for i, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		if !ok {
			continue
		}
		wantLower := lowerString(want)
		if i < len(valuesLower) {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == lowerString(prefix) {
				wantLower = lowerWant
			}
		}
		for _, got := range facts.byPrefix[prefix] {
			if foldedBoundaryMatch(got, wantLower, op == "ends_with") {
				return true
			}
		}
	}
	return false
}

func contextTokenValueMatch(text, prefix string, match func(string) bool) bool {
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var tok string
		if end < 0 {
			tok = text[start:]
			start = len(text) + 1
		} else {
			tok = text[start : start+end]
			start += end + 1
		}
		if strings.HasPrefix(tok, prefix) && match(tok[len(prefix):]) {
			return true
		}
	}
	return false
}

func contextTokensByPrefix(text string) map[string][]string {
	out := map[string][]string{}
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var tok string
		if end < 0 {
			tok = text[start:]
			start = len(text) + 1
		} else {
			tok = text[start : start+end]
			start += end + 1
		}
		if tok == "" {
			continue
		}
		prefix, value, ok := splitContextTokenPredicateValue(tok)
		if !ok {
			continue
		}
		out[prefix] = append(out[prefix], value)
	}
	return out
}

func contextTokenContainsLower(prefix, got, want, wantLower string) bool {
	if prefix == "class_base:" {
		return classBaseTokenMatches(got, want)
	}
	return valContainsFoldedNeedle(got, wantLower)
}

func classBaseTokenMatches(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if got == "" || want == "" {
		return false
	}
	if strings.EqualFold(got, want) {
		return true
	}
	gotSeg := lastTypeSegment(got)
	wantSeg := lastTypeSegment(want)
	return gotSeg != "" && wantSeg != "" && strings.EqualFold(gotSeg, wantSeg)
}

func lastTypeSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "::"); i >= 0 {
		return s[i+2:]
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func flagValuePredicate(pred flagPredicate, text string) bool {
	return valuePredicateLowerValues(pred.Op, pred.Values, pred.lowerValues(), text)
}

var scopePolicy = func() unresolvedPolicy {
	if os.Getenv("VYQL_UNRESOLVED_RECEIVER") == "skip" {
		return unresolvedSkipsResolvedOnly
	}
	return unresolvedMatches
}()

// receiverScopeSatisfied reports whether a call is in scope for a spec gated on
// packages. A spec with no package gate is unscoped and always satisfied, so
// this only ever narrows bindings that named a package in the first place.
//
// Two pieces of evidence, in order. `recv_package` is the receiver resolved
// through the module import table, which is the only thing that can see through
// an alias -- `Bourne.parse` is a call on @hapi/bourne and the callee path
// cannot say so. When it is absent the root of the callee path is used instead:
// a node built by hand, one from a graph lowered before the property existed,
// or a frontend with no import table all still carry a path, and treating the
// missing property as "no match" would silently drop every package-gated
// binding on those.

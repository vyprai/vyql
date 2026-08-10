// Package bindings is the binding layer: it turns authored VyQL binding data into applicators
// that label graph nodes with concepts, and resolves the conflicts when several disagree.
//
// This lived inside the extractor package, which the architecture forbids from knowing about
// concepts at all -- and because Go's package boundary was not available to enforce the split,
// the file grew to 7,429 lines mixing the spec compiler, the applicators, the pattern matcher,
// the requirement gate and the store indexes. It is now its own package, one file per job.
package bindings

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/extract/sca"
	"github.com/vyprai/vyql/internal/usg"
)

var activeSources map[string]bool

var activeBindingConcepts map[string]bool

var (
	autoBindingsCache sync.Map // map[string]cachedAutoBindings
	flagTimingOn      = os.Getenv("VYQL_FLAG_TIMING") != ""
	indexTimingOn     = os.Getenv("VYQL_INDEX_TIMING") != ""
	sinkTimingOn      = os.Getenv("VYQL_SINK_TIMING") != ""
)

type cachedAutoBindings struct {
	data []Applicator
	err  error
}

// SetActiveSources sets the active-profile filter for source labelling. Pass nil to disable.

func SetActiveSources(s map[string]bool) { activeSources = s }

// SetActiveBindingConcepts restricts graph labels to concepts the active rule set can consume.
// Pass nil to disable pruning; the returned restore func is scoped for scan graph builds.

func SetActiveBindingConcepts(concepts map[string]bool) func() {
	prev := activeBindingConcepts
	if len(concepts) == 0 {
		activeBindingConcepts = nil
	} else {
		activeBindingConcepts = make(map[string]bool, len(concepts))
		for c, ok := range concepts {
			if ok {
				activeBindingConcepts[c] = true
			}
		}
	}
	return func() { activeBindingConcepts = prev }
}

// ActiveBindingConceptsKey fingerprints the binding-demand filter for incremental labels.

func ActiveBindingConceptsKey() string {
	if activeBindingConcepts == nil {
		return "*"
	}
	keys := make([]string, 0, len(activeBindingConcepts))
	for k, on := range activeBindingConcepts {
		if on {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func BindingConceptPruningActive() bool { return activeBindingConcepts != nil }

// ActiveSourcesKey returns a deterministic fingerprint of the active source set for the
// incremental binding-label cache: changing the profile changes which
// source labels bindings emit, so cached labels from one profile must not be reused under
// another. "*" means no filter (every source active).

func ActiveSourcesKey() string {
	if activeSources == nil {
		return "*"
	}
	keys := make([]string, 0, len(activeSources))
	for k, on := range activeSources {
		if on {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// valContains reports whether the NUL-joined str_args prop contains sub,
// case-insensitively. Used by `val`/`nval` matching.

func alreadyBuiltSharedFlagIndex(s usg.Store) *flagMatchIndex {
	if _, ok := s.(interface{ StructEpoch() uint64 }); !ok {
		return nil
	}
	idx := sharedFlagIndex(s)
	if idx.built.Load() {
		return idx
	}
	return nil
}

func callIndexTerms(n usg.Node) []string {
	seen := map[string]bool{}
	var terms []string
	add := func(value string) {
		value = lowerString(strings.TrimSpace(value))
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		terms = append(terms, value)
	}
	path := n.Prop("callee_path")
	add(path)
	add(n.Prop("path"))
	add(n.Prop("method"))
	add(lastSeg(path))
	return terms
}

func (set scopedPredicateHitSet) matches(scope, anchorID string, allowUnscoped bool) bool {
	if scope == "" {
		return set.totalCount > 1 || set.singleID != "" && set.singleID != anchorID
	}
	if allowUnscoped && set.unscopedCount > 0 {
		if set.unscopedCount > 1 || set.unscopedID != anchorID {
			return true
		}
	}
	if count := set.exactCounts[scope]; count.count > 0 {
		if count.count > 1 || count.singleID != anchorID {
			return true
		}
	}
	prefix := scope + "/"
	i := sort.Search(len(set.scopes), func(i int) bool {
		return set.scopes[i] >= prefix
	})
	return i < len(set.scopes) && strings.HasPrefix(set.scopes[i], prefix)
}

var nodeDirectValuePropKeys = []string{
	"value",
	"raw",
	"name",
	"module",
	"symbol",
	"package",
	"root",
}

func nodeDirectValueTokens(n usg.Node) string {
	tokens := n.Prop("str_args")
	var b strings.Builder
	for _, key := range nodeDirectValuePropKeys {
		value := n.Prop(key)
		if value == "" {
			continue
		}
		if b.Len() == 0 {
			b.WriteString(tokens)
		}
		if b.Len() > 0 {
			b.WriteByte(0)
		}
		b.WriteString(value)
	}
	if b.Len() > 0 {
		return b.String()
	}
	return tokens
}

func functionReturnDecoratorAbsent(s usg.Store, cache *valueTokenCache, call usg.Node, argIndex int, valsLower []string) bool {
	if len(valsLower) == 0 || call.Prop("callee_path") != "analysis.function.return" {
		return false
	}
	first := valsLower[0]
	if !strings.HasPrefix(first, "decorator_method:") {
		return false
	}
	direct := cache.directSegments(s, call, argIndex)
	present, ok := rawSegmentsContainStructuredContextNeedle(direct.raw, first)
	return ok && !present
}

func segmentContainsStructuredContextNeedle(segment, lowerPrefix, lowerNeedle string) bool {
	for start := 0; start <= len(segment); {
		end := strings.IndexByte(segment[start:], '\x00')
		var token string
		if end < 0 {
			token = segment[start:]
			start = len(segment) + 1
		} else {
			token = segment[start : start+end]
			start += end + 1
		}
		if len(token) < len(lowerPrefix) || !asciiHasFoldedPrefix(token, lowerPrefix) {
			continue
		}
		if valContainsFoldedNeedle(token, lowerNeedle) {
			return true
		}
	}
	return false
}

var callablePropTypes = []string{
	"code.Call",
	"code.Attr",
	"code.Name",
	"code.Subscript",
	"code.BinOp",
	"code.Unary",
	"code.Seq",
	"code.Literal",
	"code.Const",
	"code.Function",
	"code.Class",
	"code.Import",
}

func rangeNodeIDs(s usg.Store, ids []string, fn func(usg.Node) bool) bool {
	for _, id := range ids {
		n, ok, err := s.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if !fn(n) {
			return false
		}
	}
	return true
}

func rangeNodeIndexes(is interface {
	NodeAtIndex(int32) (usg.Node, bool)
}, idxs []int32, fn func(usg.Node) bool) bool {
	for _, idx := range idxs {
		n, ok := is.NodeAtIndex(idx)
		if !ok {
			continue
		}
		if !fn(n) {
			return false
		}
	}
	return true
}

func rangeTechNodesDirect(s usg.Store, tech string, crossLang bool, fn func(usg.Node) bool, types ...string) {
	if idx := alreadyBuiltSharedFlagIndex(s); idx != nil {
		idx.rangeTechNodes(s, tech, crossLang, fn, types...)
		return
	}
	if rg, ok := s.(interface {
		RangeNodesOfType(string, func(usg.Node) bool)
	}); ok {
		for _, typ := range types {
			stopped := false
			rg.RangeNodesOfType(typ, func(n usg.Node) bool {
				if !crossLang && tech != "" {
					if nt := nodeTechFromNode(n); nt != "" && nt != tech {
						return true
					}
				}
				if !fn(n) {
					stopped = true
					return false
				}
				return true
			})
			if stopped {
				return
			}
		}
		return
	}
	for _, typ := range types {
		ids, _ := s.NodesOfType(typ)
		for _, id := range ids {
			n, ok, err := s.GetNode(id)
			if err != nil || !ok {
				continue
			}
			if !crossLang && tech != "" {
				if nt := nodeTechFromNode(n); nt != "" && nt != tech {
					continue
				}
			}
			if !fn(n) {
				return
			}
		}
	}
}

func rangeFlowIn(s usg.Store, idx *flowTokenIndex, id string, fn func(string) bool) {
	if rg, ok := s.(interface {
		RangeInEdges(string, string, func(string) bool)
	}); ok {
		rg.RangeInEdges(id, "FLOWS", fn)
		return
	}
	if idx != nil {
		idx.ensure(s)
		for _, srcID := range idx.rev[id] {
			if !fn(srcID) {
				return
			}
		}
		return
	}
	edges, _ := s.InEdges(id, "FLOWS")
	for _, edge := range edges {
		if !fn(edge.Src) {
			return
		}
	}
}

func rangeFlowOut(s usg.Store, idx *flowTokenIndex, id string, fn func(string) bool) {
	if rg, ok := s.(interface {
		RangeOutEdges(string, string, func(string) bool)
	}); ok {
		rg.RangeOutEdges(id, "FLOWS", fn)
		return
	}
	if idx != nil {
		idx.ensure(s)
		for _, dstID := range idx.fwd[id] {
			if !fn(dstID) {
				return
			}
		}
		return
	}
	edges, _ := s.OutEdges(id, "FLOWS")
	for _, edge := range edges {
		if !fn(edge.Dst) {
			return
		}
	}
}

func appendFlowingStringToken(b *strings.Builder, wrote *bool, direct, str string) {
	if str == "" {
		return
	}
	if !*wrote {
		if direct != "" {
			b.Grow(len(direct) + 1 + len(str))
			b.WriteString(direct)
			b.WriteByte(0)
		}
		b.WriteString(str)
		*wrote = true
		return
	}
	b.WriteByte(0)
	b.WriteString(str)
}

func flowingStringTokens(s usg.Store, idx *flowTokenIndex, start, direct string) string {
	type item struct {
		id    string
		depth int
	}
	var (
		seen map[string]bool
		q    []item
		b    strings.Builder
	)
	wrote := false
	visitIncoming := func(id string, nextDepth int) {
		rangeFlowIn(s, idx, id, func(srcID string) bool {
			if seen == nil {
				seen = map[string]bool{start: true}
			}
			if seen[srcID] {
				return true
			}
			seen[srcID] = true
			src, ok, err := s.GetNode(srcID)
			if err == nil && ok {
				appendFlowingStringToken(&b, &wrote, direct, src.Prop("str_args"))
			}
			q = append(q, item{id: srcID, depth: nextDepth})
			return len(seen) < 128
		})
	}
	visitIncoming(start, 1)
	for head := 0; seen != nil && head < len(q) && len(seen) < 128; head++ {
		cur := q[head]
		if cur.depth >= 6 {
			continue
		}
		visitIncoming(cur.id, cur.depth+1)
	}
	if wrote {
		return b.String()
	}
	return direct
}

func collectionElement(s usg.Store, idx *collectionFlowIndex, argID string, elemIndex int) string {
	seqs := idx.seqsForArg(s, argID)
	for i := len(seqs) - 1; i >= 0; i-- {
		seqID := seqs[i]
		if elemID := idx.elementForSeq(s, seqID, elemIndex); elemID != "" {
			return elemID
		}
	}
	return ""
}

func collectionArgument(s usg.Store, idx *collectionFlowIndex, argID string) bool {
	return len(idx.seqsForArg(s, argID)) > 0
}

func collectionArgKindAllowsFlow(vkind string) bool {
	switch vkind {
	case "Name", "Call", "Index":
		return true
	}
	return false
}

var (
	conceptDetailOnce sync.Once
	conceptDetails    map[string]map[string]string
	conceptRoleOnce   sync.Once
	conceptRoles      map[string]map[string]bool
	bindingSetCache   sync.Map // map[bindingSetCacheKey]*Set
)

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func inputSpecsNeedScope(inputs []inputSpec) bool {
	for _, in := range inputs {
		if len(in.ScopePreds) > 0 {
			return true
		}
	}
	return false
}

func sinkSpecsNeedScope(sinks []sinkSpec) bool {
	for _, sk := range sinks {
		if len(sk.ScopePreds) > 0 {
			return true
		}
	}
	return false
}

func controlSpecsNeedScope(controls []controlSpec) bool {
	for _, c := range controls {
		if len(c.ScopePreds) > 0 {
			return true
		}
	}
	return false
}

// checkApplicator labels control concepts (transforms/validators) on the calls that
// apply them, so v2 path coveredBy controls can suppress a sanitized flow (docs/07).

func rangeNodes(s usg.Store, fn func(usg.Node) bool) {
	if rs, ok := s.(interface{ RangeNodes(func(usg.Node) bool) }); ok {
		rs.RangeNodes(fn)
		return
	}
	nodes, _ := s.AllNodes()
	for _, n := range nodes {
		if !fn(n) {
			return
		}
	}
}

func newPackageGate(have map[string]bool) *packageGate {
	g := &packageGate{
		have:     make(map[string]bool, len(have)),
		prefixes: map[string]bool{},
		segments: map[string]bool{},
		cache:    map[string]bool{},
	}
	for raw := range have {
		name := sca.NormalizePackageName(raw)
		if name == "" {
			continue
		}
		g.have[name] = true
		if root := sca.PackageRoot(name); root != "" {
			g.have[root] = true
		}
		for _, prefix := range packageGatePrefixes(name) {
			g.prefixes[prefix] = true
		}
		for _, segment := range packageGatePathSegments(name) {
			g.segments[segment] = true
		}
	}
	return g
}

const (
	requirementStateSatisfied   = "satisfied"
	requirementStateMissing     = "missing"
	requirementStateUnknown     = "unknown"
	requirementStateConflicting = "conflicting"
)

func newRequirementGate(s usg.Store, tech string, crossLang bool, packages map[string]bool) *requirementGate {
	return &requirementGate{
		packages:  newPackageGate(packages),
		store:     s,
		tech:      tech,
		crossLang: crossLang,
	}
}

func titleNodeKind(kind string) string {
	// strings.Title treats letters, digits and underscore as word characters, so
	// "foo_bar" stays "Foo_bar" and "x1y" stays "X1y". Only a lower-case letter
	// that follows something else starts a new word.
	wordChar := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_'
	}
	out := []rune(kind)
	prevWord := false
	for i, r := range out {
		if !prevWord && r >= 'a' && r <= 'z' {
			out[i] = r - 'a' + 'A'
		}
		prevWord = wordChar(r)
	}
	return string(out)
}

func newFlagOperandGroupMatchState(specs []flagOperandSpec) *flagOperandGroupMatchState {
	state := &flagOperandGroupMatchState{
		specs:   specs,
		hits:    make([][]bool, len(specs)),
		matches: make([]bool, len(specs)),
	}
	for i, spec := range specs {
		state.hits[i] = make([]bool, len(spec.Predicates))
		if len(spec.Predicates) == 0 {
			state.matches[i] = true
			state.count++
		}
	}
	return state
}

func allBool(values []bool) bool {
	for _, v := range values {
		if !v {
			return false
		}
	}
	return true
}

func binaryPredicateOps(values []string) ([]string, bool) {
	if len(values) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	var ops []string
	for _, value := range values {
		_, op, _, ok := splitBinaryPredicate(strings.TrimSpace(value))
		if !ok {
			return nil, false
		}
		if !seen[op] {
			seen[op] = true
			ops = append(ops, op)
		}
	}
	return ops, true
}

func splitContextTokenPredicateValue(v string) (prefix, want string, ok bool) {
	for _, sep := range []string{":", "="} {
		if i := strings.Index(v, sep); i > 0 {
			return v[:i+1], v[i+1:], true
		}
	}
	return "", "", false
}

func valuePredicate(op string, values []string, text string) bool {
	return valuePredicateLowerValues(op, values, lowerStrings(values), text)
}

func valuePredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	switch op {
	case "exists":
		if len(values) == 0 {
			return text != ""
		}
		return textTokenBoundaryPredicate(valuesLower, text, false)
	case "equals":
		for _, v := range values {
			if text == v {
				return true
			}
		}
		return false
	case "equals_any":
		return containsStr(values, text)
	case "contains_any":
		for _, v := range valuesLower {
			if valContainsFoldedNeedle(text, v) {
				return true
			}
		}
		return false
	case "starts_with":
		return textTokenBoundaryPredicate(valuesLower, text, false)
	case "ends_with":
		return textTokenBoundaryPredicate(valuesLower, text, true)
	default:
		return valCondsFoldedNeedles(text, valuesLower, nil)
	}
}

func valuePredicateLowerValuesWithLowerText(op string, values, valuesLower []string, text, lowerText string) bool {
	switch op {
	case "exists":
		if len(values) == 0 {
			return text != ""
		}
		return textTokenBoundaryPredicate(valuesLower, text, false)
	case "equals":
		for _, v := range values {
			if text == v {
				return true
			}
		}
		return false
	case "equals_any":
		return containsStr(values, text)
	case "contains_any":
		for _, v := range valuesLower {
			if valContainsLowerNeedle(lowerText, v) {
				return true
			}
		}
		return false
	case "starts_with":
		return textTokenBoundaryPredicate(valuesLower, text, false)
	case "ends_with":
		return textTokenBoundaryPredicate(valuesLower, text, true)
	default:
		return valCondsLowerNeedles(lowerText, valuesLower, nil)
	}
}

func textTokenBoundaryPredicate(valuesLower []string, text string, suffix bool) bool {
	if len(valuesLower) == 0 {
		return false
	}
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
		for _, value := range valuesLower {
			if foldedBoundaryMatch(tok, value, suffix) {
				return true
			}
		}
	}
	return false
}

func foldedBoundaryMatch(text, lowerWant string, suffix bool) bool {
	if lowerWant == "" {
		return true
	}
	if len(lowerWant) > len(text) {
		return false
	}
	for i := 0; i < len(lowerWant); i++ {
		if lowerWant[i] >= 0x80 {
			lowerText := lowerString(text)
			if suffix {
				return strings.HasSuffix(lowerText, lowerWant)
			}
			return strings.HasPrefix(lowerText, lowerWant)
		}
	}
	if suffix {
		offset := len(text) - len(lowerWant)
		for i := 0; i < len(lowerWant); i++ {
			ch := text[offset+i]
			if ch >= 0x80 {
				return strings.HasSuffix(lowerString(text), lowerWant)
			}
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			if ch != lowerWant[i] {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(lowerWant); i++ {
		ch := text[i]
		if ch >= 0x80 {
			return strings.HasPrefix(lowerString(text), lowerWant)
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != lowerWant[i] {
			return false
		}
	}
	return true
}

func nodeSearchText(n usg.Node) string {
	return n.Type + "\x00" + n.Prop("callee_path") + "\x00" + n.Prop("method") + "\x00" + n.Prop("op") + "\x00" + n.Prop("str_args")
}

func locFile(loc string) string {
	if i := strings.LastIndex(loc, ":"); i >= 0 {
		return loc[:i]
	}
	return loc
}

func splitLocFileLine(loc string) (string, int) {
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return loc, 0
	}
	line, _ := strconv.Atoi(loc[i+1:])
	return loc[:i], line
}

// matchPresenceApplicator labels a node with a presence concept for `match`-style rules.

func markTargets(s usg.Store, idx *collectionFlowIndex, n usg.Node, m controlSpec) []string {
	if !m.ArgTarget {
		return []string{n.ID}
	}
	if n.Type != "code.Call" {
		return nil
	}
	var out []string
	addArgTarget := func(arg string) {
		if arg == "" {
			return
		}
		target := arg
		foundCollectionTarget := false
		if m.CollectionFirst {
			if first := collectionElement(s, idx, arg, m.CollectionIndex); first != "" {
				target = first
				foundCollectionTarget = true
			}
		}
		if a, ok, _ := s.GetNode(arg); ok {
			vkind := a.Prop("vkind")
			if m.Collection && !foundCollectionTarget && vkind != "Seq" &&
				(!collectionArgKindAllowsFlow(vkind) || !collectionArgument(s, idx, arg)) {
				return
			}
			if !m.Collection && !m.CollectionFirst && a.Prop("vkind") == "Seq" {
				return
			}
		} else if m.Collection {
			return
		}
		out = append(out, target)
	}
	if m.ArgIndex < 0 {
		for ai := 0; ; ai++ {
			arg := n.Prop(usg.ArgPropKey(ai))
			if arg == "" {
				break
			}
			addArgTarget(arg)
		}
		return out
	}
	addArgTarget(n.Prop(usg.ArgPropKey(m.ArgIndex)))
	return out
}

func mergeMappingDetail(base, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// --- binding spec indexing -------------------------------------------------
//
// Binding matching is a search problem: for each graph node, find the specs whose
// pattern matches its method/callee_path. Done naively that is O(nodes × specs) —
// the dominant scan cost on large repos. Every matcher here (method exact, path
// prefix/suffix/segment) shares one invariant: a matching spec's pattern FIRST
// SEGMENT must appear as a dotted segment of the node path, OR the spec is a
// by-method spec whose name equals the node method. So we index specs by those
// keys once per Apply and, per node, consult only the candidate specs. Patterns
// that need unanchored substring matching (`contains` mode) can't be indexed and
// go into `loose`, always considered. Restricting the precise match loop to
// candidates is exactly equivalent to the full scan: a non-candidate spec always
// fails the precise check, so it could never have produced a mapping.

// firstSeg returns the leading dotted/bracket segment of a pattern or path
// ("client.get" → "client", "run" → "run").

func firstSeg(p string) string {
	if i := strings.IndexAny(p, ".["); i >= 0 {
		return p[:i]
	}
	return p
}

// specIndex maps node method names and path segments to candidate spec indices.
// visited/gen provide allocation-free dedup across the per-node candidate lookups
// (a generation stamp per spec instead of a fresh map each call); buf is the reused
// output. Not safe for concurrent use — binding applicators apply sequentially.

type specIndex struct {
	byMethod map[string][]int
	bySeg    map[string][]int
	byExact  map[string][]int
	loose    []int
	visited  []int32
	gen      int32
	buf      []int
}

// buildSpecIndex indexes n specs. keysOf reports, for spec i, its by-method keys
// (exact method names), its path patterns (indexed by first segment), and whether
// it needs unanchored matching (loose → always a candidate).

func buildSpecIndex(n int, keysOf func(i int) (methods, paths []string, loose bool)) *specIndex {
	idx := &specIndex{byMethod: map[string][]int{}, bySeg: map[string][]int{}, byExact: map[string][]int{}, visited: make([]int32, n)}
	for i := 0; i < n; i++ {
		methods, paths, loose := keysOf(i)
		if loose {
			idx.loose = append(idx.loose, i)
			continue
		}
		for _, m := range methods {
			idx.byMethod[m] = append(idx.byMethod[m], i)
		}
		for _, p := range paths {
			if exactSpecPath(p) {
				idx.byExact[p] = append(idx.byExact[p], i)
				continue
			}
			idx.bySeg[firstSeg(p)] = append(idx.bySeg[firstSeg(p)], i)
		}
	}
	return idx
}

func exactSpecPath(p string) bool {
	return strings.HasPrefix(p, "analysis.") && strings.HasSuffix(p, ".context")
}

// candidates returns the sorted spec indices that could match a node with the
// given method/path (a superset filter; the caller still runs the precise check).
// The returned slice is reused on the next call — consume it before calling again.

func (idx *specIndex) candidates(method, path string) []int {
	idx.gen++
	g := idx.gen
	out := idx.buf[:0]
	add := func(is []int) {
		for _, i := range is {
			if idx.visited[i] != g {
				idx.visited[i] = g
				out = append(out, i)
			}
		}
	}
	if method != "" {
		add(idx.byMethod[method])
	}
	if path != "" && len(idx.byExact) > 0 {
		add(idx.byExact[path])
	}
	// walk path segments without allocating (substring map lookups don't copy).
	if path != "" && len(idx.bySeg) > 0 {
		start := 0
		for i := 0; i <= len(path); i++ {
			if i == len(path) || path[i] == '.' || path[i] == '[' || path[i] == ']' {
				if i > start {
					add(idx.bySeg[path[start:i]])
				}
				start = i + 1
			}
		}
	}
	add(idx.loose)
	sort.Ints(out)
	idx.buf = out
	return out
}

// matchSinkPath matches a sink pattern against a callee path with dotted-segment
// boundaries: exact, as a prefix (method chains after), or as a SUFFIX / interior
// segment (namespace or receiver before it, e.g. pattern "Process.Start" matches
// "System.Diagnostics.Process.Start"). Boundary-aware so "File" ≠ "FileInputStream".

func matchSinkPath(path, p string) bool {
	if path == p || p == "" {
		return path == p
	}
	lp := len(p)
	if len(path) < lp {
		return false
	}
	if strings.HasPrefix(path, p) {
		switch path[lp] {
		case '.', '[':
			return true
		}
	}
	start := 1
	for {
		i := strings.Index(path[start:], p)
		if i < 0 {
			return false
		}
		pos := start + i
		if path[pos-1] == '.' {
			end := pos + lp
			if end == len(path) {
				return true
			}
			switch path[end] {
			case '.', '[':
				return true
			}
		}
		start = pos + 1
		if start+lp > len(path) {
			return false
		}
	}
}

// constraintAllows reports whether recvType is in a sink's `on` constraint (a
// single type or a comma-separated list from `on [a, b]`).

func constraintAllows(constraint, recvType string) bool {
	for _, t := range strings.Split(constraint, ",") {
		t = strings.TrimSpace(t)
		recvType = strings.TrimSpace(recvType)
		if t == recvType ||
			strings.HasSuffix(t, "."+recvType) ||
			strings.HasSuffix(recvType, "."+t) ||
			strings.HasSuffix(t, "::"+recvType) ||
			strings.HasSuffix(recvType, "::"+t) {
			return true
		}
	}
	return false
}

// matchPath reports whether a callee_path matches any of the patterns. Default
// mode "prefix" matches exact / dotted / subscript continuations and dotted
// suffix/interior segments; "contains" matches any substring (for languages
// whose receiver name varies, e.g. Go r/req).

func matchPath(path string, patterns []string, mode string) bool {
	for _, p := range patterns {
		if mode == "contains" {
			if strings.Contains(path, p) {
				return true
			}
			continue
		}
		if matchSinkPath(path, p) {
			return true
		}
	}
	return false
}

// ConfigBindings and the accessors beside it are the per-language binding
// applicator sets, loaded from vyql/bindings/<tech>/.

func ConfigBindings() []Applicator { return BindingsFor("config") }

func TextPatternBindings() []Applicator { return BindingsFor("textpattern") }

// AutoBindings returns v2 binding sets that opt into whole-graph application through
// `meta { auto_apply: graph }`.

func jsAttrReceiverFromDomLookup(s usg.Store, idx *flowTokenIndex, attrID string) bool {
	hit := false
	rangeFlowIn(s, idx, attrID, func(src string) bool {
		n, ok, err := s.GetNode(src)
		if err != nil || !ok || n.Type != "code.Call" {
			return true
		}
		path := n.Prop("callee_path")
		if path == "document.getElementById" ||
			path == "document.querySelector" ||
			path == "document.querySelectorAll" ||
			path == "document.getElementsByName" ||
			path == "document.getElementsByClassName" ||
			path == "document.getElementsByTagName" {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func safeJSPathResolverFunction(tokens string) (string, bool) {
	name := ""
	for _, tok := range strings.Split(tokens, "\x00") {
		if strings.HasPrefix(tok, "name=") {
			name = strings.TrimPrefix(tok, "name=")
			break
		}
	}
	if name == "" || name == "<lambda>" {
		return "", false
	}
	lower := lowerString(tokens)
	if !strings.Contains(lower, "path.resolve") {
		return "", false
	}
	if !strings.Contains(lower, "startswith") {
		return "", false
	}
	if !strings.Contains(lower, "path.relative") {
		return "", false
	}
	if !strings.Contains(lower, ".includes") && !strings.Contains(lower, "includes(") {
		return "", false
	}
	if !strings.Contains(lower, "return") {
		return "", false
	}
	// A safe resolver must reject escape and allowlist failures before returning
	// the resolved path. path.resolve alone remains intentionally untrusted.
	if !strings.Contains(lower, "returnnull") && !strings.Contains(lower, "return null") &&
		!strings.Contains(lower, "throw") {
		return "", false
	}
	return name, true
}

func safeJSPathComponentRegex(lit string) bool {
	body, ok := jsRegexBody(lit)
	if !ok || len(body) < 2 || body[0] != '^' || body[len(body)-1] != '$' {
		return false
	}
	body = body[1 : len(body)-1]
	if body == "" {
		return false
	}
	inClass := false
	escaped := false
	for _, r := range body {
		if escaped {
			if !strings.ContainsRune(`.-_dDwW[](){}|^$+?*,`, r) {
				return false
			}
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '/':
			return false
		case '.':
			if !inClass {
				return false
			}
		case '[':
			inClass = true
		case ']':
			inClass = false
		default:
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				continue
			}
			if !strings.ContainsRune(`^$(){}|?+*,-_`, r) {
				return false
			}
		}
	}
	return !escaped && !inClass
}

func jsRegexBody(lit string) (string, bool) {
	if len(lit) < 3 || lit[0] != '/' {
		return "", false
	}
	inClass := false
	escaped := false
	for i := 1; i < len(lit); i++ {
		ch := lit[i]
		if escaped {
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			escaped = true
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				return lit[1:i], true
			}
		}
	}
	return "", false
}

func safeProcessArgVectorSeq(s usg.Store, idx *collectionFlowIndex, seqID string) bool {
	first := idx.elementForSeq(s, seqID, 0)
	if first == "" {
		return false
	}
	elem, ok, err := s.GetNode(first)
	if err != nil || !ok {
		return false
	}
	switch elem.Prop("vkind") {
	case "Name", "Call", "Format", "Index", "Seq", "Lambda":
		return false
	default:
		return true
	}
}

func ElixirBindings() []Applicator { return BindingsFor("elixir") }

func DartBindings() []Applicator { return BindingsFor("dart") }

func GroovyBindings() []Applicator { return BindingsFor("groovy") }

func PythonBindings() []Applicator { return BindingsFor("python") }

func JsBindings() []Applicator { return BindingsFor("javascript") }

func RubyBindings() []Applicator { return BindingsFor("ruby") }

func GoBindings() []Applicator { return BindingsFor("go") }

func JavaBindings() []Applicator { return BindingsFor("java") }

func PHPBindings() []Applicator { return BindingsFor("php") }

func CSharpBindings() []Applicator { return BindingsFor("csharp") }

func CBindings() []Applicator { return BindingsFor("c") }

func CPPBindings() []Applicator { return BindingsFor("cpp") }

func RustBindings() []Applicator { return BindingsFor("rust") }

func BashBindings() []Applicator { return BindingsFor("bash") }

func ScalaBindings() []Applicator { return BindingsFor("scala") }

func LuaBindings() []Applicator { return BindingsFor("lua") }

func KotlinBindings() []Applicator { return BindingsFor("kotlin") }

func PowerShellBindings() []Applicator { return BindingsFor("powershell") }

func SwiftBindings() []Applicator { return BindingsFor("swift") }

func PerlBindings() []Applicator { return BindingsFor("perl") }

func SolidityBindings() []Applicator { return BindingsFor("solidity") }

func ObjCBindings() []Applicator { return BindingsFor("objc") }

// containsStr reports whether xs contains v.

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// unresolvedPolicy decides whether a package-gated bare-method spec matches a
// call whose receiver does not resolve to any import -- a builtin, a dynamic
// receiver, or a language whose frontend has no import table.

type unresolvedPolicy int

const (
	// Reject only a receiver that resolves to a different package; an
	// unresolved receiver still matches, because nothing says it is foreign.
	unresolvedMatches unresolvedPolicy = iota
	// Reject anything that does not positively resolve to the gated package.
	// Stricter, and it discards instance-method calls.
	unresolvedSkipsResolvedOnly
)

// scopePolicy governs bare-method specs whose receiver does not resolve.
// VYQL_UNRESOLVED_RECEIVER=skip tightens it, which exists so the choice can be
// measured against a corpus rather than argued about.

func receiverScopeSatisfied(nodePkg, calleePath string, packages []string, policy unresolvedPolicy) bool {
	if len(packages) == 0 {
		return true
	}
	root := calleePathRoot(calleePath)
	for _, p := range packages {
		for _, name := range importNamesForPackage(p) {
			if name == nodePkg || name == root {
				return true
			}
		}
	}
	// Rejection needs positive evidence. A resolved receiver that belongs to a
	// different package is that evidence. An unresolved one is not: `const zip
	// = new AdmZip(...); zip.extractAllTo(...)` calls into adm-zip through an
	// instance, and the import table cannot see through a variable. Rejecting
	// those would discard every instance-method binding in the corpus.
	if nodePkg != "" {
		return false
	}
	return policy != unresolvedSkipsResolvedOnly
}

// calleePathRoot is the first dotted segment of a callee path: the receiver as
// the source text spells it.

func calleePathRoot(path string) string {
	if i := strings.IndexByte(path, '.'); i > 0 {
		return path[:i]
	}
	return ""
}

// Package frontend turns extracted code.* graphs into concept labels using
// framework bindings (docs/07). The binding content - which framework calls
// are inputs, sinks, controls, and which constructors yield which types - is
// VyQL, authored in vyql/bindings/<tech>.vyql and loaded at runtime. Only the
// matching engine and the language parsers are Go code.
package frontend

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vyprai/vyql/bindings"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/resultpolicy"
	"github.com/vyprai/vyql/usg"
)

type inputSpec struct {
	Concept     string
	NodeType    string
	Paths       []string
	Methods     []string // receiver-agnostic: match the call's `method` prop (last segment)
	Match       string   // "prefix" (default) | "contains"
	Receiver    bool     // match a receiver attribute/method with a recv_type constraint
	Constraint  string   // optional `on <type>` receiver-type constraint
	ValMatches  []string // `val "substr"` (AND) — only a source when an arg literal matches
	ValAbsents  []string // `nval "substr"` (AND) — not a source if any arg literal contains a substr
	ScopePreds  []flagPredicate
	ArgCountSet bool
	ArgCountMin int
	ArgCountMax int
	Packages    []string // derived from v2 dependency requirements; require matching import/SBOM package evidence
	Requirement *parser.BindingRequirement
	Fidelity    string
	Confidence  string
}

type sinkSpec struct {
	Concept         string
	NodeType        string
	Pattern         string
	ByMethod        bool     // match the bare method name vs the dotted callee path
	Exact           bool     // exact path match instead of segment-prefix path matching
	Receiver        bool     // tainted data is the RECEIVER, not an arg — label the call node
	Constraint      string   // optional `on <type>` receiver-type constraint
	ArgIndex        int      // which argument position is targeted (default 0)
	ValMatches      []string // `val "substr"` (AND) — every substr must be in some arg/option literal
	ValAbsents      []string // `nval "substr"` (AND) — no arg/option literal may contain any substr
	ScopePreds      []flagPredicate
	ArgCountSet     bool
	ArgCountMin     int
	ArgCountMax     int
	Packages        []string // derived from v2 dependency requirements; require matching import/SBOM package evidence
	Collection      bool     // also flag a Seq/collection-literal arg
	CollectionFirst bool     // label a specific element of a Seq/collection arg when present
	CollectionIndex int      // selected collection element index
	Requirement     *parser.BindingRequirement
	Fidelity        string
	Confidence      string
}

type controlSpec struct {
	Concept         string
	NodeType        string
	Pattern         string
	ByMethod        bool     // match the call's `method` prop (receiver-agnostic, e.g. .close())
	Receiver        bool     // label the call receiver node instead of the call result
	Exact           bool     // exact path match instead of segment-prefix path matching
	ArgTarget       bool     // label call arguments instead of the matched call node
	ArgIndex        int      // which argument position is targeted when ArgTarget is true; -1 means args.any
	Collection      bool     // also label a Seq/collection-literal arg
	CollectionFirst bool     // label a specific element of a Seq/collection arg when present
	CollectionIndex int      // selected collection element index
	ValMatches      []string // `val "substr"` (AND — marks AND controls)
	ValAbsents      []string // `nval "substr"` (AND — marks AND controls)
	ScopePreds      []flagPredicate
	ArgCountSet     bool
	ArgCountMin     int
	ArgCountMax     int
	Packages        []string // derived from v2 dependency requirements; require matching import/SBOM package evidence
	Detail          map[string]string
	Requirement     *parser.BindingRequirement
	Fidelity        string
	Confidence      string
}

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

type flagOperandSpec struct {
	Predicates     []flagPredicate
	PredicateOrder []int
}

type flagSpec struct {
	Concept        string
	NodeKind       string
	Scope          string
	Predicates     []flagPredicate
	PredicateOrder []int
	Operands       []flagOperandSpec
	Packages       []string
	Detail         map[string]string
	Requirement    *parser.BindingRequirement
	Fidelity       string
	Confidence     string
}

// activeSources, when non-nil, restricts which source concepts the input bindings
// emit for the active analysis profile. nil = every source active.
var activeSources map[string]bool
var activeBindingConcepts map[string]bool

var (
	autoBindingsCache sync.Map // map[string]cachedAutoBindings
	flagTimingOn      = os.Getenv("VYQL_FLAG_TIMING") != ""
	indexTimingOn     = os.Getenv("VYQL_INDEX_TIMING") != ""
	sinkTimingOn      = os.Getenv("VYQL_SINK_TIMING") != ""
)

type cachedAutoBindings struct {
	data []bindings.Applicator
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
func valContains(tokens, sub string) bool {
	return valContainsLower(lowerString(tokens), sub)
}

func valContainsLower(lowerTokens, sub string) bool {
	return strings.Contains(lowerTokens, lowerString(sub))
}

func lowerString(s string) string {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 0x80 {
			return strings.ToLower(s)
		}
		if ch >= 'A' && ch <= 'Z' {
			b := []byte(s)
			b[i] = ch + ('a' - 'A')
			for j := i + 1; j < len(b); j++ {
				ch = b[j]
				if ch >= 0x80 {
					return strings.ToLower(s)
				}
				if ch >= 'A' && ch <= 'Z' {
					b[j] = ch + ('a' - 'A')
				}
			}
			return string(b)
		}
	}
	return s
}

func valContainsLowerNeedle(lowerTokens, lowerSub string) bool {
	return strings.Contains(lowerTokens, lowerSub)
}

func valContainsFoldedNeedle(tokens, lowerSub string) bool {
	if lowerSub == "" {
		return true
	}
	if len(lowerSub) > len(tokens) {
		return false
	}
	for i := 0; i < len(lowerSub); i++ {
		if lowerSub[i] >= 0x80 {
			return strings.Contains(lowerString(tokens), lowerSub)
		}
	}
	first := lowerSub[0]
	limit := len(tokens) - len(lowerSub)
	for i := 0; i <= limit; i++ {
		ch := tokens[i]
		if ch >= 0x80 {
			return strings.Contains(lowerString(tokens), lowerSub)
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != first {
			continue
		}
		match := true
		for j := 1; j < len(lowerSub); j++ {
			ch = tokens[i+j]
			if ch >= 0x80 {
				return strings.Contains(lowerString(tokens), lowerSub)
			}
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			if ch != lowerSub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// valConds reports whether every `val` substring is present (AND) and every
// `nval` substring is absent among the value tokens. Empty lists pass.
func valConds(tokens string, vals, nvals []string) bool {
	return valCondsLower(lowerString(tokens), vals, nvals)
}

func valCondsLower(lowerTokens string, vals, nvals []string) bool {
	for _, v := range vals {
		if !valContainsLower(lowerTokens, v) {
			return false
		}
	}
	for _, nv := range nvals {
		if valContainsLower(lowerTokens, nv) {
			return false
		}
	}
	return true
}

func valCondsLowerNeedles(lowerTokens string, valsLower, nvalsLower []string) bool {
	for _, v := range valsLower {
		if !valContainsLowerNeedle(lowerTokens, v) {
			return false
		}
	}
	for _, nv := range nvalsLower {
		if valContainsLowerNeedle(lowerTokens, nv) {
			return false
		}
	}
	return true
}

type valueTokenCache struct {
	textLower           map[string]string
	strArgsLower        map[string]string
	directLower         map[string]string
	flowLower           map[string]string
	sinkLower           map[string]string
	directSinkSegments  map[string]directSinkSegments
	directRawContains   map[string]bool
	directLowerContains map[string]bool
}

func (c *valueTokenCache) lowerText(text string) string {
	if text == "" {
		return ""
	}
	if c.textLower == nil {
		c.textLower = map[string]string{}
	}
	if lower, ok := c.textLower[text]; ok {
		return lower
	}
	lower := lowerString(text)
	c.textLower[text] = lower
	return lower
}

func (c *valueTokenCache) nodeStrArgsLower(n usg.Node) string {
	text := n.Prop("str_args")
	if text == "" {
		return ""
	}
	if n.ID == "" {
		return c.lowerText(text)
	}
	if c.strArgsLower == nil {
		c.strArgsLower = map[string]string{}
	}
	if lower, ok := c.strArgsLower[n.ID]; ok {
		return lower
	}
	lower := lowerString(text)
	c.strArgsLower[n.ID] = lower
	return lower
}

func (c *valueTokenCache) directNodeLower(n usg.Node) string {
	if n.ID == "" {
		return c.lowerText(nodeDirectValueTokens(n))
	}
	if c.directLower == nil {
		c.directLower = map[string]string{}
	}
	if lower, ok := c.directLower[n.ID]; ok {
		return lower
	}
	lower := c.lowerText(nodeDirectValueTokens(n))
	c.directLower[n.ID] = lower
	return lower
}

func (c *valueTokenCache) flowingLower(s usg.Store, idx *flowTokenIndex, n usg.Node) string {
	if n.ID == "" {
		return ""
	}
	if c.flowLower == nil {
		c.flowLower = map[string]string{}
	}
	if lower, ok := c.flowLower[n.ID]; ok {
		return lower
	}
	lower := c.lowerText(flowingStringTokens(s, idx, n.ID, n.Prop("str_args")))
	c.flowLower[n.ID] = lower
	return lower
}

func (c *valueTokenCache) sinkValueLower(s usg.Store, idx *flowTokenIndex, call usg.Node, argIndex int, includeFlow bool) string {
	if call.ID != "" {
		if c.sinkLower == nil {
			c.sinkLower = map[string]string{}
		}
		key := call.ID + "\x00" + strconv.Itoa(argIndex)
		if includeFlow {
			key += "\x00flow"
		} else {
			key += "\x00direct"
		}
		if lower, ok := c.sinkLower[key]; ok {
			return lower
		}
		lower := c.buildSinkValueLower(s, idx, call, argIndex, includeFlow)
		c.sinkLower[key] = lower
		return lower
	}
	return c.buildSinkValueLower(s, idx, call, argIndex, includeFlow)
}

func (c *valueTokenCache) buildSinkValueLower(s usg.Store, idx *flowTokenIndex, call usg.Node, argIndex int, includeFlow bool) string {
	var b strings.Builder
	addLower := func(lower string) {
		if lower == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(0)
		}
		b.WriteString(lower)
	}
	addLower(c.lowerText(call.Prop("str_args")))
	addArg := func(arg string) {
		if arg == "" {
			return
		}
		if n, ok, err := s.GetNode(arg); err == nil && ok {
			addLower(c.lowerText(n.Prop("str_args")))
			if includeFlow {
				addLower(c.flowingLower(s, idx, n))
			}
		}
	}
	if argIndex >= 0 {
		addArg(call.Prop("arg" + strconv.Itoa(argIndex)))
	} else {
		for ai := 0; ; ai++ {
			arg := call.Prop("arg" + strconv.Itoa(ai))
			if arg == "" {
				break
			}
			addArg(arg)
		}
	}
	if includeFlow {
		addLower(c.flowingLower(s, idx, call))
	}
	return b.String()
}

type directSinkSegments struct {
	raw   []string
	nodes []usg.Node
}

func (c *valueTokenCache) directSegments(s usg.Store, call usg.Node, argIndex int) directSinkSegments {
	key := directSinkSegmentKey(call, argIndex)
	if key != "" {
		if c.directSinkSegments == nil {
			c.directSinkSegments = map[string]directSinkSegments{}
		}
		if segs, ok := c.directSinkSegments[key]; ok {
			return segs
		}
	}
	segs := directSinkSegments{}
	segs.addRaw(call.Prop("str_args"))
	addArg := func(arg string) {
		if arg == "" {
			return
		}
		if n, ok, err := s.GetNode(arg); err == nil && ok {
			if text := n.Prop("str_args"); text != "" {
				if segs.addRaw(text) {
					segs.nodes = append(segs.nodes, n)
				}
			}
		}
	}
	if argIndex >= 0 {
		addArg(call.Prop("arg" + strconv.Itoa(argIndex)))
	} else {
		for ai := 0; ; ai++ {
			arg := call.Prop("arg" + strconv.Itoa(ai))
			if arg == "" {
				break
			}
			addArg(arg)
		}
	}
	if key != "" {
		c.directSinkSegments[key] = segs
	}
	return segs
}

func (segs *directSinkSegments) addRaw(text string) bool {
	if text == "" {
		return false
	}
	for _, existing := range segs.raw {
		if rawSegmentCoveredBy(existing, text) {
			return false
		}
	}
	segs.raw = append(segs.raw, text)
	return true
}

func rawSegmentCoveredBy(existing, text string) bool {
	if existing == text {
		return true
	}
	if text == "" || len(text) > len(existing) {
		return false
	}
	for start := 0; start <= len(existing)-len(text); {
		rel := strings.Index(existing[start:], text)
		if rel < 0 {
			return false
		}
		pos := start + rel
		end := pos + len(text)
		if (pos == 0 || existing[pos-1] == 0) && (end == len(existing) || existing[end] == 0) {
			return true
		}
		start = pos + 1
	}
	return false
}

func directSinkSegmentKey(call usg.Node, argIndex int) string {
	if call.ID == "" {
		return ""
	}
	return call.ID + "\x00" + strconv.Itoa(argIndex)
}

func (c *valueTokenCache) directRawContainsFolded(call usg.Node, argIndex int, rawSegments []string, needle string) bool {
	key := directSinkSegmentKey(call, argIndex)
	if key == "" {
		return rawSegmentsContainFolded(rawSegments, needle)
	}
	cacheKey := key + "\x00raw\x00" + needle
	if c.directRawContains == nil {
		c.directRawContains = map[string]bool{}
	}
	if hit, ok := c.directRawContains[cacheKey]; ok {
		return hit
	}
	hit := rawSegmentsContainFolded(rawSegments, needle)
	c.directRawContains[cacheKey] = hit
	return hit
}

func (c *valueTokenCache) directContainsLower(call usg.Node, argIndex int, lowerSegments []string, needle string) bool {
	if needle == "" {
		return true
	}
	key := directSinkSegmentKey(call, argIndex)
	if key == "" {
		return lowerSegmentsContain(lowerSegments, needle)
	}
	cacheKey := key + "\x00lower\x00" + needle
	if c.directLowerContains == nil {
		c.directLowerContains = map[string]bool{}
	}
	if hit, ok := c.directLowerContains[cacheKey]; ok {
		return hit
	}
	hit := lowerSegmentsContain(lowerSegments, needle)
	c.directLowerContains[cacheKey] = hit
	return hit
}

func lowerSegmentsContain(segments []string, needle string) bool {
	for _, segment := range segments {
		if valContainsLowerNeedle(segment, needle) {
			return true
		}
	}
	return false
}

func lowerStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = lowerString(v)
	}
	return out
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

func (pred flagPredicate) lowerValues() []string {
	if len(pred.valuesLower) == len(pred.Values) {
		return pred.valuesLower
	}
	return lowerStrings(pred.Values)
}

type flowTokenIndex struct {
	once sync.Once
	rev  map[string][]string
	fwd  map[string][]string
}

// Per-Apply shared node indexes. bindings.Apply runs every applicator sequentially
// against one immutable store (binding application only adds concept labels, never
// nodes/edges), so the whole-store flagMatchIndex / flowTokenIndex / fileTech map can
// be built ONCE and reused by all applicators instead of rebuilt per applicator. On a
// large tree with hundreds of (mostly CVE-specific) presence bindings, the per-applicator
// rebuild was hundreds of full RangeNodes scans and the dominant GC source. Keyed by store
// identity so distinct in-process scans (e.g. parallel tests) never share an index.
type sharedStoreIndexes struct {
	flagOnce  sync.Once
	flag      *flagMatchIndex
	flowOnce  sync.Once
	flow      *flowTokenIndex
	techOnce  sync.Once
	fileTech  map[string]string
	contentMu sync.Mutex
	content   map[string]bool
	gramOnce  sync.Once
	grams     map[uint32]struct{}
}

var sharedStoreIndexCache sync.Map // structural epoch (uint64) -> *sharedStoreIndexes

func storeIndexes(s usg.Store) *sharedStoreIndexes {
	// Key by the store's structural epoch, not its pointer: the epoch is globally
	// monotonic (no reuse across store lifetimes) and changes on any node/edge
	// mutation, so a store re-applied after a structural change (e.g. a unit test that
	// adds nodes between two Apply calls) gets a fresh index instead of a stale one.
	es, ok := s.(interface{ StructEpoch() uint64 })
	if !ok {
		return &sharedStoreIndexes{} // un-epoched store: no cross-applicator sharing (still correct)
	}
	epoch := es.StructEpoch()
	if v, ok := sharedStoreIndexCache.Load(epoch); ok {
		return v.(*sharedStoreIndexes)
	}
	v, _ := sharedStoreIndexCache.LoadOrStore(epoch, &sharedStoreIndexes{})
	return v.(*sharedStoreIndexes)
}

func sharedFlagIndex(s usg.Store) *flagMatchIndex {
	si := storeIndexes(s)
	si.flagOnce.Do(func() { si.flag = &flagMatchIndex{} })
	return si.flag
}

func sharedFlowIndex(s usg.Store) *flowTokenIndex {
	si := storeIndexes(s)
	si.flowOnce.Do(func() { si.flow = &flowTokenIndex{} })
	return si.flow
}

func sharedFileContextTechs(s usg.Store) map[string]string {
	si := storeIndexes(s)
	si.techOnce.Do(func() { si.fileTech = fileContextTechs(s) })
	return si.fileTech
}

// sharedContentContains reports whether the store text may contain a lowercased literal. On large
// repositories it is used as a recall-safe presence gate: a false result means at least one
// required trigram is absent from the whole graph, so an exact match is impossible; a true result
// means "maybe" and lets the normal binding matcher decide.
// presenceGateMinNodes is the graph size above which the content() presence gate is worth its
// check. Normal repos fall below it and run unchanged; only very large trees cross it, where
// skipping CVE pattern bindings that target other projects saves far more than the gate costs.
var presenceGateMinNodes = configuredPresenceGateMinNodes()

func configuredPresenceGateMinNodes() int {
	if v := strings.TrimSpace(os.Getenv("VYQL_PRESENCE_GATE_MIN_NODES")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n >= 0 {
			return n
		}
	}
	return 1 << 60
}

func storeNodeCount(s usg.Store) int {
	if c, ok := s.(interface{ NodeCount() int }); ok {
		return c.NodeCount()
	}
	return 0
}

func sharedContentContains(s usg.Store, lowerNeedle string) bool {
	if lowerNeedle == "" {
		return true
	}
	si := storeIndexes(s)
	si.contentMu.Lock()
	if si.content == nil {
		si.content = map[string]bool{}
	}
	if hit, ok := si.content[lowerNeedle]; ok {
		si.contentMu.Unlock()
		return hit
	}
	si.contentMu.Unlock()

	hit := storeTextMayContainLower(s, lowerNeedle)

	si.contentMu.Lock()
	si.content[lowerNeedle] = hit
	si.contentMu.Unlock()
	return hit
}

func prewarmContentRequirements(s usg.Store, reqs ...*parser.BindingRequirement) {
	if storeNodeCount(s) < presenceGateMinNodes {
		return
	}
	needles := map[string]bool{}
	var walk func(*parser.BindingRequirement)
	walk = func(req *parser.BindingRequirement) {
		if req == nil {
			return
		}
		if req.Op == "content" && req.Value != "" {
			needles[lowerString(req.Value)] = true
		}
		for i := range req.Args {
			walk(&req.Args[i])
		}
	}
	for _, req := range reqs {
		walk(req)
	}
	if len(needles) == 0 {
		return
	}
	sharedContentContainsAny(s, needles)
}

func sharedContentContainsAny(s usg.Store, lowerNeedles map[string]bool) {
	si := storeIndexes(s)
	si.contentMu.Lock()
	if si.content == nil {
		si.content = map[string]bool{}
	}
	missing := map[string]bool{}
	for needle := range lowerNeedles {
		if needle == "" {
			continue
		}
		if _, ok := si.content[needle]; !ok {
			missing[needle] = false
		}
	}
	si.contentMu.Unlock()
	if len(missing) == 0 {
		return
	}

	storeTextMayContainAnyLower(s, missing)

	si.contentMu.Lock()
	for needle, hit := range missing {
		si.content[needle] = hit
	}
	si.contentMu.Unlock()
}

func storeTextMayContainLower(s usg.Store, lowerNeedle string) bool {
	if len(lowerNeedle) < 3 {
		return true
	}
	grams := sharedContentGrams(s)
	for i := 0; i+3 <= len(lowerNeedle); i++ {
		if _, ok := grams[contentGram(lowerNeedle[i:i+3])]; !ok {
			return false
		}
	}
	return true
}

func storeTextMayContainAnyLower(s usg.Store, missing map[string]bool) {
	grams := sharedContentGrams(s)
	for needle := range missing {
		if len(needle) < 3 {
			missing[needle] = true
			continue
		}
		missing[needle] = true
		for i := 0; i+3 <= len(needle); i++ {
			if _, ok := grams[contentGram(needle[i:i+3])]; !ok {
				missing[needle] = false
				break
			}
		}
	}
}

func sharedContentGrams(s usg.Store) map[uint32]struct{} {
	si := storeIndexes(s)
	si.gramOnce.Do(func() {
		grams := map[uint32]struct{}{}
		add := func(v string) {
			if len(v) < 3 {
				return
			}
			addContentGrams(grams, lowerString(v))
		}
		rangeNodes(s, func(n usg.Node) bool {
			add(n.ID)
			add(n.Type)
			add(n.Loc)
			add(n.Region)
			add(n.Scope)
			for _, v := range n.Props {
				add(v)
			}
			return true
		})
		si.grams = grams
	})
	return si.grams
}

func addContentGrams(grams map[uint32]struct{}, lower string) {
	for i := 0; i+3 <= len(lower); i++ {
		grams[contentGram(lower[i:i+3])] = struct{}{}
	}
}

func contentGram(s string) uint32 {
	if len(s) < 3 {
		return 0
	}
	return uint32(s[0])<<16 | uint32(s[1])<<8 | uint32(s[2])
}

func storeTextContainsAnyLower(s usg.Store, missing map[string]bool) {
	check := func(v string) bool {
		if v == "" {
			return len(missing) == 0
		}
		lower := lowerString(v)
		for needle, hit := range missing {
			if !hit && strings.Contains(lower, needle) {
				missing[needle] = true
			}
		}
		return allContentNeedlesFound(missing)
	}
	rangeNodes(s, func(n usg.Node) bool {
		if check(n.ID) || check(n.Type) || check(n.Loc) || check(n.Region) || check(n.Scope) {
			return false
		}
		for _, v := range n.Props {
			if check(v) {
				return false
			}
		}
		return true
	})
}

func allContentNeedlesFound(missing map[string]bool) bool {
	for _, hit := range missing {
		if !hit {
			return false
		}
	}
	return true
}

type flagMatchIndex struct {
	once            sync.Once // guards the read-only index build (ensure)
	flow            flowTokenIndex
	types           map[string][]string
	typesByTech     map[string]map[string][]string // tech -> type -> node IDs ("" tech = unknown, kept by every language)
	typesByFile     map[string]map[string][]string
	binopsByFile    map[string]map[string][]string
	callsByFileTerm map[string]map[string][]string
	paramsByLine    map[string]map[int][]string
	intNodes        bool
	typesI          map[string][]int32
	typesByTechI    map[string]map[string][]int32 // tech -> type -> node indexes
	typesByFileI    map[string]map[string][]int32
	binopsByFileI   map[string]map[string][]int32
	paramsByLineI   map[string]map[int][]int32
	// Lazy memoization caches written during matching. They hold pure-function results
	// (lowering/parsing/scope of a node or text), so concurrent racing producers compute
	// the same value; sync.Map only has to keep the map itself race-free under the parallel
	// binding phase, without serializing the hot read path the way an RWMutex would.
	scopes      sync.Map // nodeID -> string
	lowerText   sync.Map // text -> string
	tokenFacts  sync.Map // text -> *contextTokenFacts
	callArgText sync.Map // key -> string
	operands    sync.Map // nodeID/includeFlow -> [][]usg.Node
	predHitSets sync.Map // key -> scopedPredicateHitSet
}

// nodesOfTechType returns the nodes of nodeType that a binding of the given technology must
// consider: only that technology's nodes (plus unknown-technology nodes, which every language
// binding kept), or all nodes for a cross-language binding. This replaces scanning every node of
// the type and skipping by technology per node — the cost that made a polyglot tree (the kernel
// has a few .py/.php files) run every present language's bindings over all ~millions of nodes.
// techNodes returns, across the given node types, the nodes a binding of the given technology must
// consider (its own technology's nodes plus unknown-technology nodes, or all for cross-language).
// Applicators iterate this instead of every node of the type followed by a per-node technology
// skip, so a language with few files (a handful of .py in a C tree) costs a handful of nodes, not a
// full-graph scan.
func (idx *flagMatchIndex) techNodes(s usg.Store, tech string, crossLang bool, types ...string) []usg.Node {
	var out []usg.Node
	idx.rangeTechNodes(s, tech, crossLang, func(n usg.Node) bool {
		out = append(out, n)
		return true
	}, types...)
	return out
}

func (idx *flagMatchIndex) rangeTechNodes(s usg.Store, tech string, crossLang bool, fn func(usg.Node) bool, types ...string) {
	for _, t := range types {
		if !idx.rangeNodesOfTechType(s, tech, t, crossLang, fn) {
			return
		}
	}
}

func (idx *flagMatchIndex) nodesOfTechType(s usg.Store, tech, nodeType string, crossLang bool) []usg.Node {
	var out []usg.Node
	idx.rangeNodesOfTechType(s, tech, nodeType, crossLang, func(n usg.Node) bool {
		out = append(out, n)
		return true
	})
	return out
}

func (idx *flagMatchIndex) rangeNodesOfTechType(s usg.Store, tech, nodeType string, crossLang bool, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if crossLang || tech == "" {
			return rangeNodeIndexes(is, idx.typesI[nodeType], fn)
		}
		if !rangeNodeIndexes(is, idx.typesByTechI[tech][nodeType], fn) {
			return false
		}
		return rangeNodeIndexes(is, idx.typesByTechI[""][nodeType], fn)
	}
	if crossLang || tech == "" {
		return rangeNodeIDs(s, idx.types[nodeType], fn)
	}
	if !rangeNodeIDs(s, idx.typesByTech[tech][nodeType], fn) {
		return false
	}
	return rangeNodeIDs(s, idx.typesByTech[""][nodeType], fn)
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

func (idx *flagMatchIndex) ensure(s usg.Store) {
	idx.once.Do(func() { idx.build(s) })
}

func (idx *flagMatchIndex) build(s usg.Store) {
	start := time.Now()
	count := 0
	techCounts := map[string]int{}
	defer func() {
		if indexTimingOn {
			var parts []string
			for tech, n := range techCounts {
				label := tech
				if label == "" {
					label = "<unknown>"
				}
				parts = append(parts, fmt.Sprintf("%s=%d", label, n))
			}
			sort.Strings(parts)
			fmt.Fprintf(os.Stderr, "[index] flagMatchIndex build %7.1fms nodes=%d int=%v tech=%s\n", float64(time.Since(start))/1e6, count, idx.intNodes, strings.Join(parts, ","))
		}
	}()
	if is, ok := s.(interface {
		RangeNodeIndexes(func(int32, usg.Node) bool)
		NodeAtIndex(int32) (usg.Node, bool)
	}); ok {
		count, techCounts = idx.buildInt(s, is)
		return
	}
	idx.types = map[string][]string{}
	idx.typesByTech = map[string]map[string][]string{}
	idx.typesByFile = map[string]map[string][]string{}
	idx.binopsByFile = map[string]map[string][]string{}
	idx.callsByFileTerm = map[string]map[string][]string{}
	idx.paramsByLine = map[string]map[int][]string{}
	fileTech := sharedFileContextTechs(s)
	rangeNodes(s, func(n usg.Node) bool {
		count++
		idx.types[n.Type] = append(idx.types[n.Type], n.ID)
		tech := nodeTechFromNodeWithFileContext(n, fileTech)
		techCounts[tech]++
		if idx.typesByTech[tech] == nil {
			idx.typesByTech[tech] = map[string][]string{}
		}
		idx.typesByTech[tech][n.Type] = append(idx.typesByTech[tech][n.Type], n.ID)
		if file := locFile(n.Prop("loc")); file != "" {
			if idx.typesByFile[n.Type] == nil {
				idx.typesByFile[n.Type] = map[string][]string{}
			}
			idx.typesByFile[n.Type][file] = append(idx.typesByFile[n.Type][file], n.ID)
			if n.Type == "code.BinOp" {
				if idx.binopsByFile[file] == nil {
					idx.binopsByFile[file] = map[string][]string{}
				}
				idx.binopsByFile[file][n.Prop("op")] = append(idx.binopsByFile[file][n.Prop("op")], n.ID)
			}
			if n.Type == "code.Call" {
				idx.addCallTerms(file, n)
			}
			if n.Type == "code.Param" {
				_, line := splitLocFileLine(n.Prop("loc"))
				if line != 0 {
					if idx.paramsByLine[file] == nil {
						idx.paramsByLine[file] = map[int][]string{}
					}
					idx.paramsByLine[file][line] = append(idx.paramsByLine[file][line], n.ID)
				}
			}
		}
		return true
	})
}

func (idx *flagMatchIndex) buildInt(s usg.Store, is interface {
	RangeNodeIndexes(func(int32, usg.Node) bool)
	NodeAtIndex(int32) (usg.Node, bool)
}) (int, map[string]int) {
	idx.intNodes = true
	idx.typesI = map[string][]int32{}
	idx.typesByTechI = map[string]map[string][]int32{}
	idx.typesByFileI = map[string]map[string][]int32{}
	idx.binopsByFileI = map[string]map[string][]int32{}
	idx.callsByFileTerm = map[string]map[string][]string{}
	idx.paramsByLineI = map[string]map[int][]int32{}
	fileTech := sharedFileContextTechs(s)
	count := 0
	techCounts := map[string]int{}
	is.RangeNodeIndexes(func(i int32, n usg.Node) bool {
		count++
		idx.typesI[n.Type] = append(idx.typesI[n.Type], i)
		tech := nodeTechFromNodeWithFileContext(n, fileTech)
		techCounts[tech]++
		if idx.typesByTechI[tech] == nil {
			idx.typesByTechI[tech] = map[string][]int32{}
		}
		idx.typesByTechI[tech][n.Type] = append(idx.typesByTechI[tech][n.Type], i)
		if file := locFile(n.Prop("loc")); file != "" {
			if idx.typesByFileI[n.Type] == nil {
				idx.typesByFileI[n.Type] = map[string][]int32{}
			}
			idx.typesByFileI[n.Type][file] = append(idx.typesByFileI[n.Type][file], i)
			if n.Type == "code.BinOp" {
				if idx.binopsByFileI[file] == nil {
					idx.binopsByFileI[file] = map[string][]int32{}
				}
				idx.binopsByFileI[file][n.Prop("op")] = append(idx.binopsByFileI[file][n.Prop("op")], i)
			}
			if n.Type == "code.Call" {
				idx.addCallTerms(file, n)
			}
			if n.Type == "code.Param" {
				_, line := splitLocFileLine(n.Prop("loc"))
				if line != 0 {
					if idx.paramsByLineI[file] == nil {
						idx.paramsByLineI[file] = map[int][]int32{}
					}
					idx.paramsByLineI[file][line] = append(idx.paramsByLineI[file][line], i)
				}
			}
		}
		return true
	})
	return count, techCounts
}

func (idx *flagMatchIndex) addCallTerms(file string, n usg.Node) {
	terms := callIndexTerms(n)
	if len(terms) == 0 {
		return
	}
	byTerm := idx.callsByFileTerm[file]
	if byTerm == nil {
		byTerm = map[string][]string{}
		idx.callsByFileTerm[file] = byTerm
	}
	for _, term := range terms {
		byTerm[term] = append(byTerm[term], n.ID)
	}
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

func (idx *flagMatchIndex) nodesOfType(s usg.Store, typ string) []usg.Node {
	return collectNodesOfType(s, typ)
}

func (idx *flagMatchIndex) nodesOfTypeInFile(s usg.Store, typ, file string) []usg.Node {
	idx.ensure(s)
	if file == "" {
		return collectNodesOfType(s, typ)
	}
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		return collectNodesByIndex(is, idx.typesByFileI[typ][file])
	}
	return collectNodesByID(s, idx.typesByFile[typ][file])
}

func (idx *flagMatchIndex) rangeNodesOfTypeInFile(s usg.Store, typ, file string, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if file == "" {
			return rangeNodeIndexes(is, idx.typesI[typ], fn)
		}
		return rangeNodeIndexes(is, idx.typesByFileI[typ][file], fn)
	}
	if file == "" {
		return rangeNodeIDs(s, idx.types[typ], fn)
	}
	return rangeNodeIDs(s, idx.typesByFile[typ][file], fn)
}

func (idx *flagMatchIndex) binopsInFileForValues(s usg.Store, file string, values []string) []usg.Node {
	idx.ensure(s)
	ops, ok := binaryPredicateOps(values)
	if !ok {
		return idx.nodesOfTypeInFile(s, "code.BinOp", file)
	}
	if file == "" {
		var out []usg.Node
		for _, op := range ops {
			if idx.intNodes {
				is := s.(interface {
					NodeAtIndex(int32) (usg.Node, bool)
				})
				for _, byOp := range idx.binopsByFileI {
					out = append(out, collectNodesByIndex(is, byOp[op])...)
				}
			} else {
				for _, byOp := range idx.binopsByFile {
					out = append(out, collectNodesByID(s, byOp[op])...)
				}
			}
		}
		return out
	}
	if idx.intNodes {
		byOp := idx.binopsByFileI[file]
		if len(byOp) == 0 {
			return nil
		}
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		var out []usg.Node
		for _, op := range ops {
			out = append(out, collectNodesByIndex(is, byOp[op])...)
		}
		return out
	}
	byOp := idx.binopsByFile[file]
	if len(byOp) == 0 {
		return nil
	}
	var out []usg.Node
	for _, op := range ops {
		out = append(out, collectNodesByID(s, byOp[op])...)
	}
	return out
}

func (idx *flagMatchIndex) rangeBinopsInFileForValues(s usg.Store, file string, values []string, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	ops, ok := binaryPredicateOps(values)
	if !ok {
		return idx.rangeNodesOfTypeInFile(s, "code.BinOp", file, fn)
	}
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if file == "" {
			for _, op := range ops {
				for _, byOp := range idx.binopsByFileI {
					if !rangeNodeIndexes(is, byOp[op], fn) {
						return false
					}
				}
			}
			return true
		}
		byOp := idx.binopsByFileI[file]
		for _, op := range ops {
			if !rangeNodeIndexes(is, byOp[op], fn) {
				return false
			}
		}
		return true
	}
	if file == "" {
		for _, op := range ops {
			for _, byOp := range idx.binopsByFile {
				if !rangeNodeIDs(s, byOp[op], fn) {
					return false
				}
			}
		}
		return true
	}
	byOp := idx.binopsByFile[file]
	for _, op := range ops {
		if !rangeNodeIDs(s, byOp[op], fn) {
			return false
		}
	}
	return true
}

func (idx *flagMatchIndex) node(s usg.Store, id string) (usg.Node, bool) {
	n, ok, err := s.GetNode(id)
	if err != nil {
		return usg.Node{}, false
	}
	return n, ok
}

func (idx *flagMatchIndex) ensureFlow(s usg.Store) *flowTokenIndex {
	idx.ensure(s)
	idx.flow.ensure(s)
	return &idx.flow
}

func (idx *flagMatchIndex) normalizedScope(n usg.Node) string {
	if n.ID == "" {
		return scopeWithoutOrder(nodeLexicalScope(n))
	}
	if scope, ok := idx.scopes.Load(n.ID); ok {
		return scope.(string)
	}
	scope := scopeWithoutOrder(nodeLexicalScope(n))
	idx.scopes.Store(n.ID, scope)
	return scope
}

func (idx *flagMatchIndex) lowerTextValue(text string) string {
	if text == "" {
		return ""
	}
	if len(text) > lowerTextCacheMaxBytes {
		return lowerString(text)
	}
	if lower, ok := idx.lowerText.Load(text); ok {
		return lower.(string)
	}
	lower := lowerString(text)
	idx.lowerText.Store(text, lower)
	return lower
}

var lowerTextCacheMaxBytes = configuredLowerTextCacheMaxBytes()

func configuredLowerTextCacheMaxBytes() int {
	if v := strings.TrimSpace(os.Getenv("VYQL_LOWER_TEXT_CACHE_MAX_BYTES")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n >= 0 {
			return n
		}
	}
	return 64 * 1024
}

type contextTokenFacts struct {
	byPrefix      map[string][]string
	lowerByPrefix map[string][]string
}

func (idx *flagMatchIndex) contextFacts(text string) *contextTokenFacts {
	if facts, ok := idx.tokenFacts.Load(text); ok {
		return facts.(*contextTokenFacts)
	}
	facts := &contextTokenFacts{
		byPrefix:      map[string][]string{},
		lowerByPrefix: map[string][]string{},
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
		if tok == "" {
			continue
		}
		prefix, value, ok := splitContextTokenPredicateValue(tok)
		if !ok {
			continue
		}
		facts.byPrefix[prefix] = append(facts.byPrefix[prefix], value)
		facts.lowerByPrefix[prefix] = append(facts.lowerByPrefix[prefix], lowerString(value))
	}
	idx.tokenFacts.Store(text, facts)
	return facts
}

func (idx *flagMatchIndex) scopedHit(s usg.Store, kind string, pred flagPredicate, values []string, nodeTypes []string, n usg.Node, tech string, crossLang bool, allowUnscoped bool, match func(usg.Node) bool) bool {
	idx.ensure(s)
	file := locFile(n.Prop("loc"))
	scope := idx.normalizedScope(n)
	hits := idx.scopedPredicateHits(s, kind, pred, values, nodeTypes, file, tech, crossLang, match)
	return hits.matches(scope, n.ID, allowUnscoped)
}

func (idx *flagMatchIndex) scopedPredicateHits(s usg.Store, kind string, pred flagPredicate, values []string, nodeTypes []string, file string, tech string, crossLang bool, match func(usg.Node) bool) scopedPredicateHitSet {
	key := strings.Join([]string{
		kind,
		flagPredicateCacheKey(pred),
		strings.Join(values, "\x1f"),
		strings.Join(nodeTypes, "\x1f"),
		file,
		tech,
		strconv.FormatBool(crossLang),
	}, "\x1e")
	if cached, ok := idx.predHitSets.Load(key); ok {
		return cached.(scopedPredicateHitSet)
	}
	var out scopedPredicateHitSet
	addCandidate := func(cand usg.Node) {
		candScope := idx.normalizedScope(cand)
		out.totalCount++
		out.singleID = cand.ID
		if candScope == "" {
			out.unscopedCount++
			out.unscopedID = cand.ID
			return
		}
		if out.exactCounts == nil {
			out.exactCounts = map[string]scopeHitCount{}
		}
		count := out.exactCounts[candScope]
		if count.count == 0 {
			out.scopes = append(out.scopes, candScope)
		}
		count.count++
		count.singleID = cand.ID
		out.exactCounts[candScope] = count
	}
	if ids, ok := idx.scopeCallCandidateIDs(file, pred, nodeTypes); ok {
		for _, id := range ids {
			cand, ok := idx.node(s, id)
			if !ok {
				continue
			}
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				continue
			}
			if match(cand) {
				addCandidate(cand)
			}
		}
		sort.Strings(out.scopes)
		idx.predHitSets.Store(key, out)
		return out
	}
	for _, nodeType := range nodeTypes {
		if kind == "binop" && nodeType == "code.BinOp" {
			idx.rangeBinopsInFileForValues(s, file, values, func(cand usg.Node) bool {
				if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
					return true
				}
				if !match(cand) {
					return true
				}
				addCandidate(cand)
				return true
			})
			continue
		}
		idx.rangeNodesOfTypeInFile(s, nodeType, file, func(cand usg.Node) bool {
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				return true
			}
			if !match(cand) {
				return true
			}
			addCandidate(cand)
			return true
		})
	}
	sort.Strings(out.scopes)
	idx.predHitSets.Store(key, out)
	return out
}

func (idx *flagMatchIndex) scopeCallCandidateIDs(file string, pred flagPredicate, nodeTypes []string) ([]string, bool) {
	if len(nodeTypes) != 1 || nodeTypes[0] != "code.Call" || !scopeCallPredicateIndexable(pred) {
		return nil, false
	}
	byTerm := idx.callsByFileTerm[file]
	if len(byTerm) == 0 {
		return nil, true
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range pred.Values {
		term := lowerString(strings.TrimSpace(value))
		for _, id := range byTerm[term] {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
		if len(byTerm[term]) > 0 {
			continue
		}
		for got, ids := range byTerm {
			if !strings.Contains(got, term) {
				continue
			}
			for _, id := range ids {
				if seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out, true
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

func (idx *flowTokenIndex) ensure(s usg.Store) {
	idx.once.Do(func() { idx.build(s) })
}

func (idx *flowTokenIndex) build(s usg.Store) {
	idx.rev = map[string][]string{}
	idx.fwd = map[string][]string{}
	rangeNodes(s, func(n usg.Node) bool {
		if rg, ok := s.(interface {
			RangeOutEdges(string, string, func(string) bool)
		}); ok {
			rg.RangeOutEdges(n.ID, "FLOWS", func(dst string) bool {
				idx.rev[dst] = append(idx.rev[dst], n.ID)
				idx.fwd[n.ID] = append(idx.fwd[n.ID], dst)
				return true
			})
			return true
		}
		edges, _ := s.OutEdges(n.ID, "FLOWS")
		for _, edge := range edges {
			idx.rev[edge.Dst] = append(idx.rev[edge.Dst], edge.Src)
			idx.fwd[n.ID] = append(idx.fwd[n.ID], edge.Dst)
		}
		return true
	})
}

func valCondsForNode(s usg.Store, idx *flowTokenIndex, n usg.Node, vals, nvals []string) bool {
	if len(vals) == 0 && len(nvals) == 0 {
		return true
	}
	direct := n.Prop("str_args")
	lowerDirect := lowerString(direct)
	if valCondsLower(lowerDirect, vals, nvals) {
		return true
	}
	for _, nv := range nvals {
		if valContainsLower(lowerDirect, nv) {
			return false
		}
	}
	if strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		return false
	}
	if len(vals) == 0 {
		return false
	}
	return valConds(flowingStringTokens(s, idx, n.ID, direct), vals, nvals)
}

func valCondsDirectForNode(n usg.Node, vals, nvals []string) bool {
	if len(vals) == 0 && len(nvals) == 0 {
		return true
	}
	return valConds(nodeDirectValueTokens(n), vals, nvals)
}

func valCondsDirectForNodeCached(cache *valueTokenCache, n usg.Node, valsLower, nvalsLower []string) bool {
	if len(valsLower) == 0 && len(nvalsLower) == 0 {
		return true
	}
	if len(valsLower) > 0 && strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		if present, ok := rawSegmentsContainStructuredContextNeedle([]string{n.Prop("str_args")}, valsLower[0]); ok && !present {
			return false
		}
	}
	return valCondsLowerNeedles(cache.directNodeLower(n), valsLower, nvalsLower)
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

func callArgCount(n usg.Node) int {
	for i := 0; ; i++ {
		if n.Prop("arg"+strconv.Itoa(i)) == "" {
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

func valCondsForSink(s usg.Store, idx *flowTokenIndex, call usg.Node, sk sinkSpec) bool {
	if len(sk.ValMatches) == 0 && len(sk.ValAbsents) == 0 {
		return true
	}

	tokens := []string{call.Prop("str_args")}
	addArg := func(arg string) {
		if arg == "" {
			return
		}
		if n, ok, err := s.GetNode(arg); err == nil && ok {
			tokens = append(tokens, n.Prop("str_args"))
			if len(sk.ValMatches) > 0 {
				tokens = append(tokens, flowingStringTokens(s, idx, n.ID, n.Prop("str_args")))
			}
		}
	}
	if sk.ArgIndex >= 0 {
		addArg(call.Prop("arg" + strconv.Itoa(sk.ArgIndex)))
	} else {
		for ai := 0; ; ai++ {
			arg := call.Prop("arg" + strconv.Itoa(ai))
			if arg == "" {
				break
			}
			addArg(arg)
		}
	}
	if len(sk.ValMatches) > 0 {
		tokens = append(tokens, flowingStringTokens(s, idx, call.ID, call.Prop("str_args")))
	}
	return valConds(strings.Join(tokens, "\x00"), sk.ValMatches, sk.ValAbsents)
}

func valCondsForSinkCached(s usg.Store, idx *flowTokenIndex, cache *valueTokenCache, call usg.Node, sk sinkSpec, valsLower, nvalsLower []string) bool {
	if len(valsLower) == 0 && len(nvalsLower) == 0 {
		return true
	}
	if len(valsLower) > 0 && strings.HasPrefix(call.Prop("callee_path"), "analysis.function.context.") {
		return valCondsForSinkDirectSegments(s, cache, call, sk.ArgIndex, valsLower, nvalsLower)
	}
	if functionReturnDecoratorAbsent(s, cache, call, sk.ArgIndex, valsLower) {
		return false
	}
	return valCondsLowerNeedles(cache.sinkValueLower(s, idx, call, sk.ArgIndex, len(valsLower) > 0), valsLower, nvalsLower)
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

func valCondsForSinkDirectSegments(s usg.Store, cache *valueTokenCache, call usg.Node, argIndex int, valsLower, nvalsLower []string) bool {
	direct := cache.directSegments(s, call, argIndex)
	if len(valsLower) > 0 {
		if present, ok := rawSegmentsContainStructuredContextNeedle(direct.raw, valsLower[0]); ok {
			if !present {
				return false
			}
		} else if shouldFoldedDirectPrecheck(valsLower, nvalsLower) &&
			!cache.directRawContainsFolded(call, argIndex, direct.raw, valsLower[0]) {
			return false
		}
		for _, v := range valsLower[1:] {
			if shouldFoldedDirectPrecheckValue(v) && !cache.directRawContainsFolded(call, argIndex, direct.raw, v) {
				return false
			}
		}
	}

	segments := []string{cache.nodeStrArgsLower(call)}
	for _, n := range direct.nodes {
		segments = append(segments, cache.nodeStrArgsLower(n))
	}
	contains := func(needle string) bool {
		return cache.directContainsLower(call, argIndex, segments, needle)
	}
	for _, v := range valsLower {
		if !contains(v) {
			return false
		}
	}
	for _, nv := range nvalsLower {
		if contains(nv) {
			return false
		}
	}
	return true
}

func shouldFoldedDirectPrecheck(valsLower, _ []string) bool {
	if len(valsLower) == 0 {
		return false
	}
	first := valsLower[0]
	return shouldFoldedDirectPrecheckValue(first)
}

func shouldFoldedDirectPrecheckValue(lowerNeedle string) bool {
	return strings.HasSuffix(lowerNeedle, ":") ||
		len(lowerNeedle) >= 16 ||
		(strings.HasPrefix(lowerNeedle, "<") && len(lowerNeedle) >= 4)
}

func rawSegmentsContainStructuredContextNeedle(segments []string, lowerNeedle string) (bool, bool) {
	prefix, ok := structuredContextNeedlePrefix(lowerNeedle)
	if !ok {
		return false, false
	}
	for _, segment := range segments {
		if segmentContainsStructuredContextNeedle(segment, prefix, lowerNeedle) {
			return true, true
		}
	}
	return false, true
}

func structuredContextNeedlePrefix(lowerNeedle string) (string, bool) {
	for _, prefix := range []string{"name=", "class_bases=", "decorator_method:", "python_review:"} {
		if strings.HasPrefix(lowerNeedle, prefix) {
			return prefix, true
		}
	}
	return "", false
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

func asciiHasFoldedPrefix(s, lowerPrefix string) bool {
	if len(s) < len(lowerPrefix) {
		return false
	}
	for i := 0; i < len(lowerPrefix); i++ {
		ch := s[i]
		if ch >= 0x80 || lowerPrefix[i] >= 0x80 {
			return strings.HasPrefix(lowerString(s), lowerPrefix)
		}
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch != lowerPrefix[i] {
			return false
		}
	}
	return true
}

func rawSegmentsContainFolded(segments []string, needle string) bool {
	for _, segment := range segments {
		if valContainsFoldedNeedle(segment, needle) {
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

// rangeTechCallablePropNodes is rangeCallablePropNodes restricted to a binding's technology (plus
// unknown-technology nodes), or all nodes for a cross-language binding — so a language applicator
// visits only its own nodes instead of scanning every callable node and skipping by technology.
func rangeTechCallablePropNodes(idx *flagMatchIndex, s usg.Store, tech string, crossLang bool, fn func(usg.Node) bool) {
	idx.rangeTechNodes(s, tech, crossLang, fn, callablePropTypes...)
}

func collectNodesOfType(s usg.Store, typ string) []usg.Node {
	var out []usg.Node
	rangeNodesOfTypeDirect(s, typ, func(n usg.Node) bool {
		out = append(out, n)
		return true
	})
	return out
}

func collectNodesByID(s usg.Store, ids []string) []usg.Node {
	if len(ids) == 0 {
		return nil
	}
	out := make([]usg.Node, 0, len(ids))
	for _, id := range ids {
		n, ok, err := s.GetNode(id)
		if err != nil || !ok {
			continue
		}
		out = append(out, n)
	}
	return out
}

func collectNodesByIndex(is interface {
	NodeAtIndex(int32) (usg.Node, bool)
}, idxs []int32) []usg.Node {
	if len(idxs) == 0 {
		return nil
	}
	out := make([]usg.Node, 0, len(idxs))
	for _, idx := range idxs {
		n, ok := is.NodeAtIndex(idx)
		if !ok {
			continue
		}
		out = append(out, n)
	}
	return out
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

func rangeNodesOfTypeDirect(s usg.Store, typ string, fn func(usg.Node) bool) bool {
	if rg, ok := s.(interface {
		RangeNodesOfType(string, func(usg.Node) bool)
	}); ok {
		stopped := false
		rg.RangeNodesOfType(typ, func(n usg.Node) bool {
			if !fn(n) {
				stopped = true
				return false
			}
			return true
		})
		return !stopped
	}
	ids, _ := s.NodesOfType(typ)
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

func nodeAllowedForBindingTech(n usg.Node, fileTech map[string]string, tech string, crossLang bool) bool {
	if crossLang || tech == "" {
		return true
	}
	nt := nodeTechFromNodeWithFileContext(n, fileTech)
	return nt == "" || nt == tech
}

func rangeNodesOfTechTypeDirect(s usg.Store, tech, typ string, crossLang bool, fn func(usg.Node) bool) bool {
	fileTech := sharedFileContextTechs(s)
	return rangeNodesOfTypeDirect(s, typ, func(n usg.Node) bool {
		if !nodeAllowedForBindingTech(n, fileTech, tech, crossLang) {
			return true
		}
		return fn(n)
	})
}

func rangeTechNodesDirect(s usg.Store, tech string, crossLang bool, fn func(usg.Node) bool, types ...string) {
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

func rangeCallablePropNodes(s usg.Store, fn func(usg.Node) bool) {
	for _, typ := range callablePropTypes {
		ids, _ := s.NodesOfType(typ)
		for _, id := range ids {
			n, ok, err := s.GetNode(id)
			if err != nil || !ok {
				continue
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

type collectionFlowIndex struct {
	reachesSeq  map[string][]string
	reachesDone map[string]bool
	seqElements map[string]map[int]string
}

func (idx *collectionFlowIndex) seqsForArg(s usg.Store, argID string) []string {
	if argID == "" {
		return nil
	}
	if idx.reachesSeq == nil {
		idx.reachesSeq = map[string][]string{}
		idx.reachesDone = map[string]bool{}
	}
	if idx.reachesDone[argID] {
		return idx.reachesSeq[argID]
	}
	idx.reachesDone[argID] = true
	type item struct {
		id    string
		depth int
	}
	seen := map[string]bool{argID: true}
	q := []item{{id: argID}}
	for head := 0; head < len(q) && len(seen) < 64; head++ {
		cur := q[head]
		n, ok, err := s.GetNode(cur.id)
		if err == nil && ok && n.Type == "code.Seq" {
			idx.reachesSeq[argID] = append(idx.reachesSeq[argID], cur.id)
		}
		if cur.depth >= 4 {
			continue
		}
		rangeFlowIn(s, nil, cur.id, func(srcID string) bool {
			if seen[srcID] {
				return true
			}
			seen[srcID] = true
			q = append(q, item{id: srcID, depth: cur.depth + 1})
			return true
		})
	}
	return idx.reachesSeq[argID]
}

func (idx *collectionFlowIndex) elementForSeq(s usg.Store, seqID string, elemIndex int) string {
	if idx.seqElements == nil {
		idx.seqElements = map[string]map[int]string{}
	}
	if elems, ok := idx.seqElements[seqID]; ok {
		return elems[elemIndex]
	}
	elems := map[int]string{}
	rangeFlowIn(s, nil, seqID, func(srcID string) bool {
		elem, ok, err := s.GetNode(srcID)
		if err != nil || !ok || elem.Type != "code.CollectionElement" {
			return true
		}
		i, err := strconv.Atoi(elem.Prop("collection_index"))
		if err != nil {
			return true
		}
		elems[i] = srcID
		return true
	})
	idx.seqElements[seqID] = elems
	return elems[elemIndex]
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

func detailWithPattern(detail map[string]string, pattern string) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	out := make(map[string]string, len(detail)+1)
	for k, v := range detail {
		out[k] = v
	}
	if pattern != "" && out["pattern"] == "" {
		out["pattern"] = pattern
	}
	return out
}

var (
	conceptDetailOnce sync.Once
	conceptDetails    map[string]map[string]string
	conceptRoleOnce   sync.Once
	conceptRoles      map[string]map[string]bool
	bindingSetCache   sync.Map // map[bindingSetCacheKey]*parser.BindingSet
)

func reviewDetail(concept, pattern string) (map[string]string, string) {
	template := ontologyConceptDetails()[concept]
	if len(template) == 0 {
		return nil, ""
	}
	detail := make(map[string]string, len(template))
	for k, v := range template {
		detail[k] = strings.ReplaceAll(v, "{pattern}", pattern)
	}
	conf := ""
	if detail["review_confidence"] == "low" {
		conf = "low"
	}
	return detailWithPattern(detail, pattern), conf
}

func ontologyConceptDetails() map[string]map[string]string {
	conceptDetailOnce.Do(func() {
		conceptDetails = map[string]map[string]string{}
		files, err := datadir.ReadVYQLDir("ontology")
		if err != nil {
			panic("frontend: read ontology: " + err.Error())
		}
		decls, err := parseV2BindingSources(files)
		if err != nil {
			panic("frontend: parse ontology detail corpus: " + err.Error())
		}
		for _, d := range decls {
			cd, ok := d.(*parser.ConceptDecl)
			if !ok {
				continue
			}
			detail := map[string]string{}
			for k, v := range cd.Fields {
				if !strings.HasPrefix(k, "review_") {
					continue
				}
				if s, ok := v.(string); ok && s != "" {
					detail[k] = s
				}
			}
			if len(detail) > 0 {
				conceptDetails[cd.QualifiedName()] = detail
			}
		}
	})
	return conceptDetails
}

func ontologyRoleConcepts(role string) map[string]bool {
	conceptRoleOnce.Do(func() {
		conceptRoles = map[string]map[string]bool{}
		o := ontology.Seed()
		for _, role := range ontology.InternalConceptRoles() {
			conceptRoles[role] = o.ConceptsWithInternalConceptRole(role)
		}
	})
	return conceptRoles[role]
}

func singleOntologyRoleConcept(role string) string {
	var out string
	for c := range ontologyRoleConcepts(role) {
		if strings.HasSuffix(c, "Issue") {
			continue
		}
		out = c
	}
	if out != "" {
		return out
	}
	for c := range ontologyRoleConcepts(role) {
		if out != "" {
			return ""
		}
		out = c
	}
	return out
}

type filterSpec struct {
	Pattern     string
	ByMethod    bool // match the bare method name (x.replace) vs the dotted path (re.sub)
	Global      bool // always-global replace (gsub/replaceAll/re.sub); else needs the /g flag
	ArgCountSet bool
	ArgCountMin int
	ArgCountMax int
	Packages    []string
	Requirement *parser.BindingRequirement
}

// advisoryNeutralizerSpec is an UNSOUND neutralizer: a guard (dominance) or sanitizer (on-path) that
// might apply but cannot be proven to. It never kills a flow; the engine
// attaches an advisory note instead.
type advisoryNeutralizerSpec struct {
	Pattern     string
	ByMethod    bool
	Mode        string // "guard" (must dominate the sink) | "sanitizer" (must lie on the path)
	About       string // the sink concept it purports to cover
	Detail      map[string]string
	ValMatches  []string
	ValAbsents  []string
	ScopePreds  []flagPredicate
	ArgCountSet bool
	ArgCountMin int
	ArgCountMax int
	Packages    []string
	Requirement *parser.BindingRequirement
	Fidelity    string
	Confidence  string
}

type paramSourceSpec struct {
	Concept     string
	Packages    []string
	Requirement *parser.BindingRequirement
	Fidelity    string
	Confidence  string
}

type bindingSpec struct {
	Name                 string
	Technology           string
	containsMatch        bool
	crossLang            bool // labels nodes in EVERY language (skips the per-tech filter)
	Inputs               []inputSpec
	Sinks                []sinkSpec
	Controls             []controlSpec
	Marks                []controlSpec // presence markers (label the call node with a concept)
	Flags                []flagSpec
	Filters              []filterSpec
	AdvisoryNeutralizers []advisoryNeutralizerSpec
	ParamSources         []paramSourceSpec // `source param -> X`: concepts to label parameter nodes with
}

// BindingsFor loads v2 bindings for a technology and builds the graph-labeling
// applicators that apply those bindings to an extracted graph.
func BindingsFor(tech string) []bindings.Applicator {
	out := bindingApplicatorsFromSpec(filterBindingSpecForActiveConcepts(loadSpec(tech)))
	if tech == "javascript" {
		out = append(out, jsDomValueInputApplicator())
		out = append(out, jsPathRegexGuardApplicator())
		out = append(out, jsSafePathResolverApplicator())
		out = append(out, jsModuleHelperLdapEscapeApplicator())
	}
	if tech == "ruby" {
		out = append(out, processArgVectorApplicator(tech))
	}
	return out
}

// OverlayBindings loads repo-local binding overlays from root. Files may live
// directly under root or under root/bindings. The overlay is intentionally
// explicit and opt-in; parse errors are returned so a bad generated file does
// not silently change scan behavior.
func OverlayBindings(root string, techs []string) ([]bindings.Applicator, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil
	}
	allowed := map[string]bool{}
	for _, tech := range techs {
		allowed[tech] = true
	}
	var files []string
	for _, dir := range []string{root, filepath.Join(root, "bindings")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".vyql") {
				continue
			}
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	var out []bindings.Applicator
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		decls, err := parseV2BindingSources([]datadir.Source{{
			Name: filepath.ToSlash(file),
			Data: b,
		}})
		if err != nil {
			return nil, err
		}
		for _, d := range decls {
			ad, ok := d.(*parser.BindingSet)
			if !ok {
				continue
			}
			if len(allowed) > 0 && !allowed[ad.Name] {
				return nil, fmt.Errorf("overlay binding %s declares %q, which is not present in this scan", file, ad.Name)
			}
			spec := filterBindingSpecForActiveConcepts(specFromBindingSet(ad))
			spec.Name = "overlay." + spec.Name
			out = append(out, bindingApplicatorsFromSpec(spec)...)
		}
	}
	return out, nil
}

// bindingApplicatorsFromSpec turns a compiled binding spec into concrete
// graph-labeling applicators, one per action family present. Shared by
// BindingsFor and the dynamic package loader.
func bindingApplicatorsFromSpec(spec bindingSpec) []bindings.Applicator {
	var out []bindings.Applicator
	if len(spec.Inputs) > 0 {
		out = append(out, spec.sourceApplicator())
	}
	if len(spec.Sinks) > 0 {
		out = append(out, spec.sinkApplicator())
	}
	if len(spec.Controls) > 0 {
		out = append(out, spec.checkApplicator())
	}
	if len(spec.Marks) > 0 {
		out = append(out, spec.matchPresenceApplicator())
	}
	if len(spec.Flags) > 0 {
		out = append(out, spec.presenceApplicator())
	}
	if len(spec.Filters) > 0 {
		out = append(out, spec.filterApplicator())
	}
	if len(spec.ParamSources) > 0 {
		out = append(out, spec.paramSourceApplicator())
	}
	if len(spec.AdvisoryNeutralizers) > 0 {
		out = append(out, spec.advisoryNeutralizerApplicator())
	}
	return out
}

func bindingConceptActive(concept string) bool {
	return activeBindingConcepts == nil || concept == "" || activeBindingConcepts[concept]
}

func filterBindingSpecForActiveConcepts(spec bindingSpec) bindingSpec {
	if activeBindingConcepts == nil {
		return spec
	}
	out := spec
	out.Inputs = nil
	for _, x := range spec.Inputs {
		if bindingConceptActive(x.Concept) {
			out.Inputs = append(out.Inputs, x)
		}
	}
	out.Sinks = nil
	for _, x := range spec.Sinks {
		if bindingConceptActive(x.Concept) {
			out.Sinks = append(out.Sinks, x)
		}
	}
	out.Controls = nil
	for _, x := range spec.Controls {
		if bindingConceptActive(x.Concept) {
			out.Controls = append(out.Controls, x)
		}
	}
	out.Marks = nil
	for _, x := range spec.Marks {
		if bindingConceptActive(x.Concept) {
			out.Marks = append(out.Marks, x)
		}
	}
	out.Flags = nil
	for _, x := range spec.Flags {
		if bindingConceptActive(x.Concept) {
			out.Flags = append(out.Flags, x)
		}
	}
	// Filters emit an ontology-role concept selected at runtime, not a per-binding concept.
	// Keep them when pruning is active so sanitizer semantics stay intact for taint rules.
	out.Filters = spec.Filters
	out.AdvisoryNeutralizers = nil
	for _, x := range spec.AdvisoryNeutralizers {
		if bindingConceptActive(x.About) {
			out.AdvisoryNeutralizers = append(out.AdvisoryNeutralizers, x)
		}
	}
	out.ParamSources = nil
	for _, x := range spec.ParamSources {
		if bindingConceptActive(x.Concept) {
			out.ParamSources = append(out.ParamSources, x)
		}
	}
	return out
}

// advisoryNeutralizerApplicator labels unsound-neutralizer calls (guards/transforms that cannot be
// proven sound) with a Go-owned internal concept that the engine can surface as
// review context.
func (spec bindingSpec) advisoryNeutralizerApplicator() bindings.Applicator {
	concept := ontology.InternalNeutralizerAssumptionConcept
	return bindings.Applicator{
		Name: spec.Name + ".assumptions", Technology: spec.Technology, Specificity: 2,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			effects := make([]requirementEffect, len(spec.AdvisoryNeutralizers))
			valMatchesLower := make([][]string, len(spec.AdvisoryNeutralizers))
			valAbsentsLower := make([][]string, len(spec.AdvisoryNeutralizers))
			for i := range spec.AdvisoryNeutralizers {
				effects[i] = reqGate.effect(spec.AdvisoryNeutralizers[i].Packages, spec.AdvisoryNeutralizers[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.AdvisoryNeutralizers[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.AdvisoryNeutralizers[i].ValAbsents)
			}
			var out []bindings.Mapping
			valCache := &valueTokenCache{}
			scopeIdx := sharedFlagIndex(s)
			scopeIdx.rangeTechNodes(s, spec.Technology, spec.crossLang, func(n usg.Node) bool {
				id := n.ID
				method, path := n.Prop("method"), n.Prop("callee_path")
				for ai, as := range spec.AdvisoryNeutralizers {
					if !effects[ai].Allowed {
						continue
					}
					if !(as.ByMethod && method == as.Pattern || !as.ByMethod && matchSinkPath(path, as.Pattern)) {
						continue
					}
					if !callArgCountMatches(n, as.ArgCountSet, as.ArgCountMin, as.ArgCountMax) {
						continue
					}
					if !valCondsDirectForNodeCached(valCache, n, valMatchesLower[ai], valAbsentsLower[ai]) {
						continue
					}
					if !scopePredicatesMatch(s, scopeIdx, as.ScopePreds, n, spec.Technology, spec.crossLang) {
						continue
					}
					detail := cloneStringMap(as.Detail)
					if detail == nil {
						detail = map[string]string{}
					}
					detail["mode"] = as.Mode
					detail["about"] = as.About
					detail["pattern"] = as.Pattern
					conf, detail := effects[ai].apply(mappingConfidence(as.Confidence, ""), detail)
					out = append(out, bindings.Mapping{NodeID: id, Concept: concept,
						Fidelity: mappingFidelity(as.Fidelity, "syntactic"), Confidence: conf, Detail: detail})
					break
				}
				return true
			}, "code.Call")
			return out
		},
	}
}

// filterApplicator labels character-filtering replace(pattern, repl) calls with the
// ontology role concept, recording the proven OUTPUT alphabet (or that it is unbounded)
// in the label Detail. The solver then treats it as a SOUND sanitizer for any sink whose
// excluded chars the alphabet excludes, and the engine surfaces an unproven filter
// as an advisory note. The regex math is general (charfilter.go); WHICH methods
// filter is data (the `filter` directive).
func (spec bindingSpec) filterApplicator() bindings.Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleCharFilter)
	return bindings.Applicator{
		Name: spec.Name + ".filters", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			if concept == "" {
				return nil
			}
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			allowed := make([]bool, len(spec.Filters))
			for i := range spec.Filters {
				allowed[i] = reqGate.allowed(spec.Filters[i].Packages, spec.Filters[i].Requirement)
			}
			var out []bindings.Mapping
			sharedFlagIndex(s).rangeTechNodes(s, spec.Technology, false, func(n usg.Node) bool {
				id := n.ID
				method, path := n.Prop("method"), n.Prop("callee_path")
				matched, global := false, false
				for fi, f := range spec.Filters {
					if !allowed[fi] {
						continue
					}
					if (f.ByMethod && method == f.Pattern || !f.ByMethod && matchSinkPath(path, f.Pattern)) &&
						callArgCountMatches(n, f.ArgCountSet, f.ArgCountMin, f.ArgCountMax) {
						matched, global = true, f.Global
						break
					}
				}
				if !matched {
					return true
				}
				pattern, repl := n.Prop("lit0"), n.Prop("lit1")
				alphabet, bounded, removed := replaceCharEffects(pattern, repl, global)
				detail := map[string]string{"bounded": "false", "pattern": pattern}
				if bounded {
					detail["bounded"] = "true"
					detail["alphabet"] = alphabet
				}
				if removed != "" {
					detail["removed"] = removed
				}
				out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Detail: detail})
				return true
			}, "code.Call")
			return out
		},
	}
}

// CtorTypesFor returns the constructor-to-type table declared by v2 bindings,
// used by lowering to stamp recv_type.
func CtorTypesFor(tech string) map[string]string {
	out := map[string]string{}
	for _, mp := range loadBindingSet(tech).Mappings {
		if mp.Kind == "type" {
			out[mp.Pattern] = mp.Concept
		}
	}
	return out
}

func loadBindingSet(tech string) *parser.BindingSet {
	key := bindingSetCacheKey{tech: tech}
	if cached, ok := bindingSetCache.Load(key); ok {
		return cached.(*parser.BindingSet)
	}
	sources, err := datadir.ReadVYQLDir("bindings/" + tech)
	if err != nil {
		panic("frontend: read bindings/" + tech + ": " + err.Error())
	}
	if extra, err := datadir.ReadVYQLDir("bindings/packages/" + tech); err == nil {
		sources = append(sources, extra...)
	}
	decls, err := parseV2BindingSources(sources)
	if err != nil {
		panic("frontend: invalid binding corpus for " + tech + ": " + err.Error())
	}
	var merged *parser.BindingSet
	for _, d := range decls {
		a, ok := d.(*parser.BindingSet)
		if !ok || a.Name != tech {
			continue
		}
		if merged == nil {
			merged = &parser.BindingSet{Name: a.Name, Meta: a.Meta}
		} else {
			for k, v := range a.Meta {
				merged.Meta[k] = v
			}
		}
		merged.Mappings = append(merged.Mappings, a.Mappings...)
	}
	if merged != nil {
		actual, _ := bindingSetCache.LoadOrStore(key, merged)
		return actual.(*parser.BindingSet)
	}
	panic("frontend: no v2 binding set in bindings/" + tech)
}

type bindingSetCacheKey struct {
	tech string
}

func v2DefinitionSourcesForBindings(sources []datadir.Source) []parser.V2DefinitionSource {
	out := make([]parser.V2DefinitionSource, 0, len(sources)+32)
	hasOntology, hasPolicies := false, false
	for _, source := range sources {
		hasOntology = hasOntology || strings.HasPrefix(source.Name, "ontology/")
		hasPolicies = hasPolicies || strings.HasPrefix(source.Name, "policies/")
	}
	if !hasOntology {
		if files, err := datadir.ReadVYQLDir("ontology/concepts"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
		if files, err := datadir.ReadVYQLDir("ontology/threatkinds"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
	}
	if !hasPolicies {
		if files, err := datadir.ReadVYQLDir("policies"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
	}
	for _, source := range sources {
		out = append(out, parser.V2DefinitionSource{Name: source.Name, Source: string(source.Data)})
	}
	return out
}

func parseV2BindingSources(sources []datadir.Source) ([]parser.Decl, error) {
	selected := make(map[string]bool, len(sources))
	for _, source := range sources {
		selected[source.Name] = true
	}
	return parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForBindings(sources), func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
}

func loadSpec(tech string) bindingSpec {
	return specFromBindingSet(loadBindingSet(tech))
}

// specFromBindingSet builds a bindingSpec from an already-compiled v2 binding
// set. Split out of loadSpec so the dynamic per-package binding loader
// (packages.go) can reuse the exact same action-to-spec compilation.
func specFromBindingSet(d *parser.BindingSet) bindingSpec {
	s := bindingSpec{Name: d.Name, Technology: d.Name}
	if m, _ := d.Meta["match"].(string); m == "contains" {
		s.containsMatch = true
	}
	if bindingMetaBool(d.Meta, "cross_language") {
		s.crossLang = true
	}
	matchMode := "prefix"
	if s.containsMatch {
		matchMode = "contains"
	}
	srcByConcept := map[string]int{}
	for _, mp := range d.Mappings {
		scopePreds := scopePredicatesFromMapping(mp)
		switch mp.Kind {
		case "source":
			// a value-constrained source gets its own spec so the
			// val/nval filter is not shared with other patterns mapping to the same concept.
			if mp.NodeType != "" || len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(scopePreds) > 0 || len(mp.Packages) > 0 || mp.ArgCountSet || mp.Requirement != nil || mp.Fidelity != "" || mp.Confidence != "" {
				paths := []string{mp.Pattern}
				if mp.Pattern == "" {
					paths = nil
				}
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, NodeType: mp.NodeType, Match: matchMode,
					Paths: paths, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
					ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement,
					Fidelity: mp.Fidelity, Confidence: mp.Confidence})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, NodeType: mp.NodeType, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			if mp.Pattern != "" {
				s.Inputs[i].Paths = append(s.Inputs[i].Paths, mp.Pattern)
			}
		case "source_method":
			if mp.NodeType != "" || len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(scopePreds) > 0 || len(mp.Packages) > 0 || mp.ArgCountSet || mp.Requirement != nil || mp.Fidelity != "" || mp.Confidence != "" {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, NodeType: mp.NodeType, Match: matchMode,
					Methods: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
					ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement,
					Fidelity: mp.Fidelity, Confidence: mp.Confidence})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, NodeType: mp.NodeType, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Methods = append(s.Inputs[i].Methods, mp.Pattern)
		case "source_param":
			s.ParamSources = append(s.ParamSources, paramSourceSpec{Concept: mp.Concept, Packages: mp.Packages, Requirement: mp.Requirement, Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "type":
			// Constructor type facts are read by CtorTypesFor; they do not create
			// graph-labeling bindings.
		case "source_receiver":
			s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, NodeType: mp.NodeType, Match: matchMode,
				Methods: []string{mp.Pattern}, Receiver: true, Constraint: mp.Constraint,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement,
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "sink_method":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, ByMethod: true, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex, Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "sink_path":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex, Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "sink_receiver":
			// the tainted DATA is the receiver of a no-arg method; match the bare
			// method name and label the call node itself.
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, ByMethod: true, Receiver: true, Constraint: mp.Constraint, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "check":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "check_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "check_arg":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "check_method_arg":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "check_receiver_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, Receiver: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "sink_node":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_method_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "sink_method_node":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "issue":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "issue_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "issue_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "issue_method_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "presence_source", "presence_sink", "presence_check", "presence_issue":
			if mp.Flag != nil {
				fs := flagSpec{Concept: mp.Concept, NodeKind: mp.Flag.NodeKind, Scope: mp.Flag.Scope, Packages: mp.Packages, Requirement: mp.Requirement, Detail: bindingMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence}
				for _, pred := range mp.Flag.Predicates {
					fs.Predicates = append(fs.Predicates, newFlagPredicate(pred.Subject, pred.Property, pred.Op, pred.Values, pred.Exact, pred.Negative))
				}
				fs.PredicateOrder = flagPredicateOrder(fs.Predicates)
				for _, operand := range mp.Flag.Operands {
					var os flagOperandSpec
					for _, pred := range operand.Predicates {
						os.Predicates = append(os.Predicates, newFlagPredicate(pred.Subject, pred.Property, pred.Op, pred.Values, pred.Exact, pred.Negative))
					}
					os.PredicateOrder = flagPredicateOrder(os.Predicates)
					fs.Operands = append(fs.Operands, os)
				}
				s.Flags = append(s.Flags, fs)
			}
		case "filter_method":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, ByMethod: true, Global: mp.Constraint == "global", ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement})
		case "filter_path":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, Global: mp.Constraint == "global", ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement})
		case "advisory_guard_method", "advisory_guard_path", "advisory_sanitizer_method", "advisory_sanitizer_path":
			mode := "guard"
			if strings.Contains(mp.Kind, "sanitizer") {
				mode = "sanitizer"
			}
			s.AdvisoryNeutralizers = append(s.AdvisoryNeutralizers, advisoryNeutralizerSpec{Pattern: mp.Pattern, ByMethod: strings.HasSuffix(mp.Kind, "_method"),
				Mode: mode, About: mp.About, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				Detail: bindingMappingDetail(mp), ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement,
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		default:
			panic(fmt.Sprintf("unsupported compiled v2 binding action kind %q", mp.Kind))
		}
	}
	return s
}

func bindingMetaBool(meta map[string]any, key string) bool {
	switch v := meta[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

func bindingMappingDetail(mp parser.BindingAction) map[string]string {
	if !mp.Advisory && mp.About == "" && mp.Coverage == "" && len(mp.CoverageDetail) == 0 {
		return nil
	}
	out := map[string]string{}
	if mp.Advisory {
		out["advisory"] = "true"
	}
	if mp.About != "" {
		out["about"] = mp.About
	}
	if mp.Coverage != "" {
		out["coverage"] = mp.Coverage
	}
	for k, v := range mp.CoverageDetail {
		if v != "" {
			out["coverage."+k] = v
		}
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func scopePredicatesFromMapping(mp parser.BindingAction) []flagPredicate {
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
func (spec bindingSpec) sourceApplicator() bindings.Applicator {
	fidelity := "resolved"
	if spec.containsMatch {
		fidelity = "syntactic"
	}
	return bindings.Applicator{
		Name: spec.Name + ".input", Technology: spec.Technology, Specificity: 2,
		Fidelity: fidelity, Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			inIdx := buildSpecIndex(len(spec.Inputs), func(i int) (methods, paths []string, loose bool) {
				if spec.Inputs[i].NodeType != "" && len(spec.Inputs[i].Methods) == 0 && len(spec.Inputs[i].Paths) == 0 {
					return nil, nil, true
				}
				return spec.Inputs[i].Methods, spec.Inputs[i].Paths, spec.Inputs[i].Match == "contains"
			})
			// package gating is node-independent (pkgs is constant for this Apply), so
			// resolve it once per spec instead of re-running the costly evidence match per node.
			effects := make([]requirementEffect, len(spec.Inputs))
			valMatchesLower := make([][]string, len(spec.Inputs))
			valAbsentsLower := make([][]string, len(spec.Inputs))
			for i := range spec.Inputs {
				effects[i] = reqGate.effect(spec.Inputs[i].Packages, spec.Inputs[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Inputs[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Inputs[i].ValAbsents)
			}
			var out []bindings.Mapping
			valCache := &valueTokenCache{}
			needsScope := inputSpecsNeedScope(spec.Inputs)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeInputs := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, spec.crossLang, fn, inputApplicatorNodeTypes(spec.Technology, spec.Inputs)...)
					return
				}
				rangeTechNodesDirect(s, spec.Technology, spec.crossLang, fn, inputApplicatorNodeTypes(spec.Technology, spec.Inputs)...)
			}
			rangeInputs(func(n usg.Node) bool {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" && len(inIdx.loose) == 0 {
					return true
				}
				for _, ci := range inIdx.candidates(method, path) {
					in := spec.Inputs[ci]
					if !nodeTypeAllowed(in.NodeType, n.Type) {
						continue
					}
					if !effects[ci].Allowed {
						continue
					}
					matched := (path != "" && matchPath(path, in.Paths, in.Match)) ||
						(method != "" && containsStr(in.Methods, method)) ||
						(in.NodeType != "" && len(in.Paths) == 0 && len(in.Methods) == 0)
					if in.Receiver {
						matched = method != "" && containsStr(in.Methods, method) &&
							constraintAllows(in.Constraint, n.Prop("recv_type"))
					}
					if matched {
						if !callArgCountMatches(n, in.ArgCountSet, in.ArgCountMin, in.ArgCountMax) {
							continue
						}
						// value-constrained source: only a source when configured literal
						// tokens are present or absent as declared by the binding.
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valCondsDirectForNodeCached(valCache, n, valMatchesLower[ci], valAbsentsLower[ci]) {
							continue
						}
						if len(in.ScopePreds) > 0 && !scopePredicatesMatch(s, scopeIdx, in.ScopePreds, n, spec.Technology, spec.crossLang) {
							continue
						}
						// active-profile gating: a profile restricts which
						// source families are active for this profile.
						if activeSources == nil || activeSources[in.Concept] {
							spec := 0
							if len(in.Packages) > 0 {
								spec = 3 // package-specific source supersedes native/general
							}
							conf, detail := effects[ci].apply(mappingConfidence(in.Confidence, ""), nil)
							out = append(out, bindings.Mapping{NodeID: n.ID, Concept: in.Concept, Fidelity: mappingFidelity(in.Fidelity, fidelity), Confidence: conf, Specificity: spec, Detail: detail})
						}
						break
					}
				}
				return true
			})
			return out
		},
	}
}

func inputSpecsNeedScope(inputs []inputSpec) bool {
	for _, in := range inputs {
		if len(in.ScopePreds) > 0 {
			return true
		}
	}
	return false
}

func inputApplicatorNodeTypes(_ string, inputs []inputSpec) []string {
	seen := map[string]bool{"code.Call": true}
	out := append([]string{}, callablePropTypes...)
	for _, typ := range out {
		seen[typ] = true
	}
	for _, in := range inputs {
		if in.NodeType != "" && !seen[in.NodeType] {
			seen[in.NodeType] = true
			out = append(out, in.NodeType)
		}
	}
	return out
}

// sinkApplicator labels arg0 of matching calls with a PER-MAPPING fidelity:
//   - dotted-path match           → resolved (high)
//   - bare-method match, no `on`  → syntactic (medium — receiver type unknown)
//   - method match with `on T`:
//     recv_type == T              → resolved (high, type-verified)
//     recv_type unknown           → syntactic (medium, can't disprove)
//     recv_type != T              → SKIP (known wrong type — not a sink here)
//
// Collection-literal arg0s (vkind == Seq) are skipped.
func (spec bindingSpec) sinkApplicator() bindings.Applicator {
	attributeSinks := ontologyRoleConcepts(ontology.InternalConceptRoleAttributeSink)
	return bindings.Applicator{
		Name: spec.Name + ".sinks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			sinkIdx := buildSpecIndex(len(spec.Sinks), func(i int) (methods, paths []string, loose bool) {
				if spec.Sinks[i].ByMethod {
					return []string{spec.Sinks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Sinks[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Sinks))
			valMatchesLower := make([][]string, len(spec.Sinks))
			valAbsentsLower := make([][]string, len(spec.Sinks))
			for i := range spec.Sinks {
				effects[i] = reqGate.effect(spec.Sinks[i].Packages, spec.Sinks[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Sinks[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Sinks[i].ValAbsents)
			}
			var sinkStats []sinkSpecTiming
			var sinkProgress sinkApplicatorProgress
			if sinkTimingOn {
				sinkStats = make([]sinkSpecTiming, len(spec.Sinks))
				sinkProgress.Start = time.Now()
				sinkProgress.Last = sinkProgress.Start
			}
			var out []bindings.Mapping
			valCache := &valueTokenCache{}
			flowIdx := sharedFlowIndex(s)
			var collectionIdx collectionFlowIndex
			needsScope := sinkSpecsNeedScope(spec.Sinks)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeSinks := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, false, fn, "code.Call", "code.Attr", "code.BinOp")
					return
				}
				rangeTechNodesDirect(s, spec.Technology, false, fn, "code.Call", "code.Attr", "code.BinOp")
			}
			rangeSinks(func(n usg.Node) bool {
				if sinkTimingOn {
					sinkProgress.Nodes++
				}
				id := n.ID
				isAttr := n.Type == "code.Attr"
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				cand := sinkIdx.candidates(method, path)
				if sinkTimingOn {
					sinkProgress.Candidates += len(cand)
				}
				// Pick the MOST SPECIFIC matching sink (longest pattern) per concept, so
				// e.g. a qualified path wins over its short method for overlapping
				// mappings, while one call can still carry genuinely distinct concepts.
				bestByConcept := map[string]int{}
				for _, i := range cand {
					var statStart time.Time
					if sinkTimingOn {
						sinkStats[i].Candidates++
						statStart = time.Now()
					}
					sk := spec.Sinks[i]
					if !nodeTypeAllowed(sk.NodeType, n.Type) {
						continue
					}
					if !effects[i].Allowed {
						continue
					}
					if isAttr && !attributeSinks[sk.Concept] {
						continue
					}
					hit := sk.ByMethod && method == sk.Pattern ||
						!sk.ByMethod && ((sk.Exact && path == sk.Pattern) || (!sk.Exact && matchSinkPath(path, sk.Pattern)))
					if sinkTimingOn {
						sinkStats[i].MatchDuration += time.Since(statStart)
					}
					// value-matched sink: every `val` must be present and every `nval`
					// absent among the literal arg/option tokens (case-insensitive).
					if hit {
						if sinkTimingOn {
							statStart = time.Now()
						}
						if !valCondsForSinkCached(s, flowIdx, valCache, n, sk, valMatchesLower[i], valAbsentsLower[i]) {
							hit = false
						}
						if sinkTimingOn {
							sinkStats[i].ValueDuration += time.Since(statStart)
						}
					}
					if sinkTimingOn && hit {
						sinkStats[i].ValueHits++
					}
					if hit && !callArgCountMatches(n, sk.ArgCountSet, sk.ArgCountMin, sk.ArgCountMax) {
						hit = false
					}
					if sinkTimingOn && hit {
						sinkStats[i].ArgCountHits++
					}
					if hit && len(sk.ScopePreds) > 0 {
						if sinkTimingOn {
							statStart = time.Now()
						}
						if !scopePredicatesMatch(s, scopeIdx, sk.ScopePreds, n, spec.Technology, spec.crossLang) {
							hit = false
						}
						if sinkTimingOn {
							sinkStats[i].ScopeDuration += time.Since(statStart)
						}
					}
					if sinkTimingOn && hit {
						sinkStats[i].Hits++
					}
					if !hit {
						continue
					}
					// Most specific wins: longer pattern, then more value constraints
					// (a `val`-matched sink is more specific than the plain form).
					// Keyed by (concept,
					// ARG INDEX): the same concept can be injectable at MULTIPLE arg
					// positions of one call, so those must not collapse together.
					bkey := sinkBestKey(sk)
					if curIdx, ok := bestByConcept[bkey]; !ok {
						bestByConcept[bkey] = i
					} else if cur := spec.Sinks[curIdx]; len(sk.Pattern) > len(cur.Pattern) ||
						(len(sk.Pattern) == len(cur.Pattern) && len(sk.ValMatches) > len(cur.ValMatches)) {
						bestByConcept[bkey] = i
					}
				}
				for _, i := range cand {
					sk := spec.Sinks[i]
					best, ok := bestByConcept[sinkBestKey(sk)]
					if !ok || best != i {
						continue
					}
					// tiering: a package-scoped sink is the most specific match (tier 3) and
					// supersedes native path (resolved) and general method (syntactic) matches.
					pkgSpec := 0
					if len(sk.Packages) > 0 {
						pkgSpec = 3
					}
					if isAttr {
						if sk.ByMethod {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, bindings.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						} else {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, bindings.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "resolved"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						}
						continue
					}
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						if sk.Constraint != "" && recvType != "" && !constraintAllows(sk.Constraint, recvType) {
							continue
						}
						detail, conf := reviewDetail(sk.Concept, sk.Pattern)
						conf = mappingConfidence(sk.Confidence, conf)
						conf, detail = effects[i].apply(conf, detail)
						out = append(out, bindings.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
						if sinkTimingOn {
							sinkProgress.Mappings++
						}
						continue
					}
					fidelity := "resolved"
					if sk.ByMethod {
						fidelity = "syntactic"
					}
					if sk.Constraint != "" {
						switch {
						case recvType == "":
							// unknown type — can't disprove, keep syntactic
						case constraintAllows(sk.Constraint, recvType):
							fidelity = "resolved" // type-verified
						default:
							continue // known, conflicting type — not this sink
						}
					}
					// arg all (ArgIndex == -1): any tainted argument may be relevant.
					if sk.ArgIndex < 0 {
						for ai := 0; ; ai++ {
							arg := n.Prop("arg" + strconv.Itoa(ai))
							if arg == "" {
								break
							}
							target := arg
							foundCollectionTarget := false
							if sk.CollectionFirst {
								if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
									target = first
									foundCollectionTarget = true
								}
							}
							if a, ok, _ := s.GetNode(arg); ok {
								vkind := a.Prop("vkind")
								if sk.Collection && !foundCollectionTarget && vkind != "Seq" &&
									(!collectionArgKindAllowsFlow(vkind) || !collectionArgument(s, &collectionIdx, arg)) {
									continue
								}
								if !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
									continue
								}
							} else if sk.Collection {
								continue
							}
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, bindings.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						}
						continue
					}
					arg := n.Prop("arg" + strconv.Itoa(sk.ArgIndex))
					if arg == "" {
						continue
					}
					target := arg
					foundCollectionTarget := false
					if sk.CollectionFirst {
						if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
							target = first
							foundCollectionTarget = true
						}
					}
					if a, ok, _ := s.GetNode(arg); ok {
						vkind := a.Prop("vkind")
						if sk.Collection && !foundCollectionTarget && vkind != "Seq" &&
							(!collectionArgKindAllowsFlow(vkind) || !collectionArgument(s, &collectionIdx, arg)) {
							continue
						}
						if !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
							continue
						}
					} else if sk.Collection {
						continue
					}
					detail, conf := reviewDetail(sk.Concept, sk.Pattern)
					conf = mappingConfidence(sk.Confidence, conf)
					conf, detail = effects[i].apply(conf, detail)
					out = append(out, bindings.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
					if sinkTimingOn {
						sinkProgress.Mappings++
					}
				}
				if sinkTimingOn {
					now := time.Now()
					if now.Sub(sinkProgress.Last) >= 5*time.Second {
						fmt.Fprintf(os.Stderr, "[sink-progress] %-36s nodes=%-8d candidates=%-8d mappings=%-6d elapsed=%7.1fms\n",
							spec.Name+".sinks",
							sinkProgress.Nodes,
							sinkProgress.Candidates,
							sinkProgress.Mappings,
							float64(now.Sub(sinkProgress.Start))/1e6,
						)
						sinkProgress.Last = now
					}
				}
				return true
			})
			if sinkTimingOn {
				printSinkSpecTiming(spec.Name+".sinks", spec.Sinks, sinkStats)
			}
			return out
		},
	}
}

type sinkSpecTiming struct {
	Candidates    int
	ValueHits     int
	ArgCountHits  int
	Hits          int
	MatchDuration time.Duration
	ValueDuration time.Duration
	ScopeDuration time.Duration
}

type sinkApplicatorProgress struct {
	Start      time.Time
	Last       time.Time
	Nodes      int
	Candidates int
	Mappings   int
}

func printSinkSpecTiming(name string, sinks []sinkSpec, stats []sinkSpecTiming) {
	type row struct {
		idx  int
		stat sinkSpecTiming
	}
	rows := make([]row, 0, len(stats))
	for i, stat := range stats {
		if stat.Candidates == 0 && stat.Hits == 0 {
			continue
		}
		rows = append(rows, row{idx: i, stat: stat})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		aDur := a.stat.MatchDuration + a.stat.ValueDuration + a.stat.ScopeDuration
		bDur := b.stat.MatchDuration + b.stat.ValueDuration + b.stat.ScopeDuration
		if aDur != bDur {
			return aDur > bDur
		}
		if a.stat.Candidates != b.stat.Candidates {
			return a.stat.Candidates > b.stat.Candidates
		}
		return a.idx < b.idx
	})
	limit := 20
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, row := range rows[:limit] {
		sk := sinks[row.idx]
		mode := "path"
		if sk.ByMethod {
			mode = "method"
		}
		fmt.Fprintf(os.Stderr, "[sink] %-36s #%03d cand=%-8d val=%-6d argc=%-6d hits=%-6d match=%7.1fms value=%7.1fms scope=%7.1fms kind=%-6s concept=%s pattern=%s\n",
			name,
			row.idx,
			row.stat.Candidates,
			row.stat.ValueHits,
			row.stat.ArgCountHits,
			row.stat.Hits,
			float64(row.stat.MatchDuration)/1e6,
			float64(row.stat.ValueDuration)/1e6,
			float64(row.stat.ScopeDuration)/1e6,
			mode,
			sk.Concept,
			sk.Pattern,
		)
	}
}

func sinkBestKey(sk sinkSpec) string {
	return sk.Concept + "\x00" +
		strconv.Itoa(sk.ArgIndex) + "\x00" +
		strconv.FormatBool(sk.Collection) + "\x00" +
		strconv.FormatBool(sk.CollectionFirst) + "\x00" +
		strconv.Itoa(sk.CollectionIndex)
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
func (spec bindingSpec) checkApplicator() bindings.Applicator {
	return bindings.Applicator{
		Name: spec.Name + ".controls", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			ctrlIdx := buildSpecIndex(len(spec.Controls), func(i int) (methods, paths []string, loose bool) {
				if spec.Controls[i].ByMethod {
					return []string{spec.Controls[i].Pattern}, nil, false
				}
				return nil, []string{spec.Controls[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Controls))
			valMatchesLower := make([][]string, len(spec.Controls))
			valAbsentsLower := make([][]string, len(spec.Controls))
			for i := range spec.Controls {
				effects[i] = reqGate.effect(spec.Controls[i].Packages, spec.Controls[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Controls[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Controls[i].ValAbsents)
			}
			var out []bindings.Mapping
			valCache := &valueTokenCache{}
			var collectionIdx collectionFlowIndex
			needsScope := controlSpecsNeedScope(spec.Controls)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeControls := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, false, fn, "code.Call")
					return
				}
				rangeTechNodesDirect(s, spec.Technology, false, fn, "code.Call")
			}
			rangeControls(func(n usg.Node) bool {
				id := n.ID
				path, method := n.Prop("callee_path"), n.Prop("method")
				for _, ci := range ctrlIdx.candidates(method, path) {
					c := spec.Controls[ci]
					if !nodeTypeAllowed(c.NodeType, n.Type) {
						continue
					}
					if !effects[ci].Allowed {
						continue
					}
					// no break: a single call can be MULTIPLE controls, so attach every match.
					hit := c.ByMethod && method == c.Pattern ||
						!c.ByMethod && ((c.Exact && path == c.Pattern) || (!c.Exact && matchPath(path, []string{c.Pattern}, "prefix")))
					if hit && !callArgCountMatches(n, c.ArgCountSet, c.ArgCountMin, c.ArgCountMax) {
						hit = false
					}
					if hit && valCondsDirectForNodeCached(valCache, n, valMatchesLower[ci], valAbsentsLower[ci]) &&
						(len(c.ScopePreds) == 0 || scopePredicatesMatch(s, scopeIdx, c.ScopePreds, n, spec.Technology, spec.crossLang)) {
						nodeID := id
						if c.Receiver {
							nodeID = n.Prop("recv")
							if nodeID == "" {
								continue
							}
						}
						spec := 0
						if len(c.Packages) > 0 {
							spec = 3 // package-specific control supersedes native/general
						}
						conf, detail := effects[ci].apply(mappingConfidence(c.Confidence, ""), c.Detail)
						if c.ArgTarget {
							for _, target := range markTargets(s, &collectionIdx, n, c) {
								out = append(out, bindings.Mapping{NodeID: target, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
							}
							continue
						}
						out = append(out, bindings.Mapping{NodeID: nodeID, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
					}
				}
				return true
			})
			return out
		},
	}
}

// extTech maps a source file extension to its binding technology, so a binding
// only labels nodes from its own language (avoids cross-language FPs in polyglot
// repos — e.g. one language's binding matching another language's same-named call).
var extTech = map[string]string{
	".go": "go", ".py": "python",
	".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript", ".vue": "javascript",
	".rb": "ruby", ".java": "java", ".php": "php", ".phtml": "php", ".inc": "php", ".cs": "csharp",
	".c": "c", ".h": "c", ".xs": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
	".rs": "rust", ".sh": "bash", ".bash": "bash", ".scala": "scala", ".sc": "scala", ".lua": "lua", ".kt": "kotlin", ".kts": "kotlin", ".ps1": "powershell", ".psm1": "powershell", ".swift": "swift", ".pl": "perl", ".pm": "perl", ".cgi": "perl", ".sol": "solidity", ".m": "objc",
	".xml": "config", ".plist": "config", ".jelly": "config", ".jsp": "config", ".tag": "config", ".html": "config", ".pest": "config", ".sch": "config",
	".ex": "elixir", ".exs": "elixir",
	".dart":   "dart",
	".groovy": "groovy", ".gradle": "groovy",
}

// nodeTech returns the language technology of a node from its loc ("file.ext:line").
func nodeTech(loc string) string {
	if i := strings.LastIndexByte(loc, ':'); i >= 0 {
		loc = loc[:i]
	}
	if i := strings.LastIndexByte(loc, '.'); i >= 0 {
		return extTech[loc[i:]]
	}
	return ""
}

func nodeTechFromNode(n usg.Node) string {
	if t := contextNodeTech(n); t != "" {
		return t
	}
	return nodeTech(n.Prop("loc"))
}

func nodeTechFromNodeWithFileContext(n usg.Node, fileTech map[string]string) string {
	if t := contextNodeTech(n); t != "" {
		return t
	}
	if fileTech != nil {
		if t := fileTech[locFile(n.Prop("loc"))]; t != "" {
			return t
		}
	}
	return nodeTech(n.Prop("loc"))
}

func fileContextTechs(s usg.Store) map[string]string {
	out := map[string]string{}
	ids, _ := s.NodesOfType("code.Call")
	for _, id := range ids {
		n, ok, err := s.GetNode(id)
		if err != nil || !ok {
			continue
		}
		t := contextNodeTech(n)
		if t == "" {
			continue
		}
		if file := locFile(n.Prop("loc")); file != "" {
			out[file] = t
		}
	}
	return out
}

func contextNodeTech(n usg.Node) string {
	if n.Type != "code.Call" || !strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		return ""
	}
	text := n.Prop("str_args")
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
		if strings.HasPrefix(tok, "lang=") {
			return tok[len("lang="):]
		}
	}
	return ""
}

// rangeNodes streams every node to fn via the store's RangeNodes fast path (no full []Node copy)
// when available, else falls back to AllNodes. Binding passes iterate every node once; the slice
// copy was a multi-GB transient on large graphs.
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

func packageEvidence(s usg.Store, tech string, crossLang bool) map[string]bool {
	out := map[string]bool{}
	// only import/SBOM nodes carry package evidence — use the type index (O(result)) instead of
	// scanning every node, since this runs once per binding spec.
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		if !crossLang {
			if t := nodeTechFromNode(n); t != "" && t != tech {
				continue
			}
		}
		addPackageEvidenceName(out, n.Prop("module"))
		addPackageEvidenceName(out, n.Prop("symbol"))
		addPackageEvidenceName(out, n.Prop("package"))
		addPackageEvidenceName(out, n.Prop("root"))
	}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		if n, ok, _ := s.GetNode(id); ok {
			addPackageEvidenceName(out, n.Prop("name"))
		}
	}
	return out
}

func importEvidence(s usg.Store, tech string, crossLang bool) map[string]bool {
	out := map[string]bool{}
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		if !crossLang {
			if t := nodeTechFromNode(n); t != "" && t != tech {
				continue
			}
		}
		addPackageEvidenceName(out, n.Prop("module"))
		addPackageEvidenceName(out, n.Prop("symbol"))
		addPackageEvidenceName(out, n.Prop("package"))
		addPackageEvidenceName(out, n.Prop("root"))
	}
	return out
}

func addPackageEvidenceName(out map[string]bool, raw string) {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return
	}
	out[name] = true
	if root := sca.PackageRoot(name); root != "" {
		out[root] = true
	}
	for _, alias := range sca.ImportAliases(name) {
		out[alias] = true
	}
}

func packageAllowed(want []string, have map[string]bool) bool {
	return newPackageGate(have).allowed(want)
}

type packageGate struct {
	have     map[string]bool
	prefixes map[string]bool
	segments map[string]bool
	cache    map[string]bool
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

func (g *packageGate) allowed(want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if g.inEvidence(w) {
			return true
		}
	}
	return false
}

func (g *packageGate) inEvidence(want string) bool {
	want = sca.NormalizePackageName(want)
	if want == "" {
		return true
	}
	if hit, ok := g.cache[want]; ok {
		return hit
	}
	hit := g.matches(want)
	g.cache[want] = hit
	return hit
}

func (g *packageGate) matches(want string) bool {
	if g.have[want] {
		return true
	}
	if root := sca.PackageRoot(want); root != "" && g.have[root] {
		return true
	}
	if g.prefixes[want] {
		return true
	}
	for _, prefix := range packageGatePrefixes(want) {
		if g.have[prefix] {
			return true
		}
	}
	if !strings.ContainsAny(want, "/.") && g.segments[want] {
		return true
	}
	for _, segment := range packageGatePathSegments(want) {
		if g.have[segment] {
			return true
		}
	}
	return false
}

func packageInEvidence(want string, have map[string]bool) bool {
	return newPackageGate(have).inEvidence(want)
}

type requirementGate struct {
	packages   *packageGate
	imports    *packageGate
	versions   map[string][]string
	languages  map[string]bool
	project    map[string]bool
	files      map[string]bool
	filesBuilt bool
	store      usg.Store
	tech       string
	crossLang  bool
}

type requirementEffect struct {
	Allowed             bool
	State               string
	ConfidenceDowngrade int
	Detail              map[string]string
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

func (g *requirementGate) importGate() *packageGate {
	if g.imports == nil {
		g.imports = newPackageGate(importEvidence(g.store, g.tech, g.crossLang))
	}
	return g.imports
}

func (g *requirementGate) languageEvidence() map[string]bool {
	if g.languages != nil {
		return g.languages
	}
	langs := map[string]bool{}
	if g.tech != "" {
		langs[g.tech] = true
	}
	impIDs, _ := g.store.NodesOfType("code.Import")
	for _, id := range impIDs {
		if n, ok, _ := g.store.GetNode(id); ok {
			if t := nodeTechFromNode(n); t != "" {
				langs[t] = true
			}
		}
	}
	g.languages = langs
	return langs
}

func (g *requirementGate) versionEvidence() map[string][]string {
	if g.versions == nil {
		g.versions = dependencyVersionEvidence(g.store)
	}
	return g.versions
}

func (g *requirementGate) projectEvidence() map[string]bool {
	if g.project == nil {
		g.project = projectFactEvidence(g.store)
	}
	return g.project
}

func (g *requirementGate) allowed(packages []string, req *parser.BindingRequirement) bool {
	return g.effect(packages, req).Allowed
}

func (g *requirementGate) effect(packages []string, req *parser.BindingRequirement) requirementEffect {
	if req == nil {
		if g.packages.allowed(packages) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
	return g.evalEffect(*req)
}

func (g *requirementGate) eval(req parser.BindingRequirement) bool {
	return g.evalEffect(req).Allowed
}

func (g *requirementGate) evalEffect(req parser.BindingRequirement) requirementEffect {
	switch req.Op {
	case "":
		return requirementEffect{Allowed: true, State: requirementStateSatisfied}
	case "dependency", "framework":
		if req.Range != "" {
			return g.dependencyVersionEffect(req.Value, req.Range)
		}
		if g.packages.inEvidence(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "import":
		if g.importGate().inEvidence(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "content":
		// A code-literal presence gate: the binding only applies when this literal occurs
		// somewhere in the program. Absent ⇒ the binding's match (which requires the literal)
		// is impossible, so it is gated off — letting a CVE pattern binding skip projects it
		// does not target without scanning their nodes. Matched case-insensitively against the
		// whole-program text corpus (a superset of all node text), consistent with how the
		// predicate value itself is matched.
		//
		// This is a pure performance gate (running an un-gated binding just matches nothing), so it
		// is only evaluated above a node-count threshold: building the corpus is not worth it on
		// small/normal repos, where the binding scan is already cheap. Below the threshold the gate
		// is treated as satisfied and the binding runs unchanged.
		if req.Value == "" || storeNodeCount(g.store) < presenceGateMinNodes ||
			sharedContentContains(g.store, lowerString(req.Value)) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "language":
		langs := g.languageEvidence()
		if langs[lowerString(req.Value)] {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateUnknown
		if len(langs) > 0 {
			state = requirementStateConflicting
		}
		return requirementEffect{Allowed: false, State: state}
	case "file":
		g.ensureFiles()
		if g.files[filepath.ToSlash(req.Value)] {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateMissing
		if len(g.files) == 0 {
			state = requirementStateUnknown
		}
		return requirementEffect{Allowed: false, State: state}
	case "schema":
		name, version, _ := strings.Cut(req.Value, "\x00")
		if name == "nir" && (version == "" || version == "2.0") {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateMissing
		if name == "nir" {
			state = requirementStateConflicting
		}
		return requirementEffect{Allowed: false, State: state}
	case "project.has":
		if g.hasProjectFact(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "all":
		out := requirementEffect{Allowed: true, State: requirementStateSatisfied}
		for _, child := range req.Args {
			eff := g.evalEffect(child)
			if !eff.Allowed {
				return eff
			}
			out = mergeRequirementEffects(out, eff)
		}
		return out
	case "any":
		var best requirementEffect
		found := false
		for _, child := range req.Args {
			if eff := g.evalEffect(child); eff.Allowed {
				if !found || eff.ConfidenceDowngrade < best.ConfidenceDowngrade {
					best = eff
					found = true
				}
			} else if !found {
				best = preferRequirementFailure(best, eff)
			}
		}
		if found {
			return best
		}
		if best.State == "" {
			best.State = requirementStateMissing
		}
		return best
	case "not":
		if len(req.Args) != 1 {
			return requirementEffect{Allowed: false, State: requirementStateConflicting}
		}
		child := g.evalEffect(req.Args[0])
		switch child.State {
		case requirementStateMissing, requirementStateConflicting:
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		case requirementStateUnknown:
			return requirementEffect{Allowed: false, State: requirementStateUnknown}
		default:
			return requirementEffect{Allowed: !child.Allowed, State: requirementStateSatisfied}
		}
	case "soft":
		if len(req.Args) != 1 {
			return requirementEffect{Allowed: false, State: requirementStateConflicting}
		}
		child := g.evalEffect(req.Args[0])
		if child.Allowed {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := child.State
		if state == "" {
			state = requirementStateMissing
		}
		return requirementEffect{
			Allowed:             true,
			State:               state,
			ConfidenceDowngrade: 1,
			Detail: map[string]string{
				"requirement_state": state,
				"requirement":       "soft evidence " + state,
			},
		}
	default:
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
}

func mergeRequirementEffects(a, b requirementEffect) requirementEffect {
	out := a
	out.State = mergeRequirementState(out.State, b.State)
	if b.ConfidenceDowngrade > out.ConfidenceDowngrade {
		out.ConfidenceDowngrade = b.ConfidenceDowngrade
	}
	out.Detail = mergeMappingDetail(out.Detail, b.Detail)
	return out
}

func mergeRequirementState(a, b string) string {
	if a == "" || a == requirementStateSatisfied {
		if b == "" {
			return a
		}
		return b
	}
	if b == "" || b == requirementStateSatisfied {
		return a
	}
	if requirementStateRank(b) > requirementStateRank(a) {
		return b
	}
	return a
}

func preferRequirementFailure(a, b requirementEffect) requirementEffect {
	if a.State == "" || requirementStateRank(b.State) > requirementStateRank(a.State) {
		return b
	}
	return a
}

func requirementStateRank(state string) int {
	switch state {
	case requirementStateConflicting:
		return 3
	case requirementStateUnknown:
		return 2
	case requirementStateMissing:
		return 1
	default:
		return 0
	}
}

func (e requirementEffect) apply(conf string, detail map[string]string) (string, map[string]string) {
	if e.ConfidenceDowngrade > 0 {
		conf = downgradeConfidence(conf, e.ConfidenceDowngrade)
	}
	return conf, mergeMappingDetail(detail, e.Detail)
}

func downgradeConfidence(conf string, steps int) string {
	idx := resultpolicy.MaxConfidenceRank()
	if conf != "" {
		if rank := resultpolicy.ConfidenceRank(conf); rank > 0 {
			idx = rank
		}
	}
	idx -= steps
	if idx < 1 {
		idx = 1
	}
	return resultpolicy.ConfidenceName(idx)
}

func mappingFidelity(authored, fallback string) string {
	if authored != "" {
		return authored
	}
	return fallback
}

func mappingConfidence(authored, derived string) string {
	if authored == "" {
		return derived
	}
	if derived == "" {
		return authored
	}
	if confidenceRank(authored) <= confidenceRank(derived) {
		return authored
	}
	return derived
}

func confidenceRank(conf string) int {
	if rank := resultpolicy.ConfidenceRank(conf); rank > 0 {
		return rank
	}
	return resultpolicy.MaxConfidenceRank()
}

func dependencyVersionEvidence(s usg.Store) map[string][]string {
	out := map[string][]string{}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		version := strings.TrimSpace(n.Prop("version"))
		if version == "" {
			continue
		}
		addPackageVersionEvidence(out, n.Prop("name"), version)
	}
	return out
}

func projectFactEvidence(s usg.Store) map[string]bool {
	out := map[string]bool{}
	ids, _ := s.NodesOfType("project.Fact")
	for _, id := range ids {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		addProjectFactEvidence(out, n.Prop("key"))
		addProjectFactEvidence(out, n.Prop("name"))
		addProjectFactEvidence(out, n.Prop("fact"))
		family := strings.TrimSpace(n.Prop("family"))
		name := strings.TrimSpace(n.Prop("value"))
		if name == "" {
			name = strings.TrimSpace(n.Prop("name"))
		}
		if family != "" && name != "" {
			addProjectFactEvidence(out, family+":"+name)
		}
	}
	return out
}

func addProjectFactEvidence(out map[string]bool, raw string) {
	key := normalizeProjectFactKey(raw)
	if key != "" {
		out[key] = true
	}
}

func normalizeProjectFactKey(raw string) string {
	return lowerString(strings.TrimSpace(filepath.ToSlash(raw)))
}

func (g *requirementGate) hasProjectFact(raw string) bool {
	key := normalizeProjectFactKey(raw)
	if key == "" {
		return false
	}
	if g.projectEvidence()[key] {
		return true
	}
	family, value, ok := strings.Cut(key, ":")
	if ok {
		switch family {
		case "dependency", "package", "dep", "npm", "pypi", "go", "maven", "nuget", "gem", "cargo":
			return g.packages.inEvidence(value)
		case "import":
			return g.importGate().inEvidence(value)
		case "framework":
			return g.packages.inEvidence(value)
		case "language", "lang":
			return g.languageEvidence()[value]
		case "file":
			g.ensureFiles()
			return g.files[filepath.ToSlash(value)]
		}
	}
	return false
}

func addPackageVersionEvidence(out map[string][]string, raw, version string) {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return
	}
	add := func(key string) {
		if key != "" {
			out[key] = append(out[key], version)
		}
	}
	add(name)
	add(sca.PackageRoot(name))
	for _, alias := range sca.ImportAliases(name) {
		add(alias)
	}
}

func (g *requirementGate) dependencyVersionSatisfies(pkg, expr string) bool {
	return g.dependencyVersionEffect(pkg, expr).Allowed
}

func (g *requirementGate) dependencyVersionEffect(pkg, expr string) requirementEffect {
	hasPackage := g.packages.inEvidence(pkg)
	hasVersion := false
	versions := g.versionEvidence()
	for _, key := range packageEvidenceKeys(pkg) {
		for _, version := range versions[key] {
			hasVersion = true
			if versionSatisfiesRange(version, expr) {
				return requirementEffect{Allowed: true, State: requirementStateSatisfied}
			}
		}
	}
	switch {
	case hasVersion:
		return requirementEffect{Allowed: false, State: requirementStateConflicting}
	case hasPackage:
		return requirementEffect{Allowed: false, State: requirementStateUnknown}
	default:
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
}

func packageEvidenceKeys(raw string) []string {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(key string) {
		if key != "" && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	add(name)
	add(sca.PackageRoot(name))
	for _, alias := range sca.ImportAliases(name) {
		add(alias)
	}
	return out
}

func versionSatisfiesRange(version, expr string) bool {
	for _, part := range strings.Fields(expr) {
		if !versionSatisfiesComparator(version, part) {
			return false
		}
	}
	return strings.TrimSpace(expr) != ""
}

func versionSatisfiesComparator(version, cmp string) bool {
	op := "="
	value := cmp
	for _, prefix := range []string{">=", "<=", ">", "<", "==", "="} {
		if strings.HasPrefix(cmp, prefix) {
			op = prefix
			value = strings.TrimSpace(strings.TrimPrefix(cmp, prefix))
			break
		}
	}
	order, ok := compareVersions(version, value)
	if !ok {
		return false
	}
	switch op {
	case "=", "==":
		return order == 0
	case ">=":
		return order >= 0
	case "<=":
		return order <= 0
	case ">":
		return order > 0
	case "<":
		return order < 0
	default:
		return false
	}
}

func compareVersions(a, b string) (int, bool) {
	av, okA := parseVersionParts(a)
	bv, okB := parseVersionParts(b)
	if !okA || !okB {
		return 0, false
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(av) {
			ai = av[i]
		}
		if i < len(bv) {
			bi = bv[i]
		}
		if ai < bi {
			return -1, true
		}
		if ai > bi {
			return 1, true
		}
	}
	return 0, true
}

func parseVersionParts(v string) ([]int, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	raw := strings.Split(v, ".")
	out := make([]int, 0, len(raw))
	for _, part := range raw {
		if part == "" {
			return nil, false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func (g *requirementGate) ensureFiles() {
	if g.filesBuilt {
		return
	}
	g.filesBuilt = true
	g.files = map[string]bool{}
	rangeNodes(g.store, func(n usg.Node) bool {
		if !g.crossLang {
			if t := nodeTechFromNode(n); t != "" && t != g.tech {
				return true
			}
		}
		if file := locFile(n.Prop("loc")); file != "" {
			g.files[filepath.ToSlash(file)] = true
		}
		return true
	})
}

func packageGatePrefixes(name string) []string {
	var out []string
	for _, sep := range []byte{'.', '/'} {
		for i := strings.IndexByte(name, sep); i >= 0; {
			prefix := name[:i]
			if prefix != "" {
				out = append(out, prefix)
			}
			next := strings.IndexByte(name[i+1:], sep)
			if next < 0 {
				break
			}
			i += 1 + next
		}
	}
	return out
}

func packageGatePathSegments(name string) []string {
	if !strings.Contains(name, "/") {
		return nil
	}
	parts := strings.Split(name, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" && !strings.ContainsAny(part, "/.") {
			out = append(out, part)
		}
	}
	return out
}

// presenceApplicator labels nodes with presence/review concepts emitted by v2
// presenceNode bindings.
func (spec bindingSpec) presenceApplicator() bindings.Applicator {
	return bindings.Applicator{
		Name: spec.Name + ".flags", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			flagReqs := make([]*parser.BindingRequirement, 0, len(spec.Flags))
			for i := range spec.Flags {
				flagReqs = append(flagReqs, spec.Flags[i].Requirement)
			}
			prewarmContentRequirements(s, flagReqs...)
			effects := make([]requirementEffect, len(spec.Flags))
			anyAllowed := false
			for i := range spec.Flags {
				effects[i] = reqGate.effect(spec.Flags[i].Packages, spec.Flags[i].Requirement)
				if effects[i].Allowed {
					anyAllowed = true
				}
			}
			if !anyAllowed {
				return nil
			}
			fileTech := sharedFileContextTechs(s)
			flagIdx := buildSpecIndex(len(spec.Flags), func(i int) (methods, paths []string, loose bool) {
				if spec.Flags[i].Scope != "" {
					return nil, []string{"analysis." + lowerString(spec.Flags[i].Scope) + ".context"}, false
				}
				for _, pred := range spec.Flags[i].Predicates {
					if pred.Subject == "flow_to" {
						continue
					}
					switch pred.Property {
					case "path":
						paths = append(paths, pred.Values...)
					case "method":
						methods = append(methods, pred.Values...)
					}
				}
				return methods, paths, len(methods) == 0 && len(paths) == 0
			})
			var out []bindings.Mapping
			needsFullIndex := flagSpecsNeedFullIndex(spec.Flags)
			matchIdx := &flagMatchIndex{}
			if needsFullIndex {
				matchIdx = sharedFlagIndex(s)
			}
			contextOnlyPreds := make([]flagPredicate, len(spec.Flags))
			contextOnlyOK := make([]bool, len(spec.Flags))
			opPreds := make([]flagPredicate, len(spec.Flags))
			opOK := make([]bool, len(spec.Flags))
			for i := range spec.Flags {
				contextOnlyPreds[i], contextOnlyOK[i] = flagContextOnlyPredicate(spec.Flags[i], spec.Technology)
				opPreds[i], opOK[i] = flagPositiveOpPredicate(spec.Flags[i])
			}
			var flagStats []presenceFlagTiming
			if flagTimingOn {
				flagStats = make([]presenceFlagTiming, len(spec.Flags))
			}
			nodeTypes := flagApplicatorNodeTypes(spec.Flags, spec.crossLang)
			for _, nodeType := range nodeTypes {
				rangeFlagNodes := func(fn func(usg.Node) bool) {
					if needsFullIndex {
						matchIdx.rangeNodesOfTechType(s, spec.Technology, nodeType, spec.crossLang, fn)
						return
					}
					rangeTechNodesDirect(s, spec.Technology, spec.crossLang, fn, nodeType)
				}
				rangeFlagNodes(func(n usg.Node) bool {
					var contextOnlyLower string
					contextOnlyLowerSet := false
					for _, i := range flagIdx.candidates(n.Prop("method"), n.Prop("callee_path")) {
						if !effects[i].Allowed {
							continue
						}
						fl := spec.Flags[i]
						if !flagNodeKindAllows(fl, n) {
							continue
						}
						if opOK[i] && !flagValuePredicate(opPreds[i], n.Prop("op")) {
							continue
						}
						if contextOnlyOK[i] {
							text := n.Prop("str_args")
							if !contextOnlyLowerSet {
								contextOnlyLower = lowerString(text)
								contextOnlyLowerSet = true
							}
							if !flagContextOnlyPredicateMaybePresent(contextOnlyPreds[i], text, contextOnlyLower) {
								continue
							}
						}
						var matched bool
						if flagTimingOn {
							start := time.Now()
							matched = flagMatchesNode(s, matchIdx, fl, n, spec.Technology, spec.crossLang, fileTech)
							elapsed := time.Since(start)
							flagStats[i].Calls++
							flagStats[i].Duration += elapsed
							if matched {
								flagStats[i].Hits++
							}
						} else {
							matched = flagMatchesNode(s, matchIdx, fl, n, spec.Technology, spec.crossLang, fileTech)
						}
						if !matched {
							continue
						}
						detail, conf := reviewDetail(fl.Concept, flagPattern(fl))
						detail = mergeMappingDetail(detail, fl.Detail)
						conf = mappingConfidence(fl.Confidence, conf)
						conf, detail = effects[i].apply(conf, detail)
						specificity := 0
						if len(fl.Packages) > 0 {
							specificity = 3
						}
						out = append(out, bindings.Mapping{NodeID: n.ID, Concept: fl.Concept, Fidelity: mappingFidelity(fl.Fidelity, "resolved"), Confidence: conf, Specificity: specificity, Detail: detail})
					}
					return true
				})
			}
			if flagTimingOn {
				printPresenceFlagTiming(spec.Name+".flags", spec.Flags, flagStats)
			}
			return out
		},
	}
}

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

type presenceFlagTiming struct {
	Calls    int
	Hits     int
	Duration time.Duration
}

func printPresenceFlagTiming(name string, flags []flagSpec, stats []presenceFlagTiming) {
	type row struct {
		idx  int
		stat presenceFlagTiming
	}
	rows := make([]row, 0, len(stats))
	for i, stat := range stats {
		if stat.Calls == 0 && stat.Duration == 0 {
			continue
		}
		rows = append(rows, row{idx: i, stat: stat})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].stat.Duration == rows[j].stat.Duration {
			return rows[i].stat.Calls > rows[j].stat.Calls
		}
		return rows[i].stat.Duration > rows[j].stat.Duration
	})
	limit := 12
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, row := range rows[:limit] {
		fl := flags[row.idx]
		fmt.Fprintf(os.Stderr, "[flag] %-36s #%03d %7.1fms calls=%-7d hits=%-4d scope=%-8s kind=%-8s concept=%s pattern=%s\n",
			name,
			row.idx,
			float64(row.stat.Duration)/1e6,
			row.stat.Calls,
			row.stat.Hits,
			fl.Scope,
			fl.NodeKind,
			fl.Concept,
			flagPattern(fl),
		)
	}
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
			return n.Type == "code."+strings.Title(fl.NodeKind)
		}
	}
}

func flagApplicatorNodeTypes(flags []flagSpec, crossLang bool) []string {
	base := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Name"}
	all := func() []string {
		out := append([]string{}, base...)
		if crossLang {
			out = append(out, "sbom.PackageVersion")
		}
		return out
	}
	if len(flags) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(typ string) {
		if typ == "" || seen[typ] {
			return
		}
		seen[typ] = true
		out = append(out, typ)
	}
	for _, fl := range flags {
		switch lowerString(fl.Scope) {
		case "function", "module", "class":
			add("code.Call")
			continue
		}
		switch lowerString(fl.NodeKind) {
		case "", "any":
			return all()
		case "call":
			add("code.Call")
		case "attr", "attribute":
			add("code.Attr")
		case "seq", "collection", "object":
			add("code.Seq")
		case "subscript", "index":
			add("code.Subscript")
		case "binop", "binary":
			add("code.BinOp")
		case "unary":
			add("code.Unary")
		case "name", "identifier":
			add("code.Name")
		default:
			add("code." + strings.Title(fl.NodeKind))
		}
	}
	if crossLang {
		add("sbom.PackageVersion")
	}
	return out
}

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

func flagOperandsMatch(specs []flagOperandSpec, operands [][]usg.Node) bool {
	used := make([]bool, len(operands))
	var matchOperand func(int) bool
	matchOperand = func(i int) bool {
		if i == len(specs) {
			return true
		}
		for oi, opNodes := range operands {
			if used[oi] {
				continue
			}
			if flagOperandMatches(specs[i], opNodes) {
				used[oi] = true
				if matchOperand(i + 1) {
					return true
				}
				used[oi] = false
			}
		}
		return false
	}
	return matchOperand(0)
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
		argID := n.Prop("arg" + strconv.Itoa(ai))
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

func allBool(values []bool) bool {
	for _, v := range values {
		if !v {
			return false
		}
	}
	return true
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
		argID := n.Prop("arg" + strconv.Itoa(ai))
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

func flagOperandMatches(spec flagOperandSpec, nodes []usg.Node) bool {
	if len(spec.PredicateOrder) > 0 {
		for _, i := range spec.PredicateOrder {
			if !flagOperandPredicateMatches(spec.Predicates[i], nodes) {
				return false
			}
		}
		return true
	}
	for _, pred := range spec.Predicates {
		if !flagOperandPredicateMatches(pred, nodes) {
			return false
		}
	}
	return true
}

func flagOperandPredicateMatches(pred flagPredicate, nodes []usg.Node) bool {
	for _, n := range nodes {
		if flagPredicateMatchesNodeOnly(pred, n) {
			return true
		}
	}
	return false
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

func flagContextOnlyPredicateMaybePresent(pred flagPredicate, text, lowerText string) bool {
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
			return valuePredicateLowerValuesWithLowerText(op, pred.Values, pred.lowerValues(), text, lowerText)
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
		if binopPredicateMatches(s, idx, pred.Op, values, cand) {
			return true
		}
		return false
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
		if subscriptPredicateMatches(pred.Op, values, cand) {
			return true
		}
		return false
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
		if contextTokenValuePredicate(pred.Op, pred.Values, callArgContextTokensScoped(s, idx, cand, tech, crossLang)) {
			return true
		}
		return false
	})
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

func callArgContextTokensScoped(s usg.Store, idx *flagMatchIndex, n usg.Node, tech string, crossLang bool) string {
	idx.ensure(s)
	cacheKey := strings.Join([]string{n.ID, tech, strconv.FormatBool(crossLang)}, "\x1f")
	if cached, ok := idx.callArgText.Load(cacheKey); ok {
		return cached.(string)
	}
	tokens := callArgContextTokens(n)
	path := n.Prop("callee_path")
	method := n.Prop("method")
	if path == "" && method == "" {
		idx.callArgText.Store(cacheKey, tokens)
		return tokens
	}
	var out []string
	if tokens != "" {
		out = append(out, strings.Split(tokens, "\x00")...)
	}
	seen := map[string]bool{}
	add := func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		if path != "" {
			tok := "call_arg:" + path + ":" + text
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
		if method != "" {
			tok := "call_arg_method:" + method + ":" + text
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
	}
	addNode := func(node usg.Node) {
		add(node.Prop("str_args"))
		for _, part := range strings.Split(nodeSearchText(node), "\x00") {
			add(part)
		}
		add(node.Prop("name"))
		add(node.Prop("path"))
		add(node.ID)
	}
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
	result := strings.Join(out, "\x00")
	idx.callArgText.Store(cacheKey, result)
	return result
}

func callArgSourceNodeType(typ string) bool {
	switch typ {
	case "code.Format", "code.Const", "code.Name", "code.Attr", "code.Seq", "code.Call":
		return true
	default:
		return false
	}
}

func (idx *flagMatchIndex) scopedCallArgCandidate(cand, anchor usg.Node, tech string, crossLang bool) bool {
	scope := idx.normalizedScope(anchor)
	candScope := idx.normalizedScope(cand)
	if scope != "" && candScope != "" && !sameOrNestedNormalizedScope(candScope, scope) {
		return false
	}
	if prefix := locFile(anchor.Prop("loc")); prefix != "" && locFile(cand.Prop("loc")) != prefix {
		return false
	}
	if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
		return false
	}
	return true
}

func callArgContextTokens(n usg.Node) string {
	path := n.Prop("callee_path")
	method := n.Prop("method")
	if path == "" && method == "" {
		return ""
	}
	var out []string
	for _, arg := range strings.Split(n.Prop("str_args"), "\x00") {
		if arg == "" {
			continue
		}
		if path != "" {
			out = append(out, "call_arg:"+path+":"+arg)
		}
		if method != "" {
			out = append(out, "call_arg_method:"+method+":"+arg)
		}
	}
	return strings.Join(out, "\x00")
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

func unscopedNodeBelongsToScopedContext(candidate, anchor usg.Node) bool {
	if candidate.Type != "code.Param" {
		return false
	}
	cFile, cLine := splitLocFileLine(candidate.Prop("loc"))
	aFile, aLine := splitLocFileLine(anchor.Prop("loc"))
	return cFile != "" && cFile == aFile && cLine != 0 && cLine == aLine
}

func nodeLexicalScope(n usg.Node) string {
	if n.Scope != "" {
		return n.Scope
	}
	return n.Prop("region")
}

func sameOrNestedScope(candidate, anchor string) bool {
	candidate = scopeWithoutOrder(candidate)
	anchor = scopeWithoutOrder(anchor)
	return sameOrNestedNormalizedScope(candidate, anchor)
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

// flagContextTokenValuePredicateWithLowerText is flagContextTokenValuePredicate with a
// caller-supplied lowercased text, so a hot loop can reuse an epoch-cached
// idx.lowerTextValue(text) instead of re-lowercasing the node's str_args every call. It
// is byte-for-byte equivalent to the uncached form (which passes lowerString(text)).
func flagContextTokenValuePredicateWithLowerText(pred flagPredicate, text, lowerText string) bool {
	return contextTokenValuePredicateLowerValuesWithLowerText(pred.Op, pred.Values, pred.lowerValues(), text, lowerText)
}

func flagContextTokenValuePredicateCached(idx *flagMatchIndex, pred flagPredicate, text string) bool {
	return contextTokenValuePredicateLowerValuesWithCache(pred.Op, pred.Values, pred.lowerValues(), text, idx.lowerTextValue(text), idx.contextFacts(text))
}

func contextTokenValuePredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	return contextTokenValuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerString(text))
}

func contextTokenValuePredicateLowerValuesWithCache(op string, values, valuesLower []string, text, lowerText string, facts *contextTokenFacts) bool {
	if facts == nil {
		return contextTokenValuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText)
	}
	if op == "exists" {
		return contextTokenExistsPredicateCached(values, text, facts)
	}
	if op == "equals" || op == "equals_any" {
		if contextTokenEqualsPredicateCached(op, values, text, facts) {
			return true
		}
	}
	if op == "contains" || op == "" || op == "contains_any" {
		if valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText) {
			return true
		}
		return contextTokenContainsPredicateCached(op, values, valuesLower, facts)
	}
	if op == "starts_with" || op == "ends_with" {
		if contextTokenBoundaryPredicateCached(op, values, valuesLower, facts) {
			return true
		}
	}
	return valuePredicateLowerValuesWithLowerText(op, values, valuesLower, text, lowerText)
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

func contextTokenContainsPredicate(op string, values []string, text string) bool {
	return contextTokenContainsPredicateLowerValues(op, values, lowerStrings(values), text)
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
				for _, got := range facts.lowerByPrefix[prefix] {
					if valContainsLowerNeedle(got, wantLower) {
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
	match := strings.HasPrefix
	if op == "ends_with" {
		match = strings.HasSuffix
	}
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
			return match(lowerString(got), wantLower)
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
			if match(lowerString(got), wantLower) {
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
	match := strings.HasPrefix
	if op == "ends_with" {
		match = strings.HasSuffix
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
		for _, got := range facts.lowerByPrefix[prefix] {
			if match(got, wantLower) {
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

func contextTokenContains(prefix, got, want string) bool {
	return contextTokenContainsLower(prefix, got, want, lowerString(want))
}

func contextTokenContainsLower(prefix, got, want, wantLower string) bool {
	if prefix == "class_base:" {
		return classBaseTokenMatches(got, want)
	}
	return valContainsLowerNeedle(lowerString(got), wantLower)
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

func flagValuePredicate(pred flagPredicate, text string) bool {
	return valuePredicateLowerValues(pred.Op, pred.Values, pred.lowerValues(), text)
}

func valuePredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	switch op {
	case "exists":
		if len(values) == 0 {
			return text != ""
		}
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasPrefix)
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
		lowerText := lowerString(text)
		for _, v := range valuesLower {
			if valContainsLowerNeedle(lowerText, v) {
				return true
			}
		}
		return false
	case "starts_with":
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasPrefix)
	case "ends_with":
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasSuffix)
	default:
		return valCondsLowerNeedles(lowerString(text), valuesLower, nil)
	}
}

func valuePredicateLowerValuesWithLowerText(op string, values, valuesLower []string, text, lowerText string) bool {
	switch op {
	case "exists":
		if len(values) == 0 {
			return text != ""
		}
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasPrefix)
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
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasPrefix)
	case "ends_with":
		return textTokenBoundaryPredicate(valuesLower, text, strings.HasSuffix)
	default:
		return valCondsLowerNeedles(lowerText, valuesLower, nil)
	}
}

func textTokenBoundaryPredicate(valuesLower []string, text string, match func(string, string) bool) bool {
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
		lowerTok := lowerString(tok)
		for _, value := range valuesLower {
			if match(lowerTok, value) {
				return true
			}
		}
	}
	return false
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
func (spec bindingSpec) matchPresenceApplicator() bindings.Applicator {
	return bindings.Applicator{
		Name: spec.Name + ".marks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			// Most presence events are calls, but some are bare member accesses with
			// no call, so scan Attr nodes too.
			var out []bindings.Mapping
			// cross-language binding applicators label nodes in source files of
			// every language, so the per-language tech filter doesn't apply.
			crossLang := spec.crossLang
			pkgs := packageEvidence(s, spec.Technology, crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			markIdx := buildSpecIndex(len(spec.Marks), func(i int) (methods, paths []string, loose bool) {
				if spec.Marks[i].NodeType != "" && spec.Marks[i].Pattern == "" {
					return nil, nil, true
				}
				if spec.Marks[i].ByMethod {
					return []string{spec.Marks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Marks[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Marks))
			valMatchesLower := make([][]string, len(spec.Marks))
			valAbsentsLower := make([][]string, len(spec.Marks))
			for i := range spec.Marks {
				effects[i] = reqGate.effect(spec.Marks[i].Packages, spec.Marks[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Marks[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Marks[i].ValAbsents)
			}
			nodeTypes := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Literal", "code.Const", "code.Function", "code.Class", "code.Import"}
			if crossLang {
				nodeTypes = append(nodeTypes, "sbom.PackageVersion")
			}
			var collectionIdx collectionFlowIndex
			needsScope := controlSpecsNeedScope(spec.Marks)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			valCache := &valueTokenCache{}
			rangeMarks := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, crossLang, fn, nodeTypes...)
					return
				}
				rangeTechNodesDirect(s, spec.Technology, crossLang, fn, nodeTypes...)
			}
			rangeMarks(func(n usg.Node) bool {
				path := n.Prop("callee_path")
				method := n.Prop("method")
				seenMapping := map[string]bool{}
				for _, mi := range markIdx.candidates(method, path) {
					m := spec.Marks[mi]
					if !nodeTypeAllowed(m.NodeType, n.Type) {
						continue
					}
					if !effects[mi].Allowed {
						continue
					}
					hit := m.ByMethod && method == m.Pattern ||
						!m.ByMethod && ((m.Pattern == "" && m.NodeType != "") || (m.Exact && path == m.Pattern) || (!m.Exact && matchSinkPath(path, m.Pattern)))
					if !hit {
						continue
					}
					if !callArgCountMatches(n, m.ArgCountSet, m.ArgCountMin, m.ArgCountMax) {
						continue
					}
					if !valCondsDirectForNodeCached(valCache, n, valMatchesLower[mi], valAbsentsLower[mi]) {
						continue
					}
					if len(m.ScopePreds) > 0 && !scopePredicatesMatch(s, scopeIdx, m.ScopePreds, n, spec.Technology, crossLang) {
						continue
					}
					detail, conf := reviewDetail(m.Concept, m.Pattern)
					detail = mergeMappingDetail(detail, m.Detail)
					conf = mappingConfidence(m.Confidence, conf)
					conf, detail = effects[mi].apply(conf, detail)
					spec := 0
					if len(m.Packages) > 0 {
						spec = 3 // package-specific direct label supersedes native/general
					}
					for _, target := range markTargets(s, &collectionIdx, n, m) {
						key := m.Concept + "\x00" + target
						if seenMapping[key] {
							continue
						}
						out = append(out, bindings.Mapping{NodeID: target, Concept: m.Concept, Fidelity: mappingFidelity(m.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
						seenMapping[key] = true
					}
				}
				return true
			})
			return out
		},
	}
}

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
			arg := n.Prop("arg" + strconv.Itoa(ai))
			if arg == "" {
				break
			}
			addArgTarget(arg)
		}
		return out
	}
	addArgTarget(n.Prop("arg" + strconv.Itoa(m.ArgIndex)))
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

// Per-language binding applicator sets (loaded from vyql/bindings/<tech>/).
func ConfigBindings() []bindings.Applicator      { return BindingsFor("config") }
func TextPatternBindings() []bindings.Applicator { return BindingsFor("textpattern") }

// AutoBindings returns v2 binding sets that opt into whole-graph application through
// `meta { auto_apply: graph }`.
func AutoBindings() []bindings.Applicator {
	key := "v2\x00" + ActiveBindingConceptsKey()
	if cached, ok := autoBindingsCache.Load(key); ok {
		res := cached.(cachedAutoBindings)
		if res.err != nil {
			panic(res.err.Error())
		}
		return res.data
	}
	data, err := loadAutoBindingApplicators()
	res := cachedAutoBindings{data: data, err: err}
	actual, _ := autoBindingsCache.LoadOrStore(key, res)
	actualRes := actual.(cachedAutoBindings)
	if actualRes.err != nil {
		panic(actualRes.err.Error())
	}
	return actualRes.data
}

func loadAutoBindingApplicators() ([]bindings.Applicator, error) {
	sources, err := autoBindingSources()
	if err != nil {
		return nil, fmt.Errorf("frontend: read auto bindings: %w", err)
	}
	byName := map[string]*parser.BindingSet{}
	var order []string
	decls, err := parseV2BindingSources(sources)
	if err != nil {
		return nil, fmt.Errorf("frontend: parse auto binding corpus: %w", err)
	}
	for _, d := range decls {
		ad, ok := d.(*parser.BindingSet)
		if !ok {
			continue
		}
		merged := byName[ad.Name]
		if merged == nil {
			merged = &parser.BindingSet{Name: ad.Name, Meta: map[string]any{}}
			byName[ad.Name] = merged
			order = append(order, ad.Name)
		}
		for k, v := range ad.Meta {
			merged.Meta[k] = v
		}
		merged.Mappings = append(merged.Mappings, ad.Mappings...)
	}
	var out []bindings.Applicator
	for _, name := range order {
		ad := byName[name]
		if mode, _ := ad.Meta["auto_apply"].(string); mode == "graph" {
			out = append(out, bindingApplicatorsFromSpec(filterBindingSpecForActiveConcepts(specFromBindingSet(ad)))...)
		}
	}
	return out, nil
}

func autoBindingSources() ([]datadir.Source, error) {
	root := filepath.Join(datadir.Root(), "bindings")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []datadir.Source
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if name == "packages" {
				continue
			}
			sources, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join("bindings", name)))
			if err != nil {
				return nil, err
			}
			out = append(out, sources...)
			continue
		}
		if !strings.HasSuffix(name, ".vyql") {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("bindings", name))
		raw, err := datadir.Read(rel)
		if err != nil {
			return nil, err
		}
		out = append(out, datadir.Source{Name: rel, Data: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// paramSourceApplicator labels function/method parameter nodes with the spec's
// `source param -> X` concept(s) for profiles that opt into parameter entrypoints.
// The concrete concept is declared by the .vyql line; this is only the mechanism.
//
// Default-OFF, opt-in: unlike the pattern source binding (where activeSources==nil means
// "no profile → every source on"), a parameter source fires ONLY when a profile is set AND
// explicitly lists the concept (i.e. the library profile). So application profiles, and the
// no-profile default, never taint parameters. Low confidence (syntactic): a finding
// surfaces only if a param actually reaches a sink.
func (spec bindingSpec) paramSourceApplicator() bindings.Applicator {
	sources := spec.ParamSources
	return bindings.Applicator{
		Name: spec.Name + ".param-source", Technology: spec.Technology, Specificity: 0,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			if activeSources == nil {
				return nil // no active source set -> parameters are not sources
			}
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			type activeParamSource struct {
				spec   paramSourceSpec
				effect requirementEffect
			}
			active := make([]activeParamSource, 0, len(sources))
			for _, src := range sources {
				eff := reqGate.effect(src.Packages, src.Requirement)
				if activeSources[src.Concept] && eff.Allowed {
					active = append(active, activeParamSource{spec: src, effect: eff})
				}
			}
			if len(active) == 0 {
				return nil
			}
			ids, _ := s.NodesOfType("code.Param")
			out := make([]bindings.Mapping, 0, len(active))
			for _, id := range ids {
				n, ok, _ := s.GetNode(id)
				if !ok || n.Prop("exported") != "true" {
					continue // only PUBLIC-API params are entry points; internal helpers are
					// reached by ordinary interprocedural propagation (precision).
				}
				for _, activeSrc := range active {
					src := activeSrc.spec
					spec := 0
					if len(src.Packages) > 0 {
						spec = 3
					}
					conf, detail := activeSrc.effect.apply(mappingConfidence(src.Confidence, ""), nil)
					out = append(out, bindings.Mapping{NodeID: id, Concept: src.Concept, Fidelity: mappingFidelity(src.Fidelity, "syntactic"), Confidence: conf, Specificity: spec, Detail: detail})
				}
			}
			return out
		},
	}
}

func jsPathRegexGuardApplicator() bindings.Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return bindings.Applicator{
		Name: "javascript.path-regex-guards", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []bindings.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			var out []bindings.Mapping
			for _, id := range ids {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				method := n.Prop("method")
				path := n.Prop("callee_path")
				if method != "match" && method != "test" && !matchSinkPath(path, "match") && !matchSinkPath(path, "test") {
					continue
				}
				if !safeJSPathComponentRegex(n.Prop("lit0")) {
					continue
				}
				out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
			}
			return out
		},
	}
}

func jsDomValueInputApplicator() bindings.Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleDomInput)
	return bindings.Applicator{
		Name: "javascript.dom-value-inputs", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []bindings.Mapping {
			if concept == "" {
				return nil
			}
			attrs, _ := s.NodesOfType("code.Attr")
			var out []bindings.Mapping
			flowIdx := sharedFlowIndex(s)
			for _, id := range attrs {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				path := n.Prop("callee_path")
				if path == "" {
					path = n.Prop("path")
				}
				if path != "value" && !strings.HasSuffix(path, ".value") {
					continue
				}
				if !jsAttrReceiverFromDomLookup(s, flowIdx, id) {
					continue
				}
				out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Specificity: 2})
			}
			return out
		},
	}
}

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

func jsSafePathResolverApplicator() bindings.Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return bindings.Applicator{
		Name: "javascript.safe-path-resolver-summaries", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []bindings.Mapping {
			if concept == "" {
				return nil
			}
			contexts, _ := s.NodesOfType("code.Call")
			safe := map[string]bool{}
			for _, id := range contexts {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("callee_path") != "analysis.function.context" {
					continue
				}
				name, ok := safeJSPathResolverFunction(n.Prop("str_args"))
				if ok {
					safe[name] = true
				}
			}
			if len(safe) == 0 {
				return nil
			}
			var out []bindings.Mapping
			for _, id := range contexts {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				path := n.Prop("callee_path")
				method := n.Prop("method")
				for name := range safe {
					if path == name || method == name || strings.HasSuffix(path, "."+name) {
						out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
						break
					}
				}
			}
			return out
		},
	}
}

func jsModuleHelperLdapEscapeApplicator() bindings.Applicator {
	concept := "core." + "Ldap" + "Escape"
	return bindings.Applicator{
		Name: "javascript.module-helper-ldap-escape", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []bindings.Mapping {
			moduleHelperFiles := map[string]bool{}
			names, _ := s.NodesOfType("code.Name")
			for _, id := range names {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("callee_path") == "ldapEscape" && strings.Contains(n.ID, "__module#var#ldapEscape") {
					if file := locFile(n.Prop("loc")); file != "" {
						moduleHelperFiles[file] = true
					}
				}
			}
			if len(moduleHelperFiles) == 0 {
				return nil
			}
			calls, _ := s.NodesOfType("code.Call")
			var out []bindings.Mapping
			for _, id := range calls {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("method") != "ldapEscape" && n.Prop("callee_path") != "ldapEscape" {
					continue
				}
				if moduleHelperFiles[locFile(n.Prop("loc"))] {
					out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Specificity: 2})
				}
			}
			return out
		},
	}
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

func processArgVectorApplicator(tech string) bindings.Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleProcessArgVector)
	return bindings.Applicator{
		Name: "process-arg-vector.controls", Technology: tech, Specificity: 1,
		Fidelity: "semantic", Origin: "human",
		Apply: func(s usg.Store) []bindings.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Seq")
			var idx collectionFlowIndex
			var out []bindings.Mapping
			for _, id := range ids {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && tech != "" && t != tech {
					continue
				}
				if !safeProcessArgVectorSeq(s, &idx, id) {
					continue
				}
				out = append(out, bindings.Mapping{NodeID: id, Concept: concept, Specificity: 1})
			}
			return out
		},
	}
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

func ElixirBindings() []bindings.Applicator     { return BindingsFor("elixir") }
func DartBindings() []bindings.Applicator       { return BindingsFor("dart") }
func GroovyBindings() []bindings.Applicator     { return BindingsFor("groovy") }
func PythonBindings() []bindings.Applicator     { return BindingsFor("python") }
func JsBindings() []bindings.Applicator         { return BindingsFor("javascript") }
func RubyBindings() []bindings.Applicator       { return BindingsFor("ruby") }
func GoBindings() []bindings.Applicator         { return BindingsFor("go") }
func JavaBindings() []bindings.Applicator       { return BindingsFor("java") }
func PHPBindings() []bindings.Applicator        { return BindingsFor("php") }
func CSharpBindings() []bindings.Applicator     { return BindingsFor("csharp") }
func CBindings() []bindings.Applicator          { return BindingsFor("c") }
func CPPBindings() []bindings.Applicator        { return BindingsFor("cpp") }
func RustBindings() []bindings.Applicator       { return BindingsFor("rust") }
func BashBindings() []bindings.Applicator       { return BindingsFor("bash") }
func ScalaBindings() []bindings.Applicator      { return BindingsFor("scala") }
func LuaBindings() []bindings.Applicator        { return BindingsFor("lua") }
func KotlinBindings() []bindings.Applicator     { return BindingsFor("kotlin") }
func PowerShellBindings() []bindings.Applicator { return BindingsFor("powershell") }
func SwiftBindings() []bindings.Applicator      { return BindingsFor("swift") }
func PerlBindings() []bindings.Applicator       { return BindingsFor("perl") }
func SolidityBindings() []bindings.Applicator   { return BindingsFor("solidity") }
func ObjCBindings() []bindings.Applicator       { return BindingsFor("objc") }

// containsStr reports whether xs contains v.
func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

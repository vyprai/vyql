// Package frontend turns extracted code.* graphs into concept labels using
// framework adapters (docs/07). The adapter CONTENT — which framework calls
// are inputs, sinks, controls, and which constructors yield which types — is
// VyQL, authored in vyql/adapters/<tech>.vyql and loaded at runtime. Only the
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

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
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
	Exact       bool
	Negative    bool
}

type flagOperandSpec struct {
	Predicates []flagPredicate
}

type flagSpec struct {
	Concept     string
	NodeKind    string
	Scope       string
	Predicates  []flagPredicate
	Operands    []flagOperandSpec
	Packages    []string
	Detail      map[string]string
	Requirement *parser.BindingRequirement
	Fidelity    string
	Confidence  string
}

// activeSources, when non-nil, restricts which source concepts the input adapters
// emit for the active analysis profile. nil = every source active.
var activeSources map[string]bool

var (
	autoAdaptersCache sync.Map // map[string]cachedAutoAdapters
)

type cachedAutoAdapters struct {
	data []adapters.Adapter
	err  error
}

// SetActiveSources sets the active-profile filter for source labelling. Pass nil to disable.
func SetActiveSources(s map[string]bool) { activeSources = s }

// ActiveSourcesKey returns a deterministic fingerprint of the active source set for the
// incremental adapter-label cache: changing the profile changes which
// source labels adapters emit, so cached labels from one profile must not be reused under
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
	return valContainsLower(strings.ToLower(tokens), sub)
}

func valContainsLower(lowerTokens, sub string) bool {
	return strings.Contains(lowerTokens, strings.ToLower(sub))
}

func valContainsLowerNeedle(lowerTokens, lowerSub string) bool {
	return strings.Contains(lowerTokens, lowerSub)
}

// valConds reports whether every `val` substring is present (AND) and every
// `nval` substring is absent among the value tokens. Empty lists pass.
func valConds(tokens string, vals, nvals []string) bool {
	return valCondsLower(strings.ToLower(tokens), vals, nvals)
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

func lowerStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(v)
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
		Exact:       exact,
		Negative:    negative,
	}
}

func (pred flagPredicate) lowerValues() []string {
	if len(pred.valuesLower) == len(pred.Values) {
		return pred.valuesLower
	}
	return lowerStrings(pred.Values)
}

type flowTokenIndex struct {
	built bool
	rev   map[string][]string
	fwd   map[string][]string
}

type flagMatchIndex struct {
	built        bool
	flow         flowTokenIndex
	nodes        map[string]usg.Node
	types        map[string][]usg.Node
	typesByFile  map[string]map[string][]usg.Node
	paramsByLine map[string]map[int][]usg.Node
	scopedHits   map[string]bool
	scopedReady  map[string]bool
	callArgText  map[string]string
}

func (idx *flagMatchIndex) ensure(s usg.Store) {
	if idx.built {
		return
	}
	idx.built = true
	idx.nodes = map[string]usg.Node{}
	idx.types = map[string][]usg.Node{}
	idx.typesByFile = map[string]map[string][]usg.Node{}
	idx.paramsByLine = map[string]map[int][]usg.Node{}
	idx.scopedHits = map[string]bool{}
	idx.scopedReady = map[string]bool{}
	idx.callArgText = map[string]string{}
	rangeNodes(s, func(n usg.Node) bool {
		idx.nodes[n.ID] = n
		idx.types[n.Type] = append(idx.types[n.Type], n)
		if file := locFile(n.Prop("loc")); file != "" {
			if idx.typesByFile[n.Type] == nil {
				idx.typesByFile[n.Type] = map[string][]usg.Node{}
			}
			idx.typesByFile[n.Type][file] = append(idx.typesByFile[n.Type][file], n)
			if n.Type == "code.Param" {
				_, line := splitLocFileLine(n.Prop("loc"))
				if line != 0 {
					if idx.paramsByLine[file] == nil {
						idx.paramsByLine[file] = map[int][]usg.Node{}
					}
					idx.paramsByLine[file][line] = append(idx.paramsByLine[file][line], n)
				}
			}
		}
		return true
	})
	idx.flow.ensure(s)
}

func (idx *flagMatchIndex) nodesOfType(s usg.Store, typ string) []usg.Node {
	idx.ensure(s)
	return idx.types[typ]
}

func (idx *flagMatchIndex) nodesOfTypeInFile(s usg.Store, typ, file string) []usg.Node {
	idx.ensure(s)
	if file == "" {
		return idx.types[typ]
	}
	return idx.typesByFile[typ][file]
}

func (idx *flagMatchIndex) node(s usg.Store, id string) (usg.Node, bool) {
	idx.ensure(s)
	n, ok := idx.nodes[id]
	return n, ok
}

func (idx *flagMatchIndex) scopedHit(s usg.Store, kind string, pred flagPredicate, values []string, nodeTypes []string, n usg.Node, tech string, crossLang bool, allowUnscoped bool, match func(usg.Node) bool) bool {
	idx.ensure(s)
	file := locFile(n.Prop("loc"))
	scope := scopeWithoutOrder(nodeLexicalScope(n))
	key := strings.Join([]string{
		kind,
		flagPredicateCacheKey(pred),
		strings.Join(values, "\x1f"),
		strings.Join(nodeTypes, "\x1f"),
		file,
		scope,
		tech,
		strconv.FormatBool(crossLang),
		strconv.FormatBool(allowUnscoped),
	}, "\x1e")
	if idx.scopedReady[key] {
		return idx.scopedHits[key]
	}
	hit := false
	for _, nodeType := range nodeTypes {
		for _, cand := range idx.nodesOfTypeInFile(s, nodeType, file) {
			if cand.ID == n.ID {
				continue
			}
			candScope := scopeWithoutOrder(nodeLexicalScope(cand))
			if scope != "" {
				if candScope == "" {
					if !allowUnscoped {
						continue
					}
				} else if !sameOrNestedScope(candScope, scope) {
					continue
				}
			}
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				continue
			}
			if match(cand) {
				hit = true
				break
			}
		}
		if hit {
			break
		}
	}
	idx.scopedReady[key] = true
	idx.scopedHits[key] = hit
	return hit
}

func flagPredicateCacheKey(pred flagPredicate) string {
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
	if idx.built {
		return
	}
	idx.built = true
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
	lowerDirect := strings.ToLower(direct)
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

func flowingStringTokens(s usg.Store, idx *flowTokenIndex, start, direct string) string {
	tokens := []string{}
	if direct != "" {
		tokens = append(tokens, direct)
	}
	idx.ensure(s)
	seen := map[string]bool{start: true}
	type item struct {
		id    string
		depth int
	}
	q := []item{{id: start}}
	for len(q) > 0 && len(seen) < 128 {
		cur := q[0]
		q = q[1:]
		if cur.depth >= 6 {
			continue
		}
		for _, srcID := range idx.rev[cur.id] {
			if seen[srcID] {
				continue
			}
			seen[srcID] = true
			src, ok, err := s.GetNode(srcID)
			if err == nil && ok {
				if str := src.Prop("str_args"); str != "" {
					tokens = append(tokens, str)
				}
			}
			q = append(q, item{id: srcID, depth: cur.depth + 1})
		}
	}
	return strings.Join(tokens, "\x00")
}

type collectionFlowIndex struct {
	built       bool
	reachesSeq  map[string][]string
	seqElements map[string]map[int]string
}

func (idx *collectionFlowIndex) ensure(s usg.Store) {
	if idx.built {
		return
	}
	idx.built = true
	idx.reachesSeq = map[string][]string{}
	idx.seqElements = map[string]map[int]string{}
	rg, _ := s.(interface {
		RangeOutEdges(string, string, func(string) bool)
	})
	rangeOut := func(id string, fn func(string) bool) {
		if rg != nil {
			rg.RangeOutEdges(id, "FLOWS", fn)
			return
		}
		edges, _ := s.OutEdges(id, "FLOWS")
		for _, edge := range edges {
			if !fn(edge.Dst) {
				return
			}
		}
	}
	elemIDs, _ := s.NodesOfType("code.CollectionElement")
	for _, id := range elemIDs {
		elem, ok, err := s.GetNode(id)
		if err != nil || !ok {
			continue
		}
		elemIndex, err := strconv.Atoi(elem.Prop("collection_index"))
		if err != nil {
			continue
		}
		rangeOut(id, func(dst string) bool {
			dstNode, ok, err := s.GetNode(dst)
			if err == nil && ok && dstNode.Type == "code.Seq" {
				if idx.seqElements[dst] == nil {
					idx.seqElements[dst] = map[int]string{}
				}
				idx.seqElements[dst][elemIndex] = id
			}
			return true
		})
	}
	seqIDs, _ := s.NodesOfType("code.Seq")
	type item struct {
		id    string
		depth int
	}
	for _, seqID := range seqIDs {
		seen := map[string]bool{seqID: true}
		q := []item{{id: seqID}}
		for len(q) > 0 && len(seen) < 64 {
			cur := q[0]
			q = q[1:]
			if cur.depth > 4 {
				continue
			}
			idx.reachesSeq[cur.id] = append(idx.reachesSeq[cur.id], seqID)
			rangeOut(cur.id, func(dst string) bool {
				if seen[dst] {
					return true
				}
				seen[dst] = true
				q = append(q, item{id: dst, depth: cur.depth + 1})
				return true
			})
		}
	}
}

func collectionElement(s usg.Store, idx *collectionFlowIndex, argID string, elemIndex int) string {
	idx.ensure(s)
	for _, seqID := range idx.reachesSeq[argID] {
		if elemID := idx.seqElements[seqID][elemIndex]; elemID != "" {
			return elemID
		}
	}
	return ""
}

func collectionArgument(s usg.Store, idx *collectionFlowIndex, argID string) bool {
	idx.ensure(s)
	return len(idx.reachesSeq[argID]) > 0
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
		decls, err := parseV2AdapterSources(files)
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

type adapterSpec struct {
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

// AdaptersFor loads v2 bindings for a technology and builds the graph-labeling
// adapters that apply those bindings to an extracted graph.
func AdaptersFor(tech string) []adapters.Adapter {
	out := adaptersFromSpec(loadSpec(tech))
	if tech == "javascript" {
		out = append(out, jsDomValueInputAdapter())
		out = append(out, jsPathRegexGuardAdapter())
		out = append(out, jsSafePathResolverAdapter())
		out = append(out, jsModuleHelperLdapEscapeAdapter())
	}
	if tech == "ruby" {
		out = append(out, processArgVectorAdapter(tech))
	}
	return out
}

// OverlayAdapters loads repo-local adapter overlays from root. Files may live
// directly under root or under root/adapters. The overlay is intentionally
// explicit and opt-in; parse errors are returned so a bad generated file does
// not silently change scan behavior.
func OverlayAdapters(root string, techs []string) ([]adapters.Adapter, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil
	}
	allowed := map[string]bool{}
	for _, tech := range techs {
		allowed[tech] = true
	}
	var files []string
	for _, dir := range []string{root, filepath.Join(root, "adapters")} {
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
	var out []adapters.Adapter
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		decls, err := parseV2AdapterSources([]datadir.Source{{
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
				return nil, fmt.Errorf("overlay adapter %s declares %q, which is not present in this scan", file, ad.Name)
			}
			spec := specFromBindingSet(ad)
			spec.Name = "overlay." + spec.Name
			out = append(out, adaptersFromSpec(spec)...)
		}
	}
	return out, nil
}

// adaptersFromSpec turns a compiled binding spec into concrete graph-labeling
// adapters, one per action family present. Shared by AdaptersFor and the
// dynamic package loader.
func adaptersFromSpec(spec adapterSpec) []adapters.Adapter {
	var out []adapters.Adapter
	if len(spec.Inputs) > 0 {
		out = append(out, spec.inputAdapter())
	}
	if len(spec.Sinks) > 0 {
		out = append(out, spec.sinkAdapter())
	}
	if len(spec.Controls) > 0 {
		out = append(out, spec.controlAdapter())
	}
	if len(spec.Marks) > 0 {
		out = append(out, spec.markAdapter())
	}
	if len(spec.Flags) > 0 {
		out = append(out, spec.flagAdapter())
	}
	if len(spec.Filters) > 0 {
		out = append(out, spec.filterAdapter())
	}
	if len(spec.ParamSources) > 0 {
		out = append(out, spec.paramSourceAdapter())
	}
	if len(spec.AdvisoryNeutralizers) > 0 {
		out = append(out, spec.advisoryNeutralizerAdapter())
	}
	return out
}

// advisoryNeutralizerAdapter labels unsound-neutralizer calls (guards/transforms that cannot be
// proven sound) with a Go-owned internal concept that the engine can surface as
// review context.
func (spec adapterSpec) advisoryNeutralizerAdapter() adapters.Adapter {
	concept := ontology.InternalNeutralizerAssumptionConcept
	return adapters.Adapter{
		Name: spec.Name + ".assumptions", Technology: spec.Technology, Specificity: 2,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			effects := make([]requirementEffect, len(spec.AdvisoryNeutralizers))
			for i := range spec.AdvisoryNeutralizers {
				effects[i] = reqGate.effect(spec.AdvisoryNeutralizers[i].Packages, spec.AdvisoryNeutralizers[i].Requirement)
			}
			var out []adapters.Mapping
			var scopeIdx flagMatchIndex
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); !spec.crossLang && t != "" && t != spec.Technology {
					continue
				}
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
					if !valCondsDirectForNode(n, as.ValMatches, as.ValAbsents) {
						continue
					}
					if !scopePredicatesMatch(s, &scopeIdx, as.ScopePreds, n, spec.Technology, spec.crossLang) {
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
					out = append(out, adapters.Mapping{NodeID: id, Concept: concept,
						Fidelity: mappingFidelity(as.Fidelity, "syntactic"), Confidence: conf, Detail: detail})
					break
				}
			}
			return out
		},
	}
}

// filterAdapter labels character-filtering replace(pattern, repl) calls with the
// ontology role concept, recording the proven OUTPUT alphabet (or that it is unbounded)
// in the label Detail. The solver then treats it as a SOUND sanitizer for any sink whose
// excluded chars the alphabet excludes, and the engine surfaces an unproven filter
// as an advisory note. The regex math is general (charfilter.go); WHICH methods
// filter is data (the `filter` directive).
func (spec adapterSpec) filterAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleCharFilter)
	return adapters.Adapter{
		Name: spec.Name + ".filters", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			allowed := make([]bool, len(spec.Filters))
			for i := range spec.Filters {
				allowed[i] = reqGate.allowed(spec.Filters[i].Packages, spec.Filters[i].Requirement)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); t != "" && t != spec.Technology {
					continue
				}
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
					continue
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
				out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Detail: detail})
			}
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
	sources, err := datadir.ReadVYQLDir("adapters/" + tech)
	if err != nil {
		panic("frontend: read adapters/" + tech + ": " + err.Error())
	}
	if extra, err := datadir.ReadVYQLDir("adapters/packages/" + tech); err == nil {
		sources = append(sources, extra...)
	}
	decls, err := parseV2AdapterSources(sources)
	if err != nil {
		panic("frontend: invalid adapter corpus for " + tech + ": " + err.Error())
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
	panic("frontend: no v2 binding set in adapters/" + tech)
}

type bindingSetCacheKey struct {
	tech string
}

func v2DefinitionSourcesForAdapter(sources []datadir.Source) []parser.V2DefinitionSource {
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

func parseV2AdapterSources(sources []datadir.Source) ([]parser.Decl, error) {
	selected := make(map[string]bool, len(sources))
	for _, source := range sources {
		selected[source.Name] = true
	}
	return parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForAdapter(sources), func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
}

func loadSpec(tech string) adapterSpec {
	return specFromBindingSet(loadBindingSet(tech))
}

// specFromBindingSet builds an adapterSpec from an already-compiled v2 binding
// set. Split out of loadSpec so the dynamic per-package adapter loader
// (packages.go) can reuse the exact same action-to-spec compilation.
func specFromBindingSet(d *parser.BindingSet) adapterSpec {
	s := adapterSpec{Name: d.Name, Technology: d.Name}
	if m, _ := d.Meta["match"].(string); m == "contains" {
		s.containsMatch = true
	}
	if adapterMetaBool(d.Meta, "cross_language") {
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
		case "control":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "control_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "control_arg":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "control_method_arg":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "control_receiver_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, Receiver: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "mark":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "mark_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds, ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern, Exact: mp.Exact,
				ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "fact_method_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "mark_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "mark_method_arg":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, NodeType: mp.NodeType, Pattern: mp.Pattern,
				ByMethod: true, ArgTarget: true, ArgIndex: mp.ArgIndex, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, ScopePreds: scopePreds,
				ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp),
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		case "flag":
			if mp.Flag != nil {
				fs := flagSpec{Concept: mp.Concept, NodeKind: mp.Flag.NodeKind, Scope: mp.Flag.Scope, Packages: mp.Packages, Requirement: mp.Requirement, Detail: adapterMappingDetail(mp), Fidelity: mp.Fidelity, Confidence: mp.Confidence}
				for _, pred := range mp.Flag.Predicates {
					fs.Predicates = append(fs.Predicates, newFlagPredicate(pred.Subject, pred.Property, pred.Op, pred.Values, pred.Exact, pred.Negative))
				}
				for _, operand := range mp.Flag.Operands {
					var os flagOperandSpec
					for _, pred := range operand.Predicates {
						os.Predicates = append(os.Predicates, newFlagPredicate(pred.Subject, pred.Property, pred.Op, pred.Values, pred.Exact, pred.Negative))
					}
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
				Detail: adapterMappingDetail(mp), ArgCountSet: mp.ArgCountSet, ArgCountMin: mp.ArgCountMin, ArgCountMax: mp.ArgCountMax, Packages: mp.Packages, Requirement: mp.Requirement,
				Fidelity: mp.Fidelity, Confidence: mp.Confidence})
		}
	}
	return s
}

func adapterMetaBool(meta map[string]any, key string) bool {
	switch v := meta[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

func adapterMappingDetail(mp parser.BindingAction) map[string]string {
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

func scopePredicatesMatch(s usg.Store, idx *flagMatchIndex, preds []flagPredicate, n usg.Node, tech string, crossLang bool) bool {
	for _, pred := range preds {
		probe := pred
		probe.Negative = false
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

// inputAdapter labels source reads. Prefix matching is `resolved`; `contains`
// matching (Go's varying receivers) is `syntactic` → lower confidence.
func (spec adapterSpec) inputAdapter() adapters.Adapter {
	fidelity := "resolved"
	if spec.containsMatch {
		fidelity = "syntactic"
	}
	return adapters.Adapter{
		Name: spec.Name + ".input", Technology: spec.Technology, Specificity: 2,
		Fidelity: fidelity, Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
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
			for i := range spec.Inputs {
				effects[i] = reqGate.effect(spec.Inputs[i].Packages, spec.Inputs[i].Requirement)
			}
			var out []adapters.Mapping
			var scopeIdx flagMatchIndex
			rangeCallablePropNodes(s, func(n usg.Node) bool {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" && len(inIdx.loose) == 0 {
					return true
				}
				if t := nodeTechFromNode(n); !spec.crossLang && t != "" && t != spec.Technology {
					return true // only label this language's nodes (cross-language adapters skip this)
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
						// tokens are present or absent as declared by the adapter.
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valCondsDirectForNode(n, in.ValMatches, in.ValAbsents) {
							continue
						}
						if !scopePredicatesMatch(s, &scopeIdx, in.ScopePreds, n, spec.Technology, spec.crossLang) {
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
							out = append(out, adapters.Mapping{NodeID: n.ID, Concept: in.Concept, Fidelity: mappingFidelity(in.Fidelity, fidelity), Confidence: conf, Specificity: spec, Detail: detail})
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

// sinkAdapter labels arg0 of matching calls with a PER-MAPPING fidelity:
//   - dotted-path match           → resolved (high)
//   - bare-method match, no `on`  → syntactic (medium — receiver type unknown)
//   - method match with `on T`:
//     recv_type == T              → resolved (high, type-verified)
//     recv_type unknown           → syntactic (medium, can't disprove)
//     recv_type != T              → SKIP (known wrong type — not a sink here)
//
// Collection-literal arg0s (vkind == Seq) are skipped.
func (spec adapterSpec) sinkAdapter() adapters.Adapter {
	attributeSinks := ontologyRoleConcepts(ontology.InternalConceptRoleAttributeSink)
	return adapters.Adapter{
		Name: spec.Name + ".sinks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			attrs, _ := s.NodesOfType("code.Attr")
			ids = append(ids, attrs...)
			binops, _ := s.NodesOfType("code.BinOp")
			ids = append(ids, binops...)
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			sinkIdx := buildSpecIndex(len(spec.Sinks), func(i int) (methods, paths []string, loose bool) {
				if spec.Sinks[i].ByMethod {
					return []string{spec.Sinks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Sinks[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Sinks))
			for i := range spec.Sinks {
				effects[i] = reqGate.effect(spec.Sinks[i].Packages, spec.Sinks[i].Requirement)
			}
			var out []adapters.Mapping
			var flowIdx flowTokenIndex
			var collectionIdx collectionFlowIndex
			var scopeIdx flagMatchIndex
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				isAttr := n.Type == "code.Attr"
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				cand := sinkIdx.candidates(method, path)
				// Pick the MOST SPECIFIC matching sink (longest pattern) per concept, so
				// e.g. a qualified path wins over its short method for overlapping
				// mappings, while one call can still carry genuinely distinct concepts.
				bestByConcept := map[string]int{}
				for _, i := range cand {
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
					// value-matched sink: every `val` must be present and every `nval`
					// absent among the literal arg/option tokens (case-insensitive).
					if hit && !valCondsForSink(s, &flowIdx, n, sk) {
						hit = false
					}
					if hit && !callArgCountMatches(n, sk.ArgCountSet, sk.ArgCountMin, sk.ArgCountMax) {
						hit = false
					}
					if hit && !scopePredicatesMatch(s, &scopeIdx, sk.ScopePreds, n, spec.Technology, spec.crossLang) {
						hit = false
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
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
						} else {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "resolved"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
						out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
							out = append(out, adapters.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
					out = append(out, adapters.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
				}
			}
			return out
		},
	}
}

func sinkBestKey(sk sinkSpec) string {
	return sk.Concept + "\x00" +
		strconv.Itoa(sk.ArgIndex) + "\x00" +
		strconv.FormatBool(sk.Collection) + "\x00" +
		strconv.FormatBool(sk.CollectionFirst) + "\x00" +
		strconv.Itoa(sk.CollectionIndex)
}

// controlAdapter labels control concepts (transforms/validators) on the calls that
// apply them, so v2 path coveredBy controls can suppress a sanitized flow (docs/07).
func (spec adapterSpec) controlAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".controls", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			ctrlIdx := buildSpecIndex(len(spec.Controls), func(i int) (methods, paths []string, loose bool) {
				if spec.Controls[i].ByMethod {
					return []string{spec.Controls[i].Pattern}, nil, false
				}
				return nil, []string{spec.Controls[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Controls))
			for i := range spec.Controls {
				effects[i] = reqGate.effect(spec.Controls[i].Packages, spec.Controls[i].Requirement)
			}
			var out []adapters.Mapping
			var collectionIdx collectionFlowIndex
			var scopeIdx flagMatchIndex
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
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
					if hit && valCondsDirectForNode(n, c.ValMatches, c.ValAbsents) &&
						scopePredicatesMatch(s, &scopeIdx, c.ScopePreds, n, spec.Technology, spec.crossLang) {
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
								out = append(out, adapters.Mapping{NodeID: target, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
							}
							continue
						}
						out = append(out, adapters.Mapping{NodeID: nodeID, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
					}
				}
			}
			return out
		},
	}
}

// extTech maps a source file extension to its adapter technology, so an adapter
// only labels nodes from its own language (avoids cross-language FPs in polyglot
// repos — e.g. one language's adapter matching another language's same-named call).
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
	for _, tok := range strings.Split(n.Prop("str_args"), "\x00") {
		if strings.HasPrefix(tok, "lang=") {
			return strings.TrimPrefix(tok, "lang=")
		}
	}
	return ""
}

// rangeNodes streams every node to fn via the store's RangeNodes fast path (no full []Node copy)
// when available, else falls back to AllNodes. Adapter passes iterate every node once; the slice
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
	// scanning every node, since this runs once per adapter spec.
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
	ConfidenceDowngrade int
	Detail              map[string]string
}

func newRequirementGate(s usg.Store, tech string, crossLang bool, packages map[string]bool) *requirementGate {
	langs := map[string]bool{}
	if tech != "" {
		langs[tech] = true
	}
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		if n, ok, _ := s.GetNode(id); ok {
			if t := nodeTechFromNode(n); t != "" {
				langs[t] = true
			}
		}
	}
	imports := importEvidence(s, tech, crossLang)
	return &requirementGate{
		packages:  newPackageGate(packages),
		imports:   newPackageGate(imports),
		versions:  dependencyVersionEvidence(s),
		languages: langs,
		project:   projectFactEvidence(s),
		store:     s,
		tech:      tech,
		crossLang: crossLang,
	}
}

func (g *requirementGate) allowed(packages []string, req *parser.BindingRequirement) bool {
	return g.effect(packages, req).Allowed
}

func (g *requirementGate) effect(packages []string, req *parser.BindingRequirement) requirementEffect {
	if req == nil {
		return requirementEffect{Allowed: g.packages.allowed(packages)}
	}
	return g.evalEffect(*req)
}

func (g *requirementGate) eval(req parser.BindingRequirement) bool {
	return g.evalEffect(req).Allowed
}

func (g *requirementGate) evalEffect(req parser.BindingRequirement) requirementEffect {
	switch req.Op {
	case "":
		return requirementEffect{Allowed: true}
	case "dependency", "framework":
		if req.Range != "" {
			return requirementEffect{Allowed: g.dependencyVersionSatisfies(req.Value, req.Range)}
		}
		return requirementEffect{Allowed: g.packages.inEvidence(req.Value)}
	case "import":
		return requirementEffect{Allowed: g.imports.inEvidence(req.Value)}
	case "language":
		return requirementEffect{Allowed: g.languages[strings.ToLower(req.Value)]}
	case "file":
		g.ensureFiles()
		return requirementEffect{Allowed: g.files[filepath.ToSlash(req.Value)]}
	case "schema":
		name, version, _ := strings.Cut(req.Value, "\x00")
		return requirementEffect{Allowed: name == "nir" && (version == "" || version == "2.0")}
	case "project.has":
		return requirementEffect{Allowed: g.hasProjectFact(req.Value)}
	case "all":
		out := requirementEffect{Allowed: true}
		for _, child := range req.Args {
			eff := g.evalEffect(child)
			if !eff.Allowed {
				return requirementEffect{Allowed: false}
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
			}
		}
		if found {
			return best
		}
		return requirementEffect{Allowed: false}
	case "not":
		return requirementEffect{Allowed: len(req.Args) == 1 && !g.evalEffect(req.Args[0]).Allowed}
	case "soft":
		if len(req.Args) != 1 {
			return requirementEffect{Allowed: false}
		}
		child := g.evalEffect(req.Args[0])
		if child.Allowed {
			return requirementEffect{Allowed: true}
		}
		return requirementEffect{
			Allowed:             true,
			ConfidenceDowngrade: 1,
			Detail: map[string]string{
				"requirement_state": "missing",
				"requirement":       "soft evidence missing",
			},
		}
	default:
		return requirementEffect{Allowed: false}
	}
}

func mergeRequirementEffects(a, b requirementEffect) requirementEffect {
	out := a
	if b.ConfidenceDowngrade > out.ConfidenceDowngrade {
		out.ConfidenceDowngrade = b.ConfidenceDowngrade
	}
	out.Detail = mergeMappingDetail(out.Detail, b.Detail)
	return out
}

func (e requirementEffect) apply(conf string, detail map[string]string) (string, map[string]string) {
	if e.ConfidenceDowngrade > 0 {
		conf = downgradeConfidence(conf, e.ConfidenceDowngrade)
	}
	return conf, mergeMappingDetail(detail, e.Detail)
}

func downgradeConfidence(conf string, steps int) string {
	levels := []string{"low", "medium", "high"}
	idx := 2
	if conf != "" {
		for i, level := range levels {
			if conf == level {
				idx = i
				break
			}
		}
	}
	idx -= steps
	if idx < 0 {
		idx = 0
	}
	return levels[idx]
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
	switch conf {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 3
	}
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
	return strings.ToLower(strings.TrimSpace(filepath.ToSlash(raw)))
}

func (g *requirementGate) hasProjectFact(raw string) bool {
	key := normalizeProjectFactKey(raw)
	if key == "" {
		return false
	}
	if g.project[key] {
		return true
	}
	family, value, ok := strings.Cut(key, ":")
	if ok {
		switch family {
		case "dependency", "package", "dep", "npm", "pypi", "go", "maven", "nuget", "gem", "cargo":
			return g.packages.inEvidence(value)
		case "import":
			return g.imports.inEvidence(value)
		case "framework":
			return g.packages.inEvidence(value)
		case "language", "lang":
			return g.languages[value]
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
	for _, key := range packageEvidenceKeys(pkg) {
		for _, version := range g.versions[key] {
			if versionSatisfiesRange(version, expr) {
				return true
			}
		}
	}
	return false
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

// flagAdapter labels nodes with presence/review concepts emitted by v2
// presenceNode bindings.
func (spec adapterSpec) flagAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".flags", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			fileTech := fileContextTechs(s)
			effects := make([]requirementEffect, len(spec.Flags))
			for i := range spec.Flags {
				effects[i] = reqGate.effect(spec.Flags[i].Packages, spec.Flags[i].Requirement)
			}
			flagIdx := buildSpecIndex(len(spec.Flags), func(i int) (methods, paths []string, loose bool) {
				if spec.Flags[i].Scope != "" {
					return nil, []string{"analysis." + strings.ToLower(spec.Flags[i].Scope) + ".context"}, false
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
			var out []adapters.Mapping
			var matchIdx flagMatchIndex
			nodeTypes := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Name"}
			if spec.crossLang {
				nodeTypes = append(nodeTypes, "sbom.PackageVersion")
			}
			for _, nodeType := range nodeTypes {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, ok, err := s.GetNode(id)
					if err != nil || !ok {
						continue
					}
					if t := nodeTechFromNodeWithFileContext(n, fileTech); !spec.crossLang && t != "" && t != spec.Technology {
						continue
					}
					for _, i := range flagIdx.candidates(n.Prop("method"), n.Prop("callee_path")) {
						if !effects[i].Allowed {
							continue
						}
						fl := spec.Flags[i]
						if !flagNodeKindAllows(fl, n) {
							continue
						}
						if !flagMatchesNode(s, &matchIdx, fl, n, spec.Technology, spec.crossLang, fileTech) {
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
						out = append(out, adapters.Mapping{NodeID: n.ID, Concept: fl.Concept, Fidelity: mappingFidelity(fl.Fidelity, "resolved"), Confidence: conf, Specificity: specificity, Detail: detail})
					}
				}
			}
			return out
		},
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
	switch strings.ToLower(fl.Scope) {
	case "function":
		return n.Type == "code.Call"
	case "module":
		return n.Type == "code.Call"
	case "class":
		return n.Type == "code.Call"
	default:
		switch strings.ToLower(fl.NodeKind) {
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

func flagMatchesNode(s usg.Store, idx *flagMatchIndex, fl flagSpec, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if fl.Scope != "" && n.Prop("callee_path") != "analysis."+strings.ToLower(fl.Scope)+".context" {
		return false
	}
	for _, pred := range fl.Predicates {
		if !flagPredicateMatches(s, idx, pred, n, tech, crossLang, fileTech) {
			return false
		}
	}
	if len(fl.Operands) == 0 {
		return true
	}
	operands := flagOperandCandidates(s, &idx.flow, n)
	used := make([]bool, len(operands))
	var matchOperand func(int) bool
	matchOperand = func(i int) bool {
		if i == len(fl.Operands) {
			return true
		}
		for oi, opNodes := range operands {
			if used[oi] {
				continue
			}
			if flagOperandMatches(fl.Operands[i], opNodes) {
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

func flagOperandCandidates(s usg.Store, idx *flowTokenIndex, n usg.Node) [][]usg.Node {
	idx.ensure(s)
	var out [][]usg.Node
	addArg := func(argID string) {
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
			for _, srcID := range idx.rev[id] {
				if seen[srcID] {
					continue
				}
				seen[srcID] = true
				if src, ok, err := s.GetNode(srcID); err == nil && ok {
					nodes = append(nodes, src)
				}
				collectUpstream(srcID, depth+1)
			}
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
		addArg(argID)
	}
	if !hadArgProps {
		for _, srcID := range idx.rev[n.ID] {
			src, ok, err := s.GetNode(srcID)
			if err != nil || !ok || src.Type != "code.Arg" {
				continue
			}
			addArg(srcID)
		}
	}
	return out
}

func flagOperandMatches(spec flagOperandSpec, nodes []usg.Node) bool {
	for _, pred := range spec.Predicates {
		hit := false
		for _, n := range nodes {
			if flagPredicateMatchesNodeOnly(pred, n) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
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
		hit := flagScopeNodeHit(s, idx, pred, n, []string{"code.Call"}, tech, crossLang)
		if pred.Negative {
			return !hit
		}
		return hit
	}
	if n.Prop("callee_path") == "analysis.function.context" ||
		n.Prop("callee_path") == "analysis.module.context" ||
		n.Prop("callee_path") == "analysis.class.context" {
		if ok, hit := flagContextPredicateMatchesAST(s, idx, pred, n, tech, crossLang); ok {
			if !flagPredicateUsesCallArg(pred) {
				probe := pred
				probe.Negative = false
				hit = hit || flagPredicateMatchesNodeOnly(probe, n)
			}
			if pred.Negative {
				return !hit
			}
			return hit
		}
	}
	return flagPredicateMatchesNodeOnly(pred, n)
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

func flagFlowToNodeHit(s usg.Store, idx *flowTokenIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if idx == nil {
		return false
	}
	idx.ensure(s)
	probe := pred
	probe.Subject = "node"
	probe.Negative = false
	prefix := locFile(n.Prop("loc"))
	seen := map[string]bool{n.ID: true}
	type item struct {
		id    string
		depth int
	}
	q := []item{{id: n.ID}}
	for len(q) > 0 && len(seen) < 256 {
		cur := q[0]
		q = q[1:]
		if cur.depth >= 6 {
			continue
		}
		for _, dstID := range idx.fwd[cur.id] {
			if seen[dstID] {
				continue
			}
			seen[dstID] = true
			dst, ok, err := s.GetNode(dstID)
			if err == nil && ok {
				if prefix != "" && locFile(dst.Prop("loc")) != prefix {
					continue
				}
				if t := nodeTechFromNodeWithFileContext(dst, fileTech); !crossLang && t != "" && t != tech {
					continue
				}
				if flagPredicateMatchesNodeOnly(probe, dst) {
					return true
				}
			}
			q = append(q, item{id: dstID, depth: cur.depth + 1})
		}
	}
	return false
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

func binopValueMatches(s usg.Store, idx *flagMatchIndex, value string, n usg.Node) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if valuePredicate("contains", []string{value}, nodeSearchText(n)) {
		return true
	}
	left, op, right, ok := splitBinaryPredicate(value)
	if !ok {
		return false
	}
	if n.Prop("op") != op {
		return false
	}
	operands := flagOperandCandidates(s, &idx.flow, n)
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

func normalizeFlagExprFragment(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") && len(s) > 1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	repl := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", `"`, "", "'", "", "`", "")
	return repl.Replace(s)
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
		if contextTokenValuePredicate(pred.Op, pred.Values, callArgContextTokensScoped(s, idx, cand, tech, crossLang)) {
			return true
		}
		return false
	})
}

func callArgContextTokensScoped(s usg.Store, idx *flagMatchIndex, n usg.Node, tech string, crossLang bool) string {
	idx.ensure(s)
	cacheKey := strings.Join([]string{n.ID, tech, strconv.FormatBool(crossLang)}, "\x1f")
	if cached, ok := idx.callArgText[cacheKey]; ok {
		return cached
	}
	tokens := callArgContextTokens(n)
	path := n.Prop("callee_path")
	method := n.Prop("method")
	if path == "" && method == "" {
		idx.callArgText[cacheKey] = tokens
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
	for _, argID := range idx.flow.rev[n.ID] {
		arg, ok := idx.node(s, argID)
		if !ok || arg.Type != "code.Arg" || !scopedCallArgCandidate(arg, n, tech, crossLang) {
			continue
		}
		addNode(arg)
		for _, srcID := range idx.flow.rev[arg.ID] {
			src, ok := idx.node(s, srcID)
			if !ok || !callArgSourceNodeType(src.Type) || !scopedCallArgCandidate(src, n, tech, crossLang) {
				continue
			}
			addNode(src)
		}
	}
	result := strings.Join(out, "\x00")
	idx.callArgText[cacheKey] = result
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

func scopedCallArgCandidate(cand, anchor usg.Node, tech string, crossLang bool) bool {
	scope := nodeLexicalScope(anchor)
	candScope := nodeLexicalScope(cand)
	if scope != "" && candScope != "" && !sameOrNestedScope(candScope, scope) {
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
	if idx.scopedHit(s, "node", probe, nil, nodeTypes, n, tech, crossLang, false, func(cand usg.Node) bool {
		return flagPredicateMatchesNodeOnly(probe, cand)
	}) {
		return true
	}
	if nodeLexicalScope(n) == "" || !containsStr(nodeTypes, "code.Param") {
		return false
	}
	file, line := splitLocFileLine(n.Prop("loc"))
	for _, cand := range idx.paramsByLine[file][line] {
		if cand.ID == n.ID || nodeLexicalScope(cand) != "" {
			continue
		}
		if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
			continue
		}
		if flagPredicateMatchesNodeOnly(probe, cand) {
			return true
		}
	}
	return false
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
	return candidate == anchor || strings.HasPrefix(candidate, anchor+"/")
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
			for _, v := range pred.Values {
				if pred.Exact && path == v || !pred.Exact && matchSinkPath(path, v) {
					return true
				}
			}
		}
		return false
	case "method":
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

func contextTokenValuePredicateLowerValues(op string, values, valuesLower []string, text string) bool {
	if op == "equals" || op == "equals_any" {
		if contextTokenEqualsPredicate(op, values, text) {
			return true
		}
	}
	if op == "contains" || op == "" || op == "contains_any" {
		if contextTokenContainsPredicateLowerValues(op, values, valuesLower, text) {
			return true
		}
	}
	return valuePredicateLowerValues(op, values, valuesLower, text)
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
		wantLower := strings.ToLower(want)
		if len(valuesLower) == 1 {
			if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[0]); lowerOK && lowerPrefix == strings.ToLower(prefix) {
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
			wantLower := strings.ToLower(want)
			if i < len(valuesLower) {
				if lowerPrefix, lowerWant, lowerOK := splitContextTokenPredicateValue(valuesLower[i]); lowerOK && lowerPrefix == strings.ToLower(prefix) {
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
	return contextTokenContainsLower(prefix, got, want, strings.ToLower(want))
}

func contextTokenContainsLower(prefix, got, want, wantLower string) bool {
	if prefix == "class_base:" {
		return classBaseTokenMatches(got, want)
	}
	return valContainsLowerNeedle(strings.ToLower(got), wantLower)
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
		lowerText := strings.ToLower(text)
		for _, v := range valuesLower {
			if valContainsLowerNeedle(lowerText, v) {
				return true
			}
		}
		return false
	default:
		return valCondsLowerNeedles(strings.ToLower(text), valuesLower, nil)
	}
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

// markAdapter labels a node with a presence concept for `match`-style rules.
func (spec adapterSpec) markAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".marks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			// Most presence events are calls, but some are bare member accesses with
			// no call, so scan Attr nodes too.
			var out []adapters.Mapping
			// cross-language adapters label nodes in source files of
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
			for i := range spec.Marks {
				effects[i] = reqGate.effect(spec.Marks[i].Packages, spec.Marks[i].Requirement)
			}
			nodeTypes := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Literal", "code.Const", "code.Function", "code.Class", "code.Import"}
			if crossLang {
				nodeTypes = append(nodeTypes, "sbom.PackageVersion")
			}
			var collectionIdx collectionFlowIndex
			var scopeIdx flagMatchIndex
			for _, nodeType := range nodeTypes {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, _, _ := s.GetNode(id)
					if t := nodeTechFromNode(n); !crossLang && t != "" && t != spec.Technology {
						continue
					}
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
						if !valCondsDirectForNode(n, m.ValMatches, m.ValAbsents) {
							continue
						}
						if !scopePredicatesMatch(s, &scopeIdx, m.ScopePreds, n, spec.Technology, crossLang) {
							continue
						}
						detail, conf := reviewDetail(m.Concept, m.Pattern)
						detail = mergeMappingDetail(detail, m.Detail)
						conf = mappingConfidence(m.Confidence, conf)
						conf, detail = effects[mi].apply(conf, detail)
						spec := 0
						if len(m.Packages) > 0 {
							spec = 3 // package-specific mark supersedes native/general
						}
						for _, target := range markTargets(s, &collectionIdx, n, m) {
							key := m.Concept + "\x00" + target
							if seenMapping[key] {
								continue
							}
							out = append(out, adapters.Mapping{NodeID: target, Concept: m.Concept, Fidelity: mappingFidelity(m.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
							seenMapping[key] = true
						}
					}
				}
			}
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

// --- adapter spec indexing -------------------------------------------------
//
// Adapter matching is a search problem: for each graph node, find the specs whose
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
// output. Not safe for concurrent use — adapters apply sequentially.
type specIndex struct {
	byMethod map[string][]int
	bySeg    map[string][]int
	loose    []int
	visited  []int32
	gen      int32
	buf      []int
}

// buildSpecIndex indexes n specs. keysOf reports, for spec i, its by-method keys
// (exact method names), its path patterns (indexed by first segment), and whether
// it needs unanchored matching (loose → always a candidate).
func buildSpecIndex(n int, keysOf func(i int) (methods, paths []string, loose bool)) *specIndex {
	idx := &specIndex{byMethod: map[string][]int{}, bySeg: map[string][]int{}, visited: make([]int32, n)}
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
			idx.bySeg[firstSeg(p)] = append(idx.bySeg[firstSeg(p)], i)
		}
	}
	return idx
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
	return path == p ||
		strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") ||
		strings.HasSuffix(path, "."+p) ||
		strings.Contains(path, "."+p+".") || strings.Contains(path, "."+p+"[")
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

// Per-language adapter sets (loaded from vyql/adapters/<tech>/).
func ConfigAdapters() []adapters.Adapter      { return AdaptersFor("config") }
func TextPatternAdapters() []adapters.Adapter { return AdaptersFor("textpattern") }

// AutoAdapters returns v2 binding sets that opt into whole-graph application through
// `meta { auto_apply: graph }`.
func AutoAdapters() []adapters.Adapter {
	const key = "v2"
	if cached, ok := autoAdaptersCache.Load(key); ok {
		res := cached.(cachedAutoAdapters)
		if res.err != nil {
			panic(res.err.Error())
		}
		return res.data
	}
	data, err := loadAutoAdapters()
	res := cachedAutoAdapters{data: data, err: err}
	actual, _ := autoAdaptersCache.LoadOrStore(key, res)
	actualRes := actual.(cachedAutoAdapters)
	if actualRes.err != nil {
		panic(actualRes.err.Error())
	}
	return actualRes.data
}

func loadAutoAdapters() ([]adapters.Adapter, error) {
	sources, err := autoAdapterSources()
	if err != nil {
		return nil, fmt.Errorf("frontend: read auto adapters: %w", err)
	}
	byName := map[string]*parser.BindingSet{}
	var order []string
	decls, err := parseV2AdapterSources(sources)
	if err != nil {
		return nil, fmt.Errorf("frontend: parse auto adapter corpus: %w", err)
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
	var out []adapters.Adapter
	for _, name := range order {
		ad := byName[name]
		if mode, _ := ad.Meta["auto_apply"].(string); mode == "graph" {
			out = append(out, adaptersFromSpec(specFromBindingSet(ad))...)
		}
	}
	return out, nil
}

func autoAdapterSources() ([]datadir.Source, error) {
	root := filepath.Join(datadir.Root(), "adapters")
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
			sources, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join("adapters", name)))
			if err != nil {
				return nil, err
			}
			out = append(out, sources...)
			continue
		}
		if !strings.HasSuffix(name, ".vyql") {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("adapters", name))
		raw, err := datadir.Read(rel)
		if err != nil {
			return nil, err
		}
		out = append(out, datadir.Source{Name: rel, Data: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// paramSourceAdapter labels function/method parameter nodes with the spec's
// `source param -> X` concept(s) for profiles that opt into parameter entrypoints.
// The concrete concept is declared by the .vyql line; this is only the mechanism.
//
// Default-OFF, opt-in: unlike the pattern source adapter (where activeSources==nil means
// "no profile → every source on"), a parameter source fires ONLY when a profile is set AND
// explicitly lists the concept (i.e. the library profile). So application profiles, and the
// no-profile default, never taint parameters. Low confidence (syntactic): a finding
// surfaces only if a param actually reaches a sink.
func (spec adapterSpec) paramSourceAdapter() adapters.Adapter {
	sources := spec.ParamSources
	return adapters.Adapter{
		Name: spec.Name + ".param-source", Technology: spec.Technology, Specificity: 0,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
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
			out := make([]adapters.Mapping, 0, len(active))
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
					out = append(out, adapters.Mapping{NodeID: id, Concept: src.Concept, Fidelity: mappingFidelity(src.Fidelity, "syntactic"), Confidence: conf, Specificity: spec, Detail: detail})
				}
			}
			return out
		},
	}
}

func jsPathRegexGuardAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return adapters.Adapter{
		Name: "javascript.path-regex-guards", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			var out []adapters.Mapping
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
				out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
			}
			return out
		},
	}
}

func jsDomValueInputAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleDomInput)
	return adapters.Adapter{
		Name: "javascript.dom-value-inputs", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			attrs, _ := s.NodesOfType("code.Attr")
			var out []adapters.Mapping
			var flowIdx flowTokenIndex
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
				if !jsAttrReceiverFromDomLookup(s, &flowIdx, id) {
					continue
				}
				out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2})
			}
			return out
		},
	}
}

func jsAttrReceiverFromDomLookup(s usg.Store, idx *flowTokenIndex, attrID string) bool {
	idx.ensure(s)
	for _, src := range idx.rev[attrID] {
		n, ok, err := s.GetNode(src)
		if err != nil || !ok || n.Type != "code.Call" {
			continue
		}
		path := n.Prop("callee_path")
		if path == "document.getElementById" ||
			path == "document.querySelector" ||
			path == "document.querySelectorAll" ||
			path == "document.getElementsByName" ||
			path == "document.getElementsByClassName" ||
			path == "document.getElementsByTagName" {
			return true
		}
	}
	return false
}

func jsSafePathResolverAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return adapters.Adapter{
		Name: "javascript.safe-path-resolver-summaries", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []adapters.Mapping {
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
			var out []adapters.Mapping
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
						out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
						break
					}
				}
			}
			return out
		},
	}
}

func jsModuleHelperLdapEscapeAdapter() adapters.Adapter {
	concept := "core." + "Ldap" + "Escape"
	return adapters.Adapter{
		Name: "javascript.module-helper-ldap-escape", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []adapters.Mapping {
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
			var out []adapters.Mapping
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
					out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2})
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
	lower := strings.ToLower(tokens)
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

func processArgVectorAdapter(tech string) adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleProcessArgVector)
	return adapters.Adapter{
		Name: "process-arg-vector.controls", Technology: tech, Specificity: 1,
		Fidelity: "semantic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Seq")
			var idx collectionFlowIndex
			var out []adapters.Mapping
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
				out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 1})
			}
			return out
		},
	}
}

func safeProcessArgVectorSeq(s usg.Store, idx *collectionFlowIndex, seqID string) bool {
	idx.ensure(s)
	first := idx.seqElements[seqID][0]
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

func ElixirAdapters() []adapters.Adapter     { return AdaptersFor("elixir") }
func DartAdapters() []adapters.Adapter       { return AdaptersFor("dart") }
func GroovyAdapters() []adapters.Adapter     { return AdaptersFor("groovy") }
func PythonAdapters() []adapters.Adapter     { return AdaptersFor("python") }
func JsAdapters() []adapters.Adapter         { return AdaptersFor("javascript") }
func RubyAdapters() []adapters.Adapter       { return AdaptersFor("ruby") }
func GoAdapters() []adapters.Adapter         { return AdaptersFor("go") }
func JavaAdapters() []adapters.Adapter       { return AdaptersFor("java") }
func PHPAdapters() []adapters.Adapter        { return AdaptersFor("php") }
func CSharpAdapters() []adapters.Adapter     { return AdaptersFor("csharp") }
func CAdapters() []adapters.Adapter          { return AdaptersFor("c") }
func CPPAdapters() []adapters.Adapter        { return AdaptersFor("cpp") }
func RustAdapters() []adapters.Adapter       { return AdaptersFor("rust") }
func BashAdapters() []adapters.Adapter       { return AdaptersFor("bash") }
func ScalaAdapters() []adapters.Adapter      { return AdaptersFor("scala") }
func LuaAdapters() []adapters.Adapter        { return AdaptersFor("lua") }
func KotlinAdapters() []adapters.Adapter     { return AdaptersFor("kotlin") }
func PowerShellAdapters() []adapters.Adapter { return AdaptersFor("powershell") }
func SwiftAdapters() []adapters.Adapter      { return AdaptersFor("swift") }
func PerlAdapters() []adapters.Adapter       { return AdaptersFor("perl") }
func SolidityAdapters() []adapters.Adapter   { return AdaptersFor("solidity") }
func ObjCAdapters() []adapters.Adapter       { return AdaptersFor("objc") }

// containsStr reports whether xs contains v.
func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

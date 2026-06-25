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
	Concept    string
	Paths      []string
	Methods    []string // receiver-agnostic: match the call's `method` prop (last segment)
	Match      string   // "prefix" (default) | "contains"
	Receiver   bool     // match a receiver attribute/method with a recv_type constraint
	Constraint string   // optional `on <type>` receiver-type constraint
	ValMatches []string // `val "substr"` (AND) — only a source when an arg literal matches
	ValAbsents []string // `nval "substr"` (AND) — not a source if any arg literal contains a substr
	Packages   []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
}

type sinkSpec struct {
	Concept         string
	Pattern         string
	ByMethod        bool     // match the bare method name vs the dotted callee path
	Exact           bool     // exact path match instead of segment-prefix path matching
	Receiver        bool     // tainted data is the RECEIVER, not an arg — label the call node
	Constraint      string   // optional `on <type>` receiver-type constraint
	ArgIndex        int      // which argument position is targeted (default 0)
	ValMatches      []string // `val "substr"` (AND) — every substr must be in some arg/option literal
	ValAbsents      []string // `nval "substr"` (AND) — no arg/option literal may contain any substr
	Packages        []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
	Collection      bool     // also flag a Seq/collection-literal arg
	CollectionFirst bool     // label a specific element of a Seq/collection arg when present
	CollectionIndex int      // selected collection element index
}

type controlSpec struct {
	Concept    string
	Pattern    string
	ByMethod   bool     // match the call's `method` prop (receiver-agnostic, e.g. .close())
	Receiver   bool     // label the call receiver node instead of the call result
	Exact      bool     // exact path match instead of segment-prefix path matching
	ValMatches []string // `val "substr"` (AND — marks AND controls)
	ValAbsents []string // `nval "substr"` (AND — marks AND controls)
	Packages   []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
}

type flagPredicate struct {
	Subject  string
	Property string
	Op       string
	Values   []string
	Exact    bool
	Negative bool
}

type flagOperandSpec struct {
	Predicates []flagPredicate
}

type flagSpec struct {
	Concept    string
	NodeKind   string
	Scope      string
	Predicates []flagPredicate
	Operands   []flagOperandSpec
	Packages   []string
}

// activeSources, when non-nil, restricts which source concepts the input adapters
// emit for the active analysis profile. nil = every source active.
var activeSources map[string]bool

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

type flowTokenIndex struct {
	built bool
	rev   map[string][]string
	fwd   map[string][]string
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
	return len(vals) == 0 && len(nvals) == 0 || valConds(n.Prop("str_args"), vals, nvals)
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
		files, err := filepath.Glob(filepath.Join(datadir.Root(), "ontology", "*.vyql"))
		if err != nil {
			panic("frontend: glob ontology/*.vyql: " + err.Error())
		}
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				panic("frontend: read " + file + ": " + err.Error())
			}
			decls, err := parser.Parse(string(raw))
			if err != nil {
				panic("frontend: parse " + file + ": " + err.Error())
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
		}
	})
	return conceptDetails
}

func ontologyRoleConcepts(role string) map[string]bool {
	conceptRoleOnce.Do(func() {
		conceptRoles = map[string]map[string]bool{}
		for _, c := range ontology.Seed().AllConcepts() {
			if c.AnalysisRole == "" {
				continue
			}
			if conceptRoles[c.AnalysisRole] == nil {
				conceptRoles[c.AnalysisRole] = map[string]bool{}
			}
			conceptRoles[c.AnalysisRole][c.QualifiedName()] = true
		}
	})
	return conceptRoles[role]
}

func singleOntologyRoleConcept(role string) string {
	var out string
	for c := range ontologyRoleConcepts(role) {
		if out != "" {
			return ""
		}
		out = c
	}
	return out
}

type filterSpec struct {
	Pattern  string
	ByMethod bool // match the bare method name (x.replace) vs the dotted path (re.sub)
	Global   bool // always-global replace (gsub/replaceAll/re.sub); else needs the /g flag
	Packages []string
}

// assumeSpec is an UNSOUND neutralizer: a guard (dominance) or sanitizer (on-path) that
// might apply but cannot be proven to. It never kills a flow; the engine
// attaches an assumption note instead.
type assumeSpec struct {
	Pattern    string
	ByMethod   bool
	Mode       string // "guard" (must dominate the sink) | "sanitizer" (must lie on the path)
	About      string // the sink concept it purports to cover
	ValMatches []string
	ValAbsents []string
	Packages   []string
}

type paramSourceSpec struct {
	Concept  string
	Packages []string
}

type adapterSpec struct {
	Name          string
	Technology    string
	containsMatch bool
	crossLang     bool // labels nodes in EVERY language (skips the per-tech filter)
	Inputs        []inputSpec
	Sinks         []sinkSpec
	Controls      []controlSpec
	Marks         []controlSpec // presence markers (label the call node with a concept)
	Flags         []flagSpec
	Filters       []filterSpec
	Assumes       []assumeSpec
	ParamSources  []paramSourceSpec // `source param -> X`: concepts to label parameter nodes with
}

// AdaptersFor loads the framework adapters for a technology from
// vyql/adapters/<tech>.vyql and builds the input + sink + control adapters.
func AdaptersFor(tech string) []adapters.Adapter {
	out := adaptersFromSpec(loadSpec(tech))
	if tech == "javascript" {
		out = append(out, jsDomValueInputAdapter())
		out = append(out, jsPathRegexGuardAdapter())
		out = append(out, jsSafePathResolverAdapter())
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
		decls, err := parser.Parse(string(b))
		if err != nil {
			return nil, err
		}
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			if len(allowed) > 0 && !allowed[ad.Name] {
				return nil, fmt.Errorf("overlay adapter %s declares %q, which is not present in this scan", file, ad.Name)
			}
			spec := specFromDecl(ad)
			spec.Name = "agentic." + spec.Name
			out = append(out, adaptersFromSpec(spec)...)
		}
	}
	return out, nil
}

// adaptersFromSpec turns a built adapterSpec into the concrete adapter set (one adapter
// per mapping kind present). Shared by AdaptersFor and the dynamic package loader.
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
	if len(spec.Assumes) > 0 {
		out = append(out, spec.assumeAdapter())
	}
	return out
}

// assumeAdapter labels unsound-neutralizer calls (guards/transforms that cannot be proven
// sound) with the ontology role concept that the engine can surface as review context.
func (spec adapterSpec) assumeAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.AnalysisRoleNeutralizerAssumption)
	return adapters.Adapter{
		Name: spec.Name + ".assumptions", Technology: spec.Technology, Specificity: 2,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			allowed := make([]bool, len(spec.Assumes))
			for i := range spec.Assumes {
				allowed[i] = packageAllowed(spec.Assumes[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); !spec.crossLang && t != "" && t != spec.Technology {
					continue
				}
				method, path := n.Prop("method"), n.Prop("callee_path")
				for ai, as := range spec.Assumes {
					if !allowed[ai] {
						continue
					}
					if !(as.ByMethod && method == as.Pattern || !as.ByMethod && matchSinkPath(path, as.Pattern)) {
						continue
					}
					if !valCondsDirectForNode(n, as.ValMatches, as.ValAbsents) {
						continue
					}
					out = append(out, adapters.Mapping{NodeID: id, Concept: concept,
						Detail: map[string]string{"mode": as.Mode, "about": as.About, "pattern": as.Pattern}})
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
// as an assumption note. The regex math is general (charfilter.go); WHICH methods
// filter is data (the `filter` directive).
func (spec adapterSpec) filterAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.AnalysisRoleCharFilter)
	return adapters.Adapter{
		Name: spec.Name + ".filters", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			allowed := make([]bool, len(spec.Filters))
			for i := range spec.Filters {
				allowed[i] = packageAllowed(spec.Filters[i].Packages, pkgs)
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
					if f.ByMethod && method == f.Pattern || !f.ByMethod && matchSinkPath(path, f.Pattern) {
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

// CtorTypesFor returns the constructor→type table declared in the adapter (for example,
// `type "pkg.Open" -> pkg.Handle`), used by the lowering to stamp recv_type.
func CtorTypesFor(tech string) map[string]string {
	out := map[string]string{}
	for _, mp := range loadDecl(tech).Mappings {
		if mp.Kind == "type" {
			out[mp.Pattern] = mp.Concept
		}
	}
	return out
}

func loadDecl(tech string) *parser.AdapterDecl {
	src := string(datadir.MustRead("adapters/" + tech + ".vyql"))
	if extra, err := datadir.Read("adapters/packages/" + tech + ".vyql"); err == nil {
		src += "\n" + string(extra)
	}
	decls, err := parser.Parse(src)
	if err != nil {
		panic("frontend: invalid adapters/" + tech + ".vyql: " + err.Error())
	}
	var merged *parser.AdapterDecl
	for _, d := range decls {
		a, ok := d.(*parser.AdapterDecl)
		if !ok || a.Name != tech {
			continue
		}
		if merged == nil {
			merged = &parser.AdapterDecl{Name: a.Name, Meta: a.Meta}
		} else {
			for k, v := range a.Meta {
				merged.Meta[k] = v
			}
		}
		merged.Mappings = append(merged.Mappings, a.Mappings...)
	}
	if merged != nil {
		return merged
	}
	panic("frontend: no adapter declaration in adapters/" + tech + ".vyql")
}

func loadSpec(tech string) adapterSpec {
	return specFromDecl(loadDecl(tech))
}

// specFromDecl builds an adapterSpec from an already-parsed adapter declaration.
// Split out of loadSpec so the dynamic per-package adapter loader (packages.go) can
// reuse the exact same mapping→spec lowering for the generated catalog.
func specFromDecl(d *parser.AdapterDecl) adapterSpec {
	s := adapterSpec{Name: d.Name, Technology: d.Name}
	if m, _ := d.Meta["match"].(string); m == "contains" {
		s.containsMatch = true
	}
	if cl, _ := d.Meta["cross_language"].(string); cl == "true" {
		s.crossLang = true
	}
	matchMode := "prefix"
	if s.containsMatch {
		matchMode = "contains"
	}
	srcByConcept := map[string]int{}
	for _, mp := range d.Mappings {
		switch mp.Kind {
		case "source":
			// a value-constrained source gets its own spec so the
			// val/nval filter is not shared with other patterns mapping to the same concept.
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(mp.Packages) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Paths: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Paths = append(s.Inputs[i].Paths, mp.Pattern)
		case "source_method":
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(mp.Packages) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Methods: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Methods = append(s.Inputs[i].Methods, mp.Pattern)
		case "source_param":
			s.ParamSources = append(s.ParamSources, paramSourceSpec{Concept: mp.Concept, Packages: mp.Packages})
		case "source_receiver":
			s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
				Methods: []string{mp.Pattern}, Receiver: true, Constraint: mp.Constraint,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "sink_method":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex})
		case "sink_path":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, Exact: mp.Exact, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages, Collection: mp.Collection, CollectionFirst: mp.CollectionFirst, CollectionIndex: mp.CollectionIndex})
		case "sink_receiver":
			// the tainted DATA is the receiver of a no-arg method; match the bare
			// method name and label the call node itself.
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Receiver: true, Constraint: mp.Constraint, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "control":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "control_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "control_receiver_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, Receiver: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "mark":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "mark_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "flag":
			if mp.Flag != nil {
				fs := flagSpec{Concept: mp.Concept, NodeKind: mp.Flag.NodeKind, Scope: mp.Flag.Scope, Packages: mp.Packages}
				for _, pred := range mp.Flag.Predicates {
					fs.Predicates = append(fs.Predicates, flagPredicate{
						Subject: pred.Subject, Property: pred.Property, Op: pred.Op, Values: pred.Values, Exact: pred.Exact, Negative: pred.Negative,
					})
				}
				for _, operand := range mp.Flag.Operands {
					var os flagOperandSpec
					for _, pred := range operand.Predicates {
						os.Predicates = append(os.Predicates, flagPredicate{
							Subject: pred.Subject, Property: pred.Property, Op: pred.Op, Values: pred.Values, Exact: pred.Exact, Negative: pred.Negative,
						})
					}
					fs.Operands = append(fs.Operands, os)
				}
				s.Flags = append(s.Flags, fs)
			}
		case "filter_method":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, ByMethod: true, Global: mp.Constraint == "global", Packages: mp.Packages})
		case "filter_path":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, Global: mp.Constraint == "global", Packages: mp.Packages})
		case "assume_guard_method", "assume_guard_path", "assume_sanitizer_method", "assume_sanitizer_path":
			mode := "guard"
			if strings.Contains(mp.Kind, "sanitizer") {
				mode = "sanitizer"
			}
			s.Assumes = append(s.Assumes, assumeSpec{Pattern: mp.Pattern, ByMethod: strings.HasSuffix(mp.Kind, "_method"),
				Mode: mode, About: mp.About, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		}
	}
	return s
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
			inIdx := buildSpecIndex(len(spec.Inputs), func(i int) (methods, paths []string, loose bool) {
				return spec.Inputs[i].Methods, spec.Inputs[i].Paths, spec.Inputs[i].Match == "contains"
			})
			// package gating is node-independent (pkgs is constant for this Apply), so
			// resolve it once per spec instead of re-running the costly evidence match per node.
			allowed := make([]bool, len(spec.Inputs))
			for i := range spec.Inputs {
				allowed[i] = packageAllowed(spec.Inputs[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			rangeCallablePropNodes(s, func(n usg.Node) bool {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" {
					return true
				}
				if t := nodeTechFromNode(n); !spec.crossLang && t != "" && t != spec.Technology {
					return true // only label this language's nodes (cross-language adapters skip this)
				}
				for _, ci := range inIdx.candidates(method, path) {
					in := spec.Inputs[ci]
					if !allowed[ci] {
						continue
					}
					matched := (path != "" && matchPath(path, in.Paths, in.Match)) ||
						(method != "" && containsStr(in.Methods, method))
					if in.Receiver {
						matched = method != "" && containsStr(in.Methods, method) &&
							constraintAllows(in.Constraint, n.Prop("recv_type"))
					}
					if matched {
						// value-constrained source: only a source when configured literal
						// tokens are present or absent as declared by the adapter.
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valCondsDirectForNode(n, in.ValMatches, in.ValAbsents) {
							continue
						}
						// active-profile gating: a profile restricts which
						// source families are active for this profile.
						if activeSources == nil || activeSources[in.Concept] {
							spec := 0
							if len(in.Packages) > 0 {
								spec = 3 // package-specific source supersedes native/general
							}
							out = append(out, adapters.Mapping{NodeID: n.ID, Concept: in.Concept, Specificity: spec})
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
	attributeSinks := ontologyRoleConcepts(ontology.AnalysisRoleAttributeSink)
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
			sinkIdx := buildSpecIndex(len(spec.Sinks), func(i int) (methods, paths []string, loose bool) {
				if spec.Sinks[i].ByMethod {
					return []string{spec.Sinks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Sinks[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Sinks))
			for i := range spec.Sinks {
				allowed[i] = packageAllowed(spec.Sinks[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			var flowIdx flowTokenIndex
			var collectionIdx collectionFlowIndex
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
					if !allowed[i] {
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
					if !hit {
						continue
					}
					// Most specific wins: longer pattern, then more value constraints
					// (a `val`-matched sink is more specific than the plain form).
					// Keyed by (concept,
					// ARG INDEX): the same concept can be injectable at MULTIPLE arg
					// positions of one call, so those must not collapse together.
					bkey := sk.Concept + "\x00" + strconv.Itoa(sk.ArgIndex)
					if curIdx, ok := bestByConcept[bkey]; !ok {
						bestByConcept[bkey] = i
					} else if cur := spec.Sinks[curIdx]; len(sk.Pattern) > len(cur.Pattern) ||
						(len(sk.Pattern) == len(cur.Pattern) && len(sk.ValMatches) > len(cur.ValMatches)) {
						bestByConcept[bkey] = i
					}
				}
				for _, i := range cand {
					sk := spec.Sinks[i]
					best, ok := bestByConcept[sk.Concept+"\x00"+strconv.Itoa(sk.ArgIndex)]
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
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Specificity: pkgSpec, Detail: detail})
						} else {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "resolved", Confidence: conf, Specificity: pkgSpec, Detail: detail})
						}
						continue
					}
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						detail, conf := reviewDetail(sk.Concept, sk.Pattern)
						out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
							if sk.CollectionFirst {
								if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
									target = first
								}
							}
							if a, ok, _ := s.GetNode(arg); ok && !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
								continue
							}
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Specificity: pkgSpec, Detail: detail})
						}
						continue
					}
					arg := n.Prop("arg" + strconv.Itoa(sk.ArgIndex))
					if arg == "" {
						continue
					}
					target := arg
					if sk.CollectionFirst {
						if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
							target = first
						}
					}
					if a, ok, _ := s.GetNode(arg); ok && !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
						continue
					}
					detail, conf := reviewDetail(sk.Concept, sk.Pattern)
					out = append(out, adapters.Mapping{NodeID: target, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Specificity: pkgSpec, Detail: detail})
				}
			}
			return out
		},
	}
}

// controlAdapter labels control concepts (transforms/validators) on the calls that
// apply them, so `unless sanitized_by` can suppress a sanitized flow (docs/07).
func (spec adapterSpec) controlAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".controls", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			ctrlIdx := buildSpecIndex(len(spec.Controls), func(i int) (methods, paths []string, loose bool) {
				if spec.Controls[i].ByMethod {
					return []string{spec.Controls[i].Pattern}, nil, false
				}
				return nil, []string{spec.Controls[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Controls))
			for i := range spec.Controls {
				allowed[i] = packageAllowed(spec.Controls[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTechFromNode(n); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				path, method := n.Prop("callee_path"), n.Prop("method")
				for _, ci := range ctrlIdx.candidates(method, path) {
					c := spec.Controls[ci]
					if !allowed[ci] {
						continue
					}
					// no break: a single call can be MULTIPLE controls, so attach every match.
					hit := c.ByMethod && method == c.Pattern || !c.ByMethod && matchPath(path, []string{c.Pattern}, "prefix")
					if hit && valCondsDirectForNode(n, c.ValMatches, c.ValAbsents) {
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
						out = append(out, adapters.Mapping{NodeID: nodeID, Concept: c.Concept, Specificity: spec})
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
	add := func(v string) {
		v = sca.NormalizePackageName(v)
		if v == "" {
			return
		}
		out[v] = true
		if root := sca.PackageRoot(v); root != "" {
			out[root] = true
		}
		// expand import→distribution aliases so package-scoped
		// adapters keyed by the distribution name activate from imports, not just manifests.
		for _, a := range sca.ImportAliases(v) {
			out[a] = true
		}
	}
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
		add(n.Prop("module"))
		add(n.Prop("symbol"))
		add(n.Prop("package"))
		add(n.Prop("root"))
	}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		if n, ok, _ := s.GetNode(id); ok {
			add(n.Prop("name"))
		}
	}
	return out
}

func packageAllowed(want []string, have map[string]bool) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if packageInEvidence(w, have) {
			return true
		}
	}
	return false
}

func packageInEvidence(want string, have map[string]bool) bool {
	want = sca.NormalizePackageName(want)
	if want == "" {
		return true
	}
	if have[want] {
		return true
	}
	if root := sca.PackageRoot(want); root != "" && have[root] {
		return true
	}
	for got := range have {
		if sca.PackageMatches(got, want) {
			return true
		}
	}
	return false
}

// flagAdapter labels nodes with presence/review concepts through the AST-shaped
// `flag <concept> on|in ... { ... }` DSL.
func (spec adapterSpec) flagAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".flags", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			fileTech := fileContextTechs(s)
			allowed := make([]bool, len(spec.Flags))
			for i := range spec.Flags {
				allowed[i] = packageAllowed(spec.Flags[i].Packages, pkgs)
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
			var flowIdx flowTokenIndex
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
						if !allowed[i] {
							continue
						}
						fl := spec.Flags[i]
						if !flagNodeKindAllows(fl, n) {
							continue
						}
						if !flagMatchesNode(s, &flowIdx, fl, n, spec.Technology, spec.crossLang, fileTech) {
							continue
						}
						detail, conf := reviewDetail(fl.Concept, flagPattern(fl))
						specificity := 0
						if len(fl.Packages) > 0 {
							specificity = 3
						}
						out = append(out, adapters.Mapping{NodeID: n.ID, Concept: fl.Concept, Confidence: conf, Specificity: specificity, Detail: detail})
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

func flagMatchesNode(s usg.Store, idx *flowTokenIndex, fl flagSpec, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
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
	operands := flagOperandCandidates(s, idx, n)
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

func flagPredicateMatches(s usg.Store, idx *flowTokenIndex, pred flagPredicate, n usg.Node, tech string, crossLang bool, fileTech map[string]string) bool {
	if pred.Subject == "flow_to" {
		hit := flagFlowToNodeHit(s, idx, pred, n, tech, crossLang, fileTech)
		if pred.Negative {
			return !hit
		}
		return hit
	}
	if pred.Subject == "scope_call" {
		hit := flagScopeNodeHit(s, pred, n, []string{"code.Call"}, tech, crossLang)
		if pred.Negative {
			return !hit
		}
		return hit
	}
	if n.Prop("callee_path") == "analysis.function.context" ||
		n.Prop("callee_path") == "analysis.module.context" ||
		n.Prop("callee_path") == "analysis.class.context" {
		if ok, hit := flagContextPredicateMatchesAST(s, pred, n, tech, crossLang); ok {
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

func flagContextPredicateMatchesAST(s usg.Store, pred flagPredicate, n usg.Node, tech string, crossLang bool) (bool, bool) {
	if pred.Property != "tokens" || len(pred.Values) == 0 {
		return false, false
	}
	var probe flagPredicate
	var nodeTypes []string
	for _, v := range pred.Values {
		switch {
		case strings.HasPrefix(v, "call_arg:"):
			return true, flagScopeCallArgHit(s, pred, n, tech, crossLang)
		case strings.HasPrefix(v, "call_path:"):
			probe = flagPredicate{Property: "path", Op: pred.Op, Values: trimFlagValuePrefix(pred.Values, "call_path:"), Exact: pred.Exact}
			nodeTypes = []string{"code.Call"}
		case strings.HasPrefix(v, "call:"):
			probe = flagPredicate{Property: "method", Op: pred.Op, Values: trimFlagValuePrefix(pred.Values, "call:"), Exact: pred.Exact}
			nodeTypes = []string{"code.Call"}
		case strings.HasPrefix(v, "literal:"):
			probe = flagPredicate{Property: "tokens", Op: pred.Op, Values: trimFlagValuePrefix(pred.Values, "literal:"), Exact: pred.Exact}
			nodeTypes = []string{"code.Const"}
		case strings.HasPrefix(v, "identifier:"):
			probe = flagPredicate{Property: "identifier", Op: pred.Op, Values: trimFlagValuePrefix(pred.Values, "identifier:"), Exact: pred.Exact}
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
			probe = flagPredicate{Property: prop, Op: pred.Op, Values: trimFlagValuePrefix(pred.Values, prefix), Exact: pred.Exact}
			nodeTypes = []string{"code.Attr"}
		case strings.HasPrefix(v, "index:"), strings.HasPrefix(v, "subscript:"):
			prefix := "index:"
			if strings.HasPrefix(v, "subscript:") {
				prefix = "subscript:"
			}
			return true, flagScopeSubscriptHit(s, pred, n, trimFlagValuePrefix(pred.Values, prefix), tech, crossLang)
		case strings.HasPrefix(v, "binary:"), strings.HasPrefix(v, "expr:"):
			prefix := "binary:"
			if strings.HasPrefix(v, "expr:") {
				prefix = "expr:"
			}
			return true, flagScopeBinopHit(s, pred, n, trimFlagValuePrefix(pred.Values, prefix), tech, crossLang)
		case strings.HasPrefix(v, "name="), strings.HasPrefix(v, "function_name:"):
			return false, false
		default:
			return false, false
		}
	}
	return true, flagScopeNodeHit(s, probe, n, nodeTypes, tech, crossLang)
}

func flagScopeBinopHit(s usg.Store, pred flagPredicate, n usg.Node, values []string, tech string, crossLang bool) bool {
	prefix := locFile(n.Prop("loc"))
	scope := nodeLexicalScope(n)
	ids, _ := s.NodesOfType("code.BinOp")
	for _, id := range ids {
		cand, ok, err := s.GetNode(id)
		if err != nil || !ok || cand.ID == n.ID {
			continue
		}
		candScope := nodeLexicalScope(cand)
		if scope != "" && candScope != "" && !sameOrNestedScope(candScope, scope) {
			continue
		}
		if prefix != "" && locFile(cand.Prop("loc")) != prefix {
			continue
		}
		if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
			continue
		}
		if binopPredicateMatches(s, pred.Op, values, cand) {
			return true
		}
	}
	return false
}

func binopPredicateMatches(s usg.Store, op string, values []string, n usg.Node) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any" && op != "any"
	for _, value := range values {
		hit := binopValueMatches(s, value, n)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func binopValueMatches(s usg.Store, value string, n usg.Node) bool {
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
	operands := flagOperandCandidates(s, &flowTokenIndex{}, n)
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

func flagScopeSubscriptHit(s usg.Store, pred flagPredicate, n usg.Node, values []string, tech string, crossLang bool) bool {
	prefix := locFile(n.Prop("loc"))
	scope := nodeLexicalScope(n)
	ids, _ := s.NodesOfType("code.Subscript")
	for _, id := range ids {
		cand, ok, err := s.GetNode(id)
		if err != nil || !ok || cand.ID == n.ID {
			continue
		}
		candScope := nodeLexicalScope(cand)
		if scope != "" && candScope != "" && !sameOrNestedScope(candScope, scope) {
			continue
		}
		if prefix != "" && locFile(cand.Prop("loc")) != prefix {
			continue
		}
		if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
			continue
		}
		if subscriptPredicateMatches(pred.Op, values, cand) {
			return true
		}
	}
	return false
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

func flagScopeCallArgHit(s usg.Store, pred flagPredicate, n usg.Node, tech string, crossLang bool) bool {
	prefix := locFile(n.Prop("loc"))
	scope := nodeLexicalScope(n)
	ids, _ := s.NodesOfType("code.Call")
	for _, id := range ids {
		cand, ok, err := s.GetNode(id)
		if err != nil || !ok || cand.ID == n.ID {
			continue
		}
		candScope := nodeLexicalScope(cand)
		if scope != "" && candScope != "" && !sameOrNestedScope(candScope, scope) {
			continue
		}
		if prefix != "" && locFile(cand.Prop("loc")) != prefix {
			continue
		}
		if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
			continue
		}
		if contextTokenValuePredicate(pred.Op, pred.Values, callArgContextTokensScoped(s, cand, tech, crossLang)) {
			return true
		}
	}
	return false
}

func callArgContextTokensScoped(s usg.Store, n usg.Node, tech string, crossLang bool) string {
	tokens := callArgContextTokens(n)
	path := n.Prop("callee_path")
	method := n.Prop("method")
	if path == "" && method == "" {
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
	argIDs, _ := s.NodesOfType("code.Arg")
	for _, argID := range argIDs {
		arg, ok, err := s.GetNode(argID)
		if err != nil || !ok || !scopedCallArgCandidate(arg, n, tech, crossLang) || !nodeFlowsTo(s, arg.ID, n.ID) {
			continue
		}
		addNode(arg)
		for _, nodeType := range []string{"code.Format", "code.Const", "code.Name", "code.Attr", "code.Seq", "code.Call"} {
			ids, _ := s.NodesOfType(nodeType)
			for _, srcID := range ids {
				src, ok, err := s.GetNode(srcID)
				if err != nil || !ok || !scopedCallArgCandidate(src, n, tech, crossLang) || !nodeFlowsTo(s, src.ID, arg.ID) {
					continue
				}
				addNode(src)
			}
		}
	}
	return strings.Join(out, "\x00")
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

func nodeFlowsTo(s usg.Store, srcID, dstID string) bool {
	edges, _ := s.OutEdges(srcID, "FLOWS")
	for _, e := range edges {
		if e.Dst == dstID {
			return true
		}
	}
	return false
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

func flagScopeNodeHit(s usg.Store, pred flagPredicate, n usg.Node, nodeTypes []string, tech string, crossLang bool) bool {
	probe := pred
	probe.Negative = false
	prefix := locFile(n.Prop("loc"))
	scope := nodeLexicalScope(n)
	for _, nodeType := range nodeTypes {
		ids, _ := s.NodesOfType(nodeType)
		for _, id := range ids {
			cand, ok, err := s.GetNode(id)
			if err != nil || !ok || cand.ID == n.ID {
				continue
			}
			candScope := nodeLexicalScope(cand)
			if scope != "" {
				if candScope != "" {
					if !sameOrNestedScope(candScope, scope) {
						continue
					}
				} else if !unscopedNodeBelongsToScopedContext(cand, n) {
					continue
				}
			}
			if prefix != "" && locFile(cand.Prop("loc")) != prefix {
				continue
			}
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				continue
			}
			if flagPredicateMatchesNodeOnly(probe, cand) {
				return true
			}
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
		return valuePredicate(pred.Op, pred.Values, n.Prop("op"))
	case "tokens":
		if flagPredicateUsesCallArg(pred) {
			return contextTokenValuePredicate(pred.Op, pred.Values, callArgContextTokens(n))
		}
		return contextTokenValuePredicate(pred.Op, pred.Values, n.Prop("str_args"))
	case "identifier":
		if n.Type != "code.Name" && n.Type != "code.Param" {
			return false
		}
		return valuePredicate(pred.Op, pred.Values, n.Prop("callee_path")+"\x00"+n.Prop("method")+"\x00"+n.Prop("name")+"\x00"+n.ID)
	case "key":
		return valuePredicate(pred.Op, pred.Values, n.Prop("str_args")+"\x00"+n.Prop("callee_path"))
	case "call":
		if n.Type != "code.Call" {
			return false
		}
		return valuePredicate(pred.Op, pred.Values, nodeSearchText(n))
	case "any":
		return valuePredicate(pred.Op, pred.Values, nodeSearchText(n))
	default:
		return valuePredicate(pred.Op, pred.Values, n.Prop(pred.Property))
	}
}

func contextTokenValuePredicate(op string, values []string, text string) bool {
	if op == "equals" || op == "equals_any" {
		if contextTokenEqualsPredicate(op, values, text) {
			return true
		}
	}
	if op == "contains" || op == "" || op == "contains_any" {
		if contextTokenContainsPredicate(op, values, text) {
			return true
		}
	}
	return valuePredicate(op, values, text)
}

func contextTokenEqualsPredicate(op string, values []string, text string) bool {
	if len(values) == 0 {
		return false
	}
	all := op != "equals_any"
	for _, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			for _, tok := range strings.Split(text, "\x00") {
				if strings.HasPrefix(tok, prefix) && strings.TrimPrefix(tok, prefix) == want {
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
	if len(values) == 0 {
		return false
	}
	all := op != "contains_any"
	for _, v := range values {
		prefix, want, ok := splitContextTokenPredicateValue(v)
		hit := false
		if ok {
			for _, tok := range strings.Split(text, "\x00") {
				if strings.HasPrefix(tok, prefix) && valContains(strings.TrimPrefix(tok, prefix), want) {
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

func splitContextTokenPredicateValue(v string) (prefix, want string, ok bool) {
	for _, sep := range []string{":", "="} {
		if i := strings.Index(v, sep); i > 0 {
			return v[:i+1], v[i+1:], true
		}
	}
	return "", "", false
}

func valuePredicate(op string, values []string, text string) bool {
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
		for _, v := range values {
			if valContains(text, v) {
				return true
			}
		}
		return false
	default:
		for _, v := range values {
			if !valContains(text, v) {
				return false
			}
		}
		return true
	}
}

func nodeSearchText(n usg.Node) string {
	return strings.Join([]string{n.Type, n.Prop("callee_path"), n.Prop("method"), n.Prop("op"), n.Prop("str_args")}, "\x00")
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
			markIdx := buildSpecIndex(len(spec.Marks), func(i int) (methods, paths []string, loose bool) {
				if spec.Marks[i].ByMethod {
					return []string{spec.Marks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Marks[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Marks))
			for i := range spec.Marks {
				allowed[i] = packageAllowed(spec.Marks[i].Packages, pkgs)
			}
			nodeTypes := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary"}
			if crossLang {
				nodeTypes = append(nodeTypes, "sbom.PackageVersion")
			}
			for _, nodeType := range nodeTypes {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, _, _ := s.GetNode(id)
					if t := nodeTechFromNode(n); !crossLang && t != "" && t != spec.Technology {
						continue
					}
					path := n.Prop("callee_path")
					method := n.Prop("method")
					seenConcept := map[string]bool{}
					for _, mi := range markIdx.candidates(method, path) {
						m := spec.Marks[mi]
						if !allowed[mi] {
							continue
						}
						if seenConcept[m.Concept] {
							continue
						}
						hit := m.ByMethod && method == m.Pattern ||
							!m.ByMethod && ((m.Exact && path == m.Pattern) || (!m.Exact && matchSinkPath(path, m.Pattern)))
						if !hit {
							continue
						}
						if !valCondsDirectForNode(n, m.ValMatches, m.ValAbsents) {
							continue
						}
						detail, conf := reviewDetail(m.Concept, m.Pattern)
						spec := 0
						if len(m.Packages) > 0 {
							spec = 3 // package-specific mark supersedes native/general
						}
						out = append(out, adapters.Mapping{NodeID: id, Concept: m.Concept, Confidence: conf, Specificity: spec, Detail: detail})
						seenConcept[m.Concept] = true
					}
				}
			}
			return out
		},
	}
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

// Per-language adapter sets (loaded from vyql/adapters/*.vyql).
func ConfigAdapters() []adapters.Adapter      { return AdaptersFor("config") }
func TextPatternAdapters() []adapters.Adapter { return AdaptersFor("textpattern") }

// AutoAdapters returns adapter declarations that opt into whole-graph application through
// `meta { auto_apply: graph }`.
func AutoAdapters() []adapters.Adapter {
	files, err := filepath.Glob(filepath.Join(datadir.Root(), "adapters", "*.vyql"))
	if err != nil {
		panic("frontend: glob adapters/*.vyql: " + err.Error())
	}
	sort.Strings(files)
	var out []adapters.Adapter
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			panic("frontend: read " + file + ": " + err.Error())
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			panic("frontend: parse " + file + ": " + err.Error())
		}
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			if mode, _ := ad.Meta["auto_apply"].(string); mode == "graph" {
				out = append(out, adaptersFromSpec(specFromDecl(ad))...)
			}
		}
	}
	return out
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
			active := make([]paramSourceSpec, 0, len(sources))
			for _, src := range sources {
				if activeSources[src.Concept] && packageAllowed(src.Packages, pkgs) {
					active = append(active, src)
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
				for _, src := range active {
					spec := 0
					if len(src.Packages) > 0 {
						spec = 3
					}
					out = append(out, adapters.Mapping{NodeID: id, Concept: src.Concept, Specificity: spec})
				}
			}
			return out
		},
	}
}

func jsPathRegexGuardAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.AnalysisRolePathAccessCheck)
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
				out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2})
			}
			return out
		},
	}
}

func jsDomValueInputAdapter() adapters.Adapter {
	concept := singleOntologyRoleConcept(ontology.AnalysisRoleDomInput)
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
	concept := singleOntologyRoleConcept(ontology.AnalysisRolePathAccessCheck)
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
						out = append(out, adapters.Mapping{NodeID: id, Concept: concept, Specificity: 2})
						break
					}
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
	concept := singleOntologyRoleConcept(ontology.AnalysisRoleProcessArgVector)
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

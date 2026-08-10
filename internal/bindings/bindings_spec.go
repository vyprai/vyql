// Compiling authored binding data into specs: parse the corpus, fold in the ontology, and build
// the per-family spec each applicator family is constructed from.

package bindings

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
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

func bindingApplicatorsFromSpec(spec bindingSpec) []Applicator {
	var out []Applicator
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

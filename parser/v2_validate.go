package parser

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

var (
	v2ProjectFamilies = map[string]bool{
		"file": true, "dependency": true, "package": true, "language": true,
		"build": true, "repository": true, "manifest": true,
	}
	v2CodeFamilies = map[string]bool{
		"call": true, "memberAccess": true, "assignment": true, "binaryExpr": true,
		"literal": true, "stringLiteral": true, "function": true, "class": true, "import": true,
		"route": true, "config": true, "param": true,
	}
	v2SchemaGatedCodeFamilies = map[string]string{"route": "nir", "config": "nir"}
	v2SemanticFamilies        = map[string]bool{
		"concept": true, "finding": true, "exposure": true, "asset": true,
		"principal": true, "privilege": true, "state": true,
	}
	v2RequirementPrimitives = map[string]bool{
		"language": true, "dependency": true, "import": true, "file": true,
		"framework": true, "schema": true, "project.has": true,
	}
	v2RequirementCombinators   = map[string]bool{"all": true, "any": true, "not": true, "soft": true}
	v2CoverageModes            = map[string]bool{"path": true, "endpoint": true, "sameReceiver": true, "sameScope": true, "dominates": true, "postDominates": true, "global": true}
	v2BuiltInRuleVerbs         = map[string]bool{"taint": true, "reach": true, "grant": true, "issue": true, "fact": true, "query": true}
	v2ConceptKinds             = map[string]bool{"source": true, "sink": true, "check": true, "issue": true, "fact": true, "asset": true, "exposure": true, "principal": true, "privilege": true, "state": true}
	v2MechanicKinds            = map[string]bool{"ruleVerb": true, "coverage": true, "context": true, "requirement": true}
	v2ImplementedMechanicKinds = map[string]bool{"ruleVerb": true, "coverage": true}
	v2PolicyKinds              = map[string]bool{"resultLifecycle": true, "resultIdentity": true, "confidence": true, "priority": true, "display": true, "diagnostic": true}
	v2ImplementedPolicyKinds   = map[string]bool{"resultLifecycle": true, "resultIdentity": true, "confidence": true, "priority": true, "display": true, "diagnostic": true}
	v2MechanicCapabilities     = map[string]bool{"coverage.path": true, "coverage.endpoint": true, "coverage.sameReceiver": true, "coverage.sameScope": true, "coverage.dominates": true, "coverage.postDominates": true, "coverage.global": true, "dataflow.taint": true, "graph.reach": true, "graph.grant": true, "fact.exists": true, "query.semantic": true}
	v2RuleClauseKinds          = map[string]bool{"where": true, "coveredBy": true, "confidence": true, "profile": true}
	v2EmitKinds                = map[string]bool{"source": true, "sink": true, "check": true, "issue": true, "fact": true}
	v2FactEmitKinds            = map[string]bool{"fact": true, "asset": true, "exposure": true, "principal": true, "privilege": true, "state": true}
	v2PropagateKinds           = map[string]bool{"value": true, "taint": true, "identity": true, "receiver": true}
	v2ProductionPropagateKinds = map[string]bool{"value": true, "taint": true, "identity": true, "receiver": true}
	v2GoOwnedMechanicNames     = map[string]bool{"assume": true}
	v2FidelityLevels           = map[string]bool{"syntactic": true, "resolved": true, "semantic": true}
	v2ConfidenceLevels         = map[string]bool{"low": true, "medium": true, "high": true}
	v2CoverageSolversByMode    = map[string][]string{
		"path":          {"solver.pathCovered"},
		"endpoint":      {"solver.sameEndpoint"},
		"sameReceiver":  {"solver.sameValue"},
		"sameScope":     {"solver.sameScope"},
		"dominates":     {"solver.dominates", "graph.reach"},
		"postDominates": {"solver.postDominates"},
		"global":        {"solver.always"},
	}
)

// ValidateV2 applies language-contract checks that are semantic enough to sit
// above token parsing but below scanner IR and engine typechecking. It intentionally does not
// validate concept existence; converted content may be checked one file at a
// time before the whole definition graph is loaded.
func ValidateV2(prog *V2Program) error {
	errs := validateV2ProgramNames(prog)
	localConceptKinds := v2LocalConceptKinds(prog)
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *V2ConceptDecl:
			errs = append(errs, validateV2Concept(x)...)
		case *V2PatternDecl:
			errs = append(errs, validateV2Pattern(x)...)
		case *V2MatcherDecl:
			errs = append(errs, validateV2Matcher(x)...)
		case *V2BindingDecl:
			errs = append(errs, validateV2Binding(x, localConceptKinds)...)
		case *V2RuleDecl:
			errs = append(errs, validateV2Rule(x, localConceptKinds)...)
		case *V2MechanicDecl:
			if !v2MechanicKinds[x.Kind] {
				errs = append(errs, fmt.Errorf("mechanic %s: unknown mechanic kind %q", x.Name, x.Kind))
			} else if !v2ImplementedMechanicKinds[x.Kind] {
				errs = append(errs, fmt.Errorf("mechanic %s %s: mechanic kind is recognized by the v2 contract but is not implemented by the current runtime", x.Kind, x.Name))
			}
			errs = append(errs, validateV2Mechanic(x)...)
		case *V2PolicyDecl:
			if !v2PolicyKinds[x.Kind] {
				errs = append(errs, fmt.Errorf("policy %s: unknown policy kind %q", x.Name, x.Kind))
			} else if !v2ImplementedPolicyKinds[x.Kind] {
				errs = append(errs, fmt.Errorf("policy %s %s: policy kind is recognized by the v2 contract but is not implemented by the current runtime", x.Kind, x.Name))
			}
			errs = append(errs, validateV2Policy(x)...)
		case *V2ProfileDecl:
			errs = append(errs, validateV2Profile(x)...)
		case *V2PackDecl:
			errs = append(errs, validateV2Pack(x)...)
		}
	}
	return errors.Join(errs...)
}

func validateV2Matcher(m *V2MatcherDecl) []error {
	var errs []error
	if len(m.Items) == 0 {
		errs = append(errs, fmt.Errorf("matcher %s: must declare at least one matcher item", m.Name))
	}
	for _, item := range m.Items {
		switch item.Kind {
		case "containsAny", "equalsAny":
			if len(item.Values) == 0 {
				errs = append(errs, fmt.Errorf("matcher %s: %s requires a non-empty string list", m.Name, item.Kind))
			}
		case "matches":
			if len(item.Values) != 1 || item.Values[0] == "" {
				errs = append(errs, fmt.Errorf("matcher %s: matches requires one non-empty regex string", m.Name))
			}
		default:
			errs = append(errs, fmt.Errorf("matcher %s: unknown matcher item %q", m.Name, item.Kind))
		}
	}
	return errs
}

type V2Source struct {
	Name    string
	Program *V2Program
}

type v2ConceptMeta struct {
	Kind   string
	Covers map[string]bool
}

type v2MechanicID struct {
	Kind string
	Name string
}

type v2PolicyID struct {
	Kind string
	Name string
}

type v2RuleVerbMechanic struct {
	FromKinds      []string
	ToKinds        []string
	AllowedClauses map[string]bool
}

type v2CoverageMechanic struct {
	TargetParts map[string]bool
}

type v2ConceptScope struct {
	global map[string]v2ConceptMeta
	local  map[string]v2ConceptMeta
}

func (s v2ConceptScope) lookup(name string) (v2ConceptMeta, bool) {
	if s.local != nil {
		if meta, ok := s.local[name]; ok {
			return meta, true
		}
	}
	meta, ok := s.global[name]
	return meta, ok
}

type v2ModelScope struct {
	concepts      v2ConceptScope
	globalThreats map[string]bool
	localThreats  map[string]bool
}

func (s v2ModelScope) lookupThreat(name string) bool {
	if s.localThreats != nil && s.localThreats[name] {
		return true
	}
	return s.globalThreats[name]
}

func (s v2ModelScope) lookupModel(name string) bool {
	if _, ok := s.concepts.lookup(name); ok {
		return true
	}
	return s.lookupThreat(name)
}

func builtinV2RuleVerbMechanics() map[string]v2RuleVerbMechanic {
	clauses := v2StringSet([]string{"where", "coveredBy", "confidence", "profile"})
	return map[string]v2RuleVerbMechanic{
		"taint": {FromKinds: []string{"source"}, ToKinds: []string{"sink"}, AllowedClauses: clauses},
		"reach": {FromKinds: []string{"asset", "exposure"}, ToKinds: []string{"asset", "exposure"}, AllowedClauses: clauses},
		"grant": {FromKinds: []string{"principal"}, ToKinds: []string{"principal", "privilege"}, AllowedClauses: clauses},
		"issue": {FromKinds: []string{"issue"}, AllowedClauses: clauses},
		"fact":  {FromKinds: []string{"fact", "asset", "exposure", "principal", "privilege", "state"}, AllowedClauses: clauses},
		"query": {FromKinds: []string{"concept", "fact", "asset", "exposure", "principal", "privilege", "state"}, AllowedClauses: v2StringSet([]string{"where", "confidence", "profile"})},
	}
}

func builtinV2CoverageMechanics() map[string]v2CoverageMechanic {
	out := make(map[string]v2CoverageMechanic, len(v2CoverageModes))
	for mode := range v2CoverageModes {
		out[mode] = v2CoverageMechanic{TargetParts: map[string]bool{mode: true}}
	}
	return out
}

func builtinV2MechanicSources() map[v2MechanicID]string {
	out := make(map[v2MechanicID]string, len(v2CoverageModes)+len(builtinV2RuleVerbMechanics()))
	for mode := range v2CoverageModes {
		out[v2MechanicID{Kind: "coverage", Name: mode}] = "<builtin>"
	}
	for verb := range builtinV2RuleVerbMechanics() {
		out[v2MechanicID{Kind: "ruleVerb", Name: verb}] = "<builtin>"
	}
	return out
}

// ValidateV2Corpus applies whole-definition-graph checks that require all files:
// duplicate fully qualified declarations, import resolution, concept existence,
// emit kind compatibility, rule endpoint kind compatibility, and coveredBy
// target typing. It runs in linear time over declarations and references.
func ValidateV2Corpus(sources []V2Source) error {
	declCount := 0
	for _, src := range sources {
		if src.Program != nil {
			declCount += len(src.Program.Decls)
		}
	}
	declSources := make(map[string]string, declCount)
	concepts := make(map[string]v2ConceptMeta, declCount)
	threats := make(map[string]bool, declCount/8)
	mechanics := builtinV2MechanicSources()
	ruleMechanics := builtinV2RuleVerbMechanics()
	coverageMechanics := builtinV2CoverageMechanics()
	policies := make(map[v2PolicyID]string, 8)
	var errs []error
	for _, src := range sources {
		if src.Program == nil {
			errs = append(errs, fmt.Errorf("%s: nil v2 program", src.Name))
			continue
		}
		for _, d := range src.Program.Decls {
			_, fq := v2DeclNames(src.Program.Module, d)
			if fq == "" {
				continue
			}
			if prev := declSources[fq]; prev != "" {
				errs = append(errs, fmt.Errorf("%s: duplicate v2 declaration %s; first declared in %s", src.Name, fq, prev))
				continue
			}
			declSources[fq] = src.Name
			if c, ok := d.(*V2ConceptDecl); ok {
				concepts[fq] = v2ConceptMeta{Kind: c.Kind, Covers: v2ConceptCovers(c)}
			}
			if _, ok := d.(*V2ThreatDecl); ok {
				threats[fq] = true
			}
			if m, ok := d.(*V2MechanicDecl); ok {
				key := v2MechanicID{Kind: m.Kind, Name: m.Name}
				if prev := mechanics[key]; prev != "" {
					errs = append(errs, fmt.Errorf("%s: duplicate v2 mechanic %s.%s; first declared in %s", src.Name, m.Kind, m.Name, prev))
				} else {
					mechanics[key] = src.Name
					if m.Kind == "ruleVerb" {
						ruleMechanics[m.Name] = v2RuleVerbMechanic{
							FromKinds:      v2BlockItemStringList(m.Items, "fromKinds"),
							ToKinds:        v2BlockItemStringList(m.Items, "toKinds"),
							AllowedClauses: v2StringSet(v2BlockItemStringList(m.Items, "allowedClauses")),
						}
					} else if m.Kind == "coverage" {
						coverageMechanics[m.Name] = v2CoverageMechanic{
							TargetParts: v2StringSet(v2BlockItemStringList(m.Items, "targetParts")),
						}
					}
				}
			}
			if p, ok := d.(*V2PolicyDecl); ok {
				key := v2PolicyID{Kind: p.Kind, Name: p.Name}
				if prev := policies[key]; prev != "" {
					errs = append(errs, fmt.Errorf("%s: duplicate v2 policy %s.%s; first declared in %s", src.Name, p.Kind, p.Name, prev))
				} else {
					policies[key] = src.Name
				}
			}
		}
	}
	errs = append(errs, validateV2PackCycles(sources)...)
	errs = append(errs, validateV2RequiredMechanics(concepts, mechanics)...)
	for _, src := range sources {
		if src.Program == nil {
			continue
		}
		scope := v2CorpusConceptScope(src.Program, concepts, declSources, &errs, src.Name)
		modelScope := v2CorpusModelScope(src.Program, scope, threats, declSources)
		for _, d := range src.Program.Decls {
			switch x := d.(type) {
			case *V2ConceptDecl:
				errs = append(errs, validateV2ConceptModelReferences(src.Name, x, modelScope)...)
			case *V2ReviewDecl:
				errs = append(errs, validateV2ReviewModelReferences(src.Name, x, modelScope)...)
			case *V2BindingDecl:
				errs = append(errs, validateV2BindingCorpus(src.Name, x, scope)...)
				errs = append(errs, validateV2BindingMechanics(src.Name, x, mechanics)...)
			case *V2RuleDecl:
				errs = append(errs, validateV2RuleCorpus(src.Name, x, scope, ruleMechanics, coverageMechanics, policies)...)
			}
		}
	}
	return errors.Join(errs...)
}

func validateV2Pack(p *V2PackDecl) []error {
	var errs []error
	for _, key := range []string{"includes", "excludes"} {
		raw, ok := p.Fields[key]
		if !ok {
			continue
		}
		values, ok := raw.([]string)
		if !ok {
			errs = append(errs, fmt.Errorf("pack %s: %s must be a string reference list", p.Name, key))
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				errs = append(errs, fmt.Errorf("pack %s: %s contains an empty reference", p.Name, key))
			}
		}
	}
	return errs
}

func validateV2PackCycles(sources []V2Source) []error {
	type packInfo struct {
		fq       string
		includes []string
	}
	var packs []packInfo
	refToFQ := map[string]string{}
	ambiguous := map[string]bool{}
	addRef := func(ref, fq string) {
		if ref == "" {
			return
		}
		if prev := refToFQ[ref]; prev != "" && prev != fq {
			ambiguous[ref] = true
			return
		}
		refToFQ[ref] = fq
	}
	for _, src := range sources {
		if src.Program == nil {
			continue
		}
		for _, decl := range src.Program.Decls {
			p, ok := decl.(*V2PackDecl)
			if !ok {
				continue
			}
			local, fq := v2DeclNames(src.Program.Module, p)
			if fq == "" {
				continue
			}
			packs = append(packs, packInfo{fq: fq, includes: v2PackStringList(p.Fields, "includes")})
			addRef(local, fq)
			addRef(fq, fq)
			addRef("pack."+local, fq)
			addRef("pack."+fq, fq)
		}
	}
	if len(packs) == 0 {
		return nil
	}
	edges := make(map[string][]string, len(packs))
	var errs []error
	for _, pack := range packs {
		for _, ref := range pack.includes {
			if ambiguous[ref] {
				errs = append(errs, fmt.Errorf("pack %s: include reference %q is ambiguous", pack.fq, ref))
				continue
			}
			if target := refToFQ[ref]; target != "" {
				edges[pack.fq] = append(edges[pack.fq], target)
			}
		}
	}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var stack []string
	var visit func(string)
	visit = func(node string) {
		if visiting[node] {
			cycle := append(append([]string(nil), stack...), node)
			errs = append(errs, fmt.Errorf("pack cycle detected: %s", strings.Join(cycle, " -> ")))
			return
		}
		if visited[node] {
			return
		}
		visiting[node] = true
		stack = append(stack, node)
		for _, next := range edges[node] {
			visit(next)
		}
		stack = stack[:len(stack)-1]
		visiting[node] = false
		visited[node] = true
	}
	for _, pack := range packs {
		visit(pack.fq)
	}
	return errs
}

func v2PackStringList(fields map[string]any, key string) []string {
	values, ok := fields[key].([]string)
	if !ok {
		return nil
	}
	return values
}

func v2CorpusModelScope(prog *V2Program, concepts v2ConceptScope, threats map[string]bool, declSources map[string]string) v2ModelScope {
	localThreats := make(map[string]bool, len(prog.Decls)+len(prog.Uses))
	for _, d := range prog.Decls {
		if _, ok := d.(*V2ThreatDecl); !ok {
			continue
		}
		local, fq := v2DeclNames(prog.Module, d)
		if local != "" {
			localThreats[local] = true
		}
		if fq != "" {
			localThreats[fq] = true
		}
	}
	for _, u := range prog.Uses {
		if declSources[u.Name] == "" || !threats[u.Name] {
			continue
		}
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		localThreats[local] = true
	}
	return v2ModelScope{concepts: concepts, globalThreats: threats, localThreats: localThreats}
}

func validateV2ConceptModelReferences(sourceName string, c *V2ConceptDecl, scope v2ModelScope) []error {
	ctx := sourceName + ": concept " + c.Name
	var errs []error
	errs = append(errs, validateV2ModelRefList(ctx, c.Fields, "vulnerableTo", scope, true, true)...)
	errs = append(errs, validateV2ModelRefList(ctx, c.Fields, "neutralizes", scope, true, true)...)
	errs = append(errs, validateV2ConceptRefList(ctx, c.Fields, "enabledBy", scope, "source", "fact", "asset", "exposure", "principal", "privilege", "state")...)
	errs = append(errs, validateV2ConceptRefList(ctx, c.Fields, "expected", scope, "check")...)
	errs = append(errs, validateV2ConceptRefList(ctx, c.Fields, "taint", scope, "source", "fact")...)
	if raw, ok := c.Fields["refines"]; ok {
		ref, ok := raw.(string)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: refines must be a concept reference", ctx))
		} else {
			errs = append(errs, validateV2ConceptRef(ctx, "refines", ref, scope)...)
		}
	}
	return errs
}

func validateV2ReviewModelReferences(sourceName string, r *V2ReviewDecl, scope v2ModelScope) []error {
	ctx := sourceName + ": review " + r.Concept
	var errs []error
	errs = append(errs, validateV2ConceptRef(ctx, "review", r.Concept, scope)...)
	errs = append(errs, validateV2ConceptRefList(ctx, r.Fields, "expected", scope, "check")...)
	return errs
}

func validateV2ModelRefList(ctx string, fields map[string]any, field string, scope v2ModelScope, allowConcept, allowThreat bool) []error {
	values, ok, err := v2StringListField(ctx, fields, field)
	if err != nil || !ok {
		if err != nil {
			return []error{err}
		}
		return nil
	}
	var errs []error
	for _, ref := range values {
		conceptOK := false
		if allowConcept {
			_, conceptOK = scope.concepts.lookup(ref)
		}
		threatOK := allowThreat && scope.lookupThreat(ref)
		if !conceptOK && !threatOK {
			errs = append(errs, fmt.Errorf("%s: %s references unknown model %s", ctx, field, ref))
		}
	}
	return errs
}

func validateV2ConceptRefList(ctx string, fields map[string]any, field string, scope v2ModelScope, wants ...string) []error {
	values, ok, err := v2StringListField(ctx, fields, field)
	if err != nil || !ok {
		if err != nil {
			return []error{err}
		}
		return nil
	}
	var errs []error
	for _, ref := range values {
		errs = append(errs, validateV2ConceptRef(ctx, field, ref, scope, wants...)...)
	}
	return errs
}

func validateV2ConceptRef(ctx, field, ref string, scope v2ModelScope, wants ...string) []error {
	meta, ok := scope.concepts.lookup(ref)
	if !ok {
		return []error{fmt.Errorf("%s: %s references unknown concept %s", ctx, field, ref)}
	}
	if len(wants) == 0 {
		return nil
	}
	for _, want := range wants {
		if want == "concept" || meta.Kind == want {
			return nil
		}
	}
	return []error{fmt.Errorf("%s: %s references concept %s of kind %s; want %s", ctx, field, ref, meta.Kind, strings.Join(wants, "|"))}
}

func v2StringListField(ctx string, fields map[string]any, field string) ([]string, bool, error) {
	raw, ok := fields[field]
	if !ok {
		return nil, false, nil
	}
	values, ok := raw.([]string)
	if !ok {
		return nil, true, fmt.Errorf("%s: %s must be a string list", ctx, field)
	}
	return values, true, nil
}

func validateV2RequiredMechanics(concepts map[string]v2ConceptMeta, mechanics map[v2MechanicID]string) []error {
	var errs []error
	seenCoverage := map[string]bool{}
	for concept, meta := range concepts {
		if meta.Kind != "check" {
			continue
		}
		for mode := range meta.Covers {
			if seenCoverage[mode] {
				continue
			}
			seenCoverage[mode] = true
			if mechanics[v2MechanicID{Kind: "coverage", Name: mode}] == "" {
				errs = append(errs, fmt.Errorf("check concept %s references coverage mode %q without mechanic coverage %s", concept, mode, mode))
			}
		}
	}
	return errs
}

func validateV2BindingMechanics(sourceName string, b *V2BindingDecl, mechanics map[v2MechanicID]string) []error {
	var errs []error
	var seen map[string]bool
	for _, out := range b.Outputs {
		if out.Kind != "emit check" {
			continue
		}
		for _, cov := range out.Covers {
			if cov.Mode == "" {
				continue
			}
			if seen != nil && seen[cov.Mode] {
				continue
			}
			if seen == nil && len(out.Covers) > 1 {
				seen = make(map[string]bool, len(out.Covers))
			}
			if seen != nil {
				seen[cov.Mode] = true
			}
			if mechanics[v2MechanicID{Kind: "coverage", Name: cov.Mode}] == "" {
				errs = append(errs, fmt.Errorf("%s: binding %s emits coverage mode %q without mechanic coverage %s", sourceName, b.Name, cov.Mode, cov.Mode))
			}
		}
	}
	return errs
}

func v2ConceptCovers(c *V2ConceptDecl) map[string]bool {
	if c.Kind != "check" {
		return nil
	}
	out := map[string]bool{}
	if values, ok := c.Fields["covers"].([]string); ok {
		for _, mode := range values {
			out[mode] = true
		}
	}
	return out
}

func v2CorpusConceptScope(prog *V2Program, concepts map[string]v2ConceptMeta, declSources map[string]string, errs *[]error, sourceName string) v2ConceptScope {
	scope := v2ConceptScope{
		global: concepts,
		local:  make(map[string]v2ConceptMeta, len(prog.Decls)*3+len(prog.Uses)),
	}
	for _, d := range prog.Decls {
		c, ok := d.(*V2ConceptDecl)
		if !ok {
			continue
		}
		local, fq := v2DeclNames(prog.Module, c)
		meta := v2ConceptMeta{Kind: c.Kind, Covers: v2ConceptCovers(c)}
		v2StoreConceptMeta(scope.local, c.Name, meta)
		v2StoreConceptMeta(scope.local, local, meta)
		v2StoreConceptMeta(scope.local, fq, meta)
	}
	for _, u := range prog.Uses {
		if declSources[u.Name] == "" {
			*errs = append(*errs, fmt.Errorf("%s: uses %s does not resolve to a v2 declaration", sourceName, u.Name))
			continue
		}
		meta, ok := concepts[u.Name]
		if !ok {
			continue
		}
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		scope.local[local] = meta
	}
	return scope
}

func v2StoreConceptMeta(dst map[string]v2ConceptMeta, name string, meta v2ConceptMeta) {
	if name != "" {
		dst[name] = meta
	}
}

func v2StringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func validateV2BindingCorpus(sourceName string, b *V2BindingDecl, concepts v2ConceptScope) []error {
	var errs []error
	ctx := sourceName + ": binding " + b.Name
	for _, out := range b.Outputs {
		errs = append(errs, validateV2EmitConceptKindStrict(ctx, out.Kind, out.Concept, concepts)...)
		if out.Kind == "emit check" {
			for _, cov := range out.Covers {
				errs = append(errs, validateV2CheckCoverageMode(ctx, "emit check", out.Concept, cov.Mode, concepts)...)
			}
		}
	}
	return errs
}

func validateV2RuleCorpus(sourceName string, r *V2RuleDecl, concepts v2ConceptScope, mechanics map[string]v2RuleVerbMechanic, coverageMechanics map[string]v2CoverageMechanic, policies map[v2PolicyID]string) []error {
	ctx := sourceName + ": rule " + r.Name
	var errs []error
	hasConfidencePolicy := policies[v2PolicyID{Kind: "confidence", Name: "default"}] != ""
	if v2RuleHasConfidenceFloor(r) && !hasConfidencePolicy {
		errs = append(errs, fmt.Errorf("%s: confidence floor requires policy confidence default", ctx))
	}
	if m, ok := mechanics[r.Body.Verb]; ok {
		switch {
		case r.Body.From.Concept != "" || r.Body.To.Concept != "":
			errs = append(errs, validateV2EndpointConceptKind(ctx, "from", r.Body.From.Concept, concepts, m.FromKinds...)...)
			errs = append(errs, validateV2EndpointConceptKind(ctx, "to", r.Body.To.Concept, concepts, m.ToKinds...)...)
		case r.Body.Issue.Concept != "":
			errs = append(errs, validateV2EndpointConceptKind(ctx, r.Body.Verb, r.Body.Issue.Concept, concepts, m.FromKinds...)...)
		}
	}
	for _, cl := range r.Clauses {
		if m, ok := mechanics[r.Body.Verb]; ok {
			if clause := v2RuleClauseMechanicName(cl); clause != "" && !m.AllowedClauses[clause] {
				errs = append(errs, fmt.Errorf("%s: clause %q is not allowed by mechanic ruleVerb %s", ctx, clause, r.Body.Verb))
			}
		}
		if cl.Kind == "unless" {
			errs = append(errs, validateV2EndpointConceptKind(ctx, "coveredBy", cl.Concept, concepts, "check")...)
			errs = append(errs, validateV2CheckCoverageMode(ctx, "coveredBy", cl.Concept, cl.Coverage, concepts)...)
			errs = append(errs, validateV2RuleCoverageTargetPart(ctx, cl, coverageMechanics)...)
		}
	}
	return errs
}

func v2RuleHasConfidenceFloor(r *V2RuleDecl) bool {
	if r == nil {
		return false
	}
	if _, ok := r.Meta["confidenceFloor"]; ok {
		return true
	}
	if _, ok := r.Meta["confidence_floor"]; ok {
		return true
	}
	for _, cl := range r.Clauses {
		if cl.Kind == "with" {
			return true
		}
	}
	return false
}

func validateV2RuleCoverageTargetPart(ctx string, cl V2RuleClause, coverageMechanics map[string]v2CoverageMechanic) []error {
	if cl.Coverage == "" {
		return nil
	}
	mech, ok := coverageMechanics[cl.Coverage]
	if !ok {
		return nil
	}
	if mech.TargetParts[cl.Coverage] {
		return nil
	}
	if len(mech.TargetParts) == 0 {
		return []error{fmt.Errorf("%s: coverage mechanic %s declares no targetParts for coveredBy target %q", ctx, cl.Coverage, cl.Target)}
	}
	return []error{fmt.Errorf("%s: coveredBy target %q uses coverage part %q not declared by mechanic coverage %s targetParts [%s]", ctx, cl.Target, cl.Coverage, cl.Coverage, strings.Join(v2SortedStrings(mech.TargetParts), ", "))}
}

func v2RuleClauseMechanicName(cl V2RuleClause) string {
	switch cl.Kind {
	case "where":
		return "where"
	case "unless":
		return "coveredBy"
	case "with":
		return "confidence"
	case "require":
		return "profile"
	default:
		return cl.Kind
	}
}

func validateV2EmitConceptKindStrict(ctx, emitKind, concept string, concepts v2ConceptScope) []error {
	if concept == "" || !strings.HasPrefix(emitKind, "emit ") {
		return nil
	}
	want := strings.TrimPrefix(emitKind, "emit ")
	switch want {
	case "source", "sink", "check", "issue":
		return validateV2EndpointConceptKind(ctx, emitKind, concept, concepts, want)
	case "fact":
		return validateV2EndpointConceptKind(ctx, emitKind, concept, concepts, "fact", "asset", "exposure", "principal", "privilege", "state")
	default:
		return nil
	}
}

func validateV2EndpointConceptKind(ctx, role, concept string, concepts v2ConceptScope, wants ...string) []error {
	if concept == "" {
		return nil
	}
	meta, ok := concepts.lookup(concept)
	if !ok {
		return []error{fmt.Errorf("%s: %s uses unknown concept %s", ctx, role, concept)}
	}
	for _, want := range wants {
		if want == "concept" || meta.Kind == want {
			return nil
		}
	}
	return []error{fmt.Errorf("%s: %s uses concept %s of kind %s; want %s", ctx, role, concept, meta.Kind, strings.Join(wants, "|"))}
}

func validateV2CheckCoverageMode(ctx, role, concept, mode string, concepts v2ConceptScope) []error {
	if concept == "" || mode == "" {
		return nil
	}
	meta, ok := concepts.lookup(concept)
	if !ok || meta.Kind != "check" {
		return nil
	}
	if meta.Covers[mode] {
		return nil
	}
	if len(meta.Covers) == 0 {
		return []error{fmt.Errorf("%s: %s check %s uses coverage mode %q but the concept declares no covers modes", ctx, role, concept, mode)}
	}
	return []error{fmt.Errorf("%s: %s check %s uses coverage mode %q not declared in concept covers [%s]", ctx, role, concept, mode, strings.Join(v2SortedCoverageModes(meta.Covers), ", "))}
}

func v2SortedCoverageModes(modes map[string]bool) []string {
	return v2SortedStrings(modes)
}

func v2SortedStrings(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func v2LocalConceptKinds(prog *V2Program) map[string]string {
	out := map[string]string{}
	for _, d := range prog.Decls {
		c, ok := d.(*V2ConceptDecl)
		if !ok {
			continue
		}
		local, fq := v2DeclNames(prog.Module, c)
		for _, name := range []string{c.Name, local, fq} {
			if name != "" {
				out[name] = c.Kind
			}
		}
	}
	return out
}

func validateV2Concept(c *V2ConceptDecl) []error {
	var errs []error
	if !v2ConceptKinds[c.Kind] {
		errs = append(errs, fmt.Errorf("concept %s: unknown v2 concept kind %q", c.Name, c.Kind))
	}
	if _, ok := c.Fields["analysisRole"]; ok {
		errs = append(errs, fmt.Errorf("concept %s: analysisRole is a Go-owned language mechanic and must not be authored in VyQL", c.Name))
	}
	if raw, ok := c.Fields["covers"]; ok {
		values, ok := raw.([]string)
		if !ok {
			errs = append(errs, fmt.Errorf("concept %s: covers must be a string list", c.Name))
		} else {
			for _, mode := range values {
				if !v2CoverageModes[mode] {
					errs = append(errs, fmt.Errorf("concept %s: unknown coverage mode %q", c.Name, mode))
				}
			}
		}
	}
	return errs
}

func validateV2ProgramNames(prog *V2Program) []error {
	var errs []error
	localDecls := map[string]string{}
	fqDecls := map[string]bool{}
	for _, d := range prog.Decls {
		local, fq := v2DeclNames(prog.Module, d)
		if local == "" {
			continue
		}
		if prev := localDecls[local]; prev != "" {
			errs = append(errs, fmt.Errorf("declaration %s: local name %q conflicts with %s", fq, local, prev))
		}
		localDecls[local] = fq
		if fqDecls[fq] {
			errs = append(errs, fmt.Errorf("duplicate v2 declaration %s", fq))
		}
		fqDecls[fq] = true
	}
	uses := map[string]string{}
	for _, u := range prog.Uses {
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		if prev := uses[local]; prev != "" {
			errs = append(errs, fmt.Errorf("uses %s: local import name %q conflicts with uses %s", u.Name, local, prev))
		}
		uses[local] = u.Name
		if decl := localDecls[local]; decl != "" {
			errs = append(errs, fmt.Errorf("uses %s: local import name %q shadows declaration %s", u.Name, local, decl))
		}
	}
	return errs
}

func v2DeclNames(module string, d V2Decl) (local, fq string) {
	switch x := d.(type) {
	case *V2ConceptDecl:
		local = x.Name
	case *V2ThreatDecl:
		local = x.Name
	case *V2PatternDecl:
		local = x.Name
	case *V2MatcherDecl:
		local = x.Name
	case *V2BindingDecl:
		local = x.Name
	case *V2RuleDecl:
		local = x.Name
	case *V2ProfileDecl:
		local = x.Name
	case *V2PackDecl:
		local = x.Name
	case *V2ReviewDecl:
		local = "review:" + x.Concept
		fq = module + "." + local
	case *V2MechanicDecl:
		local = "mechanic:" + x.Kind + ":" + x.Name
		fq = module + "." + local
	case *V2PolicyDecl:
		local = "policy:" + x.Kind + ":" + x.Name
		fq = module + "." + local
	}
	if fq != "" {
		return local, fq
	}
	if local == "" {
		return "", ""
	}
	if strings.Contains(local, ".") {
		return lastSeg(local), local
	}
	if module == "" {
		return local, local
	}
	return local, module + "." + local
}

func validateV2Mechanic(m *V2MechanicDecl) []error {
	var errs []error
	if v2GoOwnedMechanicNames[m.Name] {
		errs = append(errs, fmt.Errorf("mechanic %s %s: %q is a Go-owned language mechanic and must not be authored in VyQL", m.Kind, m.Name, m.Name))
	}
	if isV2BuiltInMechanicDecl(m) {
		errs = append(errs, fmt.Errorf("mechanic %s %s: built-in language mechanics are implemented in Go and must not be authored in VyQL", m.Kind, m.Name))
	}
	if m.Kind == "ruleVerb" && !v2BuiltInRuleVerbs[m.Name] {
		errs = append(errs, fmt.Errorf("mechanic ruleVerb %s: extension rule verbs are recognized by the v2 contract but are not implemented by the current parser/runtime", m.Name))
	}
	switch m.Kind {
	case "coverage":
		if !v2CoverageModes[m.Name] {
			errs = append(errs, fmt.Errorf("mechanic %s: unknown coverage mode %q", m.Name, m.Name))
		}
		capability := v2BlockItemString(m.Items, "capability")
		if capability == "" {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: missing capability", m.Name))
		} else if !v2MechanicCapabilities[capability] {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: unknown capability %q", m.Name, capability))
		} else if want := "coverage." + m.Name; capability != want {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: capability %q must match %q", m.Name, capability, want))
		}
		targetParts := v2BlockItemStringList(m.Items, "targetParts")
		if len(targetParts) == 0 {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: missing targetParts", m.Name))
		}
		for _, part := range targetParts {
			if !v2CoverageModes[part] {
				errs = append(errs, fmt.Errorf("mechanic coverage %s: unknown targetPart %q", m.Name, part))
			}
		}
		if requiresAnchor, ok := v2BlockItemBool(m.Items, "requiresAnchor"); ok {
			if m.Name == "global" && requiresAnchor {
				errs = append(errs, fmt.Errorf("mechanic coverage global: requiresAnchor must be false"))
			}
			if m.Name != "global" && !requiresAnchor {
				errs = append(errs, fmt.Errorf("mechanic coverage %s: requiresAnchor must be true", m.Name))
			}
		}
		if m.Name != "global" && !v2BlockItemExists(m.Items, "coversWhen") && !v2BlockItemExists(m.Items, "requiresAnchor") {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: missing coversWhen or requiresAnchor", m.Name))
		}
		if expr, ok := v2BlockItemExpr(m.Items, "coversWhen"); ok {
			errs = append(errs, validateV2CoverageMechanicExpr(m.Name, targetParts, expr)...)
		}
	case "ruleVerb":
		solver := v2BlockItemString(m.Items, "solver")
		if solver == "" {
			errs = append(errs, fmt.Errorf("mechanic ruleVerb %s: missing solver", m.Name))
		} else if !v2MechanicCapabilities[solver] {
			errs = append(errs, fmt.Errorf("mechanic ruleVerb %s: unknown solver capability %q", m.Name, solver))
		}
		for _, kind := range append(v2BlockItemStringList(m.Items, "fromKinds"), v2BlockItemStringList(m.Items, "toKinds")...) {
			if kind != "concept" && !v2ConceptKinds[kind] {
				errs = append(errs, fmt.Errorf("mechanic ruleVerb %s: unknown endpoint kind %q", m.Name, kind))
			}
		}
		for _, clause := range v2BlockItemStringList(m.Items, "allowedClauses") {
			if !v2RuleClauseKinds[clause] {
				errs = append(errs, fmt.Errorf("mechanic ruleVerb %s: unknown allowed clause %q", m.Name, clause))
			}
		}
	}
	return errs
}

func isV2BuiltInMechanicDecl(m *V2MechanicDecl) bool {
	return (m.Kind == "coverage" && v2CoverageModes[m.Name]) || (m.Kind == "ruleVerb" && v2BuiltInRuleVerbs[m.Name])
}

func validateV2Policy(p *V2PolicyDecl) []error {
	var errs []error
	switch p.Kind {
	case "resultLifecycle":
		errs = append(errs, validateV2ResultLifecyclePolicy(p)...)
	case "resultIdentity":
		errs = append(errs, validateV2StringListPolicy(p, "findingKey", "flagKey", "fingerprint", "stableAcross")...)
	case "confidence":
		errs = append(errs, validateV2ConfidencePolicy(p)...)
	case "priority":
		errs = append(errs, validateV2PriorityPolicy(p)...)
	case "display":
		errs = append(errs, validateV2DisplayPolicy(p)...)
	case "diagnostic":
		errs = append(errs, validateV2DiagnosticPolicy(p)...)
	}
	return errs
}

func validateV2ResultLifecyclePolicy(p *V2PolicyDecl) []error {
	allowed := map[string]bool{"flagWhen": true, "candidateWhen": true, "findingWhen": true, "checkWhen": true}
	required := map[string]V2Expr{
		"flagWhen":      V2BinaryExpr{Op: "and", Left: V2CallExpr{Name: "emitted", Args: []V2Expr{V2RefExpr{Name: "issue"}}}, Right: V2CallExpr{Name: "hasReview", Args: []V2Expr{V2RefExpr{Name: "concept"}}}},
		"candidateWhen": V2CallExpr{Name: "matched", Args: []V2Expr{V2RefExpr{Name: "rule"}}},
		"findingWhen":   V2BinaryExpr{Op: "and", Left: V2RefExpr{Name: "candidate"}, Right: V2UnaryExpr{Op: "not", X: V2RefExpr{Name: "covered"}}},
		"checkWhen":     V2BinaryExpr{Op: "and", Left: V2CallExpr{Name: "emitted", Args: []V2Expr{V2RefExpr{Name: "check"}}}, Right: V2BinaryExpr{Op: "or", Left: V2CallExpr{Name: "hasReview", Args: []V2Expr{V2RefExpr{Name: "concept"}}}, Right: V2RefExpr{Name: "explainsFinding"}}},
	}
	seen := map[string]bool{}
	var errs []error
	for _, item := range p.Items {
		if len(item.Key) != 1 || !allowed[item.Key[0]] {
			errs = append(errs, fmt.Errorf("policy resultLifecycle %s: unknown item %s", p.Name, strings.Join(item.Key, ".")))
			continue
		}
		expr, ok := item.Value.(V2Expr)
		if !ok {
			errs = append(errs, fmt.Errorf("policy resultLifecycle %s: %s must be a predicate expression", p.Name, item.Key[0]))
			continue
		}
		errs = append(errs, validateV2PolicyExpr("policy resultLifecycle "+p.Name+": "+item.Key[0], expr, v2LifecyclePolicyRefs, v2LifecyclePolicyCalls)...)
		if want := required[item.Key[0]]; !v2ExprEqual(expr, want) {
			errs = append(errs, fmt.Errorf("policy resultLifecycle %s: %s must match the runtime-supported default lifecycle contract", p.Name, item.Key[0]))
		}
		seen[item.Key[0]] = true
	}
	for key := range required {
		if !seen[key] {
			errs = append(errs, fmt.Errorf("policy resultLifecycle %s: missing runtime-required item %s", p.Name, key))
		}
	}
	return errs
}

func validateV2ConfidencePolicy(p *V2PolicyDecl) []error {
	var errs []error
	seen := map[string]bool{}
	for _, item := range p.Items {
		switch {
		case len(item.Key) == 1 && (item.Key[0] == "values" || item.Key[0] == "order"):
			values := v2BlockItemValueStringList(item.Value)
			if len(values) == 0 {
				errs = append(errs, fmt.Errorf("policy confidence %s: %s must be a non-empty string list", p.Name, item.Key[0]))
			} else if !v2StringListEqual(values, []string{"low", "medium", "high"}) {
				errs = append(errs, fmt.Errorf("policy confidence %s: %s must match runtime-supported order [low, medium, high]", p.Name, item.Key[0]))
			}
			seen[item.Key[0]] = true
		case len(item.Key) == 1 && item.Key[0] == "aggregate":
			expr, ok := item.Value.(V2Expr)
			if !ok {
				errs = append(errs, fmt.Errorf("policy confidence %s: aggregate must be an expression", p.Name))
				continue
			}
			errs = append(errs, validateV2PolicyExpr("policy confidence "+p.Name+": aggregate", expr, v2ConfidencePolicyRefs, v2ConfidencePolicyCalls)...)
			if !v2ConfidenceAggregateIsRuntimeSupported(expr) {
				errs = append(errs, fmt.Errorf("policy confidence %s: aggregate must be runtime-supported min(rule, endpoints, propagation, requirements)", p.Name))
			}
			seen["aggregate"] = true
		case len(item.Key) == 2 && item.Key[0] == "softRequirement":
			if !v2RequirementEvidenceStates[item.Key[1]] {
				errs = append(errs, fmt.Errorf("policy confidence %s: unknown softRequirement state %q", p.Name, item.Key[1]))
			}
			expr, ok := item.Value.(V2Expr)
			if !ok {
				errs = append(errs, fmt.Errorf("policy confidence %s: softRequirement %s must be an action expression", p.Name, item.Key[1]))
				continue
			}
			errs = append(errs, validateV2ConfidenceActionExpr("policy confidence "+p.Name+": softRequirement "+item.Key[1], expr)...)
			if !v2ConfidenceSoftRequirementIsRuntimeSupported(item.Key[1], expr) {
				errs = append(errs, fmt.Errorf("policy confidence %s: softRequirement %s must match runtime-supported downgrade(1)/keep behavior", p.Name, item.Key[1]))
			}
			seen["softRequirement."+item.Key[1]] = true
		default:
			errs = append(errs, fmt.Errorf("policy confidence %s: unknown item %s", p.Name, strings.Join(item.Key, ".")))
		}
	}
	for _, key := range []string{"values", "order", "aggregate", "softRequirement.missing", "softRequirement.unknown", "softRequirement.conflicting", "softRequirement.satisfied"} {
		if !seen[key] {
			errs = append(errs, fmt.Errorf("policy confidence %s: missing runtime-required item %s", p.Name, key))
		}
	}
	return errs
}

func validateV2PriorityPolicy(p *V2PolicyDecl) []error {
	var errs []error
	for _, item := range p.Items {
		switch {
		case len(item.Key) == 2 && item.Key[0] == "score":
			if len(item.Block) == 0 {
				errs = append(errs, fmt.Errorf("policy priority %s: score %s requires a block", p.Name, item.Key[1]))
				continue
			}
			for _, score := range item.Block {
				if len(score.Key) != 1 {
					errs = append(errs, fmt.Errorf("policy priority %s: malformed score key %s", p.Name, strings.Join(score.Key, ".")))
					continue
				}
				if _, ok := v2BlockValueInt(score.Value); !ok {
					errs = append(errs, fmt.Errorf("policy priority %s: score %s.%s must be an integer", p.Name, item.Key[1], score.Key[0]))
				}
			}
		case len(item.Key) == 2 && item.Key[0] == "factor":
			if len(item.Block) == 0 {
				errs = append(errs, fmt.Errorf("policy priority %s: factor %s requires a block", p.Name, item.Key[1]))
				continue
			}
			if expr, ok := v2BlockItemExpr(item.Block, "when"); ok {
				errs = append(errs, validateV2PolicyExpr("policy priority "+p.Name+": factor "+item.Key[1], expr, v2PriorityPolicyRefs, v2PriorityPolicyCalls)...)
			} else {
				errs = append(errs, fmt.Errorf("policy priority %s: factor %s requires when", p.Name, item.Key[1]))
			}
			if _, ok := v2BlockItemInt(item.Block, "weight"); !ok {
				errs = append(errs, fmt.Errorf("policy priority %s: factor %s requires integer weight", p.Name, item.Key[1]))
			}
		case len(item.Key) == 1 && item.Key[0] == "bands":
			errs = append(errs, validateV2PriorityBands(p.Name, item.Value)...)
		default:
			errs = append(errs, fmt.Errorf("policy priority %s: unknown item %s", p.Name, strings.Join(item.Key, ".")))
		}
	}
	return errs
}

func validateV2PriorityBands(policyName string, value any) []error {
	raw, ok := value.([]any)
	if !ok || len(raw) == 0 {
		return []error{fmt.Errorf("policy priority %s: bands must be a non-empty list of blocks", policyName)}
	}
	var errs []error
	for i, band := range raw {
		items, ok := band.([]V2BlockItem)
		if !ok {
			errs = append(errs, fmt.Errorf("policy priority %s: bands[%d] must be a block", policyName, i))
			continue
		}
		if v2BlockItemString(items, "band") == "" {
			errs = append(errs, fmt.Errorf("policy priority %s: bands[%d] requires band", policyName, i))
		}
		if _, ok := v2BlockItemInt(items, "min"); !ok {
			errs = append(errs, fmt.Errorf("policy priority %s: bands[%d] requires integer min", policyName, i))
		}
	}
	return errs
}

func validateV2DisplayPolicy(p *V2PolicyDecl) []error {
	var errs []error
	for _, item := range p.Items {
		switch {
		case len(item.Key) == 1 && (item.Key[0] == "scanAll" || item.Key[0] == "flagSort"):
			values := v2BlockItemValueStringList(item.Value)
			if len(values) == 0 {
				errs = append(errs, fmt.Errorf("policy display %s: %s must be a non-empty string list", p.Name, item.Key[0]))
			}
			if item.Key[0] == "scanAll" && !v2StringListEqual(values, []string{"findings", "flags", "checks", "advisoryEvidence", "requirementDiagnostics"}) {
				errs = append(errs, fmt.Errorf("policy display %s: scanAll must match runtime-supported outputs [findings, flags, checks, advisoryEvidence, requirementDiagnostics]", p.Name))
			}
		case len(item.Key) == 1 && item.Key[0] == "includeNearbyChecks":
			if _, ok := v2BlockValueBool(item.Value); !ok {
				errs = append(errs, fmt.Errorf("policy display %s: includeNearbyChecks must be boolean", p.Name))
			}
		case len(item.Key) == 1 && item.Key[0] == "nearbyCheckLimit":
			if _, ok := v2BlockValueInt(item.Value); !ok {
				errs = append(errs, fmt.Errorf("policy display %s: nearbyCheckLimit must be an integer", p.Name))
			}
		default:
			errs = append(errs, fmt.Errorf("policy display %s: unknown item %s", p.Name, strings.Join(item.Key, ".")))
		}
	}
	return errs
}

func validateV2DiagnosticPolicy(p *V2PolicyDecl) []error {
	var errs []error
	seen := map[string]bool{}
	for _, item := range p.Items {
		switch {
		case len(item.Key) == 1 && item.Key[0] == "format":
			value, ok := v2BlockValueString(item.Value)
			if !ok {
				errs = append(errs, fmt.Errorf("policy diagnostic %s: format must be a string", p.Name))
			} else if value != "structured" {
				errs = append(errs, fmt.Errorf("policy diagnostic %s: format must match runtime-supported value structured", p.Name))
			}
			seen["format"] = true
		case len(item.Key) == 1 && item.Key[0] == "fields":
			values := v2BlockItemValueStringList(item.Value)
			if len(values) == 0 {
				errs = append(errs, fmt.Errorf("policy diagnostic %s: fields must be a non-empty string list", p.Name))
			} else if !v2StringListEqual(values, []string{"file", "line", "column", "declarationId", "code", "message", "why", "suggestedFix"}) {
				errs = append(errs, fmt.Errorf("policy diagnostic %s: fields must match runtime-supported fields [file, line, column, declarationId, code, message, why, suggestedFix]", p.Name))
			}
			seen["fields"] = true
		default:
			errs = append(errs, fmt.Errorf("policy diagnostic %s: unknown item %s", p.Name, strings.Join(item.Key, ".")))
		}
	}
	for _, key := range []string{"format", "fields"} {
		if !seen[key] {
			errs = append(errs, fmt.Errorf("policy diagnostic %s: missing runtime-required item %s", p.Name, key))
		}
	}
	return errs
}

func validateV2StringListPolicy(p *V2PolicyDecl, allowedKeys ...string) []error {
	allowed := v2StringSet(allowedKeys)
	var errs []error
	for _, item := range p.Items {
		if len(item.Key) != 1 || !allowed[item.Key[0]] {
			errs = append(errs, fmt.Errorf("policy %s %s: unknown item %s", p.Kind, p.Name, strings.Join(item.Key, ".")))
			continue
		}
		if len(v2BlockItemValueStringList(item.Value)) == 0 {
			errs = append(errs, fmt.Errorf("policy %s %s: %s must be a non-empty string list", p.Kind, p.Name, item.Key[0]))
			continue
		}
		if p.Kind == "resultIdentity" {
			errs = append(errs, validateV2ResultIdentityRuntimeField(p.Name, item.Key[0], v2BlockItemValueStringList(item.Value))...)
		}
	}
	return errs
}

func validateV2ResultIdentityRuntimeField(policyName, field string, values []string) []error {
	switch field {
	case "flagKey":
		if !v2StringListEqual(values, []string{"concept", "location", "call.path", "call.method"}) {
			return []error{fmt.Errorf("policy resultIdentity %s: flagKey must match runtime-supported key [concept, location, call.path, call.method]", policyName)}
		}
	case "stableAcross":
		if !v2StringListEqual(values, []string{"formatting", "requirementDiagnosticText", "traversalOrder"}) {
			return []error{fmt.Errorf("policy resultIdentity %s: stableAcross must match runtime-supported metadata [formatting, requirementDiagnosticText, traversalOrder]", policyName)}
		}
	}
	return nil
}

func v2ExprEqual(a, b V2Expr) bool {
	switch ax := a.(type) {
	case nil:
		return b == nil
	case V2RefExpr:
		bx, ok := b.(V2RefExpr)
		return ok && ax.Name == bx.Name
	case V2LiteralExpr:
		bx, ok := b.(V2LiteralExpr)
		return ok && reflect.DeepEqual(ax.Value, bx.Value)
	case V2UnaryExpr:
		bx, ok := b.(V2UnaryExpr)
		return ok && ax.Op == bx.Op && v2ExprEqual(ax.X, bx.X)
	case V2BinaryExpr:
		bx, ok := b.(V2BinaryExpr)
		return ok && ax.Op == bx.Op && v2ExprEqual(ax.Left, bx.Left) && v2ExprEqual(ax.Right, bx.Right)
	case V2CallExpr:
		bx, ok := b.(V2CallExpr)
		if !ok || ax.Name != bx.Name || len(ax.Args) != len(bx.Args) || len(ax.NamedArgs) != len(bx.NamedArgs) {
			return false
		}
		for i := range ax.Args {
			if !v2ExprEqual(ax.Args[i], bx.Args[i]) {
				return false
			}
		}
		for i := range ax.NamedArgs {
			if ax.NamedArgs[i].Name != bx.NamedArgs[i].Name || !v2ExprEqual(ax.NamedArgs[i].Expr, bx.NamedArgs[i].Expr) {
				return false
			}
		}
		return true
	case V2SequenceExpr:
		bx, ok := b.(V2SequenceExpr)
		if !ok || len(ax.Items) != len(bx.Items) {
			return false
		}
		for i := range ax.Items {
			if !v2ExprEqual(ax.Items[i], bx.Items[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func v2ConfidenceAggregateIsRuntimeSupported(expr V2Expr) bool {
	call, ok := expr.(V2CallExpr)
	if !ok || call.Name != "min" || len(call.NamedArgs) != 0 || len(call.Args) != 4 {
		return false
	}
	for i, want := range []string{"rule", "endpoints", "propagation", "requirements"} {
		ref, ok := call.Args[i].(V2RefExpr)
		if !ok || ref.Name != want {
			return false
		}
	}
	return true
}

func v2ConfidenceSoftRequirementIsRuntimeSupported(state string, expr V2Expr) bool {
	if state == "satisfied" {
		ref, ok := expr.(V2RefExpr)
		return ok && ref.Name == "keep"
	}
	if state != "missing" && state != "unknown" && state != "conflicting" {
		return false
	}
	return v2ExprSequenceContainsDowngradeOne(expr)
}

func v2ExprSequenceContainsDowngradeOne(expr V2Expr) bool {
	if seq, ok := expr.(V2SequenceExpr); ok {
		for _, item := range seq.Items {
			if v2ExprSequenceContainsDowngradeOne(item) {
				return true
			}
		}
		return false
	}
	call, ok := expr.(V2CallExpr)
	if !ok || call.Name != "downgrade" || len(call.NamedArgs) != 0 || len(call.Args) != 1 {
		return false
	}
	n, ok := v2ExprInt(call.Args[0])
	return ok && n == 1
}

func v2StringListEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

var (
	v2RequirementEvidenceStates = map[string]bool{"satisfied": true, "missing": true, "unknown": true, "conflicting": true}
	v2LifecyclePolicyRefs       = map[string]bool{"explainsFinding": true, "candidate": true, "covered": true, "rule": true, "concept": true, "source": true, "sink": true, "check": true, "issue": true, "fact": true, "asset": true, "exposure": true, "principal": true, "privilege": true, "state": true}
	v2LifecyclePolicyCalls      = map[string]int{"emitted": 1, "matched": 1, "hasReview": 1}
	v2ConfidencePolicyRefs      = map[string]bool{"rule": true, "endpoints": true, "propagation": true, "requirements": true}
	v2ConfidencePolicyCalls     = map[string]int{"min": -1, "max": -1}
	v2PriorityPolicyRefs        = map[string]bool{"context": true, "finding": true, "rule": true, "requirement": true, "low": true, "medium": true, "high": true, "critical": true, "info": true}
	v2PriorityPolicyCalls       = map[string]int{}
)

func validateV2PolicyExpr(ctx string, expr V2Expr, allowedRefs map[string]bool, allowedCalls map[string]int) []error {
	switch x := expr.(type) {
	case nil:
		return nil
	case V2LiteralExpr:
		return nil
	case V2RefExpr:
		if v2PolicyRefAllowed(x.Name, allowedRefs) {
			return nil
		}
		return []error{fmt.Errorf("%s: unknown policy reference %q", ctx, x.Name)}
	case V2UnaryExpr:
		if x.Op != "not" {
			return []error{fmt.Errorf("%s: unsupported policy unary operator %q", ctx, x.Op)}
		}
		return validateV2PolicyExpr(ctx, x.X, allowedRefs, allowedCalls)
	case V2BinaryExpr:
		if !v2PolicyBinaryOps[x.Op] {
			return []error{fmt.Errorf("%s: unsupported policy binary operator %q", ctx, x.Op)}
		}
		errs := validateV2PolicyExpr(ctx, x.Left, allowedRefs, allowedCalls)
		errs = append(errs, validateV2PolicyExpr(ctx, x.Right, allowedRefs, allowedCalls)...)
		return errs
	case V2CallExpr:
		want, ok := allowedCalls[x.Name]
		if !ok {
			return []error{fmt.Errorf("%s: unknown policy builtin %q", ctx, x.Name)}
		}
		if want >= 0 && len(x.Args) != want {
			return []error{fmt.Errorf("%s: policy builtin %s expects %d argument(s)", ctx, x.Name, want)}
		}
		if len(x.NamedArgs) != 0 {
			return []error{fmt.Errorf("%s: policy builtin %s does not accept named arguments", ctx, x.Name)}
		}
		var errs []error
		for _, arg := range x.Args {
			errs = append(errs, validateV2PolicyExpr(ctx, arg, allowedRefs, allowedCalls)...)
		}
		return errs
	case V2SequenceExpr:
		var errs []error
		for _, item := range x.Items {
			errs = append(errs, validateV2PolicyExpr(ctx, item, allowedRefs, allowedCalls)...)
		}
		return errs
	default:
		return []error{fmt.Errorf("%s: unsupported policy expression %T", ctx, expr)}
	}
}

var v2PolicyBinaryOps = map[string]bool{"and": true, "or": true, "==": true, "!=": true, ">=": true, "<=": true, ">": true, "<": true}

func v2PolicyRefAllowed(ref string, allowed map[string]bool) bool {
	if allowed[ref] {
		return true
	}
	if head, _, ok := strings.Cut(ref, "."); ok && allowed[head] {
		return true
	}
	return false
}

func validateV2ConfidenceActionExpr(ctx string, expr V2Expr) []error {
	switch x := expr.(type) {
	case V2RefExpr:
		if x.Name == "keep" {
			return nil
		}
		return []error{fmt.Errorf("%s: unknown confidence action %q", ctx, x.Name)}
	case V2SequenceExpr:
		var errs []error
		for _, item := range x.Items {
			errs = append(errs, validateV2ConfidenceActionExpr(ctx, item)...)
		}
		return errs
	case V2CallExpr:
		switch x.Name {
		case "downgrade":
			if len(x.Args) != 1 || len(x.NamedArgs) != 0 {
				return []error{fmt.Errorf("%s: downgrade expects one positional argument", ctx)}
			}
			if _, ok := v2ExprInt(x.Args[0]); !ok {
				return []error{fmt.Errorf("%s: downgrade argument must be an integer", ctx)}
			}
		case "annotate":
			if len(x.Args) != 1 || len(x.NamedArgs) != 0 {
				return []error{fmt.Errorf("%s: annotate expects one positional argument", ctx)}
			}
			if _, ok := v2ExprString(x.Args[0]); !ok {
				return []error{fmt.Errorf("%s: annotate argument must be a string", ctx)}
			}
		default:
			return []error{fmt.Errorf("%s: unknown confidence action %q", ctx, x.Name)}
		}
		return nil
	default:
		return []error{fmt.Errorf("%s: unsupported confidence action %T", ctx, expr)}
	}
}

func validateV2CoverageMechanicExpr(mode string, targetParts []string, expr V2Expr) []error {
	call, ok := expr.(V2CallExpr)
	if !ok {
		return []error{fmt.Errorf("mechanic coverage %s: coversWhen must be a known indexed solver call", mode)}
	}
	if !v2ContainsString(v2CoverageSolversByMode[mode], call.Name) {
		return []error{fmt.Errorf("mechanic coverage %s: coversWhen uses non-indexed or wrong solver %q", mode, call.Name)}
	}
	if mode == "global" && len(call.Args) != 0 {
		return []error{fmt.Errorf("mechanic coverage global: coversWhen solver %q expects no arguments", call.Name)}
	}
	if len(call.Args) != 2 && mode != "global" {
		return []error{fmt.Errorf("mechanic coverage %s: coversWhen solver %q expects exactly two arguments", mode, call.Name)}
	}
	if len(call.NamedArgs) != 0 {
		return []error{fmt.Errorf("mechanic coverage %s: coversWhen solver %q does not accept named arguments", mode, call.Name)}
	}
	var errs []error
	if mode == "global" {
		return nil
	}
	targetSet := v2StringSet(targetParts)
	for i, arg := range call.Args {
		ref, ok := arg.(V2RefExpr)
		if !ok {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: coversWhen argument %q is not an indexable check/candidate reference", mode, v2ExprDebug(arg)))
			continue
		}
		if i == 0 && !strings.HasPrefix(ref.Name, "check.") {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: first coversWhen argument %q must be a check index", mode, ref.Name))
			continue
		}
		if i == 1 && !strings.HasPrefix(ref.Name, "candidate.") {
			errs = append(errs, fmt.Errorf("mechanic coverage %s: second coversWhen argument %q must be a candidate index", mode, ref.Name))
			continue
		}
		if i == 1 {
			part := strings.TrimPrefix(ref.Name, "candidate.")
			if len(targetSet) != 0 && !targetSet[part] {
				errs = append(errs, fmt.Errorf("mechanic coverage %s: candidate index %q is not declared in targetParts [%s]", mode, ref.Name, strings.Join(v2SortedStrings(targetSet), ", ")))
			}
		}
	}
	return errs
}

func v2ContainsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func v2CoverageRefAllowed(ref string) bool {
	return strings.HasPrefix(ref, "check.") || strings.HasPrefix(ref, "candidate.")
}

func validateV2Pattern(pat *V2PatternDecl) []error {
	var errs []error
	unstableOK := false
	useCount := 0
	nodeCount := 0
	for _, item := range pat.Items {
		switch item.Kind {
		case "unstable":
			if !v2UnstableMetadataOK(item.Meta) {
				errs = append(errs, fmt.Errorf("pattern %s: unstable metadata requires owner and reason", pat.Name))
			} else {
				unstableOK = true
			}
		case "node":
			nodeCount++
			if !v2FamilyAllowed(item.Name, "recognition") {
				errs = append(errs, fmt.Errorf("pattern %s: node family %q is not a project/code family", pat.Name, item.Name))
			}
			errs = append(errs, validateV2SchemaGatedFamily("pattern "+pat.Name, item.Name, false)...)
			if strings.HasPrefix(item.Name, "unstable.") && !unstableOK {
				errs = append(errs, fmt.Errorf("pattern %s: unstable node family %q requires owner and reason metadata", pat.Name, item.Name))
			}
		case "where":
			if calls := v2RequirementCallsInExpr(item.Expr); len(calls) > 0 {
				errs = append(errs, fmt.Errorf("pattern %s: project prerequisites %s belong in requires, not where", pat.Name, strings.Join(calls, ", ")))
			}
		case "use":
			useCount++
		}
	}
	if useCount > 0 && nodeCount > 0 {
		errs = append(errs, fmt.Errorf("pattern %s: composed pattern use with additional node is an arbitrary Cartesian composition; connect subpatterns with stable query relations instead", pat.Name))
	}
	return errs
}

func validateV2Binding(b *V2BindingDecl, conceptKinds map[string]string) []error {
	var errs []error
	if fidelity := b.Attrs["fidelity"]; fidelity != "" && !v2FidelityLevels[fidelity] {
		errs = append(errs, fmt.Errorf("binding %s: unknown fidelity level %q", b.Name, fidelity))
	}
	if confidence := b.Attrs["confidence"]; confidence != "" && !v2ConfidenceLevels[confidence] {
		errs = append(errs, fmt.Errorf("binding %s: unknown confidence level %q", b.Name, confidence))
	}
	for _, req := range b.Requirements {
		errs = append(errs, validateV2Requirement("binding "+b.Name, req)...)
	}
	if b.Query.Expr != nil {
		if b.Query.Expr.Family == "unstable.legacyFlag" {
			errs = append(errs, fmt.Errorf("binding %s: legacy query family %q is not valid v2; use stable presenceNode or callExpr patterns", b.Name, b.Query.Expr.Family))
		}
		if strings.HasPrefix(b.Query.Expr.Family, "unstable.") && !v2UnstableMetadataOK(b.Unstable) {
			errs = append(errs, fmt.Errorf("binding %s: unstable query family %q requires owner and reason metadata", b.Name, b.Query.Expr.Family))
		}
		errs = append(errs, validateV2QueryFamilies("binding "+b.Name, *b.Query.Expr, "recognition")...)
		errs = append(errs, validateV2SchemaGatedQueryFamilies("binding "+b.Name, *b.Query.Expr, v2RequirementsHaveHardSchema(b.Requirements, "nir", "2.0"))...)
		if calls := v2RequirementCallsInExpr(b.Query.Expr.Where); len(calls) > 0 {
			errs = append(errs, fmt.Errorf("binding %s: project prerequisites %s belong in requires, not query where", b.Name, strings.Join(calls, ", ")))
		}
		for _, step := range b.Query.Expr.Steps {
			if !v2SupportedBindingQueryRelationStep(*b.Query.Expr, step) {
				errs = append(errs, fmt.Errorf("binding %s: query relation step %s %s needs native production v2 lowering", b.Name, step.Relation, step.Family))
			}
			if calls := v2RequirementCallsInExpr(step.Where); len(calls) > 0 {
				errs = append(errs, fmt.Errorf("binding %s: project prerequisites %s belong in requires, not query where", b.Name, strings.Join(calls, ", ")))
			}
		}
	}
	if calls := v2RequirementCallsInExpr(b.Query.Where); len(calls) > 0 {
		errs = append(errs, fmt.Errorf("binding %s: project prerequisites %s belong in requires, not query where", b.Name, strings.Join(calls, ", ")))
	}
	if len(b.Outputs) == 0 {
		errs = append(errs, fmt.Errorf("binding %s: binding requires at least one emit or propagate output", b.Name))
	}
	for _, out := range b.Outputs {
		if strings.HasPrefix(out.Kind, "emit ") {
			kind := strings.TrimPrefix(out.Kind, "emit ")
			if !v2EmitKinds[kind] {
				errs = append(errs, fmt.Errorf("binding %s: unknown emit kind %q", b.Name, kind))
			}
		}
		if strings.HasPrefix(out.Kind, "propagate ") {
			kind := strings.TrimPrefix(out.Kind, "propagate ")
			if !v2PropagateKinds[kind] {
				errs = append(errs, fmt.Errorf("binding %s: unknown propagate kind %q", b.Name, kind))
			} else if !v2ProductionPropagateKinds[kind] {
				errs = append(errs, fmt.Errorf("binding %s: propagate kind %q is not implemented in production v2", b.Name, kind))
			}
		}
		errs = append(errs, validateV2EmitConceptKind("binding "+b.Name, out.Kind, out.Concept, conceptKinds)...)
		if out.Kind == "emit check" {
			advisory := out.Advisory != nil && *out.Advisory
			if !advisory && len(out.Covers) == 0 && !isV2PresenceNodeBinding(b) {
				errs = append(errs, fmt.Errorf("binding %s: non-advisory check %s requires concrete covers metadata", b.Name, out.Concept))
			}
		}
		for _, cov := range out.Covers {
			if !v2CoverageModes[cov.Mode] {
				errs = append(errs, fmt.Errorf("binding %s: unknown coverage mode %q", b.Name, cov.Mode))
			}
			errs = append(errs, validateV2CoverageBlock("binding "+b.Name, cov)...)
		}
	}
	return errs
}

func v2SupportedBindingQueryRelationStep(q V2QueryExpr, step V2QueryStep) bool {
	if normalizedV2CodeFamily(q.Family) == "call" &&
		(step.Relation == "references" || step.Relation == "sameScope") &&
		normalizedV2CodeFamily(step.Family) == "call" &&
		step.Alias != "" &&
		step.Where != nil {
		return true
	}
	return normalizedV2CodeFamily(q.Family) == "call" &&
		(step.Relation == "encloses" || step.Relation == "contains") &&
		v2LiteralRelationFamily(step.Family) &&
		step.Alias != "" &&
		step.Where != nil
}

func v2LiteralRelationFamily(family string) bool {
	switch family {
	case "literal", "stringLiteral":
		return true
	default:
		return false
	}
}

func isV2PresenceNodeBinding(b *V2BindingDecl) bool {
	return b.Query.Expr == nil && b.Query.Pattern == "presenceNode"
}

func validateV2CoverageBlock(ctx string, cov V2Coverage) []error {
	has := func(key string) bool {
		_, ok := cov.Items[key]
		return ok
	}
	var errs []error
	switch cov.Mode {
	case "path", "dominates":
		if !has("from") || !has("to") {
			errs = append(errs, fmt.Errorf("%s: covers %s requires from and to", ctx, cov.Mode))
		}
	case "endpoint", "sameReceiver", "sameScope":
		if !has("anchor") {
			errs = append(errs, fmt.Errorf("%s: covers %s requires anchor", ctx, cov.Mode))
		}
	case "global":
		if len(cov.Items) != 0 {
			errs = append(errs, fmt.Errorf("%s: covers global must not declare anchor/from/to fields", ctx))
		}
	}
	return errs
}

func v2UnstableMetadataOK(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	owner, ok := meta["owner"].(string)
	if !ok || strings.TrimSpace(owner) == "" {
		return false
	}
	reason, ok := meta["reason"].(string)
	return ok && strings.TrimSpace(reason) != ""
}

func validateV2Rule(r *V2RuleDecl, conceptKinds map[string]string) []error {
	var errs []error
	switch r.Body.Verb {
	case "issue":
		errs = append(errs, validateV2RuleEndpointKind("rule "+r.Name, "issue", r.Body.Issue.Concept, conceptKinds)...)
	case "fact":
		errs = append(errs, validateV2RuleEndpointKind("rule "+r.Name, "fact", r.Body.Issue.Concept, conceptKinds)...)
	}
	if r.Body.Verb == "query" && r.Body.Query != nil {
		errs = append(errs, validateV2QueryFamilies("rule "+r.Name, *r.Body.Query, "semantic")...)
		if r.Body.Select == "" || !v2QueryHasAlias(*r.Body.Query, r.Body.Select) {
			errs = append(errs, fmt.Errorf("rule %s: raw query select %q does not name a query alias", r.Name, r.Body.Select))
		}
	}
	for _, cl := range r.Clauses {
		if cl.Kind == "unless" && !v2CoverageModes[cl.Coverage] {
			errs = append(errs, fmt.Errorf("rule %s: coveredBy target %q must name an explicit coverage part", r.Name, cl.Target))
		}
		if cl.Kind == "with" && !v2ConfidenceLevels[cl.Value] {
			errs = append(errs, fmt.Errorf("rule %s: unknown confidence level %q", r.Name, cl.Value))
		}
	}
	return errs
}

func validateV2EmitConceptKind(ctx, emitKind, concept string, conceptKinds map[string]string) []error {
	if concept == "" || !strings.HasPrefix(emitKind, "emit ") {
		return nil
	}
	kind, ok := conceptKinds[concept]
	if !ok {
		return nil
	}
	want := strings.TrimPrefix(emitKind, "emit ")
	switch want {
	case "source", "sink", "check", "issue":
		if kind != want {
			return []error{fmt.Errorf("%s: %s uses concept %s of kind %s", ctx, emitKind, concept, kind)}
		}
	case "fact":
		if !v2FactEmitKinds[kind] {
			return []error{fmt.Errorf("%s: emit fact uses concept %s of kind %s", ctx, concept, kind)}
		}
	}
	return nil
}

func validateV2RuleEndpointKind(ctx, verb, concept string, conceptKinds map[string]string) []error {
	kind, ok := conceptKinds[concept]
	if !ok {
		return nil
	}
	if verb == "issue" && kind != "issue" {
		return []error{fmt.Errorf("%s: issue rule uses concept %s of kind %s", ctx, concept, kind)}
	}
	if verb == "fact" && !v2FactEmitKinds[kind] {
		return []error{fmt.Errorf("%s: fact rule uses concept %s of kind %s", ctx, concept, kind)}
	}
	return nil
}

func validateV2Requirement(ctx string, req V2Requirement) []error {
	var errs []error
	if !v2RequirementPrimitives[req.Name] && !v2RequirementCombinators[req.Name] {
		errs = append(errs, fmt.Errorf("%s: unknown requirement %q", ctx, req.Name))
	}
	if req.Name == "not" || req.Name == "soft" {
		children := 0
		for _, arg := range req.Args {
			if _, ok := arg.(V2Requirement); ok {
				children++
			}
		}
		if children != 1 {
			errs = append(errs, fmt.Errorf("%s: requirement %s expects exactly one child requirement", ctx, req.Name))
		}
	}
	for _, arg := range req.Args {
		if child, ok := arg.(V2Requirement); ok {
			errs = append(errs, validateV2Requirement(ctx, child)...)
		}
	}
	return errs
}

func validateV2Profile(p *V2ProfileDecl) []error {
	raw, ok := p.Fields["detect"]
	if !ok {
		return nil
	}
	exprs, ok := raw.([]V2Expr)
	if !ok {
		return []error{fmt.Errorf("profile %s: detect must use v2 requirement predicate expressions", p.Name)}
	}
	if len(exprs) == 0 {
		return []error{fmt.Errorf("profile %s: detect must not be empty", p.Name)}
	}
	var errs []error
	for _, expr := range exprs {
		errs = append(errs, validateV2ProfileDetectExpr("profile "+p.Name+" detect", expr)...)
	}
	return errs
}

func validateV2ProfileDetectExpr(ctx string, expr V2Expr) []error {
	call, ok := expr.(V2CallExpr)
	if !ok {
		return []error{fmt.Errorf("%s: detect entries must be requirement predicate calls", ctx)}
	}
	if call.Name == "soft" {
		return []error{fmt.Errorf("%s: soft requirement is not valid for profile activation", ctx)}
	}
	if !v2RequirementPrimitives[call.Name] && !v2RequirementCombinators[call.Name] {
		return []error{fmt.Errorf("%s: unknown requirement %q", ctx, call.Name)}
	}
	if len(call.NamedArgs) != 0 {
		return []error{fmt.Errorf("%s: requirement %s does not support named arguments in profile activation", ctx, call.Name)}
	}
	var errs []error
	switch call.Name {
	case "all", "any":
		if len(call.Args) == 0 {
			errs = append(errs, fmt.Errorf("%s: requirement %s expects at least one child requirement", ctx, call.Name))
		}
		for _, arg := range call.Args {
			errs = append(errs, validateV2ProfileDetectExpr(ctx, arg)...)
		}
	case "not":
		if len(call.Args) != 1 {
			errs = append(errs, fmt.Errorf("%s: requirement not expects exactly one child requirement", ctx))
		}
		for _, arg := range call.Args {
			errs = append(errs, validateV2ProfileDetectExpr(ctx, arg)...)
		}
	default:
		if len(call.Args) == 0 {
			errs = append(errs, fmt.Errorf("%s: requirement %s requires at least one string argument", ctx, call.Name))
		}
		for _, arg := range call.Args {
			if _, ok := v2LiteralString(arg); !ok {
				errs = append(errs, fmt.Errorf("%s: requirement %s expects string arguments", ctx, call.Name))
			}
		}
	}
	return errs
}

func validateV2QueryFamilies(ctx string, q V2QueryExpr, role string) []error {
	var errs []error
	if !v2FamilyAllowed(q.Family, role) {
		errs = append(errs, fmt.Errorf("%s: query family %q is not allowed in %s-tier query", ctx, q.Family, role))
	}
	for _, step := range q.Steps {
		if !v2FamilyAllowed(step.Family, role) {
			errs = append(errs, fmt.Errorf("%s: query family %q is not allowed in %s-tier query", ctx, step.Family, role))
		}
	}
	return errs
}

func validateV2SchemaGatedQueryFamilies(ctx string, q V2QueryExpr, hasNIRSchema bool) []error {
	var errs []error
	errs = append(errs, validateV2SchemaGatedFamily(ctx, q.Family, hasNIRSchema)...)
	for _, step := range q.Steps {
		errs = append(errs, validateV2SchemaGatedFamily(ctx, step.Family, hasNIRSchema)...)
	}
	return errs
}

func validateV2SchemaGatedFamily(ctx, family string, hasNIRSchema bool) []error {
	schema, ok := v2SchemaGatedCodeFamilies[family]
	if !ok || hasNIRSchema {
		return nil
	}
	return []error{fmt.Errorf("%s: query family %q requires hard schema(%q, \"2.0\") requirement", ctx, family, schema)}
}

func v2RequirementsHaveHardSchema(reqs []V2Requirement, schema, version string) bool {
	for _, req := range reqs {
		if v2RequirementHasHardSchema(req, schema, version) {
			return true
		}
	}
	return false
}

func v2RequirementHasHardSchema(req V2Requirement, schema, version string) bool {
	switch req.Name {
	case "schema":
		values := v2RequirementStringArgs(req)
		return len(values) >= 2 && values[0] == schema && values[1] == version
	case "all":
		for _, raw := range req.Args {
			child, ok := raw.(V2Requirement)
			if ok && v2RequirementHasHardSchema(child, schema, version) {
				return true
			}
		}
	}
	return false
}

func v2RequirementStringArgs(req V2Requirement) []string {
	out := make([]string, 0, len(req.Args))
	for _, raw := range req.Args {
		if s, ok := raw.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func v2FamilyAllowed(family, role string) bool {
	if family == "unstable.legacyFlag" {
		return false
	}
	if strings.HasPrefix(family, "unstable.") {
		return role == "recognition"
	}
	switch role {
	case "recognition":
		return v2ProjectFamilies[family] || v2CodeFamilies[family]
	case "semantic":
		return v2SemanticFamilies[family]
	}
	return false
}

func v2QueryHasAlias(q V2QueryExpr, alias string) bool {
	if q.Alias == alias {
		return true
	}
	for _, step := range q.Steps {
		if step.Alias == alias {
			return true
		}
	}
	return false
}

func v2BlockItemExists(items []V2BlockItem, key string) bool {
	for _, item := range items {
		if len(item.Key) == 1 && item.Key[0] == key {
			return true
		}
	}
	return false
}

func v2BlockItemString(items []V2BlockItem, key string) string {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		switch v := item.Value.(type) {
		case string:
			return v
		case V2RefExpr:
			return v.Name
		case V2LiteralExpr:
			if s, ok := v.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func v2BlockItemStringList(items []V2BlockItem, key string) []string {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		return v2BlockItemValueStringList(item.Value)
	}
	return nil
}

func v2BlockItemValueStringList(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case V2RefExpr:
			out = append(out, x.Name)
		case V2LiteralExpr:
			if s, ok := x.Value.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func v2BlockItemInt(items []V2BlockItem, key string) (int, bool) {
	for _, item := range items {
		if len(item.Key) == 1 && item.Key[0] == key {
			return v2BlockValueInt(item.Value)
		}
	}
	return 0, false
}

func v2BlockValueInt(value any) (int, bool) {
	switch x := value.(type) {
	case int:
		return x, true
	case V2LiteralExpr:
		return v2ExprInt(x)
	default:
		return 0, false
	}
}

func v2BlockValueString(value any) (string, bool) {
	switch x := value.(type) {
	case string:
		return x, true
	case V2RefExpr:
		return x.Name, true
	case V2LiteralExpr:
		s, ok := x.Value.(string)
		return s, ok
	default:
		return "", false
	}
}

func v2ExprInt(expr V2Expr) (int, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return 0, false
	}
	n, ok := lit.Value.(int)
	return n, ok
}

func v2ExprString(expr V2Expr) (string, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return "", false
	}
	s, ok := lit.Value.(string)
	return s, ok
}

func v2BlockItemBool(items []V2BlockItem, key string) (bool, bool) {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		switch value := item.Value.(type) {
		case bool:
			return value, true
		case V2LiteralExpr:
			if b, ok := value.Value.(bool); ok {
				return b, true
			}
		}
		return false, false
	}
	return false, false
}

func v2BlockValueBool(value any) (bool, bool) {
	switch x := value.(type) {
	case bool:
		return x, true
	case V2LiteralExpr:
		b, ok := x.Value.(bool)
		return b, ok
	default:
		return false, false
	}
}

func v2BlockItemExpr(items []V2BlockItem, key string) (V2Expr, bool) {
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		expr, ok := item.Value.(V2Expr)
		return expr, ok
	}
	return nil, false
}

func v2ExprDebug(expr V2Expr) string {
	switch x := expr.(type) {
	case nil:
		return "<nil>"
	case V2RefExpr:
		return x.Name
	case V2LiteralExpr:
		return fmt.Sprint(x.Value)
	case V2CallExpr:
		return x.Name + "(...)"
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func v2RequirementCallsInExpr(expr V2Expr) []string {
	seen := map[string]bool{}
	var out []string
	var visit func(V2Expr)
	visit = func(e V2Expr) {
		switch x := e.(type) {
		case nil:
			return
		case V2CallExpr:
			if v2RequirementPrimitives[x.Name] && !seen[x.Name] {
				seen[x.Name] = true
				out = append(out, x.Name)
			}
			for _, arg := range x.Args {
				visit(arg)
			}
			for _, arg := range x.NamedArgs {
				visit(arg.Expr)
			}
		case V2UnaryExpr:
			visit(x.X)
		case V2BinaryExpr:
			visit(x.Left)
			visit(x.Right)
		}
	}
	visit(expr)
	return out
}

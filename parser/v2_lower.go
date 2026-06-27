package parser

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseV2Definitions parses authored VyQL v2 definition modules and compiles
// them into the scanner IR.
func ParseV2Definitions(src string) ([]Decl, error) {
	prog, err := ParseV2(src)
	if err != nil {
		return nil, err
	}
	return lowerV2ProgramToDeclarations(prog)
}

type V2DefinitionSource struct {
	Name   string
	Source string
}

func V2DefinitionSourcesFromText(name, src string) []V2DefinitionSource {
	return []V2DefinitionSource{{Name: name, Source: src}}
}

func ParseV2DefinitionSources(raw []V2DefinitionSource) ([]Decl, error) {
	return ParseV2DefinitionSourcesSelected(raw, nil)
}

// ParseV2DefinitionSourcesSelected validates the full v2 corpus but only lowers
// sources accepted by keep. A nil keep function lowers every source.
func ParseV2DefinitionSourcesSelected(raw []V2DefinitionSource, keep func(V2DefinitionSource) bool) ([]Decl, error) {
	sources := make([]V2Source, 0, len(raw))
	keepSource := make([]bool, 0, len(raw))
	for _, src := range raw {
		prog, err := ParseV2(src.Source)
		if err != nil {
			return nil, fmt.Errorf("%s: v2 parse failed: %w", src.Name, err)
		}
		sources = append(sources, V2Source{Name: src.Name, Program: prog})
		keepSource = append(keepSource, keep == nil || keep(src))
	}
	if err := ValidateV2Corpus(sources); err != nil {
		return nil, fmt.Errorf("v2 corpus validation failed: %w", err)
	}
	return lowerV2DefinitionSourcesSelected(sources, keepSource)
}

// lowerV2ProgramToDeclarations compiles authored v2 definitions into scanner IR.
func lowerV2ProgramToDeclarations(prog *V2Program) ([]Decl, error) {
	mechanics := v2Mechanics{ruleSolvers: builtinV2RuleSolvers(), coverageModes: builtinV2CoverageModes()}
	mechanics.merge(v2MechanicsFromProgram(prog))
	return lowerV2ProgramToDeclarationsWithMechanics(prog, mechanics)
}

func LowerV2DefinitionSources(sources []V2Source) ([]Decl, error) {
	if err := validateV2ParsedSourceMechanicBoundary(sources); err != nil {
		return nil, err
	}
	return lowerV2DefinitionSourcesSelected(sources, nil)
}

func validateV2ParsedSourceMechanicBoundary(sources []V2Source) error {
	builtins := builtinV2MechanicSources()
	var errs []error
	for _, src := range sources {
		if src.Program == nil {
			continue
		}
		for _, decl := range src.Program.Decls {
			m, ok := decl.(*V2MechanicDecl)
			if !ok {
				continue
			}
			key := v2MechanicID{Kind: m.Kind, Name: m.Name}
			if builtins[key] != "" {
				errs = append(errs, fmt.Errorf("%s: duplicate v2 mechanic %s.%s; first declared in <builtin>", src.Name, m.Kind, m.Name))
			}
		}
	}
	return errors.Join(errs...)
}

func lowerV2DefinitionSourcesSelected(sources []V2Source, keep []bool) ([]Decl, error) {
	mechanics := v2Mechanics{ruleSolvers: builtinV2RuleSolvers(), coverageModes: builtinV2CoverageModes()}
	outCap := 0
	for _, src := range sources {
		mechanics.merge(v2MechanicsFromProgram(src.Program))
	}
	for i, src := range sources {
		if keep != nil && !keep[i] {
			continue
		}
		if src.Program != nil {
			outCap += len(src.Program.Decls)
		}
	}
	out := make([]Decl, 0, outCap)
	for i, src := range sources {
		if keep != nil && !keep[i] {
			continue
		}
		decls, err := lowerV2ProgramToDeclarationsWithMechanics(src.Program, mechanics)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		out = append(out, decls...)
	}
	return out, nil
}

type v2Mechanics struct {
	ruleSolvers   map[string]string
	coverageModes map[string]bool
	policies      map[string]bool
	matchers      map[string]v2MatcherSpec
}

type v2MatcherSpec struct {
	Op          string
	Values      []string
	Unsupported string
}

func (m *v2Mechanics) merge(other v2Mechanics) {
	if len(other.ruleSolvers) != 0 && m.ruleSolvers == nil {
		m.ruleSolvers = make(map[string]string, len(other.ruleSolvers))
	}
	for verb, solver := range other.ruleSolvers {
		m.ruleSolvers[verb] = solver
	}
	if len(other.coverageModes) != 0 && m.coverageModes == nil {
		m.coverageModes = make(map[string]bool, len(other.coverageModes))
	}
	for mode := range other.coverageModes {
		m.coverageModes[mode] = true
	}
	if len(other.policies) != 0 && m.policies == nil {
		m.policies = make(map[string]bool, len(other.policies))
	}
	for policy := range other.policies {
		m.policies[policy] = true
	}
	if len(other.matchers) != 0 && m.matchers == nil {
		m.matchers = make(map[string]v2MatcherSpec, len(other.matchers))
	}
	for name, matcher := range other.matchers {
		m.matchers[name] = matcher
	}
}

func v2MechanicsFromProgram(prog *V2Program) v2Mechanics {
	out := v2Mechanics{ruleSolvers: map[string]string{}, coverageModes: map[string]bool{}, policies: map[string]bool{}, matchers: map[string]v2MatcherSpec{}}
	if prog == nil {
		return out
	}
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *V2MechanicDecl:
			switch x.Kind {
			case "ruleVerb":
				if solver := v2BlockItemString(x.Items, "solver"); solver != "" {
					out.ruleSolvers[x.Name] = solver
				}
			case "coverage":
				out.coverageModes[x.Name] = true
			}
		case *V2PolicyDecl:
			out.policies[x.Kind+":"+x.Name] = true
		case *V2MatcherDecl:
			spec := v2MatcherSpecFromDecl(x)
			_, fq := v2DeclNames(prog.Module, x)
			if fq != "" {
				out.matchers[fq] = spec
			}
		}
	}
	return out
}

func v2MatcherSpecFromDecl(m *V2MatcherDecl) v2MatcherSpec {
	var spec v2MatcherSpec
	for _, item := range m.Items {
		op := ""
		switch item.Kind {
		case "containsAny":
			op = "contains_any"
		case "equalsAny":
			op = "equals_any"
		case "matches":
			op = "matches"
		}
		if op == "" {
			continue
		}
		if spec.Op == "" {
			spec.Op = op
		} else if spec.Op != op {
			spec.Unsupported = "mixed matcher item kinds"
		}
		spec.Values = append(spec.Values, item.Values...)
	}
	return spec
}

func builtinV2RuleSolvers() map[string]string {
	return map[string]string{
		"taint": "dataflow.taint",
		"reach": "graph.reach",
		"grant": "graph.grant",
		"issue": "fact.exists",
		"fact":  "fact.exists",
		"query": "query.semantic",
	}
}

func builtinV2CoverageModes() map[string]bool {
	out := make(map[string]bool, len(v2CoverageModes))
	for mode := range v2CoverageModes {
		out[mode] = true
	}
	return out
}

func lowerV2ProgramToDeclarationsWithMechanics(prog *V2Program, mechanics v2Mechanics) ([]Decl, error) {
	if prog == nil {
		return nil, nil
	}
	out := make([]Decl, 0, len(prog.Decls))
	names := newV2NameResolver(prog)
	patterns := newV2PatternResolver(prog)
	matchers := newV2MatcherResolver(prog, mechanics.matchers)
	bindingsByTech := map[string]*BindingSet{}
	bindingSetFor := func(tech string) *BindingSet {
		set := bindingsByTech[tech]
		if set == nil {
			set = &BindingSet{Name: tech, Meta: map[string]any{}}
			bindingsByTech[tech] = set
			out = append(out, set)
		}
		return set
	}
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *V2ConceptDecl:
			out = append(out, &ConceptDecl{Name: x.Name, Package: x.Module, Kind: x.Kind, Fields: lowerV2FieldNames(x.Fields)})
		case *V2ThreatDecl:
			out = append(out, &ThreatDecl{Name: x.Name, Package: x.Module, Fields: lowerV2FieldNames(x.Fields)})
		case *V2PatternDecl:
			tech, meta, err := lowerV2AdapterMetaPattern(x)
			if err != nil {
				return nil, err
			}
			if tech != "" {
				set := bindingSetFor(tech)
				for k, v := range meta {
					set.Meta[k] = v
				}
			}
		case *V2ReviewDecl:
			out = append(out, &ReviewDecl{Concept: names.concept(x.Concept), Fields: lowerV2FieldNames(x.Fields)})
		case *V2ProfileDecl:
			out = append(out, &ProfileDecl{Name: x.Name, Fields: lowerV2FieldNames(x.Fields)})
		case *V2BindingDecl:
			tech := v2BindingTechnology(x.Module)
			if tech == "" {
				return nil, fmt.Errorf("binding %s: cannot infer technology from module %q", x.Name, x.Module)
			}
			set := bindingSetFor(tech)
			maps, err := lowerV2Binding(x, names, patterns, matchers, mechanics)
			if err != nil {
				return nil, err
			}
			set.Mappings = append(set.Mappings, maps...)
		case *V2RuleDecl:
			r, err := lowerV2Rule(x, names, mechanics)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		case *V2MechanicDecl:
			out = append(out, x)
		case *V2PolicyDecl:
			out = append(out, x)
		}
	}
	return out, nil
}

type v2NameResolver struct {
	concepts map[string]string
}

func newV2NameResolver(prog *V2Program) v2NameResolver {
	out := v2NameResolver{concepts: map[string]string{}}
	if prog == nil {
		return out
	}
	for _, d := range prog.Decls {
		c, ok := d.(*V2ConceptDecl)
		if !ok {
			continue
		}
		local, fq := v2DeclNames(prog.Module, c)
		for _, name := range []string{c.Name, local, fq} {
			if name != "" {
				out.concepts[name] = fq
			}
		}
	}
	for _, u := range prog.Uses {
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		if local != "" {
			out.concepts[local] = u.Name
		}
		out.concepts[u.Name] = u.Name
	}
	return out
}

func (r v2NameResolver) concept(name string) string {
	if resolved := r.concepts[name]; resolved != "" {
		return resolved
	}
	return name
}

type v2MatcherResolver struct {
	matchers map[string]v2MatcherSpec
	local    map[string]v2MatcherSpec
	imports  map[string]string
	module   string
}

func newV2MatcherResolver(prog *V2Program, matchers map[string]v2MatcherSpec) v2MatcherResolver {
	out := v2MatcherResolver{
		matchers: matchers,
		local:    map[string]v2MatcherSpec{},
		imports:  map[string]string{},
	}
	if prog == nil {
		return out
	}
	out.module = prog.Module
	for _, d := range prog.Decls {
		m, ok := d.(*V2MatcherDecl)
		if !ok {
			continue
		}
		spec := v2MatcherSpecFromDecl(m)
		local, fq := v2DeclNames(prog.Module, m)
		for _, name := range []string{m.Name, local, fq} {
			if name != "" {
				out.local[name] = spec
			}
		}
	}
	for _, u := range prog.Uses {
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		if local != "" {
			out.imports[local] = u.Name
		}
		out.imports[u.Name] = u.Name
	}
	return out
}

func (r v2MatcherResolver) resolve(name string) (v2MatcherSpec, bool) {
	if m, ok := r.local[name]; ok {
		return m, true
	}
	if imported := r.imports[name]; imported != "" {
		if m, ok := r.matchers[imported]; ok {
			return m, true
		}
	}
	if strings.Contains(name, ".") {
		if m, ok := r.matchers[name]; ok {
			return m, true
		}
	}
	if r.module != "" && !strings.Contains(name, ".") {
		if m, ok := r.local[r.module+"."+name]; ok {
			return m, true
		}
	}
	return v2MatcherSpec{}, false
}

type v2PatternResolver struct {
	patterns map[string]*V2PatternDecl
	imports  map[string]string
	module   string
}

func newV2PatternResolver(prog *V2Program) v2PatternResolver {
	out := v2PatternResolver{
		patterns: map[string]*V2PatternDecl{},
		imports:  map[string]string{},
	}
	if prog == nil {
		return out
	}
	out.module = prog.Module
	for _, d := range prog.Decls {
		p, ok := d.(*V2PatternDecl)
		if !ok {
			continue
		}
		local, fq := v2DeclNames(prog.Module, p)
		for _, name := range []string{p.Name, local, fq} {
			if name != "" {
				out.patterns[name] = p
			}
		}
	}
	for _, u := range prog.Uses {
		local := u.Alias
		if local == "" {
			local = lastSeg(u.Name)
		}
		if local != "" {
			out.imports[local] = u.Name
		}
		out.imports[u.Name] = u.Name
	}
	return out
}

func (r v2PatternResolver) resolve(name string) (*V2PatternDecl, bool, error) {
	if p := r.patterns[name]; p != nil {
		return p, true, nil
	}
	if imported := r.imports[name]; imported != "" {
		if p := r.patterns[imported]; p != nil {
			return p, true, nil
		}
		if lastSeg(imported) == "callExpr" {
			return builtinV2CallExprPattern(), true, nil
		}
		if lastSeg(imported) == "presenceNode" {
			return builtinV2PresenceNodePattern(), true, nil
		}
		return nil, false, fmt.Errorf("imported pattern %s requires native cross-file pattern lowering", imported)
	}
	if lastSeg(name) == "callExpr" {
		return builtinV2CallExprPattern(), true, nil
	}
	if lastSeg(name) == "presenceNode" {
		return builtinV2PresenceNodePattern(), true, nil
	}
	if r.module != "" && !strings.Contains(name, ".") {
		if p := r.patterns[r.module+"."+name]; p != nil {
			return p, true, nil
		}
	}
	return nil, false, nil
}

func builtinV2CallExprPattern() *V2PatternDecl {
	return &V2PatternDecl{
		Name:  "callExpr",
		Alias: "call",
		Items: []V2PatternItem{{Kind: "node", Name: "call"}},
	}
}

func builtinV2PresenceNodePattern() *V2PatternDecl {
	return &V2PatternDecl{
		Name:  "presenceNode",
		Alias: "node",
		Items: []V2PatternItem{{Kind: "node", Name: "node"}},
	}
}

func lowerV2FieldNames(fields map[string]any) map[string]any {
	return LowerV2FieldNames(fields)
}

func LowerV2FieldNames(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[lowerV2FieldName(k)] = v
	}
	return out
}

func lowerV2FieldName(name string) string {
	switch name {
	case "vulnerableTo":
		return "vulnerable_to"
	case "enabledBy":
		return "enabled_by"
	case "confidenceFloor":
		return "confidence_floor"
	case "sourcePolicy":
		return "source_policy"
	case "sourceConditionCategory":
		return "source_condition_category"
	case "sourceCondition":
		return "source_condition"
	case "sourceAssumption":
		return "source_assumption"
	case "sourceConfidence":
		return "source_confidence"
	case "contextReachSource":
		return "context_reach_source"
	case "contextReachLabel":
		return "context_reach_label"
	case "contextReachTargetProp":
		return "context_reach_target_prop"
	case "contextAssetTargetProp":
		return "context_asset_target_prop"
	case "contextAssetLabel":
		return "context_asset_label"
	case "contextConfirmDstProp":
		return "context_confirm_dst_prop"
	case "contextConfirmFlagProp":
		return "context_confirm_flag_prop"
	case "contextConfirmFlagValue":
		return "context_confirm_flag_value"
	case "contextConfirmLabel":
		return "context_confirm_label"
	case "excludedChars":
		return "excluded_chars"
	case "reviewCategory":
		return "review_category"
	case "reviewCondition":
		return "review_condition"
	case "reviewEvidence":
		return "review_evidence"
	case "reviewConfidence":
		return "review_confidence"
	default:
		return name
	}
}

func lowerV2AdapterMetaPattern(p *V2PatternDecl) (string, map[string]any, error) {
	for _, item := range p.Items {
		if item.Kind == "adapter" {
			name, _ := item.Meta["name"].(string)
			if name == "" {
				return "", nil, fmt.Errorf("pattern %s: adapter metadata requires name", p.Name)
			}
			rawMeta, ok := item.Meta["meta"].(map[string]any)
			if !ok {
				return "", nil, fmt.Errorf("pattern %s: adapter metadata requires meta block", p.Name)
			}
			return name, rawMeta, nil
		}
		if item.Kind == "unstable" {
			if _, hasAdapter := item.Meta["adapter"]; hasAdapter {
				return "", nil, fmt.Errorf("pattern %s: unstable adapter metadata must use stable adapter item", p.Name)
			}
			if _, hasMeta := item.Meta["meta"]; hasMeta {
				return "", nil, fmt.Errorf("pattern %s: unstable adapter metadata must use stable adapter item", p.Name)
			}
		}
	}
	return "", nil, nil
}

func v2BindingTechnology(module string) string {
	for rest := module; rest != ""; {
		part, tail, hasTail := strings.Cut(rest, ".")
		if part == "bindings" {
			if !hasTail {
				return ""
			}
			tech, _, _ := strings.Cut(tail, ".")
			return tech
		}
		if !hasTail {
			return ""
		}
		rest = tail
	}
	return ""
}

func lowerV2Binding(b *V2BindingDecl, names v2NameResolver, patterns v2PatternResolver, matchers v2MatcherResolver, mechanics v2Mechanics) ([]BindingAction, error) {
	if b.Query.Expr != nil && strings.HasPrefix(b.Query.Expr.Family, "unstable.") {
		return nil, fmt.Errorf("binding %s: unsupported unstable query family %q; migrate to stable v2", b.Name, b.Query.Expr.Family)
	}
	if b.Query.Expr != nil && b.Query.Expr.Family == "param" {
		return lowerV2ParamSourceBinding(b, names)
	}
	queryWhere := b.Query.Where
	queryAlias := ""
	queryNodeType := ""
	if b.Query.Expr != nil {
		if len(b.Query.Expr.Steps) != 0 {
			return nil, fmt.Errorf("binding %s: query relation steps need native production v2 lowering", b.Name)
		}
		switch b.Query.Expr.Family {
		case "call":
		case "memberAccess":
			queryNodeType = "code.Attr"
		case "binaryExpr":
			queryNodeType = "code.BinOp"
		default:
			return nil, fmt.Errorf("binding %s: inline query lowering is only implemented for single call, memberAccess, or binaryExpr queries", b.Name)
		}
		queryWhere = b.Query.Expr.Where
		queryAlias = b.Query.Expr.Alias
	} else if b.Query.Pattern == "" {
		return nil, fmt.Errorf("binding %s: missing query", b.Name)
	} else {
		var err error
		queryWhere, queryAlias, queryNodeType, err = lowerV2PatternQuery(b.Name, b.Query, patterns)
		if err != nil {
			return nil, err
		}
	}
	if queryAlias == "node" {
		if out, ok, err := lowerV2PresenceBinding(b, names, queryWhere, queryAlias, matchers, mechanics); ok || err != nil {
			return out, err
		}
	}
	shapes, err := lowerV2CallShapes(b.Name, queryWhere)
	if err != nil {
		return nil, err
	}
	for i := range shapes {
		shapes[i].NodeType = queryNodeType
	}
	pkgs, req, err := lowerV2Requirements(b.Requirements)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []BindingAction
	for _, shape := range shapes {
		for _, action := range b.Outputs {
			action.Concept = names.concept(action.Concept)
			action.About = names.concept(action.About)
			if err := validateV2OutputCoverageMechanics(b.Name, action, mechanics); err != nil {
				return nil, err
			}
			switch {
			case action.Kind == "emit source":
				m := shape.mapping(BindingAction{Kind: shape.sourceKind(), Pattern: shape.Pattern, Concept: action.Concept, Constraint: shape.Constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = append(out, m)
			case action.Kind == "emit sink":
				if action.Location == "call" || action.Location == "node" {
					m := shape.mapping(BindingAction{Kind: shape.markKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
					out = append(out, m)
					continue
				}
				kind := shape.sinkKind()
				loc, err := v2SinkLocationParts(action.Location)
				if err != nil {
					if action.Location == "callee.receiver" {
						kind = "sink_receiver"
						loc = v2SinkLocationInfo{ArgIndex: 0}
					} else {
						return nil, fmt.Errorf("binding %s: %w", b.Name, err)
					}
				}
				m := shape.mapping(BindingAction{
					Kind:            kind,
					Pattern:         shape.Pattern,
					Exact:           shape.Exact,
					Concept:         action.Concept,
					Constraint:      shape.Constraint,
					ArgIndex:        loc.ArgIndex,
					ValMatches:      shape.ValMatches,
					ValAbsents:      shape.ValAbsents,
					Collection:      loc.Collection,
					CollectionFirst: loc.CollectionFirst,
					CollectionIndex: loc.CollectionIndex,
					Packages:        pkgs,
					Requirement:     req,
				})
				out = append(out, m)
			case action.Kind == "emit check":
				if isV2AdvisoryNeutralizerCheck(action) {
					m, ok, err := lowerV2AdvisoryNeutralizerCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					if ok {
						out = append(out, m)
						continue
					}
				}
				if action.Advisory != nil && *action.Advisory {
					m, err := lowerV2AdvisoryCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					out = append(out, m)
					continue
				}
				if action.Concept == "threat.CharFilter" {
					if action.Location != "call" {
						return nil, fmt.Errorf("binding %s: CharFilter check must be emitted at call", b.Name)
					}
					if err := validateV2PathOnlyCheck(b.Name, action); err != nil {
						return nil, err
					}
					kind := "filter_path"
					if shape.Field == "callee.method" {
						kind = "filter_method"
					}
					constraint := ""
					if lowerV2CharFilterGlobal(queryWhere) {
						constraint = "global"
					}
					out = append(out, shape.mapping(BindingAction{Kind: kind, Pattern: shape.Pattern, Concept: action.Concept, Constraint: constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req}))
					continue
				}
				if isV2GlobalCheck(action) {
					m, err := lowerV2GlobalCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					out = append(out, m)
					continue
				}
				kind := shape.controlKind()
				if action.Location == "callee.receiver" {
					if shape.Field != "callee.method" {
						return nil, fmt.Errorf("binding %s: receiver check lowering requires callee.method predicate", b.Name)
					}
					if err := validateV2ConcreteCheck(b.Name, action); err != nil {
						return nil, err
					}
					if action.Covers[0].Mode != "sameReceiver" {
						return nil, fmt.Errorf("binding %s: receiver checks must declare sameReceiver coverage", b.Name)
					}
					kind = "control_receiver_method"
				} else {
					if err := validateV2ConcreteCheck(b.Name, action); err != nil {
						return nil, err
					}
				}
				m := shape.mapping(BindingAction{Kind: kind, Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, Coverage: action.Covers[0].Mode, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = append(out, m)
			case action.Kind == "emit issue":
				m := shape.mapping(BindingAction{Kind: shape.markKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = append(out, m)
			case action.Kind == "emit fact" && action.Location == "call.result" && action.About != "":
				m := shape.mapping(BindingAction{Kind: "type", Pattern: shape.Pattern, Concept: action.About, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = append(out, m)
			case strings.HasPrefix(action.Kind, "propagate "):
				m, err := lowerV2Propagation(b.Name, shape, queryAlias, action, pkgs, req)
				if err != nil {
					return nil, err
				}
				out = append(out, m)
			default:
				return nil, fmt.Errorf("binding %s: unsupported output %q", b.Name, action.Kind)
			}
		}
	}
	return out, nil
}

func isV2GlobalCheck(action V2BindingOutput) bool {
	return len(action.Covers) == 1 && action.Covers[0].Mode == "global"
}

func isV2AdvisoryNeutralizerCheck(action V2BindingOutput) bool {
	advisory := action.Advisory != nil && *action.Advisory
	if !advisory || action.About == "" || len(action.Covers) != 1 {
		return false
	}
	switch action.Covers[0].Mode {
	case "dominates", "path":
		return true
	default:
		return false
	}
}

func lowerV2GlobalCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string, req *BindingRequirement) (BindingAction, error) {
	if action.Location != "call" && action.Location != "node" {
		return BindingAction{}, fmt.Errorf("binding %s: global checks currently lower at call/node only", binding)
	}
	if action.About != "" {
		return BindingAction{}, fmt.Errorf("binding %s: global check about metadata is only supported on advisory checks", binding)
	}
	return shape.mapping(BindingAction{
		Kind:        shape.markKind(),
		Pattern:     shape.Pattern,
		Exact:       shape.Exact,
		Concept:     action.Concept,
		Coverage:    "global",
		ValMatches:  shape.ValMatches,
		ValAbsents:  shape.ValAbsents,
		Packages:    pkgs,
		Requirement: req,
	}), nil
}

func lowerV2AdvisoryCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string, req *BindingRequirement) (BindingAction, error) {
	if action.Location != "call" && action.Location != "node" {
		return BindingAction{}, fmt.Errorf("binding %s: advisory checks currently lower at call/node only", binding)
	}
	if len(action.Covers) != 1 {
		return BindingAction{}, fmt.Errorf("binding %s: advisory check requires exactly one coverage mode", binding)
	}
	kind := shape.markKind()
	return shape.mapping(BindingAction{
		Kind:        kind,
		Pattern:     shape.Pattern,
		Exact:       shape.Exact,
		Concept:     action.Concept,
		About:       action.About,
		Advisory:    true,
		Coverage:    action.Covers[0].Mode,
		ValMatches:  shape.ValMatches,
		ValAbsents:  shape.ValAbsents,
		Packages:    pkgs,
		Requirement: req,
	}), nil
}

func lowerV2PatternQuery(binding string, query V2BindingQuery, patterns v2PatternResolver) (V2Expr, string, string, error) {
	pat, ok, err := patterns.resolve(query.Pattern)
	if err != nil {
		return nil, "", "", fmt.Errorf("binding %s: pattern %s: %w", binding, query.Pattern, err)
	}
	if !ok {
		return nil, "", "", fmt.Errorf("binding %s: pattern %s is not declared in this module", binding, query.Pattern)
	}
	where, alias, nodeType, binds, err := lowerV2PatternRecognitionExpr(binding, pat, patterns)
	if err != nil {
		return nil, "", "", err
	}
	queryWhere := rewriteV2PatternRefs(query.Where, binds)
	return andV2Expr(where, queryWhere), alias, nodeType, nil
}

func lowerV2PatternRecognitionExpr(binding string, pat *V2PatternDecl, patterns v2PatternResolver) (V2Expr, string, string, map[string]string, error) {
	where, alias, nodeType, binds, _, err := lowerV2PatternRecognitionExprSeen(binding, pat, patterns, map[*V2PatternDecl]bool{})
	return where, alias, nodeType, binds, err
}

func lowerV2PatternRecognitionExprSeen(binding string, pat *V2PatternDecl, patterns v2PatternResolver, seen map[*V2PatternDecl]bool) (V2Expr, string, string, map[string]string, int, error) {
	if pat == nil {
		return nil, "", "", nil, 0, fmt.Errorf("binding %s: nil pattern", binding)
	}
	if seen[pat] {
		return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s has cyclic use", binding, pat.Name)
	}
	seen[pat] = true
	defer delete(seen, pat)

	alias := pat.Alias
	nodeType := ""
	binds := map[string]string{}
	var where V2Expr
	nodeCount := 0
	for _, item := range pat.Items {
		switch item.Kind {
		case "node":
			nodeCount++
			switch item.Name {
			case "call", "callExpr", "node":
			case "memberAccess":
				nodeType = "code.Attr"
			case "binaryExpr":
				nodeType = "code.BinOp"
			default:
				return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s node family %q needs native pattern lowering", binding, pat.Name, item.Name)
			}
			if alias == "" {
				alias = item.Alias
			}
		case "bind":
			ref, ok := item.Expr.(V2RefExpr)
			if !ok {
				return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s bind %s needs native expression lowering", binding, pat.Name, item.Name)
			}
			if err := addV2PatternBind(binding, pat.Name, binds, item.Name, ref.Name); err != nil {
				return nil, "", "", nil, 0, err
			}
		case "where":
			where = andV2Expr(where, rewriteV2PatternRefs(item.Expr, binds))
		case "unstable":
			return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s unstable items need native pattern lowering", binding, pat.Name)
		case "use":
			sub, ok, err := patterns.resolve(item.Name)
			if err != nil {
				return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s use %s: %w", binding, pat.Name, item.Name, err)
			}
			if !ok {
				return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s use %s is not declared in this module", binding, pat.Name, item.Name)
			}
			subWhere, subAlias, subNodeType, subBinds, subNodes, err := lowerV2PatternRecognitionExprSeen(binding, sub, patterns, seen)
			if err != nil {
				return nil, "", "", nil, 0, err
			}
			if alias == "" {
				alias = item.Alias
			}
			targetAlias := alias
			aliasBinds := map[string]string{}
			if subAlias != "" && targetAlias != "" {
				aliasBinds[subAlias] = targetAlias
			}
			if item.Alias != "" && targetAlias != "" {
				aliasBinds[item.Alias] = targetAlias
			}
			where = andV2Expr(where, rewriteV2PatternRefs(subWhere, aliasBinds))
			nodeCount += subNodes
			if nodeType != "" && subNodeType != "" && nodeType != subNodeType {
				return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s composes incompatible node families", binding, pat.Name)
			}
			if nodeType == "" {
				nodeType = subNodeType
			}
			for name, target := range subBinds {
				if rewritten, ok := rewriteV2PatternRefName(target, aliasBinds); ok {
					target = rewritten
				}
				if err := addV2PatternBind(binding, pat.Name, binds, name, target); err != nil {
					return nil, "", "", nil, 0, err
				}
			}
			if item.Alias != "" && targetAlias != "" {
				if err := addV2PatternBind(binding, pat.Name, binds, item.Alias, targetAlias); err != nil {
					return nil, "", "", nil, 0, err
				}
			}
		default:
			return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s item %q needs native pattern lowering", binding, pat.Name, item.Kind)
		}
	}
	if nodeCount != 1 {
		return nil, "", "", nil, 0, fmt.Errorf("binding %s: pattern %s must have exactly one call/memberAccess node for scanner IR lowering", binding, pat.Name)
	}
	return where, alias, nodeType, binds, nodeCount, nil
}

func addV2PatternBind(binding, pattern string, binds map[string]string, name, target string) error {
	if prev := binds[name]; prev != "" && prev != target {
		return fmt.Errorf("binding %s: pattern %s bind %s is ambiguous", binding, pattern, name)
	}
	binds[name] = target
	return nil
}

func lowerV2PresenceBinding(b *V2BindingDecl, names v2NameResolver, expr V2Expr, alias string, matchers v2MatcherResolver, mechanics v2Mechanics) ([]BindingAction, bool, error) {
	fl, ok, err := lowerV2PresenceFlagExpr(alias, expr, matchers)
	if err != nil || !ok {
		return nil, ok, err
	}
	pkgs, req, err := lowerV2Requirements(b.Requirements)
	if err != nil {
		return nil, true, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []BindingAction
	for _, action := range b.Outputs {
		action.Concept = names.concept(action.Concept)
		action.About = names.concept(action.About)
		if action.Kind != "emit issue" && action.Kind != "emit sink" && action.Kind != "emit source" && action.Kind != "emit check" {
			return nil, true, fmt.Errorf("binding %s: presenceNode only supports emit issue/source/sink/check", b.Name)
		}
		if action.Location != alias {
			return nil, true, fmt.Errorf("binding %s: presenceNode emit location must be %q", b.Name, alias)
		}
		coverage := ""
		if len(action.Covers) > 1 {
			return nil, true, fmt.Errorf("binding %s: presenceNode supports at most one coverage mode", b.Name)
		}
		if len(action.Covers) == 1 {
			if err := validateV2OutputCoverageMechanics(b.Name, action, mechanics); err != nil {
				return nil, true, err
			}
			coverage = action.Covers[0].Mode
		}
		flag := *fl
		out = append(out, BindingAction{
			Kind:        "flag",
			Concept:     action.Concept,
			About:       action.About,
			Advisory:    action.Advisory != nil && *action.Advisory,
			Coverage:    coverage,
			Packages:    pkgs,
			Requirement: req,
			Flag:        &flag,
		})
	}
	return out, true, nil
}

func lowerV2PresenceFlagExpr(alias string, expr V2Expr, matchers v2MatcherResolver) (*BindingPresence, bool, error) {
	if alias == "" {
		return nil, true, fmt.Errorf("query alias is required")
	}
	fl := &BindingPresence{NodeKind: "any"}
	handled := false
	for _, atom := range flattenV2And(expr) {
		neg := false
		if u, ok := atom.(V2UnaryExpr); ok && u.Op == "not" {
			neg = true
			atom = u.X
		}
		if handledOperand, err := lowerV2PresenceOperand(fl, alias, atom, neg, matchers); handledOperand || err != nil {
			if err != nil {
				return nil, true, err
			}
			handled = true
			continue
		}
		if handledMeta, err := lowerV2PresenceMeta(fl, alias, atom, neg); handledMeta || err != nil {
			if err != nil {
				return nil, true, err
			}
			handled = true
			continue
		}
		pred, err := lowerV2PresencePredicate(alias, "node", atom, neg, matchers)
		if err != nil {
			return nil, true, err
		}
		handled = true
		fl.Predicates = append(fl.Predicates, pred)
	}
	if !handled {
		return nil, false, nil
	}
	return fl, true, nil
}

func andV2Expr(left, right V2Expr) V2Expr {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return V2BinaryExpr{Op: "and", Left: left, Right: right}
}

func rewriteV2PatternRefs(expr V2Expr, binds map[string]string) V2Expr {
	if expr == nil || len(binds) == 0 {
		return expr
	}
	switch x := expr.(type) {
	case V2RefExpr:
		if name, ok := rewriteV2PatternRefName(x.Name, binds); ok {
			return V2RefExpr{Name: name}
		}
		return x
	case V2UnaryExpr:
		x.X = rewriteV2PatternRefs(x.X, binds)
		return x
	case V2BinaryExpr:
		x.Left = rewriteV2PatternRefs(x.Left, binds)
		x.Right = rewriteV2PatternRefs(x.Right, binds)
		return x
	case V2CallExpr:
		for i := range x.Args {
			x.Args[i] = rewriteV2PatternRefs(x.Args[i], binds)
		}
		for i := range x.NamedArgs {
			x.NamedArgs[i].Expr = rewriteV2PatternRefs(x.NamedArgs[i].Expr, binds)
		}
		return x
	case V2SequenceExpr:
		for i := range x.Items {
			x.Items[i] = rewriteV2PatternRefs(x.Items[i], binds)
		}
		return x
	default:
		return x
	}
}

func rewriteV2PatternRefName(name string, binds map[string]string) (string, bool) {
	head, rest, hasRest := strings.Cut(name, ".")
	target := binds[head]
	if target == "" {
		return "", false
	}
	if hasRest {
		return target + "." + rest, true
	}
	return target, true
}

func lowerV2ParamSourceBinding(b *V2BindingDecl, names v2NameResolver) ([]BindingAction, error) {
	if b.Query.Expr.Alias != "param" || b.Query.Expr.Where != nil || len(b.Query.Expr.Steps) != 0 {
		return nil, fmt.Errorf("binding %s: param source lowering requires query param as param", b.Name)
	}
	pkgs, req, err := lowerV2Requirements(b.Requirements)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []BindingAction
	for _, action := range b.Outputs {
		action.Concept = names.concept(action.Concept)
		if action.Kind != "emit source" || action.Location != "param" {
			return nil, fmt.Errorf("binding %s: param query only supports emit source at param", b.Name)
		}
		out = append(out, BindingAction{Kind: "source_param", Concept: action.Concept, Packages: pkgs, Requirement: req})
	}
	return out, nil
}

func lowerV2PresenceOperand(fl *BindingPresence, alias string, expr V2Expr, neg bool, matchers v2MatcherResolver) (bool, error) {
	if neg {
		return false, nil
	}
	call, ok := expr.(V2CallExpr)
	if !ok || call.Name != "operand" {
		return false, nil
	}
	if len(call.Args) != 1 {
		return true, fmt.Errorf("operand requires the flag alias as its positional arg")
	}
	ref, ok := call.Args[0].(V2RefExpr)
	if !ok || ref.Name != alias {
		return true, fmt.Errorf("operand first arg must be %s", alias)
	}
	var where V2Expr
	for _, arg := range call.NamedArgs {
		if arg.Name != "where" {
			return true, fmt.Errorf("unsupported operand arg %q", arg.Name)
		}
		where = arg.Expr
	}
	if where == nil {
		return true, fmt.Errorf("operand requires where")
	}
	var operand BindingPresenceOperand
	for _, atom := range flattenV2And(where) {
		opNeg := false
		if u, ok := atom.(V2UnaryExpr); ok && u.Op == "not" {
			opNeg = true
			atom = u.X
		}
		pred, err := lowerV2PresencePredicate("operand", "operand", atom, opNeg, matchers)
		if err != nil {
			return true, err
		}
		operand.Predicates = append(operand.Predicates, pred)
	}
	fl.Operands = append(fl.Operands, operand)
	return true, nil
}

func flattenV2And(expr V2Expr) []V2Expr {
	var out []V2Expr
	flattenV2AndInto(expr, &out)
	return out
}

func flattenV2AndInto(expr V2Expr, out *[]V2Expr) {
	if b, ok := expr.(V2BinaryExpr); ok && b.Op == "and" {
		flattenV2AndInto(b.Left, out)
		flattenV2AndInto(b.Right, out)
		return
	}
	*out = append(*out, expr)
}

func lowerV2PresenceMeta(fl *BindingPresence, alias string, expr V2Expr, neg bool) (bool, error) {
	if neg {
		return false, nil
	}
	b, ok := expr.(V2BinaryExpr)
	if !ok || b.Op != "==" {
		return false, nil
	}
	field, ok := v2PresenceField(alias, b.Left)
	if !ok || (field != "kind" && field != "scope") {
		return false, nil
	}
	value, ok := v2LiteralString(b.Right)
	if !ok {
		return true, fmt.Errorf("%s must compare to a string", field)
	}
	if field == "scope" {
		fl.Scope = value
	} else {
		fl.NodeKind = value
	}
	return true, nil
}

func lowerV2PresencePredicate(alias, defaultSubject string, expr V2Expr, neg bool, matchers v2MatcherResolver) (BindingPresencePredicate, error) {
	switch x := expr.(type) {
	case V2BinaryExpr:
		return lowerV2PresenceBinary(alias, defaultSubject, x, neg, matchers)
	case V2CallExpr:
		return lowerV2PresenceCall(alias, defaultSubject, x, neg)
	default:
		return BindingPresencePredicate{}, fmt.Errorf("unsupported predicate expression %T", expr)
	}
}

func lowerV2PresenceBinary(alias, defaultSubject string, x V2BinaryExpr, neg bool, matchers v2MatcherResolver) (BindingPresencePredicate, error) {
	field, ok := v2PresenceField(alias, x.Left)
	if !ok {
		return BindingPresencePredicate{}, fmt.Errorf("predicate left side must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return BindingPresencePredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	switch x.Op {
	case "~=", "==", "contains":
		value, ok := v2LiteralString(x.Right)
		if !ok {
			return BindingPresencePredicate{}, fmt.Errorf("%s predicate right side must be a string", field)
		}
		value = prefixV2PresenceValue(field, value)
		pred := BindingPresencePredicate{Subject: subject, Property: prop, Values: []string{value}, Negative: neg}
		switch {
		case prop == "path":
			pred.Op = "match"
			pred.Exact = x.Op == "=="
		case x.Op == "contains":
			pred.Op = "contains"
		case x.Op == "==":
			pred.Op = "equals"
		default:
			return BindingPresencePredicate{}, fmt.Errorf("unsupported operator %q for %s", x.Op, field)
		}
		return pred, nil
	case "in":
		values, ok := v2RuleWhereStringList(x.Right)
		if !ok {
			return BindingPresencePredicate{}, fmt.Errorf("%s in predicate requires a string list", field)
		}
		values = prefixV2PresenceValues(field, values)
		return BindingPresencePredicate{Subject: subject, Property: prop, Op: "equals_any", Values: values, Negative: neg}, nil
	case "is":
		matcherName, ok := v2MatcherRef(x.Right)
		if !ok {
			return BindingPresencePredicate{}, fmt.Errorf("%s is predicate requires a matcher name", field)
		}
		matcher, ok := matchers.resolve(matcherName)
		if !ok {
			return BindingPresencePredicate{}, fmt.Errorf("unknown matcher %q", matcherName)
		}
		if matcher.Unsupported != "" {
			return BindingPresencePredicate{}, fmt.Errorf("matcher %s: %s requires native matcher lowering", matcherName, matcher.Unsupported)
		}
		if matcher.Op == "matches" {
			return BindingPresencePredicate{}, fmt.Errorf("matcher %s: regex matcher invocation requires reviewed scanner support", matcherName)
		}
		if matcher.Op == "" || len(matcher.Values) == 0 {
			return BindingPresencePredicate{}, fmt.Errorf("matcher %s: empty matcher", matcherName)
		}
		return BindingPresencePredicate{Subject: subject, Property: prop, Op: matcher.Op, Values: prefixV2PresenceValues(field, matcher.Values), Negative: neg}, nil
	default:
		return BindingPresencePredicate{}, fmt.Errorf("unsupported operator %q", x.Op)
	}
}

func v2MatcherRef(expr V2Expr) (string, bool) {
	ref, ok := expr.(V2RefExpr)
	if !ok || ref.Name == "" {
		return "", false
	}
	return ref.Name, true
}

func lowerV2PresenceCall(alias, defaultSubject string, x V2CallExpr, neg bool) (BindingPresencePredicate, error) {
	if x.Name != "containsAny" {
		return BindingPresencePredicate{}, fmt.Errorf("unsupported call %q", x.Name)
	}
	if len(x.Args) != 2 || len(x.NamedArgs) != 0 {
		return BindingPresencePredicate{}, fmt.Errorf("containsAny requires two positional args")
	}
	field, ok := v2PresenceField(alias, x.Args[0])
	if !ok {
		return BindingPresencePredicate{}, fmt.Errorf("containsAny first arg must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return BindingPresencePredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	values, ok := v2RuleWhereStringList(x.Args[1])
	if !ok {
		return BindingPresencePredicate{}, fmt.Errorf("containsAny second arg must be a string list")
	}
	values = prefixV2PresenceValues(field, values)
	return BindingPresencePredicate{Subject: subject, Property: prop, Op: "contains_any", Values: values, Negative: neg}, nil
}

func v2PresenceField(alias string, expr V2Expr) (string, bool) {
	ref, ok := expr.(V2RefExpr)
	if !ok {
		return "", false
	}
	prefix := alias + "."
	if !strings.HasPrefix(ref.Name, prefix) {
		return "", false
	}
	return strings.TrimPrefix(ref.Name, prefix), true
}

func v2PresenceProperty(defaultSubject, field string) (string, string, bool) {
	if rest, ok := strings.CutPrefix(field, "scopeCall."); ok {
		return "scope_call", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "scope_call."); ok {
		return "scope_call", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "flowTo."); ok {
		return "flow_to", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "flow_to."); ok {
		return "flow_to", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "prop."); ok {
		return defaultSubject, rest, true
	}
	if field == "context.scopeCall" || field == "context.inScopeCall" {
		return "scope_call", "any", true
	}
	if field == "analysis" {
		return defaultSubject, "path", true
	}
	if _, ok := strings.CutPrefix(field, "context."); ok {
		if v2PresenceValuePrefix(field) != "" {
			return defaultSubject, "tokens", true
		}
	}
	switch field {
	case "path":
		return defaultSubject, "path", true
	case "method":
		return defaultSubject, "method", true
	case "token":
		return defaultSubject, "tokens", true
	case "op", "identifier", "key", "any":
		return defaultSubject, field, true
	default:
		return "", "", false
	}
}

func prefixV2PresenceValue(field, value string) string {
	prefix := v2PresenceValuePrefix(field)
	if prefix == "" || strings.HasPrefix(value, prefix) {
		return value
	}
	return prefix + value
}

func prefixV2PresenceValues(field string, values []string) []string {
	prefix := v2PresenceValuePrefix(field)
	if prefix == "" {
		return values
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value
		if !strings.HasPrefix(value, prefix) {
			out[i] = prefix + value
		}
	}
	return out
}

func v2PresenceValuePrefix(field string) string {
	if field == "analysis" {
		return "analysis."
	}
	if !strings.HasPrefix(field, "context.") {
		return ""
	}
	field = strings.TrimPrefix(field, "context.")
	switch field {
	case "language":
		return "lang="
	case "name":
		return "name="
	case "callPath":
		return "call_path:"
	case "call":
		return "call:"
	case "callArg":
		return "call_arg:"
	case "callMethod":
		return "call_method:"
	case "callOrder":
		return "call_order:"
	case "entryKind":
		return "entry_kind:"
	case "functionParamType":
		return "function_param_type:"
	case "functionName":
		return "function_name:"
	case "functionVisibility":
		return "function_visibility:"
	case "category":
		return "category:"
	case "vulnerable":
		return "vulnerable:"
	case "className":
		return "class_name:"
	case "classBase":
		return "class_base:"
	case "classAttribute":
		return "class_attribute:"
	case "classAnnotation":
		return "class_annotation:"
	case "methodAttribute":
		return "method_attribute:"
	case "attrName":
		return "attr_name:"
	case "selector":
		return "selector:"
	case "literal":
		return "literal:"
	case "identifier":
		return "identifier:"
	case "expr":
		return "expr:"
	case "annotation":
		return "annotation:"
	case "attrPath":
		return "attr_path:"
	case "paramName":
		return "param_name:"
	case "paramType":
		return "param_type:"
	case "binary":
		return "binary:"
	case "assign":
		return "assign:"
	case "subscript":
		return "subscript:"
	case "field":
		return "field:"
	case "macroName":
		return "macro_name:"
	case "macroBody":
		return "macro_body:"
	case "catchType":
		return "catch_type:"
	case "prop":
		return "prop:"
	case "index":
		return "index:"
	case "indexKey":
		return "index_key:"
	case "return":
		return "return:"
	case "returnCallPath":
		return "return_call_path:"
	case "returnIdentifier":
		return "return_identifier:"
	case "advisoryCwe":
		return "advisory_cwe="
	case "annotationArg":
		return "annotation_arg:"
	case "assignCall":
		return "assign_call:"
	case "assignCallMethod":
		return "assign_call_method:"
	case "assignItem":
		return "assign_item:"
	case "assignLiteral":
		return "assign_literal:"
	case "callBefore":
		return "call_before:"
	case "castCallLiteral":
		return "cast_call_literal:"
	case "classModifier":
		return "class_modifier:"
	case "decoratorMethod":
		return "decorator_method:"
	case "decoratorPath":
		return "decorator_path:"
	case "fieldType":
		return "field_type:"
	case "functionModifier":
		return "function_modifier:"
	case "matchArm":
		return "match_arm:"
	case "paramIndex":
		return "param_index:"
	case "paramLabel":
		return "param_label:"
	case "repr":
		return "repr:"
	case "serdeAttr":
		return "serde_attr:"
	case "noNetwork":
		return "no_network:"
	case "resolveEntities":
		return "resolve_entities:"
	case "value":
		return "value:"
	case "switchCase":
		return "switch_case:"
	case "varName":
		return "var_name:"
	default:
		return ""
	}
}

func v2LiteralString(expr V2Expr) (string, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return "", false
	}
	s, ok := lit.Value.(string)
	return s, ok
}

func v2LiteralInt(expr V2Expr) (int, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return 0, false
	}
	n, ok := lit.Value.(int)
	return n, ok && n >= 0
}

func v2LiteralIntList(expr V2Expr) ([]int, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return nil, false
	}
	raw, ok := lit.Value.([]string)
	if !ok {
		return nil, false
	}
	out := make([]int, 0, len(raw))
	for _, item := range raw {
		n, err := strconv.Atoi(item)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func validateV2ConcreteCheck(binding string, action V2BindingOutput) error {
	if action.Advisory != nil && *action.Advisory {
		return fmt.Errorf("binding %s: advisory checks must lower through advisory coverage support", binding)
	}
	if action.About != "" {
		return fmt.Errorf("binding %s: concrete suppressing checks cannot declare about metadata", binding)
	}
	if len(action.Covers) != 1 {
		return fmt.Errorf("binding %s: concrete checks require exactly one coverage mode", binding)
	}
	switch action.Covers[0].Mode {
	case "path", "endpoint", "sameReceiver", "sameScope", "dominates", "postDominates":
		return nil
	case "global":
		return fmt.Errorf("binding %s: global checks must lower through global coverage support", binding)
	default:
		return fmt.Errorf("binding %s: coverage mode %q lowering is not implemented yet", binding, action.Covers[0].Mode)
	}
}

func validateV2OutputCoverageMechanics(binding string, action V2BindingOutput, mechanics v2Mechanics) error {
	for _, cov := range action.Covers {
		if cov.Mode == "" {
			continue
		}
		if !mechanics.coverageModes[cov.Mode] {
			return fmt.Errorf("binding %s: no loaded mechanic coverage %q", binding, cov.Mode)
		}
	}
	return nil
}

func validateV2PathOnlyCheck(binding string, action V2BindingOutput) error {
	if err := validateV2ConcreteCheck(binding, action); err != nil {
		return err
	}
	if action.Covers[0].Mode != "path" {
		return fmt.Errorf("binding %s: this check only supports path coverage", binding)
	}
	return nil
}

func lowerV2AdvisoryNeutralizerCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string, req *BindingRequirement) (BindingAction, bool, error) {
	advisory := action.Advisory != nil && *action.Advisory
	if !advisory || action.About == "" {
		return BindingAction{}, false, nil
	}
	if action.Location != "call" {
		return BindingAction{}, true, fmt.Errorf("binding %s: advisory neutralizer check must be emitted at call", binding)
	}
	if len(action.Covers) != 1 {
		return BindingAction{}, true, fmt.Errorf("binding %s: advisory neutralizer check requires exactly one coverage mode", binding)
	}
	mode := ""
	switch action.Covers[0].Mode {
	case "dominates":
		mode = "guard"
	case "path":
		mode = "sanitizer"
	default:
		return BindingAction{}, true, fmt.Errorf("binding %s: unsupported advisory neutralizer coverage mode %q", binding, action.Covers[0].Mode)
	}
	kind := "advisory_" + mode + "_path"
	if shape.Field == "callee.method" {
		kind = "advisory_" + mode + "_method"
	}
	return shape.mapping(BindingAction{
		Kind:        kind,
		Pattern:     shape.Pattern,
		About:       action.About,
		ValMatches:  shape.ValMatches,
		ValAbsents:  shape.ValAbsents,
		Packages:    pkgs,
		Requirement: req,
	}), true, nil
}

func lowerV2CharFilterGlobal(expr V2Expr) bool {
	for _, atom := range flattenV2And(expr) {
		cmp, ok := atom.(V2BinaryExpr)
		if !ok || cmp.Op != "==" {
			continue
		}
		left, ok := cmp.Left.(V2RefExpr)
		if !ok || left.Name != "call.filter.global" {
			continue
		}
		lit, ok := cmp.Right.(V2LiteralExpr)
		if !ok {
			continue
		}
		v, ok := lit.Value.(bool)
		return ok && v
	}
	return false
}

type v2CallShape struct {
	NodeType    string
	Field       string
	Pattern     string
	Exact       bool
	Constraint  string
	ArgCountSet bool
	ArgCountMin int
	ArgCountMax int
	ValMatches  []string
	ValAbsents  []string
}

const maxV2CallShapeExpansion = 256

func checkV2CallShapeExpansion(binding, op string, n int) error {
	if n <= maxV2CallShapeExpansion {
		return nil
	}
	return fmt.Errorf("binding %s: query predicate expansion for %s produced %d call shapes, limit %d", binding, op, n, maxV2CallShapeExpansion)
}

func (s v2CallShape) mapping(m BindingAction) BindingAction {
	m.NodeType = s.NodeType
	if s.ArgCountSet {
		m.ArgCountSet = true
		m.ArgCountMin = s.ArgCountMin
		m.ArgCountMax = s.ArgCountMax
	}
	return m
}

func (s v2CallShape) sourceKind() string {
	if s.Constraint != "" && s.Field == "callee.method" {
		return "source_receiver"
	}
	if s.Field == "callee.method" {
		return "source_method"
	}
	return "source"
}

func (s v2CallShape) sinkKind() string {
	if s.Field == "callee.method" {
		return "sink_method"
	}
	return "sink_path"
}

func (s v2CallShape) controlKind() string {
	if s.Field == "callee.method" {
		return "control_method"
	}
	return "control"
}

func (s v2CallShape) markKind() string {
	if s.Field == "callee.method" {
		return "mark_method"
	}
	return "mark"
}

func lowerV2CallShapes(binding string, expr V2Expr) ([]v2CallShape, error) {
	shapes, err := lowerV2CallShapeExpr(binding, expr, false)
	if err != nil {
		return nil, err
	}
	for _, shape := range shapes {
		if shape.Field == "" {
			return nil, fmt.Errorf("binding %s: query pattern lowering needs a callee.method/path predicate", binding)
		}
	}
	return dedupeV2CallShapes(shapes), nil
}

func lowerV2CallShapeExpr(binding string, expr V2Expr, neg bool) ([]v2CallShape, error) {
	if u, ok := expr.(V2UnaryExpr); ok && u.Op == "not" {
		return lowerV2CallShapeExpr(binding, u.X, !neg)
	}
	cmp, ok := expr.(V2BinaryExpr)
	if !ok {
		return nil, fmt.Errorf("binding %s: unsupported query predicate %T", binding, expr)
	}
	switch cmp.Op {
	case "and":
		if neg {
			return lowerV2CallShapeOr(binding, cmp.Left, cmp.Right, true)
		}
		return lowerV2CallShapeAnd(binding, cmp.Left, cmp.Right, false)
	case "or":
		if neg {
			return lowerV2CallShapeAnd(binding, cmp.Left, cmp.Right, true)
		}
		return lowerV2CallShapeOr(binding, cmp.Left, cmp.Right, false)
	default:
		return lowerV2CallShapeAtom(binding, cmp, neg)
	}
}

func lowerV2CallShapeAnd(binding string, left, right V2Expr, neg bool) ([]v2CallShape, error) {
	leftShapes, err := lowerV2CallShapeExpr(binding, left, neg)
	if err != nil {
		return nil, err
	}
	rightShapes, err := lowerV2CallShapeExpr(binding, right, neg)
	if err != nil {
		return nil, err
	}
	if err := checkV2CallShapeExpansion(binding, "and", len(leftShapes)*len(rightShapes)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(leftShapes)*len(rightShapes))
	for _, l := range leftShapes {
		for _, r := range rightShapes {
			merged, err := mergeV2CallShapes(binding, l, r)
			if err != nil {
				return nil, err
			}
			out = append(out, merged)
		}
	}
	return out, nil
}

func lowerV2CallShapeOr(binding string, left, right V2Expr, neg bool) ([]v2CallShape, error) {
	leftShapes, err := lowerV2CallShapeExpr(binding, left, neg)
	if err != nil {
		return nil, err
	}
	rightShapes, err := lowerV2CallShapeExpr(binding, right, neg)
	if err != nil {
		return nil, err
	}
	if err := checkV2CallShapeExpansion(binding, "or", len(leftShapes)+len(rightShapes)); err != nil {
		return nil, err
	}
	return append(leftShapes, rightShapes...), nil
}

func lowerV2CallShapeAtom(binding string, cmp V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	leftExpr := cmp.Left
	cmpNeg := neg
	if u, ok := leftExpr.(V2UnaryExpr); ok && u.Op == "not" {
		leftExpr = u.X
		cmpNeg = !cmpNeg
	}
	left, ok := leftExpr.(V2RefExpr)
	if !ok {
		return nil, fmt.Errorf("binding %s: unsupported query predicate left side %T", binding, cmp.Left)
	}
	field := v2CallQueryField(left.Name)
	if _, prefix, ok := v2ArgsAnyContextField(field); ok {
		if cmp.Op != "contains" {
			return nil, fmt.Errorf("binding %s: %s operator %q is not implemented in scanner IR lowering", binding, field, cmp.Op)
		}
		value, ok := v2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: %s predicate right side must be a string", binding, field)
		}
		if !strings.HasPrefix(value, prefix) {
			value = prefix + value
		}
		if cmpNeg {
			return []v2CallShape{{ValAbsents: []string{value}}}, nil
		}
		return []v2CallShape{{ValMatches: []string{value}}}, nil
	}
	switch field {
	case "operator":
		return lowerV2OperatorShapes(binding, cmp, cmpNeg)
	case "callee.method", "call.callee.method", "callee.path", "call.callee.path",
		"callee.analysis", "call.callee.analysis":
		return lowerV2CalleeShapes(binding, strings.TrimPrefix(field, "call."), cmp, cmpNeg)
	case "callee.receiver.type", "call.callee.receiver.type":
		if cmpNeg {
			return nil, fmt.Errorf("binding %s: negated receiver type predicate is not implemented in scanner IR lowering", binding)
		}
		constraint, ok := lowerV2ReceiverConstraint(cmp)
		if !ok {
			return nil, fmt.Errorf("binding %s: receiver type predicate must compare to string or string list", binding)
		}
		return []v2CallShape{{Constraint: constraint}}, nil
	case "args.any.literal", "call.args.any.literal":
		if cmp.Op != "contains" {
			return nil, fmt.Errorf("binding %s: args.any.literal operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
		}
		value, ok := v2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: args.any.literal predicate right side must be a string", binding)
		}
		if cmpNeg {
			return []v2CallShape{{ValAbsents: []string{value}}}, nil
		}
		return []v2CallShape{{ValMatches: []string{value}}}, nil
	case "args.count", "call.args.count":
		shapes, ok := lowerV2ArgsCountShapes(cmp, cmpNeg)
		if !ok {
			return nil, fmt.Errorf("binding %s: args.count predicate must compare to a non-negative integer or integer list", binding)
		}
		if err := checkV2CallShapeExpansion(binding, field, len(shapes)); err != nil {
			return nil, err
		}
		return shapes, nil
	case "call.filter.global", "filter.global":
		if cmpNeg || cmp.Op != "==" {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate must be == true", binding)
		}
		lit, ok := cmp.Right.(V2LiteralExpr)
		if !ok {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
		}
		v, ok := lit.Value.(bool)
		if !ok {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
		}
		if !v {
			return nil, fmt.Errorf("binding %s: call.filter.global == false is not implemented in scanner IR lowering", binding)
		}
		return []v2CallShape{{}}, nil
	default:
		return nil, fmt.Errorf("binding %s: query predicate %q is not implemented in scanner IR lowering", binding, left.Name)
	}
}

func v2ArgsAnyContextField(field string) (string, string, bool) {
	for _, prefix := range []string{"args.any.context.", "call.args.any.context."} {
		if rest, ok := strings.CutPrefix(field, prefix); ok {
			if valuePrefix := v2ArgsAnyContextValuePrefix(rest); valuePrefix != "" {
				return rest, valuePrefix, true
			}
		}
	}
	return "", "", false
}

func v2ArgsAnyContextValuePrefix(field string) string {
	switch field {
	case "firstParam":
		return "first_param:"
	case "hasParamType":
		return "has_param_type:"
	case "noNetwork":
		return "no_network="
	case "resolveEntities":
		return "resolve_entities="
	case "value":
		return "value="
	default:
		return v2PresenceValuePrefix("context." + field)
	}
}

func lowerV2CalleeShapes(binding, field string, cmp V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	if neg {
		return nil, fmt.Errorf("binding %s: negated callee predicate is not implemented in scanner IR lowering", binding)
	}
	var values []string
	shapeField := field
	valuePrefix := ""
	if field == "callee.analysis" {
		shapeField = "callee.path"
		valuePrefix = "analysis."
	}
	exact := shapeField == "callee.path" && (cmp.Op == "==" || cmp.Op == "in")
	switch cmp.Op {
	case "==", "~=":
		pat, ok := v2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: query predicate right side must be a string", binding)
		}
		values = []string{pat}
	case "in":
		var ok bool
		values, ok = v2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: callee %s in predicate requires a non-empty string list", binding, field)
		}
	default:
		return nil, fmt.Errorf("binding %s: callee predicate operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, field, len(values)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		if valuePrefix != "" && !strings.HasPrefix(value, valuePrefix) {
			value = valuePrefix + value
		}
		out = append(out, v2CallShape{Field: shapeField, Pattern: value, Exact: exact})
	}
	return out, nil
}

func lowerV2OperatorShapes(binding string, cmp V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	if neg {
		return nil, fmt.Errorf("binding %s: negated operator predicate is not implemented in scanner IR lowering", binding)
	}
	var values []string
	switch cmp.Op {
	case "==":
		pat, ok := v2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: operator predicate right side must be a string", binding)
		}
		values = []string{pat}
	case "in":
		var ok bool
		values, ok = v2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: operator in predicate requires a non-empty string list", binding)
		}
	default:
		return nil, fmt.Errorf("binding %s: operator predicate operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, "operator", len(values)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		out = append(out, v2CallShape{Field: "callee.method", Pattern: v2BinaryOperatorMethod(value), Exact: true})
	}
	return out, nil
}

func v2BinaryOperatorMethod(op string) string {
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

func mergeV2CallShapes(binding string, left, right v2CallShape) (v2CallShape, error) {
	out := left
	if right.Field != "" {
		if out.Field != "" && (out.Field != right.Field || out.Pattern != right.Pattern || out.Exact != right.Exact) {
			return v2CallShape{}, fmt.Errorf("binding %s: multiple different callee predicates in one conjunction are not supported", binding)
		}
		out.Field = right.Field
		out.Pattern = right.Pattern
		out.Exact = right.Exact
	}
	if right.Constraint != "" {
		if out.Constraint != "" && out.Constraint != right.Constraint {
			return v2CallShape{}, fmt.Errorf("binding %s: multiple receiver type predicates in one conjunction are not supported", binding)
		}
		out.Constraint = right.Constraint
	}
	if right.ArgCountSet {
		if out.ArgCountSet {
			min, max, ok := intersectV2ArgCount(out.ArgCountMin, out.ArgCountMax, right.ArgCountMin, right.ArgCountMax)
			if !ok {
				return v2CallShape{}, fmt.Errorf("binding %s: contradictory args.count predicates in one conjunction", binding)
			}
			out.ArgCountMin = min
			out.ArgCountMax = max
		} else {
			out.ArgCountSet = true
			out.ArgCountMin = right.ArgCountMin
			out.ArgCountMax = right.ArgCountMax
		}
	}
	out.ValMatches = append(out.ValMatches, right.ValMatches...)
	out.ValAbsents = append(out.ValAbsents, right.ValAbsents...)
	return out, nil
}

func dedupeV2CallShapes(shapes []v2CallShape) []v2CallShape {
	seen := make(map[string]bool, len(shapes))
	out := make([]v2CallShape, 0, len(shapes))
	for _, shape := range shapes {
		key := strings.Join([]string{
			shape.NodeType,
			shape.Field,
			shape.Pattern,
			strconv.FormatBool(shape.Exact),
			shape.Constraint,
			strconv.FormatBool(shape.ArgCountSet),
			strconv.Itoa(shape.ArgCountMin),
			strconv.Itoa(shape.ArgCountMax),
			strings.Join(shape.ValMatches, "\x00"),
			strings.Join(shape.ValAbsents, "\x00"),
		}, "\x01")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, shape)
	}
	return out
}

func v2CallQueryField(name string) string {
	if mapped := v2MappedCallQueryField(name); mapped != "" {
		return mapped
	}
	if _, rest, ok := strings.Cut(name, "."); ok && v2IsKnownCallQueryField(rest) {
		return rest
	}
	if _, rest, ok := strings.Cut(name, "."); ok {
		if mapped := v2MappedCallQueryField(rest); mapped != "" {
			return mapped
		}
	}
	return name
}

func v2MappedCallQueryField(name string) string {
	switch name {
	case "property", "memberAccess.property":
		return "callee.method"
	case "path", "memberAccess.path":
		return "callee.path"
	case "operator", "op", "binaryExpr.operator", "binaryExpr.op":
		return "operator"
	default:
		if v2IsKnownCallQueryField(name) {
			return name
		}
		return ""
	}
}

func v2IsKnownCallQueryField(name string) bool {
	switch name {
	case "callee.method", "call.callee.method", "callee.path", "call.callee.path",
		"callee.analysis", "call.callee.analysis",
		"callee.receiver.type", "call.callee.receiver.type",
		"args.any.literal", "call.args.any.literal",
		"args.count", "call.args.count",
		"call.filter.global", "filter.global":
		return true
	default:
		return false
	}
}

func lowerV2ArgsCountShapes(cmp V2BinaryExpr, neg bool) ([]v2CallShape, bool) {
	if neg {
		return nil, false
	}
	value, ok := v2LiteralInt(cmp.Right)
	switch cmp.Op {
	case "==":
		if !ok {
			return nil, false
		}
		return []v2CallShape{v2ArgCountShape(value, value)}, true
	case ">=":
		if !ok {
			return nil, false
		}
		return []v2CallShape{v2ArgCountShape(value, -1)}, true
	case ">":
		if !ok {
			return nil, false
		}
		return []v2CallShape{v2ArgCountShape(value+1, -1)}, true
	case "<=":
		if !ok {
			return nil, false
		}
		return []v2CallShape{v2ArgCountShape(0, value)}, true
	case "<":
		if !ok || value == 0 {
			return nil, false
		}
		return []v2CallShape{v2ArgCountShape(0, value-1)}, true
	case "in":
		values, ok := v2LiteralIntList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, false
		}
		out := make([]v2CallShape, 0, len(values))
		for _, v := range values {
			out = append(out, v2ArgCountShape(v, v))
		}
		return out, true
	default:
		return nil, false
	}
}

func v2ArgCountShape(min, max int) v2CallShape {
	return v2CallShape{ArgCountSet: true, ArgCountMin: min, ArgCountMax: max}
}

func intersectV2ArgCount(aMin, aMax, bMin, bMax int) (int, int, bool) {
	min := aMin
	if bMin > min {
		min = bMin
	}
	max := aMax
	if max < 0 || (bMax >= 0 && bMax < max) {
		max = bMax
	}
	if max >= 0 && min > max {
		return 0, 0, false
	}
	return min, max, true
}

func lowerV2ReceiverConstraint(cmp V2BinaryExpr) (string, bool) {
	switch cmp.Op {
	case "==":
		lit, ok := cmp.Right.(V2LiteralExpr)
		if !ok {
			return "", false
		}
		s, ok := lit.Value.(string)
		return s, ok
	case "in":
		values, ok := v2RuleWhereStringList(cmp.Right)
		if !ok {
			return "", false
		}
		return strings.Join(values, ","), true
	default:
		return "", false
	}
}

func lowerV2Propagation(binding string, shape v2CallShape, queryAlias string, action V2BindingOutput, pkgs []string, req *BindingRequirement) (BindingAction, error) {
	if action.Kind != "propagate value" && action.Kind != "propagate taint" && action.Kind != "propagate identity" && action.Kind != "propagate receiver" {
		return BindingAction{}, fmt.Errorf("binding %s: unsupported propagation kind %q", binding, action.Kind)
	}
	kind := "flow_path"
	if shape.Field == "callee.method" {
		kind = "flow_method"
	}
	if action.Kind == "propagate receiver" {
		if err := v2PropagationReceiverLocations(v2NormalizeQueryLocation(action.From, queryAlias), v2NormalizeQueryLocation(action.To, queryAlias)); err != nil {
			return BindingAction{}, fmt.Errorf("binding %s: %w", binding, err)
		}
		return shape.mapping(BindingAction{
			Kind:         kind,
			Pattern:      shape.Pattern,
			FlowReceiver: true,
			Packages:     pkgs,
			Requirement:  req,
		}), nil
	}
	dest, err := v2PropagationDestArg(v2NormalizeQueryLocation(action.To, queryAlias))
	if err != nil {
		return BindingAction{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	srcArg, srcResult, err := v2PropagationSource(v2NormalizeQueryLocation(action.From, queryAlias))
	if err != nil {
		return BindingAction{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	return shape.mapping(BindingAction{
		Kind:             kind,
		Pattern:          shape.Pattern,
		FlowDestArg:      dest,
		FlowSourceArg:    srcArg,
		FlowSourceResult: srcResult,
		FlowIdentity:     action.Kind == "propagate identity",
		Packages:         pkgs,
		Requirement:      req,
	}), nil
}

func v2PropagationReceiverLocations(from, to string) error {
	from = strings.TrimPrefix(from, "call.")
	to = strings.TrimPrefix(to, "call.")
	if from != "callee.receiver" || to != "result" {
		return fmt.Errorf("propagate receiver must be from callee.receiver to call.result")
	}
	return nil
}

func v2NormalizeQueryLocation(location, alias string) string {
	if alias != "" {
		location = strings.TrimPrefix(location, alias+".")
	}
	return location
}

func v2PropagationSource(location string) (arg int, result bool, err error) {
	location = strings.TrimPrefix(location, "call.")
	if location == "result" {
		return -1, true, nil
	}
	if strings.HasPrefix(location, "args[") || strings.HasPrefix(location, "call.args[") {
		location = strings.TrimPrefix(location, "call.")
		n, err := v2ArgIndex(location)
		if err != nil {
			return 0, false, fmt.Errorf("propagate source %q must be call.result or args[N]", location)
		}
		return n, false, nil
	}
	return 0, false, fmt.Errorf("propagate source %q must be call.result or args[N]", location)
}

func v2PropagationDestArg(location string) (int, error) {
	location = strings.TrimPrefix(location, "call.")
	location = strings.TrimSuffix(location, ".pointee")
	if !strings.HasPrefix(location, "args[") {
		return 0, fmt.Errorf("propagate destination %q must be args[N].pointee", location)
	}
	return v2ArgIndex(location)
}

func lowerV2Requirements(reqs []V2Requirement) ([]string, *BindingRequirement, error) {
	if len(reqs) == 0 {
		return nil, nil, nil
	}
	var req BindingRequirement
	var err error
	if len(reqs) == 1 {
		req, err = lowerV2Requirement(reqs[0])
	} else {
		req.Op = "all"
		req.Args = make([]BindingRequirement, 0, len(reqs))
		for _, raw := range reqs {
			child, childErr := lowerV2Requirement(raw)
			if childErr != nil {
				err = childErr
				break
			}
			req.Args = append(req.Args, child)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	return v2RequirementPackageHints(req), &req, nil
}

func lowerV2Requirement(req V2Requirement) (BindingRequirement, error) {
	switch req.Name {
	case "all", "any":
		if len(req.Args) == 0 {
			return BindingRequirement{}, fmt.Errorf("%s requirement needs at least one child", req.Name)
		}
		out := BindingRequirement{Op: req.Name, Args: make([]BindingRequirement, 0, len(req.Args))}
		for _, raw := range req.Args {
			child, ok := raw.(V2Requirement)
			if !ok {
				return BindingRequirement{}, fmt.Errorf("%s requirement needs child requirements", req.Name)
			}
			lowered, err := lowerV2Requirement(child)
			if err != nil {
				return BindingRequirement{}, err
			}
			out.Args = append(out.Args, lowered)
		}
		return out, nil
	case "not", "soft":
		if len(req.Args) != 1 {
			return BindingRequirement{}, fmt.Errorf("%s requirement needs exactly one child", req.Name)
		}
		child, ok := req.Args[0].(V2Requirement)
		if !ok {
			return BindingRequirement{}, fmt.Errorf("%s requirement needs a child requirement", req.Name)
		}
		lowered, err := lowerV2Requirement(child)
		if err != nil {
			return BindingRequirement{}, err
		}
		return BindingRequirement{Op: req.Name, Args: []BindingRequirement{lowered}}, nil
	case "dependency", "import", "language", "file", "framework", "schema", "project.has":
		return lowerV2PrimitiveRequirement(req)
	default:
		return BindingRequirement{}, fmt.Errorf("requirement %s needs native v2 requirement evaluation", req.Name)
	}
}

func lowerV2PrimitiveRequirement(req V2Requirement) (BindingRequirement, error) {
	values := make([]string, 0, len(req.Args))
	rangeValue := ""
	for _, raw := range req.Args {
		switch arg := raw.(type) {
		case string:
			if arg != "" {
				values = append(values, arg)
			}
		case V2NamedArg:
			if req.Name == "dependency" && arg.Name == "range" {
				s, ok := arg.Value.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return BindingRequirement{}, fmt.Errorf("dependency range requires a non-empty string")
				}
				rangeValue = strings.TrimSpace(s)
				continue
			}
			return BindingRequirement{}, fmt.Errorf("%s requirement named arg %q needs native v2 requirement evaluation", req.Name, arg.Name)
		default:
			return BindingRequirement{}, fmt.Errorf("%s requirement expects string arguments", req.Name)
		}
	}
	if len(values) == 0 {
		return BindingRequirement{}, fmt.Errorf("%s requirement requires at least one string argument", req.Name)
	}
	if req.Name != "schema" && len(values) != 1 {
		return BindingRequirement{}, fmt.Errorf("%s requirement requires exactly one string argument", req.Name)
	}
	return BindingRequirement{Op: req.Name, Value: strings.Join(values, "\x00"), Range: rangeValue}, nil
}

func v2RequirementPackageHints(req BindingRequirement) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(BindingRequirement)
	walk = func(r BindingRequirement) {
		switch r.Op {
		case "dependency", "import", "framework":
			if r.Value != "" && !seen[r.Value] {
				seen[r.Value] = true
				out = append(out, r.Value)
			}
		default:
			for _, child := range r.Args {
				walk(child)
			}
		}
	}
	walk(req)
	return out
}

type v2SinkLocationInfo struct {
	ArgIndex        int
	Collection      bool
	CollectionFirst bool
	CollectionIndex int
}

func v2ArgIndex(location string) (int, error) {
	loc, err := v2SinkLocationParts(location)
	return loc.ArgIndex, err
}

func v2SinkLocationParts(location string) (v2SinkLocationInfo, error) {
	base := location
	out := v2SinkLocationInfo{}
	if strings.HasSuffix(base, ".collection") {
		out.Collection = true
		base = strings.TrimSuffix(base, ".collection")
	} else if i := strings.LastIndex(base, ".collection["); i >= 0 && strings.HasSuffix(base, "]") {
		out.Collection = true
		out.CollectionFirst = true
		idx := strings.TrimSuffix(strings.TrimPrefix(base[i:], ".collection["), "]")
		n, err := strconv.Atoi(idx)
		if err != nil {
			return v2SinkLocationInfo{}, fmt.Errorf("invalid collection index in %q", location)
		}
		out.CollectionIndex = n
		base = base[:i]
	}
	if base == "args.any" {
		out.ArgIndex = -1
		return out, nil
	}
	if !strings.HasPrefix(base, "args[") || !strings.HasSuffix(base, "]") {
		return v2SinkLocationInfo{}, fmt.Errorf("sink/check location %q is not an args[N], args.any, or collection location", location)
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(base, "args["), "]"))
	if err != nil {
		return v2SinkLocationInfo{}, fmt.Errorf("invalid argument index in %q", location)
	}
	out.ArgIndex = n
	return out, nil
}

func lowerV2Rule(r *V2RuleDecl, names v2NameResolver, mechanics v2Mechanics) (*Rule, error) {
	out := &Rule{Name: r.Name, Package: r.Module, Meta: lowerV2FieldNames(r.Meta)}
	if out.Meta != nil {
		if raw := out.Meta["confidence_floor"]; raw != nil {
			if !mechanics.policies["confidence:default"] {
				return nil, fmt.Errorf("rule %s: no loaded policy confidence default", r.Name)
			}
			level, ok := raw.(string)
			if !ok || !v2ConfidenceLevels[level] {
				return nil, fmt.Errorf("rule %s: unknown confidence level %q", r.Name, raw)
			}
		}
	}
	solver := mechanics.ruleSolvers[r.Body.Verb]
	if solver == "" {
		return nil, fmt.Errorf("rule %s: no built-in solver for rule verb %q", r.Name, r.Body.Verb)
	}
	switch solver {
	case "dataflow.taint", "graph.reach":
		if r.Body.From.Concept == "" || r.Body.To.Concept == "" {
			return nil, fmt.Errorf("rule %s: solver capability %q requires from/to endpoints", r.Name, solver)
		}
		verb, err := v2IRFlowVerbForSolver(solver)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		out.Body = &FlowStmt{
			Verb: verb,
			Src:  Endpoint{Concept: names.concept(r.Body.From.Concept), Binding: r.Body.From.Alias},
			Dst:  Endpoint{Concept: names.concept(r.Body.To.Concept), Binding: r.Body.To.Alias},
		}
	case "graph.grant":
		if r.Body.From.Concept == "" || r.Body.To.Concept == "" {
			return nil, fmt.Errorf("rule %s: solver capability %q requires from/to endpoints", r.Name, solver)
		}
		out.Body = &FlowStmt{
			Verb: "grant",
			Src:  Endpoint{Concept: names.concept(r.Body.From.Concept), Binding: r.Body.From.Alias},
			Dst:  Endpoint{Concept: names.concept(r.Body.To.Concept), Binding: r.Body.To.Alias},
		}
	case "fact.exists":
		if r.Body.Issue.Concept == "" {
			return nil, fmt.Errorf("rule %s: solver capability %q requires a fact or issue endpoint", r.Name, solver)
		}
		out.Body = &MatchStmt{TargetKind: "concept", Concept: names.concept(r.Body.Issue.Concept), Binding: r.Body.Issue.Alias}
	case "query.semantic":
		if r.Body.Query == nil {
			return nil, fmt.Errorf("rule %s: solver capability %q requires a query body", r.Name, solver)
		}
		body, err := lowerV2RuleQuery(r.Body, names)
		if err != nil {
			return nil, fmt.Errorf("rule %s: query lowering: %w", r.Name, err)
		}
		out.Body = body
	default:
		return nil, fmt.Errorf("rule %s: solver capability %q lowering is not implemented yet", r.Name, solver)
	}
	for _, cl := range r.Clauses {
		switch cl.Kind {
		case "unless":
			if !mechanics.coverageModes[cl.Coverage] {
				return nil, fmt.Errorf("rule %s: no loaded mechanic coverage %q", r.Name, cl.Coverage)
			}
			switch cl.Coverage {
			case "path":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: PathCoveredBy{Concept: names.concept(cl.Concept)}})
			case "dominates":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: DominatesCoveredBy{Concept: names.concept(cl.Concept)}})
			case "postDominates":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: PostDominatesCoveredBy{Concept: names.concept(cl.Concept)}})
			case "endpoint":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: EndpointCoveredBy{Concept: names.concept(cl.Concept)}})
			case "sameReceiver":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: SameReceiverCoveredBy{Concept: names.concept(cl.Concept)}})
			case "sameScope":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: SameScopeCoveredBy{Concept: names.concept(cl.Concept)}})
			case "global":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: GlobalCoveredBy{Concept: names.concept(cl.Concept)}})
			default:
				return nil, fmt.Errorf("rule %s: coverage mode %q lowering is not implemented yet", r.Name, cl.Coverage)
			}
		case "where":
			expr, err := lowerV2RuleWhereExpr(cl.Expr, names)
			if err != nil {
				return nil, fmt.Errorf("rule %s: where lowering: %w", r.Name, err)
			}
			out.Clauses = append(out.Clauses, Clause{Kind: "where", Where: expr})
		case "with":
			if !mechanics.policies["confidence:default"] {
				return nil, fmt.Errorf("rule %s: no loaded policy confidence default", r.Name)
			}
			if !v2ConfidenceLevels[cl.Value] {
				return nil, fmt.Errorf("rule %s: unknown confidence level %q", r.Name, cl.Value)
			}
			if out.Meta == nil {
				out.Meta = map[string]any{}
			}
			out.Meta["confidence_floor"] = cl.Value
		case "require":
			if out.Meta == nil {
				out.Meta = map[string]any{}
			}
			out.Meta["required_profiles"] = appendStringField(out.Meta["required_profiles"], cl.Value)
		}
	}
	return out, nil
}

func appendStringField(raw any, value string) []string {
	switch xs := raw.(type) {
	case []string:
		return append(xs, value)
	case string:
		if xs == "" {
			return []string{value}
		}
		return []string{xs, value}
	default:
		return []string{value}
	}
}

func v2IRFlowVerbForSolver(solver string) (string, error) {
	switch solver {
	case "dataflow.taint":
		return "taint", nil
	case "graph.reach":
		return "reach", nil
	default:
		return "", fmt.Errorf("solver capability %q is not a scanner IR flow solver", solver)
	}
}

func lowerV2RuleQuery(body V2RuleBody, names v2NameResolver) (Stmt, error) {
	if body.Query == nil {
		return nil, fmt.Errorf("missing query body")
	}
	if order, ok := lowerV2OrderQuery(*body.Query, body.Select, names); ok {
		return order, nil
	}
	if transition, ok := lowerV2TransitionQuery(*body.Query, body.Select); ok {
		return transition, nil
	}
	if labeled, ok := lowerV2SemanticLabelQuery(*body.Query, body.Select, names); ok {
		return labeled, nil
	}
	return nil, fmt.Errorf("unsupported semantic query shape")
}

func lowerV2OrderQuery(q V2QueryExpr, selectAlias string, names v2NameResolver) (*OrderStmt, bool) {
	if !v2SemanticConceptFamily(q.Family) || q.Alias == "" || len(q.Steps) != 1 {
		return nil, false
	}
	step := q.Steps[0]
	if step.Relation != "reaches" || !v2SemanticConceptFamily(step.Family) || step.Alias == "" || selectAlias != step.Alias {
		return nil, false
	}
	first, ok := v2QueryWhereFieldEquals(q.Where, q.Alias, "concept")
	if !ok {
		return nil, false
	}
	second, ok := v2QueryWhereFieldEquals(step.Where, step.Alias, "concept")
	if !ok {
		return nil, false
	}
	return &OrderStmt{
		First:  Endpoint{Concept: names.concept(first), Binding: q.Alias},
		Second: Endpoint{Concept: names.concept(second), Binding: step.Alias},
	}, true
}

func v2SemanticConceptFamily(family string) bool {
	switch family {
	case "concept", "fact", "asset", "exposure", "principal", "privilege", "observation":
		return true
	default:
		return false
	}
}

func lowerV2TransitionQuery(q V2QueryExpr, selectAlias string) (*MatchStmt, bool) {
	if q.Family != "state" || q.Alias == "" || selectAlias != q.Alias || len(q.Steps) != 0 {
		return nil, false
	}
	fields := v2QueryWhereEqualities(q.Where, q.Alias)
	machine, okMachine := fields["machine"]
	from, okFrom := fields["from"]
	to, okTo := fields["to"]
	if !okMachine || !okFrom || !okTo {
		return nil, false
	}
	return &MatchStmt{
		TargetKind: "transition",
		Binding:    q.Alias,
		Machine:    machine,
		FromState:  from,
		ToState:    to,
	}, true
}

func lowerV2SemanticLabelQuery(q V2QueryExpr, selectAlias string, names v2NameResolver) (*MatchStmt, bool) {
	if !v2SemanticConceptFamily(q.Family) || q.Alias == "" || len(q.Steps) != 1 || selectAlias != q.Alias {
		return nil, false
	}
	step := q.Steps[0]
	if !v2SemanticConceptFamily(step.Family) || step.Alias == "" {
		return nil, false
	}
	if step.Relation != "labeledAs" && step.Relation != "references" {
		return nil, false
	}
	baseConcept, ok := v2QueryWhereFieldEquals(q.Where, q.Alias, "concept")
	if !ok {
		return nil, false
	}
	relatedConcept, ok := v2QueryWhereFieldEquals(step.Where, step.Alias, "concept")
	if !ok {
		return nil, false
	}
	out := &MatchStmt{
		TargetKind:     "concept",
		Concept:        names.concept(baseConcept),
		Binding:        q.Alias,
		Relation:       step.Relation,
		RelatedConcept: names.concept(relatedConcept),
	}
	if step.Relation == "references" {
		prop, ok := v2QueryWhereIDEqualsBaseProp(step.Where, step.Alias, q.Alias)
		if !ok {
			return nil, false
		}
		out.RelationProp = prop
	}
	return out, true
}

func v2QueryWhereIDEqualsBaseProp(expr V2Expr, stepAlias, baseAlias string) (string, bool) {
	var out string
	var visit func(V2Expr)
	visit = func(e V2Expr) {
		if out != "" {
			return
		}
		x, ok := e.(V2BinaryExpr)
		if !ok {
			return
		}
		if x.Op == "and" {
			visit(x.Left)
			visit(x.Right)
			return
		}
		if x.Op != "==" {
			return
		}
		if prop, ok := v2IDBasePropJoin(x.Left, x.Right, stepAlias, baseAlias); ok {
			out = prop
			return
		}
		if prop, ok := v2IDBasePropJoin(x.Right, x.Left, stepAlias, baseAlias); ok {
			out = prop
		}
	}
	visit(expr)
	return out, out != ""
}

func v2IDBasePropJoin(left, right V2Expr, stepAlias, baseAlias string) (string, bool) {
	lref, lok := left.(V2RefExpr)
	rref, rok := right.(V2RefExpr)
	if !lok || !rok || lref.Name != stepAlias+".id" {
		return "", false
	}
	prefix := baseAlias + "."
	if !strings.HasPrefix(rref.Name, prefix) {
		return "", false
	}
	prop := strings.TrimPrefix(rref.Name, prefix)
	if prop == "" || prop == "id" || strings.Contains(prop, ".") {
		return "", false
	}
	return prop, true
}

func v2QueryWhereFieldEquals(expr V2Expr, alias, field string) (string, bool) {
	fields := v2QueryWhereEqualities(expr, alias)
	value, ok := fields[field]
	return value, ok
}

func v2QueryWhereEqualities(expr V2Expr, alias string) map[string]string {
	out := map[string]string{}
	var visit func(V2Expr)
	visit = func(e V2Expr) {
		switch x := e.(type) {
		case V2BinaryExpr:
			if x.Op == "and" {
				visit(x.Left)
				visit(x.Right)
				return
			}
			if x.Op != "==" {
				return
			}
			left, ok := x.Left.(V2RefExpr)
			if !ok {
				return
			}
			prefix := alias + "."
			if !strings.HasPrefix(left.Name, prefix) {
				return
			}
			value, ok := v2RuleWhereValue(x.Right)
			if !ok {
				return
			}
			s, ok := value.(string)
			if !ok {
				return
			}
			out[strings.TrimPrefix(left.Name, prefix)] = s
		}
	}
	visit(expr)
	return out
}

func lowerV2RuleWhereExpr(expr V2Expr, names v2NameResolver) (Expr, error) {
	switch x := expr.(type) {
	case V2RefExpr:
		return refFromString(x.Name), nil
	case V2UnaryExpr:
		if x.Op != "not" {
			return nil, fmt.Errorf("unsupported unary operator %q", x.Op)
		}
		inner, err := lowerV2RuleWhereExpr(x.X, names)
		if err != nil {
			return nil, err
		}
		return Not{Inner: inner}, nil
	case V2BinaryExpr:
		return lowerV2RuleWhereBinary(x, names)
	case V2CallExpr:
		return lowerV2RuleWhereCall(x, names)
	default:
		return nil, fmt.Errorf("unsupported expression %T", expr)
	}
}

func lowerV2RuleWhereBinary(x V2BinaryExpr, names v2NameResolver) (Expr, error) {
	switch x.Op {
	case "and":
		left, err := lowerV2RuleWhereExpr(x.Left, names)
		if err != nil {
			return nil, err
		}
		right, err := lowerV2RuleWhereExpr(x.Right, names)
		if err != nil {
			return nil, err
		}
		var parts []Expr
		if l, ok := left.(And); ok {
			parts = append(parts, l.Parts...)
		} else {
			parts = append(parts, left)
		}
		if r, ok := right.(And); ok {
			parts = append(parts, r.Parts...)
		} else {
			parts = append(parts, right)
		}
		return And{Parts: parts}, nil
	case "==", "!=":
		ref, ok := v2RuleWhereRef(x.Left)
		if !ok {
			return nil, fmt.Errorf("%s left side must be a field reference", x.Op)
		}
		value, ok := v2RuleWhereValue(x.Right)
		if !ok {
			return nil, fmt.Errorf("%s right side must be a literal or reference", x.Op)
		}
		return Cmp{Ref: ref, Op: x.Op, Value: value}, nil
	case "in", "not in":
		ref, ok := v2RuleWhereRef(x.Left)
		if !ok {
			return nil, fmt.Errorf("%s left side must be a field reference", x.Op)
		}
		values, ok := v2RuleWhereStringList(x.Right)
		if !ok {
			return nil, fmt.Errorf("%s right side must be a list", x.Op)
		}
		return NotIn{Ref: ref, Values: values, Negate: x.Op == "not in"}, nil
	case "is":
		ref, ok := v2RuleWhereRef(x.Left)
		if !ok {
			return nil, fmt.Errorf("is left side must be a field reference")
		}
		concept, ok := v2RuleWhereRefString(x.Right)
		if !ok {
			return nil, fmt.Errorf("is right side must be a concept reference")
		}
		return Is{Ref: ref, Concept: names.concept(concept)}, nil
	default:
		return nil, fmt.Errorf("unsupported binary operator %q", x.Op)
	}
}

func lowerV2RuleWhereCall(x V2CallExpr, names v2NameResolver) (Expr, error) {
	if len(x.NamedArgs) != 0 {
		return nil, fmt.Errorf("named call args are not supported")
	}
	switch x.Name {
	case "holdsAssetKind":
		if len(x.Args) != 2 {
			return nil, fmt.Errorf("holdsAssetKind requires two args")
		}
		ref, ok := v2RuleWhereRef(x.Args[0])
		if !ok {
			return nil, fmt.Errorf("holdsAssetKind first arg must be a field reference")
		}
		kinds, ok := v2RuleWhereStringList(x.Args[1])
		if !ok {
			return nil, fmt.Errorf("holdsAssetKind second arg must be a list")
		}
		return HoldsAssetKind{Ref: ref, Kinds: kinds}, nil
	default:
		if !SolverVerbs[x.Name] {
			return nil, fmt.Errorf("unsupported call %q", x.Name)
		}
		args := make([]Arg, 0, len(x.Args))
		for _, arg := range x.Args {
			ref, ok := v2RuleWhereRef(arg)
			if !ok {
				return nil, fmt.Errorf("%s args must be references", x.Name)
			}
			args = append(args, Arg{Ref: ref})
		}
		return SolverCall{Verb: x.Name, Args: args}, nil
	}
}

func v2RuleWhereRef(expr V2Expr) (Ref, bool) {
	if ref, ok := expr.(V2RefExpr); ok {
		return refFromString(ref.Name), true
	}
	return Ref{}, false
}

func v2RuleWhereRefString(expr V2Expr) (string, bool) {
	ref, ok := expr.(V2RefExpr)
	if !ok {
		return "", false
	}
	return ref.Name, true
}

func v2RuleWhereStringList(expr V2Expr) ([]string, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return nil, false
	}
	values, ok := lit.Value.([]string)
	return values, ok
}

func v2RuleWhereValue(expr V2Expr) (any, bool) {
	switch x := expr.(type) {
	case V2LiteralExpr:
		switch x.Value.(type) {
		case string, []string:
			return x.Value, true
		default:
			return nil, false
		}
	case V2RefExpr:
		return x.Name, true
	default:
		return nil, false
	}
}

func refFromString(name string) Ref {
	if name == "" {
		return Ref{}
	}
	return Ref{Parts: strings.Split(name, ".")}
}

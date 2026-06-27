package parser

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseV2Runtime parses v2 source and lowers it into the current runtime
// declaration model.
func ParseV2Runtime(src string) ([]Decl, error) {
	prog, err := ParseV2(src)
	if err != nil {
		return nil, err
	}
	return LowerV2ToRuntime(prog)
}

type V2RuntimeSource struct {
	Name   string
	Source string
}

func V2RuntimeSourcesFromText(name, src string) []V2RuntimeSource {
	chunks := splitV2ModuleChunks(src)
	if len(chunks) == 0 {
		return []V2RuntimeSource{{Name: name, Source: src}}
	}
	out := make([]V2RuntimeSource, 0, len(chunks))
	for i, chunk := range chunks {
		out = append(out, V2RuntimeSource{Name: fmt.Sprintf("%s#module%d", name, i+1), Source: chunk})
	}
	return out
}

func ParseV2RuntimeSources(raw []V2RuntimeSource) ([]Decl, error) {
	return ParseV2RuntimeSourcesSelected(raw, nil)
}

// ParseV2RuntimeSourcesSelected validates the full v2 corpus but only lowers
// sources accepted by keep. A nil keep function lowers every source.
func ParseV2RuntimeSourcesSelected(raw []V2RuntimeSource, keep func(V2RuntimeSource) bool) ([]Decl, error) {
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
	return lowerV2SourcesToRuntimeSelected(sources, keepSource)
}

// ParseV2RuntimeMulti parses one or more concatenated v2 modules and lowers
// them into the current runtime declaration model without falling back to v1.
func ParseV2RuntimeMulti(src string) ([]Decl, error) {
	if chunks := splitV2ModuleChunks(src); len(chunks) > 1 {
		programs := make([]*V2Program, 0, len(chunks))
		mechanics := v2RuntimeMechanics{}
		for _, chunk := range chunks {
			prog, err := ParseV2(chunk)
			if err != nil {
				return nil, err
			}
			programs = append(programs, prog)
			mechanics.merge(v2RuntimeMechanicsFromProgram(prog))
		}
		var out []Decl
		for _, prog := range programs {
			decls, err := lowerV2ToRuntimeWithMechanics(prog, mechanics)
			if err != nil {
				return nil, err
			}
			out = append(out, decls...)
		}
		return out, nil
	}
	return ParseV2Runtime(src)
}

// ParseRuntimeStrict parses runtime definitions as v2 only. It accepts
// concatenated v2 modules but never falls back to legacy v1 syntax.
func ParseRuntimeStrict(src string) ([]Decl, error) {
	return ParseV2RuntimeMulti(src)
}

// ParseRuntime parses definitions for the current scanner runtime. Production
// runtime definitions are v2-only and never fall back to legacy v1 syntax.
func ParseRuntime(src string) ([]Decl, error) {
	return ParseRuntimeStrict(src)
}

func splitV2ModuleChunks(src string) []string {
	var chunks []string
	start := 0
	for lineStart := 0; lineStart < len(src); {
		lineEnd := lineStart
		for lineEnd < len(src) && src[lineEnd] != '\n' {
			lineEnd++
		}
		trimmed := strings.TrimSpace(src[lineStart:lineEnd])
		if strings.HasPrefix(trimmed, "module ") && strings.HasSuffix(trimmed, ";") && lineStart > start {
			chunk := strings.TrimSpace(src[start:lineStart])
			if chunk != "" {
				chunks = append(chunks, chunk)
			}
			start = lineStart
		}
		lineStart = lineEnd
		if lineStart < len(src) && src[lineStart] == '\n' {
			lineStart++
		}
	}
	if chunk := strings.TrimSpace(src[start:]); chunk != "" {
		chunks = append(chunks, chunk)
	}
	if len(chunks) <= 1 {
		return nil
	}
	return chunks
}

// LowerV2ToRuntime lowers v2 declarations into the current runtime structs.
// It is a migration bridge: authored syntax is v2, while scanner internals are
// converted incrementally behind this boundary.
func LowerV2ToRuntime(prog *V2Program) ([]Decl, error) {
	return lowerV2ToRuntimeWithMechanics(prog, v2RuntimeMechanicsFromProgram(prog))
}

func LowerV2SourcesToRuntime(sources []V2Source) ([]Decl, error) {
	return lowerV2SourcesToRuntimeSelected(sources, nil)
}

func lowerV2SourcesToRuntimeSelected(sources []V2Source, keep []bool) ([]Decl, error) {
	mechanics := v2RuntimeMechanics{}
	outCap := 0
	for _, src := range sources {
		mechanics.merge(v2RuntimeMechanicsFromProgram(src.Program))
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
		decls, err := lowerV2ToRuntimeWithMechanics(src.Program, mechanics)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		out = append(out, decls...)
	}
	return out, nil
}

type v2RuntimeMechanics struct {
	ruleSolvers map[string]string
}

func (m *v2RuntimeMechanics) merge(other v2RuntimeMechanics) {
	if len(other.ruleSolvers) == 0 {
		return
	}
	if m.ruleSolvers == nil {
		m.ruleSolvers = make(map[string]string, len(other.ruleSolvers))
	}
	for verb, solver := range other.ruleSolvers {
		m.ruleSolvers[verb] = solver
	}
}

func v2RuntimeMechanicsFromProgram(prog *V2Program) v2RuntimeMechanics {
	out := v2RuntimeMechanics{ruleSolvers: map[string]string{}}
	if prog == nil {
		return out
	}
	for _, d := range prog.Decls {
		m, ok := d.(*V2MechanicDecl)
		if !ok || m.Kind != "ruleVerb" {
			continue
		}
		if solver := v2BlockItemString(m.Items, "solver"); solver != "" {
			out.ruleSolvers[m.Name] = solver
		}
	}
	return out
}

func lowerV2ToRuntimeWithMechanics(prog *V2Program, mechanics v2RuntimeMechanics) ([]Decl, error) {
	if prog == nil {
		return nil, nil
	}
	out := make([]Decl, 0, len(prog.Decls))
	names := newV2NameResolver(prog)
	patterns := newV2PatternResolver(prog)
	adaptersByTech := map[string]*AdapterDecl{}
	adapterFor := func(tech string) *AdapterDecl {
		ad := adaptersByTech[tech]
		if ad == nil {
			ad = &AdapterDecl{Name: tech, Meta: map[string]any{}}
			adaptersByTech[tech] = ad
			out = append(out, ad)
		}
		return ad
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
				ad := adapterFor(tech)
				for k, v := range meta {
					ad.Meta[k] = v
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
			ad := adapterFor(tech)
			maps, err := lowerV2Binding(x, names, patterns)
			if err != nil {
				return nil, err
			}
			ad.Mappings = append(ad.Mappings, maps...)
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
	case "assumeMinLevel":
		return "assume_min_level"
	case "analysisRole":
		return "analysis_role"
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
		if item.Kind != "unstable" {
			continue
		}
		adapter, _ := item.Meta["adapter"].(string)
		rawMeta, hasMeta := item.Meta["meta"]
		if adapter == "" && !hasMeta {
			continue
		}
		if adapter == "" {
			return "", nil, fmt.Errorf("pattern %s: unstable adapter metadata requires adapter", p.Name)
		}
		meta, ok := rawMeta.(map[string]any)
		if !ok {
			return "", nil, fmt.Errorf("pattern %s: unstable adapter metadata requires meta block", p.Name)
		}
		return adapter, meta, nil
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

func lowerV2Binding(b *V2BindingDecl, names v2NameResolver, patterns v2PatternResolver) ([]AdapterMapping, error) {
	if b.Query.Expr != nil && strings.HasPrefix(b.Query.Expr.Family, "unstable.") {
		return nil, fmt.Errorf("binding %s: unsupported unstable query family %q; migrate to stable v2", b.Name, b.Query.Expr.Family)
	}
	if b.Query.Expr != nil && b.Query.Expr.Family == "param" {
		return lowerV2ParamSourceBinding(b, names)
	}
	queryWhere := b.Query.Where
	queryAlias := ""
	if b.Query.Expr != nil {
		if b.Query.Expr.Family != "call" || len(b.Query.Expr.Steps) != 0 {
			return nil, fmt.Errorf("binding %s: inline query lowering is only implemented for single call queries", b.Name)
		}
		queryWhere = b.Query.Expr.Where
		queryAlias = b.Query.Expr.Alias
	} else if b.Query.Pattern == "" {
		return nil, fmt.Errorf("binding %s: missing query", b.Name)
	} else {
		var err error
		queryWhere, queryAlias, err = lowerV2PatternQuery(b.Name, b.Query, patterns)
		if err != nil {
			return nil, err
		}
	}
	if queryAlias == "node" {
		if out, ok, err := lowerV2PresenceBinding(b, names, queryWhere, queryAlias); ok || err != nil {
			return out, err
		}
	}
	shape, err := lowerV2CallShape(b.Name, queryWhere)
	if err != nil {
		return nil, err
	}
	pkgs, err := lowerV2RequirementsToPackages(b.Requirements)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []AdapterMapping
	for _, action := range b.Outputs {
		action.Concept = names.concept(action.Concept)
		action.About = names.concept(action.About)
		switch {
		case action.Kind == "emit source":
			m := AdapterMapping{Kind: shape.sourceKind(), Pattern: shape.Pattern, Concept: action.Concept, Constraint: shape.Constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit sink":
			if action.Location == "call" || action.Location == "node" {
				m := AdapterMapping{Kind: shape.markKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs}
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
			m := AdapterMapping{
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
			}
			out = append(out, m)
		case action.Kind == "emit check":
			if action.Concept == "core.Assumption" {
				m, ok, err := lowerV2AssumptionCheck(b.Name, shape, action, pkgs)
				if err != nil {
					return nil, err
				}
				if ok {
					out = append(out, m)
					continue
				}
			}
			if action.Advisory != nil && *action.Advisory {
				m, err := lowerV2AdvisoryCheck(b.Name, shape, action, pkgs)
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
				out = append(out, AdapterMapping{Kind: kind, Pattern: shape.Pattern, Concept: action.Concept, Constraint: constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs})
				continue
			}
			if isV2GlobalCheck(action) {
				m, err := lowerV2GlobalCheck(b.Name, shape, action, pkgs)
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
			m := AdapterMapping{Kind: kind, Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, Coverage: action.Covers[0].Mode, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit issue":
			m := AdapterMapping{Kind: shape.markKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit fact" && action.Location == "call.result" && action.About != "":
			m := AdapterMapping{Kind: "type", Pattern: shape.Pattern, Concept: action.About, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs}
			out = append(out, m)
		case strings.HasPrefix(action.Kind, "propagate "):
			m, err := lowerV2Propagation(b.Name, shape, queryAlias, action, pkgs)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		default:
			return nil, fmt.Errorf("binding %s: unsupported output %q", b.Name, action.Kind)
		}
	}
	return out, nil
}

func isV2GlobalCheck(action V2BindingOutput) bool {
	return len(action.Covers) == 1 && action.Covers[0].Mode == "global"
}

func lowerV2GlobalCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string) (AdapterMapping, error) {
	if action.Location != "call" && action.Location != "node" {
		return AdapterMapping{}, fmt.Errorf("binding %s: global checks currently lower at call/node only", binding)
	}
	if action.About != "" {
		return AdapterMapping{}, fmt.Errorf("binding %s: global check about metadata is only supported on advisory checks", binding)
	}
	return AdapterMapping{
		Kind:       shape.markKind(),
		Pattern:    shape.Pattern,
		Exact:      shape.Exact,
		Concept:    action.Concept,
		Coverage:   "global",
		ValMatches: shape.ValMatches,
		ValAbsents: shape.ValAbsents,
		Packages:   pkgs,
	}, nil
}

func lowerV2AdvisoryCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string) (AdapterMapping, error) {
	if action.Location != "call" && action.Location != "node" {
		return AdapterMapping{}, fmt.Errorf("binding %s: advisory checks currently lower at call/node only", binding)
	}
	if len(action.Covers) != 1 {
		return AdapterMapping{}, fmt.Errorf("binding %s: advisory check requires exactly one coverage mode", binding)
	}
	kind := shape.markKind()
	return AdapterMapping{
		Kind:       kind,
		Pattern:    shape.Pattern,
		Exact:      shape.Exact,
		Concept:    action.Concept,
		About:      action.About,
		Advisory:   true,
		Coverage:   action.Covers[0].Mode,
		ValMatches: shape.ValMatches,
		ValAbsents: shape.ValAbsents,
		Packages:   pkgs,
	}, nil
}

func lowerV2PatternQuery(binding string, query V2BindingQuery, patterns v2PatternResolver) (V2Expr, string, error) {
	pat, ok, err := patterns.resolve(query.Pattern)
	if err != nil {
		return nil, "", fmt.Errorf("binding %s: pattern %s: %w", binding, query.Pattern, err)
	}
	if !ok {
		return nil, "", fmt.Errorf("binding %s: pattern %s is not declared in this module", binding, query.Pattern)
	}
	where, alias, binds, err := lowerV2PatternRecognitionExpr(binding, pat)
	if err != nil {
		return nil, "", err
	}
	queryWhere := rewriteV2PatternRefs(query.Where, binds)
	return andV2Expr(where, queryWhere), alias, nil
}

func lowerV2PatternRecognitionExpr(binding string, pat *V2PatternDecl) (V2Expr, string, map[string]string, error) {
	if pat == nil {
		return nil, "", nil, fmt.Errorf("binding %s: nil pattern", binding)
	}
	alias := pat.Alias
	binds := map[string]string{}
	var where V2Expr
	nodeCount := 0
	for _, item := range pat.Items {
		switch item.Kind {
		case "node":
			nodeCount++
			if item.Name != "call" && item.Name != "callExpr" && item.Name != "node" {
				return nil, "", nil, fmt.Errorf("binding %s: pattern %s node family %q needs native pattern lowering", binding, pat.Name, item.Name)
			}
			if alias == "" {
				alias = item.Alias
			}
		case "bind":
			ref, ok := item.Expr.(V2RefExpr)
			if !ok {
				return nil, "", nil, fmt.Errorf("binding %s: pattern %s bind %s needs native expression lowering", binding, pat.Name, item.Name)
			}
			binds[item.Name] = ref.Name
		case "where":
			where = andV2Expr(where, rewriteV2PatternRefs(item.Expr, binds))
		case "unstable":
			return nil, "", nil, fmt.Errorf("binding %s: pattern %s unstable items need native pattern lowering", binding, pat.Name)
		case "use":
			return nil, "", nil, fmt.Errorf("binding %s: pattern %s use items need native pattern lowering", binding, pat.Name)
		default:
			return nil, "", nil, fmt.Errorf("binding %s: pattern %s item %q needs native pattern lowering", binding, pat.Name, item.Kind)
		}
	}
	if nodeCount != 1 {
		return nil, "", nil, fmt.Errorf("binding %s: pattern %s must have exactly one call node for legacy lowering", binding, pat.Name)
	}
	return where, alias, binds, nil
}

func lowerV2PresenceBinding(b *V2BindingDecl, names v2NameResolver, expr V2Expr, alias string) ([]AdapterMapping, bool, error) {
	fl, ok, err := lowerV2PresenceFlagExpr(alias, expr)
	if err != nil || !ok {
		return nil, ok, err
	}
	pkgs, err := lowerV2RequirementsToPackages(b.Requirements)
	if err != nil {
		return nil, true, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []AdapterMapping
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
			coverage = action.Covers[0].Mode
		}
		flag := *fl
		out = append(out, AdapterMapping{
			Kind:     "flag",
			Concept:  action.Concept,
			About:    action.About,
			Advisory: action.Advisory != nil && *action.Advisory,
			Coverage: coverage,
			Packages: pkgs,
			Flag:     &flag,
		})
	}
	return out, true, nil
}

func lowerV2PresenceFlagExpr(alias string, expr V2Expr) (*AdapterFlag, bool, error) {
	if alias == "" {
		return nil, true, fmt.Errorf("query alias is required")
	}
	fl := &AdapterFlag{NodeKind: "any"}
	handled := false
	for _, atom := range flattenV2And(expr) {
		neg := false
		if u, ok := atom.(V2UnaryExpr); ok && u.Op == "not" {
			neg = true
			atom = u.X
		}
		if handledOperand, err := lowerV2PresenceOperand(fl, alias, atom, neg); handledOperand || err != nil {
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
		pred, err := lowerV2PresencePredicate(alias, "node", atom, neg)
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

func lowerV2ParamSourceBinding(b *V2BindingDecl, names v2NameResolver) ([]AdapterMapping, error) {
	if b.Query.Expr.Alias != "param" || b.Query.Expr.Where != nil || len(b.Query.Expr.Steps) != 0 {
		return nil, fmt.Errorf("binding %s: param source lowering requires query param as param", b.Name)
	}
	pkgs, err := lowerV2RequirementsToPackages(b.Requirements)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []AdapterMapping
	for _, action := range b.Outputs {
		action.Concept = names.concept(action.Concept)
		if action.Kind != "emit source" || action.Location != "param" {
			return nil, fmt.Errorf("binding %s: param query only supports emit source at param", b.Name)
		}
		out = append(out, AdapterMapping{Kind: "source_param", Concept: action.Concept, Packages: pkgs})
	}
	return out, nil
}

func lowerV2PresenceOperand(fl *AdapterFlag, alias string, expr V2Expr, neg bool) (bool, error) {
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
	var operand AdapterFlagOperand
	for _, atom := range flattenV2And(where) {
		opNeg := false
		if u, ok := atom.(V2UnaryExpr); ok && u.Op == "not" {
			opNeg = true
			atom = u.X
		}
		pred, err := lowerV2PresencePredicate("operand", "operand", atom, opNeg)
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

func lowerV2PresenceMeta(fl *AdapterFlag, alias string, expr V2Expr, neg bool) (bool, error) {
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

func lowerV2PresencePredicate(alias, defaultSubject string, expr V2Expr, neg bool) (AdapterFlagPredicate, error) {
	switch x := expr.(type) {
	case V2BinaryExpr:
		return lowerV2PresenceBinary(alias, defaultSubject, x, neg)
	case V2CallExpr:
		return lowerV2PresenceCall(alias, defaultSubject, x, neg)
	default:
		return AdapterFlagPredicate{}, fmt.Errorf("unsupported predicate expression %T", expr)
	}
}

func lowerV2PresenceBinary(alias, defaultSubject string, x V2BinaryExpr, neg bool) (AdapterFlagPredicate, error) {
	field, ok := v2PresenceField(alias, x.Left)
	if !ok {
		return AdapterFlagPredicate{}, fmt.Errorf("predicate left side must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return AdapterFlagPredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	switch x.Op {
	case "~=", "==", "contains":
		value, ok := v2LiteralString(x.Right)
		if !ok {
			return AdapterFlagPredicate{}, fmt.Errorf("%s predicate right side must be a string", field)
		}
		pred := AdapterFlagPredicate{Subject: subject, Property: prop, Values: []string{value}, Negative: neg}
		switch {
		case prop == "path":
			pred.Op = "match"
			pred.Exact = x.Op == "=="
		case x.Op == "contains":
			pred.Op = "contains"
		case x.Op == "==":
			pred.Op = "equals"
		default:
			return AdapterFlagPredicate{}, fmt.Errorf("unsupported operator %q for %s", x.Op, field)
		}
		return pred, nil
	case "in":
		values, ok := v2RuleWhereStringList(x.Right)
		if !ok {
			return AdapterFlagPredicate{}, fmt.Errorf("%s in predicate requires a string list", field)
		}
		return AdapterFlagPredicate{Subject: subject, Property: prop, Op: "equals_any", Values: values, Negative: neg}, nil
	default:
		return AdapterFlagPredicate{}, fmt.Errorf("unsupported operator %q", x.Op)
	}
}

func lowerV2PresenceCall(alias, defaultSubject string, x V2CallExpr, neg bool) (AdapterFlagPredicate, error) {
	if x.Name != "containsAny" {
		return AdapterFlagPredicate{}, fmt.Errorf("unsupported call %q", x.Name)
	}
	if len(x.Args) != 2 || len(x.NamedArgs) != 0 {
		return AdapterFlagPredicate{}, fmt.Errorf("containsAny requires two positional args")
	}
	field, ok := v2PresenceField(alias, x.Args[0])
	if !ok {
		return AdapterFlagPredicate{}, fmt.Errorf("containsAny first arg must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return AdapterFlagPredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	values, ok := v2RuleWhereStringList(x.Args[1])
	if !ok {
		return AdapterFlagPredicate{}, fmt.Errorf("containsAny second arg must be a string list")
	}
	return AdapterFlagPredicate{Subject: subject, Property: prop, Op: "contains_any", Values: values, Negative: neg}, nil
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

func v2LiteralString(expr V2Expr) (string, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return "", false
	}
	s, ok := lit.Value.(string)
	return s, ok
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
	case "path", "endpoint", "sameReceiver", "sameScope", "dominates":
		return nil
	case "global":
		return fmt.Errorf("binding %s: global checks must lower through global coverage support", binding)
	default:
		return fmt.Errorf("binding %s: coverage mode %q lowering is not implemented yet", binding, action.Covers[0].Mode)
	}
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

func lowerV2AssumptionCheck(binding string, shape v2CallShape, action V2BindingOutput, pkgs []string) (AdapterMapping, bool, error) {
	advisory := action.Advisory != nil && *action.Advisory
	if !advisory || action.About == "" {
		return AdapterMapping{}, false, nil
	}
	if action.Location != "call" {
		return AdapterMapping{}, true, fmt.Errorf("binding %s: Assumption check must be emitted at call", binding)
	}
	if len(action.Covers) != 1 {
		return AdapterMapping{}, true, fmt.Errorf("binding %s: Assumption check requires exactly one coverage mode", binding)
	}
	mode := ""
	switch action.Covers[0].Mode {
	case "dominates":
		mode = "guard"
	case "path":
		mode = "sanitizer"
	default:
		return AdapterMapping{}, true, fmt.Errorf("binding %s: unsupported Assumption coverage mode %q", binding, action.Covers[0].Mode)
	}
	kind := "assume_" + mode + "_path"
	if shape.Field == "callee.method" {
		kind = "assume_" + mode + "_method"
	}
	return AdapterMapping{
		Kind:       kind,
		Pattern:    shape.Pattern,
		About:      action.About,
		ValMatches: shape.ValMatches,
		ValAbsents: shape.ValAbsents,
		Packages:   pkgs,
	}, true, nil
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
	Field      string
	Pattern    string
	Exact      bool
	Constraint string
	ValMatches []string
	ValAbsents []string
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

func lowerV2CallShape(binding string, expr V2Expr) (v2CallShape, error) {
	var shape v2CallShape
	var haveShape bool
	var visit func(V2Expr, bool) error
	visit = func(expr V2Expr, neg bool) error {
		if u, ok := expr.(V2UnaryExpr); ok && u.Op == "not" {
			return visit(u.X, !neg)
		}
		cmp, ok := expr.(V2BinaryExpr)
		if !ok {
			return fmt.Errorf("binding %s: unsupported query predicate %T", binding, expr)
		}
		if cmp.Op == "and" {
			if err := visit(cmp.Left, neg); err != nil {
				return err
			}
			return visit(cmp.Right, neg)
		}
		if cmp.Op == "or" {
			return fmt.Errorf("binding %s: query predicate disjunction is not implemented in legacy lowering", binding)
		}
		leftExpr := cmp.Left
		cmpNeg := neg
		if u, ok := leftExpr.(V2UnaryExpr); ok && u.Op == "not" {
			leftExpr = u.X
			cmpNeg = !cmpNeg
		}
		left, ok := leftExpr.(V2RefExpr)
		if !ok {
			return fmt.Errorf("binding %s: unsupported query predicate left side %T", binding, cmp.Left)
		}
		field := v2CallQueryField(left.Name)
		switch field {
		case "callee.method", "call.callee.method", "callee.path", "call.callee.path":
			if cmpNeg {
				return fmt.Errorf("binding %s: negated callee predicate is not implemented in legacy lowering", binding)
			}
			if cmp.Op != "==" && cmp.Op != "~=" {
				return fmt.Errorf("binding %s: callee predicate operator %q is not implemented in legacy lowering", binding, cmp.Op)
			}
			lit, ok := cmp.Right.(V2LiteralExpr)
			if !ok {
				return fmt.Errorf("binding %s: query predicate right side must be a literal", binding)
			}
			pat, ok := lit.Value.(string)
			if !ok {
				return fmt.Errorf("binding %s: query predicate right side must be a string", binding)
			}
			field := strings.TrimPrefix(field, "call.")
			shape.Field = field
			shape.Pattern = pat
			shape.Exact = cmp.Op == "==" && field == "callee.path"
			haveShape = true
		case "callee.receiver.type", "call.callee.receiver.type":
			if cmpNeg {
				return fmt.Errorf("binding %s: negated receiver type predicate is not implemented in legacy lowering", binding)
			}
			constraint, ok := lowerV2ReceiverConstraint(cmp)
			if !ok {
				return fmt.Errorf("binding %s: receiver type predicate must compare to string or string list", binding)
			}
			shape.Constraint = constraint
		case "args.any.literal", "call.args.any.literal":
			if cmp.Op != "contains" {
				return fmt.Errorf("binding %s: args.any.literal operator %q is not implemented in legacy lowering", binding, cmp.Op)
			}
			value, ok := v2LiteralString(cmp.Right)
			if !ok {
				return fmt.Errorf("binding %s: args.any.literal predicate right side must be a string", binding)
			}
			if cmpNeg {
				shape.ValAbsents = append(shape.ValAbsents, value)
			} else {
				shape.ValMatches = append(shape.ValMatches, value)
			}
		case "call.filter.global", "filter.global":
			if cmpNeg || cmp.Op != "==" {
				return fmt.Errorf("binding %s: call.filter.global predicate must be == true", binding)
			}
			lit, ok := cmp.Right.(V2LiteralExpr)
			if !ok {
				return fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
			}
			v, ok := lit.Value.(bool)
			if !ok {
				return fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
			}
			if !v {
				return fmt.Errorf("binding %s: call.filter.global == false is not implemented in legacy lowering", binding)
			}
		default:
			return fmt.Errorf("binding %s: query predicate %q is not implemented in legacy lowering", binding, left.Name)
		}
		return nil
	}
	if err := visit(expr, false); err != nil {
		return v2CallShape{}, err
	}
	if !haveShape {
		return v2CallShape{}, fmt.Errorf("binding %s: query pattern lowering needs a callee.method/path predicate", binding)
	}
	return shape, nil
}

func v2CallQueryField(name string) string {
	if v2IsKnownCallQueryField(name) {
		return name
	}
	if _, rest, ok := strings.Cut(name, "."); ok && v2IsKnownCallQueryField(rest) {
		return rest
	}
	return name
}

func v2IsKnownCallQueryField(name string) bool {
	switch name {
	case "callee.method", "call.callee.method", "callee.path", "call.callee.path",
		"callee.receiver.type", "call.callee.receiver.type",
		"args.any.literal", "call.args.any.literal",
		"call.filter.global", "filter.global":
		return true
	default:
		return false
	}
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

func lowerV2Propagation(binding string, shape v2CallShape, queryAlias string, action V2BindingOutput, pkgs []string) (AdapterMapping, error) {
	if action.Kind != "propagate value" {
		return AdapterMapping{}, fmt.Errorf("binding %s: unsupported propagation kind %q", binding, action.Kind)
	}
	kind := "flow_path"
	if shape.Field == "callee.method" {
		kind = "flow_method"
	}
	dest, err := v2PropagationDestArg(v2NormalizeQueryLocation(action.To, queryAlias))
	if err != nil {
		return AdapterMapping{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	srcArg, srcResult, err := v2PropagationSource(v2NormalizeQueryLocation(action.From, queryAlias))
	if err != nil {
		return AdapterMapping{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	return AdapterMapping{
		Kind:             kind,
		Pattern:          shape.Pattern,
		FlowDestArg:      dest,
		FlowSourceArg:    srcArg,
		FlowSourceResult: srcResult,
		Packages:         pkgs,
	}, nil
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

func lowerV2RequirementsToPackages(reqs []V2Requirement) ([]string, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	if len(reqs) != 1 {
		return nil, fmt.Errorf("multiple requirements need native v2 requirement evaluation")
	}
	return lowerV2PackageRequirement(reqs[0])
}

func lowerV2PackageRequirement(req V2Requirement) ([]string, error) {
	switch req.Name {
	case "dependency":
		pkg, err := lowerV2DependencyRequirement(req)
		if err != nil {
			return nil, err
		}
		return []string{pkg}, nil
	case "any":
		if len(req.Args) == 0 {
			return nil, fmt.Errorf("any dependency requirement needs at least one child")
		}
		seen := map[string]bool{}
		out := make([]string, 0, len(req.Args))
		for _, raw := range req.Args {
			child, ok := raw.(V2Requirement)
			if !ok {
				return nil, fmt.Errorf("any requirement needs child requirements for legacy package lowering")
			}
			pkg, err := lowerV2DependencyRequirement(child)
			if err != nil {
				return nil, err
			}
			if !seen[pkg] {
				seen[pkg] = true
				out = append(out, pkg)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("requirement %s needs native v2 requirement evaluation", req.Name)
	}
}

func lowerV2DependencyRequirement(req V2Requirement) (string, error) {
	if req.Name != "dependency" {
		return "", fmt.Errorf("requirement %s needs native v2 requirement evaluation", req.Name)
	}
	if len(req.Args) != 1 {
		return "", fmt.Errorf("dependency requirement with named args or version ranges needs native v2 requirement evaluation")
	}
	pkg, ok := req.Args[0].(string)
	if !ok || pkg == "" {
		return "", fmt.Errorf("dependency requirement requires one package string")
	}
	return pkg, nil
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

func lowerV2Rule(r *V2RuleDecl, names v2NameResolver, mechanics v2RuntimeMechanics) (*Rule, error) {
	out := &Rule{Name: r.Name, Package: r.Module, Meta: r.Meta}
	solver := mechanics.ruleSolvers[r.Body.Verb]
	if solver == "" {
		solver = v2LegacySolverForRuleVerb(r.Body.Verb)
	}
	switch solver {
	case "dataflow.taint", "dataflow.flow", "graph.reach":
		if r.Body.From.Concept == "" || r.Body.To.Concept == "" {
			return nil, fmt.Errorf("rule %s: solver capability %q requires from/to endpoints", r.Name, solver)
		}
		verb, err := v2LegacyFlowVerbForSolver(solver)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		out.Body = &FlowStmt{
			Verb: verb,
			Src:  Endpoint{Concept: names.concept(r.Body.From.Concept), Binding: r.Body.From.Alias},
			Dst:  Endpoint{Concept: names.concept(r.Body.To.Concept), Binding: r.Body.To.Alias},
		}
	case "graph.grant", "graph.assume":
		if r.Body.From.Concept == "" || r.Body.To.Concept == "" {
			return nil, fmt.Errorf("rule %s: solver capability %q requires from/to endpoints", r.Name, solver)
		}
		verb := "assume"
		if solver == "graph.grant" {
			verb = "grant"
		}
		out.Body = &FlowStmt{
			Verb: verb,
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
			switch cl.Coverage {
			case "path":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: SanitizedBy{Concept: names.concept(cl.Concept)}})
			case "dominates":
				concept := names.concept(cl.Concept)
				unless := Exception(DominatesCoveredBy{Concept: concept})
				if isV2PostDominanceReleaseConcept(concept) {
					unless = ClosedBy{Concept: concept}
				}
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: unless})
			case "endpoint":
				out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: GuardedBy{Concept: names.concept(cl.Concept)}})
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

func isV2PostDominanceReleaseConcept(concept string) bool {
	short := concept
	if i := strings.LastIndexByte(short, '.'); i >= 0 {
		short = short[i+1:]
	}
	return short == "ResourceRelease" || short == "LockRelease"
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

func v2LegacySolverForRuleVerb(verb string) string {
	switch verb {
	case "taint":
		return "dataflow.taint"
	case "flow":
		return "dataflow.flow"
	case "reach":
		return "graph.reach"
	case "grant":
		return "graph.grant"
	case "assume":
		return "graph.assume"
	case "issue", "fact":
		return "fact.exists"
	case "query":
		return "query.semantic"
	default:
		return ""
	}
}

func v2LegacyFlowVerbForSolver(solver string) (string, error) {
	switch solver {
	case "dataflow.taint":
		return "taint", nil
	case "dataflow.flow":
		return "flow", nil
	case "graph.reach":
		return "reach", nil
	default:
		return "", fmt.Errorf("solver capability %q is not a legacy flow solver", solver)
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
	return nil, fmt.Errorf("unsupported semantic query shape")
}

func lowerV2OrderQuery(q V2QueryExpr, selectAlias string, names v2NameResolver) (*OrderStmt, bool) {
	if q.Family != "concept" || q.Alias == "" || len(q.Steps) != 1 {
		return nil, false
	}
	step := q.Steps[0]
	if step.Relation != "reaches" || step.Family != "concept" || step.Alias == "" || selectAlias != step.Alias {
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
	case "has":
		if len(x.Args) != 2 {
			return nil, fmt.Errorf("has requires two args")
		}
		ref, ok := v2RuleWhereRef(x.Args[0])
		if !ok {
			return nil, fmt.Errorf("has first arg must be a field reference")
		}
		concept, ok := v2RuleWhereRefString(x.Args[1])
		if !ok {
			return nil, fmt.Errorf("has second arg must be a concept reference")
		}
		return Has{Ref: ref, Concept: names.concept(concept)}, nil
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

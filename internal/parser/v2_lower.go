package parser

import (
	"errors"
	"fmt"
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
	sources, keepSource, err := ParseV2Sources(raw, keep)
	if err != nil {
		return nil, err
	}
	return LowerV2SourcesSelected(sources, keepSource)
}

// ParseV2Sources parses and validates the corpus and reports which sources the caller asked
// to lower. It exists because compiling bindings is a second pass over the same parse, run
// by the binding layer: a caller that wants both rules and bindings parses once here, then
// lowers with LowerV2SourcesSelected and compiles with the binding compiler.
func ParseV2Sources(raw []V2DefinitionSource, keep func(V2DefinitionSource) bool) ([]V2Source, []bool, error) {
	sources := make([]V2Source, 0, len(raw))
	keepSource := make([]bool, 0, len(raw))
	for _, src := range raw {
		prog, err := ParseV2(src.Source)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: v2 parse failed: %w", src.Name, err)
		}
		sources = append(sources, V2Source{Name: src.Name, Program: prog})
		keepSource = append(keepSource, keep == nil || keep(src))
	}
	if err := ValidateV2Corpus(sources); err != nil {
		return nil, nil, fmt.Errorf("v2 corpus validation failed: %w", err)
	}
	return sources, keepSource, nil
}

// LowerV2SourcesSelected lowers the sources the keep mask selects. A nil mask lowers all.
func LowerV2SourcesSelected(sources []V2Source, keep []bool) ([]Decl, error) {
	return lowerV2DefinitionSourcesSelected(sources, keep)
}

// lowerV2ProgramToDeclarations compiles authored v2 definitions into scanner IR.
func lowerV2ProgramToDeclarations(prog *V2Program) ([]Decl, error) {
	if err := validateV2ProgramMechanicBoundary("<inline>", prog); err != nil {
		return nil, err
	}
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
	var errs []error
	for _, src := range sources {
		errs = append(errs, validateV2ProgramMechanicBoundary(src.Name, src.Program))
	}
	return errors.Join(errs...)
}

func validateV2ProgramMechanicBoundary(sourceName string, prog *V2Program) error {
	if prog == nil {
		return nil
	}
	builtins := builtinV2MechanicSources()
	var errs []error
	for _, decl := range prog.Decls {
		m, ok := decl.(*V2MechanicDecl)
		if !ok {
			continue
		}
		if v2GoOwnedMechanicNames[m.Name] {
			errs = append(errs, fmt.Errorf("%s: mechanic %s.%s is Go-owned and must not be authored", sourceName, m.Kind, m.Name))
		}
		key := v2MechanicID{Kind: m.Kind, Name: m.Name}
		if builtins[key] != "" {
			errs = append(errs, fmt.Errorf("%s: duplicate v2 mechanic %s.%s; first declared in <builtin>", sourceName, m.Kind, m.Name))
		}
		if !v2MechanicKinds[m.Kind] {
			errs = append(errs, fmt.Errorf("%s: mechanic %s.%s has unknown mechanic kind %q", sourceName, m.Kind, m.Name, m.Kind))
			continue
		}
		if !v2ImplementedMechanicKinds[m.Kind] {
			errs = append(errs, fmt.Errorf("%s: mechanic %s.%s is recognized by the v2 contract but is not implemented by the current runtime", sourceName, m.Kind, m.Name))
			continue
		}
		if m.Kind == "ruleVerb" && !v2BuiltInRuleVerbs[m.Name] {
			errs = append(errs, fmt.Errorf("%s: mechanic ruleVerb.%s is an extension rule verb, which is not implemented by the current runtime", sourceName, m.Name))
		}
		if m.Kind == "coverage" && !v2CoverageModes[m.Name] {
			errs = append(errs, fmt.Errorf("%s: mechanic coverage.%s is not a built-in coverage mode and extension coverage mechanics are not implemented by the current runtime", sourceName, m.Name))
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
	conceptRoles  map[string]map[string]bool
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
	if len(other.conceptRoles) != 0 && m.conceptRoles == nil {
		m.conceptRoles = make(map[string]map[string]bool, len(other.conceptRoles))
	}
	for role, concepts := range other.conceptRoles {
		if m.conceptRoles[role] == nil {
			m.conceptRoles[role] = map[string]bool{}
		}
		for concept := range concepts {
			m.conceptRoles[role][concept] = true
		}
	}
}

func (m v2Mechanics) conceptHasRole(concept, role string) bool {
	return m.conceptRoles != nil && m.conceptRoles[role] != nil && m.conceptRoles[role][concept]
}

func v2MechanicsFromProgram(prog *V2Program) v2Mechanics {
	out := v2Mechanics{ruleSolvers: map[string]string{}, coverageModes: map[string]bool{}, policies: map[string]bool{}, conceptRoles: map[string]map[string]bool{}}
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
		case *V2ConceptDecl:
			roles, _ := x.Fields["internalRoles"].([]string)
			if len(roles) == 0 {
				roles, _ = x.Fields["internal_roles"].([]string)
			}
			if len(roles) == 0 {
				continue
			}
			_, fq := V2DeclNames(prog.Module, x)
			for _, role := range roles {
				if out.conceptRoles[role] == nil {
					out.conceptRoles[role] = map[string]bool{}
				}
				out.conceptRoles[role][fq] = true
			}
		}
	}
	return out
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
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *V2ConceptDecl:
			out = append(out, &ConceptDecl{Name: x.Name, Package: x.Module, Kind: x.Kind, Fields: lowerV2FieldNames(x.Fields)})
		case *V2ThreatDecl:
			out = append(out, &ThreatDecl{Name: x.Name, Package: x.Module, Fields: lowerV2FieldNames(x.Fields)})
		case *V2PatternDecl:
			// Passed through rather than compiled. A pattern is binding-layer input --
			// recognition shapes and binding-set metadata -- and the binding compiler reads
			// it from the declaration stream.
			out = append(out, x)
		case *V2ReviewDecl:
			out = append(out, &ReviewDecl{Concept: names.concept(x.Concept), Fields: lowerV2FieldNames(x.Fields)})
		case *V2ProfileDecl:
			out = append(out, &ProfileDecl{Name: x.Name, Fields: lowerV2FieldNames(x.Fields)})
		case *V2PackDecl:
			out = append(out, &PackDecl{Name: x.Name, Fields: lowerV2FieldNames(x.Fields)})
		case *V2BindingDecl:
			// Declared, not compiled. Turning a binding into graph-labeling actions is the
			// binding layer's job; the parser resolved the language and stops there.
			out = append(out, x)
		case *V2RuleDecl:
			r, err := lowerV2Rule(x, names, mechanics)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		case *V2MatcherDecl:
			// Matchers are named value tests used only by presence bindings, so they travel
			// to the binding compiler rather than being resolved here.
			out = append(out, x)
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
		local, fq := V2DeclNames(prog.Module, c)
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
	case "sourceConditionCategory":
		return "source_condition_category"
	case "sourceCondition":
		return "source_condition"
	case "sourceAssumption":
		return "source_assumption"
	case "sourceConfidence":
		return "source_confidence"
	case "coverageReservedSource":
		return "coverage_reserved_source"
	case "coverageReservedControl":
		return "coverage_reserved_control"
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
	case "internalRoles":
		return "internal_roles"
	case "excludedChars":
		return "excluded_chars"
	case "reviewCategory":
		return "review_category"
	case "reviewCondition":
		return "review_condition"
	case "reviewEvidence":
		return "review_evidence"
	case "reviewAssumption":
		return "review_assumption"
	case "reviewConfidence":
		return "review_confidence"
	default:
		return name
	}
}

func V2BindingTechnology(module string) string {
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
	if order, ok := lowerV2ConceptOrderQuery(*body.Query, body.Select, names); ok {
		return order, nil
	}
	if reach, ok := lowerV2SemanticReachQuery(*body.Query, body.Select, names); ok {
		return reach, nil
	}
	if transition, ok := lowerV2TransitionQuery(*body.Query, body.Select); ok {
		return transition, nil
	}
	if labeled, ok := lowerV2SemanticLabelQuery(*body.Query, body.Select, names); ok {
		return labeled, nil
	}
	return nil, fmt.Errorf("unsupported semantic query shape")
}

func lowerV2ConceptOrderQuery(q V2QueryExpr, selectAlias string, names v2NameResolver) (*OrderStmt, bool) {
	if q.Family != "concept" || q.Alias == "" || len(q.Steps) != 1 {
		return nil, false
	}
	step := q.Steps[0]
	if step.Relation != "reaches" || step.Family != "concept" || step.Alias == "" || selectAlias != step.Alias {
		return nil, false
	}
	firstFields, ok := v2QueryWhereStrictEqualities(q.Where, q.Alias, "concept")
	if !ok || firstFields["concept"] == "" {
		return nil, false
	}
	secondFields, ok := v2QueryWhereStrictEqualities(step.Where, step.Alias, "concept")
	if !ok || secondFields["concept"] == "" {
		return nil, false
	}
	return &OrderStmt{
		First:  Endpoint{Concept: names.concept(firstFields["concept"]), Binding: q.Alias},
		Second: Endpoint{Concept: names.concept(secondFields["concept"]), Binding: step.Alias},
	}, true
}

func lowerV2SemanticReachQuery(q V2QueryExpr, selectAlias string, names v2NameResolver) (*FlowStmt, bool) {
	if !v2SemanticConceptFamily(q.Family) || q.Alias == "" || len(q.Steps) != 1 {
		return nil, false
	}
	step := q.Steps[0]
	if step.Relation != "reaches" || !v2SemanticConceptFamily(step.Family) || step.Alias == "" || selectAlias != step.Alias {
		return nil, false
	}
	firstFields, ok := v2QueryWhereStrictEqualities(q.Where, q.Alias, "concept")
	if !ok || firstFields["concept"] == "" {
		return nil, false
	}
	secondFields, ok := v2QueryWhereStrictEqualities(step.Where, step.Alias, "concept")
	if !ok || secondFields["concept"] == "" {
		return nil, false
	}
	return &FlowStmt{
		Verb:          "reach",
		Src:           Endpoint{Concept: names.concept(firstFields["concept"]), Binding: q.Alias},
		Dst:           Endpoint{Concept: names.concept(secondFields["concept"]), Binding: step.Alias},
		SemanticQuery: true,
	}, true
}

func v2SemanticConceptFamily(family string) bool {
	switch family {
	case "concept", "fact", "asset", "exposure", "principal", "privilege", "state":
		return true
	default:
		return false
	}
}

func lowerV2TransitionQuery(q V2QueryExpr, selectAlias string) (*MatchStmt, bool) {
	if q.Family != "state" || q.Alias == "" || selectAlias != q.Alias || len(q.Steps) != 0 {
		return nil, false
	}
	fields, ok := v2QueryWhereStrictEqualities(q.Where, q.Alias, "machine", "from", "to")
	if !ok {
		return nil, false
	}
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
	baseFields, ok := v2QueryWhereStrictEqualities(q.Where, q.Alias, "concept")
	if !ok || baseFields["concept"] == "" {
		return nil, false
	}
	relatedFields, relationProp, ok := v2QueryWhereStrictEqualitiesAndBaseJoin(step.Where, step.Alias, q.Alias, "concept")
	if !ok || relatedFields["concept"] == "" {
		return nil, false
	}
	out := &MatchStmt{
		TargetKind:     "concept",
		Concept:        names.concept(baseFields["concept"]),
		Binding:        q.Alias,
		Relation:       step.Relation,
		RelatedConcept: names.concept(relatedFields["concept"]),
	}
	if step.Relation == "references" {
		if relationProp == "" {
			return nil, false
		}
		out.RelationProp = relationProp
	} else if relationProp != "" {
		return nil, false
	}
	return out, true
}

func v2QueryWhereStrictEqualities(expr V2Expr, alias string, allowedFields ...string) (map[string]string, bool) {
	allowed := v2AllowedFieldSet(allowedFields...)
	fields := map[string]string{}
	if !v2CollectStrictQueryWhere(expr, alias, "", allowed, fields, nil) {
		return nil, false
	}
	return fields, true
}

func v2QueryWhereStrictEqualitiesAndBaseJoin(expr V2Expr, alias, baseAlias string, allowedFields ...string) (map[string]string, string, bool) {
	allowed := v2AllowedFieldSet(allowedFields...)
	fields := map[string]string{}
	var relationProp string
	if !v2CollectStrictQueryWhere(expr, alias, baseAlias, allowed, fields, &relationProp) {
		return nil, "", false
	}
	return fields, relationProp, true
}

func v2AllowedFieldSet(fields ...string) map[string]bool {
	out := make(map[string]bool, len(fields))
	for _, field := range fields {
		out[field] = true
	}
	return out
}

func v2CollectStrictQueryWhere(expr V2Expr, alias, baseAlias string, allowed map[string]bool, fields map[string]string, relationProp *string) bool {
	if expr == nil {
		return false
	}
	x, ok := expr.(V2BinaryExpr)
	if !ok {
		return false
	}
	if x.Op == "and" {
		return v2CollectStrictQueryWhere(x.Left, alias, baseAlias, allowed, fields, relationProp) &&
			v2CollectStrictQueryWhere(x.Right, alias, baseAlias, allowed, fields, relationProp)
	}
	if x.Op != "==" {
		return false
	}
	if relationProp != nil && baseAlias != "" {
		if prop, ok := v2IDBasePropJoin(x.Left, x.Right, alias, baseAlias); ok {
			if *relationProp != "" && *relationProp != prop {
				return false
			}
			*relationProp = prop
			return true
		}
	}
	ref, ok := x.Left.(V2RefExpr)
	if !ok {
		return false
	}
	prefix := alias + "."
	if !strings.HasPrefix(ref.Name, prefix) {
		return false
	}
	field := strings.TrimPrefix(ref.Name, prefix)
	if !allowed[field] {
		return false
	}
	value, ok := v2RuleWhereValue(x.Right)
	if !ok {
		return false
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return false
	}
	if prev, exists := fields[field]; exists && prev != s {
		return false
	}
	fields[field] = s
	return true
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
	case "or":
		left, err := lowerV2RuleWhereExpr(x.Left, names)
		if err != nil {
			return nil, err
		}
		right, err := lowerV2RuleWhereExpr(x.Right, names)
		if err != nil {
			return nil, err
		}
		var parts []Expr
		if l, ok := left.(Or); ok {
			parts = append(parts, l.Parts...)
		} else {
			parts = append(parts, left)
		}
		if r, ok := right.(Or); ok {
			parts = append(parts, r.Parts...)
		} else {
			parts = append(parts, right)
		}
		return Or{Parts: parts}, nil
	case "==", "!=", ">=", "<=", ">", "<":
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
		values, ok := V2RuleWhereStringList(x.Right)
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
		kinds, ok := V2RuleWhereStringList(x.Args[1])
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

func V2RuleWhereStringList(expr V2Expr) ([]string, bool) {
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
		case string, []string, int:
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

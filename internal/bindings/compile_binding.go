package bindings

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/parser"
)

// Compiled from authored v2 binding declarations -- binding declarations to binding actions: the top-level compile of one v2 binding.

type v2MatcherSpec struct {
	Op          string
	Values      []string
	Unsupported string
}

func v2MatcherSpecFromDecl(m *parser.V2MatcherDecl) v2MatcherSpec {
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

type v2MatcherResolver struct {
	matchers map[string]v2MatcherSpec
	local    map[string]v2MatcherSpec
	imports  map[string]string
	module   string
}

func newV2MatcherResolver(prog *parser.V2Program, matchers map[string]v2MatcherSpec) v2MatcherResolver {
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
		m, ok := d.(*parser.V2MatcherDecl)
		if !ok {
			continue
		}
		spec := v2MatcherSpecFromDecl(m)
		local, fq := parser.V2DeclNames(prog.Module, m)
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

func (r v2PatternResolver) resolve(name string) (*parser.V2PatternDecl, bool, error) {
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

func lowerV2Binding(b *parser.V2BindingDecl, names parser.V2Names, patterns v2PatternResolver, matchers v2MatcherResolver, mechanics parser.V2Context) ([]Action, error) {
	if b.Query.Expr != nil && strings.HasPrefix(b.Query.Expr.Family, "unstable.") {
		return nil, fmt.Errorf("binding %s: unsupported unstable query family %q; migrate to stable v2", b.Name, b.Query.Expr.Family)
	}
	if b.Query.Expr != nil && b.Query.Expr.Family == "param" {
		return lowerV2ParamSourceBinding(b, names)
	}
	// Every branch below either assigns queryWhere or returns an error.
	var queryWhere parser.V2Expr
	queryAlias := ""
	queryNodeType := ""
	queryFamily := ""
	if b.Query.Expr != nil {
		queryFamily = parser.V2NormalizedCodeFamily(b.Query.Expr.Family)
		nodeType, ok := v2QueryFamilyNodeType(queryFamily)
		if !ok {
			if schema, staged := parser.V2SchemaGatedCodeFamilies[queryFamily]; staged {
				return nil, fmt.Errorf("binding %s: query family %q requires native runtime schema(%q, \"2.0\") lowering before it can be used in production definitions", b.Name, b.Query.Expr.Family, schema)
			}
			return nil, fmt.Errorf("binding %s: inline query lowering is not implemented for query family %q", b.Name, b.Query.Expr.Family)
		}
		queryNodeType = nodeType
		var err error
		queryWhere, err = lowerV2BindingQueryRelations(b.Name, *b.Query.Expr)
		if err != nil {
			return nil, err
		}
		queryAlias = b.Query.Expr.Alias
		queryWhere = addV2FamilyImplicitPredicates(queryWhere, queryFamily)
	} else if b.Query.Pattern == "" {
		return nil, fmt.Errorf("binding %s: missing query", b.Name)
	} else {
		var err error
		queryWhere, queryAlias, queryNodeType, queryFamily, err = lowerV2PatternQuery(b.Name, b.Query, patterns)
		if err != nil {
			return nil, err
		}
	}
	if queryAlias == "node" {
		if out, ok, err := lowerV2PresenceBinding(b, names, queryWhere, queryAlias, matchers, mechanics); ok || err != nil {
			return out, err
		}
	}
	shapes, err := lowerV2CallShapes(b.Name, queryWhere, queryNodeType != "", queryFamily)
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
	var out []Action
	for _, shape := range shapes {
		for _, action := range b.Outputs {
			action.Concept = names.Concept(action.Concept)
			action.About = names.Concept(action.About)
			if queryAlias != "" && queryAlias != "call" && queryAlias != "node" && action.Location == queryAlias {
				action.Location = "node"
			}
			if err := validateV2OutputCoverageMechanics(b.Name, action, mechanics); err != nil {
				return nil, err
			}
			switch {
			case action.Kind == "emit source":
				m := shape.mapping(Action{Kind: shape.sourceKind(), Pattern: shape.Pattern, Concept: action.Concept, Constraint: shape.Constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = appendV2BindingAction(out, m, b.Attrs)
			case action.Kind == "emit sink":
				if action.Location == "call" || action.Location == "node" {
					m := shape.mapping(Action{Kind: shape.sinkNodeKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
					out = appendV2BindingAction(out, m, b.Attrs)
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
				m := shape.mapping(Action{
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
				out = appendV2BindingAction(out, m, b.Attrs)
			case action.Kind == "emit check":
				if isV2AdvisoryNeutralizerCheck(action) {
					m, ok, err := lowerV2AdvisoryNeutralizerCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					if ok {
						out = appendV2BindingAction(out, m, b.Attrs)
						continue
					}
				}
				if action.Advisory != nil && *action.Advisory {
					m, err := lowerV2AdvisoryCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					out = appendV2BindingAction(out, m, b.Attrs)
					continue
				}
				if mechanics.ConceptHasRole(action.Concept, "char_filter") {
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
					out = appendV2BindingAction(out, shape.mapping(Action{Kind: kind, Pattern: shape.Pattern, Concept: action.Concept, Constraint: constraint, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req}), b.Attrs)
					continue
				}
				if isV2GlobalCheck(action) {
					m, err := lowerV2GlobalCheck(b.Name, shape, action, pkgs, req)
					if err != nil {
						return nil, err
					}
					out = appendV2BindingAction(out, m, b.Attrs)
					continue
				}
				kind := shape.checkKind()
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
					kind = "check_receiver_method"
				} else {
					if err := validateV2ConcreteCheck(b.Name, action); err != nil {
						return nil, err
					}
				}
				loc, hasArgTarget, err := v2CheckArgTarget(action.Location)
				if err != nil {
					return nil, fmt.Errorf("binding %s: %w", b.Name, err)
				}
				m := shape.mapping(Action{Kind: kind, Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, Coverage: action.Covers[0].Mode, CoverageDetail: lowerV2CoverageDetail(action.Covers[0]), ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				if hasArgTarget {
					if shape.Field == "callee.method" {
						m.Kind = "check_method_arg"
					} else {
						m.Kind = "check_arg"
					}
					m.ArgIndex = loc.ArgIndex
					m.Collection = loc.Collection
					m.CollectionFirst = loc.CollectionFirst
					m.CollectionIndex = loc.CollectionIndex
				}
				out = appendV2BindingAction(out, m, b.Attrs)
			case action.Kind == "emit issue":
				m := shape.mapping(Action{Kind: shape.issueKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req})
				out = appendV2BindingAction(out, m, b.Attrs)
			case action.Kind == "emit fact":
				m, err := lowerV2FactEmit(b.Name, shape, action, pkgs, req)
				if err != nil {
					return nil, err
				}
				out = appendV2BindingAction(out, m, b.Attrs)
			case strings.HasPrefix(action.Kind, "propagate "):
				m, err := lowerV2Propagation(b.Name, shape, queryAlias, action, pkgs, req)
				if err != nil {
					return nil, err
				}
				out = appendV2BindingAction(out, m, b.Attrs)
			default:
				return nil, fmt.Errorf("binding %s: unsupported output %q", b.Name, action.Kind)
			}
		}
	}
	return out, nil
}

func lowerV2BindingQueryRelations(binding string, q parser.V2QueryExpr) (parser.V2Expr, error) {
	where := q.Where
	for _, step := range q.Steps {
		rewritten, err := lowerV2BindingQueryRelation(binding, step)
		if err != nil {
			return nil, err
		}
		where = andV2Expr(where, rewritten)
	}
	return where, nil
}

func v2QueryFamilyNodeType(family string) (string, bool) {
	switch family {
	case "call":
		return "", true
	case "assignment":
		return "", true
	case "memberAccess":
		return "code.Attr", true
	case "binaryExpr":
		return "code.BinOp", true
	case "literal", "stringLiteral":
		return "code.Literal", true
	case "function":
		return "code.Function", true
	case "class":
		return "code.Class", true
	case "import":
		return "code.Import", true
	default:
		return "", false
	}
}

func addV2FamilyImplicitPredicates(expr parser.V2Expr, family string) parser.V2Expr {
	switch family {
	case "assignment":
		return andV2Expr(v2AssignmentImplicitExpr(), expr)
	default:
		return expr
	}
}

func v2AssignmentImplicitExpr() parser.V2Expr {
	return parser.V2BinaryExpr{Op: "and",
		Left:  parser.V2BinaryExpr{Op: "==", Left: parser.V2RefExpr{Name: "callee.analysis"}, Right: parser.V2LiteralExpr{Value: "function.context"}},
		Right: parser.V2BinaryExpr{Op: "contains", Left: parser.V2RefExpr{Name: "assignment.any"}, Right: parser.V2LiteralExpr{Value: ""}},
	}
}

func lowerV2BindingQueryRelation(binding string, step parser.V2QueryStep) (parser.V2Expr, error) {
	if (step.Relation == "references" || step.Relation == "sameScope" || step.Relation == "declaredIn" || step.Relation == "contains" || step.Relation == "encloses") &&
		parser.V2NormalizedCodeFamily(step.Family) == "call" && step.Alias != "" && step.Where != nil {
		rewritten, err := rewriteV2BindingRelationRefs(step.Where, step.Alias)
		if err != nil {
			return nil, fmt.Errorf("binding %s: %w", binding, err)
		}
		return rewritten, nil
	}
	if (step.Relation != "encloses" && step.Relation != "contains") || !parser.V2LiteralRelationFamily(step.Family) || step.Alias == "" || step.Where == nil {
		return nil, fmt.Errorf("binding %s: query relation step %s %s needs native production v2 lowering", binding, step.Relation, step.Family)
	}
	rewritten, err := rewriteV2BindingRelationRefs(step.Where, step.Alias)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", binding, err)
	}
	return rewritten, nil
}

func rewriteV2BindingRelationRefs(expr parser.V2Expr, alias string) (parser.V2Expr, error) {
	switch x := expr.(type) {
	case nil:
		return nil, nil
	case parser.V2RefExpr:
		head, rest, ok := strings.Cut(x.Name, ".")
		if ok && head == alias {
			switch rest {
			case "callee.method":
				return parser.V2RefExpr{Name: "scope.call.method"}, nil
			case "callee.path":
				return parser.V2RefExpr{Name: "scope.call.path"}, nil
			case "value", "raw", "literal":
				return parser.V2RefExpr{Name: "args.any.literal"}, nil
			default:
				return nil, fmt.Errorf("relation field %q needs native production v2 lowering", rest)
			}
		}
		return x, nil
	case parser.V2UnaryExpr:
		rewritten, err := rewriteV2BindingRelationRefs(x.X, alias)
		if err != nil {
			return nil, err
		}
		x.X = rewritten
		return x, nil
	case parser.V2BinaryExpr:
		left, err := rewriteV2BindingRelationRefs(x.Left, alias)
		if err != nil {
			return nil, err
		}
		right, err := rewriteV2BindingRelationRefs(x.Right, alias)
		if err != nil {
			return nil, err
		}
		x.Left = left
		x.Right = right
		return x, nil
	case parser.V2CallExpr:
		for i := range x.Args {
			rewritten, err := rewriteV2BindingRelationRefs(x.Args[i], alias)
			if err != nil {
				return nil, err
			}
			x.Args[i] = rewritten
		}
		for i := range x.NamedArgs {
			rewritten, err := rewriteV2BindingRelationRefs(x.NamedArgs[i].Expr, alias)
			if err != nil {
				return nil, err
			}
			x.NamedArgs[i].Expr = rewritten
		}
		return x, nil
	case parser.V2SequenceExpr:
		for i := range x.Items {
			rewritten, err := rewriteV2BindingRelationRefs(x.Items[i], alias)
			if err != nil {
				return nil, err
			}
			x.Items[i] = rewritten
		}
		return x, nil
	default:
		return x, nil
	}
}

func lowerV2FactEmit(binding string, shape v2CallShape, action parser.V2BindingOutput, pkgs []string, req *Requirement) (Action, error) {
	if action.Location == "call.result" && action.About != "" {
		return shape.mapping(Action{Kind: "type", Pattern: shape.Pattern, Concept: action.About, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req}), nil
	}
	if action.About != "" {
		return Action{}, fmt.Errorf("binding %s: emit fact about metadata is only supported for call.result receiver-type facts", binding)
	}
	if action.Location == "call" || action.Location == "node" {
		return shape.mapping(Action{Kind: shape.factKind(), Pattern: shape.Pattern, Exact: shape.Exact, Concept: action.Concept, ValMatches: shape.ValMatches, ValAbsents: shape.ValAbsents, Packages: pkgs, Requirement: req}), nil
	}
	loc, err := v2SinkLocationParts(action.Location)
	if err != nil {
		return Action{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	kind := "fact_arg"
	if shape.Field == "callee.method" {
		kind = "fact_method_arg"
	}
	return shape.mapping(Action{
		Kind:            kind,
		Pattern:         shape.Pattern,
		Exact:           shape.Exact,
		Concept:         action.Concept,
		ArgIndex:        loc.ArgIndex,
		ValMatches:      shape.ValMatches,
		ValAbsents:      shape.ValAbsents,
		Collection:      loc.Collection,
		CollectionFirst: loc.CollectionFirst,
		CollectionIndex: loc.CollectionIndex,
		Packages:        pkgs,
		Requirement:     req,
	}), nil
}

func appendV2BindingAction(out []Action, m Action, attrs map[string]string) []Action {
	if attrs != nil {
		m.Fidelity = attrs["fidelity"]
		m.Confidence = attrs["confidence"]
	}
	return append(out, m)
}

func isV2GlobalCheck(action parser.V2BindingOutput) bool {
	return len(action.Covers) == 1 && action.Covers[0].Mode == "global"
}

func isV2AdvisoryNeutralizerCheck(action parser.V2BindingOutput) bool {
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

func lowerV2GlobalCheck(binding string, shape v2CallShape, action parser.V2BindingOutput, pkgs []string, req *Requirement) (Action, error) {
	if action.About != "" {
		return Action{}, fmt.Errorf("binding %s: global check about metadata is only supported on advisory checks", binding)
	}
	loc, hasArgTarget, err := v2CheckArgTarget(action.Location)
	if err != nil {
		return Action{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	out := shape.mapping(Action{
		Kind:           shape.checkKind(),
		Pattern:        shape.Pattern,
		Exact:          shape.Exact,
		Concept:        action.Concept,
		Coverage:       "global",
		CoverageDetail: lowerV2CoverageDetail(action.Covers[0]),
		ValMatches:     shape.ValMatches,
		ValAbsents:     shape.ValAbsents,
		Packages:       pkgs,
		Requirement:    req,
	})
	if hasArgTarget {
		if shape.Field == "callee.method" {
			out.Kind = "check_method_arg"
		} else {
			out.Kind = "check_arg"
		}
		out.ArgIndex = loc.ArgIndex
		out.Collection = loc.Collection
		out.CollectionFirst = loc.CollectionFirst
		out.CollectionIndex = loc.CollectionIndex
	}
	return out, nil
}

func lowerV2AdvisoryCheck(binding string, shape v2CallShape, action parser.V2BindingOutput, pkgs []string, req *Requirement) (Action, error) {
	if len(action.Covers) != 1 {
		return Action{}, fmt.Errorf("binding %s: advisory check requires exactly one coverage mode", binding)
	}
	kind := shape.checkKind()
	loc, hasArgTarget, err := v2CheckArgTarget(action.Location)
	if err != nil {
		return Action{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	out := shape.mapping(Action{
		Kind:           kind,
		Pattern:        shape.Pattern,
		Exact:          shape.Exact,
		Concept:        action.Concept,
		About:          action.About,
		Advisory:       true,
		Coverage:       action.Covers[0].Mode,
		CoverageDetail: lowerV2CoverageDetail(action.Covers[0]),
		ValMatches:     shape.ValMatches,
		ValAbsents:     shape.ValAbsents,
		Packages:       pkgs,
		Requirement:    req,
	})
	if hasArgTarget {
		if shape.Field == "callee.method" {
			out.Kind = "check_method_arg"
		} else {
			out.Kind = "check_arg"
		}
		out.ArgIndex = loc.ArgIndex
		out.Collection = loc.Collection
		out.CollectionFirst = loc.CollectionFirst
		out.CollectionIndex = loc.CollectionIndex
	}
	return out, nil
}

// deriveV2ContentGate picks the most distinctive literal that MUST occur for a presence flag to
// match: the longest identifier-like value of a positive, literal-matching predicate (its
// structured prefix — call_path:/literal:/name=/… — stripped, since only the post-prefix part is
// matched against real node text). Returns "" when no such literal exists, leaving the binding
// ungated. Identifier-like (letters/digits/_/.-, reasonably long) guarantees the literal occurs
// verbatim in node text, so a whole-program absence check against it is sound.
func deriveV2ContentGate(fl *Presence) string {
	if fl == nil {
		return ""
	}
	best := ""
	for _, p := range fl.Predicates {
		if p.Negative || !v2ContentGateableOp(p.Op) {
			continue
		}
		for _, v := range p.Values {
			needle := v
			if i := strings.IndexAny(v, ":="); i > 0 {
				needle = v[i+1:]
			}
			if v2IdentifierLikeLiteral(needle) && len(needle) > len(best) {
				best = needle
			}
		}
	}
	return best
}

func v2ContentGateableOp(op string) bool {
	switch op {
	case "contains", "contains_any", "equals", "equals_any", "starts_with", "ends_with":
		return true
	default:
		return false
	}
}

func v2IdentifierLikeLiteral(s string) bool {
	if len(s) < 6 { // short tokens are rarely distinctive enough to gate usefully
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

func andV2Expr(left, right parser.V2Expr) parser.V2Expr {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return parser.V2BinaryExpr{Op: "and", Left: left, Right: right}
}

func lowerV2ParamSourceBinding(b *parser.V2BindingDecl, names parser.V2Names) ([]Action, error) {
	if b.Query.Expr.Alias != "param" || b.Query.Expr.Where != nil || len(b.Query.Expr.Steps) != 0 {
		return nil, fmt.Errorf("binding %s: param source lowering requires query param as param", b.Name)
	}
	pkgs, req, err := lowerV2Requirements(b.Requirements)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	var out []Action
	for _, action := range b.Outputs {
		action.Concept = names.Concept(action.Concept)
		if action.Kind != "emit source" || action.Location != "param" {
			return nil, fmt.Errorf("binding %s: param query only supports emit source at param", b.Name)
		}
		out = appendV2BindingAction(out, Action{Kind: "source_param", Concept: action.Concept, Packages: pkgs, Requirement: req}, b.Attrs)
	}
	return out, nil
}

func flattenV2And(expr parser.V2Expr) []parser.V2Expr {
	var out []parser.V2Expr
	flattenV2AndInto(expr, &out)
	return out
}

func flattenV2AndInto(expr parser.V2Expr, out *[]parser.V2Expr) {
	if b, ok := expr.(parser.V2BinaryExpr); ok && b.Op == "and" {
		flattenV2AndInto(b.Left, out)
		flattenV2AndInto(b.Right, out)
		return
	}
	*out = append(*out, expr)
}

func v2MatcherRef(expr parser.V2Expr) (string, bool) {
	ref, ok := expr.(parser.V2RefExpr)
	if !ok || ref.Name == "" {
		return "", false
	}
	return ref.Name, true
}

func v2LiteralInt(expr parser.V2Expr) (int, bool) {
	lit, ok := expr.(parser.V2LiteralExpr)
	if !ok {
		return 0, false
	}
	n, ok := lit.Value.(int)
	return n, ok && n >= 0
}

func v2LiteralIntList(expr parser.V2Expr) ([]int, bool) {
	lit, ok := expr.(parser.V2LiteralExpr)
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

func lowerV2CoverageDetail(cov parser.V2Coverage) map[string]string {
	if len(cov.Items) == 0 {
		return nil
	}
	out := make(map[string]string, len(cov.Items))
	for k, v := range cov.Items {
		s, ok := v2CoverageItemString(v)
		if ok && s != "" {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func v2CoverageItemString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case []string:
		return strings.Join(x, ","), true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.Itoa(x), true
	case parser.V2LiteralExpr:
		return v2CoverageItemString(x.Value)
	default:
		return "", false
	}
}

func validateV2ConcreteCheck(binding string, action parser.V2BindingOutput) error {
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

func validateV2OutputCoverageMechanics(binding string, action parser.V2BindingOutput, mechanics parser.V2Context) error {
	for _, cov := range action.Covers {
		if cov.Mode == "" {
			continue
		}
		if !mechanics.HasCoverageMode(cov.Mode) {
			return fmt.Errorf("binding %s: no loaded mechanic coverage %q", binding, cov.Mode)
		}
	}
	return nil
}

func validateV2PathOnlyCheck(binding string, action parser.V2BindingOutput) error {
	if err := validateV2ConcreteCheck(binding, action); err != nil {
		return err
	}
	if action.Covers[0].Mode != "path" {
		return fmt.Errorf("binding %s: this check only supports path coverage", binding)
	}
	return nil
}

func v2CheckArgTarget(location string) (v2SinkLocationInfo, bool, error) {
	switch location {
	case "call", "node", "callee.receiver":
		return v2SinkLocationInfo{}, false, nil
	default:
		loc, err := v2SinkLocationParts(location)
		if err != nil {
			return v2SinkLocationInfo{}, false, err
		}
		return loc, true, nil
	}
}

func lowerV2AdvisoryNeutralizerCheck(binding string, shape v2CallShape, action parser.V2BindingOutput, pkgs []string, req *Requirement) (Action, bool, error) {
	advisory := action.Advisory != nil && *action.Advisory
	if !advisory || action.About == "" {
		return Action{}, false, nil
	}
	if action.Location != "call" {
		return Action{}, true, fmt.Errorf("binding %s: advisory neutralizer check must be emitted at call", binding)
	}
	if len(action.Covers) != 1 {
		return Action{}, true, fmt.Errorf("binding %s: advisory neutralizer check requires exactly one coverage mode", binding)
	}
	mode := ""
	switch action.Covers[0].Mode {
	case "dominates":
		mode = "guard"
	case "path":
		mode = "sanitizer"
	default:
		return Action{}, true, fmt.Errorf("binding %s: unsupported advisory neutralizer coverage mode %q", binding, action.Covers[0].Mode)
	}
	kind := "advisory_" + mode + "_path"
	if shape.Field == "callee.method" {
		kind = "advisory_" + mode + "_method"
	}
	return shape.mapping(Action{
		Kind:           kind,
		Pattern:        shape.Pattern,
		About:          action.About,
		Coverage:       action.Covers[0].Mode,
		CoverageDetail: lowerV2CoverageDetail(action.Covers[0]),
		ValMatches:     shape.ValMatches,
		ValAbsents:     shape.ValAbsents,
		Packages:       pkgs,
		Requirement:    req,
	}), true, nil
}

func lowerV2CharFilterGlobal(expr parser.V2Expr) bool {
	for _, atom := range flattenV2And(expr) {
		cmp, ok := atom.(parser.V2BinaryExpr)
		if !ok || cmp.Op != "==" {
			continue
		}
		left, ok := cmp.Left.(parser.V2RefExpr)
		if !ok || left.Name != "call.filter.global" {
			continue
		}
		lit, ok := cmp.Right.(parser.V2LiteralExpr)
		if !ok {
			continue
		}
		v, ok := lit.Value.(bool)
		return ok && v
	}
	return false
}

func (s v2CallShape) mapping(m Action) Action {
	m.NodeType = s.NodeType
	if s.ArgCountSet {
		m.ArgCountSet = true
		m.ArgCountMin = s.ArgCountMin
		m.ArgCountMax = s.ArgCountMax
	}
	m.ScopePredicates = append(m.ScopePredicates, s.ScopePreds...)
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

func (s v2CallShape) sinkNodeKind() string {
	if s.Field == "callee.method" {
		return "sink_method_node"
	}
	return "sink_node"
}

func (s v2CallShape) checkKind() string {
	if s.Field == "callee.method" {
		return "check_method"
	}
	return "check"
}

func (s v2CallShape) issueKind() string {
	if s.Field == "callee.method" {
		return "issue_method"
	}
	return "issue"
}

func (s v2CallShape) factKind() string {
	if s.Field == "callee.method" {
		return "fact_method"
	}
	return "fact"
}

// A strings.Replacer builds a lookup trie on first use, so constructing one inside the
// function rebuilds and discards that trie on every call. Hoisted to build it once.
var v2BinaryOperatorNameReplacer = strings.NewReplacer(".", "_", "/", "div", "%", "mod", "*", "mul", "+", "add", "-", "sub")

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
	return v2BinaryOperatorNameReplacer.Replace(op)
}

func lowerV2ReceiverConstraint(cmp parser.V2BinaryExpr) (string, bool) {
	switch cmp.Op {
	case "==":
		lit, ok := cmp.Right.(parser.V2LiteralExpr)
		if !ok {
			return "", false
		}
		s, ok := lit.Value.(string)
		return s, ok
	case "in":
		values, ok := parser.V2RuleWhereStringList(cmp.Right)
		if !ok {
			return "", false
		}
		return strings.Join(values, ","), true
	default:
		return "", false
	}
}

func lowerV2Propagation(binding string, shape v2CallShape, queryAlias string, action parser.V2BindingOutput, pkgs []string, req *Requirement) (Action, error) {
	if action.Kind != "propagate value" && action.Kind != "propagate taint" && action.Kind != "propagate identity" && action.Kind != "propagate receiver" {
		return Action{}, fmt.Errorf("binding %s: unsupported propagation kind %q", binding, action.Kind)
	}
	kind := "flow_path"
	if shape.Field == "callee.method" {
		kind = "flow_method"
	}
	if action.Kind == "propagate receiver" {
		if err := v2PropagationReceiverLocations(v2NormalizeQueryLocation(action.From, queryAlias), v2NormalizeQueryLocation(action.To, queryAlias)); err != nil {
			return Action{}, fmt.Errorf("binding %s: %w", binding, err)
		}
		return shape.mapping(Action{
			Kind:         kind,
			Pattern:      shape.Pattern,
			FlowReceiver: true,
			Packages:     pkgs,
			Requirement:  req,
		}), nil
	}
	dest, err := v2PropagationDestArg(v2NormalizeQueryLocation(action.To, queryAlias))
	if err != nil {
		return Action{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	srcArg, srcResult, err := v2PropagationSource(v2NormalizeQueryLocation(action.From, queryAlias))
	if err != nil {
		return Action{}, fmt.Errorf("binding %s: %w", binding, err)
	}
	return shape.mapping(Action{
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

func lowerV2Requirements(reqs []parser.V2Requirement) ([]string, *Requirement, error) {
	if len(reqs) == 0 {
		return nil, nil, nil
	}
	var req Requirement
	var err error
	if len(reqs) == 1 {
		req, err = lowerV2Requirement(reqs[0])
	} else {
		req.Op = "all"
		req.Args = make([]Requirement, 0, len(reqs))
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

func lowerV2Requirement(req parser.V2Requirement) (Requirement, error) {
	switch req.Name {
	case "all", "any":
		if len(req.Args) == 0 {
			return Requirement{}, fmt.Errorf("%s requirement needs at least one child", req.Name)
		}
		out := Requirement{Op: req.Name, Args: make([]Requirement, 0, len(req.Args))}
		for _, raw := range req.Args {
			child, ok := raw.(parser.V2Requirement)
			if !ok {
				return Requirement{}, fmt.Errorf("%s requirement needs child requirements", req.Name)
			}
			lowered, err := lowerV2Requirement(child)
			if err != nil {
				return Requirement{}, err
			}
			out.Args = append(out.Args, lowered)
		}
		return out, nil
	case "not", "soft":
		if len(req.Args) != 1 {
			return Requirement{}, fmt.Errorf("%s requirement needs exactly one child", req.Name)
		}
		child, ok := req.Args[0].(parser.V2Requirement)
		if !ok {
			return Requirement{}, fmt.Errorf("%s requirement needs a child requirement", req.Name)
		}
		lowered, err := lowerV2Requirement(child)
		if err != nil {
			return Requirement{}, err
		}
		return Requirement{Op: req.Name, Args: []Requirement{lowered}}, nil
	case "dependency", "import", "language", "file", "framework", "schema", "project.has", "content":
		return lowerV2PrimitiveRequirement(req)
	default:
		return Requirement{}, fmt.Errorf("requirement %s needs native v2 requirement evaluation", req.Name)
	}
}

func lowerV2PrimitiveRequirement(req parser.V2Requirement) (Requirement, error) {
	values := make([]string, 0, len(req.Args))
	rangeValue := ""
	for _, raw := range req.Args {
		switch arg := raw.(type) {
		case string:
			if arg != "" {
				values = append(values, arg)
			}
		case parser.V2NamedArg:
			if req.Name == "dependency" && arg.Name == "range" {
				s, ok := arg.Value.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return Requirement{}, fmt.Errorf("dependency range requires a non-empty string")
				}
				rangeValue = strings.TrimSpace(s)
				continue
			}
			return Requirement{}, fmt.Errorf("%s requirement named arg %q needs native v2 requirement evaluation", req.Name, arg.Name)
		default:
			return Requirement{}, fmt.Errorf("%s requirement expects string arguments", req.Name)
		}
	}
	if len(values) == 0 {
		return Requirement{}, fmt.Errorf("%s requirement requires at least one string argument", req.Name)
	}
	if req.Name != "schema" && len(values) != 1 {
		return Requirement{}, fmt.Errorf("%s requirement requires exactly one string argument", req.Name)
	}
	return Requirement{Op: req.Name, Value: strings.Join(values, "\x00"), Range: rangeValue}, nil
}

func v2RequirementPackageHints(req Requirement) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(Requirement)
	walk = func(r Requirement) {
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

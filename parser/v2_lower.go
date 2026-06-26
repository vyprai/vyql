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

// LowerV2ToRuntime lowers v2 declarations into the current runtime structs.
// It is a migration bridge: authored syntax is v2, while scanner internals are
// converted incrementally behind this boundary.
func LowerV2ToRuntime(prog *V2Program) ([]Decl, error) {
	var out []Decl
	adaptersByTech := map[string]*AdapterDecl{}
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *V2ConceptDecl:
			out = append(out, &ConceptDecl{Name: x.Name, Package: x.Module, Kind: x.Kind, Fields: x.Fields})
		case *V2ThreatDecl:
			out = append(out, &ThreatDecl{Name: x.Name, Package: x.Module, Fields: x.Fields})
		case *V2ReviewDecl:
			out = append(out, &ReviewDecl{Concept: x.Concept, Fields: x.Fields})
		case *V2ProfileDecl:
			out = append(out, &ProfileDecl{Name: x.Name, Fields: x.Fields})
		case *V2BindingDecl:
			tech := v2BindingTechnology(x.Module)
			if tech == "" {
				return nil, fmt.Errorf("binding %s: cannot infer technology from module %q", x.Name, x.Module)
			}
			ad := adaptersByTech[tech]
			if ad == nil {
				ad = &AdapterDecl{Name: tech, Meta: map[string]any{}}
				adaptersByTech[tech] = ad
				out = append(out, ad)
			}
			maps, err := lowerV2Binding(x)
			if err != nil {
				return nil, err
			}
			ad.Mappings = append(ad.Mappings, maps...)
		case *V2RuleDecl:
			r, err := lowerV2Rule(x)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func v2BindingTechnology(module string) string {
	parts := strings.Split(module, ".")
	for i, p := range parts {
		if p == "bindings" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func lowerV2Binding(b *V2BindingDecl) ([]AdapterMapping, error) {
	if b.Query.Pattern == "" {
		return nil, fmt.Errorf("binding %s: inline query lowering is not implemented yet", b.Name)
	}
	shape, err := lowerV2CallShape(b.Name, b.Query.Where)
	if err != nil {
		return nil, err
	}
	pkgs := lowerV2RequirementsToPackages(b.Requirements)
	var out []AdapterMapping
	for _, action := range b.Outputs {
		switch {
		case action.Kind == "emit source":
			m := AdapterMapping{Kind: shape.sourceKind(), Pattern: shape.Pattern, Concept: action.Concept, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit sink":
			arg, err := v2ArgIndex(action.Location)
			if err != nil {
				return nil, fmt.Errorf("binding %s: %w", b.Name, err)
			}
			m := AdapterMapping{Kind: shape.sinkKind(), Pattern: shape.Pattern, Concept: action.Concept, ArgIndex: arg, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit check":
			if err := validateLegacyPathCheck(b.Name, action); err != nil {
				return nil, err
			}
			m := AdapterMapping{Kind: shape.controlKind(), Pattern: shape.Pattern, Concept: action.Concept, Packages: pkgs}
			out = append(out, m)
		case action.Kind == "emit issue":
			m := AdapterMapping{Kind: shape.markKind(), Pattern: shape.Pattern, Concept: action.Concept, Packages: pkgs}
			out = append(out, m)
		case strings.HasPrefix(action.Kind, "propagate "):
			return nil, fmt.Errorf("binding %s: propagate lowering is not implemented yet", b.Name)
		default:
			return nil, fmt.Errorf("binding %s: unsupported output %q", b.Name, action.Kind)
		}
	}
	return out, nil
}

func validateLegacyPathCheck(binding string, action V2BindingOutput) error {
	if action.Advisory != nil && *action.Advisory {
		return fmt.Errorf("binding %s: advisory checks require native v2 coverage support", binding)
	}
	if action.About != "" {
		return fmt.Errorf("binding %s: check about metadata requires native v2 coverage support", binding)
	}
	if len(action.Covers) != 1 || action.Covers[0].Mode != "path" {
		return fmt.Errorf("binding %s: only path-covered checks can lower to the legacy runtime", binding)
	}
	return nil
}

type v2CallShape struct {
	Field   string
	Pattern string
}

func (s v2CallShape) sourceKind() string {
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
	cmp, ok := expr.(V2BinaryExpr)
	if !ok {
		return v2CallShape{}, fmt.Errorf("binding %s: query pattern lowering needs a callee.method/path predicate", binding)
	}
	if cmp.Op != "==" && cmp.Op != "~=" {
		if shape, err := lowerV2CallShape(binding, cmp.Left); err == nil {
			return shape, nil
		}
		if shape, err := lowerV2CallShape(binding, cmp.Right); err == nil {
			return shape, nil
		}
		return v2CallShape{}, fmt.Errorf("binding %s: query pattern lowering needs a callee.method/path predicate", binding)
	}
	left, ok := cmp.Left.(V2RefExpr)
	if !ok {
		if shape, err := lowerV2CallShape(binding, cmp.Left); err == nil {
			return shape, nil
		}
		return v2CallShape{}, fmt.Errorf("binding %s: query predicate left side must be a field reference", binding)
	}
	lit, ok := cmp.Right.(V2LiteralExpr)
	if !ok {
		return v2CallShape{}, fmt.Errorf("binding %s: query predicate right side must be a literal", binding)
	}
	pat, ok := lit.Value.(string)
	if !ok {
		return v2CallShape{}, fmt.Errorf("binding %s: query predicate right side must be a string", binding)
	}
	switch left.Name {
	case "callee.method", "call.callee.method":
		return v2CallShape{Field: "callee.method", Pattern: pat}, nil
	case "callee.path", "call.callee.path":
		return v2CallShape{Field: "callee.path", Pattern: pat}, nil
	default:
		return v2CallShape{}, fmt.Errorf("binding %s: unsupported query predicate %q", binding, left.Name)
	}
}

func lowerV2RequirementsToPackages(reqs []V2Requirement) []string {
	var out []string
	var visit func(V2Requirement)
	visit = func(r V2Requirement) {
		if r.Name == "dependency" && len(r.Args) > 0 {
			if s, ok := r.Args[0].(string); ok {
				out = append(out, s)
			}
		}
		for _, arg := range r.Args {
			if child, ok := arg.(V2Requirement); ok {
				visit(child)
			}
		}
	}
	for _, req := range reqs {
		visit(req)
	}
	return out
}

func v2ArgIndex(location string) (int, error) {
	if !strings.HasPrefix(location, "args[") || !strings.HasSuffix(location, "]") {
		return 0, fmt.Errorf("sink/check location %q is not an args[N] location", location)
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(location, "args["), "]"))
	if err != nil {
		return 0, fmt.Errorf("invalid argument index in %q", location)
	}
	return n, nil
}

func lowerV2Rule(r *V2RuleDecl) (*Rule, error) {
	out := &Rule{Name: r.Name, Package: r.Module, Meta: r.Meta}
	switch r.Body.Verb {
	case "taint", "flow", "reach":
		out.Body = &FlowStmt{
			Verb: r.Body.Verb,
			Src:  Endpoint{Concept: r.Body.From.Concept, Binding: r.Body.From.Alias},
			Dst:  Endpoint{Concept: r.Body.To.Concept, Binding: r.Body.To.Alias},
		}
	case "grant":
		out.Body = &FlowStmt{
			Verb: "assume",
			Src:  Endpoint{Concept: r.Body.From.Concept, Binding: r.Body.From.Alias},
			Dst:  Endpoint{Concept: r.Body.To.Concept, Binding: r.Body.To.Alias},
		}
	case "issue", "fact":
		out.Body = &MatchStmt{TargetKind: "concept", Concept: r.Body.Issue.Concept, Binding: r.Body.Issue.Alias}
	default:
		return nil, fmt.Errorf("rule %s: unsupported v2 rule body %q", r.Name, r.Body.Verb)
	}
	for _, cl := range r.Clauses {
		switch cl.Kind {
		case "unless":
			if cl.Coverage != "path" {
				return nil, fmt.Errorf("rule %s: %s coveredBy requires native v2 coverage support", r.Name, cl.Coverage)
			}
			out.Clauses = append(out.Clauses, Clause{Kind: "unless", Unless: SanitizedBy{Concept: cl.Concept}})
		case "where":
			return nil, fmt.Errorf("rule %s: where lowering is not implemented yet", r.Name)
		case "with", "require":
			return nil, fmt.Errorf("rule %s: %s lowering is not implemented yet", r.Name, cl.Kind)
		}
	}
	return out, nil
}

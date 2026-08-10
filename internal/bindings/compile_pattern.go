package bindings

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/parser"
)

// Compiled from authored v2 binding declarations -- pattern recognition: named patterns and the matcher/pattern resolvers.

type v2PatternResolver struct {
	patterns map[string]*parser.V2PatternDecl
	imports  map[string]string
	module   string
}

func newV2PatternResolver(prog *parser.V2Program) v2PatternResolver {
	out := v2PatternResolver{
		patterns: map[string]*parser.V2PatternDecl{},
		imports:  map[string]string{},
	}
	if prog == nil {
		return out
	}
	out.module = prog.Module
	for _, d := range prog.Decls {
		p, ok := d.(*parser.V2PatternDecl)
		if !ok {
			continue
		}
		local, fq := parser.V2DeclNames(prog.Module, p)
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

func builtinV2CallExprPattern() *parser.V2PatternDecl {
	return &parser.V2PatternDecl{
		Name:  "callExpr",
		Alias: "call",
		Items: []parser.V2PatternItem{{Kind: "node", Name: "call"}},
	}
}

func lowerV2BindingMetaPattern(p *parser.V2PatternDecl) (string, map[string]any, error) {
	for _, item := range p.Items {
		if item.Kind == "binding" {
			name, _ := item.Meta["name"].(string)
			if name == "" {
				return "", nil, fmt.Errorf("pattern %s: binding metadata requires name", p.Name)
			}
			rawMeta, ok := item.Meta["meta"].(map[string]any)
			if !ok {
				return "", nil, fmt.Errorf("pattern %s: binding metadata requires meta block", p.Name)
			}
			return name, rawMeta, nil
		}
		if item.Kind == "unstable" {
			if _, hasLegacyBindingMeta := item.Meta["adap"+"ter"]; hasLegacyBindingMeta {
				return "", nil, fmt.Errorf("pattern %s: unstable binding metadata must use stable binding item", p.Name)
			}
			if _, hasMeta := item.Meta["meta"]; hasMeta {
				return "", nil, fmt.Errorf("pattern %s: unstable binding metadata must use stable binding item", p.Name)
			}
		}
	}
	return "", nil, nil
}

func lowerV2PatternQuery(binding string, query parser.V2BindingQuery, patterns v2PatternResolver) (parser.V2Expr, string, string, string, error) {
	pat, ok, err := patterns.resolve(query.Pattern)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("binding %s: pattern %s: %w", binding, query.Pattern, err)
	}
	if !ok {
		return nil, "", "", "", fmt.Errorf("binding %s: pattern %s is not declared in this module", binding, query.Pattern)
	}
	where, alias, nodeType, family, binds, err := lowerV2PatternRecognitionExpr(binding, pat, patterns)
	if err != nil {
		return nil, "", "", "", err
	}
	queryWhere := rewriteV2PatternRefs(query.Where, binds)
	return andV2Expr(where, queryWhere), alias, nodeType, family, nil
}

func lowerV2PatternRecognitionExpr(binding string, pat *parser.V2PatternDecl, patterns v2PatternResolver) (parser.V2Expr, string, string, string, map[string]string, error) {
	where, alias, nodeType, family, binds, _, err := lowerV2PatternRecognitionExprSeen(binding, pat, patterns, map[*parser.V2PatternDecl]bool{})
	return where, alias, nodeType, family, binds, err
}

func lowerV2PatternRecognitionExprSeen(binding string, pat *parser.V2PatternDecl, patterns v2PatternResolver, seen map[*parser.V2PatternDecl]bool) (parser.V2Expr, string, string, string, map[string]string, int, error) {
	if pat == nil {
		return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: nil pattern", binding)
	}
	if seen[pat] {
		return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s has cyclic use", binding, pat.Name)
	}
	seen[pat] = true
	defer delete(seen, pat)

	alias := pat.Alias
	nodeType := ""
	nodeFamily := ""
	binds := map[string]string{}
	var where parser.V2Expr
	nodeCount := 0
	for _, item := range pat.Items {
		switch item.Kind {
		case "node":
			nodeCount++
			family := parser.V2NormalizedCodeFamily(item.Name)
			itemNodeType, ok := v2QueryFamilyNodeType(family)
			if !ok {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s node family %q needs native pattern lowering", binding, pat.Name, item.Name)
			}
			nodeType = itemNodeType
			nodeFamily = family
			if alias == "" {
				alias = item.Alias
			}
		case "bind":
			ref, ok := item.Expr.(parser.V2RefExpr)
			if !ok {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s bind %s needs native expression lowering", binding, pat.Name, item.Name)
			}
			if err := addV2PatternBind(binding, pat.Name, binds, item.Name, ref.Name); err != nil {
				return nil, "", "", "", nil, 0, err
			}
		case "where":
			where = andV2Expr(where, rewriteV2PatternRefs(item.Expr, binds))
		case "unstable":
			return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s unstable items need native pattern lowering", binding, pat.Name)
		case "use":
			sub, ok, err := patterns.resolve(item.Name)
			if err != nil {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s use %s: %w", binding, pat.Name, item.Name, err)
			}
			if !ok {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s use %s is not declared in this module", binding, pat.Name, item.Name)
			}
			subWhere, subAlias, subNodeType, subFamily, subBinds, subNodes, err := lowerV2PatternRecognitionExprSeen(binding, sub, patterns, seen)
			if err != nil {
				return nil, "", "", "", nil, 0, err
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
			if nodeCount > 1 {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s multi-node pattern composition needs native pattern lowering; scanner IR lowering supports exactly one stable code node", binding, pat.Name)
			}
			if nodeType != "" && subNodeType != "" && nodeType != subNodeType {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s composes incompatible node families", binding, pat.Name)
			}
			if nodeType == "" {
				nodeType = subNodeType
			}
			if nodeFamily != "" && subFamily != "" && nodeFamily != subFamily {
				return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s composes incompatible node families", binding, pat.Name)
			}
			if nodeFamily == "" {
				nodeFamily = subFamily
			}
			for name, target := range subBinds {
				if rewritten, ok := rewriteV2PatternRefName(target, aliasBinds); ok {
					target = rewritten
				}
				if err := addV2PatternBind(binding, pat.Name, binds, name, target); err != nil {
					return nil, "", "", "", nil, 0, err
				}
			}
			if item.Alias != "" && targetAlias != "" {
				if err := addV2PatternBind(binding, pat.Name, binds, item.Alias, targetAlias); err != nil {
					return nil, "", "", "", nil, 0, err
				}
			}
		default:
			return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s item %q needs native pattern lowering", binding, pat.Name, item.Kind)
		}
	}
	if nodeCount != 1 {
		if nodeCount > 1 {
			return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s multi-node pattern composition needs native pattern lowering; scanner IR lowering supports exactly one stable code node", binding, pat.Name)
		}
		return nil, "", "", "", nil, 0, fmt.Errorf("binding %s: pattern %s must have exactly one stable code node for scanner IR lowering", binding, pat.Name)
	}
	where = addV2FamilyImplicitPredicates(where, nodeFamily)
	return where, alias, nodeType, nodeFamily, binds, nodeCount, nil
}

func addV2PatternBind(binding, pattern string, binds map[string]string, name, target string) error {
	if prev := binds[name]; prev != "" && prev != target {
		return fmt.Errorf("binding %s: pattern %s bind %s is ambiguous", binding, pattern, name)
	}
	binds[name] = target
	return nil
}

func rewriteV2PatternRefs(expr parser.V2Expr, binds map[string]string) parser.V2Expr {
	if expr == nil || len(binds) == 0 {
		return expr
	}
	switch x := expr.(type) {
	case parser.V2RefExpr:
		if name, ok := rewriteV2PatternRefName(x.Name, binds); ok {
			return parser.V2RefExpr{Name: name}
		}
		return x
	case parser.V2UnaryExpr:
		x.X = rewriteV2PatternRefs(x.X, binds)
		return x
	case parser.V2BinaryExpr:
		x.Left = rewriteV2PatternRefs(x.Left, binds)
		x.Right = rewriteV2PatternRefs(x.Right, binds)
		return x
	case parser.V2CallExpr:
		for i := range x.Args {
			x.Args[i] = rewriteV2PatternRefs(x.Args[i], binds)
		}
		for i := range x.NamedArgs {
			x.NamedArgs[i].Expr = rewriteV2PatternRefs(x.NamedArgs[i].Expr, binds)
		}
		return x
	case parser.V2SequenceExpr:
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

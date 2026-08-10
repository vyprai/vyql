package engine

import (
	"strings"

	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
)

// BindingConcepts is the demand analysis behind binding pruning: the set of concepts the
// active rules can actually reach, so the binding layer can skip labelling anything no rule
// asks about.
//
// It walks rule syntax -- exception kinds, solver calls, where-expressions -- which is this
// package's vocabulary, and it ran in the CLI. Being wrong here is not a slow scan but a
// silent one: a concept missed is a binding pruned is a finding that never appears, which is
// why the exhaustiveness of the switches below is pinned by a test rather than left to review.
func BindingConcepts(onto *ontology.Ontology, compiled []*CompiledRule, profileName string) map[string]bool {
	out := map[string]bool{}
	add := func(concept string) {
		if strings.TrimSpace(concept) == "" {
			return
		}
		out[concept] = true
		for c := range onto.Descendants(concept) {
			out[c] = true
		}
	}
	var addExpr func(parser.Expr)
	addException := func(ex parser.Exception) {
		switch x := ex.(type) {
		case parser.PathCoveredBy:
			add(x.Concept)
		case parser.EndpointCoveredBy:
			add(x.Concept)
		case parser.SameReceiverCoveredBy:
			add(x.Concept)
		case parser.SameScopeCoveredBy:
			add(x.Concept)
		case parser.GlobalCoveredBy:
			add(x.Concept)
		case parser.DominatesCoveredBy:
			add(x.Concept)
		case parser.PostDominatesCoveredBy:
			add(x.Concept)
		case parser.ExprException:
			addExpr(x.Expr)
		}
	}
	addExpr = func(expr parser.Expr) {
		switch x := expr.(type) {
		case parser.And:
			for _, part := range x.Parts {
				addExpr(part)
			}
		case parser.Or:
			for _, part := range x.Parts {
				addExpr(part)
			}
		case parser.Not:
			addExpr(x.Inner)
		case parser.SolverCall:
			for _, arg := range x.Args {
				add(arg.Ref.String())
			}
		case parser.HoldsAssetKind:
			add(x.Ref.String())
		case parser.Is:
			add(x.Concept)
			add(x.Ref.String())
		}
	}
	for _, cr := range compiled {
		if !RuleActiveForProfile(cr, profileName) {
			continue
		}
		switch body := cr.Rule.Body.(type) {
		case *parser.FlowStmt:
			add(body.Src.Concept)
			add(body.Dst.Concept)
			for c := range cr.SourceConcepts {
				add(c)
			}
			for c := range cr.SinkConcepts {
				add(c)
			}
			for c := range cr.KillControls {
				add(c)
			}
		case *parser.MatchStmt:
			add(body.Concept)
			add(body.RelatedConcept)
		case *parser.OrderStmt:
			add(body.First.Concept)
			add(body.Second.Concept)
		}
		for _, cl := range cr.Rule.Clauses {
			if cl.Kind == "where" {
				addExpr(cl.Where)
			}
			if cl.Kind == "unless" {
				addException(cl.Unless)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RuleActiveForProfile reports whether the rule runs under the named profile. A rule with no
// required_profiles runs everywhere, and an empty profile name runs everything.
func RuleActiveForProfile(cr *CompiledRule, profileName string) bool {
	if cr == nil || cr.Rule == nil {
		return false
	}
	required := stringListMeta(cr.Rule.Meta["required_profiles"])
	if len(required) == 0 || profileName == "" {
		return true
	}
	for _, name := range required {
		if name == profileName {
			return true
		}
	}
	return false
}

func stringListMeta(raw any) []string {
	switch xs := raw.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if xs == "" {
			return nil
		}
		return []string{xs}
	default:
		return nil
	}
}

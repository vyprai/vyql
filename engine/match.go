package engine

import (
	"strconv"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/solvers"
)

// evalMatch evaluates concept/transition match rules with v2 where and coveredBy clauses.
// Composes solver calls in `where` through the engine.
func (e *Engine) evalMatch(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.MatchStmt)
	if body.TargetKind == "transition" {
		return e.evalTransition(cr)
	}
	candidates := e.nodesWithConcept(body.Concept)

	var where parser.Expr
	var guards, dominanceGuards, postDominanceGuards, sameReceiverGuards, sameScopeGuards, globalGuards []string
	for _, cl := range cr.Rule.Clauses {
		switch cl.Kind {
		case "where":
			where = mergeWhere(where, cl.Where)
		case "unless":
			switch ex := cl.Unless.(type) {
			case parser.EndpointCoveredBy:
				guards = append(guards, ex.Concept)
			case parser.DominatesCoveredBy:
				dominanceGuards = append(dominanceGuards, ex.Concept)
			case parser.PostDominatesCoveredBy:
				postDominanceGuards = append(postDominanceGuards, ex.Concept)
			case parser.SameReceiverCoveredBy:
				sameReceiverGuards = append(sameReceiverGuards, ex.Concept)
			case parser.SameScopeCoveredBy:
				sameScopeGuards = append(sameScopeGuards, ex.Concept)
			case parser.GlobalCoveredBy:
				globalGuards = append(globalGuards, ex.Concept)
			}
		}
	}

	var out []*findings.Finding
	for _, node := range candidates {
		if !e.matchRelationSatisfied(body, node) {
			continue
		}
		env := map[string]string{body.Binding: node}
		ctx := []string{}
		if where != nil {
			ok, witnesses := e.evalWhere(where, env)
			if !ok {
				continue
			}
			ctx = witnesses
		}
		suppressed := false
		var ne []findings.NegationEvidence
		for _, g := range guards {
			ok := e.endpointGuarded(node, g)
			ne = append(ne, findings.NegationEvidence{Clause: "endpoint coveredBy " + g, Satisfied: ok})
			suppressed = suppressed || ok
		}
		for _, g := range dominanceGuards {
			ok := e.dominatesGuarded(node, g)
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("dominates", g), Satisfied: ok})
			suppressed = suppressed || ok
		}
		for _, g := range postDominanceGuards {
			ok := e.postDominatesCovered(node, g)
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("postDominates", g), Satisfied: ok})
			suppressed = suppressed || ok
		}
		for _, g := range sameReceiverGuards {
			ok := e.sameReceiverGuarded(node, g)
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("sameReceiver", g), Satisfied: ok})
			suppressed = suppressed || ok
		}
		for _, g := range sameScopeGuards {
			ok := e.sameScopeGuarded(node, g)
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("sameScope", g), Satisfied: ok})
			suppressed = suppressed || ok
		}
		for _, g := range globalGuards {
			ok := e.globalGuarded(g)
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("global", g), Satisfied: ok})
			suppressed = suppressed || ok
		}
		if suppressed {
			continue
		}
		out = append(out, &findings.Finding{
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "match",
			NegationEvidence: ne, Confidence: e.confConcept(node, body.Concept), Context: ctx,
			ReviewConditions: e.reviewConditions(node, body.Concept),
			Bindings: []findings.Binding{
				{Name: body.Binding, NodeID: node, Concept: body.Concept, Loc: e.loc(node), LabelProvenance: e.prov(node, body.Concept)},
			},
		})
	}
	return out, nil
}

func v2CoverageClause(part, concept string) string {
	return part + " coveredBy " + concept
}

func (e *Engine) matchRelationSatisfied(body *parser.MatchStmt, node string) bool {
	switch body.Relation {
	case "":
		return true
	case "labeledAs":
		return body.RelatedConcept != "" && e.nodeHasConcept(node, body.RelatedConcept)
	case "references":
		if body.RelatedConcept == "" || body.RelationProp == "" {
			return false
		}
		n, ok, _ := e.Store.GetNode(node)
		if !ok {
			return false
		}
		target := n.Prop(body.RelationProp)
		return target != "" && e.nodeHasConcept(target, body.RelatedConcept)
	default:
		return false
	}
}

// evalTransition evaluates `match transition F -> T on M as t unless <expr>`.
func (e *Engine) evalTransition(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.MatchStmt)
	nodes, _ := e.Store.NodesOfType("analysis.Transition")
	var out []*findings.Finding
	for _, id := range nodes {
		n, _, _ := e.Store.GetNode(id)
		if n.Prop("machine") != body.Machine || n.Prop("to") != body.ToState {
			continue
		}
		if body.FromState != "*" && n.Prop("from") != body.FromState {
			continue
		}
		env := map[string]string{body.Binding: id}
		suppressed := false
		var ne []findings.NegationEvidence
		for _, cl := range cr.Rule.Clauses {
			if cl.Kind != "unless" {
				continue
			}
			if ex, ok := cl.Unless.(parser.ExprException); ok {
				okk, _ := e.evalWhere(ex.Expr, env)
				ne = append(ne, findings.NegationEvidence{Clause: "expr guard", Satisfied: okk, Detail: "from=" + n.Prop("from")})
				suppressed = suppressed || okk
			}
		}
		if suppressed {
			continue
		}
		out = append(out, &findings.Finding{
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "match",
			NegationEvidence: ne, Confidence: "high",
			Bindings: []findings.Binding{
				{Name: body.Binding, NodeID: id, Concept: "transition", Loc: n.Prop("from") + "->" + n.Prop("to")},
			},
		})
	}
	return out, nil
}

// --- where-expression evaluator -----------------------------------------

func (e *Engine) evalWhere(expr parser.Expr, env map[string]string) (bool, []string) {
	var witnesses []string
	for _, atom := range flattenAnd(expr) {
		ok, w := e.evalAtom(atom, env)
		if !ok {
			return false, nil
		}
		witnesses = append(witnesses, w...)
	}
	return true, witnesses
}

func (e *Engine) evalAtom(atom parser.Expr, env map[string]string) (bool, []string) {
	switch a := atom.(type) {
	case parser.Not:
		ok, _ := e.evalAtom(a.Inner, env)
		return !ok, nil
	case parser.And:
		return e.evalWhere(a, env)
	case parser.Or:
		var witnesses []string
		for _, part := range flattenOr(a) {
			ok, w := e.evalAtom(part, env)
			if ok {
				witnesses = append(witnesses, w...)
				return true, witnesses
			}
		}
		return false, nil
	case parser.SolverCall:
		return e.evalSolverCall(a, env)
	case parser.HoldsAssetKind:
		id := e.resolveRef(a.Ref, env)
		req := map[string]bool{}
		for _, k := range a.Kinds {
			req[k] = true
		}
		return id != "" && intersect(e.assetKinds(id), req), nil
	case parser.Is:
		return e.resolveScalar(a.Ref, env) == a.Concept, nil
	case parser.NotIn:
		val := e.resolveScalar(a.Ref, env)
		in := false
		for _, v := range a.Values {
			if v == val {
				in = true
				break
			}
		}
		if a.Negate {
			return !in, nil // `not in` holds when the value is absent (drift)
		}
		return in, nil
	case parser.Cmp:
		return e.evalCmp(a, env), nil
	case parser.Ref:
		return e.resolveRef(a, env) != "", nil
	}
	return false, nil
}

func (e *Engine) evalCmp(cmp parser.Cmp, env map[string]string) bool {
	val := e.resolveScalar(cmp.Ref, env)
	switch want := cmp.Value.(type) {
	case int:
		got, err := strconv.Atoi(val)
		if err != nil {
			return false
		}
		switch cmp.Op {
		case "==":
			return got == want
		case "!=":
			return got != want
		case ">=":
			return got >= want
		case "<=":
			return got <= want
		case ">":
			return got > want
		case "<":
			return got < want
		default:
			return false
		}
	case string:
		switch cmp.Op {
		case "==":
			return val == want
		case "!=":
			return val != want
		default:
			return false
		}
	default:
		return false
	}
}

func (e *Engine) evalSolverCall(call parser.SolverCall, env map[string]string) (bool, []string) {
	if len(call.Args) < 2 {
		return false, nil
	}
	aIDs := e.resolveArg(call.Args[0], env)
	switch call.Verb {
	case "reach":
		bIDs := e.resolveArg(call.Args[1], env)
		paths, _ := solvers.FindReach(e.Store, aIDs, bIDs, nil)
		if len(paths) > 0 {
			var w []string
			for _, h := range paths[0].Hops {
				w = append(w, "reach "+h.From+"->"+h.To+" via "+h.Rule)
			}
			return true, w
		}
	case "grant":
		bConcept := call.Args[1].Ref.String()
		bIDs := e.resolveArg(call.Args[1], env)
		paths, _ := solvers.FindAssume(e.Store, aIDs, bIDs, e.grantMinLevel(bConcept))
		if len(paths) > 0 {
			var w []string
			for _, s := range paths[0].Steps {
				w = append(w, call.Verb+" "+s.From+"->"+s.To+" ["+s.Ability+"]")
			}
			return true, w
		}
	case "dominates":
		bIDs := e.resolveArg(call.Args[1], env)
		for _, a := range aIDs {
			for _, b := range bIDs {
				if solvers.Dominates(e.Store, a, b) {
					return true, []string{"dominates " + a + " -> " + b}
				}
			}
		}
	}
	return false, nil
}

// resolveArg resolves a solver-call argument to node ids: a qualified concept
// expands to its labeled nodes; a binding ref resolves to a single node.
func (e *Engine) resolveArg(arg parser.Arg, env map[string]string) []string {
	if e.Onto.Exists(arg.Ref.String()) {
		return e.nodesWithConcept(arg.Ref.String())
	}
	if id := e.resolveRef(arg.Ref, env); id != "" {
		return []string{id}
	}
	return nil
}

// resolveRef resolves a dotted ref to a node id (binding head, then property
// hops that yield node ids, e.g. w.workload).
func (e *Engine) resolveRef(ref parser.Ref, env map[string]string) string {
	head := ref.Parts[0]
	id := env[head]
	if id == "" && e.Onto.Exists(ref.String()) {
		if ids := e.nodesWithConcept(ref.String()); len(ids) > 0 {
			return ids[0]
		}
		return ""
	}
	if id == "" {
		return ""
	}
	for _, part := range ref.Parts[1:] {
		n, ok, _ := e.Store.GetNode(id)
		if !ok {
			return ""
		}
		v := n.Prop(part)
		if _, exists, _ := e.Store.GetNode(v); exists {
			id = v
		} else {
			return ""
		}
	}
	return id
}

// resolveScalar resolves a ref to a scalar value (binding head + a property).
func (e *Engine) resolveScalar(ref parser.Ref, env map[string]string) string {
	head := ref.Parts[0]
	id := env[head]
	if id == "" {
		return ""
	}
	if len(ref.Parts) == 1 {
		return id
	}
	if n, ok, _ := e.Store.GetNode(id); ok {
		return n.Prop(ref.Parts[1])
	}
	return ""
}

func (e *Engine) nodeHasConcept(nodeID, concept string) bool {
	for _, l := range e.labels(nodeID) {
		if l.Concept == concept {
			return true
		}
	}
	return false
}

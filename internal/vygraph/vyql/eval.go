package vyql

import (
	"fmt"

	"github.com/vyprai/vyql/internal/vygraph/deviate"
	"github.com/vyprai/vyql/internal/vygraph/engine"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/solver"
	"github.com/vyprai/vyql/internal/vygraph/solvers/cfg"
)

// Run evaluates the program against the store: queries first (stratum by
// stratum, positive recursion to a least fixpoint), then rules in stratum
// order, so a negated predicate is always fully computed before anything
// negates it. Output is canonically ordered — a pure function of (graph,
// knowledge).
func (p *Program) Run(g *graph.Store, reg SolverRegistry) (*Output, error) {
	sets := map[string]map[string]bool{}
	for _, stratum := range p.Strata {
		if err := p.evalStratum(g, stratum, sets); err != nil {
			return nil, err
		}
	}
	out := &Output{}
	for _, r := range p.Rules {
		if err := p.evalRule(g, r, reg, sets, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// evalStratum evaluates every query named in the stratum, iterating to a least
// fixpoint when the stratum contains positive recursion.
func (p *Program) evalStratum(g *graph.Store, names []string, sets map[string]map[string]bool) error {
	changed := true
	for round := 0; changed && round < 1000; round++ {
		changed = false
		for _, name := range names {
			q, ok := p.queryByName(name)
			if !ok {
				continue // discharge relations and rules are not queries
			}
			next, err := p.evalQuery(g, q, sets)
			if err != nil {
				return err
			}
			cur := sets[name]
			if cur == nil {
				cur = map[string]bool{}
				sets[name] = cur
			}
			for n := range next {
				if !cur[n] {
					cur[n] = true
					changed = true
				}
			}
		}
	}
	return nil
}

func (p *Program) queryByName(name string) (*QueryDecl, bool) {
	q, ok := p.Queries[name]
	return q, ok
}

// evalQuery yields the node bindings of the query's yielded variable.
func (p *Program) evalQuery(g *graph.Store, q *QueryDecl, sets map[string]map[string]bool) (map[string]bool, error) {
	out := map[string]bool{}
	bodies := append([]RuleBody{q.Body}, q.Alts...)
	for _, b := range bodies {
		bindings, err := p.evalMatch(g, b, sets)
		if err != nil {
			return nil, err
		}
		for _, bind := range bindings {
			if id, ok := bind[b.Yield]; ok {
				out[id] = true
			}
		}
	}
	return out, nil
}

// binding maps pattern variables to node ids.
type binding map[string]string

// evalMatch binds a body's patterns against the store and filters by where.
// Each pattern is evaluated independently; cross-pattern variable sharing is a
// Phase 2 join concern (the 1b grammar's comma patterns bind disjoint vars).
func (p *Program) evalMatch(g *graph.Store, b RuleBody, sets map[string]map[string]bool) ([]binding, error) {
	var out []binding
	for _, pat := range b.Match {
		cand, err := p.bindPattern(g, pat)
		if err != nil {
			return nil, err
		}
		for _, bind := range cand {
			if b.Where == nil {
				out = append(out, bind)
				continue
			}
			ok, err := p.evalWhere(g, b.Where, bind, sets)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, bind)
			}
		}
	}
	return out, nil
}

// bindPattern walks a node-edge-node chain: candidates for the head node, then
// for each edge the successors (or predecessors, for a reverse edge) connected
// by that stored edge type.
func (p *Program) bindPattern(g *graph.Store, pat Pattern) ([]binding, error) {
	out := []binding{{}}
	for idx, node := range pat.Nodes {
		var next []binding
		for _, bind := range out {
			if idx > 0 {
				edge := pat.Edges[idx-1]
				prev := bind[pat.Nodes[idx-1].Var]
				for _, to := range connectedNodes(g, prev, edge) {
					if p.nodeMatches(g, node, to) {
						next = append(next, cloneBind(bind, node, to))
					}
				}
				continue
			}
			for _, id := range p.candidatesFor(g, node, bind) {
				next = append(next, cloneBind(bind, node, id))
			}
		}
		out = next
	}
	return out, nil
}

func cloneBind(b binding, n NodePattern, id string) binding {
	nb := binding{}
	for k, v := range b {
		nb[k] = v
	}
	if n.Var != "" {
		nb[n.Var] = id
	}
	return nb
}

// candidatesFor returns nodes matching a pattern head: by node type, or by
// concept label through the ontology's refines lattice.
func (p *Program) candidatesFor(g *graph.Store, n NodePattern, bind binding) []string {
	var out []string
	if _, isType := g.SchemaOf(n.TypeOrConcept); isType {
		for _, node := range g.NodesOfType(n.TypeOrConcept) {
			if p.constsHold(node, n.Fields) {
				out = append(out, node.ID)
			}
		}
		return out
	}
	for _, node := range g.NodesOfLayer(graph.LayerLow) {
		if p.labelledAs(g, node.ID, n.TypeOrConcept) && p.constsHold(node, n.Fields) {
			out = append(out, node.ID)
		}
	}
	for _, node := range g.NodesOfLayer(graph.LayerHigh) {
		if p.labelledAs(g, node.ID, n.TypeOrConcept) && p.constsHold(node, n.Fields) {
			out = append(out, node.ID)
		}
	}
	return out
}

func (p *Program) nodeMatches(g *graph.Store, n NodePattern, id string) bool {
	node, ok := g.Node(id)
	if !ok {
		return false
	}
	if ts, isType := g.SchemaOf(n.TypeOrConcept); isType {
		return ts.Type == node.Type && p.constsHold(node, n.Fields)
	}
	return p.labelledAs(g, id, n.TypeOrConcept) && p.constsHold(node, n.Fields)
}

func (p *Program) labelledAs(g *graph.Store, id, concept string) bool {
	for _, l := range g.LabelsOn(id) {
		if p.KB.Onto.IsA(l.Concept, concept) {
			return true
		}
	}
	return false
}

func (p *Program) constsHold(n graph.Node, consts []FieldConst) bool {
	for _, c := range consts {
		want, err := literalValue(c.Literal)
		if err != nil {
			return false
		}
		got, ok := n.Fields.Get(c.Name)
		if !ok || got.Kind != want.Kind || got.S != want.S || got.I != want.I || got.B != want.B {
			return false
		}
	}
	return true
}

func literalValue(e Expr) (graph.Value, error) {
	lit, ok := e.(*Literal)
	if !ok {
		return graph.Value{}, fmt.Errorf("field constant must be a literal")
	}
	switch lit.Kind {
	case TokString:
		return graph.Str(unquote(lit.Text)), nil
	case TokNumber:
		var i int64
		if _, err := fmt.Sscanf(lit.Text, "%d", &i); err != nil {
			return graph.Value{}, err
		}
		return graph.Int(i), nil
	case TokBool:
		return graph.Bool(lit.Text == "true"), nil
	}
	return graph.Value{}, fmt.Errorf("unsupported literal kind")
}

func connectedNodes(g *graph.Store, id string, e EdgePattern) []string {
	if e.Reverse {
		return reverseConnected(g, id, e.Type)
	}
	var out []string
	for _, edge := range g.Out(id, e.Type) {
		out = append(out, edge.To)
	}
	return out
}

// reverseConnected finds nodes whose outgoing edge of the type points at id.
func reverseConnected(g *graph.Store, id, edgeType string) []string {
	var out []string
	for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
		for _, n := range g.NodesOfLayer(layer) {
			for _, e := range g.Out(n.ID, edgeType) {
				if e.To == id {
					out = append(out, n.ID)
					break
				}
			}
		}
	}
	return out
}

// evalWhere evaluates a where clause under a variable binding, including query
// calls (membership in an already-computed set; `not` inverts).
func (p *Program) evalWhere(g *graph.Store, e Expr, bind binding, sets map[string]map[string]bool) (bool, error) {
	switch x := e.(type) {
	case *Call:
		set := sets[x.Name]
		if len(x.Args) != 1 {
			return false, fmt.Errorf("query call %q takes one node argument", x.Name)
		}
		id, ok := boundArg(x.Args[0], bind)
		if !ok {
			return false, nil
		}
		return set[id], nil
	case *Not:
		v, err := p.evalWhere(g, x.X, bind, sets)
		return !v, err
	case *BinOp:
		if x.Op == "and" || x.Op == "or" {
			l, err := p.evalWhere(g, x.L, bind, sets)
			if err != nil {
				return false, err
			}
			if x.Op == "and" && !l {
				return false, nil
			}
			if x.Op == "or" && l {
				return true, nil
			}
			return p.evalWhere(g, x.R, bind, sets)
		}
		if x.Op == "has" {
			id, ok := boundArg(x.L, bind)
			if !ok {
				return false, nil
			}
			concept := ""
			switch r := x.R.(type) {
			case *Name:
				concept = r.Name
			case *FieldRef:
				concept = joinDotted(r.Var, r.Fields)
			}
			return p.labelledAs(g, id, concept), nil
		}
		nodes := map[string]graph.Node{}
		for v, id := range bind {
			if n, ok := g.Node(id); ok {
				nodes[v] = n
			}
		}
		l, err := evalOperandBindings(g, x.L, nodes)
		if err != nil {
			return false, err
		}
		r, err := evalOperandBindings(g, x.R, nodes)
		if err != nil {
			return false, err
		}
		return compareValues(g, nodes[""], x.Op, l, r)
	}
	return false, fmt.Errorf("where clause is not boolean")
}

func boundArg(e Expr, bind binding) (string, bool) {
	switch x := e.(type) {
	case *FieldRef:
		if len(x.Fields) == 0 {
			if id, ok := bind[x.Var]; ok {
				return id, true
			}
		}
	case *Name:
		if id, ok := bind[x.Name]; ok {
			return id, true
		}
	}
	return "", false
}

// evalOperandBindings resolves operands against a variable→node binding.
func evalOperandBindings(g *graph.Store, e Expr, nodes map[string]graph.Node) (graph.Value, error) {
	switch x := e.(type) {
	case *Literal:
		return literalValue(x)
	case *Name:
		return graph.Str(x.Name), nil
	case *FieldRef:
		if len(x.Fields) != 1 {
			return graph.Value{}, fmt.Errorf("nested field chains are not evaluable in 1b")
		}
		n, ok := nodes[x.Var]
		if !ok {
			return graph.Value{}, fmt.Errorf("variable %q is not bound", x.Var)
		}
		v, has := n.Fields.Get(x.Fields[0])
		if !has {
			return graph.Value{}, fmt.Errorf("node %s has no field %q", n.ID, x.Fields[0])
		}
		return v, nil
	}
	return graph.Value{}, fmt.Errorf("unsupported operand")
}

// evalRule evaluates one rule into the output streams.
func (p *Program) evalRule(g *graph.Store, r RuleDecl, reg SolverRegistry, sets map[string]map[string]bool, out *Output) error {
	conf := p.ruleConfidence(r)

	emit := func(res Result) {
		if res.Stream == EmitSignal {
			out.Signals = append(out.Signals, res)
		} else {
			out.Findings = append(out.Findings, res)
		}
	}

	b := r.Body
	switch {
	case b.Deviates != nil:
		// The deviation clause operates over the bound match set: partition by
		// the selector key, detect the guard-ish feature, emit signals for
		// outliers. Routing is by construction — the emit is signal-only.
		bindings, err := p.evalMatch(g, b, sets)
		if err != nil {
			return err
		}
		var members []string
		for _, bind := range bindings {
			for _, pat := range b.Match {
				if len(pat.Nodes) > 0 {
					if v := pat.Nodes[len(pat.Nodes)-1].Var; v != "" {
						members = append(members, bind[v])
					}
				}
			}
		}
		keyFn := p.selectorKey(g, b.Deviates.Selector)
		carryFn := p.featureCarrier(g, b.Deviates.Feature)
		for _, res := range deviate.Deviate(members, keyFn, carryFn,
			deviate.Params{MinGroup: b.Deviates.MinGroup, Threshold: b.Deviates.Threshold}) {
			emit(Result{RuleID: r.Meta.ID, Source: res.Source(), Target: res.Target(),
				Confidence: ladderFloat(ConfSignal), Stream: EmitSignal,
				Proof: solver.ProofTree(res)})
		}
	case b.Sugar != nil && b.Sugar.Verb == "present":
		for _, id := range engine.NodesWithConcept(g, p.KB.Onto, b.Sugar.From) {
			if b.Where != nil {
				node, _ := g.Node(id)
				ok, err := evalWhere(g, b.Where, node)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
			}
			emit(Result{RuleID: r.Meta.ID, Source: id, Target: id, Confidence: conf, Stream: b.Emit})
		}
	case b.Sugar != nil:
		s, ok := reg[b.Sugar.Verb]
		if !ok {
			return fmt.Errorf("rule %s: unregistered solver %q", r.Meta.ID, b.Sugar.Verb)
		}
		results, err := s.Solve(g, solver.Input{
			Sources: engine.NodesWithConcept(g, p.KB.Onto, b.Sugar.From),
			Targets: engine.NodesWithConcept(g, p.KB.Onto, b.Sugar.To),
		})
		if err != nil {
			return fmt.Errorf("rule %s: solver %s: %w", r.Meta.ID, b.Sugar.Verb, err)
		}
		// Dedup one per (rule, sink), keeping the first witness in the solver's
		// deterministic order — presentation only; recall is unchanged.
		seen := map[string]bool{}
		for _, res := range results {
			if seen[res.Target()] {
				continue
			}
			seen[res.Target()] = true
			proof := solver.ProofTree(res)
			if proof == nil {
				continue // no rebuildable witness ⇒ not a finding
			}
			if b.Unless != nil && p.discharge(g, proof, b.Unless) {
				continue
			}
			emit(Result{RuleID: r.Meta.ID, Source: res.Source(), Target: res.Target(),
				Confidence: p.flowConfidence(conf, g, res.Source(), res.Target()),
				Stream:     b.Emit, Proof: proof})
		}
	default:
		bindings, err := p.evalMatch(g, b, sets)
		if err != nil {
			return err
		}
		for _, bind := range bindings {
			first, last := r.Name, r.Name
			for _, pat := range b.Match {
				if len(pat.Nodes) == 0 {
					continue
				}
				if v := pat.Nodes[0].Var; v != "" {
					first = bind[v]
				}
				if v := pat.Nodes[len(pat.Nodes)-1].Var; v != "" {
					last = bind[v]
				}
				break
			}
			// The unless suppressor applies to match bodies exactly as to flow
			// bodies: a provable discharge (a guard dominating the matched op)
			// suppresses; unprovable means the finding survives.
			if b.Unless != nil {
				proof := &solver.Proof{Source: first, Target: last, Steps: []solver.Step{{From: first, To: last, Via: "match"}}}
				if p.discharge(g, proof, b.Unless) {
					continue
				}
			}
			emit(Result{RuleID: r.Meta.ID, Source: first, Target: last, Confidence: conf, Stream: b.Emit})
		}
	}
	return nil
}

// selectorKey builds the peer-group key function for a registered selector,
// computed over the lifted domain roles the graph already indexes (the frozen
// schema from the prototype run): the decorator class for
// same_annotation_class, the accessed table for same_model, the router role
// for same_router.
func (p *Program) selectorKey(g *graph.Store, selector string) func(string) string {
	switch selector {
	case "same_annotation_class":
		return func(id string) string {
			n, ok := g.Node(id)
			if !ok {
				return ""
			}
			// The member's backing FuncDef carries ParamEntries whose decorator
			// tokens name the annotation class.
			backed := n
			if b, has := g.Backing(id); has {
				backed = b
			}
			for _, e := range g.Out(backed.ID, "child") {
				c, ok := g.Node(e.To)
				if !ok || c.Type != "code.ParamEntry" {
					continue
				}
				if d, ok := c.Fields.Get("decorators"); ok && d.Kind == graph.KindList && len(d.L) > 0 {
					return d.L[0].S
				}
			}
			return ""
		}
	case "same_model":
		return func(id string) string {
			n, ok := g.Node(id)
			if !ok {
				return ""
			}
			backed := n
			if b, has := g.Backing(id); has {
				backed = b
			}
			tables := ""
			for _, e := range g.Out(backed.ID, "CALLS") {
				_ = e
			}
			// Functions touching the same table: key by the accessed table of
			// DataAccess nodes they anchor to (Phase 4 wires the anchor edge;
			// today the key comes from call-site table facts where present).
			for _, da := range g.NodesOfType("code.DataAccess") {
				if b, has := g.Backing(da.ID); has && b.ID == backed.ID {
					if t, ok := da.Fields.Get("table"); ok {
						tables += t.S + ","
					}
				}
			}
			return tables
		}
	case "same_router":
		return func(id string) string {
			n, ok := g.Node(id)
			if !ok {
				return ""
			}
			// The router role is the framework-registration parent: entrypoints
			// under one registration object share its receiver prefix.
			if b, has := g.Backing(id); has {
				if v, ok := b.Fields.Get("path"); ok && v.S != "" {
					segs := splitFirst(v.S)
					if segs != "" {
						return segs
					}
				}
			}
			if v, ok := n.Fields.Get("httpPath"); ok {
				return v.S
			}
			return ""
		}
	}
	return func(string) string { return "" }
}

func splitFirst(path string) string {
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			return path[:i]
		}
	}
	return ""
}

// featureCarrier builds the membership predicate: a node carries the feature
// when it — or its low backing, where adapter and hint labels land — is
// labelled with the concept through the ontology's refines lattice.
func (p *Program) featureCarrier(g *graph.Store, concept string) func(string) bool {
	return func(id string) bool {
		if p.labelledAs(g, id, concept) {
			return true
		}
		if b, has := g.Backing(id); has && p.labelledAs(g, b.ID, concept) {
			return true
		}
		return false
	}
}

// flowConfidence mins the rule-level confidence with the fidelity of the
// labels that armed the flow: a syntactic-only source caps the finding at
// medium — the ladder composes downward.
func (p *Program) flowConfidence(ruleConf float64, g *graph.Store, src, dst string) float64 {
	out := ruleConf
	for _, id := range []string{src, dst} {
		for _, l := range g.LabelsOn(id) {
			if l.Confidence < out {
				out = l.Confidence
			}
		}
	}
	return out
}

// ruleConfidence computes min(rule floor, 1.0), then capped by any validation
// cap (a low-level type reference clamps to medium).
func (p *Program) ruleConfidence(r RuleDecl) float64 {
	conf := 1.0
	if r.Meta.ConfidenceFloor != "" {
		if f, ok := ParseConfidence(r.Meta.ConfidenceFloor); ok {
			conf = ladderFloat(f)
		}
	}
	if capv, capped := p.KB.RuleCaps[r.Name]; capped {
		if cf := ladderFloat(capv); cf < conf {
			conf = cf
		}
	}
	return conf
}

// discharge decides an unless suppressor for one witness. Suppression requires
// PROOF: sanitized_by is provable in-band when a
// control carrying the concept sits on the witnessed flow; guarded_by and
// closed_by are decided by the cfg solver's dominance relations over the
// endpoints' backings; anchored needs anchors (Phase 4) and is therefore NOT
// provable here — the safe polarity keeps the finding.
func (p *Program) discharge(g *graph.Store, proof *solver.Proof, s *Suppressor) bool {
	switch s.Kind {
	case "sanitized_by":
		for _, step := range proof.Steps {
			if p.labelledAs(g, step.To, s.Concept) || p.labelledAs(g, step.From, s.Concept) {
				return true
			}
		}
		return false
	case "guarded_by":
		holds, _ := cfg.GuardDischarge(g, proof.Target, s.Concept, func(id string) bool {
			return p.labelledAs(g, id, s.Concept)
		})
		return holds
	case "closed_by":
		for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
			for _, n := range g.NodesOfLayer(layer) {
				if !p.labelledAs(g, n.ID, s.Concept) {
					continue
				}
				if holds, _, _ := cfg.PostDominates(g, n.ID, proof.Target); holds {
					return true
				}
			}
		}
		return false
	}
	return false // anchored: unprovable without Phase 4 anchors — finding survives
}

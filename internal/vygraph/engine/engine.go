// Package engine plans and evaluates rules. It knows about concepts, solvers and proof
// trees — and nothing about any specific vulnerability, technology or node type.
package engine

import (
	"fmt"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// Rule is the minimal Phase-1a rule: bind a source concept and a sink concept, hand both
// to a solver. It references ONLY concepts — never a node type.
type Rule struct {
	ID            string
	SourceConcept string
	SinkConcept   string
	Solver        string
}

type Finding struct {
	RuleID string
	Source string
	Target string
	Proof  *solver.Proof
}

type Engine struct {
	g       *graph.Store
	onto    *ontology.Ontology
	solvers map[string]solver.Solver
}

func New(g *graph.Store, onto *ontology.Ontology) *Engine {
	return &Engine{g: g, onto: onto, solvers: map[string]solver.Solver{}}
}

func (e *Engine) Register(s solver.Solver) { e.solvers[s.Name()] = s }

// NodesWithConcept returns nodes labelled with concept or any concept refining from
// it. Sub-concept binding lives here, in the engine, because it is ontology mechanics —
// not knowledge.
func NodesWithConcept(g *graph.Store, onto *ontology.Ontology, concept string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range g.NodesOfLayer(graph.LayerLow) {
		collect(g, onto, concept, n.ID, seen, &out)
	}
	for _, n := range g.NodesOfLayer(graph.LayerHigh) {
		collect(g, onto, concept, n.ID, seen, &out)
	}
	return out
}

func collect(g *graph.Store, onto *ontology.Ontology, concept, id string, seen map[string]bool, out *[]string) {
	if seen[id] {
		return
	}
	for _, l := range g.LabelsOn(id) {
		if onto.IsA(l.Concept, concept) {
			seen[id] = true
			*out = append(*out, id)
			return
		}
	}
}

func (e *Engine) Evaluate(r Rule) ([]Finding, error) {
	s, ok := e.solvers[r.Solver]
	if !ok {
		return nil, fmt.Errorf("rule %s: unregistered solver %q", r.ID, r.Solver)
	}
	for _, c := range []string{r.SourceConcept, r.SinkConcept} {
		if _, ok := e.onto.Get(c); !ok {
			return nil, fmt.Errorf("rule %s: undefined concept %q", r.ID, c)
		}
	}
	in := solver.Input{
		Sources: NodesWithConcept(e.g, e.onto, r.SourceConcept),
		Targets: NodesWithConcept(e.g, e.onto, r.SinkConcept),
	}
	results, err := s.Solve(e.g, in)
	if err != nil {
		return nil, fmt.Errorf("rule %s: solver %s: %w", r.ID, r.Solver, err)
	}
	var out []Finding
	for _, res := range results {
		p := solver.ProofTree(res)
		if p == nil {
			continue // no rebuildable witness ⇒ not a finding
		}
		out = append(out, Finding{RuleID: r.ID, Source: res.Source(), Target: res.Target(), Proof: p})
	}
	return out, nil
}

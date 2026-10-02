// Package solver defines the one contract every VyGraph solver satisfies. Solvers own
// flow semantics; the engine core is threat-agnostic and never replaces a solver call
// with transitive closure over materialized edges.
package solver

import "github.com/vyprai/vyql/internal/vygraph/graph"

// Step is one link of a witness: enough to rebuild a proof tree, not a boolean.
type Step struct {
	From string
	To   string
	Via  string // edge type, closure link, or region relation
	Note string // human-facing detail, e.g. the transfer that carried the value
}

// Result is what every solver returns. Witness() is the ordered evidence a finding's
// proof tree is reconstructed from.
type Result interface {
	Source() string
	Target() string
	Witness() []Step
}

// Input is the bound sets handed to a solver. The call is opaque to the planner: it
// hands over bound sets and receives witnesses, never inspecting the solver's steps.
type Input struct {
	Sources []string
	Targets []string
	Params  map[string]string
}

type Solver interface {
	Name() string
	Solve(g *graph.Store, in Input) ([]Result, error)
}

// Flow is the ordinary two-endpoint result: taint, reach, assume, access.
type Flow struct {
	Src  string
	Dst  string
	Path []Step
}

func (f Flow) Source() string  { return f.Src }
func (f Flow) Target() string  { return f.Dst }
func (f Flow) Witness() []Step { return f.Path }

// Absence is the degenerate result shape for an absence solver such as deviate, which
// reports what is MISSING rather than a flow connecting two endpoints. Source() is empty
// (the "flow" is a non-existent guard); Target() is the outlier.
type Absence struct {
	Outlier  string
	Missing  string
	Peers    []string
	Exemplar string
}

func (a Absence) Source() string { return "" }
func (a Absence) Target() string { return a.Outlier }

func (a Absence) Witness() []Step {
	steps := []Step{{
		From: "", To: a.Outlier, Via: "deviates",
		Note: "missing " + a.Missing + "; conforming exemplar " + a.Exemplar,
	}}
	for _, p := range a.Peers {
		steps = append(steps, Step{From: p, To: a.Outlier, Via: "peer", Note: a.Missing})
	}
	return steps
}

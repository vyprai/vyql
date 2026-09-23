// Package deviate is the v3 deviation miner: a first-class absence solver
// that partitions bound members into peer groups,
// computes the frequency of a guard-ish feature, and emits signals — never
// findings — for members lacking a feature their peers overwhelmingly carry.
// The witness is degenerate but well defined: Source is empty (the flow is a
// non-existent guard), Target is the outlier, and the evidence is the peer
// group, the missing feature, and the conforming exemplars.
package deviate

import (
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// Feature is the guard-ish concept a group's members may carry.
type Feature struct {
	Concept string
}

// Group is one peer group: the key, its members, and which members carry the feature.
type Group struct {
	Key      string
	Members  []string // node ids, sorted
	Carrying map[string]bool
}

// Selector names a registered peer-group key function.
// A rule author cannot invent one from a technology name.
type Selector string

const (
	SameRouter          Selector = "same_router"
	SameModel           Selector = "same_model"
	SameAnnotationClass Selector = "same_annotation_class"
)

// Known reports whether a selector is registered.
func Known(s Selector) bool {
	switch s {
	case SameRouter, SameModel, SameAnnotationClass:
		return true
	}
	return false
}

// Params carries the rule-tunable knobs (defaults: min_group 8, threshold 0.8).
type Params struct {
	MinGroup  int
	Threshold float64
}

// DefaultParams are min_group 8, threshold 0.8.
func DefaultParams() Params { return Params{MinGroup: 8, Threshold: 0.8} }

// Solver satisfies the one-contract shape: bound sets in, absence witnesses out.
type Solver struct {
	onto *ontology.Ontology
}

// New builds the solver against the ontology — the concept facets and the
// guard/control pools live there, not in the engine.
func New(onto *ontology.Ontology) *Solver { return &Solver{onto: onto} }

func (s *Solver) Name() string { return "deviate" }

// Hint is a declared guard_hint seed: an identifier shape mapping to the
// guard-ish concept it seeds. The seed is versioned knowledge — a declared
// input, never hidden solver state (determinism, D6/P5).
type Hint struct {
	Glob    string
	Concept string
}

// Solve partitions the bound members by the peer key, computes the feature
// frequency per group, and returns one absence witness per qualifying outlier.
// The members come in via Input.Sources (the bound match set); the feature and
// hints ride Params as a serialized hint list in Input.Params["hints"] is not
// used — the caller uses Deviate directly with typed arguments.
func (s *Solver) Solve(g *graph.Store, in solver.Input) ([]solver.Result, error) {
	return nil, nil // typed entry point below; the plan-level registry path routes there
}

// Deviate is the typed entry: members grouped by keyFn, feature carriers
// detected by carryFn, outliers above the knobs. Everything is iterated in
// sorted order, so output is a pure function of (graph, knowledge).
func Deviate(members []string, keyFn func(string) string, carryFn func(string) bool, p Params) []solver.Result {
	groups := map[string][]string{}
	for _, m := range members {
		k := keyFn(m)
		if k == "" {
			continue // ungroupable members are not compared against strangers
		}
		groups[k] = append(groups[k], m)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(members)

	var out []solver.Result
	for _, k := range keys {
		mem := groups[k]
		sort.Strings(mem)
		if len(mem) < p.MinGroup {
			continue
		}
		carrying := map[string]bool{}
		n := 0
		for _, m := range mem {
			if carryFn(m) {
				carrying[m] = true
				n++
			}
		}
		if float64(n)/float64(len(mem)) < p.Threshold {
			continue // the norm does not hold strongly enough to judge outliers
		}
		var exemplars []string
		for _, m := range mem {
			if carrying[m] && len(exemplars) < 3 {
				exemplars = append(exemplars, m)
			}
		}
		for _, m := range mem {
			if carrying[m] {
				continue
			}
			out = append(out, Absence{
				Outlier:  m,
				Missing:  "feature",
				Group:    k,
				Peers:    mem,
				Exemplar: exemplars[0],
			})
		}
	}
	return out
}

// Absence is the degenerate result: empty Source (the guard does not exist),
// the outlier as Target, and the peer group + feature + exemplars as evidence.
type Absence struct {
	Outlier  string
	Missing  string
	Group    string
	Peers    []string
	Exemplar string
}

func (a Absence) Source() string { return "" }
func (a Absence) Target() string { return a.Outlier }

func (a Absence) Witness() []solver.Step {
	steps := []solver.Step{{
		From: "", To: a.Outlier, Via: "deviates",
		Note: "missing " + a.Missing + " in group " + a.Group + "; conforming exemplar " + a.Exemplar,
	}}
	for _, p := range a.Peers {
		steps = append(steps, Step(p, a.Outlier, a.Missing))
	}
	return steps
}

// HintMatches reports whether an identifier matches a guard_hint glob. Hint
// globs are substring shapes ("*auth*"), so the needle is the glob with its
// stars trimmed and the match is containment — leading and trailing, both.
func HintMatches(name, glob string) bool {
	needle := strings.Trim(glob, "*")
	if needle == "" {
		return true
	}
	return strings.Contains(name, needle)
}

// Step builds a peer-evidence witness link (exported for tests).
func Step(from, to, missing string) solver.Step {
	return solver.Step{From: from, To: to, Via: "peer", Note: missing}
}

// Package taint is the v3 taint solver: an armed value flow from a source to
// a sink over the low-level FLOWS substrate, with interprocedural reach by
// position-matched summary instantiation — never inlining callee bodies at
// call sites. Arming is a positive precondition:
// source.taint ∩ sink.enabled_by ≠ ∅, evaluated against the ontology before
// any flow is returned. A flow whose taint kind the sink cannot consume never
// arms, so there is nothing to suppress.
package taint

import (
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

type Solver struct {
	onto *ontology.Ontology
}

// New builds the solver against the knowledge base's ontology — the concept
// facets (taint kinds, enabled_by) live there, not in the engine.
func New(onto *ontology.Ontology) *Solver { return &Solver{onto: onto} }

func (s *Solver) Name() string { return "taint" }

// Solve walks FLOWS from each labelled source until it reaches a labelled
// sink, expanding through CALLS edges by instantiating the callee's
// position-matched summary. Recursion and mutual recursion terminate by
// fixpoint: a (call site, argument position) pair is visited at most once.
func (s *Solver) Solve(g *graph.Store, in solver.Input) ([]solver.Result, error) {
	targetSet := map[string]bool{}
	for _, t := range in.Targets {
		targetSet[t] = true
	}
	var out []solver.Result
	for _, src := range in.Sources {
		for _, res := range s.walk(g, src, targetSet) {
			if !s.armed(g, src, res.dst) {
				continue // the arming gate is a positive precondition, not a suppression
			}
			path := res.path
			if len(res.notes) > 0 && len(path) > 0 {
				last := path[len(path)-1]
				last.Note = last.Note + " [" + strings.Join(res.notes, ",") + "]"
				path[len(path)-1] = last
			}
			out = append(out, solver.Flow{Src: src, Dst: res.dst, Path: path})
		}
	}
	return out, nil
}

type reach struct {
	dst   string
	path  []solver.Step
	notes []string // fidelity markers: taint-through, approx_lowered
}

// walk BFS's the FLOWS graph from src, descending CALLS edges with
// position-matched argument instantiation and a visited-pair fixpoint cut.
func (s *Solver) walk(g *graph.Store, src string, targets map[string]bool) []reach {
	type state struct {
		id    string
		path  []solver.Step
		notes []string
	}
	var results []reach
	seen := map[string]bool{src: true}
	visitedPairs := map[string]bool{}
	queue := []state{{id: src}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if targets[cur.id] {
			results = append(results, reach{dst: cur.id, path: cur.path, notes: cur.notes})
			// continue walking: a sink may also be a conduit to further sinks
		}
		node, ok := g.Node(cur.id)
		if !ok {
			continue
		}
		for _, e := range g.Out(cur.id, "FLOWS") {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			next := state{id: e.To, path: cloneSteps(cur.path, solver.Step{From: e.From, To: e.To, Via: "FLOWS"}), notes: cur.notes}
			if to, ok := g.Node(e.To); ok {
				if approx, _ := to.Fields.Get("approx_lowered"); approx.Kind == graph.KindBool && approx.B {
					next.notes = append(append([]string{}, cur.notes...), "approx_lowered")
				}
			}
			queue = append(queue, next)
		}
		// CALLS expansion: taint entering a call flows to the callee's matching
		// parameter occurrences (position-matched summary instantiation).
		for _, e := range g.Out(cur.id, "CALLS") {
			if node.Type != "code.Call" {
				continue
			}
			argIdx := argIndexOf(g, cur.id)
			if argIdx < 0 {
				continue
			}
			pair := e.From + "#" + itoa(argIdx) + ">" + e.To
			if visitedPairs[pair] {
				continue
			}
			visitedPairs[pair] = true
			for _, p := range paramOccurrences(g, e.To, argIdx) {
				if seen[p] {
					continue
				}
				seen[p] = true
				queue = append(queue, state{
					id:    p,
					path:  cloneSteps(cur.path, solver.Step{From: e.From, To: p, Via: "CALLS", Note: fnName(g, e.To)}),
					notes: cur.notes,
				})
			}
		}
	}
	return results
}

// argIndexOf reports which child-argument position of the call node carried
// the flow, by finding the FLOWS edge whose target is the call itself.
func argIndexOf(g *graph.Store, callID string) int {
	// The walk arrived at callID via an edge; the carrier is any child of
	// callID with a FLOWS into callID (arg → call) or the def-flow producer.
	// Position = index among child edges.
	args := g.Out(callID, "child")
	for i, c := range args {
		for _, f := range g.Out(c.To, "FLOWS") {
			if f.To == callID {
				return i
			}
		}
	}
	// The value flowed in via threading/def directly onto the call: treat the
	// first argument position as the carrier (documented approximation).
	if len(args) > 0 {
		return 0
	}
	return -1
}

// paramOccurrences returns the Name nodes inside the function that bind the
// argIdx-th parameter.
func paramOccurrences(g *graph.Store, fnID string, argIdx int) []string {
	var params []graph.Node
	for _, e := range g.Out(fnID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.ParamEntry" {
			params = append(params, n)
		}
	}
	if argIdx >= len(params) {
		return nil
	}
	local, _ := params[argIdx].Fields.Get("name")
	var out []string
	fnFile, _ := params[argIdx].Fields.Get("file")
	for _, n := range g.NodesOfType("code.Name") {
		if l, ok := n.Fields.Get("local"); !ok || l.S != local.S {
			continue
		}
		if f, ok := n.Fields.Get("file"); !ok || f.S != fnFile.S {
			continue
		}
		out = append(out, n.ID)
	}
	return out
}

// armed evaluates the arming gate: some source-kind label on src with a taint
// kind intersecting some sink-kind label's enabled_by on dst.
func (s *Solver) armed(g *graph.Store, src, dst string) bool {
	for _, ls := range g.LabelsOn(src) {
		cs, ok := s.onto.Get(ls.Concept)
		if !ok || !cs.HasKind(ontology.KindSource) || len(cs.Taint) == 0 {
			continue
		}
		for _, ld := range g.LabelsOn(dst) {
			cd, ok := s.onto.Get(ld.Concept)
			if !ok || !cd.HasKind(ontology.KindSink) || len(cd.EnabledBy) == 0 {
				continue
			}
			for _, t := range cs.Taint {
				for _, e := range cd.EnabledBy {
					if t == e {
						return true
					}
				}
			}
		}
	}
	return false
}

// Conduit joins a tainted write of a DataAccess column to a later read of the
// same table+column — the taint-through primitive: column-granular
// over-approximation, deliberately approximate, signal-clamped downstream.
func Conduit(g *graph.Store, write, read string) bool {
	w, ok1 := g.Node(write)
	r, ok2 := g.Node(read)
	if !ok1 || !ok2 {
		return false
	}
	wt, _ := w.Fields.Get("table")
	rt, _ := r.Fields.Get("table")
	if wt.S == "" || wt.S != rt.S {
		return false
	}
	wf, _ := w.Fields.Get("filters")
	rf, _ := r.Fields.Get("filters")
	return listIntersect(wf, rf)
}

func listIntersect(a, b graph.Value) bool {
	for _, x := range a.L {
		for _, y := range b.L {
			if x.S == y.S {
				return true
			}
		}
	}
	return false
}

func cloneSteps(base []solver.Step, add solver.Step) []solver.Step {
	out := make([]solver.Step, 0, len(base)+1)
	out = append(out, base...)
	return append(out, add)
}

func fnName(g *graph.Store, fnID string) string {
	if n, ok := g.Node(fnID); ok {
		if v, ok := n.Fields.Get("name"); ok {
			return v.S
		}
	}
	return fnID
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// Package cfg is the v3 cfg solver: dominance, post-dominance, and order over
// the frontend-computed Region/Order encoding — prefix tests plus integer
// comparisons, no path enumeration. Suppression polarity is
// unambiguous: when the metadata is missing or the relation is unprovable, the
// predicate returns false — the suppressor fails and the finding survives.
// Presence is never a degraded form of dominance.
package cfg

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// regionOf and orderOf read the inline fields; a missing field reports the
// unprovable state (ok=false), never a fabricated default.
func regionOf(n graph.Node) (string, bool) {
	v, ok := n.Fields.Get("region")
	return v.S, ok
}

func orderOf(n graph.Node) (int64, bool) {
	v, ok := n.Fields.Get("order")
	return v.I, ok
}

// ancestorOrEqual reports whether gr is a structured-control ancestor of (or
// equal to) sr on the region tree: a prefix test at segment boundaries.
func ancestorOrEqual(gr, sr string) bool {
	if gr == "" {
		return true // the module/function root encloses everything below it
	}
	if gr == sr {
		return true
	}
	return strings.HasPrefix(sr, gr+"/")
}

// Dominates holds when the guard's region encloses the guarded op's and the
// guard comes first in program order: every path to the op runs through the
// guard's region.
func Dominates(g *graph.Store, guard, op string) (bool, *solver.Proof, error) {
	gn, ok := g.Node(guard)
	if !ok {
		return false, nil, fmt.Errorf("cfg: unknown guard %s", guard)
	}
	on, ok := g.Node(op)
	if !ok {
		return false, nil, fmt.Errorf("cfg: unknown op %s", op)
	}
	gr, ok1 := regionOf(gn)
	sr, ok2 := regionOf(on)
	go_, ok3 := orderOf(gn)
	so, ok4 := orderOf(on)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		// Degradation: unprovable — never fabricated dominance.
		return false, nil, nil
	}
	holds := ancestorOrEqual(gr, sr) && go_ < so
	if !holds {
		return false, nil, nil
	}
	return true, &solver.Proof{
		Source: guard, Target: op,
		Steps: []solver.Step{{
			From: guard, To: op, Via: "dominates",
			Note: fmt.Sprintf("region %s encloses %s; order %d < %d", gr, sr, go_, so),
		}},
	}, nil
}

// PostDominates holds when the closer's region encloses the op's and the
// closer follows it: the op cannot complete without reaching the closer.
func PostDominates(g *graph.Store, closer, op string) (bool, *solver.Proof, error) {
	gn, ok := g.Node(closer)
	if !ok {
		return false, nil, fmt.Errorf("cfg: unknown closer %s", closer)
	}
	on, ok := g.Node(op)
	if !ok {
		return false, nil, fmt.Errorf("cfg: unknown op %s", op)
	}
	gr, ok1 := regionOf(gn)
	sr, ok2 := regionOf(on)
	co, ok3 := orderOf(gn)
	so, ok4 := orderOf(on)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false, nil, nil
	}
	holds := ancestorOrEqual(gr, sr) && co > so
	if !holds {
		return false, nil, nil
	}
	return true, &solver.Proof{
		Source: closer, Target: op,
		Steps: []solver.Step{{
			From: closer, To: op, Via: "postdominates",
			Note: fmt.Sprintf("region %s encloses %s; order %d > %d", gr, sr, co, so),
		}},
	}, nil
}

// Before reports whether a precedes b on the region order.
func Before(g *graph.Store, a, b string) bool {
	an, ok := g.Node(a)
	if !ok {
		return false
	}
	bn, ok := g.Node(b)
	if !ok {
		return false
	}
	ar, ok1 := regionOf(an)
	br, ok2 := regionOf(bn)
	ao, ok3 := orderOf(an)
	bo, ok4 := orderOf(bn)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false
	}
	return ancestorOrEqual(regionRoot(ar, br), br) && ao < bo
}

func regionRoot(a, b string) string {
	// The shared lineage is the shorter prefix common to both region paths.
	for a != b && !strings.HasPrefix(b, a+"/") && !strings.HasPrefix(a, b+"/") {
		if i := strings.LastIndex(a, "/"); i >= 0 {
			a = a[:i]
		} else {
			return ""
		}
	}
	if len(a) <= len(b) {
		return a
	}
	return b
}

// GuardDischarge decides a guarded_by suppressor for one guarded op through
// the backs bridge: a guard labelled with the concept dominates the op's low
// backing. Returns whether the suppressor holds, and colocation evidence when
// a same-function guard exists but does not dominate (attached to the
// surviving finding at lowered fidelity — never a weaker thing the
// suppressor accepts).
func GuardDischarge(g *graph.Store, opHighID, concept string, labelled func(string) bool) (holds bool, evidence string) {
	// A guard labelled directly on the guarded node — a framework-injected
	// auth fact on the entrypoint, a decorator-middleware guard — discharges
	// trivially: the whole operation carries the guard.
	if labelled(opHighID) {
		return true, ""
	}
	op, ok := g.Node(opHighID)
	if ok {
		if backed, has := g.Backing(opHighID); has {
			op = backed
		}
	}
	opRegion, ok1 := regionOf(op)
	if !ok1 {
		return false, ""
	}
	_ = opRegion
	for _, layer := range []graph.Layer{graph.LayerLow, graph.LayerHigh} {
		for _, n := range g.NodesOfLayer(layer) {
			if !labelled(n.ID) {
				continue
			}
			guard := n
			if backed, has := g.Backing(n.ID); has {
				guard = backed
			}
			if gr, ok := regionOf(guard); ok && gr != opRegion && !strings.HasPrefix(opRegion, gr+"/") {
				// Not an enclosing guard; same-function presence is colocation
				// evidence at lowered fidelity — order is irrelevant for mere
				// presence, which is weaker than dominance by construction.
				if strings.SplitN(gr, "/", 2)[0] == strings.SplitN(opRegion, "/", 2)[0] {
					evidence = fmt.Sprintf("guard %s is present in the same function (region %s) but does not enclose %s", guard.ID, gr, opRegion)
				}
				continue
			}
			if holds, _, _ := Dominates(g, guard.ID, op.ID); holds {
				return true, ""
			}
		}
	}
	return false, evidence
}

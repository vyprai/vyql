package solvers

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/usg"
)

// Dominates reports whether node g dominates node s on the structured CFG — i.e. every
// path from the enclosing function's entry to s passes through g. VyQL's frontends emit
// goto-free structured control flow, so the lowering can encode the dominator tree
// directly as a per-node control-region path + program order (lowerer.node): g dominates
// s iff g's region is an ancestor of (or equal to) s's region AND g precedes s in order.
//
// Each function has a distinct region root, so this is intraprocedural by construction;
// when the metadata is absent (a frontend not yet converted to structured NIR) it returns
// false and callers fall back to presence semantics — never a false suppression.
func Dominates(store usg.Store, gID, sID string) bool {
	if gID == "" || sID == "" {
		return false
	}
	gn, ok1, _ := store.GetNode(gID)
	sn, ok2, _ := store.GetNode(sID)
	if !ok1 || !ok2 {
		return false
	}
	return dominatesRegion(gn.Prop("region"), gn.Prop("order"), sn.Prop("region"), sn.Prop("order"))
}

// Reaches reports whether node a can reach node b on a CFG path — a executes, then b can
// execute after it. For structured control flow that is: order(a) < order(b) AND their
// regions are COMPARABLE (one is an ancestor of the other, i.e. not in disjoint sibling
// branches). Used by order-rules (reentrancy: external_call before state_write).
func Reaches(store usg.Store, aID, bID string) bool {
	if aID == "" || bID == "" || aID == bID {
		return false
	}
	an, ok1, _ := store.GetNode(aID)
	bn, ok2, _ := store.GetNode(bID)
	if !ok1 || !ok2 {
		return false
	}
	return reachesRegion(an.Prop("region"), an.Prop("order"), bn.Prop("region"), bn.Prop("order"))
}

func reachesRegion(rA, oA, rB, oB string) bool {
	if rA == "" || rB == "" {
		return false // no CFG metadata → not decidable
	}
	comparable := rA == rB || strings.HasPrefix(rB, rA+"/") || strings.HasPrefix(rA, rB+"/")
	if !comparable {
		return false // disjoint sibling branches — no path from a to b
	}
	a, err1 := strconv.Atoi(oA)
	b, err2 := strconv.Atoi(oB)
	if err1 != nil || err2 != nil {
		return false
	}
	return a < b
}

// dominatesRegion is the pure structural check (split out for testing).
func dominatesRegion(gRegion, gOrder, sRegion, sOrder string) bool {
	// region must be present on both — an unconverted frontend stamps neither.
	if gRegion == "" && sRegion == "" {
		// both at a root with no function tag → no CFG info → not dominance-decidable.
		return false
	}
	// ancestor-or-equal: same region, or s nested under g (segment boundary on "/").
	if sRegion != gRegion && !strings.HasPrefix(sRegion, gRegion+"/") {
		return false
	}
	go_, err1 := strconv.Atoi(gOrder)
	so_, err2 := strconv.Atoi(sOrder)
	if err1 != nil || err2 != nil {
		return false
	}
	return go_ < so_
}

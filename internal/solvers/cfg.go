package solvers

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/usg"
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
	if an.Prop("region") == "" && bn.Prop("region") == "" && sameLocFile(an.Prop("loc"), bn.Prop("loc")) {
		a, err1 := strconv.Atoi(an.Prop("order"))
		b, err2 := strconv.Atoi(bn.Prop("order"))
		return err1 == nil && err2 == nil && a < b
	}
	return reachesRegion(an.Prop("region"), an.Prop("order"), bn.Prop("region"), bn.Prop("order"))
}

func sameLocFile(aLoc, bLoc string) bool {
	if aLoc == "" || bLoc == "" {
		return false
	}
	aFile := locFile(aLoc)
	bFile := locFile(bLoc)
	return aFile != "" && aFile == bFile
}

func locFile(loc string) string {
	idx := strings.LastIndex(loc, ":")
	if idx <= 0 {
		return ""
	}
	return loc[:idx]
}

// PostDominates reports whether `release` runs on EVERY path from `alloc` to function
// exit — the test for "the resource is always released" (leak detection is its negation).
// For structured control flow: release is in an ancestor-or-equal region of alloc (so it
// is not skipped by leaving a branch alloc sits in) and comes after it in order.
func PostDominates(store usg.Store, releaseID, allocID string) bool {
	if releaseID == "" || allocID == "" {
		return false
	}
	rn, ok1, _ := store.GetNode(releaseID)
	an, ok2, _ := store.GetNode(allocID)
	if !ok1 || !ok2 {
		return false
	}
	return postDominatesRegion(rn.Prop("region"), rn.Prop("order"), an.Prop("region"), an.Prop("order"))
}

func postDominatesRegion(rRel, oRel, rAlloc, oAlloc string) bool {
	if rRel == "" || rAlloc == "" {
		return false
	}
	// alloc must be in the release's region or NESTED under it: then exiting the alloc's
	// scope still reaches the release. (release nested deeper than alloc → conditionally
	// skipped → does NOT post-dominate → leak.)
	if !(rAlloc == rRel || strings.HasPrefix(rAlloc, rRel+"/")) {
		return false
	}
	r, err1 := strconv.Atoi(oRel)
	a, err2 := strconv.Atoi(oAlloc)
	if err1 != nil || err2 != nil {
		return false
	}
	return r > a
}

func reachesRegion(rA, oA, rB, oB string) bool {
	if rA == "" || rB == "" {
		return false // no CFG metadata → not decidable
	}
	if !regionsSequenced(rA, rB) {
		return false // disjoint sibling branches — no path from a to b
	}
	a, err1 := strconv.Atoi(oA)
	b, err2 := strconv.Atoi(oB)
	if err1 != nil || err2 != nil {
		return false
	}
	return a < b
}

// regionsSequenced reports whether two regions can lie on one execution path.
// Control regions nest with "/", so a prefix relation puts one inside the other;
// disjoint sibling branches never both run. A function body written inline hangs
// off its enclosing region with "#", and its code runs somewhere after the code
// that passes it, so it is sequenced with that region and with everything that
// region is sequenced with.
func regionsSequenced(a, b string) bool {
	for _, ra := range regionScopeChain(a) {
		for _, rb := range regionScopeChain(b) {
			if ra == rb || strings.HasPrefix(rb, ra+"/") || strings.HasPrefix(ra, rb+"/") {
				return true
			}
		}
	}
	return false
}

// regionScopeChain returns r followed by each region it is nested inside as an
// inline function body, outermost last.
func regionScopeChain(r string) []string {
	out := []string{r}
	for {
		i := strings.LastIndex(r, "#")
		if i < 0 {
			return out
		}
		r = r[:i]
		out = append(out, r)
	}
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

package solvers

import (
	"math"
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

// PostDominates reports the structural post-dominance of one release site over one
// acquisition: release is in an ancestor-or-equal region of alloc (so it is not skipped by
// leaving a branch alloc sits in) and comes after it in order.
//
// That is a necessary condition for "the resource is always released", not a sufficient
// one — a branch between the two can end the function without reaching the release. Ask
// PostDominatesCovered, which weighs the whole release set against the function's exits,
// for the question a leak rule is really asking.
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
	r, err1 := strconv.Atoi(oRel)
	a, err2 := strconv.Atoi(oAlloc)
	if err1 != nil || err2 != nil {
		return false
	}
	return postDominatesOrder(rRel, r, rAlloc, a)
}

// postDominatesOrder is the structural half of post-dominance: the release is written after
// the acquisition, in the acquisition's own region or one enclosing it, so leaving the
// acquisition's branch still reaches it. (release nested deeper than alloc → conditionally
// skipped → does NOT post-dominate → leak.) It says nothing about a branch that ENDS the
// function before reaching the release; PostDominatesCovered adds that.
func postDominatesOrder(rRel string, oRel int, rAlloc string, oAlloc int) bool {
	if rRel == "" || rAlloc == "" {
		return false
	}
	if !(rAlloc == rRel || strings.HasPrefix(rAlloc, rRel+"/")) {
		return false
	}
	return oRel > oAlloc
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
// Control regions nest with "/", so a prefix relation puts one inside the other.
// Siblings need a closer look: only the ARMS OF ONE construct exclude each other
// (then vs else, case vs case, try body vs handler). Two separate constructs at
// the same nesting depth — `if (a) { free(p); }` followed by `if (b) { free(p); }`
// — are written one after the other and both run whenever both guards hold, so
// they are sequenced. A function body written inline hangs off its enclosing
// region with "#", and its code runs somewhere after the code that passes it, so
// it is sequenced with that region and with everything that region is sequenced
// with.
func regionsSequenced(a, b string) bool {
	for _, ra := range regionScopeChain(a) {
		for _, rb := range regionScopeChain(b) {
			if regionPathsSequenced(ra, rb) {
				return true
			}
		}
	}
	return false
}

// regionPathsSequenced is regionsSequenced for two region paths with the inline-body
// chain already resolved. It walks the two paths in place, because Reaches is asked
// about every pair of candidate nodes and a per-call split would allocate on each.
func regionPathsSequenced(a, b string) bool {
	if a == b || hasSegmentPrefix(b, a) || hasSegmentPrefix(a, b) {
		return true
	}
	// Advance segment by segment to the first segment that differs: i is where that
	// segment starts in both paths, ea and eb are where it ends in each.
	i, ea, eb := 0, 0, 0
	for {
		ea, eb = segmentEnd(a, i), segmentEnd(b, i)
		if a[i:ea] != b[i:eb] {
			break
		}
		if ea == len(a) || eb == len(b) {
			// One path ends while every segment so far is shared, which the
			// prefix cases above already answered.
			return false
		}
		i = ea + 1
	}
	if i == 0 {
		return false // the paths share no enclosing scope, so different modules
	}
	// The paths first differ at this segment. They are on one execution path only if
	// the two segments are two DISTINCT control constructs of the same enclosing
	// scope, lowered in program order. Same construct → alternative arms, which
	// never both run; anything that is not a control construct (a function root)
	// → separate function bodies, which Reaches does not sequence.
	ca, ok1 := controlConstruct(a[i:ea])
	cb, ok2 := controlConstruct(b[i:eb])
	return ok1 && ok2 && ca != cb
}

// hasSegmentPrefix reports whether prefix covers a whole leading run of path's
// segments, which is strings.HasPrefix(path, prefix+"/") without building the
// concatenation.
func hasSegmentPrefix(path, prefix string) bool {
	return len(path) > len(prefix) && path[len(prefix)] == '/' && path[:len(prefix)] == prefix
}

// segmentEnd returns the index just past the path segment that starts at i.
func segmentEnd(path string, i int) int {
	if j := strings.IndexByte(path[i:], '/'); j >= 0 {
		return i + j
	}
	return len(path)
}

// controlConstruct names the control-flow construct a region segment belongs to —
// "if7" for both "if7.t" and "if7.e", "sw3" for every "sw3.cN" and "sw3.d", "try2"
// for "try2" and its "try2.hN" handlers, "loop4" for "loop4". The segment of an
// inline function body ("if7.t#fn9") still belongs to the construct it was written
// in. Reports false for a segment that is not a control construct — a function
// region root, or a shape a frontend introduced that this does not model.
func controlConstruct(seg string) (string, bool) {
	id := seg
	if i := strings.IndexByte(id, '.'); i >= 0 {
		id = id[:i]
	}
	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}
	for _, kind := range []string{"if", "loop", "sw", "try"} {
		if rest, ok := strings.CutPrefix(id, kind); ok && isDigits(rest) {
			return id, true
		}
	}
	return "", false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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

// ExitIndex holds the conditional-exit markers of a graph (usg.ExitNodeType), grouped by
// the function-root region they sit under so answering a question about one function never
// walks another's. Build it once per store and reuse it: the markers do not change while a
// rule set is evaluated.
type ExitIndex struct {
	byRoot map[string][]exitPoint
}

// exitPoint is one `return`/`raise` written inside a control region.
type exitPoint struct {
	region string
	order  int
	guard  string // the node the condition of the branch it sits in evaluated to, "" if none
}

// NewExitIndex reads the exit markers out of store. A graph lowered without them (an
// unconverted frontend, a store built by hand) yields an empty index, under which
// PostDominatesCovered answers exactly as the region/order approximation always did.
func NewExitIndex(store usg.Store) *ExitIndex {
	x := &ExitIndex{byRoot: map[string][]exitPoint{}}
	if store == nil {
		return x
	}
	ids, err := store.NodesOfType(usg.ExitNodeType)
	if err != nil {
		return x
	}
	for _, id := range ids {
		n, ok, _ := store.GetNode(id)
		if !ok {
			continue
		}
		region := n.Prop("region")
		order, err := strconv.Atoi(n.Prop("order"))
		if region == "" || err != nil {
			continue
		}
		root := regionRoot(region)
		x.byRoot[root] = append(x.byRoot[root],
			exitPoint{region: region, order: order, guard: n.Prop(usg.ExitGuardProp)})
	}
	return x
}

// release is one candidate release site, resolved once per PostDominatesCovered call.
type release struct {
	region string
	order  int
	unwind bool // finally / defer: the language runs it however its region is left
}

// PostDominatesCovered reports whether the releases cover EVERY path from alloc to the
// function's exit — the question `unless postDominates coveredBy` asks, and the one a single
// release site cannot answer alone.
//
// The region/order encoding says a release written after the acquisition in an enclosing-or-
// equal region is not skipped by leaving the branch the acquisition sits in. What it does not
// say is that a branch can END the function: an early `return` between the two leaves without
// ever reaching the release, and the trailing release was credited with covering that path
// anyway. Exit markers make those paths visible, and a path is still covered when one of the
// releases runs on it before it leaves — the error block that releases what it owns before
// bailing out is the common form, and it is genuinely covered. So is the path taken by the
// guard that follows the acquisition and asks whether it SUCCEEDED, which holds nothing
// because the acquisition returned nothing; see acq for the two shapes that guard is
// written in.
func PostDominatesCovered(store usg.Store, exits *ExitIndex, releaseIDs []string, allocID string) bool {
	if allocID == "" || len(releaseIDs) == 0 {
		return false
	}
	an, ok, _ := store.GetNode(allocID)
	if !ok {
		return false
	}
	allocRegion := an.Prop("region")
	allocOrder, err := strconv.Atoi(an.Prop("order"))
	if err != nil {
		return false
	}
	releases := make([]release, 0, len(releaseIDs))
	var covering []release // those that post-dominate structurally: candidates to unseat
	for _, id := range releaseIDs {
		if id == "" || id == allocID {
			continue
		}
		rn, ok, _ := store.GetNode(id)
		if !ok {
			continue
		}
		order, err := strconv.Atoi(rn.Prop("order"))
		if rn.Prop("region") == "" || err != nil {
			continue
		}
		r := release{region: rn.Prop("region"), order: order, unwind: rn.Prop(usg.UnwindProp) != ""}
		releases = append(releases, r)
		if postDominatesOrder(r.region, r.order, allocRegion, allocOrder) {
			if r.unwind {
				return true // no exit of the region it covers can skip it
			}
			covering = append(covering, r)
		}
	}
	if len(covering) == 0 {
		return false
	}
	acquisition := resolveAcq(store, allocID, allocRegion, allocOrder, releaseIDs)
	for _, r := range covering {
		if !exits.skipped(r, acquisition, releases) {
			return true
		}
	}
	return false
}

// acq is the acquisition side of one coverage question, resolved once.
type acq struct {
	region string
	order  int
	// established is the point from which a path that leaves the function is a path that
	// abandons the resource; exits at or before it belong to the acquisition's own failure
	// path. See establishedOrder.
	established int
	// tested holds the nodes the acquisition's result flows into. A branch whose condition
	// is one of them is the acquisition's own success check, so the exit it takes leaves
	// with nothing acquired. See skipped.
	tested map[string]bool
}

func resolveAcq(store usg.Store, allocID, allocRegion string, allocOrder int, releaseIDs []string) acq {
	a := acq{region: allocRegion, order: allocOrder, established: allocOrder}
	edges, err := store.OutEdges(allocID, "FLOWS")
	if err != nil || len(edges) == 0 {
		return a // no handle to check: nothing can guard on it
	}
	a.tested = make(map[string]bool, len(edges))
	for _, e := range edges {
		a.tested[e.Dst] = true
	}
	a.established = establishedOrder(store, edges, allocOrder, releaseIDs)
	return a
}

// establishedOrder is the point from which a path that leaves the function is a path that
// abandons the resource: exits before it are not read as skipping the release.
//
// An acquisition that hands back a handle is followed, in every language, by the guard that
// checks whether it succeeded — `if (U_FAILURE(errorCode)) return;`, `if err != nil { return }`.
// That branch releases nothing because there is nothing to release, and reading it as a leak
// path reports every careful acquisition in the corpus. The resource is established once
// something OTHER than a release consumes the handle; until then the early exits belong to
// the acquisition's own failure path. An acquisition with no value at all — `mu.Lock()` —
// has no such guard, so it is established where it is written.
//
// This reads the guard by what it comes BEFORE, which is what an acquisition whose status
// arrives through an out-parameter gives: the handle is the returned value and the guard
// tests something else. The other spelling — the returned value IS the status, and the
// handle is the out-parameter — is read by acq.tested instead, because there the guard is
// the only thing the returned value ever reaches.
func establishedOrder(store usg.Store, edges []usg.Edge, allocOrder int, releaseIDs []string) int {
	isRelease := make(map[string]bool, len(releaseIDs))
	for _, id := range releaseIDs {
		isRelease[id] = true
	}
	established := math.MaxInt
	for _, e := range edges {
		if isRelease[e.Dst] {
			continue
		}
		n, ok, _ := store.GetNode(e.Dst)
		if !ok {
			continue
		}
		o, err := strconv.Atoi(n.Prop("order"))
		if err != nil || o <= allocOrder || o >= established {
			continue
		}
		established = o
	}
	return established
}

// skipped reports whether some path leaves the function between the acquisition and rel
// without any release running on it first.
func (x *ExitIndex) skipped(rel release, a acq, releases []release) bool {
	if x == nil {
		return false
	}
	for _, e := range x.byRoot[regionRoot(rel.region)] {
		if e.order <= a.order || e.order >= rel.order {
			continue // not between the acquisition and the release
		}
		if e.order <= a.established {
			continue // the acquisition's own failure guard, not an abandoned resource
		}
		if e.guard != "" && a.tested[e.guard] {
			continue // the branch tests what the acquisition returned: it failed, so nothing is held
		}
		if !regionNestedIn(e.region, rel.region) {
			continue // not inside a branch of the region the release runs in
		}
		if !regionNestedIn(e.region, a.region) && !regionNestedIn(a.region, e.region) {
			continue // a sibling branch of the acquisition's — the exit is not reached after it
		}
		if !releasedBefore(e, a.order, releases) {
			return true
		}
	}
	return false
}

// releasedBefore reports whether one of the releases runs on the path to e after the
// acquisition — a release written in e's own region or in one enclosing it, before it.
func releasedBefore(e exitPoint, allocOrder int, releases []release) bool {
	for _, r := range releases {
		if r.order <= allocOrder || r.order >= e.order {
			continue
		}
		if regionNestedIn(e.region, r.region) {
			return true
		}
	}
	return false
}

// regionNestedIn reports whether inner is outer or a control region nested inside it,
// within ONE function: an inline function body ("#") is a separate flow, so a `return`
// written in a callback exits the callback and not the function that passes it.
func regionNestedIn(inner, outer string) bool {
	if outer == "" || inner == "" {
		return false
	}
	if inner == outer {
		return true
	}
	return strings.HasPrefix(inner, outer+"/") && !strings.Contains(inner[len(outer):], "#")
}

// regionRoot returns the function-root prefix of a region: the namespace plus the "/fnN"
// segment that opens the outermost function body it belongs to.
func regionRoot(region string) string {
	i := strings.IndexByte(region, '/')
	if i < 0 {
		return region
	}
	if j := strings.IndexAny(region[i+1:], "/#"); j >= 0 {
		return region[:i+1+j]
	}
	return region
}

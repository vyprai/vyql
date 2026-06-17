// Package solvers implements the flow solvers (docs/08), ported from
// poc/vyql/solvers/. The taint solver realises the normative semantics:
// sanitization is a transfer function on the dataflow fact (not a structural
// "exists" check). A finding exists iff a live tainted fact reaches a sink along
// some path with no neutralizing control on it.
package solvers

import (
	"sort"
	"strings"

	"github.com/vyprai/vyql/usg"
)

// TaintFlow is one source->sink taint result with its witness path.
type TaintFlow struct {
	SourceID string
	SinkID   string
	Kind     string
	Path     []string
	// controls on killed sibling paths (for near-miss negation evidence)
	NearMiss [][2]string
}

// excludesAll reports whether a char-filter's bounded output alphabet excludes every
// excluded character for a sink (i.e. the filter provably neutralizes the taint).
func excludesAll(alphabet, excluded string) bool {
	for _, d := range excluded {
		if strings.ContainsRune(alphabet, d) {
			return false
		}
	}
	return true
}

func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return "UNTRUSTED_DATA"
}

// FindTaintFlows enumerates source->sink paths; a path yields a flow iff no
// kill-control node lies on it (the control killed the fact). Records near-miss
// controls seen on killed sibling paths.
func FindTaintFlows(store usg.Store, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool, excluded string) ([]TaintFlow, error) {
	// int-indexed fast path: run the whole fixpoint on int32 node indices (no string ids/payload
	// in the hot loop) when the store supports it — the basis for keeping only int adjacency +
	// labels resident while ids/payload spill to disk. Produces identical findings.
	if ig, ok := store.(usg.IntGraph); ok {
		return findTaintFlowsInt(ig, sourceConcepts, sinkConcepts, taintKinds, killControls, excluded), nil
	}
	// collect source nodes (nodes carrying any source concept)
	sourceNodes := map[string]bool{}
	for c := range sourceConcepts {
		ids, err := store.NodesWithConcept(c)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			sourceNodes[id] = true
		}
	}

	kind := firstKey(taintKinds)
	var out []TaintFlow

	// Hot-path fast accessors (in-memory store): read labels and iterate out-edges without
	// the per-call slice copies that OutEdges/Labels make. The taint DFS touches every
	// reachable node, so those copies dominated transient allocation (and thus GC/scavenger
	// — runtime.madvise — time) on large graphs. Falls back to the interface for other stores.
	fast, isFast := store.(interface {
		LabelsOf(nodeID string) []usg.Label
		RangeOutEdges(src, edgeType string, fn func(dst string) bool)
	})
	labelsOf := func(id string) []usg.Label {
		if isFast {
			return fast.LabelsOf(id)
		}
		ls, _ := store.Labels(id)
		return ls
	}

	// Global cross-source taint. Rather than an independent DFS per source (which re-traverses
	// shared subgraphs once per source), compute live source→sink reachability in ONE forward
	// dataflow pass: every node carries a bitset of the sources that reach it along a LIVE
	// (un-sanitized) path. A kill control / sound char-filter absorbs taint — its live-out is
	// empty, so sources never propagate past it — which matches the DFS semantics where a
	// sanitized prefix can never reach a live sink (sanitization is monotone). Cost is
	// O((V+E)·words) ONCE instead of O(sources·(V+E)). Witnesses are presentation-only and are
	// reconstructed by a single multi-source BFS over the live graph.
	srcs := make([]string, 0, len(sourceNodes))
	for s := range sourceNodes {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	if len(srcs) == 0 {
		return nil, nil
	}
	// isKill: a node neutralizes taint if it carries a kill control, or a char-filter whose
	// bounded output alphabet provably excludes the sink's excluded chars. killOf also returns
	// the concept for near-miss detail. Memoized — each node's labels are scanned once.
	killMemo := map[string]int8{} // 0 unknown, 1 kill, 2 not-kill
	killConcept := map[string]string{}
	killOf := func(id string) (bool, string) {
		switch killMemo[id] {
		case 1:
			return true, killConcept[id]
		case 2:
			return false, ""
		}
		for _, l := range labelsOf(id) {
			if killControls[l.Concept] {
				killMemo[id], killConcept[id] = 1, l.Concept
				return true, l.Concept
			}
			if l.Concept == "core.CharFilter" && excluded != "" &&
				l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], excluded) {
				killMemo[id], killConcept[id] = 1, "core.CharFilter"
				return true, "core.CharFilter"
			}
		}
		killMemo[id] = 2
		return false, ""
	}
	forEachSucc := func(id string, fn func(string)) {
		if isFast {
			fast.RangeOutEdges(id, "FLOWS", func(dst string) bool { fn(dst); return true })
		} else {
			edges, _ := store.OutEdges(id, "FLOWS")
			for _, e := range edges {
				fn(e.Dst)
			}
		}
	}

	// forward live-reachability fixpoint. A finding is "some live source reaches this sink", and
	// findings dedup to one per (rule, sink) — so we track a single BOOLEAN per node (reached by
	// a live source) rather than a bitset of WHICH sources. That drops the cost from O(E·sources)
	// to O(V+E): a node is marked tainted once and propagates once. pred records the node that
	// first tainted each node, giving a witness source→sink path for free (no separate BFS). A
	// kill control / sound char-filter absorbs taint: it is marked reached (for near-miss) but
	// never propagates, matching the bitset semantics where a sanitized prefix can't reach a live
	// sink. The chosen witness source is "a" valid rule source (sources are pre-filtered to the
	// rule's source concept), which is all a per-(rule,sink) finding needs.
	tainted := make(map[string]bool, len(srcs)*8)
	pred := make(map[string]string, len(srcs)*8)
	var nearMiss [][2]string
	queue := make([]string, 0, len(srcs)*4)
	for _, s := range srcs {
		if !tainted[s] {
			tainted[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if kill, c := killOf(node); kill { // reached a neutralizer: record near-miss, don't propagate
			nearMiss = append(nearMiss, [2]string{node, c})
			continue
		}
		forEachSucc(node, func(dst string) {
			if !tainted[dst] {
				tainted[dst] = true
				pred[dst] = node
				queue = append(queue, dst)
			}
		})
	}

	// witness path: walk pred from a tainted node back to its source root (recorded during the
	// fixpoint, so no second traversal). path[0] is a valid source for the (rule, sink) finding.
	pathTo := func(sink string) []string {
		var rev []string
		for n := sink; ; {
			rev = append(rev, n)
			p, ok := pred[n]
			if !ok {
				break
			}
			n = p
		}
		for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
			rev[i], rev[j] = rev[j], rev[i]
		}
		return rev
	}

	// emit one flow per tainted live sink (findings dedup to one per (rule, sink) anyway);
	// sinks sorted for determinism, witness source = the recorded path's root.
	sinkSet := map[string]bool{}
	for c := range sinkConcepts {
		ids, _ := store.NodesWithConcept(c)
		for _, id := range ids {
			sinkSet[id] = true
		}
	}
	sinks := make([]string, 0, len(sinkSet))
	for s := range sinkSet {
		sinks = append(sinks, s)
	}
	sort.Strings(sinks)
	nm := dedupPairs(nearMiss)
	for _, sink := range sinks {
		if !tainted[sink] {
			continue
		}
		if k, _ := killOf(sink); k { // a sink that is itself a neutralizer sanitizes its own use
			continue
		}
		path := pathTo(sink)
		out = append(out, TaintFlow{SourceID: path[0], SinkID: sink, Kind: kind, Path: path, NearMiss: nm})
	}
	return out, nil
}

// findTaintFlowsInt is the int-indexed twin of FindTaintFlows: same boolean live-reachability
// fixpoint and witness semantics, but every per-node structure is an array indexed by node
// int32 (no string maps in the hot loop), and adjacency/labels/concept-sets come from the
// IntGraph. String ids are produced only when emitting findings (NodeID), so the inner loop
// touches no ids or payload — exactly what an out-of-core (ids/payload-on-disk) store needs.
func findTaintFlowsInt(g usg.IntGraph, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool, excluded string) []TaintFlow {
	n := g.NodeCount()
	kind := firstKey(taintKinds)

	// source indices (sorted, deduped) for a deterministic witness choice.
	srcSet := map[int32]bool{}
	for c := range sourceConcepts {
		for _, i := range g.ConceptNodes(c) {
			srcSet[i] = true
		}
	}
	if len(srcSet) == 0 {
		return nil
	}
	srcs := make([]int32, 0, len(srcSet))
	for i := range srcSet {
		srcs = append(srcs, i)
	}
	sort.Slice(srcs, func(a, b int) bool { return srcs[a] < srcs[b] })

	// memoized kill check on a node index.
	killMemo := make([]int8, n) // 0 unknown, 1 kill, 2 not-kill
	killConcept := map[int32]string{}
	killOf := func(i int32) (bool, string) {
		switch killMemo[i] {
		case 1:
			return true, killConcept[i]
		case 2:
			return false, ""
		}
		for _, l := range g.LabelsAt(i) {
			if killControls[l.Concept] {
				killMemo[i] = 1
				killConcept[i] = l.Concept
				return true, l.Concept
			}
			if l.Concept == "core.CharFilter" && excluded != "" &&
				l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], excluded) {
				killMemo[i] = 1
				killConcept[i] = "core.CharFilter"
				return true, "core.CharFilter"
			}
		}
		killMemo[i] = 2
		return false, ""
	}

	tainted := make([]bool, n)
	pred := make([]int32, n)
	for i := range pred {
		pred[i] = -1
	}
	var nearMiss [][2]string
	queue := make([]int32, 0, len(srcs)*4)
	for _, s := range srcs {
		if !tainted[s] {
			tainted[s] = true
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if kill, c := killOf(node); kill {
			nearMiss = append(nearMiss, [2]string{g.NodeID(node), c})
			continue
		}
		g.RangeOut(node, "FLOWS", func(dst int32) bool {
			if !tainted[dst] {
				tainted[dst] = true
				pred[dst] = node
				queue = append(queue, dst)
			}
			return true
		})
	}

	pathTo := func(sink int32) []string {
		var rev []int32
		for i := sink; i >= 0; i = pred[i] {
			rev = append(rev, i)
		}
		out := make([]string, len(rev))
		for k := range rev { // reverse to source→sink order, mapping to string ids
			out[k] = g.NodeID(rev[len(rev)-1-k])
		}
		return out
	}

	// sinks (sorted) → one flow per tainted live sink.
	sinkSet := map[int32]bool{}
	for c := range sinkConcepts {
		for _, i := range g.ConceptNodes(c) {
			sinkSet[i] = true
		}
	}
	sinks := make([]int32, 0, len(sinkSet))
	for i := range sinkSet {
		sinks = append(sinks, i)
	}
	sort.Slice(sinks, func(a, b int) bool { return sinks[a] < sinks[b] })
	nm := dedupPairs(nearMiss)
	var out []TaintFlow
	for _, sink := range sinks {
		if !tainted[sink] {
			continue
		}
		if k, _ := killOf(sink); k {
			continue
		}
		path := pathTo(sink)
		out = append(out, TaintFlow{SourceID: path[0], SinkID: g.NodeID(sink), Kind: kind, Path: path, NearMiss: nm})
	}
	return out
}

func dedupPairs(ps [][2]string) [][2]string {
	seen := map[[2]string]bool{}
	var out [][2]string
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

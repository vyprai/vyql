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
// dangerous character for a sink (i.e. the filter provably neutralizes the taint).
func excludesAll(alphabet, dangerous string) bool {
	for _, d := range dangerous {
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
func FindTaintFlows(store usg.Store, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool, dangerous string) ([]TaintFlow, error) {
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
	words := (len(srcs) + 63) / 64

	// isKill: a node neutralizes taint if it carries a kill control, or a char-filter whose
	// bounded output alphabet provably excludes the sink's dangerous chars. killOf also returns
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
			if l.Concept == "core.CharFilter" && dangerous != "" &&
				l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], dangerous) {
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

	// forward live-reachability fixpoint (monotone bitset OR; worklist over FLOWS edges).
	in := map[string][]uint64{}
	getBits := func(id string) []uint64 {
		b := in[id]
		if b == nil {
			b = make([]uint64, words)
			in[id] = b
		}
		return b
	}
	var nearMiss [][2]string
	queue := make([]string, 0, len(srcs)*4)
	inQ := map[string]bool{}
	push := func(id string) {
		if !inQ[id] {
			inQ[id] = true
			queue = append(queue, id)
		}
	}
	for i, s := range srcs {
		getBits(s)[i/64] |= 1 << uint(i%64)
		push(s)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		inQ[node] = false
		bits := in[node]
		if kill, c := killOf(node); kill {
			if anyBit(bits) { // sources die here — record the neutralizing control (near-miss)
				nearMiss = append(nearMiss, [2]string{node, c})
			}
			continue // killed: nothing propagates past a neutralizer
		}
		forEachSucc(node, func(dst string) {
			db := getBits(dst)
			changed := false
			for w := 0; w < words; w++ {
				if nv := db[w] | bits[w]; nv != db[w] {
					db[w] = nv
					changed = true
				}
			}
			if changed {
				push(dst)
			}
		})
	}

	// witnesses: one multi-source BFS over the live graph (kill nodes excluded) gives each
	// reached node a predecessor, so every live sink has a representative path back to a source.
	pred := map[string]string{}
	seen := make(map[string]bool, len(in))
	bfs := make([]string, 0, len(srcs))
	for _, s := range srcs {
		if k, _ := killOf(s); !k {
			seen[s] = true
			bfs = append(bfs, s)
		}
	}
	for len(bfs) > 0 {
		node := bfs[0]
		bfs = bfs[1:]
		forEachSucc(node, func(dst string) {
			if seen[dst] {
				return
			}
			if k, _ := killOf(dst); k {
				return
			}
			seen[dst] = true
			pred[dst] = node
			bfs = append(bfs, dst)
		})
	}
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

	// emit one flow per (source, sink) with a live path; sinks/sources sorted for determinism.
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
		bits := in[sink]
		if bits == nil {
			continue
		}
		if k, _ := killOf(sink); k { // a sink that is itself a neutralizer sanitizes its own use
			continue
		}
		var path []string
		for i, s := range srcs {
			if bits[i/64]&(1<<uint(i%64)) == 0 {
				continue
			}
			if path == nil {
				path = pathTo(sink)
			}
			out = append(out, TaintFlow{SourceID: s, SinkID: sink, Kind: kind, Path: path, NearMiss: nm})
		}
	}
	return out, nil
}

// anyBit reports whether any source bit is set in a reachability word slice.
func anyBit(b []uint64) bool {
	for _, w := range b {
		if w != 0 {
			return true
		}
	}
	return false
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

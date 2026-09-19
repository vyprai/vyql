// Package solvers implements the flow solvers (docs/08). The taint solver
// Realises the normative semantics:
// sanitization is a transfer function on the dataflow fact (not a structural
// "exists" check). A finding exists iff a live tainted fact reaches a sink along
// some path with no neutralizing control on it.
package solvers

import (
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/usg"
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

func coversAll(chars, excluded string) bool {
	for _, d := range excluded {
		if !strings.ContainsRune(chars, d) {
			return false
		}
	}
	return true
}

// intNearMiss defers NodeID lookup until the near-miss survives the contradiction filter,
// keeping the int fixpoint free of string ids.
type intNearMiss struct {
	node    int32
	concept string
}

// dropContradicted removes near-miss entries for neutralizers that turned out not to
// neutralize: a control the flow ran straight through is not evidence of a near miss.
func dropContradicted(ps [][2]string, contradicted func(string) bool) [][2]string {
	out := ps[:0]
	for _, p := range ps {
		if !contradicted(p[0]) {
			out = append(out, p)
		}
	}
	return out
}

func firstKey(m map[string]bool) string {
	for k := range m {
		return k
	}
	return "UNTRUSTED_DATA"
}

// receiverAnchor returns the node whose taint a receiver-anchored sink on this node
// consumes, or "" when no constraint applies.
//
// A sink bound at callee.receiver ("the tainted data is the receiver") is labelled on
// the CALL node, because that is where the finding is reported. But a call node is also
// the confluence of its ARGUMENTS: `Path("/const").write_bytes(tainted)` taints the call
// node through arg0, and the bare label would fire even though the receiver — the path
// this sink is about — is a constant. The binding records the receiver node in the label
// detail; a sink carrying it fires only when that node is itself tainted.
//
// The constraint is per NODE, while flows are emitted per node, so a node carrying an
// unconstrained sink concept as well (a different rule's sink on the same call) keeps the
// unconstrained meaning: narrowing it would suppress a sink nobody anchored at a receiver.
func receiverAnchor(labels []usg.Label, sinkConcepts map[string]bool) string {
	anchor := ""
	for _, l := range labels {
		if !sinkConcepts[l.Concept] {
			continue
		}
		recv := l.Detail[usg.TaintReceiverDetail]
		if recv == "" || (anchor != "" && recv != anchor) {
			return ""
		}
		anchor = recv
	}
	return anchor
}

// FindTaintFlows enumerates source->sink paths; a path yields a flow iff no
// kill-control node lies on it (the control killed the fact). Records near-miss
// controls seen on killed sibling paths.
func FindTaintFlows(store usg.Store, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool, excluded string, charFilters map[string]bool) ([]TaintFlow, error) {
	// int-indexed fast path: run the whole fixpoint on int32 node indices (no string ids/payload
	// in the hot loop) when the store supports it — the basis for keeping only int adjacency +
	// labels resident while ids/payload spill to disk. Produces identical findings.
	if ig, ok := store.(usg.IntGraph); ok {
		return findTaintFlowsInt(ig, store, sourceConcepts, sinkConcepts, taintKinds, killControls, excluded, charFilters), nil
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
	sinkSet := map[string]bool{}
	for c := range sinkConcepts {
		ids, _ := store.NodesWithConcept(c)
		for _, id := range ids {
			sinkSet[id] = true
		}
	}
	if len(sinkSet) == 0 {
		return nil, nil
	}
	sinks := make([]string, 0, len(sinkSet))
	for s := range sinkSet {
		sinks = append(sinks, s)
	}
	sort.Strings(sinks)

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
			if l.Detail["advisory"] == "true" {
				continue
			}
			if killControls[l.Concept] {
				killMemo[id], killConcept[id] = 1, l.Concept
				return true, l.Concept
			}
			if charFilters[l.Concept] && excluded != "" {
				if l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], excluded) {
					killMemo[id], killConcept[id] = 1, l.Concept
					return true, l.Concept
				}
				if removed := l.Detail["removed"]; removed != "" && coversAll(removed, excluded) {
					killMemo[id], killConcept[id] = 1, l.Concept
					return true, l.Concept
				}
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
	// srcFid mirrors the int path: the fidelity rank of the source rooting each
	// node's witness path, so a higher-fidelity source can re-relax the witness
	// (presentation-only; the tainted set — and thus recall — is unchanged).
	srcFid := make(map[string]int, len(srcs)*8)
	nodeSrcFid := func(id string) int {
		best := 0
		for _, l := range labelsOf(id) {
			if sourceConcepts[l.Concept] {
				if r := fidelityWitnessRank(l.Provenance.Fidelity); r > best {
					best = r
				}
			}
		}
		return best
	}
	var nearMiss [][2]string
	contradicted := map[string]bool{}
	// sinks whose own call is a neutralizing control for this rule (the sink label on
	// the argument, the check on the call it flows into). See the emit loop.
	selfChecked := map[string]bool{}
	queue := make([]string, 0, len(srcs)*4)
	for _, s := range srcs {
		if !tainted[s] {
			tainted[s] = true
			srcFid[s] = nodeSrcFid(s)
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if kill, c := killOf(node); kill && !contradicted[node] { // reached a neutralizer: record near-miss, don't propagate
			nearMiss = append(nearMiss, [2]string{node, c})
			continue
		}
		nodeFid := srcFid[node]
		nodeIsSink := sinkSet[node]
		forEachSucc(node, func(dst string) {
			// A neutralizing control and the rule's own sink can land on the same call: a
			// binding describes one call with two outputs, `emit sink <threat> at args[..]`
			// labelling the argument node and `emit check <control> at call` labelling the call
			// node that argument flows into. Java's `Paths.get` is both — a code.FilePathAccess
			// sink at its arguments and a core.PathCanonicalization check at the call — so a
			// path built from tainted components ended the flow at the construction, and
			// everything the constructed value was then handed to (`Files.newInputStream`) was
			// never reported at all. The engine cannot act on both readings at once: it reports
			// the argument as a sink, so it must not also credit the call with neutralizing what
			// it just reported.
			//
			// Narrow on purpose: only the TAINTED value reaching the neutralizer being one of
			// this rule's own sinks disqualifies it. A sanitizer whose sink label sits on a
			// different, untainted argument (jQuery's `$("<div/>", {text: t})` is a
			// core.HtmlEscape check whose code.HtmlRender sink is the constant markup argument,
			// not the escaped one) is an ordinary sanitizer and still absorbs the taint.
			if nodeIsSink {
				if kill, _ := killOf(dst); kill {
					selfChecked[node] = true
					if !contradicted[dst] {
						contradicted[dst] = true
						if tainted[dst] { // already absorbed the taint once — let it propagate now
							queue = append(queue, dst)
						}
					}
				}
			}
			switch {
			case !tainted[dst]:
				tainted[dst] = true
				pred[dst] = node
				srcFid[dst] = nodeFid
				queue = append(queue, dst)
			case nodeFid > srcFid[dst]:
				pred[dst] = node
				srcFid[dst] = nodeFid
				queue = append(queue, dst)
			}
		})
	}
	nearMiss = dropContradicted(nearMiss, func(id string) bool { return contradicted[id] })

	// witness path: walk pred from a tainted node back to its source root (recorded during the
	// fixpoint, so no second traversal). path[0] is a valid source for the (rule, sink) finding.
	wenv := strWitnessEnv{store: store, predOf: pred, taintOf: tainted, succs: forEachSucc}
	pathTo := func(sink string) []string {
		if p, ok := siteAwareWitness(wenv, sink, len(tainted)); ok {
			return p
		}
		return plainWitness(wenv, sink)
	}

	// A sink whose own call is one of this rule's neutralizing controls is a witness of
	// last resort. The definitions say two things about that one call — `emit sink
	// <threat> at args[..]` on the argument, `emit check <control> at call` on the call the
	// argument flows into — and the engine cannot act on both, so it reports the argument
	// only where the same flow reports nothing further along. Java's `Paths.get` builds a
	// path that `Files.newInputStream` then opens: the read is the operation a containment
	// check can be placed at, and reporting the construction as well is what left jmix's
	// CVE-2025-32950 report identical on both revisions — that second witness sits in a
	// helper the fix never touches, so no check placed at the read can cover it. Where
	// nothing further along is reported the construction is the whole of the dangerous
	// operation — jQuery's `$("<span>" + label + "</span>")` parses the markup right there
	// — and it stays the finding.
	//
	// Supersession is keyed on the CALL, not on the argument the witness path happens to
	// run through: `Paths.get(a, b, c)` labels every argument, and reporting the two the
	// path missed would put the witness back in the helper.
	supersededCall := map[string]bool{}
	if len(selfChecked) > 0 {
		for _, sink := range sinks {
			if !tainted[sink] || selfChecked[sink] {
				continue
			}
			if k, _ := killOf(sink); k {
				continue
			}
			for n, steps := sink, 0; steps <= len(tainted); steps++ {
				p, ok := pred[n]
				if !ok {
					break
				}
				if contradicted[p] {
					supersededCall[p] = true
				}
				n = p
			}
		}
	}
	superseded := func(sink string) bool {
		if !selfChecked[sink] || len(supersededCall) == 0 {
			return false
		}
		found := false
		forEachSucc(sink, func(dst string) {
			if supersededCall[dst] {
				found = true
			}
		})
		return found
	}

	// emit one flow per tainted live sink (findings dedup to one per (rule, sink) anyway);
	// witness source = the recorded path's root.
	nm := dedupPairs(nearMiss)
	for _, sink := range sinks {
		if !tainted[sink] {
			continue
		}
		if k, _ := killOf(sink); k { // a sink that is itself a neutralizer sanitizes its own use
			continue
		}
		if superseded(sink) {
			continue
		}
		path := pathTo(sink)
		if recv := receiverAnchor(labelsOf(sink), sinkConcepts); recv != "" && recv != sink {
			// receiver-anchored sink: the fact must be live AT THE RECEIVER, not merely
			// somewhere in the call. Report the receiver's witness so the path shown is
			// the one the finding rests on.
			if !tainted[recv] {
				continue
			}
			if k, _ := killOf(recv); k {
				continue
			}
			if pred[sink] != recv {
				flowsToSink := false
				forEachSucc(recv, func(dst string) {
					if dst == sink {
						flowsToSink = true
					}
				})
				if flowsToSink {
					path = append(pathTo(recv), sink)
				}
			}
		}
		out = append(out, TaintFlow{SourceID: path[0], SinkID: sink, Kind: kind, Path: path, NearMiss: nm})
	}
	return out, nil
}

// findTaintFlowsInt is the int-indexed twin of FindTaintFlows: same boolean live-reachability
// fixpoint and witness semantics, but every per-node structure is an array indexed by node
// int32 (no string maps in the hot loop), and adjacency/labels/concept-sets come from the
// IntGraph. String ids are produced only when emitting findings (NodeID), so the inner loop
// touches no ids or payload — exactly what an out-of-core (ids/payload-on-disk) store needs.
func findTaintFlowsInt(g usg.IntGraph, store usg.Store, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool, excluded string, charFilters map[string]bool) []TaintFlow {
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

	// sink indices (sorted, deduped). No sink means no possible finding, so avoid the fixpoint.
	sinkSet := map[int32]bool{}
	for c := range sinkConcepts {
		for _, i := range g.ConceptNodes(c) {
			sinkSet[i] = true
		}
	}
	if len(sinkSet) == 0 {
		return nil
	}
	sinks := make([]int32, 0, len(sinkSet))
	for i := range sinkSet {
		sinks = append(sinks, i)
	}
	sort.Slice(sinks, func(a, b int) bool { return sinks[a] < sinks[b] })

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
			if l.Detail["advisory"] == "true" {
				continue
			}
			if killControls[l.Concept] {
				killMemo[i] = 1
				killConcept[i] = l.Concept
				return true, l.Concept
			}
			if charFilters[l.Concept] && excluded != "" {
				if l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], excluded) {
					killMemo[i] = 1
					killConcept[i] = l.Concept
					return true, l.Concept
				}
				if removed := l.Detail["removed"]; removed != "" && coversAll(removed, excluded) {
					killMemo[i] = 1
					killConcept[i] = l.Concept
					return true, l.Concept
				}
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
	// srcFid[i] is the fidelity rank of the source rooting node i's witness path.
	// The witness path (pred chain) is presentation-only and does not affect which
	// sinks are tainted (recall), but WHICH source is reported matters: a resolved
	// HttpInput read is a truer witness than the syntactic per-parameter
	// ExternalEntryInput fallback that labels every function param and often sits
	// fewer hops from the sink. We let a higher-fidelity source route re-relax a
	// node's witness even after it is first tainted; fidelity only increases and is
	// bounded, so each node is re-queued at most a couple of times.
	srcFid := make([]int, n)
	nodeSrcFid := func(i int32) int {
		best := 0
		for _, l := range g.LabelsAt(i) {
			if sourceConcepts[l.Concept] {
				if r := fidelityWitnessRank(l.Provenance.Fidelity); r > best {
					best = r
				}
			}
		}
		return best
	}
	var nearMiss []intNearMiss
	contradicted := make([]bool, n)
	selfChecked := make([]bool, n)
	anySelfChecked := false
	isSink := make([]bool, n)
	for _, s := range sinks {
		isSink[s] = true
	}
	queue := make([]int32, 0, len(srcs)*4)
	for _, s := range srcs {
		if !tainted[s] {
			tainted[s] = true
			srcFid[s] = nodeSrcFid(s)
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if kill, c := killOf(node); kill && !contradicted[node] {
			nearMiss = append(nearMiss, intNearMiss{node: node, concept: c})
			continue
		}
		nodeFid := srcFid[node]
		nodeIsSink := isSink[node]
		g.RangeOut(node, "FLOWS", func(dst int32) bool {
			// a neutralizer reached by this rule's own tainted sink at the same call does not
			// absorb the taint, and that sink is not the finding — see the string path for why.
			if nodeIsSink {
				if kill, _ := killOf(dst); kill {
					selfChecked[node] = true
					anySelfChecked = true
					if !contradicted[dst] {
						contradicted[dst] = true
						if tainted[dst] { // already absorbed the taint once — let it propagate now
							queue = append(queue, dst)
						}
					}
				}
			}
			switch {
			case !tainted[dst]:
				tainted[dst] = true
				pred[dst] = node
				srcFid[dst] = nodeFid
				queue = append(queue, dst)
			case nodeFid > srcFid[dst]:
				// a higher-fidelity source route reaches an already-tainted node —
				// prefer it as the witness and re-propagate so the improvement flows
				// on to the sink.
				pred[dst] = node
				srcFid[dst] = nodeFid
				queue = append(queue, dst)
			}
			return true
		})
	}
	nm := make([][2]string, 0, len(nearMiss))
	for _, m := range nearMiss {
		if !contradicted[m.node] {
			nm = append(nm, [2]string{g.NodeID(m.node), m.concept})
		}
	}

	pathTo := func(sink int32) []string {
		id := g.NodeID(sink)
		wenv := intWitnessEnv{g: g, store: store, predOf: pred, taintOf: tainted}
		if p, ok := siteAwareWitness(wenv, id, n); ok {
			return p
		}
		return plainWitness(wenv, id)
	}

	// a sink whose own call is one of this rule's neutralizing controls is reported only
	// where the same witness path reports nothing further along — see the string path.
	supersededCall := make([]bool, n)
	anySupersededCall := false
	if anySelfChecked {
		for _, sink := range sinks {
			if !tainted[sink] || selfChecked[sink] {
				continue
			}
			if k, _ := killOf(sink); k {
				continue
			}
			for i, steps := sink, 0; steps <= n; steps++ {
				p := pred[i]
				if p < 0 {
					break
				}
				if contradicted[p] {
					supersededCall[p] = true
					anySupersededCall = true
				}
				i = p
			}
		}
	}
	superseded := func(sink int32) bool {
		if !selfChecked[sink] || !anySupersededCall {
			return false
		}
		found := false
		g.RangeOut(sink, "FLOWS", func(dst int32) bool {
			if supersededCall[dst] {
				found = true
				return false
			}
			return true
		})
		return found
	}

	// one flow per tainted live sink.
	nm = dedupPairs(nm)
	var out []TaintFlow
	for _, sink := range sinks {
		if !tainted[sink] {
			continue
		}
		if k, _ := killOf(sink); k {
			continue
		}
		if superseded(sink) {
			continue
		}
		path := pathTo(sink)
		// receiver-anchored sink — same rule as the string path: the receiver named by the
		// label must itself carry a live fact, and it roots the reported witness.
		if id := receiverAnchor(g.LabelsAt(sink), sinkConcepts); id != "" {
			recv, ok := g.NodeIndex(id)
			if !ok {
				continue
			}
			if recv != sink {
				if !tainted[recv] {
					continue
				}
				if k, _ := killOf(recv); k {
					continue
				}
				if pred[sink] != recv {
					flowsToSink := false
					g.RangeOut(recv, "FLOWS", func(dst int32) bool {
						if dst == sink {
							flowsToSink = true
							return false
						}
						return true
					})
					if flowsToSink {
						path = append(pathTo(recv), g.NodeID(sink))
					}
				}
			}
		}
		out = append(out, TaintFlow{SourceID: path[0], SinkID: g.NodeID(sink), Kind: kind, Path: path, NearMiss: nm})
	}
	return out
}

// fidelityWitnessRank ranks a label's match fidelity for witness selection: a
// higher rank is a more trustworthy source to report. An empty/unknown fidelity
// is treated as resolved (docs/07), matching the confidence machinery, so only
// an explicitly syntactic source (e.g. the cross-language ExternalEntryInput
// param fallback) ranks below a resolved read.
func fidelityWitnessRank(fid string) int {
	switch fid {
	case "syntactic":
		return 1
	case "semantic":
		return 3
	default: // "resolved" and unknown
		return 2
	}
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

// --- call-site-sensitive witness reconstruction ---------------------------------------------

// witnessEnv is one twin's view of the solved graph, for the witness walk only: pred and
// tainted come from that twin's fixpoint, node payload and adjacency from the store. The
// walk runs once per emitted finding (cold, never in the fixpoint hot loop), so string-id
// conversions on the int side cost nothing that matters.
type witnessEnv interface {
	pred(id string) (string, bool)
	tainted(id string) bool
	nodeType(id string) string
	argIDs(id string) []string // argument node ids recorded on a call node, in slot order
	flowsTo(src, dst string) bool
}

// strWitnessEnv adapts the string-keyed twin's maps and store.
type strWitnessEnv struct {
	store   usg.Store
	predOf  map[string]string
	taintOf map[string]bool
	succs   func(id string, fn func(string))
}

func (e strWitnessEnv) pred(id string) (string, bool) { p, ok := e.predOf[id]; return p, ok }
func (e strWitnessEnv) tainted(id string) bool        { return e.taintOf[id] }
func (e strWitnessEnv) nodeType(id string) string {
	n, ok, _ := e.store.GetNode(id)
	if !ok {
		return ""
	}
	return n.Type
}
func (e strWitnessEnv) argIDs(id string) []string {
	n, ok, _ := e.store.GetNode(id)
	if !ok {
		return nil
	}
	return argIDsOf(n)
}
func (e strWitnessEnv) flowsTo(src, dst string) bool {
	found := false
	e.succs(src, func(d string) {
		if d == dst {
			found = true
		}
	})
	return found
}

// intWitnessEnv adapts the int-indexed twin: pred/tainted are its arrays, payload and
// adjacency resolve through NodeIndex/NodeID so the fixpoint itself stays id-free.
type intWitnessEnv struct {
	g       usg.IntGraph
	store   usg.Store
	predOf  []int32
	taintOf []bool
}

func (e intWitnessEnv) pred(id string) (string, bool) {
	i, ok := e.g.NodeIndex(id)
	if !ok || e.predOf[i] < 0 {
		return "", false
	}
	return e.g.NodeID(e.predOf[i]), true
}
func (e intWitnessEnv) tainted(id string) bool {
	i, ok := e.g.NodeIndex(id)
	return ok && e.taintOf[i]
}
func (e intWitnessEnv) nodeType(id string) string {
	n, ok, _ := e.store.GetNode(id)
	if !ok {
		return ""
	}
	return n.Type
}
func (e intWitnessEnv) argIDs(id string) []string {
	n, ok, _ := e.store.GetNode(id)
	if !ok {
		return nil
	}
	return argIDsOf(n)
}
func (e intWitnessEnv) flowsTo(src, dst string) bool {
	si, ok1 := e.g.NodeIndex(src)
	di, ok2 := e.g.NodeIndex(dst)
	if !ok1 || !ok2 {
		return false
	}
	found := false
	e.g.RangeOut(si, "FLOWS", func(d int32) bool {
		if d == di {
			found = true
			return false
		}
		return true
	})
	return found
}

// argIDsOf reads a call node's recorded argument ids, slots are contiguous from arg0.
func argIDsOf(n usg.Node) []string {
	var out []string
	for i := 0; ; i++ {
		a := n.Prop(usg.ArgPropKey(i))
		if a == "" {
			return out
		}
		out = append(out, a)
	}
}

// plainWitness walks the pred chain from n back to its source root: the witness exactly as
// the fixpoint recorded it. It is the fallback when the site-aware walk cannot terminate,
// so a reported witness is never lost, only left as it was.
func plainWitness(env witnessEnv, n string) []string {
	var rev []string
	for {
		rev = append(rev, n)
		p, ok := env.pred(n)
		if !ok {
			break
		}
		n = p
	}
	reversePath(rev)
	return rev
}

// siteAwareWitness reconstructs a witness that enters and leaves each helper through the
// SAME call site. A lowered function has ONE shared Param/Return pair (context
// insensitivity by design; precision comes from facts, not from cloning callee bodies per
// call site), so taint crosses call sites freely — a value entering a helper at one
// invocation can leave at another's result. Which sinks are tainted must keep working
// that way, but the ORIGIN a finding reports does not: walking pred blindly follows
// whichever call site's argument tainted the shared parameter first, so a helper invoked
// at two sites reports the other site's value as the source. quill's notary reported the
// vulnerable fetch's own response — the sink — as the source of the URL it fetched, when
// the metadata fetch two lines up (through the client wrapper's Do) actually supplied it.
//
// The repair keys on the two structural points where the sharing is visible. Stepping
// backward from a Call node to a Return node is a return attribution — the callee's body
// below that step belongs to that call site, so it opens a frame. Stepping backward out of
// a Param node with a frame open must then leave through an argument OF THAT CALL (the
// arg ids are recorded on the call node); a predecessor from another invocation is a
// crossing, re-anchored to a tainted argument of this call that flows into the parameter.
// Where none exists the crossing stands — that witness is the only real one there is.
//
// The frames form a stack, because wrappers nest: a helper whose body calls a second
// helper and returns its result (`get` -> `do` in quill's client) passes an inner
// attribution between entering the outer helper and reaching its param, and a walk that
// carried only the innermost call site would arrive at the outer param frameless and
// report the crossing the outer repair exists to undo. A function body is entered
// backward only through its own return attribution — FLOWS is the only edge type, and
// taint reaches a body from its param or a source inside it — so the param the walk is
// leaving belongs to exactly the call site on top of the stack.
//
// Every step of a re-anchored witness is a real FLOWS edge between nodes the fixpoint
// marked tainted, so the path shown is still a genuine source→sink path. The repair is
// presentation-only: findings, fingerprints and scores key on (rule, sink) and do not
// move. A re-anchor can in principle revisit a node (a value that left a call and came
// back as its own argument), so the walk carries a step budget and reports failure rather
// than loop, leaving plainWitness as the answer.
func siteAwareWitness(env witnessEnv, sink string, budget int) ([]string, bool) {
	var rev []string
	var frames []string // call sites whose callee bodies the walk is inside, innermost last
	for n := sink; ; {
		if len(rev) > budget {
			return nil, false
		}
		rev = append(rev, n)
		p, ok := env.pred(n)
		if !ok {
			break
		}
		nt, pt := env.nodeType(n), env.nodeType(p)
		switch {
		case nt == "code.Call" && pt == "code.Return":
			frames = append(frames, n) // return attribution: the body below belongs to this call site
		case nt == "code.Param" && len(frames) > 0:
			frame := frames[len(frames)-1]
			if q := siteConsistentArg(env, frame, n, p); q != "" {
				p = q
			}
			frames = frames[:len(frames)-1] // that callee body is left either way
		}
		n = p
	}
	reversePath(rev)
	return rev, true
}

// siteConsistentArg returns the argument of call site frame whose value entered param, or
// "" when pred already is one or no argument of that call carries taint into the parameter.
func siteConsistentArg(env witnessEnv, frame, param, pred string) string {
	for _, a := range env.argIDs(frame) {
		if a == pred {
			return ""
		}
	}
	for _, a := range env.argIDs(frame) {
		if env.tainted(a) && env.flowsTo(a, param) {
			return a
		}
	}
	return ""
}

func reversePath(rev []string) {
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
}

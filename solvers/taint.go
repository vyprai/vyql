// Package solvers implements the flow solvers (docs/08), ported from
// poc/vyql/solvers/. The taint solver realises the normative semantics:
// sanitization is a transfer function on the dataflow fact (not a structural
// "exists" check). A finding exists iff a live tainted fact reaches a sink along
// some path with no neutralizing control on it.
package solvers

import (
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

// nodeConcepts returns the set of concept labels on a node.
func nodeConcepts(store usg.Store, nodeID string) map[string]bool {
	labels, _ := store.Labels(nodeID)
	out := make(map[string]bool, len(labels))
	for _, l := range labels {
		out[l.Concept] = true
	}
	return out
}

func killingControl(concepts, killControls map[string]bool) string {
	for c := range concepts {
		if killControls[c] {
			return c
		}
	}
	return ""
}

// charFilterSound reports whether a node carries a core.CharFilter label (a character-
// filtering replace) and, if so, whether it PROVABLY neutralizes the given dangerous
// characters — its output alphabet is bounded and excludes all of them.
func charFilterSound(store usg.Store, nodeID, dangerous string) (present, sound bool) {
	if dangerous == "" {
		// no dangerous-char set declared for this sink → a filter can never be proven
		// sound (but is still "present" so a weak-filter note can be emitted).
		labels, _ := store.Labels(nodeID)
		for _, l := range labels {
			if l.Concept == "core.CharFilter" {
				return true, false
			}
		}
		return false, false
	}
	labels, _ := store.Labels(nodeID)
	for _, l := range labels {
		if l.Concept != "core.CharFilter" {
			continue
		}
		present = true
		if l.Detail["bounded"] == "true" && excludesAll(l.Detail["alphabet"], dangerous) {
			sound = true
		}
	}
	return
}

func excludesAll(alphabet, dangerous string) bool {
	for _, d := range dangerous {
		if strings.ContainsRune(alphabet, d) {
			return false
		}
	}
	return true
}

func intersects(a, b map[string]bool) bool {
	for c := range a {
		if b[c] {
			return true
		}
	}
	return false
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

	for src := range sourceNodes {
		var livePaths [][]string
		var killed [][2]string
		// Memoize (node, sanitized-state) within this source's traversal. Without it the DFS
		// ENUMERATES every distinct path; a diamond-shaped graph — which a shared helper
		// (one callee reached from N call sites and feeding N results) produces — has an
		// exponential number of paths, so a few hundred call sites take minutes. Each (node,
		// sanitized) pair is explored once: the sinks reachable below a node depend only on the
		// node and whether the prefix was already sanitized, not on which prefix reached it, and
		// only one witness per sink is reported anyway. A node first seen sanitized can still be
		// re-explored unsanitized (the more permissive state) — the bool is part of the key.
		visited := map[string]bool{}

		var dfs func(nodeID string, path []string, sanitized bool, killers [][2]string)
		dfs = func(nodeID string, path []string, sanitized bool, killers [][2]string) {
			vkey := nodeID + "\x00f"
			if sanitized {
				vkey = nodeID + "\x00t"
			}
			if visited[vkey] {
				return
			}
			visited[vkey] = true
			concepts := nodeConcepts(store, nodeID)
			nowSan := sanitized
			local := killers
			if k := killingControl(concepts, killControls); k != "" {
				nowSan = true
				local = append(append([][2]string{}, killers...), [2]string{nodeID, k})
			}
			// A character-filtering replace whose bounded output alphabet excludes every
			// dangerous char for this sink soundly neutralizes the taint (allowlist).
			if _, sound := charFilterSound(store, nodeID, dangerous); sound {
				nowSan = true
				local = append(append([][2]string{}, killers...), [2]string{nodeID, "core.CharFilter"})
			}
			// sink? (DFS starts only at sources, so a sink reached here is
			// genuinely tainted — including the source node itself)
			if intersects(concepts, sinkConcepts) {
				if nowSan {
					killed = append(killed, local...)
				} else {
					cp := append([]string{}, path...)
					livePaths = append(livePaths, cp)
				}
			}
			edges, _ := store.OutEdges(nodeID, "FLOWS")
			for _, e := range edges {
				if !contains(path, e.Dst) {
					next := append(append([]string{}, path...), e.Dst)
					dfs(e.Dst, next, nowSan, local)
				}
			}
		}
		dfs(src, []string{src}, false, nil)

		// one finding per (source, sink) with at least one live path
		bySink := map[string][]string{}
		for _, p := range livePaths {
			sink := p[len(p)-1]
			if _, ok := bySink[sink]; !ok {
				bySink[sink] = p
			}
		}
		for sink, witness := range bySink {
			out = append(out, TaintFlow{
				SourceID: src, SinkID: sink, Kind: kind,
				Path: witness, NearMiss: dedupPairs(killed),
			})
		}
	}
	return out, nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
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

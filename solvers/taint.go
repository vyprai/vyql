// Package solvers implements the flow solvers (docs/08), ported from
// poc/vyql/solvers/. The taint solver realises the normative semantics:
// sanitization is a transfer function on the dataflow fact (not a structural
// "exists" check). A finding exists iff a live tainted fact reaches a sink along
// some path with no neutralizing control on it.
package solvers

import "github.com/vyprai/vyql/usg"

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
func FindTaintFlows(store usg.Store, sourceConcepts, sinkConcepts, taintKinds, killControls map[string]bool) ([]TaintFlow, error) {
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

		var dfs func(nodeID string, path []string, sanitized bool, killers [][2]string)
		dfs = func(nodeID string, path []string, sanitized bool, killers [][2]string) {
			concepts := nodeConcepts(store, nodeID)
			nowSan := sanitized
			local := killers
			if k := killingControl(concepts, killControls); k != "" {
				nowSan = true
				local = append(append([][2]string{}, killers...), [2]string{nodeID, k})
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

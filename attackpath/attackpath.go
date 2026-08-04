// Package attackpath composes typed step relations into cross-domain attack
// Paths (docs/13). Rule FINDINGS feed back
// as `exploits` step edges, so paths strengthen as each domain's rules improve;
// the path engine itself stays small.
package attackpath

import (
	"sort"
	"strings"
)

// Step is one typed hop: reach | exploits | assume | can_access | lateral | runs.
// Witness is the actionability evidence and is kind-dependent: an SG-rule id
// (string) for a reach hop, an ability chain for can_access, or the originating
// *findings.Finding for an `exploits` hop — so the hop carries the nested proof
// (e.g. the taint witness) of the finding it feeds back into the path (docs/13).
type Step struct {
	Src     string
	Dst     string
	Kind    string
	Witness any
}

// Path is a start->target attack path.
type Path struct {
	Nodes []string
	Steps []Step
}

// ChokePoint is a step whose removal severs Severed start->target paths.
type ChokePoint struct {
	Src     string
	Dst     string
	Kind    string
	Severed int
}

// FindPaths does bounded BFS start->target over the step set with monotonic
// progress (no node revisits). Paths are deduped by node sequence.
func FindPaths(steps []Step, start, target map[string]bool, maxHops int) []Path {
	adj := map[string][]Step{}
	for _, s := range steps {
		adj[s.Src] = append(adj[s.Src], s)
	}
	var out []Path
	for st := range start {
		type item struct {
			id    string
			nodes []string
			steps []Step
		}
		queue := []item{{st, []string{st}, nil}}
		seen := map[string]bool{}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if target[cur.id] && len(cur.steps) > 0 {
				key := strings.Join(cur.nodes, ">")
				if !seen[key] {
					seen[key] = true
					out = append(out, Path{Nodes: cur.nodes, Steps: cur.steps})
				}
				continue
			}
			if len(cur.nodes) > maxHops {
				continue
			}
			for _, s := range adj[cur.id] {
				if !contains(cur.nodes, s.Dst) {
					out2 := append(append([]string{}, cur.nodes...), s.Dst)
					st2 := append(append([]Step{}, cur.steps...), s)
					queue = append(queue, item{s.Dst, out2, st2})
				}
			}
		}
	}
	return out
}

// ChokePoints counts, for each distinct step, how many start->target paths its
// removal severs (a min-cut-style remediation ranking). Returns steps that sever
// >= 1 path, sorted by paths-severed descending.
func ChokePoints(steps []Step, start, target map[string]bool) []ChokePoint {
	base := pathKeys(FindPaths(steps, start, target, 8))
	distinct := map[[3]string]bool{}
	for _, s := range steps {
		distinct[[3]string{s.Src, s.Dst, s.Kind}] = true
	}
	var out []ChokePoint
	for key := range distinct {
		var remaining []Step
		for _, s := range steps {
			if [3]string{s.Src, s.Dst, s.Kind} != key {
				remaining = append(remaining, s)
			}
		}
		after := pathKeys(FindPaths(remaining, start, target, 8))
		severed := 0
		for k := range base {
			if !after[k] {
				severed++
			}
		}
		if severed > 0 {
			out = append(out, ChokePoint{Src: key[0], Dst: key[1], Kind: key[2], Severed: severed})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Severed > out[j].Severed })
	return out
}

func pathKeys(ps []Path) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[strings.Join(p.Nodes, ">")] = true
	}
	return m
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

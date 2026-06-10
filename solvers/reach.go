package solvers

import "github.com/vyprai/vyql/usg"

// Hop is one network hop in a reachability witness; Rule names the permitting
// security-group rule / route (the actionability claim, docs/09).
type Hop struct {
	From  string
	To    string
	Rule  string
	Proto string
	Port  string
}

// ReachPath is a permitted network path source->target.
type ReachPath struct {
	SourceID string
	TargetID string
	Hops     []Hop
}

// FindReach BFSes over permitted NET hops; first path to each target. Each hop
// carries the permitting rule from the edge props (docs/09). protocols ""/nil
// = no filter; otherwise a hop's proto must be in the set or "any".
func FindReach(store usg.Store, sourceIDs, targetIDs []string, protocols map[string]bool) ([]ReachPath, error) {
	targets := map[string]bool{}
	for _, t := range targetIDs {
		targets[t] = true
	}
	var out []ReachPath
	for _, s := range sourceIDs {
		seen := map[string]bool{s: true}
		type item struct {
			id   string
			hops []Hop
		}
		queue := []item{{s, nil}}
		reached := map[string][]Hop{}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if targets[cur.id] && len(cur.hops) > 0 {
				if _, ok := reached[cur.id]; !ok {
					reached[cur.id] = cur.hops
				}
				continue
			}
			edges, err := store.OutEdges(cur.id, "NET")
			if err != nil {
				return nil, err
			}
			for _, e := range edges {
				proto := e.Prop("proto")
				if len(protocols) > 0 && proto != "any" && !protocols[proto] {
					continue
				}
				if !seen[e.Dst] {
					seen[e.Dst] = true
					hop := Hop{From: cur.id, To: e.Dst, Rule: e.Prop("rule"), Proto: proto, Port: e.Prop("port")}
					next := append(append([]Hop{}, cur.hops...), hop)
					queue = append(queue, item{e.Dst, next})
				}
			}
		}
		for t, hops := range reached {
			out = append(out, ReachPath{SourceID: s, TargetID: t, Hops: hops})
		}
	}
	return out, nil
}

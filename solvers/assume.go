package solvers

import (
	"encoding/json"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/usg"
)

// privOrder is the privilege partial order (docs/06), loaded from
// vyql/ontology/privileges.json — vocabulary content, not engine code.
var (
	privOnce  sync.Once
	privOrder map[string]int
)

func privRank(level string) int {
	privOnce.Do(func() {
		var doc struct {
			Order []string `json:"order"`
		}
		if err := json.Unmarshal(datadir.MustRead("ontology/privileges.json"), &doc); err != nil {
			panic("solvers: invalid ontology/privileges.json: " + err.Error())
		}
		privOrder = map[string]int{}
		for i, name := range doc.Order {
			privOrder[name] = i + 1
		}
	})
	return privOrder[level]
}

// Step is one escalation ability in a privilege-closure witness (docs/09).
type Step struct {
	From    string
	To      string
	Ability string
}

// AssumePath is a principal -> privilege/principal escalation chain.
type AssumePath struct {
	SourceID string
	TargetID string
	Steps    []Step
}

// FindAssume computes the transitive closure over STEP (escalation) edges;
// witness = the ability chain. A node is a target if it is in targetIDs OR its
// priv_level >= minLevel (e.g. ADMIN matches anything >= admin in the order).
func FindAssume(store usg.Store, sourceIDs, targetIDs []string, minLevel string) ([]AssumePath, error) {
	targets := map[string]bool{}
	for _, t := range targetIDs {
		targets[t] = true
	}
	minLvl := privRank(minLevel)
	var out []AssumePath
	for _, s := range sourceIDs {
		seen := map[string]bool{s: true}
		type item struct {
			id    string
			steps []Step
		}
		queue := []item{{s, nil}}
		reached := map[string][]Step{}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			isTarget := targets[cur.id]
			if minLvl > 0 {
				if n, ok, _ := store.GetNode(cur.id); ok && privRank(n.Prop("priv_level")) >= minLvl {
					isTarget = true
				}
			}
			if isTarget && len(cur.steps) > 0 {
				if _, ok := reached[cur.id]; !ok {
					reached[cur.id] = cur.steps
				}
				continue
			}
			edges, err := store.OutEdges(cur.id, "STEP")
			if err != nil {
				return nil, err
			}
			for _, e := range edges {
				if !seen[e.Dst] {
					seen[e.Dst] = true
					step := Step{From: cur.id, To: e.Dst, Ability: e.Prop("ability")}
					next := append(append([]Step{}, cur.steps...), step)
					queue = append(queue, item{e.Dst, next})
				}
			}
		}
		for t, steps := range reached {
			out = append(out, AssumePath{SourceID: s, TargetID: t, Steps: steps})
		}
	}
	return out, nil
}

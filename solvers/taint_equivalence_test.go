package solvers

import (
	"fmt"
	"testing"

	"github.com/vyprai/vyql/usg"
)

// FindTaintFlows carries two full implementations of the same fixpoint: the
// string-keyed one in this package, and findTaintFlowsInt for stores that
// implement usg.IntGraph. Every store production builds — IntStore and
// BadgerGraph — is an IntGraph, so production only ever runs the int path,
// while the solver's own unit tests build usg.InMemStore and only ever run the
// string path. The dispatch comment claims the two "produce identical
// findings"; nothing checked it, and the two have already drifted apart once on
// witness-selection policy.
//
// These tests run the same graph through both and require the same answer, so a
// change to one that is not mirrored in the other fails here rather than in a
// benchmark score weeks later.

// taintGraph describes one scenario, built into whichever store is under test.
type taintGraph struct {
	name   string
	nodes  []string
	labels map[string]string // node -> concept
	edges  [][2]string
	kills  map[string]bool
}

func (tg taintGraph) build(t *testing.T, s usg.Store) usg.Store {
	t.Helper()
	for _, id := range tg.nodes {
		if err := s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}}); err != nil {
			t.Fatal(err)
		}
	}
	// sorted-by-declaration order: label and edge insertion order must match
	// across stores or the two paths could differ for reasons the test is not
	// trying to measure.
	for _, id := range tg.nodes {
		if c, ok := tg.labels[id]; ok {
			if err := s.AddLabel(id, usg.Label{Concept: c}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, e := range tg.edges {
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func taintScenarios() []taintGraph {
	return []taintGraph{
		{
			name:   "direct source to sink",
			nodes:  []string{"src", "sink"},
			labels: map[string]string{"src": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "sink"}},
		},
		{
			name:   "multi hop",
			nodes:  []string{"src", "a", "b", "sink"},
			labels: map[string]string{"src": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "a"}, {"a", "b"}, {"b", "sink"}},
		},
		{
			name:   "kill control absorbs taint",
			nodes:  []string{"src", "mid", "sink"},
			labels: map[string]string{"src": "test.Source", "mid": "test.Kill", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "mid"}, {"mid", "sink"}},
			kills:  map[string]bool{"test.Kill": true},
		},
		{
			name:   "unreachable sink",
			nodes:  []string{"src", "sink", "island"},
			labels: map[string]string{"src": "test.Source", "island": "test.Sink"},
			edges:  [][2]string{{"src", "sink"}},
		},
		{
			name:   "diamond: two routes to one sink",
			nodes:  []string{"src", "l", "r", "sink"},
			labels: map[string]string{"src": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "l"}, {"src", "r"}, {"l", "sink"}, {"r", "sink"}},
		},
		{
			name:   "cycle does not hang",
			nodes:  []string{"src", "a", "b", "sink"},
			labels: map[string]string{"src": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "a"}, {"a", "b"}, {"b", "a"}, {"b", "sink"}},
		},
		{
			name:   "sink that is its own kill control sanitizes its use",
			nodes:  []string{"src", "sink"},
			labels: map[string]string{"src": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"src", "sink"}},
			kills:  map[string]bool{"test.Sink": true},
		},
		{
			name:   "two sources, one sink",
			nodes:  []string{"s1", "s2", "sink"},
			labels: map[string]string{"s1": "test.Source", "s2": "test.Source", "sink": "test.Sink"},
			edges:  [][2]string{{"s1", "sink"}, {"s2", "sink"}},
		},
	}
}

// summarise reduces flows to a comparable, order-independent form. Witness paths
// are presentation-only, but they are exactly what drifted before, so they are
// compared too.
func summarise(flows []TaintFlow) map[string]bool {
	out := make(map[string]bool, len(flows))
	for _, f := range flows {
		out[fmt.Sprintf("%s->%s via %v", f.SourceID, f.SinkID, f.Path)] = true
	}
	return out
}

func TestTaintIntAndStringPathsAgree(t *testing.T) {
	for _, tg := range taintScenarios() {
		t.Run(tg.name, func(t *testing.T) {
			kills := set()
			for k := range tg.kills {
				kills[k] = true
			}

			strStore := tg.build(t, usg.NewInMemStore())
			if _, isInt := strStore.(usg.IntGraph); isInt {
				t.Fatal("InMemStore now satisfies usg.IntGraph, so this test no longer " +
					"exercises the string path — pick a non-IntGraph store or delete that path")
			}
			strFlows, err := FindTaintFlows(strStore, set("test.Source"), set("test.Sink"),
				set("test.Kind"), kills, "", set())
			if err != nil {
				t.Fatal(err)
			}

			intStore := tg.build(t, usg.NewIntStore(len(tg.nodes)))
			if _, isInt := intStore.(usg.IntGraph); !isInt {
				t.Fatal("IntStore no longer satisfies usg.IntGraph, so both runs took the " +
					"string path and this test proves nothing")
			}
			intFlows, err := FindTaintFlows(intStore, set("test.Source"), set("test.Sink"),
				set("test.Kind"), kills, "", set())
			if err != nil {
				t.Fatal(err)
			}

			gotStr, gotInt := summarise(strFlows), summarise(intFlows)
			if len(gotStr) != len(gotInt) {
				t.Fatalf("flow count differs: string=%d %v, int=%d %v",
					len(strFlows), gotStr, len(intFlows), gotInt)
			}
			for k := range gotStr {
				if !gotInt[k] {
					t.Errorf("string path produced %q, int path did not", k)
				}
			}
			for k := range gotInt {
				if !gotStr[k] {
					t.Errorf("int path produced %q, string path did not", k)
				}
			}
		})
	}
}

// TestProductionStoresTakeTheIntPath pins the dispatch itself. If a store
// production builds stops satisfying usg.IntGraph, FindTaintFlows silently falls
// back to the string implementation: same answers if the test above passes, but
// the whole point of the int path is that the hot loop touches no string ids, so
// the regression would show up only as a large, unexplained slowdown on big
// scans.
func TestProductionStoresTakeTheIntPath(t *testing.T) {
	if _, ok := usg.Store(usg.NewIntStore(1)).(usg.IntGraph); !ok {
		t.Error("IntStore does not satisfy usg.IntGraph — the taint hot path has " +
			"silently fallen back to the string implementation")
	}
}

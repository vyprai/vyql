package graphsync

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// memStore is a tiny in-memory Store for exercising CollectGraph.
func memStore(nodes []usg.Node, labels map[string][]usg.Label) *usg.InMemStore {
	s := usg.NewInMemStore()
	for _, n := range nodes {
		_ = s.AddNode(n)
	}
	for id, ls := range labels {
		for _, l := range ls {
			_ = s.AddLabel(id, l)
		}
	}
	return s
}

// TestDeltaStableAndScoped verifies the change-feed's core guarantees: keys are deterministic
// (a re-run of the same inputs yields identical keys), rows are scoped to their owning module,
// and a module that vanishes is tombstoned exactly once.
func TestDeltaStableAndScoped(t *testing.T) {
	nodes := []usg.Node{
		{ID: "a.js\x1fCall#1", Type: "code.Call", Props: map[string]string{"loc": "a.js:2"}},
		{ID: "b.js\x1fCall#1", Type: "code.Call", Props: map[string]string{"loc": "b.js:1"}},
	}
	labels := map[string][]usg.Label{
		"a.js\x1fCall#1": {{Concept: "code.WeakHash", Provenance: usg.Provenance{Applicator: "js.marks"}}},
	}
	g := memStore(nodes, labels)

	run := func() Delta {
		c := New()
		c.Present("a.js")
		c.Present("b.js")
		c.MarkFresh("a.js")
		c.MarkFresh("b.js")
		c.AddEdges("a.js", []usg.Edge{{Type: "FLOWS", Src: "a.js\x1fCall#1", Dst: "b.js\x1fCall#1"}})
		_ = c.CollectGraph(g, map[string]bool{"a.js": true, "b.js": true})
		d, _ := c.Finalize(nil)
		return d
	}
	d1, d2 := run(), run()

	aMod, bMod := ModuleID("a.js"), ModuleID("b.js")
	// deterministic: same keys across runs.
	if d1.NodeMods[aMod][0].Key != d2.NodeMods[aMod][0].Key {
		t.Fatal("node keys not deterministic across runs")
	}
	// scoping: a.js node row owned by a.js; the cross-module edge owned by its creator (a.js).
	if len(d1.NodeMods[aMod]) != 1 || d1.NodeMods[aMod][0].Module != aMod {
		t.Fatalf("a.js node mods wrong: %+v", d1.NodeMods[aMod])
	}
	if len(d1.EdgeMods[aMod]) != 1 || d1.EdgeMods[aMod][0].Module != aMod {
		t.Fatalf("creator-attributed edge not under a.js: %+v", d1.EdgeMods)
	}
	if len(d1.EdgeMods[bMod]) != 0 {
		t.Fatalf("b.js should own no edges (it didn't create the cross-module edge): %+v", d1.EdgeMods[bMod])
	}
	// the WeakHash label is owned by a.js, none by b.js.
	if len(d1.LabelMods[aMod]) != 1 || len(d1.LabelMods[bMod]) != 0 {
		t.Fatalf("label scoping wrong: a=%v b=%v", d1.LabelMods[aMod], d1.LabelMods[bMod])
	}

	// tombstone: next scan drops b.js entirely.
	c := New()
	c.Present("a.js")
	c.MarkFresh("a.js")
	_ = c.CollectGraph(g, map[string]bool{"a.js": true})
	d3, _ := c.Finalize(map[string]bool{"a.js": true, "b.js": true})
	if len(d3.Deleted) != 1 || d3.Deleted[0] != bMod {
		t.Fatalf("expected b.js tombstoned exactly once, got %v", d3.Deleted)
	}
}

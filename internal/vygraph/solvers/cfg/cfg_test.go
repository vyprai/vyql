package cfg

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/lower"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

// A guard inside the same then-branch dominates a sink in that branch; a guard
// in a sibling branch does not; a guard before the if dominates.
const src = `def handler(req):
    auth(req)
    data = load(req)
    if data:
        sink_a(data)
    else:
        sink_b(data)
`

func built(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	fe := python.New(g)
	if err := fe.Extract("app.py", []byte(src)); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if err := lower.Run(g, fe.Imports); err != nil {
		t.Fatal(err)
	}
	return g
}

func callByPath(t *testing.T, g *graph.Store, path string) graph.Node {
	t.Helper()
	for _, n := range g.NodesOfType("code.Call") {
		if v, ok := n.Fields.Get("path"); ok && v.S == path {
			return n
		}
	}
	t.Fatalf("no Call with path %q", path)
	return graph.Node{}
}

func TestGuardBeforeIfDominatesBothBranches(t *testing.T) {
	g := built(t)
	auth := callByPath(t, g, "auth")
	a := callByPath(t, g, "sink_a")
	b := callByPath(t, g, "sink_b")
	for _, sink := range []graph.Node{a, b} {
		holds, proof, err := Dominates(g, auth.ID, sink.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !holds {
			t.Fatalf("auth must dominate %s (region %s)", sink.ID, region(t, g, sink.ID))
		}
		if proof == nil || !strings.Contains(proof.Render(), "dominates") {
			t.Fatal("the dominance proof must render")
		}
	}
}

func TestGuardInSiblingBranchDoesNotDominate(t *testing.T) {
	g := built(t)
	a := callByPath(t, g, "sink_a")
	b := callByPath(t, g, "sink_b")
	holds, _, err := Dominates(g, a.ID, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if holds {
		t.Fatal("a guard in the then-branch must not dominate a sink in the else-branch")
	}
}

func TestPostDominanceForFinallyShape(t *testing.T) {
	const trySrc = `def f(x):
    res = open(x)
    try:
        use(res)
    finally:
        close(res)
`
	s := graph.NewSchemas()
	nir.Register(s)
	g := graph.New(s)
	fe := python.New(g)
	if err := fe.Extract("t.py", []byte(trySrc)); err != nil {
		t.Fatal(err)
	}
	if err := lower.Run(g, fe.Imports); err != nil {
		t.Fatal(err)
	}
	use := callByPath(t, g, "use")
	close_ := callByPath(t, g, "close")
	holds, proof, err := PostDominates(g, close_.ID, use.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !holds {
		t.Fatalf("close in finally must post-dominate use (regions %q, %q)", region(t, g, close_.ID), region(t, g, use.ID))
	}
	if proof == nil || !strings.Contains(proof.Render(), "postdominates") {
		t.Fatal("the post-dominance proof must render")
	}
}

// Degradation: with no Region/Order the predicate is unprovable — the
// suppressor fails and the finding survives. Presence is only ever evidence.
func TestMissingMetadataIsUnprovable(t *testing.T) {
	s := graph.NewSchemas()
	nir.Register(s)
	g := graph.New(s)
	var f1 graph.Fields
	var f2 graph.Fields
	// No region/order stamped.
	f1.Set("local", graph.Str("g"))
	f2.Set("local", graph.Str("s"))
	if err := g.AddNode(graph.Node{ID: "g1", Type: "code.Name", Layer: graph.LayerLow, Fields: f1}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddNode(graph.Node{ID: "s1", Type: "code.Name", Layer: graph.LayerLow, Fields: f2}); err != nil {
		t.Fatal(err)
	}
	holds, _, err := Dominates(g, "g1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if holds {
		t.Fatal("dominance must never be fabricated without region/order")
	}
}

func TestGuardDischargeWithColocationEvidence(t *testing.T) {
	g := built(t)
	a := callByPath(t, g, "sink_a")

	// A guard concept labelled on the pre-if auth call: dominates → holds.
	labelled := func(id string) bool { return id == callByPath(t, g, "auth").ID }
	holds, ev := GuardDischarge(g, a.ID, "code.AuthenticationCheck", labelled)
	if !holds || ev != "" {
		t.Fatalf("dominating guard: holds=%v evidence=%q", holds, ev)
	}

	// A guard labelled on the sibling sink: present in the function but not
	// enclosing → unprovable, colocation attached as evidence.
	sibling := callByPath(t, g, "sink_b")
	labelledSibling := func(id string) bool { return id == sibling.ID }
	holds, ev = GuardDischarge(g, a.ID, "code.AuthenticationCheck", labelledSibling)
	if holds {
		t.Fatal("a sibling-branch guard must not discharge guarded_by")
	}
	if ev == "" {
		t.Fatal("same-function presence must attach as colocation evidence")
	}
}

func region(t *testing.T, g *graph.Store, id string) string {
	t.Helper()
	n, _ := g.Node(id)
	v, ok := n.Fields.Get("region")
	if !ok {
		return ""
	}
	return v.S
}

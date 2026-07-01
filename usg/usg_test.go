package usg

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

// genGraph builds a deterministic code-heavy graph (mirrors poc/bench/graph_gen).
func genGraph(nNodes, avgDeg, nConcepts int, seed int64) ([]Node, []Edge, [][2]string) {
	rnd := rand.New(rand.NewSource(seed))
	codeTypes := []string{"code.Call", "code.Attr", "code.Param", "code.Const", "code.Format"}
	cloudTypes := []string{"cloud.Bucket", "cloud.Database", "identity.Role"}
	var nodes []Node
	var labels [][2]string
	for i := 0; i < nNodes; i++ {
		t := codeTypes[rnd.Intn(len(codeTypes))]
		if rnd.Float64() >= 0.85 {
			t = cloudTypes[rnd.Intn(len(cloudTypes))]
		}
		id := fmt.Sprintf("n%d", i)
		nodes = append(nodes, Node{ID: id, Type: t})
		if rnd.Float64() < 0.1 {
			labels = append(labels, [2]string{id, fmt.Sprintf("CONCEPT_%d", rnd.Intn(nConcepts))})
		}
	}
	var edges []Edge
	for i := 0; i < nNodes*avgDeg; i++ {
		a, b := rnd.Intn(nNodes), rnd.Intn(nNodes)
		edges = append(edges, Edge{Type: "FLOWS", Src: fmt.Sprintf("n%d", a), Dst: fmt.Sprintf("n%d", b)})
	}
	return nodes, edges, labels
}

func load(t *testing.T, s Store, nodes []Node, edges []Edge, labels [][2]string) {
	t.Helper()
	for _, n := range nodes {
		if err := s.AddNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range edges {
		if err := s.AddEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range labels {
		if err := s.AddLabel(l[0], Label{Concept: l[1]}); err != nil {
			t.Fatal(err)
		}
	}
}

func sorted(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func dsts(edges []Edge) []string {
	var out []string
	for _, e := range edges {
		out = append(out, e.Dst)
	}
	return sorted(out)
}

// TestStoreEquivalence: the in-memory and BadgerDB stores must return identical
// results for the hot operations — the premise of ADR 0002's hybrid decision.
func TestStoreEquivalence(t *testing.T) {
	nodes, edges, labels := genGraph(3000, 4, 20, 7)

	mem := NewInMemStore()
	bdg, err := OpenBadger(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer bdg.Close()

	load(t, mem, nodes, edges, labels)
	load(t, bdg, nodes, edges, labels)

	// concept lookups identical
	for i := 0; i < 20; i++ {
		c := fmt.Sprintf("CONCEPT_%d", i)
		m, _ := mem.NodesWithConcept(c)
		b, _ := bdg.NodesWithConcept(c)
		if a, e := sorted(m), sorted(b); !equal(a, e) {
			t.Fatalf("concept %s mismatch: mem=%v badger=%v", c, a, e)
		}
	}

	// out-edge traversal + BFS identical on a sample
	rnd := rand.New(rand.NewSource(99))
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("n%d", rnd.Intn(3000))
		me, _ := mem.OutEdges(id, "")
		be, _ := bdg.OutEdges(id, "")
		if !equal(dsts(me), dsts(be)) {
			t.Fatalf("out-edges of %s mismatch: mem=%v badger=%v", id, dsts(me), dsts(be))
		}
		if i < 30 {
			ms, _ := BFS(mem, id, "FLOWS", 5)
			bs, _ := BFS(bdg, id, "FLOWS", 5)
			if !equalSet(ms, bs) {
				t.Fatalf("BFS from %s mismatch: |mem|=%d |badger|=%d", id, len(ms), len(bs))
			}
		}
	}
}

func TestCompactFlowEdgesPreserveStoreAPI(t *testing.T) {
	makeStores := func(t *testing.T) []struct {
		name string
		s    Store
		g    IntGraph
		done func()
	} {
		t.Helper()
		intStore := NewIntStore(0)
		bdg, err := OpenBadgerGraph(":memory:", 0)
		if err != nil {
			t.Fatalf("OpenBadgerGraph: %v", err)
		}
		return []struct {
			name string
			s    Store
			g    IntGraph
			done func()
		}{
			{name: "intstore", s: intStore, g: intStore, done: func() {}},
			{name: "badgergraph", s: bdg, g: bdg, done: func() { _ = bdg.Close() }},
		}
	}

	for _, tc := range makeStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.done()
			for _, id := range []string{"a", "b", "c", "d"} {
				if err := tc.s.AddNode(Node{ID: id, Type: "code.Node"}); err != nil {
					t.Fatalf("AddNode(%s): %v", id, err)
				}
			}
			if err := tc.s.AddEdge(Edge{Type: "FLOWS", Src: "a", Dst: "b"}); err != nil {
				t.Fatalf("AddEdge compact flow: %v", err)
			}
			if err := tc.s.AddEdge(Edge{Type: "FLOWS", Src: "a", Dst: "c", Props: map[string]string{"kind": "decorated"}}); err != nil {
				t.Fatalf("AddEdge prop flow: %v", err)
			}
			if err := tc.s.AddEdge(Edge{Type: "NET", Src: "a", Dst: "d", Props: map[string]string{"rule": "net"}}); err != nil {
				t.Fatalf("AddEdge net: %v", err)
			}
			if ok := tc.s.(interface{ AddFlowEdgeIfPresent(string, string) bool }).AddFlowEdgeIfPresent("a", "missing"); ok {
				t.Fatal("AddFlowEdgeIfPresent should report missing destination")
			}
			if ok := tc.s.(interface{ AddFlowEdgeIfPresent(string, string) bool }).AddFlowEdgeIfPresent("b", "d"); !ok {
				t.Fatal("AddFlowEdgeIfPresent should append existing endpoints")
			}

			flows, _ := tc.s.OutEdges("a", "FLOWS")
			if got, want := dsts(flows), []string{"b", "c"}; !equal(got, want) {
				t.Fatalf("OutEdges(FLOWS) dsts=%v want %v; edges=%+v", got, want, flows)
			}
			var sawDecorated bool
			for _, e := range flows {
				if e.Dst == "c" && e.Props["kind"] == "decorated" {
					sawDecorated = true
				}
			}
			if !sawDecorated {
				t.Fatalf("prop-bearing FLOWS edge lost props: %+v", flows)
			}

			all, _ := tc.s.OutEdges("a", "")
			if got, want := dsts(all), []string{"b", "c", "d"}; !equal(got, want) {
				t.Fatalf("OutEdges(all) dsts=%v want %v; edges=%+v", got, want, all)
			}

			inB, _ := tc.s.InEdges("b", "FLOWS")
			if len(inB) != 1 || inB[0].Src != "a" || inB[0].Dst != "b" {
				t.Fatalf("compact InEdges(FLOWS) mismatch: %+v", inB)
			}
			inC, _ := tc.s.InEdges("c", "FLOWS")
			if len(inC) != 1 || inC[0].Src != "a" || inC[0].Props["kind"] != "decorated" {
				t.Fatalf("prop InEdges(FLOWS) mismatch: %+v", inC)
			}

			var ranged []string
			tc.g.RangeOut(0, "FLOWS", func(dst int32) bool {
				ranged = append(ranged, tc.g.NodeID(dst))
				return true
			})
			if got, want := sorted(ranged), []string{"b", "c"}; !equal(got, want) {
				t.Fatalf("RangeOut(FLOWS)=%v want %v", got, want)
			}
			var rangedB []string
			tc.g.RangeOut(1, "FLOWS", func(dst int32) bool {
				rangedB = append(rangedB, tc.g.NodeID(dst))
				return true
			})
			if got, want := sorted(rangedB), []string{"d"}; !equal(got, want) {
				t.Fatalf("RangeOut fast-added flow=%v want %v", got, want)
			}
		})
	}
}

// TestBasicOps: point lookups, labels, in-edges round-trip through Badger.
func TestBasicOps(t *testing.T) {
	bdg, err := OpenBadger(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer bdg.Close()

	bdg.AddNode(Node{ID: "a", Type: "code.Call", Props: map[string]string{"loc": "x.go:1"}})
	bdg.AddNode(Node{ID: "b", Type: "code.X"})
	bdg.AddEdge(Edge{Type: "FLOWS", Src: "a", Dst: "b"})
	bdg.AddLabel("a", Label{Concept: "HTTP_INPUT", Provenance: Provenance{Applicator: "flask"}})

	n, ok, _ := bdg.GetNode("a")
	if !ok || n.Prop("loc") != "x.go:1" {
		t.Fatalf("GetNode round-trip failed: %+v ok=%v", n, ok)
	}
	if _, ok, _ := bdg.GetNode("missing"); ok {
		t.Fatal("GetNode should report missing")
	}
	ins, _ := bdg.InEdges("b", "FLOWS")
	if len(ins) != 1 || ins[0].Src != "a" {
		t.Fatalf("InEdges failed: %+v", ins)
	}
	labels, _ := bdg.Labels("a")
	if len(labels) != 1 || labels[0].Concept != "HTTP_INPUT" || labels[0].Provenance.Applicator != "flask" {
		t.Fatalf("Labels round-trip failed: %+v", labels)
	}
	ns, _ := bdg.NodesWithConcept("HTTP_INPUT")
	if len(ns) != 1 || ns[0] != "a" {
		t.Fatalf("NodesWithConcept failed: %+v", ns)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

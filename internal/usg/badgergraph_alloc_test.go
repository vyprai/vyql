package usg

import (
	"fmt"
	"slices"
	"testing"
)

func residentGraph(t *testing.T, n int) *BadgerGraph {
	t.Helper()
	g, err := OpenBadgerGraph(t.TempDir(), 64<<20, 0) // detCap 0 = unbounded, nothing spills
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	for i := 0; i < n; i++ {
		if err := g.AddNode(Node{ID: fmt.Sprintf("n%03d", i), Type: "Call", Loc: "f.go:1",
			Props: map[string]string{"callee_path": "a.b", "method": "b"}}); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	return g
}

func TestResidentGetNodeDoesNotDecode(t *testing.T) {
	g := residentGraph(t, 100)
	allocs := testing.AllocsPerRun(200, func() {
		if _, ok, _ := g.GetNode("n000"); !ok {
			t.Fatal("node missing")
		}
	})
	// Struct-served reads share the stored strings and props map: no decode, no copies.
	if allocs > 1 {
		t.Errorf("GetNode allocated %.1f objects per call on resident detail, want <= 1", allocs)
	}
}

func TestResidentRangeNodesOfTypeDoesNotDecode(t *testing.T) {
	g := residentGraph(t, 100)
	allocs := testing.AllocsPerRun(20, func() {
		g.RangeNodesOfType("Call", func(n Node) bool { return true })
	})
	if allocs > 5 { // iteration scaffolding only, not 100 nodes' worth of decode
		t.Errorf("RangeNodesOfType allocated %.1f objects per pass, want <= 5", allocs)
	}
}

// typeOf runs inside every AddNode to detect type changes, so on a graph that
// has started spilling it must be served from the resident core — a badger
// point-read per added node turns the build quadratic-ish in disk traffic.
func TestTypeOfSpilledNodeStaysResident(t *testing.T) {
	g, err := OpenBadgerGraph(t.TempDir(), 64<<20, 1) // detCap 1 byte: spill after every add
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = g.Close() }()
	if err := g.AddNode(Node{ID: "x", Type: "Call", Loc: "f.go:1"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := g.typeOf(0); got != "Call" {
		t.Fatalf("typeOf = %q, want Call", got)
	}
	allocs := testing.AllocsPerRun(100, func() { _ = g.typeOf(0) })
	if allocs > 0 {
		t.Errorf("typeOf allocated %.1f objects per call on a spilled node, want 0 (badger-free)", allocs)
	}
}

func TestSpilledDetailStillRoundTrips(t *testing.T) {
	g, err := OpenBadgerGraph(t.TempDir(), 64<<20, 1) // detCap 1 byte: spill after every add
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = g.Close() }()
	want := Node{ID: "x", Type: "Call", Loc: "f.go:9", Scope: "s",
		Props: map[string]string{"k": "v"}}
	if err := g.AddNode(want); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, ok, err := g.GetNode("x")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Type != want.Type || got.Loc != want.Loc || got.Scope != want.Scope || got.Props["k"] != "v" {
		t.Errorf("spilled round-trip mismatch: %+v", got)
	}
}

func TestSpilledDenseNodeAccessPreservesIndexesAndHotProps(t *testing.T) {
	g, err := OpenBadgerGraph(t.TempDir(), 64<<20, 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = g.Close() }()
	wants := []Node{
		{ID: "call-0", Type: "Call", Loc: "f.go:1", Method: "Send", CalleePath: "mail.Send", StrArgs: "hello", Vkind: "Resolved"},
		{ID: "name-1", Type: "Name", Loc: "f.go:2", Props: map[string]string{"name": "recipient"}},
	}
	for _, n := range wants {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	if got := g.TypeNodeIndexes("Call"); !slices.Equal(got, []int32{0}) {
		t.Fatalf("Call indexes = %v, want [0]", got)
	}
	var indexes []int32
	var nodes []Node
	g.RangeNodeIndexes(func(i int32, n Node) bool {
		indexes = append(indexes, i)
		nodes = append(nodes, n)
		return true
	})
	if !slices.Equal(indexes, []int32{0, 1}) {
		t.Fatalf("range indexes = %v, want [0 1]", indexes)
	}
	if len(nodes) != 2 || nodes[0].Method != "Send" || nodes[0].CalleePath != "mail.Send" ||
		nodes[0].StrArgs != "hello" || nodes[0].Vkind != "Resolved" {
		t.Fatalf("range lost inline hot properties: %+v", nodes)
	}
	if got, ok := g.NodeAtIndex(0); !ok || got.ID != "call-0" || got.Method != "Send" {
		t.Fatalf("NodeAtIndex(0) = %+v, %v", got, ok)
	}
	if _, ok := g.NodeAtIndex(-1); ok {
		t.Fatal("NodeAtIndex(-1) unexpectedly succeeded")
	}
	if _, ok := g.NodeAtIndex(2); ok {
		t.Fatal("NodeAtIndex(2) unexpectedly succeeded")
	}
}

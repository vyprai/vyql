package usg

import (
	"fmt"
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

package usg

import (
	"fmt"
	"testing"
)

func TestBadgerGraphRangeNodesUsesStableIndexOrder(t *testing.T) {
	g, err := OpenBadgerGraph(":memory:", 0)
	if err != nil {
		t.Fatalf("OpenBadgerGraph: %v", err)
	}
	defer g.Close()
	g.detCapByte = 1
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("n%03d", i)
		if err := g.AddNode(Node{ID: id, Type: "code.Node", Loc: id}); err != nil {
			t.Fatalf("AddNode(%s): %v", id, err)
		}
	}
	g.detCapByte = 0
	if err := g.AddNode(Node{ID: "n001", Type: "code.Node", Loc: "updated"}); err != nil {
		t.Fatalf("AddNode update: %v", err)
	}

	var got []string
	g.RangeNodes(func(n Node) bool {
		got = append(got, n.ID)
		if n.ID == "n001" && n.Loc != "updated" {
			t.Fatalf("resident updated detail was not used: %+v", n)
		}
		return true
	})
	if len(got) != 300 {
		t.Fatalf("RangeNodes emitted %d nodes, want 300", len(got))
	}
	for i, id := range got {
		want := fmt.Sprintf("n%03d", i)
		if id != want {
			t.Fatalf("RangeNodes[%d] = %s, want %s", i, id, want)
		}
	}
}

package usg

import (
	"fmt"
	"testing"
)

func TestBadgerGraphRangeNodesUsesStableIndexOrder(t *testing.T) {
	g, err := OpenBadgerGraph(":memory:", 0, 0)
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

// A node's hottest match properties -- method, callee_path, str_args, vkind -- are carried inline
// on Node rather than in its Props map. BadgerGraph dropped all four, so passing --max-ram made
// Node.Prop("method") return "" and every ByMethod binding spec silently stopped matching: the
// flag changed which findings were reported. Both stores must answer identically.
func TestBadgerGraphPreservesInlineHotProps(t *testing.T) {
	n := Node{
		ID: "n1", Type: "code.Call", Loc: "a.go:1", Region: "a.go/fn1", Order: 7, HasOrder: true,
		Method: "query", CalleePath: "db.query", StrArgs: "SELECT", Vkind: "Name",
	}
	for _, tc := range []struct {
		name string
		open func(t *testing.T) Store
	}{
		{"IntStore", func(*testing.T) Store { return NewIntStore(4) }},
		{"BadgerGraph", func(t *testing.T) Store {
			g, err := OpenBadgerGraph(t.TempDir(), 1<<20, 0)
			if err != nil {
				t.Fatalf("OpenBadgerGraph: %v", err)
			}
			t.Cleanup(func() { _ = g.Close() })
			return g
		}},
		{"BadgerGraph/spilled", func(t *testing.T) Store {
			// detailBufBytes=1 forces every AddNode to spill, so the read goes through
			// encDet/decDet rather than the resident struct.
			g, err := OpenBadgerGraph(t.TempDir(), 1<<20, 1)
			if err != nil {
				t.Fatalf("OpenBadgerGraph: %v", err)
			}
			t.Cleanup(func() { _ = g.Close() })
			return g
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.open(t)
			if err := s.AddNode(n); err != nil {
				t.Fatalf("AddNode: %v", err)
			}
			got, ok, err := s.GetNode("n1")
			if err != nil || !ok {
				t.Fatalf("GetNode: ok=%v err=%v", ok, err)
			}
			for _, p := range []struct{ key, want string }{
				{"method", "query"}, {"callee_path", "db.query"},
				{"str_args", "SELECT"}, {"vkind", "Name"},
			} {
				if g := got.Prop(p.key); g != p.want {
					t.Errorf("Prop(%q) = %q, want %q", p.key, g, p.want)
				}
			}
		})
	}
}

// Binding application shares one node index per pass by keying on the store's structural epoch.
// A store lacking StructEpoch does not fail: bindings.storeIndexes type-asserts for it and, on a
// miss, hands back a fresh empty index every call -- so every applicator rebuilds from scratch,
// in the low-RAM mode chosen because resources were already tight. Both stores must stamp the
// same way: change on structure, hold steady across labels.
func TestStoresStampStructuralEpochAlike(t *testing.T) {
	open := map[string]func(t *testing.T) Store{
		"IntStore": func(*testing.T) Store { return NewIntStore(4) },
		"BadgerGraph": func(t *testing.T) Store {
			g, err := OpenBadgerGraph(t.TempDir(), 1<<20, 0)
			if err != nil {
				t.Fatalf("OpenBadgerGraph: %v", err)
			}
			t.Cleanup(func() { _ = g.Close() })
			return g
		},
	}
	for name, mk := range open {
		t.Run(name, func(t *testing.T) {
			s := mk(t)
			ep, ok := s.(interface{ StructEpoch() uint64 })
			if !ok {
				t.Fatalf("%s does not implement StructEpoch; shared binding indexes silently degrade", name)
			}
			_ = s.AddNode(Node{ID: "a", Type: "code.Call"})
			_ = s.AddNode(Node{ID: "b", Type: "code.Arg"})
			afterNodes := ep.StructEpoch()

			_ = s.AddEdge(Edge{Type: "FLOWS", Src: "a", Dst: "b"})
			afterEdge := ep.StructEpoch()
			if afterEdge == afterNodes {
				t.Error("epoch did not change on AddEdge; a stale index would be reused")
			}

			_ = s.AddLabel("a", Label{Concept: "code.SqlExecution"})
			if got := ep.StructEpoch(); got != afterEdge {
				t.Errorf("epoch changed on AddLabel (%d -> %d); the index would rebuild every applicator", afterEdge, got)
			}
		})
	}
}

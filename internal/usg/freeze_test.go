package usg

import "testing"

func TestPackedAdjRoundTripAndMutation(t *testing.T) {
	rows := [][]int32{{1, 2}, nil, {0}}
	p, ok := packAdj(rows)
	if !ok {
		t.Fatal("small adjacency should pack")
	}
	if got, want := len(p.offsets), len(rows)+1; got != want {
		t.Fatalf("offsets=%d want %d", got, want)
	}
	for i, want := range rows {
		got := p.at(int32(i))
		if len(got) != len(want) {
			t.Fatalf("row %d len=%d want %d", i, len(got), len(want))
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("row %d=%v want %v", i, got, want)
			}
		}
	}
	unpacked := p.unpack()
	unpacked[0][0] = 9
	if p.at(0)[0] != 1 {
		t.Fatal("unpack must restore independently appendable rows")
	}
}

func TestIntStoreFreezeReleasesRows(t *testing.T) {
	s := NewIntStore(3)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.AddNode(Node{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddEdge(Edge{Type: "FLOWS", Src: "a", Dst: "b"}); err != nil {
		t.Fatal(err)
	}
	s.Freeze()
	if s.flowOut != nil || s.flowIn != nil {
		t.Fatal("mutable rows retained after freeze")
	}
	if s.labels != nil || s.conceptHas != nil {
		t.Fatal("mutable label rows or build-only concept set retained after freeze")
	}
	if got := s.flowOutAt(0); len(got) != 1 || got[0] != 1 {
		t.Fatalf("packed row=%v want [1]", got)
	}
	if !s.AddFlowEdgeIfPresent("a", "c") {
		t.Fatal("mutation after freeze failed")
	}
	if s.flowOutPacked.offsets != nil || len(s.flowOut) != 3 {
		t.Fatal("mutation did not restore mutable rows")
	}
	if got := s.flowOutAt(0); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("thawed row=%v want [1 2]", got)
	}
	if err := s.AddLabel("a", Label{Concept: "code.Input"}); err != nil {
		t.Fatal(err)
	}
	if got := s.LabelsAt(0); len(got) != 1 || got[0].Concept != "code.Input" {
		t.Fatalf("labels after thaw=%v", got)
	}
	s.Freeze()
	if got, err := s.Labels("a"); err != nil || len(got) != 1 {
		t.Fatalf("Labels on frozen graph=%v err=%v", got, err)
	}
	if got := s.LabelsOf("a"); len(got) != 1 {
		t.Fatalf("LabelsOf on frozen graph=%v", got)
	}
}

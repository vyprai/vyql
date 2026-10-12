package graph

import "testing"

func testSchemas(t *testing.T) *Schemas {
	t.Helper()
	s := NewSchemas()
	must := func(ts *TypeSchema) {
		if err := s.Register(ts); err != nil {
			t.Fatalf("Register(%s): %v", ts.Type, err)
		}
	}
	must(&TypeSchema{Type: "code.Call", Layer: LayerLow,
		Fields: []FieldSpec{{Name: "callee", Kind: KindString}}, Key: []string{"callee"}})
	must(&TypeSchema{Type: "code.Entrypoint", Layer: LayerHigh,
		Fields: []FieldSpec{{Name: "route", Kind: KindString}}, Key: []string{"route"}})
	must(&TypeSchema{Type: EdgeBacks, Layer: LayerHigh, Fields: nil, Key: nil})
	return s
}

func TestAddNodeValidatesAgainstSchema(t *testing.T) {
	g := New(testSchemas(t))
	var bad Fields
	bad.Set("callee", Int(7)) // declared string
	if err := g.AddNode(Node{ID: "n1", Type: "code.Call", Layer: LayerLow, Fields: bad}); err == nil {
		t.Fatal("AddNode must reject a field whose kind contradicts the schema")
	}
	if err := g.AddNode(Node{ID: "n2", Type: "code.Unknown", Layer: LayerLow}); err == nil {
		t.Fatal("AddNode must reject an unregistered type")
	}
}

func TestAddNodeRejectsLayerMismatch(t *testing.T) {
	g := New(testSchemas(t))
	err := g.AddNode(Node{ID: "n1", Type: "code.Call", Layer: LayerHigh}) // schema says low
	if err == nil {
		t.Fatal("a node whose Layer contradicts its schema must be rejected")
	}
}

func TestQueriesByTypeLayerAndLabel(t *testing.T) {
	g := New(testSchemas(t))
	var cf Fields
	cf.Set("callee", Str("db.Query"))
	if err := g.AddNode(Node{ID: "low1", Type: "code.Call", Layer: LayerLow, Fields: cf}); err != nil {
		t.Fatal(err)
	}
	var ef Fields
	ef.Set("route", Str("/admin"))
	if err := g.AddNode(Node{ID: "high1", Type: "code.Entrypoint", Layer: LayerHigh, Fields: ef}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLabel(Label{Target: "high1", Concept: "AdminRoute", Confidence: 1}); err != nil {
		t.Fatal(err)
	}

	if got := g.NodesOfType("code.Call"); len(got) != 1 || got[0].ID != "low1" {
		t.Fatalf("NodesOfType = %+v", got)
	}
	if got := g.NodesOfLayer(LayerHigh); len(got) != 1 || got[0].ID != "high1" {
		t.Fatalf("NodesOfLayer(high) = %+v", got)
	}
	if got := g.LabelsOn("high1"); len(got) != 1 || got[0].Concept != "AdminRoute" {
		t.Fatalf("LabelsOn = %+v", got)
	}
}

func TestAddLabelDedupesByKeyAndKeepsDistinctProvenance(t *testing.T) {
	g := New(testSchemas(t))
	var ef Fields
	ef.Set("route", Str("/admin"))
	_ = g.AddNode(Node{ID: "high1", Type: "code.Entrypoint", Layer: LayerHigh, Fields: ef})

	same := Label{Target: "high1", Concept: "AdminRoute", Confidence: 0.5,
		Prov: Provenance{Producer: "p1", Build: BuildLabeled, Trust: TrustTrusted}}
	higher := same
	higher.Confidence = 0.9
	other := Label{Target: "high1", Concept: "AdminRoute", Confidence: 0.4,
		Prov: Provenance{Producer: "p2", Build: BuildLabeled, Trust: TrustReviewed}}

	_ = g.AddLabel(same)
	_ = g.AddLabel(higher) // same (Target, Concept, Provenance) → replaces, not appends
	_ = g.AddLabel(other)  // different provenance → a second label

	got := g.LabelsOn("high1")
	if len(got) != 2 {
		t.Fatalf("LabelsOn = %d labels, want 2 (keyed dedupe + distinct provenance)", len(got))
	}
	for _, l := range got {
		if l.Prov.Producer == "p1" && l.Confidence != 0.9 {
			t.Fatalf("re-adding the same key must replace, got %+v", l)
		}
	}
}

func TestBackingFollowsTheBacksEdge(t *testing.T) {
	g := New(testSchemas(t))
	var cf Fields
	cf.Set("callee", Str("handle"))
	_ = g.AddNode(Node{ID: "low1", Type: "code.Call", Layer: LayerLow, Fields: cf})
	var ef Fields
	ef.Set("route", Str("/admin"))
	_ = g.AddNode(Node{ID: "high1", Type: "code.Entrypoint", Layer: LayerHigh, Fields: ef})
	if err := g.AddEdge(Edge{ID: "b1", Type: EdgeBacks, From: "high1", To: "low1"}); err != nil {
		t.Fatal(err)
	}

	got, ok := g.Backing("high1")
	if !ok || got.ID != "low1" {
		t.Fatalf("Backing = %+v ok=%v, want low1", got, ok)
	}
	if _, ok := g.Backing("low1"); ok {
		t.Fatal("a low node has no backing")
	}
}

func TestAddEdgeRejectsDanglingEndpoint(t *testing.T) {
	g := New(testSchemas(t))
	var cf Fields
	cf.Set("callee", Str("x"))
	_ = g.AddNode(Node{ID: "low1", Type: "code.Call", Layer: LayerLow, Fields: cf})
	if err := g.AddEdge(Edge{ID: "e1", Type: EdgeBacks, From: "low1", To: "ghost"}); err == nil {
		t.Fatal("an edge to a non-existent node must be rejected")
	}
}

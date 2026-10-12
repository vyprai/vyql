package graph

import (
	"errors"
	"testing"
)

func TestKeyOfIsStableAndOrderIndependent(t *testing.T) {
	ts := &TypeSchema{Type: "iac.Container", Layer: LayerHigh,
		Fields: []FieldSpec{{Name: "name", Kind: KindString}, {Name: "image", Kind: KindString}},
		Key:    []string{"name", "image"}}

	var a Fields
	a.Set("name", Str("web"))
	a.Set("image", Str("nginx"))
	var b Fields
	b.Set("image", Str("nginx")) // same values, inserted in the other order
	b.Set("name", Str("web"))

	ka, err := KeyOf(ts, a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := KeyOf(ts, b)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatalf("key must not depend on field insertion order: %q vs %q", ka, kb)
	}
}

func TestKeyOfRequiresEveryKeyField(t *testing.T) {
	ts := &TypeSchema{Type: "iac.Container", Layer: LayerHigh,
		Fields: []FieldSpec{{Name: "name", Kind: KindString}}, Key: []string{"name"}}
	var missing Fields
	if _, err := KeyOf(ts, missing); err == nil {
		t.Fatal("a record missing a key field must error")
	}
}

func TestUpsertHigherTrustWins(t *testing.T) {
	g := New(mergeSchemas(t))
	var lo Fields
	lo.Set("name", Str("web"))
	lo.Set("image", Str("guess"))
	_ = g.Upsert(Node{ID: "c1", Type: "iac.Container", Layer: LayerHigh, Fields: lo,
		Prov: Provenance{Producer: "learner", Build: BuildGenerated, Trust: TrustGenerated}})

	var hi Fields
	hi.Set("name", Str("web"))
	hi.Set("image", Str("nginx:1.25"))
	if err := g.Upsert(Node{ID: "c1", Type: "iac.Container", Layer: LayerHigh, Fields: hi,
		Prov: Provenance{Producer: "terraform", Build: BuildParsed, Trust: TrustTrusted}}); err != nil {
		t.Fatal(err)
	}

	n, _ := g.Node("c1")
	v, _ := n.Fields.Get("image")
	if v.S != "nginx:1.25" {
		t.Fatalf("image = %q, want the higher-trust value", v.S)
	}
}

func TestUpsertSameTrustConflictIsAnError(t *testing.T) {
	// Two same-trust producers writing DIFFERENT values to one field must be an error,
	// never order-dependent.
	g := New(mergeSchemas(t))
	var a Fields
	a.Set("name", Str("web"))
	a.Set("image", Str("nginx"))
	_ = g.Upsert(Node{ID: "c1", Type: "iac.Container", Layer: LayerHigh, Fields: a,
		Prov: Provenance{Producer: "p1", Build: BuildParsed, Trust: TrustTrusted}})

	var b Fields
	b.Set("name", Str("web"))
	b.Set("image", Str("apache"))
	err := g.Upsert(Node{ID: "c1", Type: "iac.Container", Layer: LayerHigh, Fields: b,
		Prov: Provenance{Producer: "p2", Build: BuildParsed, Trust: TrustTrusted}})
	if !errors.Is(err, ErrTierConflict) {
		t.Fatalf("err = %v, want ErrTierConflict", err)
	}
}

func mergeSchemas(t *testing.T) *Schemas {
	t.Helper()
	s := NewSchemas()
	if err := s.Register(&TypeSchema{Type: "iac.Container", Layer: LayerHigh,
		Fields: []FieldSpec{{Name: "name", Kind: KindString}, {Name: "image", Kind: KindString}},
		Key:    []string{"name"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

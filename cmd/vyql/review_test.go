package main

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

func TestCollectReviewItemsDeduplicatesSameCallSite(t *testing.T) {
	store := usg.NewInMemStore()
	for _, id := range []string{"call-a", "call-b"} {
		store.AddNode(usg.Node{ID: id, Type: "code.Call", Props: map[string]string{
			"loc":  "x.go:10",
			"path": "pd.parseOctetString",
		}})
		store.AddLabel(id, usg.Label{Concept: "code.StructuredInputDecode"})
	}
	reviewConcepts := map[string]reviewConceptInfo{
		"code.StructuredInputDecode": {
			category: "input_validation",
			kind:     "attention",
			review:   "review structured decoder output validation",
		},
	}

	got := collectReviewItemsWithPolicy(store, reviewConcepts, reviewDisplayPolicy{flagSort: []string{"location"}})
	if len(got) != 1 {
		t.Fatalf("review items = %d, want 1", len(got))
	}
}

func TestCollectReviewItemsHandlesNilStore(t *testing.T) {
	reviewConcepts := map[string]reviewConceptInfo{
		"code.StructuredInputDecode": {
			category: "input_validation",
			kind:     "attention",
			review:   "review structured decoder output validation",
		},
	}

	if got := collectReviewItemsWithPolicy(nil, reviewConcepts, reviewDisplayPolicy{flagSort: []string{"location"}}); len(got) != 0 {
		t.Fatalf("review items = %d, want 0", len(got))
	}
}

func TestCollectReviewItemsUsesDisplayPolicyFlagSort(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "a", Type: "code.Call", Props: map[string]string{"loc": "z.go:20"}})
	store.AddNode(usg.Node{ID: "b", Type: "code.Call", Props: map[string]string{"loc": "a.go:1"}})
	store.AddLabel("a", usg.Label{Concept: "code.ZetaReview"})
	store.AddLabel("b", usg.Label{Concept: "code.AlphaReview"})
	reviewConcepts := map[string]reviewConceptInfo{
		"code.ZetaReview":  {category: "review", kind: "attention"},
		"code.AlphaReview": {category: "review", kind: "attention"},
	}

	got := collectReviewItemsWithPolicy(store, reviewConcepts, reviewDisplayPolicy{
		flagSort: []string{"concept"},
	})
	if len(got) != 2 {
		t.Fatalf("review items = %d, want 2", len(got))
	}
	if got[0].Concept != "code.AlphaReview" || got[1].Concept != "code.ZetaReview" {
		t.Fatalf("review order = [%s, %s], want concept sort", got[0].Concept, got[1].Concept)
	}
}

func TestCollectReviewItemsUsesDisplayPolicyNearbyCheckLimit(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "target", Type: "code.Call", Props: map[string]string{"loc": "target.go:10"}})
	store.AddLabel("target", usg.Label{Concept: "code.TargetReview"})
	for _, id := range []string{"check-a", "check-b", "check-c"} {
		store.AddNode(usg.Node{ID: id, Type: "code.Call", Props: map[string]string{"loc": id + ".go:1"}})
		store.AddLabel(id, usg.Label{Concept: "core.ExpectedCheck"})
		store.AddEdge(usg.Edge{Type: "PROTECTS", Src: id, Dst: "target"})
	}
	reviewConcepts := map[string]reviewConceptInfo{
		"code.TargetReview":  {category: "review", kind: "target", expected: []string{"core.ExpectedCheck"}},
		"core.ExpectedCheck": {category: "review", kind: "check"},
	}

	got := collectReviewItemsWithPolicy(store, reviewConcepts, reviewDisplayPolicy{
		flagSort:            []string{"location"},
		includeNearbyChecks: true,
		nearbyCheckLimit:    2,
	})
	var target *reviewItem
	for i := range got {
		if got[i].Concept == "code.TargetReview" {
			target = &got[i]
			break
		}
	}
	if target == nil {
		t.Fatalf("missing target review item: %+v", got)
	}
	if len(target.NearbyChecks) != 2 {
		t.Fatalf("nearby checks = %d, want 2: %+v", len(target.NearbyChecks), target.NearbyChecks)
	}
}

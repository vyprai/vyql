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

	got := collectReviewItemsWith(store, reviewConcepts)
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

	if got := collectReviewItemsWith(nil, reviewConcepts); len(got) != 0 {
		t.Fatalf("review items = %d, want 0", len(got))
	}
}

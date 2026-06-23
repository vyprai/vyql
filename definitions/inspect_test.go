package definitions

import "testing"

func TestInspectFindsShippedAdaptersAndRules(t *testing.T) {
	cat, err := Inspect(InspectOptions{Kind: "all", Query: "UrlFetch", Language: "python", Max: 20})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if cat.Stats.Concepts == 0 || cat.Stats.Rules == 0 || cat.Stats.Adapters == 0 {
		t.Fatalf("unexpected empty stats: %#v", cat.Stats)
	}
	if len(cat.Adapters) == 0 {
		t.Fatalf("expected python UrlFetch adapter mappings, got %#v", cat)
	}
	for _, m := range cat.Adapters {
		if m.Language != "python" {
			t.Fatalf("language filter leaked %q mapping: %#v", m.Language, m)
		}
	}
}

func TestInspectReviewConcepts(t *testing.T) {
	cat, err := Inspect(InspectOptions{Kind: "reviews", Query: "ProtocolStateReview", Max: 10})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(cat.Reviews) == 0 {
		t.Fatalf("expected ProtocolStateReview review metadata")
	}
	if cat.Reviews[0].Concept == "" || cat.Reviews[0].Text == "" {
		t.Fatalf("review summary should include concept and text: %#v", cat.Reviews[0])
	}
}

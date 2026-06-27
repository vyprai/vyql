package definitions

import (
	"testing"

	"github.com/vyprai/vyql/parser"
)

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

func TestInspectCatalogIncludesPackDeclarations(t *testing.T) {
	var cat Catalog
	addDecl(&cat, "packs/web.vyql", &parser.PackDecl{
		Name: "webSecurity",
		Fields: map[string]any{
			"includes": []string{"profile.web", "rules.injection.SqlInjection"},
			"excludes": []string{"rules.experimental.NoisyRule"},
		},
	})
	if len(cat.Packs) != 1 {
		t.Fatalf("packs = %d, want 1", len(cat.Packs))
	}
	got := cat.Packs[0]
	if got.Name != "webSecurity" || got.Source != "packs/web.vyql" {
		t.Fatalf("pack summary identity wrong: %#v", got)
	}
	if !sameStrings(got.Includes, []string{"profile.web", "rules.injection.SqlInjection"}) {
		t.Fatalf("includes = %#v", got.Includes)
	}
	if !sameStrings(got.Excludes, []string{"rules.experimental.NoisyRule"}) {
		t.Fatalf("excludes = %#v", got.Excludes)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

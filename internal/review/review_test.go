package review

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/usg"
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
	reviewConcepts := map[string]ConceptInfo{
		"code.StructuredInputDecode": {
			category: "input_validation",
			kind:     "attention",
			review:   "review structured decoder output validation",
		},
	}

	got := CollectWithPolicy(store, reviewConcepts, DisplayPolicy{flagSort: []string{"location"}}, resultpolicy.DefaultLifecycleContract())
	if len(got) != 1 {
		t.Fatalf("review items = %d, want 1", len(got))
	}
}

func TestReviewDisplayPolicyLoadsScanAll(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy display default {
  scanAll: [findings, flags, checks, advisoryEvidence, requirementDiagnostics]
  flagSort: [severity, category, location, concept]
  includeNearbyChecks: true
  nearbyCheckLimit: 5
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	policy, err := DisplayPolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err != nil {
		t.Fatalf("DisplayPolicyFromDecl: %v", err)
	}
	want := []string{"findings", "flags", "checks", "advisoryEvidence", "requirementDiagnostics"}
	if !stringSlicesEqual(policy.scanAll, want) {
		t.Fatalf("scanAll = %#v, want %#v", policy.scanAll, want)
	}
}

func TestReviewDisplayPolicyRequiresScanAll(t *testing.T) {
	prog, err := parser.ParseV2(`
module policies.core;
policy display default {
  flagSort: [severity]
  includeNearbyChecks: true
  nearbyCheckLimit: 5
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	_, err = DisplayPolicyFromDecl(prog.Decls[0].(*parser.V2PolicyDecl))
	if err == nil {
		t.Fatal("DisplayPolicyFromDecl succeeded, want missing scanAll diagnostic")
	}
	if !strings.Contains(err.Error(), "scanAll") {
		t.Fatalf("DisplayPolicyFromDecl error = %v, want scanAll diagnostic", err)
	}
}

func stringSlicesEqual(a, b []string) bool {
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

func TestCollectReviewItemsHandlesNilStore(t *testing.T) {
	reviewConcepts := map[string]ConceptInfo{
		"code.StructuredInputDecode": {
			category: "input_validation",
			kind:     "attention",
			review:   "review structured decoder output validation",
		},
	}

	if got := CollectWithPolicy(nil, reviewConcepts, DisplayPolicy{flagSort: []string{"location"}}, resultpolicy.DefaultLifecycleContract()); len(got) != 0 {
		t.Fatalf("review items = %d, want 0", len(got))
	}
}

func TestCollectReviewItemsUsesDisplayPolicyFlagSort(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "a", Type: "code.Call", Props: map[string]string{"loc": "z.go:20"}})
	store.AddNode(usg.Node{ID: "b", Type: "code.Call", Props: map[string]string{"loc": "a.go:1"}})
	store.AddLabel("a", usg.Label{Concept: "code.ZetaReview"})
	store.AddLabel("b", usg.Label{Concept: "code.AlphaReview"})
	reviewConcepts := map[string]ConceptInfo{
		"code.ZetaReview":  {category: "review", kind: "attention"},
		"code.AlphaReview": {category: "review", kind: "attention"},
	}

	got := CollectWithPolicy(store, reviewConcepts, DisplayPolicy{
		flagSort: []string{"concept"},
	}, resultpolicy.DefaultLifecycleContract())
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
	reviewConcepts := map[string]ConceptInfo{
		"code.TargetReview":  {category: "review", kind: "target", expected: []string{"core.ExpectedCheck"}},
		"core.ExpectedCheck": {category: "review", kind: "check"},
	}

	got := CollectWithPolicy(store, reviewConcepts, DisplayPolicy{
		flagSort:            []string{"location"},
		includeNearbyChecks: true,
		nearbyCheckLimit:    2,
	}, resultpolicy.DefaultLifecycleContract())
	var target *Item
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

// Filter used to reuse the caller's backing array via rows[:0], so filtering a slice
// rewrote the slice that was filtered. A caller holding both — the full set for a summary
// count, the filtered set for display — would find the full set quietly replaced by the
// filtered entries followed by stale tail elements.
func TestFilterDoesNotRewriteTheCallersSlice(t *testing.T) {
	all := []Item{
		{Category: "crypto", Kind: "attention", Loc: "a.py:1"},
		{Category: "injection", Kind: "attention", Loc: "b.py:2"},
		{Category: "crypto", Kind: "check", Loc: "c.py:3"},
	}
	before := append([]Item(nil), all...)

	got := Filter(all, "crypto", "all", "")
	if len(got) != 2 {
		t.Fatalf("Filter returned %d items, want 2", len(got))
	}
	for i := range all {
		if all[i].Loc != before[i].Loc || all[i].Category != before[i].Category {
			t.Fatalf("Filter rewrote the caller's slice at %d:\n  got  %+v\n  want %+v",
				i, all[i], before[i])
		}
	}
}

// A filter that matches everything may return the input untouched, but it still must not be
// the path that mutates it.
func TestFilterLeavesAnUnfilteredSliceAlone(t *testing.T) {
	all := []Item{{Category: "crypto", Kind: "attention", Loc: "a.py:1"}}
	before := append([]Item(nil), all...)
	if got := Filter(all, "all", "all", ""); len(got) != 1 || got[0].Loc != before[0].Loc {
		t.Fatalf("Filter(all) = %+v, want the input unchanged", got)
	}
	if all[0].Loc != before[0].Loc {
		t.Fatal("Filter rewrote the caller's slice on the pass-through path")
	}
}

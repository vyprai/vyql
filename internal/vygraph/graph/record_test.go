package graph

import "testing"

func TestTrustTiersOrderGeneratedBelowTrusted(t *testing.T) {
	// Machine-generated knowledge is quarantined below reviewed knowledge, so the
	// ordering is load-bearing for conflict resolution, not cosmetic.
	if !(TrustGenerated < TrustValidated && TrustValidated < TrustReviewed && TrustReviewed < TrustTrusted) {
		t.Fatal("trust tiers must order generated < validated < reviewed < trusted")
	}
}

func TestBuildKindsAreDistinct(t *testing.T) {
	kinds := []Build{BuildParsed, BuildLifted, BuildRelated, BuildResolved,
		BuildLabeled, BuildMined, BuildGenerated}
	seen := map[Build]bool{}
	for _, k := range kinds {
		if seen[k] {
			t.Fatalf("build kind %d duplicated", k)
		}
		seen[k] = true
	}
	if len(seen) != 7 {
		t.Fatalf("expected the seven design build kinds, got %d", len(seen))
	}
}

func TestLabelTargetsNodeOrEdge(t *testing.T) {
	// A label attaches to a node OR an edge — its Target is just a record id.
	n := Node{ID: "n1", Type: "iac.Container", Layer: LayerHigh}
	e := Edge{ID: "e1", Type: "runs_in", From: "n1", To: "n2"}

	onNode := Label{Target: n.ID, Concept: "PrivilegedWorkload", Confidence: 0.9}
	onEdge := Label{Target: e.ID, Concept: "CrossBoundary", Confidence: 0.5}

	if onNode.Target != "n1" || onEdge.Target != "e1" {
		t.Fatalf("label targets: %q %q", onNode.Target, onEdge.Target)
	}
}

func TestBacksEdgeTypeIsReserved(t *testing.T) {
	if EdgeBacks != "backs" {
		t.Fatalf("EdgeBacks = %q, want \"backs\"", EdgeBacks)
	}
}

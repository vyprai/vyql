package vyql

import (
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
)

func pathStore(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	must := func(ts *graph.TypeSchema) {
		if err := s.Register(ts); err != nil {
			t.Fatalf("Register(%s): %v", ts.Type, err)
		}
	}
	must(&graph.TypeSchema{Type: "code.Call", Layer: graph.LayerLow,
		Fields: []graph.FieldSpec{{Name: "path", Kind: graph.KindString}}, Key: []string{"path"}})
	must(&graph.TypeSchema{Type: "code.DataAccess", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "table", Kind: graph.KindString},
			{Name: "op", Kind: graph.KindEnum, Enum: []string{"read", "write"}},
		}, Key: []string{"table", "op"}})
	return graph.New(s)
}

func addCall(t *testing.T, g *graph.Store, id, path string) {
	t.Helper()
	var f graph.Fields
	f.Set("path", graph.Str(path))
	if err := g.AddNode(graph.Node{ID: id, Type: "code.Call", Layer: graph.LayerLow, Fields: f}); err != nil {
		t.Fatal(err)
	}
}

func kbOf(t *testing.T, src string) *KB {
	t.Helper()
	f, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kb, errs := KBFromFiles([]*File{f}, graph.NewSchemas())
	if len(errs) > 0 {
		t.Fatalf("KBFromFiles: %v", errs)
	}
	if errs := Validate(f, kb.Knowledge); len(errs) > 0 {
		t.Fatalf("Validate: %v", errs)
	}
	return kb
}

func TestApplyAdaptersLabelsAndCapsConfidence(t *testing.T) {
	kb, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	g := pathStore(t)
	addCall(t, g, "n1", "request.args.get")
	addCall(t, g, "n2", "fmt.Sprintf")
	addCall(t, g, "n3", "db.session.execute")

	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatalf("ApplyAdapters: %v", err)
	}
	labels := func(id string) []graph.Label { return g.LabelsOn(id) }
	if got := labels("n1"); len(got) != 1 || got[0].Concept != "code.HttpInput" {
		t.Fatalf("n1 labels = %+v", got)
	}
	if got := labels("n3"); len(got) != 1 || got[0].Concept != "code.SqlExecution" {
		t.Fatalf("n3 labels = %+v", got)
	}
	if got := labels("n2"); len(got) != 0 {
		t.Fatalf("n2 must stay unlabelled, got %+v", got)
	}
	// resolved fidelity caps at high (1.0); manifest says reviewed.
	l := labels("n1")[0]
	if l.Confidence != 1.0 {
		t.Fatalf("resolved confidence = %v, want 1.0 (high)", l.Confidence)
	}
	if l.Prov.Build != graph.BuildLabeled || l.Prov.Trust != graph.TrustReviewed {
		t.Fatalf("provenance = %+v", l.Prov)
	}
}

func TestApplyAdaptersSyntacticCapsAtMedium(t *testing.T) {
	kb := kbOf(t, `module toy;
concept code.A : source { }
adapter bare { source code.path("x.y") -> code.A }
`)
	g := pathStore(t)
	addCall(t, g, "m", "x.y.z")
	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatal(err)
	}
	got := g.LabelsOn("m")
	if len(got) != 1 || got[0].Confidence != 0.75 {
		t.Fatalf("syntactic confidence = %+v, want 0.75 (medium)", got)
	}
}

func TestPathMatcherIsSegmentAware(t *testing.T) {
	kb := kbOf(t, `module toy;
concept code.R : source { }
adapter lib { source code.path("Random") -> code.R }
`)
	g := pathStore(t)
	addCall(t, g, "a", "Random.secure")
	addCall(t, g, "b", "SecureRandom")
	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatal(err)
	}
	if got := g.LabelsOn("a"); len(got) != 1 {
		t.Fatalf("Random.secure must match arg Random: %+v", got)
	}
	if got := g.LabelsOn("b"); len(got) != 0 {
		t.Fatalf("SecureRandom must NOT match arg Random: %+v", got)
	}
}

func TestApplyAdaptersWhereFilters(t *testing.T) {
	kb := kbOf(t, `module toy;
concept code.S : sink { }
adapter app {
  sink code.path("db.exec") where n.path contains "db" -> code.S
}
`)
	g := pathStore(t)
	addCall(t, g, "x", "db.exec")
	addCall(t, g, "y", "other.db.exec") // matches path, contains db → labelled
	addCall(t, g, "z", "db.exec.alt")   // matches path, contains db → labelled
	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"x", "y", "z"} {
		if got := g.LabelsOn(id); len(got) != 1 {
			t.Fatalf("node %s labels = %+v", id, got)
		}
	}

	kb2 := kbOf(t, `module toy;
concept code.S : sink { }
adapter app {
  sink code.path("db.exec") where n.path == "nothing" -> code.S
}
`)
	g2 := pathStore(t)
	addCall(t, g2, "x", "db.exec")
	if err := ApplyAdapters(kb2, g2); err != nil {
		t.Fatal(err)
	}
	if got := g2.LabelsOn("x"); len(got) != 0 {
		t.Fatalf("a failed where filter must label nothing: %+v", got)
	}
}

// The labelled concepts must be consumable through the ontology exactly as the
// engine's concept binding expects (IsA over refines).
func TestApplyAdaptersLabelsBindThroughOntology(t *testing.T) {
	kb, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatal(err)
	}
	g := pathStore(t)
	addCall(t, g, "n1", "request.args.get")
	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatal(err)
	}
	if !kb.Onto.IsA("code.HttpInput", "code.UntrustedData") {
		t.Fatal("ontology must relate HttpInput to UntrustedData via refines")
	}
	if _, ok := kb.Onto.Get("code.HttpInput"); !ok {
		t.Fatal("concept missing")
	}
	_ = ontology.KindSource // ontology package stays referenced for consumers
}

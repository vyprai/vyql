package engine

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

func nFlow(t *testing.T, labels map[string]string, edges [][2]string) int {
	t.Helper()
	onto := testOntology()
	decls, err := parseV2DefinitionsForTest(flowRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	store := usg.NewInMemStore()
	ids := map[string]bool{}
	for _, e := range edges {
		ids[e[0]] = true
		ids[e[1]] = true
	}
	for id := range labels {
		ids[id] = true
	}
	for id := range ids {
		store.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
	}
	for id, concept := range labels {
		store.AddLabel(id, usg.Label{Concept: concept})
	}
	for _, e := range edges {
		store.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]})
	}
	fs, err := New(onto, store).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return len(fs)
}

func TestSanitizerConformanceTable(t *testing.T) {
	in, q, transform := "custom.Input", "custom.Target", "custom.Transform"

	if n := nFlow(t, map[string]string{"in": in, "q": q, "transform": transform}, [][2]string{{"in", "q"}}); n != 1 {
		t.Fatalf("row1 transform-exists-elsewhere -> finding, got %d", n)
	}
	if n := nFlow(t, map[string]string{"in": in, "transform": transform, "q": q},
		[][2]string{{"in", "transform"}, {"transform", "q"}, {"in", "q"}}); n != 1 {
		t.Fatalf("row2 alternate path -> finding, got %d", n)
	}
	if n := nFlow(t, map[string]string{"in": in, "transform": transform, "q": q},
		[][2]string{{"in", "transform"}, {"transform", "q"}}); n != 0 {
		t.Fatalf("row3 fully transformed -> no finding, got %d", n)
	}
	if n := nFlow(t, map[string]string{"in": in, "transform": transform, "in2": in, "q": q},
		[][2]string{{"in", "transform"}, {"transform", "join"}, {"in2", "join"}, {"join", "q"}}); n != 1 {
		t.Fatalf("row4 fresh input after transform -> finding, got %d", n)
	}
	if n := nFlow(t, map[string]string{"in": in, "bind": transform, "q": q},
		[][2]string{{"in", "bind"}, {"bind", "q"}}); n != 0 {
		t.Fatalf("row5 boundary transform -> no finding, got %d", n)
	}
	wrong := `
module bad;
rule WrongTransform {
  taint custom.Input -> custom.Target as sink
  unless sink.path coveredBy custom.OtherTransform
}
`
	decls, _ := parseV2DefinitionsForTest(wrong)
	_, errs := CompileRules(decls, testOntology())
	if len(errs) != 1 || !contains(errs[0].Msg, "does not defend") {
		t.Fatalf("row6 wrong transform -> compile error, got %v", errs)
	}
	if n := nFlow(t, map[string]string{"obj": in, "transform": transform, "q": q},
		[][2]string{{"obj", "transform"}, {"transform", "q"}}); n != 0 {
		t.Fatalf("row7 field-insensitive known limitation should suppress, got %d", n)
	}
}

func TestAdvisoryControlDoesNotSuppressTaint(t *testing.T) {
	onto := testOntology()
	decls, err := parseV2DefinitionsForTest(flowRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	store := usg.NewInMemStore()
	for _, id := range []string{"in", "transform", "q"} {
		store.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
	}
	store.AddLabel("in", usg.Label{Concept: "custom.Input"})
	store.AddLabel("transform", usg.Label{Concept: "custom.Transform", Detail: map[string]string{"advisory": "true"}})
	store.AddLabel("q", usg.Label{Concept: "custom.Target"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "transform"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "transform", Dst: "q"})

	fs, err := New(onto, store).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("advisory control suppressed taint, got %d finding(s)", len(fs))
	}
}

package engine

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

func TestContextSensitivityBoundary(t *testing.T) {
	onto := testOntology()
	decls, err := parseV2DefinitionsForTest(flowRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	count := func(s usg.Store) int {
		fs, err := New(onto, s).Evaluate(compiled[0])
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		return len(fs)
	}

	shared := usg.NewInMemStore()
	for _, n := range []struct{ id, loc string }{
		{"cleanA", "a:1"}, {"inputB", "b:1"}, {"helper", "util:1"}, {"targetA", "a:2"},
	} {
		shared.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	shared.AddLabel("inputB", usg.Label{Concept: "custom.Input"})
	shared.AddLabel("targetA", usg.Label{Concept: "custom.Target"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "cleanA", Dst: "helper"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "inputB", Dst: "helper"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "helper", Dst: "targetA"})
	if n := count(shared); n != 1 {
		t.Fatalf("context-insensitive solver should produce the documented precision limitation, got %d", n)
	}

	cloned := usg.NewInMemStore()
	for _, n := range []struct{ id, loc string }{
		{"cleanA", "a:1"}, {"inputB", "b:1"}, {"helper@A", "util:1#ctxA"},
		{"helper@B", "util:1#ctxB"}, {"targetA", "a:2"},
	} {
		cloned.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	cloned.AddLabel("inputB", usg.Label{Concept: "custom.Input"})
	cloned.AddLabel("targetA", usg.Label{Concept: "custom.Target"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "cleanA", Dst: "helper@A"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "inputB", Dst: "helper@B"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "helper@A", Dst: "targetA"})
	if n := count(cloned); n != 0 {
		t.Fatalf("per-call-site facts should eliminate the finding with the same rule, got %d", n)
	}
}

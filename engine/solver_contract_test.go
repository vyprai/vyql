package engine

// T0.8 (plan/test-coverage-tasklist.md): shared solver-contract conformance. Every
// solver kind, when it produces a finding, must stamp WitnessKind and carry a
// non-empty reconstructable witness (the proof-tree surface). One table, all kinds.

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func fireOne(t *testing.T, rule string, build func(*usg.InMemStore)) findingView {
	t.Helper()
	onto := solverContractOntology()
	decls, err := parser.Parse(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	build(s)
	eng := New(onto, s)
	var fs []findingView
	for _, cr := range compiled {
		got, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range got {
			fs = append(fs, findingView{f.RuleID, f.WitnessKind, f.Witness})
		}
	}
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(fs))
	}
	return fs[0]
}

func solverContractOntology() *ontology.Ontology {
	onto := testOntology()
	onto.Add(ontology.Concept{Name: "Edge", Package: "custom", Kind: "exposure"})
	onto.Add(ontology.Concept{Name: "Asset", Package: "custom", Kind: "asset"})
	onto.Add(ontology.Concept{Name: "Actor", Package: "custom", Kind: "principal"})
	onto.Add(ontology.Concept{Name: "Capability", Package: "custom", Kind: "privilege"})
	onto.Add(ontology.Concept{Name: "Marker", Package: "custom", Kind: "asset"})
	onto.Add(ontology.Concept{Name: "WorkItem", Package: "custom", Kind: "principal"})
	onto.Add(ontology.Concept{Name: "Action", Package: "custom", Kind: "action"})
	return onto
}

type findingView struct {
	id      string
	kind    string
	witness []string
}

func TestSolverContractConformance(t *testing.T) {
	cases := []struct {
		name     string
		rule     string
		wantKind string
		wantFlow bool // witness must be non-empty (taint/reach/assume); match may be empty
		build    func(*usg.InMemStore)
	}{
		{
			name:     "taint",
			rule:     "package t;\nrule R { meta { id: \"X-TAINT\" }\n taint custom.Input -> custom.Target }",
			wantKind: "taint", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "a:1"}})
				s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "a:2"}})
				s.AddLabel("in", usg.Label{Concept: "custom.Input"})
				s.AddLabel("q", usg.Label{Concept: "custom.Target"})
				s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
			},
		},
		{
			name:     "reach",
			rule:     "package t;\nrule R { meta { id: \"X-REACH\" }\n reach custom.Edge -> custom.Asset }",
			wantKind: "reach", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge"})
				s.AddNode(usg.Node{ID: "asset", Type: "custom.Asset", Props: map[string]string{"loc": "asset"}})
				s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
				s.AddLabel("asset", usg.Label{Concept: "custom.Asset"})
				s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "asset", Props: map[string]string{"rule": "edge-rule"}})
			},
		},
		{
			name:     "assume",
			rule:     "package t;\nrule R { meta { id: \"X-ASSUME\" }\n assume custom.Actor -> custom.Capability }",
			wantKind: "assume", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "actor", Type: "custom.Actor"})
				s.AddNode(usg.Node{ID: "capability", Type: "custom.Capability", Props: map[string]string{"level": "high"}})
				s.AddLabel("actor", usg.Label{Concept: "custom.Actor"})
				s.AddLabel("capability", usg.Label{Concept: "custom.Capability"})
				s.AddEdge(usg.Edge{Type: "STEP", Src: "actor", Dst: "capability", Props: map[string]string{"ability": "delegated"}})
			},
		},
		{
			name:     "match",
			rule:     "package t;\nrule R { meta { id: \"X-MATCH\" }\n match custom.Marker as s }",
			wantKind: "match", wantFlow: false,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "matched", Type: "custom.Marker", Props: map[string]string{"loc": "m"}})
				s.AddLabel("matched", usg.Label{Concept: "custom.Marker"})
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fireOne(t, c.rule, c.build)
			if f.kind != c.wantKind {
				t.Errorf("WitnessKind = %q, want %q", f.kind, c.wantKind)
			}
			if c.wantFlow && len(f.witness) == 0 {
				t.Errorf("%s finding must carry a non-empty witness (proof-tree surface)", c.name)
			}
		})
	}
}

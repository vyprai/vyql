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
	onto := ontology.Seed()
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
			rule:     "package t;\nrule R { meta { id: \"X-TAINT\" }\n taint code.HttpInput -> code.SqlExecution }",
			wantKind: "taint", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "a:1"}})
				s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "a:2"}})
				s.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
				s.AddLabel("q", usg.Label{Concept: "code.SqlExecution"})
				s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
			},
		},
		{
			name:     "reach",
			rule:     "package t;\nrule R { meta { id: \"X-REACH\" }\n reach cloud.Internet -> cloud.Database }",
			wantKind: "reach", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet"})
				s.AddNode(usg.Node{ID: "db", Type: "cloud.Database", Props: map[string]string{"loc": "db"}})
				s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
				s.AddLabel("db", usg.Label{Concept: "cloud.Database"})
				s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "db", Props: map[string]string{"rule": "sg-open"}})
			},
		},
		{
			name:     "assume",
			rule:     "package t;\nrule R { meta { id: \"X-ASSUME\" }\n assume identity.ExternalPrincipal -> identity.AdminPrivilege }",
			wantKind: "assume", wantFlow: true,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "ext", Type: "identity.User"})
				s.AddNode(usg.Node{ID: "admin", Type: "identity.Role", Props: map[string]string{"priv_level": "ADMIN"}})
				s.AddLabel("ext", usg.Label{Concept: "identity.ExternalPrincipal"})
				s.AddLabel("admin", usg.Label{Concept: "identity.AdminPrivilege"})
				s.AddEdge(usg.Edge{Type: "STEP", Src: "ext", Dst: "admin", Props: map[string]string{"ability": "sts:AssumeRole"}})
			},
		},
		{
			name:     "match",
			rule:     "package t;\nrule R { meta { id: \"X-MATCH\" }\n match cloud.PublicStorage as s }",
			wantKind: "match", wantFlow: false,
			build: func(s *usg.InMemStore) {
				s.AddNode(usg.Node{ID: "bucket", Type: "cloud.PublicStorage", Props: map[string]string{"loc": "b"}})
				s.AddLabel("bucket", usg.Label{Concept: "cloud.PublicStorage"})
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

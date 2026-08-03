package bindings_test

import (
	"testing"

	"github.com/vyprai/vyql/bindings"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

const sqliRule = `
module vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution as sink
  unless sink.path coveredBy core.SqlParameterization
}
`

// evalSQLI compiles + evaluates the SQLI rule over a store, returning the
// findings for VYQL-INJ-001.
func evalSQLI(t *testing.T, store usg.Store) []*finding {
	t.Helper()
	onto := ontology.Seed()
	decls, err := parseV2DefinitionsForTest(sqliRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	eng := engine.New(onto, store)
	fs, err := eng.Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	out := make([]*finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, &finding{confidence: f.Confidence})
	}
	return out
}

type finding struct{ confidence string }

func mkNode(s usg.Store, id, loc string) {
	s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": loc}})
}

// baseGraph: in -> wrap -> q, with in=HttpInput and q=SqlExecution pre-labeled.
func baseGraph() usg.Store {
	s := usg.NewInMemStore()
	mkNode(s, "in", "h.py:1")
	mkNode(s, "wrap", "h.py:2")
	mkNode(s, "q", "h.py:3")
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "wrap"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "wrap", Dst: "q"})
	s.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
	s.AddLabel("q", usg.Label{Concept: "code.SqlExecution"})
	return s
}

func genericApplicator() bindings.Applicator {
	return bindings.Applicator{Name: "python.generic", Technology: "python", Specificity: 1,
		Apply: func(usg.Store) []bindings.Mapping { return nil }}
}

func pinnedApplicator() bindings.Applicator {
	return bindings.Applicator{Name: "python.ormlib>=2", Technology: "python", Specificity: 3,
		Apply: func(usg.Store) []bindings.Mapping {
			return []bindings.Mapping{{NodeID: "wrap", Concept: "core.SqlParameterization"}}
		}}
}

// Mirrors the precedence case from the original prototype.
func TestBindingApplicatorPrecedenceAndConflict(t *testing.T) {
	// (a) specificity: pinned applicator labels wrap as parameterization -> suppresses finding
	g := baseGraph()
	if _, _, err := bindings.Apply(g, []bindings.Applicator{genericApplicator(), pinnedApplicator()}, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(evalSQLI(t, g)); n != 0 {
		t.Fatalf("(a) pinned applicator should suppress finding, got %d", n)
	}

	// (b) tenant positive override suppresses even without a pinned applicator
	g2 := baseGraph()
	if _, _, err := bindings.Apply(g2, []bindings.Applicator{genericApplicator()},
		[]bindings.Mapping{{NodeID: "wrap", Concept: "core.SqlParameterization"}}); err != nil {
		t.Fatal(err)
	}
	if n := len(evalSQLI(t, g2)); n != 0 {
		t.Fatalf("(b) tenant positive override should suppress finding, got %d", n)
	}

	// (c) tenant negative override on the sink: "q is NOT a SQL sink" -> no finding, recorded
	g3 := usg.NewInMemStore()
	mkNode(g3, "in", "h.py:1")
	mkNode(g3, "q", "h.py:3")
	g3.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	g3.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
	sinkApplicator := bindings.Applicator{Name: "python.dbapi", Technology: "python", Specificity: 2,
		Apply: func(usg.Store) []bindings.Mapping {
			return []bindings.Mapping{{NodeID: "q", Concept: "code.SqlExecution"}}
		}}
	conflicts, suppressed, err := bindings.Apply(g3, []bindings.Applicator{sinkApplicator},
		[]bindings.Mapping{{NodeID: "q", Concept: "code.SqlExecution",
			Detail: map[string]string{"negative": "code.SqlExecution"}}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(evalSQLI(t, g3)); n != 0 {
		t.Fatalf("(c) tenant negative override should remove sink -> no finding, got %d", n)
	}
	if len(conflicts) < 1 || len(suppressed) < 1 {
		t.Fatalf("(c) conflict + suppression should be recorded: conflicts=%v suppressed=%v", conflicts, suppressed)
	}
	// the suppressed label must NOT be on the node
	labels, _ := g3.Labels("q")
	for _, l := range labels {
		if l.Concept == "code.SqlExecution" {
			t.Fatalf("(c) suppressed sink label should not be attached")
		}
	}
}

// Mirrors poc/cases/case_12_confidence.py — confidence = min over derivation.
func TestConfidenceMinOverDerivation(t *testing.T) {
	mkVuln := func() usg.Store {
		s := usg.NewInMemStore()
		mkNode(s, "in", "h.py:1")
		mkNode(s, "q", "h.py:2")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
		return s
	}
	src := func(conf string) bindings.Applicator {
		return bindings.Applicator{Name: "hi", Technology: "python", Specificity: 3, Confidence: conf,
			Apply: func(usg.Store) []bindings.Mapping {
				return []bindings.Mapping{{NodeID: "in", Concept: "code.HttpInput"}}
			}}
	}
	sink := func(name, conf, fidelity string) bindings.Applicator {
		return bindings.Applicator{Name: name, Technology: "python", Specificity: 2, Confidence: conf, Fidelity: fidelity,
			Apply: func(usg.Store) []bindings.Mapping {
				return []bindings.Mapping{{NodeID: "q", Concept: "code.SqlExecution"}}
			}}
	}

	cases := []struct {
		name     string
		sinkAd   bindings.Applicator
		want     string
		srcOneAd bool // when true a single applicator labels both nodes high
	}{
		{"high+high->high", bindings.Applicator{}, "high", true},
		{"high+low->low", sink("heuristic", "low", "syntactic"), "low", false},
		{"high+medium->medium", sink("med", "medium", ""), "medium", false},
	}
	for _, c := range cases {
		g := mkVuln()
		var ads []bindings.Applicator
		if c.srcOneAd {
			ads = []bindings.Applicator{{Name: "hi", Technology: "python", Specificity: 2, Confidence: "high",
				Apply: func(usg.Store) []bindings.Mapping {
					return []bindings.Mapping{{NodeID: "in", Concept: "code.HttpInput"},
						{NodeID: "q", Concept: "code.SqlExecution"}}
				}}}
		} else {
			ads = []bindings.Applicator{src("high"), c.sinkAd}
		}
		if _, _, err := bindings.Apply(g, ads, nil); err != nil {
			t.Fatal(err)
		}
		fs := evalSQLI(t, g)
		if len(fs) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", c.name, len(fs))
		}
		if fs[0].confidence != c.want {
			t.Fatalf("%s: confidence = %q, want %q", c.name, fs[0].confidence, c.want)
		}
	}
}

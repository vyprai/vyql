package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// Mirrors poc/cases/case_13_context_sensitivity.py (ADVERSARIAL). This documents
// a KNOWN limitation and shows where the fix lives. A context-INSENSITIVE flow
// analysis reports taint "teleporting" through a shared helper between unrelated
// callers — a false positive. docs/08 places the fix INSIDE the taint solver
// (precision profile: context_sensitive, call-site, k), NOT in the layered
// language design. We show both: (a) the context-insensitive solver produces the
// FP; (b) per-call-site facts (what call-site summaries / monomorphization
// achieve) remove the FP with the SAME rule.
func TestContextSensitivityBoundary(t *testing.T) {
	onto := ontology.Seed()
	decls, err := parser.Parse(sqliRule)
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

	// (a) shared helper, ONE node: cleanA -> helper -> sinkA ; reqB(tainted) -> helper.
	// Context-insensitive: B's taint flows out through the shared helper to A's
	// sink -> known teleport FALSE POSITIVE (documented limitation).
	shared := usg.NewInMemStore()
	for _, n := range []struct{ id, loc string }{
		{"cleanA", "a.py:1"}, {"reqB", "b.py:1"}, {"helper", "util.py:1"}, {"sinkA", "a.py:2"},
	} {
		shared.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	shared.AddLabel("reqB", usg.Label{Concept: "code.HttpInput"})
	shared.AddLabel("sinkA", usg.Label{Concept: "code.SqlExecution"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "cleanA", Dst: "helper"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "reqB", Dst: "helper"})
	shared.AddEdge(usg.Edge{Type: "FLOWS", Src: "helper", Dst: "sinkA"})
	if n := count(shared); n != 1 {
		t.Fatalf("context-INSENSITIVE solver should produce the known teleport FP (documented limitation), got %d", n)
	}

	// (b) SAME program with the helper CLONED per call-site (what call-site-keyed
	// summaries produce). B's taint and A's clean value use different helper
	// instances; A's sink is reached only by the clean instance -> NO finding.
	cloned := usg.NewInMemStore()
	for _, n := range []struct{ id, loc string }{
		{"cleanA", "a.py:1"}, {"reqB", "b.py:1"}, {"helper@A", "util.py:1#ctxA"},
		{"helper@B", "util.py:1#ctxB"}, {"sinkA", "a.py:2"},
	} {
		cloned.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	cloned.AddLabel("reqB", usg.Label{Concept: "code.HttpInput"})
	cloned.AddLabel("sinkA", usg.Label{Concept: "code.SqlExecution"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "cleanA", Dst: "helper@A"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "reqB", Dst: "helper@B"})
	cloned.AddEdge(usg.Edge{Type: "FLOWS", Src: "helper@A", Dst: "sinkA"})
	if n := count(cloned); n != 0 {
		t.Fatalf("per-call-site facts should eliminate the FP with the SAME rule, got %d", n)
	}
}

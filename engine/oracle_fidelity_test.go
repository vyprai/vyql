package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestGuardedByEndpoint(t *testing.T) {
	rule := `
module test;
rule GuardedFlow {
  meta { id: "TEST-GUARDED", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.endpoint coveredBy custom.Transform
}
`
	guarded := func(s usg.Store) {
		for _, id := range []string{"in", "target", "guard"} {
			s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
		}
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddLabel("target", usg.Label{Concept: "custom.Target"})
		s.AddLabel("guard", usg.Label{Concept: "custom.Transform"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
		s.AddEdge(usg.Edge{Type: "PROTECTS", Src: "guard", Dst: "target"})
	}
	counts, errs := runRule(t, rule, guarded)
	if len(errs) != 0 {
		t.Fatalf("well-typed guard should compile, got %v", errs)
	}
	if counts[0] != 0 {
		t.Fatalf("guard on the endpoint should suppress, got %d", counts[0])
	}

	unguarded := func(s usg.Store) {
		for _, id := range []string{"in", "target"} {
			s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
		}
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddLabel("target", usg.Label{Concept: "custom.Target"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
	}
	counts, _ = runRule(t, rule, unguarded)
	if counts[0] != 1 {
		t.Fatalf("removing the guard should restore the finding, got %d", counts[0])
	}
}

func TestGuardedByFunctionContextSummary(t *testing.T) {
	rule := `
module test;
rule GuardedFlow {
  meta { id: "TEST-GUARDED", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.endpoint coveredBy custom.Transform
}
`
	counts, errs := runRule(t, rule, func(s usg.Store) {
		s.AddNode(usg.Node{ID: "in", Type: "code.Name", Scope: "sample.py/fn1@1", Props: map[string]string{"loc": "sample.py:1"}})
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddNode(usg.Node{ID: "target", Type: "code.Call", Scope: "sample.py/fn1@2", Region: "sample.py/fn1", HasOrder: true, Order: 2, Props: map[string]string{"loc": "sample.py:2"}})
		s.AddLabel("target", usg.Label{Concept: "custom.Target"})
		s.AddNode(usg.Node{ID: "summary", Type: "code.Call", Region: "sample.py/fn1", HasOrder: true, Order: 3, Props: map[string]string{"callee_path": "analysis.function.context", "loc": "sample.py:1"}})
		s.AddLabel("summary", usg.Label{Concept: "custom.Transform"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
	})
	if len(errs) != 0 {
		t.Fatalf("well-typed guard should compile, got %v", errs)
	}
	if counts[0] != 0 {
		t.Fatalf("same-function context summary should suppress, got %d", counts[0])
	}

	counts, _ = runRule(t, rule, func(s usg.Store) {
		s.AddNode(usg.Node{ID: "in", Type: "code.Name", Scope: "sample.py/fn1@1", Props: map[string]string{"loc": "sample.py:1"}})
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddNode(usg.Node{ID: "target", Type: "code.Call", Scope: "sample.py/fn1@2", Region: "sample.py/fn1", HasOrder: true, Order: 2, Props: map[string]string{"loc": "sample.py:2"}})
		s.AddLabel("target", usg.Label{Concept: "custom.Target"})
		s.AddNode(usg.Node{ID: "summary", Type: "code.Call", Scope: "sample.py/fn2@3", Props: map[string]string{"callee_path": "analysis.function.context", "loc": "sample.py:10"}})
		s.AddLabel("summary", usg.Label{Concept: "custom.Transform"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
	})
	if counts[0] != 1 {
		t.Fatalf("different-function context summary should not suppress, got %d", counts[0])
	}

	counts, _ = runRule(t, rule, func(s usg.Store) {
		s.AddNode(usg.Node{ID: "in", Type: "code.Attr", Scope: "sample.py/fn2@1", Props: map[string]string{"loc": "sample.py:31"}})
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddNode(usg.Node{ID: "param", Type: "code.Param", Scope: "sample.py/fn1@2", Props: map[string]string{"loc": "sample.py:6"}})
		s.AddNode(usg.Node{ID: "target", Type: "code.Arg", Scope: "sample.py/fn1/try8@3", Region: "sample.py/fn1/try8", Props: map[string]string{"loc": "sample.py:25"}})
		s.AddLabel("target", usg.Label{Concept: "custom.Target"})
		s.AddNode(usg.Node{ID: "summary", Type: "code.Call", Region: "sample.py/fn1", HasOrder: true, Order: 4, Props: map[string]string{"callee_path": "analysis.function.context", "loc": "sample.py:6"}})
		s.AddLabel("summary", usg.Label{Concept: "custom.Transform"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "param"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "param", Dst: "target"})
	})
	if counts[0] != 0 {
		t.Fatalf("callee function context summary should suppress callee-internal sink, got %d", counts[0])
	}
}

func TestRefinementAndDisjunctiveControls(t *testing.T) {
	rule := `
module test;
rule ParentFlow {
  meta { id: "TEST-PARENT", severity: critical }
  taint custom.ParentInput -> custom.Target as sink
  unless sink.path coveredBy custom.Transform
  unless sink.path coveredBy custom.AlternateTransform
}
`
	counts, errs := runRule(t, rule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "target", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
	})
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	if counts[0] != 1 {
		t.Fatalf("parent-concept rule should match child-labeled source, got %d", counts[0])
	}

	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "transform", "custom.Transform")
		label(s, "target", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "transform"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "transform", Dst: "target"})
	})
	if counts[0] != 0 {
		t.Fatalf("first control on the path should suppress, got %d", counts[0])
	}

	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "alternate", "custom.AlternateTransform")
		label(s, "target", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "alternate"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "alternate", Dst: "target"})
	})
	if counts[0] != 0 {
		t.Fatalf("second control on the path should also suppress, got %d", counts[0])
	}

	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "target", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "target"})
	})
	if counts[0] != 1 {
		t.Fatalf("no relevant control -> finding, got %d", counts[0])
	}
}

func TestAliasResolutionThroughEngine(t *testing.T) {
	o := testOntology()
	o.Alias("custom.Input", "custom.LegacyInput")

	if !o.Exists("custom.LegacyInput") {
		t.Fatal("alias should resolve to an existing concept")
	}
	if w := o.DeprecationWarning("custom.LegacyInput"); !strings.Contains(w, "alias of 'custom.Input'") {
		t.Fatalf("alias use should warn, got %q", w)
	}
	if w := o.DeprecationWarning("custom.Input"); w != "" {
		t.Fatalf("canonical, non-deprecated concept should not warn, got %q", w)
	}

	rule := `
module test;
rule AliasFlow {
  meta { id: "ALIAS-1", severity: high }
  taint custom.LegacyInput -> custom.Target as sink
  unless sink.path coveredBy custom.Transform
}
`
	decls, err := parser.ParseRuntime(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, o)
	if len(errs) != 0 {
		t.Fatalf("alias rule should compile, got %v", errs)
	}
	s := usg.NewInMemStore()
	label(s, "in", "custom.Input")
	label(s, "q", "custom.Target")
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	fs, err := New(o, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("alias rule should match the canonical-labeled node (1 finding), got %d", len(fs))
	}
}

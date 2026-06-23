package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func compileEval(t *testing.T, src string, s usg.Store) []int {
	t.Helper()
	onto := solverContractOntology()
	decls, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	eng := New(onto, s)
	var counts []int
	for _, cr := range compiled {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		counts = append(counts, len(fs))
	}
	return counts
}

func TestMatchComposesReachAndAssume(t *testing.T) {
	src := `
package test;
rule ComposedMatch {
  match custom.WorkItem as w
  where reach(custom.Edge, w.workload) and assume(w, custom.Capability)
}
`
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "edge", Type: "custom.Edge"})
	s.AddLabel("edge", usg.Label{Concept: "custom.Edge"})
	s.AddNode(usg.Node{ID: "workload", Type: "custom.Workload", Props: map[string]string{"loc": "workload"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "edge", Dst: "workload", Props: map[string]string{"rule": "edge-workload"}})

	s.AddNode(usg.Node{ID: "item", Type: "custom.WorkItem", Props: map[string]string{"loc": "item", "workload": "workload"}})
	s.AddLabel("item", usg.Label{Concept: "custom.WorkItem"})
	s.AddNode(usg.Node{ID: "capability", Type: "custom.Capability", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("capability", usg.Label{Concept: "custom.Capability"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "item", Dst: "capability", Props: map[string]string{"ability": "item-capability"}})

	s.AddNode(usg.Node{ID: "item2", Type: "custom.WorkItem", Props: map[string]string{"workload": "otherWorkload"}})
	s.AddLabel("item2", usg.Label{Concept: "custom.WorkItem"})
	s.AddNode(usg.Node{ID: "otherWorkload", Type: "custom.Workload"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "item2", Dst: "capability", Props: map[string]string{"ability": "other-capability"}})

	counts := compileEval(t, src, s)
	if counts[0] != 1 {
		t.Fatalf("composed match should fire once, got %d", counts[0])
	}
}

func TestConceptMatchAndTransition(t *testing.T) {
	actionRule := `
package test;
rule UnguardedAction {
  match custom.Action as a
  where a.actor is custom.ActorKind and a.resource is custom.ResourceKind
  unless guarded_by custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "action1", Type: "custom.Action", Props: map[string]string{"loc": "action.execute", "actor": "custom.ActorKind", "resource": "custom.ResourceKind"}})
	g.AddLabel("action1", usg.Label{Concept: "custom.Action"})
	if c := compileEval(t, actionRule, g); c[0] != 1 {
		t.Fatalf("unguarded action: expected 1 finding, got %d", c[0])
	}

	g2 := usg.NewInMemStore()
	g2.AddNode(usg.Node{ID: "action1", Type: "custom.Action", Props: map[string]string{"actor": "custom.ActorKind", "resource": "custom.ResourceKind"}})
	g2.AddLabel("action1", usg.Label{Concept: "custom.Action"})
	g2.AddNode(usg.Node{ID: "guard", Type: "custom.Control"})
	g2.AddLabel("guard", usg.Label{Concept: "custom.Transform"})
	g2.AddEdge(usg.Edge{Type: "CHECKS", Src: "guard", Dst: "action1"})
	if c := compileEval(t, actionRule, g2); c[0] != 0 {
		t.Fatalf("guarded action: expected 0 findings, got %d", c[0])
	}

	transitionRule := `
package test;
rule InvalidTransition {
  match transition * -> Done on Workflow as t
  unless t.from == Allowed
}
`
	gt := usg.NewInMemStore()
	gt.AddNode(usg.Node{ID: "t1", Type: "analysis.Transition", Props: map[string]string{"machine": "Workflow", "from": "Started", "to": "Done"}})
	if c := compileEval(t, transitionRule, gt); c[0] != 1 {
		t.Fatalf("invalid transition: expected 1 finding, got %d", c[0])
	}
	gv := usg.NewInMemStore()
	gv.AddNode(usg.Node{ID: "t1", Type: "analysis.Transition", Props: map[string]string{"machine": "Workflow", "from": "Allowed", "to": "Done"}})
	if c := compileEval(t, transitionRule, gv); c[0] != 0 {
		t.Fatalf("valid transition: expected 0 findings, got %d", c[0])
	}
}

func TestMatchGuardedByDominatingBranchCondition(t *testing.T) {
	actionRule := `
package test;
rule GuardedAction {
  match custom.Action as a
  unless guarded_by custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "sample.go:10", Region: "sample.go/fn1/if1.t", Order: 10, HasOrder: true})
	g.AddLabel("guard", usg.Label{Concept: "custom.Transform"})
	g.AddNode(usg.Node{ID: "action", Type: "code.Arg", Loc: "sample.go:11", Region: "sample.go/fn1/if1.t/if2.t", Order: 11, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEval(t, actionRule, g); c[0] != 0 {
		t.Fatalf("dominating branch guard should suppress match, got %d", c[0])
	}
}

func TestMatchGuardedByDominatingBranchConditionWithQualifiedConcepts(t *testing.T) {
	rule := `
package vypr.memory;
rule CountDerivedElementAccess {
  meta { id: "TEST-MEM", severity: medium, cwe: [CWE_125] }
  match code.CountDerivedElementAccess as idx
  unless guarded_by core.MemoryBoundsCheck
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "bucket.go:666", Region: "bucket.go/fn143/if144.e/if149.t", Order: 2032, HasOrder: true})
	g.AddLabel("guard", usg.Label{Concept: "core.MemoryBoundsCheck"})
	g.AddNode(usg.Node{ID: "idx", Type: "code.Arg", Loc: "bucket.go:667", Region: "bucket.go/fn143/if144.e/if149.t/if150.t", Order: 2038, HasOrder: true})
	g.AddLabel("idx", usg.Label{Concept: "code.CountDerivedElementAccess"})

	decls, err := parser.Parse(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := New(ontology.Seed(), g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("qualified dominating branch guard should suppress match, got %d", len(fs))
	}
}

func TestMatchGuardedBySameXmlFactoryHardening(t *testing.T) {
	rule := `
package vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  match code.XmlParserCreate as p
  unless guarded_by core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "hardening", Type: "code.Call", Loc: "Parser.java:10", Region: "Parser.java/static", Props: map[string]string{"callee_path": "FACTORY.setFeature"}})
	g.AddLabel("hardening", usg.Label{Concept: "core.XmlHardening"})
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20", Region: "Parser.java/fn1", Props: map[string]string{"callee_path": "FACTORY.newDocumentBuilder"}})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})

	decls, err := parser.Parse(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := New(ontology.Seed(), g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("same XML factory hardening should suppress parser creation, got %d", len(fs))
	}
}

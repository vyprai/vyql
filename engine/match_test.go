package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

func compileEval(t *testing.T, src string, s usg.Store) []int {
	t.Helper()
	onto := solverContractOntology()
	decls, err := parseV2DefinitionsForTest(src)
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

func compileEvalV2(t *testing.T, src string, s usg.Store) []int {
	t.Helper()
	onto := solverContractOntology()
	decls, err := parseV2DefinitionsForTest(src)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
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

func coverageLabel(concept, coverage string) usg.Label {
	return usg.Label{Concept: concept, Detail: map[string]string{"coverage": coverage}}
}

func TestMatchComposesReachAndAssume(t *testing.T) {
	src := `
module test;
rule ComposedMatch {
  issue custom.WorkItem as w
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

func TestMatchConfidenceIgnoresUnrelatedCoLocatedLabel(t *testing.T) {
	rule := `
module test;
rule PreciseMatch {
  meta { id: "X-MATCH", confidence_floor: high }
  issue custom.Precise as p
}
`
	decls, err := parseV2DefinitionsForTest(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Precise", Package: "custom", Kind: "sink"})
	onto.Add(ontology.Concept{Name: "Generic", Package: "custom", Kind: "sink"})
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "n", Type: "code.BinOp", Props: map[string]string{"loc": "x:1"}})
	g.AddLabel("n", usg.Label{Concept: "custom.Precise", Provenance: usg.Provenance{Confidence: "high", Fidelity: "resolved"}})
	g.AddLabel("n", usg.Label{Concept: "custom.Generic", Provenance: usg.Provenance{Confidence: "low", Fidelity: "syntactic"}})

	fs, err := New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected high-confidence precise match despite colocated generic label, got %d", len(fs))
	}
	if fs[0].Confidence != "high" {
		t.Fatalf("confidence = %q, want high", fs[0].Confidence)
	}
}

func TestConceptMatchAndTransition(t *testing.T) {
	actionRule := `
module test;
rule UnguardedAction {
  issue custom.Action as a
  where a.actor is custom.ActorKind and a.resource is custom.ResourceKind
  unless sink.endpoint coveredBy custom.Transform
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
	g2.AddLabel("guard", coverageLabel("custom.Transform", "endpoint"))
	g2.AddEdge(usg.Edge{Type: "CHECKS", Src: "guard", Dst: "action1"})
	if c := compileEval(t, actionRule, g2); c[0] != 0 {
		t.Fatalf("guarded action: expected 0 findings, got %d", c[0])
	}

	transitionRule := `
module test;
rule InvalidTransition {
  query state as t where t.machine == Workflow and t.from == Started and t.to == Done select t
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
module test;
rule GuardedAction {
  issue custom.Action as a
  unless a.endpoint coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "sample.go:10", Region: "sample.go/fn1/if1.t", Order: 10, HasOrder: true})
	g.AddLabel("guard", coverageLabel("custom.Transform", "endpoint"))
	g.AddNode(usg.Node{ID: "action", Type: "code.Arg", Loc: "sample.go:11", Region: "sample.go/fn1/if1.t/if2.t", Order: 11, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEval(t, actionRule, g); c[0] != 0 {
		t.Fatalf("dominating branch guard should suppress match, got %d", c[0])
	}
}

func TestMatchSameScopeCoveredBy(t *testing.T) {
	rule := `
module test;
rule SameScopeAction {
  issue custom.Action as a
  unless a.sameScope coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.Call", Loc: "sample.go:10", Scope: "sample.go/fn1"})
	g.AddLabel("guard", coverageLabel("custom.Transform", "sameScope"))
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:11", Scope: "sample.go/fn1/if1"})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 0 {
		t.Fatalf("same-scope guard should suppress nested action, got %d", c[0])
	}
}

func TestMatchSameScopeCoveredByDifferentScopeDoesNotSuppress(t *testing.T) {
	rule := `
module test;
rule SameScopeAction {
  issue custom.Action as a
  unless a.sameScope coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.Call", Loc: "sample.go:10", Scope: "sample.go/fn1"})
	g.AddLabel("guard", coverageLabel("custom.Transform", "sameScope"))
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:20", Scope: "sample.go/fn2"})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 1 {
		t.Fatalf("different-scope guard should not suppress action, got %d", c[0])
	}
}

func TestMatchGlobalCoveredByRequiresGlobalEvidence(t *testing.T) {
	rule := `
module test;
rule GlobalAction {
  issue custom.Action as a
  unless a.global coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.Call", Loc: "sample.go:10"})
	g.AddLabel("guard", usg.Label{Concept: "custom.Transform", Detail: map[string]string{"coverage": "global"}})
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:20"})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 0 {
		t.Fatalf("global guard should suppress action, got %d", c[0])
	}
}

func TestMatchGlobalCoveredByIgnoresOrdinaryEvidence(t *testing.T) {
	rule := `
module test;
rule GlobalAction {
  issue custom.Action as a
  unless a.global coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.Call", Loc: "sample.go:10"})
	g.AddLabel("guard", usg.Label{Concept: "custom.Transform"})
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:20"})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 1 {
		t.Fatalf("ordinary guard evidence should not satisfy global coverage, got %d", c[0])
	}
}

func TestMatchDominatesCoveredBySuppressesDominatedAction(t *testing.T) {
	rule := `
module test;
rule DominatedAction {
  issue custom.Action as a
  unless a.dominates coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "sample.go:10", Region: "sample.go/fn1/if1.t", Order: 10, HasOrder: true})
	g.AddLabel("guard", coverageLabel("custom.Transform", "dominates"))
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:11", Region: "sample.go/fn1/if1.t/if2.t", Order: 11, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 0 {
		t.Fatalf("dominating guard should satisfy dominates coverage, got %d", c[0])
	}
}

func TestMatchDominatesCoveredByDoesNotUsePostDominance(t *testing.T) {
	rule := `
module test;
rule DominatedAction {
  issue custom.Action as a
  unless a.dominates coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:10", Region: "sample.go/fn1/if1.t", Order: 10, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})
	g.AddNode(usg.Node{ID: "release", Type: "code.Call", Loc: "sample.go:20", Region: "sample.go/fn1", Order: 20, HasOrder: true})
	g.AddLabel("release", coverageLabel("custom.Transform", "dominates"))

	if c := compileEvalV2(t, rule, g); c[0] != 1 {
		t.Fatalf("post-dominating release must not satisfy dominates coverage, got %d", c[0])
	}
}

func TestMatchDominatesCoveredByIgnoresAdvisoryEvidence(t *testing.T) {
	rule := `
module test;
rule DominatedAction {
  issue custom.Action as a
  unless a.dominates coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "sample.go:10", Region: "sample.go/fn1", Order: 10, HasOrder: true})
	g.AddLabel("guard", usg.Label{Concept: "custom.Transform", Detail: map[string]string{"advisory": "true"}})
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "sample.go:11", Region: "sample.go/fn1/if1.t", Order: 11, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})

	if c := compileEvalV2(t, rule, g); c[0] != 1 {
		t.Fatalf("advisory guard must not satisfy dominates coverage, got %d", c[0])
	}
}

func TestTaintDominatesCoveredBySuppressesDominatedSink(t *testing.T) {
	rule := `
module test;
rule DominatedFlow {
  taint custom.Input -> custom.Target as sink
  unless sink.dominates coveredBy custom.Transform
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "input", Type: "code.Call", Loc: "sample.go:5"})
	g.AddLabel("input", usg.Label{Concept: "custom.Input"})
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "sample.go:10", Region: "sample.go/fn1", Order: 10, HasOrder: true})
	g.AddLabel("guard", coverageLabel("custom.Transform", "dominates"))
	g.AddNode(usg.Node{ID: "sink", Type: "code.Call", Loc: "sample.go:11", Region: "sample.go/fn1/if1.t", Order: 11, HasOrder: true})
	g.AddLabel("sink", usg.Label{Concept: "custom.Target"})
	g.AddEdge(usg.Edge{Type: "FLOWS", Src: "input", Dst: "sink"})

	if c := compileEvalV2(t, rule, g); c[0] != 0 {
		t.Fatalf("dominating guard should suppress taint finding, got %d", c[0])
	}
}

func TestMatchGuardedByDominatingBranchConditionWithQualifiedConcepts(t *testing.T) {
	rule := `
module vypr.memory;
rule CountDerivedElementAccess {
  meta { id: "TEST-MEM", severity: medium, cwe: [CWE_125] }
  issue code.CountDerivedElementAccess as idx
  unless idx.endpoint coveredBy core.MemoryBoundsCheck
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "guard", Type: "code.BinOp", Loc: "bucket.go:666", Region: "bucket.go/fn143/if144.e/if149.t", Order: 2032, HasOrder: true})
	g.AddLabel("guard", coverageLabel("core.MemoryBoundsCheck", "endpoint"))
	g.AddNode(usg.Node{ID: "idx", Type: "code.Arg", Loc: "bucket.go:667", Region: "bucket.go/fn143/if144.e/if149.t/if150.t", Order: 2038, HasOrder: true})
	g.AddLabel("idx", usg.Label{Concept: "code.CountDerivedElementAccess"})

	decls, err := parseV2DefinitionsForTest(rule)
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
module vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  issue code.XmlParserCreate as p
  unless p.sameReceiver coveredBy core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "hardening", Type: "code.Call", Loc: "Parser.java:10", Region: "Parser.java/static", Props: map[string]string{"callee_path": "FACTORY.setFeature"}})
	g.AddLabel("hardening", coverageLabel("core.XmlHardening", "sameReceiver"))
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20", Region: "Parser.java/fn1", Props: map[string]string{"callee_path": "FACTORY.newDocumentBuilder"}})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})

	decls, err := parseV2DefinitionsForTest(rule)
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

func TestMatchGuardedBySameReceiverNodeLabel(t *testing.T) {
	rule := `
module vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  issue code.XmlParserCreate as p
  unless p.sameReceiver coveredBy core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "factory", Type: "code.Name", Loc: "Parser.java:10"})
	g.AddLabel("factory", coverageLabel("core.XmlHardening", "sameReceiver"))
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20", Props: map[string]string{"recv": "factory"}})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})

	decls, err := parseV2DefinitionsForTest(rule)
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
		t.Fatalf("same receiver label should suppress parser creation, got %d", len(fs))
	}
}

func TestV2SameReceiverCoveredByIgnoresEndpointEvidence(t *testing.T) {
	rule := `
module vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  issue code.XmlParserCreate as p
  unless p.sameReceiver coveredBy core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "hardening", Type: "code.Call", Loc: "Parser.java:10"})
	g.AddLabel("hardening", coverageLabel("core.XmlHardening", "endpoint"))
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20"})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})
	g.AddEdge(usg.Edge{Type: "PROTECTS", Src: "hardening", Dst: "parser"})

	decls, err := parseV2DefinitionsForTest(rule)
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
	if len(fs) != 1 {
		t.Fatalf("endpoint evidence should not satisfy sameReceiver coverage, got %d findings", len(fs))
	}
}

func TestV2EndpointCoveredByIgnoresSameReceiverEvidence(t *testing.T) {
	rule := `
module vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  issue code.XmlParserCreate as p
  unless p.endpoint coveredBy core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "factory", Type: "code.Name", Loc: "Parser.java:10"})
	g.AddLabel("factory", coverageLabel("core.XmlHardening", "sameReceiver"))
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20", Props: map[string]string{"recv": "factory"}})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})

	decls, err := parseV2DefinitionsForTest(rule)
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
	if len(fs) != 1 {
		t.Fatalf("sameReceiver evidence should not satisfy endpoint coverage, got %d findings", len(fs))
	}
}

func TestV2SameReceiverCoveredByReceiverNodeLabel(t *testing.T) {
	rule := `
module vypr.deserialization;
rule XxeUnhardened {
  meta { id: "TEST-XXE", severity: medium, cwe: [CWE_611] }
  issue code.XmlParserCreate as p
  unless p.sameReceiver coveredBy core.XmlHardening
}
`
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "factory", Type: "code.Name", Loc: "Parser.java:10"})
	g.AddLabel("factory", coverageLabel("core.XmlHardening", "sameReceiver"))
	g.AddNode(usg.Node{ID: "parser", Type: "code.Call", Loc: "Parser.java:20", Props: map[string]string{"recv": "factory"}})
	g.AddLabel("parser", usg.Label{Concept: "code.XmlParserCreate"})

	decls, err := parseV2DefinitionsForTest(rule)
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
		t.Fatalf("same receiver label should satisfy sameReceiver coverage, got %d findings", len(fs))
	}
}

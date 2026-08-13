package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/definitions"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/usg"
)

func runRule(t *testing.T, src string, build func(s usg.Store)) ([]int, []CompileError) {
	t.Helper()
	onto := testOntology()
	decls, err := parseV2DefinitionsForTest(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	store := usg.NewInMemStore()
	build(store)
	eng := New(onto, store)
	var counts []int
	for _, cr := range compiled {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("evaluate error: %v", err)
		}
		counts = append(counts, len(fs))
	}
	return counts, errs
}

func testOntology() *ontology.Ontology {
	return addFlowConcepts(ontology.New())
}

func addFlowConcepts(onto *ontology.Ontology) *ontology.Ontology {
	onto.Add(ontology.Concept{
		Name:    "ParentInput",
		Package: "custom",
		Kind:    "source",
		Taint:   []string{"custom.Taint"},
	})
	onto.Add(ontology.Concept{
		Name:    "Input",
		Package: "custom",
		Kind:    "source",
		Taint:   []string{"custom.Taint"},
		Refines: "custom.ParentInput",
	})
	onto.Add(ontology.Concept{
		Name:         "Target",
		Package:      "custom",
		Kind:         "sink",
		VulnerableTo: []string{"custom.Condition"},
		EnabledBy:    []string{"custom.Taint"},
	})
	onto.Add(ontology.Concept{
		Name:         "OtherTarget",
		Package:      "custom",
		Kind:         "sink",
		VulnerableTo: []string{"custom.OtherCondition"},
		EnabledBy:    []string{"custom.Taint"},
	})
	onto.Add(ontology.Concept{
		Name:        "Transform",
		Package:     "custom",
		Kind:        "control",
		Neutralizes: []string{"custom.Condition"},
	})
	onto.Add(ontology.Concept{
		Name:        "AlternateTransform",
		Package:     "custom",
		Kind:        "control",
		Neutralizes: []string{"custom.Condition"},
	})
	onto.Add(ontology.Concept{
		Name:        "OtherTargetTransform",
		Package:     "custom",
		Kind:        "control",
		Neutralizes: []string{"custom.OtherCondition"},
	})
	onto.Add(ontology.Concept{
		Name:        "OtherTransform",
		Package:     "custom",
		Kind:        "control",
		Neutralizes: []string{"custom.OtherCondition"},
	})
	return onto
}

func TestEvaluateRejectsUnsupportedCompiledRuleVerb(t *testing.T) {
	cr := &CompiledRule{
		Rule: &parser.Rule{
			Name:    "InternalUnsupported",
			Package: "test",
			Meta:    map[string]any{"id": "TEST-UNSUPPORTED", "severity": "medium"},
			Body: &parser.FlowStmt{
				Verb: "assume",
				Src:  parser.Endpoint{Concept: "custom.Input"},
				Dst:  parser.Endpoint{Concept: "custom.Target"},
			},
		},
		Severity: "medium",
	}
	_, err := New(testOntology(), usg.NewInMemStore()).Evaluate(cr)
	if err == nil || !strings.Contains(err.Error(), `unsupported rule verb "assume"`) {
		t.Fatalf("Evaluate error = %v, want unsupported internal verb diagnostic", err)
	}
}

const flowRule = `
module test;
rule Flow {
  meta { id: "TEST-FLOW", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.path coveredBy custom.Transform
}
`

func label(s usg.Store, id, concept string) {
	s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
	s.AddLabel(id, usg.Label{Concept: concept})
}

func TestEngineDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	concepts := ontologyVocabularyNeedles(t)
	var hits []string
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, needle := range concepts {
			if strings.Contains(text, needle) {
				hits = append(hits, filepath.Base(path)+": "+needle)
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("engine must not hardcode ontology concepts; move roles/semantics into ontology metadata: %s", strings.Join(hits, ", "))
	}
}

func TestLabelProvenancePrefersGenericPriority(t *testing.T) {
	onto := testOntology()
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "target", Type: "code.Call", Props: map[string]string{"loc": "x:1"}})
	store.AddLabel("target", usg.Label{
		Concept:    "custom.Target",
		Provenance: usg.Provenance{Applicator: "generic.adapter", Fidelity: "resolved"},
	})
	store.AddLabel("target", usg.Label{
		Concept:    "custom.Target",
		Provenance: usg.Provenance{Applicator: "priority.adapter", Fidelity: "semantic"},
		Detail:     map[string]string{"provenance_priority": "100"},
	})

	got := New(onto, store).prov("target", "custom.Target")
	if got != "custom.Target by priority.adapter@semantic" {
		t.Fatalf("provenance priority not honored: %q", got)
	}
}

func TestLabelProvenancePriorityIgnoresAdapterName(t *testing.T) {
	if got := labelProvenancePriority(usg.Label{
		Provenance: usg.Provenance{Applicator: "priority.adapter"},
	}); got != 0 {
		t.Fatalf("adapter name influenced provenance priority: got %d", got)
	}
	if got := labelProvenancePriority(usg.Label{
		Provenance: usg.Provenance{Applicator: "plain.adapter"},
		Detail:     map[string]string{"provenance_priority": "7"},
	}); got != 7 {
		t.Fatalf("metadata provenance priority not honored: got %d", got)
	}
}

func TestTaintFlowCacheKeyCanonicalAndPolicySensitive(t *testing.T) {
	a := taintFlowCacheKey(
		map[string]bool{"src.B": true, "src.A": true},
		map[string]bool{"sink.A": true},
		map[string]bool{"kind.B": true, "kind.A": true},
		map[string]bool{"kill.A": true},
		"<>&",
		map[string]bool{"char.B": true, "char.A": true},
	)
	b := taintFlowCacheKey(
		map[string]bool{"src.A": true, "src.B": true},
		map[string]bool{"sink.A": true},
		map[string]bool{"kind.A": true, "kind.B": true},
		map[string]bool{"kill.A": true},
		"<>&",
		map[string]bool{"char.A": true, "char.B": true},
	)
	if a != b {
		t.Fatalf("cache key depends on map iteration order:\n%s\n%s", a, b)
	}
	c := taintFlowCacheKey(
		map[string]bool{"src.A": true, "src.B": true},
		map[string]bool{"sink.A": true},
		map[string]bool{"kind.A": true, "kind.B": true},
		map[string]bool{"kill.B": true},
		"<>&",
		map[string]bool{"char.A": true, "char.B": true},
	)
	if c == a {
		t.Fatal("cache key ignored kill-control policy")
	}
	ba := taintFlowBatchKey(
		map[string]bool{"src.B": true, "src.A": true},
		map[string]bool{"kind.B": true, "kind.A": true},
		map[string]bool{"kill.A": true},
		"<>&",
		map[string]bool{"char.B": true, "char.A": true},
	)
	bb := taintFlowBatchKey(
		map[string]bool{"src.A": true, "src.B": true},
		map[string]bool{"kind.A": true, "kind.B": true},
		map[string]bool{"kill.A": true},
		"<>&",
		map[string]bool{"char.A": true, "char.B": true},
	)
	if ba != bb {
		t.Fatalf("batch cache key depends on map iteration order:\n%s\n%s", ba, bb)
	}
}

func TestPrecomputeTaintFlowsBatchesUnionSinksWithoutChangingFindings(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module test;
rule FlowA {
  meta { id: "TEST-FLOW-A", severity: high }
  taint custom.Input -> custom.Target
}
rule FlowB {
  meta { id: "TEST-FLOW-B", severity: medium }
  taint custom.Input -> custom.OtherTarget
}
`)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	onto := testOntology()
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	build := func(s usg.Store) {
		label(s, "src", "custom.Input")
		label(s, "target", "custom.Target")
		label(s, "other", "custom.OtherTarget")
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "target"}); err != nil {
			t.Fatal(err)
		}
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "other"}); err != nil {
			t.Fatal(err)
		}
	}

	baselineStore := usg.NewInMemStore()
	build(baselineStore)
	baselineEng := New(onto, baselineStore)
	var baselineCounts []int
	for _, cr := range compiled {
		fs, err := baselineEng.Evaluate(cr)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		baselineCounts = append(baselineCounts, len(fs))
	}
	if len(baselineCounts) != 2 || baselineCounts[0] != 1 || baselineCounts[1] != 1 {
		t.Fatalf("unexpected baseline counts: %v", baselineCounts)
	}

	baseline := evalSignatures(t, New(onto, baselineStore), compiled)

	batchedStore := usg.NewInMemStore()
	build(batchedStore)
	batchedEngine := New(onto, batchedStore)
	if err := batchedEngine.PrecomputeTaintFlows(compiled); err != nil {
		t.Fatalf("PrecomputeTaintFlows: %v", err)
	}
	if got := len(batchedEngine.taintFlowCache); got != 2 {
		t.Fatalf("precompute cache entries = %d, want one exact entry per rule", got)
	}
	if got := evalSignatures(t, batchedEngine, compiled); strings.Join(got, "\n") != strings.Join(baseline, "\n") {
		t.Fatalf("batched findings changed:\nbase=%v\n got=%v", baseline, got)
	}
}

func TestNegationEvidenceDetailScenarios(t *testing.T) {
	onto := ontology.Seed()
	ruleSrc := `
module test.rules;
rule TestCmdInjection {
    meta { id: "TEST-CMD", severity: high }
    taint code.HttpInput -> code.CommandExecution
    unless path coveredBy core.CommandArgumentValidation
}
`
	decls, err := parseV2DefinitionsForTest(ruleSrc)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) > 0 {
		t.Fatalf("compile errors: %v", errs)
	}

	// 1. Go file (Scenario 1: CommandArgumentValidation is bound in Go)
	storeGo := usg.NewInMemStore()
	storeGo.AddNode(usg.Node{ID: "src", Type: "code.Input", Loc: "app.go:10:1"})
	storeGo.AddNode(usg.Node{ID: "snk", Type: "code.Call", Loc: "app.go:20:1"})
	storeGo.AddLabel("src", usg.Label{Concept: "code.HttpInput"})
	storeGo.AddLabel("snk", usg.Label{Concept: "code.CommandExecution"})
	storeGo.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "snk"})

	engGo := New(onto, storeGo)
	fsGo, err := engGo.Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if len(fsGo) != 1 || len(fsGo[0].NegationEvidence) == 0 {
		t.Fatalf("expected finding with negation evidence for Go")
	}
	detailGo := fsGo[0].NegationEvidence[0].Detail
	if !strings.Contains(detailGo, "control is bound in go") && !strings.Contains(detailGo, "user should fix code") {
		t.Fatalf("expected Scenario 1 message for Go, got detail: %q", detailGo)
	}

	// 2. Java file (Scenario 2: Java has no binding for CommandExecution controls in orphaned_sinks.txt)
	storeJava := usg.NewInMemStore()
	storeJava.AddNode(usg.Node{ID: "src", Type: "code.Input", Loc: "App.java:10:1"})
	storeJava.AddNode(usg.Node{ID: "snk", Type: "code.Call", Loc: "App.java:20:1"})
	storeJava.AddLabel("src", usg.Label{Concept: "code.HttpInput"})
	storeJava.AddLabel("snk", usg.Label{Concept: "code.CommandExecution"})
	storeJava.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "snk"})

	engJava := New(onto, storeJava)
	fsJava, err := engJava.Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if len(fsJava) != 1 || len(fsJava[0].NegationEvidence) == 0 {
		t.Fatalf("expected finding with negation evidence for Java")
	}
	detailJava := fsJava[0].NegationEvidence[0].Detail
	if !strings.Contains(detailJava, "has no binding for it") && !strings.Contains(detailJava, "no action required") {
		t.Fatalf("expected Scenario 2 message for Java, got detail: %q", detailJava)
	}

	// 3. Scenario 3: Threat with no control concept anywhere (e.g. concurrency.Toctou)
	class3 := definitions.ClassifyControlDefault("go", "concurrency.Toctou", "")
	if class3.Scenario != definitions.ScenarioControlMissingFromOntology {
		t.Fatalf("expected ScenarioControlMissingFromOntology for Toctou, got %+v", class3)
	}
	if !strings.Contains(class3.Message, "no control concept exists for this threat") || !strings.Contains(class3.Message, "no action required") {
		t.Fatalf("expected Scenario 3 message, got: %q", class3.Message)
	}
}

func evalSignatures(t *testing.T, eng *Engine, rules []*CompiledRule) []string {
	t.Helper()
	var out []string
	for _, cr := range rules {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", cr.Rule.QualifiedName(), err)
		}
		for _, f := range fs {
			sink := ""
			source := ""
			for _, b := range f.Bindings {
				switch b.Name {
				case "source":
					source = b.NodeID + ":" + b.Concept
				case "sink":
					sink = b.NodeID + ":" + b.Concept
				}
			}
			out = append(out, f.RuleID+"|"+source+"|"+sink+"|"+f.Confidence)
		}
	}
	return out
}

func ontologyVocabularyNeedles(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range ontology.Seed().AllConcepts() {
		if ontology.IsInternalConceptRoleConcept(c.QualifiedName()) {
			continue
		}
		seen["\""+c.Name+"\""] = true
		seen["\""+c.QualifiedName()+"\""] = true
		for _, id := range append(append([]string{}, c.CWE...), append(c.CAPEC, c.Attack...)...) {
			seen["\""+id+"\""] = true
		}
	}
	for _, tk := range ontology.ThreatKinds() {
		seen["\""+tk.Name+"\""] = true
		seen["\""+tk.QualifiedName()+"\""] = true
		for _, id := range tk.CWE {
			seen["\""+id+"\""] = true
		}
	}
	addPackRuleIDNeedles(t, seen)
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

func addPackRuleIDNeedles(t *testing.T, seen map[string]bool) {
	t.Helper()
	root := filepath.Join(datadir.Root(), "packs")
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		decls, err := parseV2DefinitionsForTest(string(raw))
		if err != nil {
			return err
		}
		for _, decl := range decls {
			rule, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			if id, _ := rule.Meta["id"].(string); id != "" {
				seen["\""+id+"\""] = true
				seen["`"+id+"`"] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read pack rule ids: %v", err)
	}
}

func TestTaintFindingAndSanitizer(t *testing.T) {
	counts, errs := runRule(t, flowRule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "q", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected compile errors: %v", errs)
	}
	if counts[0] != 1 {
		t.Fatalf("direct flow case: expected 1 finding, got %d", counts[0])
	}

	counts, _ = runRule(t, flowRule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "p", "custom.Transform")
		label(s, "q", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "p"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "p", Dst: "q"})
	})
	if counts[0] != 0 {
		t.Fatalf("transformed case: expected 0 findings, got %d", counts[0])
	}

	counts, _ = runRule(t, flowRule, func(s usg.Store) {
		label(s, "in", "custom.Input")
		label(s, "p", "custom.Transform")
		label(s, "q", "custom.Target")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "p"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "p", Dst: "q"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	})
	if counts[0] != 1 {
		t.Fatalf("alternate path case: expected 1 finding, got %d", counts[0])
	}
}

func TestMistypedSanitizerRejected(t *testing.T) {
	src := `
module bad;
rule MismatchedTransform {
  taint custom.Input -> custom.Target as sink
  unless sink.path coveredBy custom.OtherTransform
}
`
	_, errs := runRule(t, src, func(s usg.Store) {})
	if len(errs) != 1 {
		t.Fatalf("expected 1 compile error, got %d: %v", len(errs), errs)
	}
	if !contains(errs[0].Msg, "does not defend") {
		t.Fatalf("expected 'does not defend' error, got %q", errs[0].Msg)
	}
}

func TestWrongRoleEndpoint(t *testing.T) {
	src := `
module bad;
rule Reversed { taint custom.Target -> custom.Input }
`
	_, errs := runRule(t, src, func(s usg.Store) {})
	if len(errs) != 1 || !contains(errs[0].Msg, "wrong role") {
		t.Fatalf("expected wrong-role compile error, got %v", errs)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

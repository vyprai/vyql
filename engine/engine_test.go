package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func runRule(t *testing.T, src string, build func(s usg.Store)) ([]int, []CompileError) {
	t.Helper()
	onto := testOntology()
	decls, err := parser.Parse(src)
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

func seededTestOntology() *ontology.Ontology {
	return addFlowConcepts(ontology.Seed())
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

const flowRule = `
package test;
rule Flow {
  meta { id: "TEST-FLOW", severity: high }
  taint custom.Input -> custom.Target
  unless sanitized_by custom.Transform
}
`

func label(s usg.Store, id, concept string) {
	s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
	s.AddLabel(id, usg.Label{Concept: concept})
}

func TestPossibilityFindingsUseConceptReviewData(t *testing.T) {
	onto := ontology.New()
	onto.Add(ontology.Concept{
		Name:             "Target",
		Package:          "custom",
		Kind:             "sink",
		VulnerableTo:     []string{"custom.Condition"},
		ReviewCategory:   "custom-category",
		ReviewCondition:  "custom condition text",
		ReviewEvidence:   "custom evidence text",
		ReviewAssumption: "custom assumption text",
		ReviewConfidence: "medium",
	})
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "target", Type: "code.Call", Props: map[string]string{"loc": "x:1"}})
	store.AddLabel("target", usg.Label{Concept: "custom.Target"})

	got := New(onto, store).PossibilityFindings(nil)
	if len(got) != 1 {
		t.Fatalf("possibility findings = %d, want 1", len(got))
	}
	rc := got[0].ReviewConditions[0]
	if rc.Category != "custom-category" ||
		rc.Condition != "custom condition text" ||
		rc.Evidence != "custom evidence text" ||
		rc.Assumption != "custom assumption text" ||
		rc.Confidence != "medium" {
		t.Fatalf("review condition was not data-driven: %+v", rc)
	}
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
		Provenance: usg.Provenance{Adapter: "generic.adapter", Fidelity: "resolved"},
	})
	store.AddLabel("target", usg.Label{
		Concept:    "custom.Target",
		Provenance: usg.Provenance{Adapter: "priority.adapter", Fidelity: "semantic"},
		Detail:     map[string]string{"provenance_priority": "100"},
	})

	got := New(onto, store).prov("target", "custom.Target")
	if got != "custom.Target by priority.adapter@semantic" {
		t.Fatalf("provenance priority not honored: %q", got)
	}
}

func TestLabelProvenancePriorityIgnoresAdapterName(t *testing.T) {
	if got := labelProvenancePriority(usg.Label{
		Provenance: usg.Provenance{Adapter: "priority.adapter"},
	}); got != 0 {
		t.Fatalf("adapter name influenced provenance priority: got %d", got)
	}
	if got := labelProvenancePriority(usg.Label{
		Provenance: usg.Provenance{Adapter: "plain.adapter"},
		Detail:     map[string]string{"provenance_priority": "7"},
	}); got != 7 {
		t.Fatalf("metadata provenance priority not honored: got %d", got)
	}
}

func ontologyVocabularyNeedles(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range ontology.Seed().AllConcepts() {
		if c.AnalysisRole != "" {
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
		decls, err := parser.Parse(string(raw))
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
package bad;
rule MismatchedTransform {
  taint custom.Input -> custom.Target
  unless sanitized_by custom.OtherTransform
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
package bad;
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

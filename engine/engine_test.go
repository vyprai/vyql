package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// helper: build a store, compile a rule program, evaluate the single rule.
func runRule(t *testing.T, src string, build func(s usg.Store)) ([]int, []CompileError) {
	t.Helper()
	onto := ontology.Seed()
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

const sqliRule = `
package vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE_89] }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
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

// Mirrors poc/cases/case_01 (universality) + case_03: a tainted source reaching
// an unparameterized SQL sink is a finding.
func TestTaintFindingAndSanitizer(t *testing.T) {
	// vulnerable: HttpInput -> SqlExecution, no sanitizer -> 1 finding
	counts, errs := runRule(t, sqliRule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "q", "code.SqlExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected compile errors: %v", errs)
	}
	if counts[0] != 1 {
		t.Fatalf("vulnerable case: expected 1 finding, got %d", counts[0])
	}

	// sanitized: only path passes through SqlParameterization -> 0 findings
	counts, _ = runRule(t, sqliRule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "p", "core.SqlParameterization")
		label(s, "q", "code.SqlExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "p"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "p", Dst: "q"})
	})
	if counts[0] != 0 {
		t.Fatalf("sanitized case: expected 0 findings, got %d", counts[0])
	}

	// branch-around: tainted value flows around the sanitizer -> 1 finding
	counts, _ = runRule(t, sqliRule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "p", "core.SqlParameterization")
		label(s, "q", "code.SqlExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "p"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "p", Dst: "q"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"}) // bypass
	})
	if counts[0] != 1 {
		t.Fatalf("branch-around case: expected 1 finding, got %d", counts[0])
	}
}

// Mirrors poc/cases/case_02/03: a mistyped sanitizer is a COMPILE error.
func TestMistypedSanitizerRejected(t *testing.T) {
	src := `
package bad;
rule SqliWithHtmlEscape {
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.HtmlEscape
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

// Wrong-role endpoint (sink as source) is a compile error.
func TestWrongRoleEndpoint(t *testing.T) {
	src := `
package bad;
rule Reversed { taint code.SqlExecution -> code.HttpInput }
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

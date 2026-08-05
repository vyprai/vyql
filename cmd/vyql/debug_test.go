package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/usg"
)

func TestDebugConceptClassificationUsesPassedOntology(t *testing.T) {
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Input", Package: "customdebug", Kind: "source"})
	onto.Add(ontology.Concept{Name: "Target", Package: "customdebug", Kind: "sink"})

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "in", Type: "code.X"})
	store.AddNode(usg.Node{ID: "out", Type: "code.X"})
	store.AddLabel("in", usg.Label{Concept: "customdebug.Input"})
	store.AddLabel("out", usg.Label{Concept: "customdebug.Target"})

	if !isSourceConcept(onto, "customdebug.Input") {
		t.Fatal("source concept should be classified from the passed ontology")
	}
	if !isSource(onto, store, "in") {
		t.Fatal("source node should be classified from the passed ontology")
	}
	if !isSink(onto, store, "out") {
		t.Fatal("sink node should be classified from the passed ontology")
	}
}

func TestValidateBindingRunsV2CorpusValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binding.vyql")
	if err := os.WriteFile(path, []byte(`
module bindings.python.test;
binding bad {
  query pattern callExpr where callee.method == "execute"
  emit sink custom.MissingSink at args[0]
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdValidateBinding([]string{"-file", path})
	if err == nil || !strings.Contains(err.Error(), "unknown concept custom.MissingSink") {
		t.Fatalf("cmdValidateBinding error = %v, want corpus validation", err)
	}
}

func TestBindingDisplayKindUsesV2AdvisoryVocabulary(t *testing.T) {
	cases := []struct {
		in   parser.BindingAction
		want string
	}{
		{parser.BindingAction{Kind: "advisory_guard_method"}, "advisory"},
		{parser.BindingAction{Kind: "advisory_sanitizer_path"}, "advisory"},
		{parser.BindingAction{Kind: "source_param"}, "source"},
		{parser.BindingAction{Kind: "sink_call_arg"}, "sink"},
		{parser.BindingAction{Kind: "check_authentication"}, "check"},
		{parser.BindingAction{Kind: "issue_method"}, "issue"},
		{parser.BindingAction{Kind: "presence_issue"}, "issue"},
		{parser.BindingAction{Kind: "presence_check"}, "check"},
		{parser.BindingAction{Kind: "flow_method"}, "propagate"},
		{parser.BindingAction{Kind: "type"}, "type"},
	}
	for _, tc := range cases {
		if got := bindingDisplayKind(tc.in); got != tc.want {
			t.Fatalf("bindingDisplayKind(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateBindingReportsV2IssueKinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binding.vyql")
	if err := os.WriteFile(path, []byte(`
module bindings.javascript.test;
binding callIssue {
  query pattern callExpr where callee.method == "danger"
  emit issue code.WeakCipher at call
}
binding presenceIssue {
  query pattern presenceNode where node.kind == "any" and node.path ~= "Random"
  emit issue code.WeakRandomValue at node
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return cmdValidateBinding([]string{"-file", path})
	})
	if err != nil {
		t.Fatalf("cmdValidateBinding: %v", err)
	}
	if strings.Contains(out, `"mark`) || strings.Contains(out, `"flag"`) {
		t.Fatalf("validate-binding leaked legacy action kind:\n%s", out)
	}
	if got := strings.Count(out, `"kind": "issue"`); got != 2 {
		t.Fatalf("validate-binding issue kind count = %d, want 2:\n%s", got, out)
	}
}

func TestFindingsJSONUsesV2AdvisoryVocabulary(t *testing.T) {
	got := findingsJSON([]*findings.Finding{{
		RuleID:     "VYQL-TEST-001",
		Severity:   "medium",
		Confidence: "medium",
		Bindings: []findings.Binding{{
			Name: "sink",
			Loc:  "app.js:1",
		}},
		NegationEvidence: []findings.NegationEvidence{{
			Clause:    "path advisory",
			Satisfied: false,
			Detail:    "candidate advisory evidence",
		}},
		ReviewConditions: []findings.ReviewCondition{{
			Condition:  "review this",
			Assumption: "requires a deployment condition",
		}},
	}})
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"advisory_noted":true`) || !strings.Contains(text, `"advisory":"requires a deployment condition"`) {
		t.Fatalf("findings JSON should use v2 advisory fields, got %s", text)
	}
	if strings.Contains(text, "assumption_noted") || strings.Contains(text, `"Assumption"`) || strings.Contains(text, `"assumption"`) {
		t.Fatalf("findings JSON leaked legacy assumption vocabulary: %s", text)
	}
}

func TestCmdRuntimeDoesNotHardcodeDomainKnowledge(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	needles := cmdForbiddenKnowledgeNeedles(t)
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		if strings.Contains(text, `Concept: "`) || strings.Contains(text, "Concept: `") {
			rel, _ := filepath.Rel(root, path)
			hits = append(hits, rel+": direct concept literal")
		}
		for _, needle := range needles {
			if strings.Contains(text, needle) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, rel+": "+needle)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("cmd runtime must not hardcode ontology/domain knowledge; load it from VyQL data: %s", strings.Join(hits, ", "))
	}
}

func cmdForbiddenKnowledgeNeedles(t *testing.T) []string {
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
	for _, phrase := range []string{"threat-model", "threat model", "trust boundary"} {
		seen[phrase] = true
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

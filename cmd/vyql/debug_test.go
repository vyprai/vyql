package main

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

func TestValidateAdapterRunsV2CorpusValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adapter.vyql")
	if err := os.WriteFile(path, []byte(`
module bindings.python.test;
binding bad {
  query pattern callExpr where callee.method == "execute"
  emit sink custom.MissingSink at args[0]
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdValidateAdapter([]string{"-file", path})
	if err == nil || !strings.Contains(err.Error(), "unknown concept custom.MissingSink") {
		t.Fatalf("cmdValidateAdapter error = %v, want corpus validation", err)
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
		decls, err := parser.ParseRuntime(string(raw))
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

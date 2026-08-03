package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/resultpolicy"
	"github.com/vyprai/vyql/usg"
)

func TestCompileLoweredV2Rule(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) > 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(compiled))
	}
	cr := compiled[0]
	if cr.Rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("qualified name = %q", cr.Rule.QualifiedName())
	}
	if !cr.KillControls["core.SqlParameterization"] {
		t.Fatalf("coveredBy check did not become a kill control: %+v", cr.KillControls)
	}
}

func TestLoweredV2ConfidenceClauseFiltersFindings(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module rules.review;
rule HighConfidenceReview {
  issue custom.Review as r
  with confidence >= high
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Review", Package: "custom", Kind: "issue"})
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "low", Type: "code.Call"})
	store.AddLabel("low", usg.Label{Concept: "custom.Review", Provenance: usg.Provenance{Confidence: "low"}})
	if got, err := New(onto, store).Evaluate(compiled[0]); err != nil {
		t.Fatalf("evaluate low: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("low-confidence finding passed v2 floor: %+v", got)
	}

	store.AddNode(usg.Node{ID: "high", Type: "code.Call"})
	store.AddLabel("high", usg.Label{Concept: "custom.Review", Provenance: usg.Provenance{Confidence: "high"}})
	got, err := New(onto, store).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate high: %v", err)
	}
	if len(got) != 1 || got[0].Bindings[0].NodeID != "high" {
		t.Fatalf("high-confidence finding did not pass v2 floor: %+v", got)
	}
}

func TestLoweredV2FindingFingerprintStableAcrossStores(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput -> code.SqlExecution
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	onto := ontology.Seed()
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}

	mem := usg.NewInMemStore()
	loadV2FingerprintGraph(t, mem)
	memFP := v2SingleFingerprint(t, onto, mem, compiled[0])
	if got := v2SingleFingerprint(t, onto, mem, compiled[0]); got != memFP {
		t.Fatalf("in-memory v2 fingerprint changed across runs: %s then %s", memFP, got)
	}

	badger, err := usg.OpenBadger(":memory:")
	if err != nil {
		t.Fatalf("OpenBadger: %v", err)
	}
	defer badger.Close()
	loadV2FingerprintGraph(t, badger)
	badgerFP := v2SingleFingerprint(t, onto, badger, compiled[0])
	if badgerFP != memFP {
		t.Fatalf("v2 fingerprint differs across stores: mem=%s badger=%s", memFP, badgerFP)
	}
	if got := v2SingleFingerprint(t, onto, badger, compiled[0]); got != badgerFP {
		t.Fatalf("badger v2 fingerprint changed across runs: %s then %s", badgerFP, got)
	}
}

func TestLoweredV2DedupCanonicalAcrossStoreOrder(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput -> code.SqlExecution
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	onto := ontology.Seed()
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}

	memA := usg.NewInMemStore()
	loadV2DuplicateFlowGraph(t, memA, []string{"srcB", "srcA"})
	memSource := v2SingleSourceBinding(t, onto, memA, compiled[0])
	if memSource != "srcA" {
		t.Fatalf("canonical in-memory source = %q, want srcA", memSource)
	}

	memB := usg.NewInMemStore()
	loadV2DuplicateFlowGraph(t, memB, []string{"srcA", "srcB"})
	if got := v2SingleSourceBinding(t, onto, memB, compiled[0]); got != memSource {
		t.Fatalf("in-memory canonical source changed across insertion order: %s then %s", memSource, got)
	}

	badger, err := usg.OpenBadger(":memory:")
	if err != nil {
		t.Fatalf("OpenBadger: %v", err)
	}
	defer badger.Close()
	loadV2DuplicateFlowGraph(t, badger, []string{"srcB", "srcA"})
	if got := v2SingleSourceBinding(t, onto, badger, compiled[0]); got != memSource {
		t.Fatalf("badger canonical source differs from in-memory: mem=%s badger=%s", memSource, got)
	}
}

func TestLowerRejectsAuthoredBuiltInRuleVerbMechanic(t *testing.T) {
	_, err := parser.ParseV2(`
module mechanics.test;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [asset]
  allowedClauses: [where, coveredBy, confidence]
}
`)
	if err == nil || !strings.Contains(err.Error(), "built-in language mechanics are implemented in Go") {
		t.Fatalf("ParseV2 error = %v, want built-in mechanic rejection", err)
	}
}

func TestCompileKeepsGoRuleVerbEndpointKindsWhenDeclTriesToOverride(t *testing.T) {
	decls := []parser.Decl{
		&parser.V2MechanicDecl{Kind: "ruleVerb", Name: "taint", Items: []parser.V2BlockItem{
			{Key: []string{"fromKinds"}, Value: []any{"source"}},
			{Key: []string{"toKinds"}, Value: []any{"asset"}},
		}},
		&parser.Rule{
			Name:    "SourceToAsset",
			Package: "rules.test",
			Body: &parser.FlowStmt{
				Verb: "taint",
				Src:  parser.Endpoint{Concept: "custom.Input"},
				Dst:  parser.Endpoint{Concept: "custom.Asset"},
			},
		},
	}
	onto := ontology.New()
	onto.Add(ontology.Concept{Name: "Input", Package: "custom", Kind: "source"})
	onto.Add(ontology.Concept{Name: "Asset", Package: "custom", Kind: "asset"})
	_, errs := CompileRules(decls, onto)
	if len(errs) != 1 || !strings.Contains(errs[0].Msg, "expected one of") || !strings.Contains(errs[0].Msg, "sink") {
		t.Fatalf("CompileRules errors = %+v, want Go-owned endpoint kind rejection", errs)
	}
}

func TestCompileRulesUsesGoBuiltInRuleVerbMechanics(t *testing.T) {
	decls := []parser.Decl{
		&parser.Rule{
			Name:    "SourceToSink",
			Package: "rules.test",
			Body: &parser.FlowStmt{
				Verb: "taint",
				Src:  parser.Endpoint{Concept: "code.HttpInput"},
				Dst:  parser.Endpoint{Concept: "code.SqlExecution"},
			},
		},
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) != 0 {
		t.Fatalf("CompileRules errors = %+v, want built-in rule verb mechanics", errs)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(compiled))
	}
}

func TestAuthoredExtensionRuleVerbMechanicsRejected(t *testing.T) {
	_, err := parser.ParseV2(`
module mechanics.test;
mechanic ruleVerb observe {
  solver: fact.exists
  fromKinds: [issue]
  allowedClauses: [where, confidence]
}
`)
	if err == nil || !strings.Contains(err.Error(), "extension rule verbs are recognized by the v2 contract but are not implemented") {
		t.Fatalf("ParseV2 error = %v, want extension rule verb rejection", err)
	}
}

func parseV2DefinitionSourcesForCompileTest(t *testing.T, raw []parser.V2DefinitionSource) []parser.Decl {
	t.Helper()
	sources := parseV2SourcesForCompileTest(t, raw)
	decls, err := parser.LowerV2DefinitionSources(sources)
	if err != nil {
		t.Fatalf("LowerV2DefinitionSources: %v", err)
	}
	return decls
}

func parseV2SourcesForCompileTest(t *testing.T, raw []parser.V2DefinitionSource) []parser.V2Source {
	t.Helper()
	sources := make([]parser.V2Source, 0, len(raw))
	for _, src := range raw {
		prog, err := parser.ParseV2(src.Source)
		if err != nil {
			t.Fatalf("ParseV2 %s: %v", src.Name, err)
		}
		sources = append(sources, parser.V2Source{Name: src.Name, Program: prog})
	}
	return sources
}

func loadV2FingerprintGraph(t *testing.T, store usg.Store) {
	t.Helper()
	if err := store.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{"loc": "app.py:10"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddNode(usg.Node{ID: "sink", Type: "code.Call", Props: map[string]string{"loc": "app.py:20"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "sink"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddLabel("src", usg.Label{Concept: "code.HttpInput"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddLabel("sink", usg.Label{Concept: "code.SqlExecution"}); err != nil {
		t.Fatal(err)
	}
}

func loadV2DuplicateFlowGraph(t *testing.T, store usg.Store, sources []string) {
	t.Helper()
	for _, id := range sources {
		if err := store.AddNode(usg.Node{ID: id, Type: "code.Call", Props: map[string]string{"loc": "app.py:10"}}); err != nil {
			t.Fatal(err)
		}
		if err := store.AddLabel(id, usg.Label{Concept: "code.HttpInput"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.AddNode(usg.Node{ID: "sink", Type: "code.Call", Props: map[string]string{"loc": "app.py:20"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddLabel("sink", usg.Label{Concept: "code.SqlExecution"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range sources {
		if err := store.AddEdge(usg.Edge{Type: "FLOWS", Src: id, Dst: "sink"}); err != nil {
			t.Fatal(err)
		}
	}
}

func v2SingleFingerprint(t *testing.T, onto *ontology.Ontology, store usg.Store, cr *CompiledRule) string {
	t.Helper()
	fs, err := New(onto, store).Evaluate(cr)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(fs), fs)
	}
	return resultpolicy.Fingerprint(fs[0])
}

func v2SingleSourceBinding(t *testing.T, onto *ontology.Ontology, store usg.Store, cr *CompiledRule) string {
	t.Helper()
	fs, err := New(onto, store).Evaluate(cr)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(fs), fs)
	}
	for _, b := range fs[0].Bindings {
		if b.Name == "source" {
			return b.NodeID
		}
	}
	t.Fatalf("finding has no source binding: %+v", fs[0].Bindings)
	return ""
}

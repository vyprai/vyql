package frontend

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/bindings"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func firstBindingSet(t *testing.T, decls []parser.Decl) *parser.BindingSet {
	t.Helper()
	for _, decl := range decls {
		if ad, ok := decl.(*parser.BindingSet); ok {
			return ad
		}
	}
	t.Fatalf("expected binding declaration, got %d decls", len(decls))
	return nil
}

func TestConstraintAllows(t *testing.T) {
	cases := []struct {
		constraint, recvType string
		want                 bool
	}{
		{"alpha.Type", "alpha.Type", true},
		{"Widget", "vendor.pkg.Widget", true},
		{"vendor.pkg.Widget", "Widget", true},
		{"alpha.Type", "beta.Type", false},
		{"alpha.Type,beta.Type,gamma.Type", "gamma.Type", true},
		{"alpha.Type,beta.Type,gamma.Type", "delta.Type", false},
		{"alpha.Type", "", false}, // empty recv handled by the caller, not here
	}
	for _, c := range cases {
		if got := constraintAllows(c.constraint, c.recvType); got != c.want {
			t.Errorf("constraintAllows(%q,%q)=%v want %v", c.constraint, c.recvType, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	// prefix mode: exact, dotted, subscript continuations
	if !matchPath("source.value", []string{"source.value"}, "prefix") {
		t.Error("exact prefix should match")
	}
	if !matchPath("source.value.get", []string{"source.value"}, "prefix") {
		t.Error("dotted continuation should match")
	}
	if !matchPath("Model.query.get", []string{"query.get"}, "prefix") {
		t.Error("dotted suffix should match a path behind a receiver/model segment")
	}
	if matchPath("source.valued", []string{"source.value"}, "prefix") {
		t.Error("a longer word should NOT prefix-match (source.valued != source.value.)")
	}
	// contains mode: substring anywhere (Go varying receivers)
	if !matchPath("obj.Meta.Read.Get", []string{".Meta.Read"}, "contains") {
		t.Error("contains should match a mid-path substring")
	}
	if matchPath("obj.Other", []string{".Meta.Read"}, "contains") {
		t.Error("contains should not falsely match an unrelated path")
	}
}

func TestClassBaseContextTokenDoesNotMatchSuffixes(t *testing.T) {
	tokens := "class_base:org.yaml.snakeyaml.constructor.SafeConstructor"
	if contextTokenValuePredicate("contains", []string{"class_base:Constructor"}, tokens) {
		t.Fatal("class_base:Constructor should not match SafeConstructor")
	}
	if !contextTokenValuePredicate("contains", []string{"class_base:SafeConstructor"}, tokens) {
		t.Fatal("class_base:SafeConstructor should match its exact simple name")
	}
	if !contextTokenValuePredicate("contains", []string{"class_base:org.yaml.snakeyaml.constructor.SafeConstructor"}, tokens) {
		t.Fatal("fully qualified class base should match")
	}
}

func TestBoundaryValuePredicatesMatchTokenSegments(t *testing.T) {
	text := "alpha\x00BetaValue\x00omega"
	if !valuePredicate("starts_with", []string{"beta"}, text) {
		t.Fatal("starts_with should match a later NUL-delimited token")
	}
	if !valuePredicate("ends_with", []string{"value"}, text) {
		t.Fatal("ends_with should match a later NUL-delimited token")
	}
	if valuePredicate("starts_with", []string{"value"}, text) {
		t.Fatal("starts_with should not match a middle substring")
	}
}

func TestContextTokenBoundaryPredicatesMatchTokenValues(t *testing.T) {
	tokens := "function_name:validateRedirect\x00literal:/admin.html"
	if !contextTokenValuePredicate("starts_with", []string{"function_name:validate"}, tokens) {
		t.Fatal("starts_with should match the context token value after its prefix")
	}
	if !contextTokenValuePredicate("ends_with", []string{"literal:.html"}, tokens) {
		t.Fatal("ends_with should match the context token value after its prefix")
	}
	if contextTokenValuePredicate("ends_with", []string{"function_name:validate"}, tokens) {
		t.Fatal("ends_with should not match a prefix-only value")
	}
}

func TestPathEqualsAnyPredicateIsExact(t *testing.T) {
	pred := newFlagPredicate("node", "path", "equals_any", []string{"source.value"}, false, false)
	if flagPredicateHit(pred, usg.Node{Props: map[string]string{"callee_path": "source.valued"}}) {
		t.Fatal("path equals_any should not segment-prefix match a longer path")
	}
	if !flagPredicateHit(pred, usg.Node{Props: map[string]string{"callee_path": "source.value"}}) {
		t.Fatal("path equals_any should match the exact path")
	}
}

func TestExistsPredicatesMatchPresentFields(t *testing.T) {
	if !flagPredicateHit(newFlagPredicate("node", "path", "exists", nil, false, false), usg.Node{Props: map[string]string{"callee_path": "source.value"}}) {
		t.Fatal("path exists should match a non-empty callee_path")
	}
	if flagPredicateHit(newFlagPredicate("node", "method", "exists", nil, false, false), usg.Node{Props: map[string]string{"method": ""}}) {
		t.Fatal("method exists should not match an empty method")
	}
	tokens := "function_name:validateRedirect\x00literal:/admin.html"
	if !contextTokenValuePredicate("exists", []string{"function_name:"}, tokens) {
		t.Fatal("context exists should match a present token prefix")
	}
	if contextTokenValuePredicate("exists", []string{"decorator_path:"}, tokens) {
		t.Fatal("context exists should not match a missing token prefix")
	}
}

func TestFrontendDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	concepts := frontendOntologyConceptNeedles(t)
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
		for _, needle := range concepts {
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
		t.Fatalf("frontend extractors must not hardcode ontology concepts; move roles/semantics into VyQL metadata: %s", strings.Join(hits, ", "))
	}
}

func TestFrontendEntryVariableNamesComeFromData(t *testing.T) {
	root := frontendPackageRoot(t)
	forbidden := frontendSourceVarNeedles(t)
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range forbidden {
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
		t.Fatalf("frontend entry variable names must be loaded from VyQL data, not hardcoded in Go: %s", strings.Join(hits, ", "))
	}
}

func frontendSourceVarNeedles(t *testing.T) []string {
	t.Helper()
	sources, err := datadir.ReadVYQLDirExcept("bindings", "packages")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, source := range sources {
		decls, err := parseV2DefinitionsForTest(string(source.Data))
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range decls {
			ad, ok := decl.(*parser.BindingSet)
			if !ok {
				continue
			}
			for _, key := range []string{"source_var_exact", "source_var_prefix", "source_var_strip_prefix"} {
				for _, value := range metaValues(ad.Meta, key) {
					if len(value) < 3 && !strings.Contains(value, "_") {
						continue
					}
					seen["\""+value+"\""] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

func metaValues(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func frontendPackageRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func frontendOntologyConceptNeedles(t *testing.T) []string {
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

func TestExplicitPackageBlockSinkRequiresPackageEvidence(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:  "custom.Target",
			Pattern:  "samplepkg.handle",
			Packages: []string{"samplepkg"},
		}},
	}
	binding := spec.sinkApplicator()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := binding.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("explicit package-block sink fired without evidence: %+v", got)
	}

	withImport := usg.NewInMemStore()
	withImport.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withImport.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withImport.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := binding.Apply(withImport); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Target" {
		t.Fatalf("explicit package-block sink did not fire with import evidence: %+v", got)
	}

	withSBOM := usg.NewInMemStore()
	withSBOM.AddNode(usg.Node{ID: "pkg:generic/samplepkg@1.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "samplepkg", "version": "1.0",
	}})
	withSBOM.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withSBOM.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := binding.Apply(withSBOM); len(got) != 1 || got[0].NodeID != "arg" {
		t.Fatalf("explicit package-block sink did not fire with SBOM evidence: %+v", got)
	}
}

func TestV2RequirementGateEvaluatesStructuredEvidence(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "imp", Type: "code.Import", Loc: "app.js:1", Props: map[string]string{
		"module": "express", "package": "express",
	}})
	g.AddNode(usg.Node{ID: "pkg:generic/koa@1.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "koa", "version": "1.0",
	}})
	g.AddNode(usg.Node{ID: "pkg:npm/express@4.18.2", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "express", "version": "4.18.2",
	}})
	g.AddNode(usg.Node{ID: "fact:npm:publishable", Type: "project.Fact", Props: map[string]string{
		"key": "npm:publishable",
	}})
	g.AddNode(usg.Node{ID: "fact:manifest", Type: "project.Fact", Props: map[string]string{
		"family": "manifest", "value": "publishable",
	}})
	g.AddNode(usg.Node{ID: "call", Type: "code.Call", Loc: "app.js:3", Props: map[string]string{
		"callee_path": "handler", "method": "handler",
	}})
	gate := newRequirementGate(g, "javascript", false, packageEvidence(g, "javascript", false))

	cases := []struct {
		name string
		req  parser.BindingRequirement
		want bool
	}{
		{name: "dependency uses sbom evidence", req: parser.BindingRequirement{Op: "dependency", Value: "koa"}, want: true},
		{name: "dependency preserves package evidence from imports", req: parser.BindingRequirement{Op: "dependency", Value: "express"}, want: true},
		{name: "dependency range accepts matching version", req: parser.BindingRequirement{Op: "dependency", Value: "express", Range: ">=4 <6"}, want: true},
		{name: "dependency range rejects nonmatching version", req: parser.BindingRequirement{Op: "dependency", Value: "koa", Range: ">=4 <6"}, want: false},
		{name: "import uses import evidence", req: parser.BindingRequirement{Op: "import", Value: "express"}, want: true},
		{name: "language uses scan technology evidence", req: parser.BindingRequirement{Op: "language", Value: "javascript"}, want: true},
		{name: "file uses lazy file evidence", req: parser.BindingRequirement{Op: "file", Value: "app.js"}, want: true},
		{name: "project.has uses explicit project fact key", req: parser.BindingRequirement{Op: "project.has", Value: "npm:publishable"}, want: true},
		{name: "project.has uses family value fact", req: parser.BindingRequirement{Op: "project.has", Value: "manifest:publishable"}, want: true},
		{name: "project.has uses dependency evidence fallback", req: parser.BindingRequirement{Op: "project.has", Value: "dependency:express"}, want: true},
		{name: "project.has uses import evidence fallback", req: parser.BindingRequirement{Op: "project.has", Value: "import:express"}, want: true},
		{name: "project.has uses language evidence fallback", req: parser.BindingRequirement{Op: "project.has", Value: "language:javascript"}, want: true},
		{name: "project.has uses file evidence fallback", req: parser.BindingRequirement{Op: "project.has", Value: "file:app.js"}, want: true},
		{name: "project.has rejects absent fact", req: parser.BindingRequirement{Op: "project.has", Value: "repository:vendored"}, want: false},
		{name: "all combines children", req: parser.BindingRequirement{Op: "all", Args: []parser.BindingRequirement{
			{Op: "dependency", Value: "koa"},
			{Op: "import", Value: "express"},
		}}, want: true},
		{name: "not negates child", req: parser.BindingRequirement{Op: "not", Args: []parser.BindingRequirement{
			{Op: "dependency", Value: "missing"},
		}}, want: true},
		{name: "soft never blocks", req: parser.BindingRequirement{Op: "soft", Args: []parser.BindingRequirement{
			{Op: "dependency", Value: "missing"},
		}}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gate.allowed(nil, &tc.req); got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestV2SoftRequirementDowngradesMappingConfidence(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "app.js:3"}})
	g.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:3", "callee_path": "danger", "method": "danger", "arg0": "arg",
	}})
	spec := bindingSpec{
		Name:       "soft",
		Technology: "javascript",
		Sinks: []sinkSpec{{
			Concept: "custom.Target",
			Pattern: "danger",
			Requirement: &parser.BindingRequirement{Op: "soft", Args: []parser.BindingRequirement{
				{Op: "dependency", Value: "missing"},
			}},
		}},
	}

	got := spec.sinkApplicator().Apply(g)
	if len(got) != 1 {
		t.Fatalf("soft requirement should not block mapping, got %+v", got)
	}
	if got[0].Confidence != "medium" {
		t.Fatalf("confidence = %q, want medium", got[0].Confidence)
	}
	if got[0].Detail["requirement_state"] != "missing" {
		t.Fatalf("detail = %#v, want missing soft requirement diagnostic", got[0].Detail)
	}
}

func TestV2SoftRequirementReportsEvidenceStates(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*usg.InMemStore)
		req   parser.BindingRequirement
		want  string
	}{
		{
			name: "missing",
			req: parser.BindingRequirement{Op: "soft", Args: []parser.BindingRequirement{
				{Op: "dependency", Value: "missing"},
			}},
			want: "missing",
		},
		{
			name: "unknown version",
			setup: func(g *usg.InMemStore) {
				g.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
					"module": "express", "package": "express",
				}})
			},
			req: parser.BindingRequirement{Op: "soft", Args: []parser.BindingRequirement{
				{Op: "dependency", Value: "express", Range: ">=4 <6"},
			}},
			want: "unknown",
		},
		{
			name: "conflicting version",
			setup: func(g *usg.InMemStore) {
				g.AddNode(usg.Node{ID: "pkg:npm/express@3.0.0", Type: "sbom.PackageVersion", Props: map[string]string{
					"name": "express", "version": "3.0.0",
				}})
			},
			req: parser.BindingRequirement{Op: "soft", Args: []parser.BindingRequirement{
				{Op: "dependency", Value: "express", Range: ">=4 <6"},
			}},
			want: "conflicting",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := usg.NewInMemStore()
			if tt.setup != nil {
				tt.setup(g)
			}
			gate := newRequirementGate(g, "javascript", false, packageEvidence(g, "javascript", false))
			got := gate.evalEffect(tt.req)
			if !got.Allowed {
				t.Fatalf("soft requirement should allow mapping: %+v", got)
			}
			if got.State != tt.want || got.Detail["requirement_state"] != tt.want {
				t.Fatalf("effect = %+v, want state %q", got, tt.want)
			}
		})
	}
}

func TestV2AnyRequirementPrefersHardSatisfiedEvidence(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "pkg:npm/express@4.18.2", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "express", "version": "4.18.2",
	}})
	gate := newRequirementGate(g, "javascript", false, packageEvidence(g, "javascript", false))
	req := parser.BindingRequirement{Op: "any", Args: []parser.BindingRequirement{
		{Op: "soft", Args: []parser.BindingRequirement{{Op: "dependency", Value: "missing"}}},
		{Op: "dependency", Value: "express"},
	}}

	got := gate.evalEffect(req)
	if !got.Allowed {
		t.Fatalf("requirement should be allowed")
	}
	if got.ConfidenceDowngrade != 0 {
		t.Fatalf("confidence downgrade = %d, want 0 for satisfied hard branch", got.ConfidenceDowngrade)
	}
	if len(got.Detail) != 0 {
		t.Fatalf("detail = %#v, want no soft-missing diagnostic", got.Detail)
	}
}

func TestV2DependencyRequirementPreservesPackageHintRecall(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:     "custom.Target",
			Pattern:     "samplepkg.handle",
			Packages:    []string{"samplepkg"},
			Requirement: &parser.BindingRequirement{Op: "dependency", Value: "samplepkg"},
		}},
	}
	binding := spec.sinkApplicator()

	withImportOnly := usg.NewInMemStore()
	withImportOnly.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withImportOnly.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withImportOnly.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := binding.Apply(withImportOnly); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Target" {
		t.Fatalf("dependency-gated sink did not fire from import evidence: %+v", got)
	}

	withSBOM := usg.NewInMemStore()
	withSBOM.AddNode(usg.Node{ID: "pkg:generic/samplepkg@1.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "samplepkg", "version": "1.0",
	}})
	withSBOM.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withSBOM.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := binding.Apply(withSBOM); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Target" {
		t.Fatalf("dependency-gated sink did not fire from SBOM evidence: %+v", got)
	}
}

func TestPackageGateMatchesReferencePackageSemantics(t *testing.T) {
	have := map[string]bool{
		"org.apache.commons.lang3":      true,
		"github.com/acme/widget/subpkg": true,
		"@scope/pkg/lib":                true,
		"expressive/router":             true,
		"foo/bar.baz":                   true,
		"pyyaml":                        true,
	}
	gate := newPackageGate(have)
	wants := []string{
		"",
		"org.apache.commons.lang3",
		"org.apache.commons",
		"org.apache.commons.lang3.extra",
		"github.com/acme/widget",
		"acme",
		"widget",
		"subpkg",
		"@scope/pkg",
		"@scope/pkg/lib/router",
		"@scope",
		"pkg",
		"express",
		"expressive",
		"router",
		"bar",
		"bar.baz",
		"pyyaml",
		"yaml",
	}
	for _, want := range wants {
		want := want
		t.Run(strings.ReplaceAll(want, "/", "_"), func(t *testing.T) {
			expected := referencePackageInEvidence(want, have)
			if got := gate.inEvidence(want); got != expected {
				t.Fatalf("packageGate.inEvidence(%q)=%v, want %v", want, got, expected)
			}
			if got := packageAllowed([]string{want}, have); got != expected {
				t.Fatalf("packageAllowed(%q)=%v, want %v", want, got, expected)
			}
		})
	}
	if !packageAllowed([]string{"missing", "pyyaml"}, have) {
		t.Fatal("packageAllowed should accept when any requested package matches evidence")
	}
}

func referencePackageInEvidence(want string, have map[string]bool) bool {
	want = sca.NormalizePackageName(want)
	if want == "" {
		return true
	}
	if have[want] {
		return true
	}
	if root := sca.PackageRoot(want); root != "" && have[root] {
		return true
	}
	for got := range have {
		if sca.PackageMatches(got, want) {
			return true
		}
	}
	return false
}

func TestExplicitPackageBlockParamSourceRequiresPackageEvidence(t *testing.T) {
	defer SetActiveSources(nil)
	SetActiveSources(map[string]bool{"custom.ParamSource": true})

	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		ParamSources: []paramSourceSpec{{
			Concept:  "custom.ParamSource",
			Packages: []string{"samplepkg"},
		}},
	}
	binding := spec.paramSourceApplicator()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "param", Type: "code.Param", Props: map[string]string{
		"loc": "sample.x:2", "exported": "true",
	}})
	if got := binding.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("explicit package-block param source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "param", Type: "code.Param", Props: map[string]string{
		"loc": "sample.x:2", "exported": "true",
	}})
	if got := binding.Apply(withPkg); len(got) != 1 || got[0].NodeID != "param" || got[0].Concept != "custom.ParamSource" || got[0].Specificity != 3 {
		t.Fatalf("explicit package-block param source did not fire with evidence: %+v", got)
	}
}

func TestValueMatchedSinkUsesFlowingStringTokens(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.Target",
			Pattern:    "open",
			ValMatches: []string{"/tmp/", "w"},
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "tmp", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "path.join", "method": "join", "str_args": "/tmp/fixed",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "arg1", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Const",
	}})
	store.AddNode(usg.Node{ID: "open", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "open", "method": "open", "arg0": "arg0", "arg1": "arg1", "str_args": "w",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tmp", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "open"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg1", Dst: "open"})

	openNode, _, _ := store.GetNode("open")
	var flowIdx flowTokenIndex
	if !valCondsForNode(store, &flowIdx, openNode, []string{"/tmp/", "w"}, nil) {
		t.Fatalf("flowing string tokens did not satisfy value constraints: %q", flowingStringTokens(store, &flowIdx, "open", openNode.Prop("str_args")))
	}

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg0" || got[0].Concept != "custom.Target" {
		t.Fatalf("value-matched sink did not use flowing string tokens: %+v", got)
	}

	markSpec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Marks: []controlSpec{{
			Concept:    "custom.Mark",
			Pattern:    "open",
			ValMatches: []string{"/tmp/", "w"},
		}},
	}
	got = markSpec.matchPresenceApplicator().Apply(store)
	if len(got) != 0 {
		t.Fatalf("value-matched direct label used flowing string tokens: %+v", got)
	}

	directMarkStore := usg.NewInMemStore()
	directMarkStore.AddNode(usg.Node{ID: "open", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "open", "method": "open", "str_args": "/tmp/fixed\x00w",
	}})
	got = markSpec.matchPresenceApplicator().Apply(directMarkStore)
	if len(got) != 1 || got[0].NodeID != "open" || got[0].Concept != "custom.Mark" {
		t.Fatalf("value-matched direct label did not use direct string tokens: %+v", got)
	}
}

func TestValueMatchedSinkUsesUpstreamTokensWhenCallHasNoDirectStrings(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.Target",
			Pattern:    "queryDB",
			ValMatches: []string{"insert into"},
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "sql", Type: "code.Format", Props: map[string]string{
		"loc": "sample.x:1", "str_args": "INSERT INTO users VALUES (?)",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "queryDB", "method": "queryDB", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "sql", Dst: "arg0"})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg0" || got[0].Concept != "custom.Target" {
		t.Fatalf("value-matched sink did not use upstream tokens when call had no direct strings: %+v", got)
	}
}

func TestContextFlagSyntaxBuildsScopedFlag(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding secretComparison {
  query pattern presenceNode where node.scope == "function" and node.context.language == "javascript" and node.context.callPath contains "parseOut" and node.context.selector contains "data.x-csrf-token" and node.context.identifier contains "providedToken" and not (node.context.callPath contains "crypto.timingSafeEqual")
  emit issue custom.SecretComparison at node
}
`)
	if err != nil {
		t.Fatalf("parse context flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	if len(spec.Flags) != 1 {
		t.Fatalf("expected one flag spec, got %#v", spec.Flags)
	}
	flag := spec.Flags[0]
	if flag.Scope != "function" || len(flag.Predicates) != 5 ||
		flag.Predicates[0].Values[0] != "lang=javascript" ||
		flag.Predicates[1].Values[0] != "call_path:parseOut" ||
		flag.Predicates[2].Values[0] != "selector:data.x-csrf-token" ||
		flag.Predicates[3].Values[0] != "identifier:providedToken" ||
		!flag.Predicates[4].Negative {
		t.Fatalf("unexpected context flag spec: %#v", flag)
	}

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.js:1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=javascript\x00selector:data.x-csrf-token\x00identifier:providedToken",
	}})
	store.AddNode(usg.Node{ID: "parse", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.js:5",
		"callee_path": "parseOut",
		"method":      "parseOut",
	}})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.SecretComparison" {
		t.Fatalf("context flag did not label matching context node: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:2",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=javascript\x00selector:data.x-csrf-token\x00identifier:providedToken\x00call_path:crypto.timingSafeEqual",
	}})
	store.AddNode(usg.Node{ID: "fixed-parse", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:5",
		"callee_path": "parseOut",
		"method":      "parseOut",
	}})
	store.AddNode(usg.Node{ID: "fixed-safe", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:6",
		"callee_path": "crypto.timingSafeEqual",
		"method":      "timingSafeEqual",
	}})
	got = spec.presenceApplicator().Apply(store)
	if len(got) != 1 {
		t.Fatalf("context flag should skip scope with matching excluded call, got %+v", got)
	}
}

func TestContextFlagAstCallPredicatesPreferLexicalScope(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.test;

binding worldAccess {
  query pattern presenceNode where node.scope == "function" and node.token contains "function_name:safe" and node.token contains "call_path:world.getBlockAt" and not containsAny(node.context.scopeCall, ["testCoord"])
  emit issue custom.WorldAccess at node
}
`)
	if err != nil {
		t.Fatalf("parse scoped context flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "World.java:10",
		Scope: "World.java/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "function_name:safe",
		},
	})
	store.AddNode(usg.Node{
		ID:    "other-call",
		Type:  "code.Call",
		Loc:   "World.java:30",
		Scope: "World.java/fn2",
		Props: map[string]string{
			"callee_path": "world.getBlockAt",
			"method":      "getBlockAt",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context flag matched call outside lexical scope: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "local-call",
		Type:  "code.Call",
		Loc:   "World.java:12",
		Scope: "World.java/fn1/if0.t",
		Props: map[string]string{
			"callee_path": "world.getBlockAt",
			"method":      "getBlockAt",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.WorldAccess" {
		t.Fatalf("context flag did not match nested in-scope call: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "guard",
		Type:  "code.Call",
		Loc:   "World.java:11",
		Scope: "World.java/fn1",
		Props: map[string]string{
			"callee_path": "testCoords",
			"method":      "testCoords",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context flag should skip guarded lexical scope, got %+v", got)
	}
}

func TestContextFlagIndexesScopedContextAndMatchesOrderedSelectorScope(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.test;

binding shareInfoLeak {
  query pattern presenceNode where node.scope == "function" and node.token contains "function_name:shareInfoHandler" and node.token contains "call_path:store.Share.GetByHash" and node.token contains "call_path:getShareURL" and node.token contains "selector:shareLink.Token"
  emit issue custom.ShareInfoLeak at node
}
`)
	if err != nil {
		t.Fatalf("parse scoped selector flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "share.go:610",
		Scope: "share.go/fn77@1361",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "function_name:shareInfoHandler",
		},
	})
	store.AddNode(usg.Node{
		ID:    "lookup",
		Type:  "code.Call",
		Loc:   "share.go:613",
		Scope: "share.go/fn77@1370",
		Props: map[string]string{
			"callee_path": "store.Share.GetByHash",
			"method":      "GetByHash",
		},
	})
	store.AddNode(usg.Node{
		ID:    "token",
		Type:  "code.Attr",
		Loc:   "share.go:618",
		Scope: "share.go/fn77@1384",
		Props: map[string]string{
			"callee_path": "shareLink.Token",
			"method":      "Token",
		},
	})
	store.AddNode(usg.Node{
		ID:    "url",
		Type:  "code.Call",
		Loc:   "share.go:618",
		Scope: "share.go/fn77@1386",
		Props: map[string]string{
			"callee_path": "getShareURL",
			"method":      "getShareURL",
		},
	})

	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.ShareInfoLeak" {
		t.Fatalf("context flag did not match ordered same-function call and selector evidence: %+v", got)
	}
}

func TestAstFlagMatchesUnorderedBinopOperands(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding secretComparison {
  query pattern presenceNode where node.kind == "binop" and node.op in ["==", "==="] and operand(node, where: containsAny(operand.key, ["csrf-token", "x-csrf-token"])) and operand(node, where: containsAny(operand.identifier, ["token", "secret", "signature", "key"])) and not containsAny(node.context.scopeCall, ["scmp", "timingSafeEqual"])
  emit issue custom.SecretComparison at node
}
`)
	if err != nil {
		t.Fatalf("parse ast flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "cmp", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.js:10", "op": "===", "callee_path": "__binop.eq", "method": "eq", "arg0": "a0", "arg1": "a1",
	}})
	store.AddNode(usg.Node{ID: "a0", Type: "code.Arg"})
	store.AddNode(usg.Node{ID: "a1", Type: "code.Arg"})
	store.AddNode(usg.Node{ID: "header", Type: "code.Subscript", Props: map[string]string{
		"loc": "sample.js:10", "callee_path": "data.__subscript", "method": "[]", "str_args": "x-csrf-token",
	}})
	store.AddNode(usg.Node{ID: "candidate", Type: "code.Param", Props: map[string]string{
		"loc": "sample.js:10", "name": "providedToken",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "header", Dst: "a0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "candidate", Dst: "a1"})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "cmp" || got[0].Concept != "custom.SecretComparison" {
		t.Fatalf("AST flag did not label matching binop: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:20", "callee_path": "crypto.timingSafeEqual", "method": "timingSafeEqual",
	}})
	got = spec.presenceApplicator().Apply(store)
	if len(got) != 0 {
		t.Fatalf("AST flag should skip file with constant-time comparison call: %+v", got)
	}
}

func TestContextFlagAstScopedLiteralAndSubscriptPredicates(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding prototypeMerge {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=javascript" and node.token contains "index:base.__subscript" and node.token contains "subscript:obj[key]" and not (node.token contains "literal:__proto__")
  emit issue custom.PrototypeMerge at node
}
`)
	if err != nil {
		t.Fatalf("parse context ast flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "merge.js:1",
		Scope: "merge.js/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=javascript",
		},
	})
	store.AddNode(usg.Node{
		ID:    "base-sub",
		Type:  "code.Subscript",
		Loc:   "merge.js:9",
		Scope: "merge.js/fn1/loop",
		Props: map[string]string{"callee_path": "base.__subscript", "method": "[]"},
	})
	store.AddNode(usg.Node{
		ID:    "obj-sub",
		Type:  "code.Subscript",
		Loc:   "merge.js:6",
		Scope: "merge.js/fn1/loop",
		Props: map[string]string{"callee_path": "obj.__subscript", "method": "[]", "str_args": "key"},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST flag did not match scoped subscript nodes: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "proto-literal",
		Type:  "code.Const",
		Loc:   "merge.js:5",
		Scope: "merge.js/fn1",
		Props: map[string]string{"str_args": "__proto__"},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context AST flag should skip scoped prototype literal guard: %+v", got)
	}
}

func TestContextFlagAstScopedSelectorContainsAny(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.test;

binding lockOpen {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=python" and containsAny(node.token, ["selector:lock_file", "selector:.lock", "selector:lock"])
  emit issue custom.LockOpen at node
}
`)
	if err != nil {
		t.Fatalf("parse context ast selector flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "lock.py:1",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	store.AddNode(usg.Node{
		ID:    "lock-attr",
		Type:  "code.Attr",
		Loc:   "lock.py:9",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "self.lock_file",
			"method":      "lock_file",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST flag did not match selector contains_any text: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "other-ctx",
		Type:  "code.Call",
		Loc:   "other.py:1",
		Scope: "other.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 {
		t.Fatalf("context AST flag should stay file/scope-local, got %+v", got)
	}
}

func TestContextFlagAstScopedBinaryPredicate(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.test;

binding emptyPayloadCheck {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=go" and node.token contains "binary:len(payload)==0" and not (node.token contains "binary:len(checked)==0")
  emit issue custom.EmptyPayloadCheck at node
}
`)
	if err != nil {
		t.Fatalf("parse context binary flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "handler.go:1",
		Scope: "handler.go/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=go",
		},
	})
	for _, node := range []usg.Node{
		{ID: "payload", Type: "code.Param", Loc: "handler.go:1", Scope: "handler.go/fn1", Props: map[string]string{"name": "payload"}},
		{ID: "len-call", Type: "code.Call", Loc: "handler.go:4", Scope: "handler.go/fn1/if1", Props: map[string]string{"callee_path": "len", "method": "len"}},
		{ID: "zero", Type: "code.Const", Loc: "handler.go:4", Scope: "handler.go/fn1/if1", Props: map[string]string{"str_args": "0"}},
		{ID: "arg0", Type: "code.Arg", Loc: "handler.go:4", Scope: "handler.go/fn1/if1"},
		{ID: "arg1", Type: "code.Arg", Loc: "handler.go:4", Scope: "handler.go/fn1/if1"},
		{ID: "cmp", Type: "code.BinOp", Loc: "handler.go:4", Scope: "handler.go/fn1/if1", Props: map[string]string{"op": "==", "callee_path": "__binop.eq", "method": "eq", "arg0": "arg0", "arg1": "arg1"}},
	} {
		store.AddNode(node)
	}
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "payload", Dst: "len-call"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "len-call", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "zero", Dst: "arg1"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST binary flag did not match scoped binop: %+v", got)
	}

	for _, node := range []usg.Node{
		{ID: "checked", Type: "code.Param", Loc: "handler.go:1", Scope: "handler.go/fn1", Props: map[string]string{"name": "checked"}},
		{ID: "checked-len", Type: "code.Call", Loc: "handler.go:5", Scope: "handler.go/fn1/if2", Props: map[string]string{"callee_path": "len", "method": "len"}},
		{ID: "checked-zero", Type: "code.Const", Loc: "handler.go:5", Scope: "handler.go/fn1/if2", Props: map[string]string{"str_args": "0"}},
		{ID: "checked-arg0", Type: "code.Arg", Loc: "handler.go:5", Scope: "handler.go/fn1/if2"},
		{ID: "checked-arg1", Type: "code.Arg", Loc: "handler.go:5", Scope: "handler.go/fn1/if2"},
		{ID: "checked-cmp", Type: "code.BinOp", Loc: "handler.go:5", Scope: "handler.go/fn1/if2", Props: map[string]string{"op": "==", "callee_path": "__binop.eq", "method": "eq", "arg0": "checked-arg0", "arg1": "checked-arg1"}},
	} {
		store.AddNode(node)
	}
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "checked", Dst: "checked-len"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "checked-len", Dst: "checked-arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "checked-zero", Dst: "checked-arg1"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context AST binary flag should skip scoped negative binop: %+v", got)
	}
}

func TestCContextFlagMatchesICMPEchoLengthUnderflowTokens(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.c.test;

binding icmpEchoPayloadLengthUnderflow {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=c" and node.token contains "name=prvProcessICMPMessage_IPv6" and node.token contains "switch_case:ipICMP_PING_REPLY_IPv6" and node.token contains "selector:usPayloadLength" and node.token contains "assign:uxDataLength=uxDataLength-sizeof" and node.token contains "selector:pxICMPEchoHeader.usIdentifier" and node.token contains "call_path:FreeRTOS_ntohs" and node.token contains "call_path:vApplicationPingReplyHook" and containsAny(node.token, ["binary:uxDataLength-sizeof(*pxICMPEchoHeader)", "binary:uxDataLength-sizeof"]) and not containsAny(node.token, ["binary:uxDataLength<sizeof(*pxICMPEchoHeader)", "binary:sizeof(*pxICMPEchoHeader)>uxDataLength"])
  emit issue custom.IcmpEchoPayloadLengthUnderflow at node
}
`)
	if err != nil {
		t.Fatalf("parse C context flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	tokens := strings.Join([]string{
		"lang=c",
		"name=prvProcessICMPMessage_IPv6",
		"switch_case:ipICMP_PING_REPLY_IPv6",
		"assign:uxDataLength=uxDataLength-sizeof(*pxICMPEchoHeader)",
		"call_path:FreeRTOS_ntohs",
		"call_path:vApplicationPingReplyHook",
		"binary:uxDataLength-sizeof(*pxICMPEchoHeader)",
	}, "\x00")
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "FreeRTOS_ND.c:1", Scope: "FreeRTOS_ND.c/fn1", Props: map[string]string{
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    tokens,
	}})
	store.AddNode(usg.Node{ID: "payload", Type: "code.Attr", Loc: "FreeRTOS_ND.c:10", Scope: "FreeRTOS_ND.c/fn1/case0", Props: map[string]string{
		"path": "pxICMPPacket.xIPHeader.usPayloadLength",
	}})
	store.AddNode(usg.Node{ID: "ident", Type: "code.Attr", Loc: "FreeRTOS_ND.c:20", Scope: "FreeRTOS_ND.c/fn1/case0", Props: map[string]string{
		"path": "pxICMPEchoHeader.usIdentifier",
	}})
	store.AddNode(usg.Node{ID: "ntohs", Type: "code.Call", Loc: "FreeRTOS_ND.c:10", Scope: "FreeRTOS_ND.c/fn1/case0", Props: map[string]string{
		"callee_path": "FreeRTOS_ntohs",
		"method":      "FreeRTOS_ntohs",
	}})
	store.AddNode(usg.Node{ID: "hook", Type: "code.Call", Loc: "FreeRTOS_ND.c:20", Scope: "FreeRTOS_ND.c/fn1/case0", Props: map[string]string{
		"callee_path": "vApplicationPingReplyHook",
		"method":      "vApplicationPingReplyHook",
	}})

	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("C ICMP echo context flag did not match, got %+v", got)
	}
}

func TestContextFlagAstSoftLockNoFollowPredicateMix(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.test;

binding lockNoFollow {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=python" and node.token contains "call_path:os.open" and node.token contains "selector:os.O_CREAT" and node.token contains "selector:os.O_EXCL" and containsAny(node.token, ["selector:lock_file", "selector:.lock", "selector:lock"]) and not (node.token contains "literal:O_NOFOLLOW")
  emit issue custom.LockNoFollow at node
}
`)
	if err != nil {
		t.Fatalf("parse soft-lock context flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "lock.py:1",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	for _, node := range []usg.Node{
		{ID: "open", Type: "code.Call", Loc: "lock.py:9", Scope: "lock.py/fn1/try2", Props: map[string]string{"callee_path": "os.open", "method": "open"}},
		{ID: "create", Type: "code.Attr", Loc: "lock.py:5", Scope: "lock.py/fn1", Props: map[string]string{"callee_path": "os.O_CREAT", "method": "O_CREAT"}},
		{ID: "excl", Type: "code.Attr", Loc: "lock.py:6", Scope: "lock.py/fn1", Props: map[string]string{"callee_path": "os.O_EXCL", "method": "O_EXCL"}},
		{ID: "lock", Type: "code.Attr", Loc: "lock.py:9", Scope: "lock.py/fn1/try2", Props: map[string]string{"callee_path": "self.lock_file", "method": "lock_file"}},
	} {
		store.AddNode(node)
	}
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("soft-lock context flag did not match AST predicate mix: %+v", got)
	}

	store.AddNode(usg.Node{ID: "nofollow", Type: "code.Const", Loc: "lock.py:7", Scope: "lock.py/fn1", Props: map[string]string{"str_args": "O_NOFOLLOW"}})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("soft-lock context flag should skip no-follow hardening: %+v", got)
	}
}

func TestContextFlagAstScopedCallArgPredicates(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.php.test;

binding directJsonEncode {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=php" and node.token contains "call_arg:json_encode:$data[$field_name]" and not (node.token contains "call_arg:json_encode:$value")
  emit issue custom.DirectJsonEncode at node
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "fields.php:1",
		Scope: "fields.php/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=php",
		},
	})
	store.AddNode(usg.Node{
		ID:    "encode",
		Type:  "code.Call",
		Loc:   "fields.php:9",
		Scope: "fields.php/fn1/if2",
		Props: map[string]string{
			"callee_path": "json_encode",
			"method":      "json_encode",
			"str_args":    "$data[$field_name]",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST call-arg flag did not match scoped call argument: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "fixed",
		Type:  "code.Call",
		Loc:   "fields.php:10",
		Scope: "fields.php/fn1",
		Props: map[string]string{
			"callee_path": "json_encode",
			"method":      "json_encode",
			"str_args":    "$value",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context AST call-arg flag should honor excluded scoped argument: %+v", got)
	}
}

func TestContextFlagAstScopedCallArgPredicatesInspectArgumentNodes(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding gitCloneWrapper {
  query pattern presenceNode where node.scope == "function" and node.token contains "call_path:utils.run" and node.token contains "call_arg:utils.run:git clone"
  emit issue custom.GitCloneWrapper at node
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "index.js:1", Scope: "index.js/fn1", Props: map[string]string{
		"callee_path": "analysis.function.context",
		"method":      "context",
	}})
	store.AddNode(usg.Node{ID: "run", Type: "code.Call", Loc: "index.js:20", Scope: "index.js/fn1/try2", Props: map[string]string{
		"callee_path": "utils.run",
		"method":      "run",
	}})
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Loc: "index.js:20", Scope: "index.js/fn1/try2"})
	store.AddNode(usg.Node{ID: "fmt", Type: "code.Format", Loc: "index.js:20", Scope: "index.js/fn1/try2", Props: map[string]string{
		"str_args": "git clone ${remoteUrl} ${tmpDir}",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "fmt", Dst: "arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg", Dst: "run"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST call-arg flag did not inspect argument expression nodes: %+v", got)
	}
}

func TestContextFlagAstScopedCallArgPredicatesInspectNestedCallArguments(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.test;

binding bulkMailRecipients {
  query pattern presenceNode where node.scope == "function" and node.token contains "call_path:SendMail" and node.token contains "call_arg:SendMail:getUserEmailsByNames"
  emit issue custom.BulkMailRecipients at node
}
`)
	if err != nil {
		t.Fatalf("parse context nested call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "mail.go:1", Scope: "mail.go/fn1", Props: map[string]string{
		"callee_path": "analysis.function.context",
		"method":      "context",
	}})
	store.AddNode(usg.Node{ID: "send", Type: "code.Call", Loc: "mail.go:20", Scope: "mail.go/fn1", Props: map[string]string{
		"callee_path": "SendMail",
		"method":      "SendMail",
	}})
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Loc: "mail.go:20", Scope: "mail.go/fn1"})
	store.AddNode(usg.Node{ID: "lookup", Type: "code.Call", Loc: "mail.go:20", Scope: "mail.go/fn1", Props: map[string]string{
		"callee_path": "getUserEmailsByNames",
		"method":      "getUserEmailsByNames",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "lookup", Dst: "arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg", Dst: "send"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST call-arg flag did not inspect nested call argument: %+v", got)
	}
}

func TestContextFlagAstScopedCallArgPredicatesInspectNamePath(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.test;

binding bulkMailRecipients {
  query pattern presenceNode where node.scope == "function" and node.token contains "call_path:SendMail" and node.token contains "call_arg:SendMail:tos" and not (node.token contains "call_arg:SendMail:__object_literal")
  emit issue custom.BulkMailRecipients at node
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "issue_mail.go:1", Scope: "issue_mail.go/fn1", Props: map[string]string{
		"callee_path": "analysis.function.context",
		"method":      "context",
	}})
	store.AddNode(usg.Node{ID: "send", Type: "code.Call", Loc: "issue_mail.go:20", Scope: "issue_mail.go/fn1", Props: map[string]string{
		"callee_path": "SendMail",
		"method":      "SendMail",
	}})
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Loc: "issue_mail.go:20", Scope: "issue_mail.go/fn1"})
	store.AddNode(usg.Node{ID: "tos", Type: "code.Name", Loc: "issue_mail.go:20", Scope: "issue_mail.go/fn1", Props: map[string]string{
		"path": "tos",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tos", Dst: "arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg", Dst: "send"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST call-arg flag did not inspect Go name path: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Loc: "issue_mail.go:24", Scope: "issue_mail.go/fn1/loop2", Props: map[string]string{
		"callee_path": "SendMail",
		"method":      "SendMail",
	}})
	store.AddNode(usg.Node{ID: "fixedArg", Type: "code.Arg", Loc: "issue_mail.go:24", Scope: "issue_mail.go/fn1/loop2"})
	store.AddNode(usg.Node{ID: "single", Type: "code.Seq", Loc: "issue_mail.go:24", Scope: "issue_mail.go/fn1/loop2", Props: map[string]string{
		"path": "__object_literal",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "single", Dst: "fixedArg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "fixedArg", Dst: "fixed"})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context AST call-arg flag should honor object-literal exclusion: %+v", got)
	}
}

func TestDirectFlagCallArgPredicatesUseCallArguments(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.test;

binding unhardenedXmlParser {
  query pattern presenceNode where node.kind == "call" and node.path ~= "etree.XMLParser" and node.token contains "call_arg:etree.XMLParser:huge_tree=True" and not (node.token contains "call_arg:etree.XMLParser:resolve_entities=False")
  emit issue custom.UnhardenedXmlParser at node
}
`)
	if err != nil {
		t.Fatalf("parse direct call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:   "parser",
		Type: "code.Call",
		Props: map[string]string{
			"callee_path": "etree.XMLParser",
			"method":      "XMLParser",
			"str_args":    "huge_tree=True",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "parser" {
		t.Fatalf("direct call-arg flag should match call arguments: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:   "hardened",
		Type: "code.Call",
		Props: map[string]string{
			"callee_path": "etree.XMLParser",
			"method":      "XMLParser",
			"str_args":    "huge_tree=True\x00resolve_entities=False",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "parser" {
		t.Fatalf("direct call-arg flag should reject hardened call arguments: %+v", got)
	}
}

func TestContextFlagAstSubscriptPredicatesHonorKeys(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.php.test;

binding passwordOnlySessionHash {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=php" and node.token contains "name=authenticate" and node.token contains "subscript:$u['password']" and not (node.token contains "subscript:$u['permissions']")
  emit issue custom.PasswordOnlySessionHash at node
}
`)
	if err != nil {
		t.Fatalf("parse context subscript flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "auth.php:10",
		Scope: "auth.php/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=php\x00name=authenticate",
		},
	})
	store.AddNode(usg.Node{
		ID:    "password",
		Type:  "code.Subscript",
		Loc:   "auth.php:12",
		Scope: "auth.php/fn1",
		Props: map[string]string{"callee_path": "$u.__subscript", "str_args": "password"},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context subscript flag should match password without permissions: %+v", got)
	}
	store.AddNode(usg.Node{
		ID:    "permissions",
		Type:  "code.Subscript",
		Loc:   "auth.php:12",
		Scope: "auth.php/fn1",
		Props: map[string]string{"callee_path": "$u.__subscript", "str_args": "permissions"},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context subscript flag should reject matching permissions key: %+v", got)
	}
}

func TestContextFlagIgnoresUnscopedParamsFromOtherFunctions(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding remoteUrlDebugLog {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=javascript" and node.token contains "name=fetchRepo" and node.token contains "call_path:logger.debug" and node.token contains "identifier:url"
  emit issue custom.RemoteUrlDebugLog at node
}
`)
	if err != nil {
		t.Fatalf("parse context identifier flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "file.ts:40",
		Scope: "file.ts/fn2",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=javascript\x00name=fetchRepo",
		},
	})
	store.AddNode(usg.Node{
		ID:    "debug",
		Type:  "code.Call",
		Loc:   "file.ts:45",
		Scope: "file.ts/fn2",
		Props: map[string]string{"callee_path": "logger.debug", "method": "debug"},
	})
	store.AddNode(usg.Node{
		ID:   "other-param",
		Type: "code.Param",
		Loc:  "file.ts:10",
		Props: map[string]string{
			"name": "url",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context identifier flag matched unscoped param from a different function: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:   "local-param",
		Type: "code.Param",
		Loc:  "file.ts:40",
		Props: map[string]string{
			"name": "url",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context identifier flag should match unscoped param on context declaration line: %+v", got)
	}
}

func TestContextFlagCallArgDoesNotUseCompactTokenFallback(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.php.test;

binding directJsonEncode {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=php" and node.token contains "call_arg:json_encode:$data[$field_name]"
  emit issue custom.DirectJsonEncode at node
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:1",
		"region":      "fields.php/fn1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php\x00call_arg:json_encode:$data[$field_name]",
	}})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("context call-arg flag should require scoped AST call evidence, got %+v", got)
	}
}

func TestContextFlagStructuredTokenEqualsUsesTokenBoundary(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.ruby.test;

binding exactParse {
  query pattern presenceNode where node.scope == "function" and node.token == "function_name:parse"
  emit issue custom.ExactParse at node
}
`)
	if err != nil {
		t.Fatalf("parse context exact-token flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "parse", Type: "code.Call", Props: map[string]string{
		"loc":         "nat.rb:10",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00function_name:parse",
	}})
	store.AddNode(usg.Node{ID: "do-parse", Type: "code.Call", Props: map[string]string{
		"loc":         "nat.rb:20",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00function_name:do_parse",
	}})
	store.AddNode(usg.Node{ID: "parse-cron", Type: "code.Call", Props: map[string]string{
		"loc":         "nat.rb:30",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00function_name:parse_cron",
	}})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "parse" {
		t.Fatalf("context exact-token flag should only match function_name:parse, got %+v", got)
	}
}

func TestContextFlagAstPredicatesUseRegionWhenScopeIsEmpty(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.php.test;

binding scopedLiteral {
  query pattern presenceNode where node.scope == "function" and node.token contains "lang=php" and node.token contains "literal:multiple_dropdown_action" and node.token contains "call_arg:json_encode:$data[$field_name]"
  emit issue custom.ScopedLiteral at node
}
`)
	if err != nil {
		t.Fatalf("parse region-scoped context flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "target-ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:10",
		"region":      "fields.php/fn1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php",
	}})
	store.AddNode(usg.Node{ID: "other-ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:30",
		"region":      "fields.php/fn2",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php",
	}})
	store.AddNode(usg.Node{ID: "lit", Type: "code.Const", Props: map[string]string{
		"loc":      "fields.php:11",
		"region":   "fields.php/fn1",
		"str_args": "multiple_dropdown_action",
	}})
	store.AddNode(usg.Node{ID: "encode", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:12",
		"callee_path": "json_encode",
		"method":      "json_encode",
		"str_args":    "$data[$field_name]",
	}})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "target-ctx" {
		t.Fatalf("context AST flag should use region as lexical scope, got %+v", got)
	}
}

func TestContextFlagStructuredTokenContainsSearchesTokenPayload(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.ruby.test;

binding railsSecretToken {
  query pattern presenceNode where node.scope == "module" and node.token contains "lang=ruby" and containsAny(node.token, ["assign:.config.secret_token="]) and not (node.token contains "expr:Rails.env=='test'")
  emit issue custom.RailsSecretToken at node
}
`)
	if err != nil {
		t.Fatalf("parse context structured-token flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "secret_token.rb:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
	}})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.RailsSecretToken" {
		t.Fatalf("context structured-token flag did not search token payload: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc":         "secret_token_fixed.rb:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
	}})
	store.AddNode(usg.Node{ID: "fixed-env", Type: "code.Param", Loc: "secret_token_fixed.rb:2", Scope: "secret_token_fixed.rb/module", Props: map[string]string{"name": "Rails.env"}})
	store.AddNode(usg.Node{ID: "fixed-test", Type: "code.Const", Loc: "secret_token_fixed.rb:2", Scope: "secret_token_fixed.rb/module", Props: map[string]string{"str_args": "test"}})
	store.AddNode(usg.Node{ID: "fixed-arg0", Type: "code.Arg", Loc: "secret_token_fixed.rb:2", Scope: "secret_token_fixed.rb/module"})
	store.AddNode(usg.Node{ID: "fixed-arg1", Type: "code.Arg", Loc: "secret_token_fixed.rb:2", Scope: "secret_token_fixed.rb/module"})
	store.AddNode(usg.Node{ID: "fixed-cmp", Type: "code.BinOp", Loc: "secret_token_fixed.rb:2", Scope: "secret_token_fixed.rb/module", Props: map[string]string{"op": "==", "callee_path": "__binop.eq", "method": "eq", "arg0": "fixed-arg0", "arg1": "fixed-arg1"}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "fixed-env", Dst: "fixed-arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "fixed-test", Dst: "fixed-arg1"})
	got = spec.presenceApplicator().Apply(store)
	if len(got) != 1 {
		t.Fatalf("context structured-token flag should skip test-only guarded scope, got %+v", got)
	}
}

func TestModuleContextFlagStructuredPredicatesUseAstNodes(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.c.test;

binding pathBasedSandboxExposeBindRace {
  query pattern presenceNode where node.scope == "module" and node.token contains "lang=c" and node.token contains "call_path:filesystem_sandbox_arg" and node.token contains "literal:sandbox-expose" and not (node.token contains "call_path:fd_map_remap_fd")
  emit issue custom.PathBasedSandboxExposeBindRace at node
}
`)
	if err != nil {
		t.Fatalf("parse module context ast flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "portal.c:1",
		Scope: "portal.c",
		Props: map[string]string{
			"callee_path": "analysis.module.context",
			"method":      "context",
			"str_args":    "lang=c",
		},
	})
	store.AddNode(usg.Node{
		ID:    "lookup",
		Type:  "code.Call",
		Loc:   "portal.c:12",
		Scope: "portal.c/handle_spawn",
		Props: map[string]string{
			"callee_path": "g_variant_lookup",
			"method":      "g_variant_lookup",
		},
	})
	store.AddNode(usg.Node{
		ID:    "literal",
		Type:  "code.Const",
		Loc:   "portal.c:12",
		Scope: "portal.c/handle_spawn",
		Props: map[string]string{"str_args": "sandbox-expose"},
	})
	store.AddNode(usg.Node{
		ID:    "arg",
		Type:  "code.Call",
		Loc:   "portal.c:16",
		Scope: "portal.c/handle_spawn",
		Props: map[string]string{
			"callee_path": "filesystem_sandbox_arg",
			"method":      "filesystem_sandbox_arg",
		},
	})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.PathBasedSandboxExposeBindRace" {
		t.Fatalf("module context flag should match AST call/literal predicates even when context tokens are sparse: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "safe",
		Type:  "code.Call",
		Loc:   "portal.c:20",
		Scope: "portal.c/handle_spawn",
		Props: map[string]string{
			"callee_path": "fd_map_remap_fd",
			"method":      "fd_map_remap_fd",
		},
	})
	if got := spec.presenceApplicator().Apply(store); len(got) != 0 {
		t.Fatalf("module context flag should honor AST negative call predicates: %+v", got)
	}
}

func TestAstFlagMatchesDownstreamFlowPredicate(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.cpp.test;

binding pointerAddOverflow {
  query pattern presenceNode where node.kind == "binop" and node.op contains "+" and operand(node, where: operand.path ~= "alignPointer") and node.flowTo.op contains ">" and not (node.flowTo.op contains "<")
  emit issue custom.PointerAddOverflow at node
}
`)
	if err != nil {
		t.Fatalf("parse ast flow flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.h:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=cpp",
	}})
	store.AddNode(usg.Node{ID: "add", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:10", "op": "+", "callee_path": "__binop.add", "arg0": "a0", "arg1": "a1",
	}})
	store.AddNode(usg.Node{ID: "a0", Type: "code.Arg", Props: map[string]string{"loc": "sample.h:10"}})
	store.AddNode(usg.Node{ID: "a1", Type: "code.Arg", Props: map[string]string{"loc": "sample.h:10"}})
	store.AddNode(usg.Node{ID: "align", Type: "code.Call", Props: map[string]string{
		"loc": "sample.h:9", "callee_path": "alignPointer", "method": "alignPointer",
	}})
	store.AddNode(usg.Node{ID: "upper", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:12", "op": ">", "callee_path": "__binop.gt",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "align", Dst: "a0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "a0", Dst: "add"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "a1", Dst: "add"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "add", Dst: "upper"})
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "add" || got[0].Concept != "custom.PointerAddOverflow" {
		t.Fatalf("AST flow flag did not label vulnerable add: %+v", got)
	}

	store.AddNode(usg.Node{ID: "wrap", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:12", "op": "<", "callee_path": "__binop.lt",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "add", Dst: "wrap"})
	got = spec.presenceApplicator().Apply(store)
	if len(got) != 0 {
		t.Fatalf("AST flow flag should skip add with downstream wraparound check: %+v", got)
	}
}

func TestAstFlagCallOperandMatchesTransitiveFlow(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding remoteUrlDebugLog {
  query pattern presenceNode where node.kind == "call" and node.path ~= "logger.debug" and operand(node, where: containsAny(operand.identifier, ["url", "uri"]))
  emit issue custom.RemoteUrlDebugLog at node
}
`)
	if err != nil {
		t.Fatalf("parse param flow flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "url-param", Type: "code.Param", Props: map[string]string{
		"loc": "file.js:10", "name": "url",
	}})
	store.AddNode(usg.Node{ID: "elem", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "obj", Type: "code.Seq", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "__object_literal",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "debug", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "logger.debug", "method": "debug", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "url-param", Dst: "elem"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem", Dst: "obj"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "obj", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "debug"})

	debug, ok, err := store.GetNode("debug")
	if err != nil || !ok {
		t.Fatalf("missing debug node: ok=%v err=%v", ok, err)
	}
	if !flagNodeKindAllows(spec.Flags[0], debug) {
		t.Fatalf("debug node kind was not allowed by flag: %+v", spec.Flags[0])
	}
	if !flagMatchesNode(store, &flagMatchIndex{}, spec.Flags[0], debug, "javascript", false, nil) {
		t.Fatalf("call operand flag did not match transitive URL flow into debug call")
	}

	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "debug" || got[0].Concept != "custom.RemoteUrlDebugLog" {
		t.Fatalf("call operand flag did not label debug log call: %+v", got)
	}
}

func TestAstFlagCallOperandFallsBackToIncomingArgFlow(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.test;

binding zipCompressedSizeRead {
  query pattern presenceNode where node.kind == "call" and node.path ~= "tokenizer.readToken" and operand(node, where: operand.path ~= "Token.StringType" and operand.path ~= "zipHeader.compressedSize")
  emit issue custom.ZipCompressedSizeRead at node
}
`)
	if err != nil {
		t.Fatalf("parse call operand flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "size", Type: "code.Attr", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "zipHeader.compressedSize",
	}})
	store.AddNode(usg.Node{ID: "size-arg", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "string-type", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "Token.StringType", "method": "StringType",
	}})
	store.AddNode(usg.Node{ID: "read-arg", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "read-token", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "tokenizer.readToken", "method": "readToken",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "size", Dst: "size-arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "size-arg", Dst: "string-type"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "string-type", Dst: "read-arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "read-arg", Dst: "read-token"})

	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "read-token" || got[0].Concept != "custom.ZipCompressedSizeRead" {
		t.Fatalf("call operand flag did not use incoming arg flow fallback: %+v", got)
	}
}

func TestCollectionFirstSinkTargetsIndexedElement(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:         "custom.Command",
			Pattern:         "runtime.execv",
			CollectionFirst: true,
			CollectionIndex: 0,
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "elem0", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "0",
	}})
	store.AddNode(usg.Node{ID: "elem1", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "1",
	}})
	store.AddNode(usg.Node{ID: "seq", Type: "code.Seq", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "__object_literal",
	}})
	store.AddNode(usg.Node{ID: "tmp", Type: "code.Name", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "runtime.execv", "method": "execv", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem0", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem1", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "seq", Dst: "tmp"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tmp", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "call"})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "elem0" || got[0].Concept != "custom.Command" {
		t.Fatalf("collection first sink mapping wrong: %+v", got)
	}
}

func TestCollectionFirstSinkTargetsElementThroughVariableArg(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:         "custom.Command",
			Pattern:         "subprocess.Popen",
			Collection:      true,
			CollectionFirst: true,
			CollectionIndex: 0,
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "elem0", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "0",
	}})
	store.AddNode(usg.Node{ID: "seq", Type: "code.Seq", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "subprocess.Popen", "method": "Popen", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem0", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "seq", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "call"})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "elem0" || got[0].Concept != "custom.Command" {
		t.Fatalf("collection first sink should follow variable-held argv list: %+v", got)
	}
}

func TestCollectionSinkAcceptsVariableHeldCollectionArg(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.Command",
			Pattern:    "runtime.execv",
			Collection: true,
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "elem0", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "0",
	}})
	store.AddNode(usg.Node{ID: "seq", Type: "code.Seq", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "tmp", Type: "code.Call", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Call",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "runtime.execv", "method": "execv", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem0", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "seq", Dst: "tmp"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tmp", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "call"})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg0" || got[0].Concept != "custom.Command" {
		t.Fatalf("collection sink should accept collection-valued call arg: %+v", got)
	}
}

func TestSinkBestMatchKeepsCollectionAndScalarTargets(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{
			{Concept: "custom.Command", Pattern: "Process.run", ArgIndex: -1},
			{Concept: "custom.Command", Pattern: "Process.run", ArgIndex: -1, Collection: true},
		},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:1", "vkind": "Const",
	}})
	store.AddNode(usg.Node{ID: "arg1", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:1", "vkind": "Seq",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "Process.run", "method": "run", "arg0": "arg0", "arg1": "arg1",
	}})

	got := spec.sinkApplicator().Apply(store)
	seen := map[string]bool{}
	for _, m := range got {
		if m.Concept == "custom.Command" {
			seen[m.NodeID] = true
		}
	}
	if !seen["arg0"] || !seen["arg1"] {
		t.Fatalf("collection and scalar sink mappings should both survive best-match selection: %+v", got)
	}
}

func TestOverlayBindingsLoadV2Binding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.vyql")
	if err := os.WriteFile(path, []byte(`
module bindings.python.overlay;
concept custom.SqlExecution : sink {}
binding cursorExecuteQuery {
  query pattern callExpr where callee.method == "execute"
  emit sink custom.SqlExecution at args[0]
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	ads, err := OverlayBindings(dir, []string{"python"})
	if err != nil {
		t.Fatalf("OverlayBindings: %v", err)
	}
	if len(ads) == 0 {
		t.Fatal("OverlayBindings returned no graph labelers for v2 binding")
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.py:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.py:2", "callee_path": "cursor.execute", "method": "execute", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "call"})

	var got []string
	for _, ad := range ads {
		for _, m := range ad.Apply(store) {
			got = append(got, m.NodeID+":"+m.Concept)
		}
	}
	if strings.Join(got, ",") != "arg0:custom.SqlExecution" {
		t.Fatalf("v2 overlay binding labels = %v, want arg0:custom.SqlExecution", got)
	}
}

func TestV2ArgsCountPredicateFiltersSinkMappings(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.db;
concept custom.SqlExecution : sink {}
binding executeParameterized {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit sink custom.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	var ad *parser.BindingSet
	for _, decl := range decls {
		if got, ok := decl.(*parser.BindingSet); ok {
			ad = got
			break
		}
	}
	if ad == nil {
		t.Fatalf("ParseV2Definitions decls = %#v, want binding decl", decls)
	}
	spec := specFromBindingSet(ad)

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "oneArg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.py:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "oneArgCall", Type: "code.Call", Props: map[string]string{
		"loc": "sample.py:2", "callee_path": "cursor.execute", "method": "execute", "arg0": "oneArg0",
	}})
	store.AddNode(usg.Node{ID: "twoArg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.py:3", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "twoArg1", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.py:3", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "twoArgCall", Type: "code.Call", Props: map[string]string{
		"loc": "sample.py:3", "callee_path": "cursor.execute", "method": "execute", "arg0": "twoArg0", "arg1": "twoArg1",
	}})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "twoArg0" || got[0].Concept != "custom.SqlExecution" {
		t.Fatalf("args.count-gated sink labels = %+v, want only twoArg0", got)
	}
}

func TestValueMatchedSourceUsesDirectStringTokensOnly(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:    "custom.Source",
			Paths:      []string{"os.getenv"},
			Match:      "prefix",
			ValMatches: []string{"HTTP_PROXY"},
		}},
	}
	binding := spec.sourceApplicator()

	direct := usg.NewInMemStore()
	direct.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "os.getenv", "method": "getenv", "str_args": "HTTP_PROXY",
	}})
	if got := binding.Apply(direct); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("value-matched source did not use direct string tokens: %+v", got)
	}

	flowed := usg.NewInMemStore()
	flowed.AddNode(usg.Node{ID: "literal", Type: "code.Const", Props: map[string]string{
		"loc": "sample.x:1", "str_args": "HTTP_PROXY",
	}})
	flowed.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	flowed.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "os.getenv", "method": "getenv", "arg0": "arg0",
	}})
	flowed.AddEdge(usg.Edge{Type: "FLOWS", Src: "literal", Dst: "arg0"})
	flowed.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "src"})
	if got := binding.Apply(flowed); len(got) != 0 {
		t.Fatalf("value-matched source used flowing string tokens: %+v", got)
	}
}

func TestV2BindingQueryEnclosesLiteralLabelsMatchedCall(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.sql;
concept SqlExecution : sink {}
binding sqlLiteralQuery {
  query call as c where c.callee.method == "query"
    encloses literal as lit where lit.value contains "SELECT" and not lit.raw contains "SafeQuery"
  emit sink SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "matchedArg", Type: "code.Arg", Props: map[string]string{
		"loc": "app.js:7", "vkind": "String",
	}})
	store.AddNode(usg.Node{ID: "matchedCall", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "db.query", "method": "query", "arg0": "matchedArg", "str_args": "SELECT * FROM users",
	}})
	store.AddNode(usg.Node{ID: "safeArg", Type: "code.Arg", Props: map[string]string{
		"loc": "app.js:8", "vkind": "String",
	}})
	store.AddNode(usg.Node{ID: "safeCall", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:8", "callee_path": "db.query", "method": "query", "arg0": "safeArg", "str_args": "SELECT SafeQuery",
	}})
	store.AddNode(usg.Node{ID: "otherArg", Type: "code.Arg", Props: map[string]string{
		"loc": "app.js:9", "vkind": "String",
	}})
	store.AddNode(usg.Node{ID: "otherCall", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:9", "callee_path": "db.query", "method": "query", "arg0": "otherArg", "str_args": "UPDATE users",
	}})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "matchedArg" || got[0].Concept != "bindings.javascript.sql.SqlExecution" {
		t.Fatalf("literal relation sink labels = %+v, want only matchedArg", got)
	}
}

func TestV2BindingQueryReferencesCallRequiresScopedCall(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.composed;
concept CommandExecution : sink {}
binding guardedDanger {
  query call as c where c.callee.method == "danger" references call as other where other.callee.method == "safe"
  emit sink CommandExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "matchedArg", Type: "code.Arg", Scope: "fn", Props: map[string]string{
		"loc": "app.js:7",
	}})
	store.AddNode(usg.Node{ID: "matchedCall", Type: "code.Call", Scope: "fn", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "danger", "method": "danger", "arg0": "matchedArg",
	}})
	store.AddNode(usg.Node{ID: "safeCall", Type: "code.Call", Scope: "fn", Props: map[string]string{
		"loc": "app.js:8", "callee_path": "safe", "method": "safe",
	}})
	store.AddNode(usg.Node{ID: "otherArg", Type: "code.Arg", Scope: "other", Props: map[string]string{
		"loc": "app.js:20",
	}})
	store.AddNode(usg.Node{ID: "otherCall", Type: "code.Call", Scope: "other", Props: map[string]string{
		"loc": "app.js:20", "callee_path": "danger", "method": "danger", "arg0": "otherArg",
	}})

	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "matchedArg" || got[0].Concept != "bindings.javascript.composed.CommandExecution" {
		t.Fatalf("scoped relation sink labels = %+v, want only matchedArg", got)
	}
}

func TestJSDomValueInputApplicatorUsesFlowIndex(t *testing.T) {
	want := singleOntologyRoleConcept(ontology.InternalConceptRoleDomInput)
	if want == "" {
		t.Fatal("DomInput analysis role did not resolve")
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "lookup", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:1", "callee_path": "document.getElementById",
	}})
	store.AddNode(usg.Node{ID: "value", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.js:2", "callee_path": "source.value",
	}})
	store.AddNode(usg.Node{ID: "plain", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.js:3", "callee_path": "model.value",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "lookup", Dst: "value"})

	got := jsDomValueInputApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "value" || got[0].Concept != want {
		t.Fatalf("DOM value source mapping wrong: %+v want concept %s", got, want)
	}
}

func TestSourceApplicatorVisitsCallablePropertyNodeTypes(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept: "custom.Source",
			Paths: []string{
				"call.source",
				"attr.source",
				"name_source",
				"bag.__subscript",
				"__binop.add",
				"__unary.neg",
				"__object_literal",
			},
			Match: "prefix",
		}},
	}
	store := usg.NewInMemStore()
	for _, tc := range []struct {
		id   string
		typ  string
		path string
	}{
		{"call", "code.Call", "call.source"},
		{"attr", "code.Attr", "attr.source"},
		{"name", "code.Name", "name_source"},
		{"subscript", "code.Subscript", "bag.__subscript"},
		{"binop", "code.BinOp", "__binop.add"},
		{"unary", "code.Unary", "__unary.neg"},
		{"seq", "code.Seq", "__object_literal"},
	} {
		store.AddNode(usg.Node{ID: tc.id, Type: tc.typ, Props: map[string]string{
			"loc": "sample.x:1", "callee_path": tc.path, "method": tc.path,
		}})
	}
	got := spec.sourceApplicator().Apply(store)
	if len(got) != 7 {
		t.Fatalf("input binding missed callable node types: %+v", got)
	}
	seen := map[string]bool{}
	for _, m := range got {
		seen[m.NodeID] = true
	}
	for _, id := range []string{"call", "attr", "name", "subscript", "binop", "unary", "seq"} {
		if !seen[id] {
			t.Fatalf("input binding missed %s in %+v", id, got)
		}
	}
}

func TestV2MemberAccessPatternOnlyLabelsAttrs(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.dom;
pattern domValue as member {
  node: memberAccess
  where member.property == "value"
}
binding domValueSource {
  query pattern domValue
  emit source custom.DomValue at member
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "attr", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.js:1", "callee_path": "input.value", "method": "value",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:2", "callee_path": "input.value", "method": "value",
	}})

	got := spec.sourceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "attr" || got[0].Concept != "custom.DomValue" {
		t.Fatalf("memberAccess pattern matched wrong nodes: %+v", got)
	}
}

func TestV2BinaryExprPatternOnlyLabelsBinOps(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.compare;
pattern equalityComparison as cmp {
  node: binaryExpr
  where cmp.operator == "=="
}
binding secretComparison {
  query pattern equalityComparison
  emit issue custom.SecretComparison at cmp
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "cmp", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.js:1", "callee_path": "__binop.eq", "method": "eq",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:2", "callee_path": "__binop.eq", "method": "eq",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "cmp" || got[0].Concept != "custom.SecretComparison" {
		t.Fatalf("binaryExpr pattern matched wrong nodes: %+v", got)
	}
}

func TestV2LiteralPatternLabelsLiteralNodesByValue(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.literal;
pattern dangerousPath as lit {
  node: literal
  where lit.value contains "/etc/"
}
binding dangerousPathLiteral {
  query pattern dangerousPath
  emit issue custom.DangerousPath at lit
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "lit", Type: "code.Literal", Props: map[string]string{
		"loc": "sample.js:1", "value": "/etc/passwd",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:2", "value": "/etc/passwd",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "lit" || got[0].Concept != "custom.DangerousPath" {
		t.Fatalf("literal pattern matched wrong nodes: %+v", got)
	}
}

func TestV2FunctionInlineQueryLabelsFunctionNodesByName(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.functions;
binding exportedHandler {
  query function as fn where fn.name contains "handler"
  emit source custom.HandlerEntry at fn
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "fn", Type: "code.Function", Props: map[string]string{
		"loc": "sample.js:1", "name": "exportedHandler",
	}})
	store.AddNode(usg.Node{ID: "name", Type: "code.Name", Props: map[string]string{
		"loc": "sample.js:2", "name": "exportedHandler",
	}})

	got := spec.sourceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "fn" || got[0].Concept != "custom.HandlerEntry" {
		t.Fatalf("function query matched wrong nodes: %+v", got)
	}
}

func TestV2ImportInlineQueryLabelsImportNodesByModule(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.imports;
binding lodashImport {
  query import as imp where imp.module == "lodash"
  emit fact custom.DependencyUse at imp
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.js:1", "module": "lodash",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:2", "module": "lodash",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "imp" || got[0].Concept != "custom.DependencyUse" {
		t.Fatalf("import query matched wrong nodes: %+v", got)
	}
}

func TestV2ClassInlineQueryLabelsClassNodesByName(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.classes;
binding adminClass {
  query class as cls where cls.name contains "Admin"
  emit source custom.AdminSurface at cls
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "class", Type: "code.Class", Props: map[string]string{
		"loc": "sample.js:1", "name": "AdminController",
	}})
	store.AddNode(usg.Node{ID: "fn", Type: "code.Function", Props: map[string]string{
		"loc": "sample.js:2", "name": "AdminController",
	}})

	got := spec.sourceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "class" || got[0].Concept != "custom.AdminSurface" {
		t.Fatalf("class query matched wrong nodes: %+v", got)
	}
}

func TestV2AssignmentQueryLabelsAssignmentContextNodes(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.assignments;
binding secretAssignment {
  query assignment as a where a.target contains "token" and a.value contains "secret"
  emit issue custom.SecretAssignment at a
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "assignment", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:1", "callee_path": "analysis.function.context", "method": "context", "str_args": "assign:token=secretValue",
	}})
	store.AddNode(usg.Node{ID: "ordinary-call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:2", "callee_path": "log", "method": "log", "str_args": "assign:token=secretValue",
	}})
	store.AddNode(usg.Node{ID: "other-assignment", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:3", "callee_path": "analysis.function.context", "method": "context", "str_args": "assign:other=secretValue",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "assignment" || got[0].Concept != "custom.SecretAssignment" {
		t.Fatalf("assignment query matched wrong nodes: %+v", got)
	}
}

func TestV2FactEmitLabelsMatchedCall(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept PublicEndpoint : fact {}
binding expressRoute {
  query pattern callExpr where callee.method == "get"
  emit fact PublicEndpoint at call
  fidelity: resolved
  confidence: high
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "route", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "app.get", "method": "get", "tech": "javascript",
	}})
	store.AddNode(usg.Node{ID: "post", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:8", "callee_path": "app.post", "method": "post", "tech": "javascript",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "route" || got[0].Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("fact emit labeled wrong nodes: %+v", got)
	}
	if got[0].Fidelity != "resolved" || got[0].Confidence != "high" {
		t.Fatalf("fact emit provenance = fidelity %q confidence %q, want resolved/high", got[0].Fidelity, got[0].Confidence)
	}

	applied := usg.NewInMemStore()
	applied.AddNode(usg.Node{ID: "route", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "app.get", "method": "get", "tech": "javascript",
	}})
	applied.AddNode(usg.Node{ID: "post", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:8", "callee_path": "app.post", "method": "post", "tech": "javascript",
	}})
	if _, suppressed, err := bindings.Apply(applied, []bindings.Applicator{spec.matchPresenceApplicator()}, nil); err != nil {
		t.Fatalf("apply fact binding: %v", err)
	} else if len(suppressed) != 0 {
		t.Fatalf("suppressed fact mappings: %+v", suppressed)
	}
	labels, err := applied.Labels("route")
	if err != nil {
		t.Fatalf("route labels: %v", err)
	}
	if len(labels) != 1 || labels[0].Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("route labels = %+v, want PublicEndpoint", labels)
	}
	postLabels, err := applied.Labels("post")
	if err != nil {
		t.Fatalf("post labels: %v", err)
	}
	if len(postLabels) != 0 {
		t.Fatalf("post labels = %+v, want none", postLabels)
	}
}

func TestV2FactEmitLabelsArgumentLocation(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept RoutePath : fact {}
binding expressRoute {
  query pattern callExpr where callee.method == "get"
  emit fact RoutePath at args[0]
  fidelity: resolved
  confidence: high
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "path", Type: "code.Literal", Props: map[string]string{
		"loc": "app.js:7", "str_args": "/users", "tech": "javascript",
	}})
	store.AddNode(usg.Node{ID: "route", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "app.get", "method": "get", "arg0": "path", "tech": "javascript",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "path" || got[0].Concept != "bindings.javascript.facts.RoutePath" {
		t.Fatalf("argument fact emit labeled wrong nodes: %+v", got)
	}
}

func TestV2FactEmitLabelsAllArgumentLocations(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept RoutePart : fact {}
binding expressRoute {
  query pattern callExpr where callee.method == "route"
  emit fact RoutePart at args.any
}
`)
	if err != nil {
		t.Fatalf("parse v2 definitions: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, decls))

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "path", Type: "code.Literal", Props: map[string]string{
		"loc": "app.js:7", "str_args": "/users", "tech": "javascript",
	}})
	store.AddNode(usg.Node{ID: "handler", Type: "code.Function", Props: map[string]string{
		"loc": "app.js:7", "tech": "javascript",
	}})
	store.AddNode(usg.Node{ID: "route", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:7", "callee_path": "router.route", "method": "route", "arg0": "path", "arg1": "handler", "tech": "javascript",
	}})

	got := spec.matchPresenceApplicator().Apply(store)
	if len(got) != 2 {
		t.Fatalf("argument fact emit labels = %+v, want two args", got)
	}
	seen := map[string]bool{}
	for _, m := range got {
		if m.Concept != "bindings.javascript.facts.RoutePart" {
			t.Fatalf("unexpected concept in mapping: %+v", m)
		}
		seen[m.NodeID] = true
	}
	if !seen["path"] || !seen["handler"] {
		t.Fatalf("argument fact emit targets = %+v, want path and handler", got)
	}
}

func TestExplicitPackageBlockSourceRequiresPackageEvidence(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:  "custom.Source",
			Paths:    []string{"samplepkg.source.value"},
			Match:    "prefix",
			Packages: []string{"samplepkg"},
		}},
	}
	binding := spec.sourceApplicator()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := binding.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("explicit package-block source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := binding.Apply(withPkg); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("explicit package-block source did not fire with package evidence: %+v", got)
	}
}

func TestExplicitPackageBlockReceiverSourceUsesResolvedType(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:    "custom.Source",
			Methods:    []string{"value"},
			Receiver:   true,
			Constraint: "samplepkg.Request",
			Packages:   []string{"samplepkg"},
		}},
	}
	binding := spec.sourceApplicator()

	withWrongReceiver := usg.NewInMemStore()
	withWrongReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withWrongReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "payload.value", "method": "value",
	}})
	if got := binding.Apply(withWrongReceiver); len(got) != 0 {
		t.Fatalf("receiver source fired without receiver type: %+v", got)
	}

	withReceiver := usg.NewInMemStore()
	withReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "request.value", "method": "value", "recv_type": "samplepkg.Request",
	}})
	if got := binding.Apply(withReceiver); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("receiver source did not fire with receiver type: %+v", got)
	}
}

func TestExplicitPackageBlockControlRequiresPackageEvidence(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "normalize",
			ByMethod: true,
			Packages: []string{"samplepkg"},
		}},
	}
	binding := spec.checkApplicator()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := binding.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("explicit package-block control fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := binding.Apply(withPkg); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("explicit package-block control did not fire with package evidence: %+v", got)
	}
}

func TestBindingMetadataCrossLanguageAcceptsBoolAndString(t *testing.T) {
	for _, meta := range []map[string]any{
		{"cross_language": true},
		{"cross_language": "true"},
	} {
		spec := specFromBindingSet(&parser.BindingSet{Name: "sample", Meta: meta})
		if !spec.crossLang {
			t.Fatalf("cross_language metadata not honored: %#v", meta)
		}
	}
}

func TestCheckApplicatorPreservesCoverageDetail(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})

	spec := specFromBindingSet(&parser.BindingSet{
		Name: "neutral",
		Mappings: []parser.BindingAction{{
			Kind:           "check_method",
			Concept:        "custom.Control",
			Pattern:        "normalize",
			Coverage:       "sameScope",
			CoverageDetail: map[string]string{"anchor": "call.scope"},
			Fidelity:       "semantic",
			Confidence:     "medium",
		}},
	})
	got := spec.checkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("control mapping wrong: %+v", got)
	}
	if got[0].Detail["coverage"] != "sameScope" {
		t.Fatalf("coverage detail not preserved: %+v", got[0])
	}
	if got[0].Detail["coverage.anchor"] != "call.scope" {
		t.Fatalf("coverage item detail not preserved: %+v", got[0])
	}
	if got[0].Fidelity != "semantic" || got[0].Confidence != "medium" {
		t.Fatalf("binding evidence attrs not preserved: %+v", got[0])
	}
}

func TestCheckApplicatorLabelsArgumentLocation(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:2"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.execute", "method": "execute", "arg0": "arg",
	}})

	spec := specFromBindingSet(&parser.BindingSet{
		Name: "neutral",
		Mappings: []parser.BindingAction{{
			Kind:           "check_method_arg",
			Concept:        "custom.Parameterized",
			Pattern:        "execute",
			ArgIndex:       0,
			Coverage:       "path",
			CoverageDetail: map[string]string{"from": "args[0]", "to": "call"},
			Fidelity:       "semantic",
			Confidence:     "high",
		}},
	})
	got := spec.checkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Parameterized" {
		t.Fatalf("argument control mapping wrong: %+v", got)
	}
	if got[0].Detail["coverage"] != "path" || got[0].Detail["coverage.from"] != "args[0]" || got[0].Detail["coverage.to"] != "call" {
		t.Fatalf("coverage detail not preserved on argument control: %+v", got[0])
	}
	if got[0].Fidelity != "semantic" || got[0].Confidence != "high" {
		t.Fatalf("binding evidence attrs not preserved: %+v", got[0])
	}
}

func TestCheckApplicatorLabelsAdvisoryArgumentLocation(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:2"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.startswith", "method": "startswith", "arg0": "arg",
	}})

	spec := specFromBindingSet(&parser.BindingSet{
		Name: "neutral",
		Mappings: []parser.BindingAction{{
			Kind:           "check_method_arg",
			Concept:        "custom.PathCanonicalization",
			Pattern:        "startswith",
			ArgIndex:       0,
			About:          "custom.FilePathAccess",
			Advisory:       true,
			Coverage:       "sameScope",
			CoverageDetail: map[string]string{"anchor": "call.scope"},
			Fidelity:       "syntactic",
			Confidence:     "low",
		}},
	})
	got := spec.checkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.PathCanonicalization" {
		t.Fatalf("argument advisory check mapping wrong: %+v", got)
	}
	if got[0].Detail["advisory"] != "true" || got[0].Detail["about"] != "custom.FilePathAccess" ||
		got[0].Detail["coverage"] != "sameScope" || got[0].Detail["coverage.anchor"] != "call.scope" {
		t.Fatalf("advisory detail not preserved on argument check: %+v", got[0])
	}
	if got[0].Fidelity != "syntactic" || got[0].Confidence != "low" {
		t.Fatalf("binding evidence attrs not preserved: %+v", got[0])
	}
}

func TestCheckApplicatorLabelsGlobalArgumentLocation(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:2"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.enableHardening", "method": "enableHardening", "arg0": "arg",
	}})

	spec := specFromBindingSet(&parser.BindingSet{
		Name: "neutral",
		Mappings: []parser.BindingAction{{
			Kind:       "check_method_arg",
			Concept:    "custom.GlobalHardening",
			Pattern:    "enableHardening",
			ArgIndex:   0,
			Coverage:   "global",
			Fidelity:   "semantic",
			Confidence: "medium",
		}},
	})
	got := spec.checkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.GlobalHardening" {
		t.Fatalf("argument global check mapping wrong: %+v", got)
	}
	if got[0].Detail["coverage"] != "global" {
		t.Fatalf("global detail not preserved on argument check: %+v", got[0])
	}
	if got[0].Fidelity != "semantic" || got[0].Confidence != "medium" {
		t.Fatalf("binding evidence attrs not preserved: %+v", got[0])
	}
}

func TestSinkApplicatorUsesBindingEvidenceAttrs(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "app.js:2"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:2", "callee_path": "runner.exec", "method": "exec", "arg0": "arg",
	}})

	spec := specFromBindingSet(&parser.BindingSet{
		Name: "javascript",
		Mappings: []parser.BindingAction{{
			Kind:       "sink_method",
			Concept:    "custom.Command",
			Pattern:    "exec",
			Fidelity:   "semantic",
			Confidence: "medium",
		}},
	})
	got := spec.sinkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Command" {
		t.Fatalf("sink mapping wrong: %+v", got)
	}
	if got[0].Fidelity != "semantic" || got[0].Confidence != "medium" {
		t.Fatalf("binding evidence attrs not used: %+v", got[0])
	}
}

func TestPresenceApplicatorPreservesAdvisoryDetail(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})

	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Flags: []flagSpec{{
			Concept:  "custom.Control",
			NodeKind: "any",
			Predicates: []flagPredicate{
				newFlagPredicate("node", "path", "match", []string{"samplepkg.normalize"}, false, false),
			},
			Detail: map[string]string{"advisory": "true", "coverage": "sameScope"},
		}},
	}
	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("flag mapping wrong: %+v", got)
	}
	if got[0].Detail["advisory"] != "true" || got[0].Detail["coverage"] != "sameScope" {
		t.Fatalf("flag detail not preserved: %+v", got[0])
	}
}

func TestReceiverControlLabelsReceiverNode(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "recv", Type: "code.Name", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc":    "sample.x:1",
		"method": "checked",
		"recv":   "recv",
	}})

	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "checked",
			ByMethod: true,
			Receiver: true,
		}},
	}
	got := spec.checkApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "recv" || got[0].Concept != "custom.Control" {
		t.Fatalf("receiver control mapping wrong: %+v", got)
	}
}

func TestReceiverSinkHonorsReceiverTypeConstraint(t *testing.T) {
	spec := bindingSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.ReceiverSink",
			Pattern:    "danger",
			ByMethod:   true,
			Receiver:   true,
			Constraint: "samplepkg.SafeReceiver",
		}},
	}
	binding := spec.sinkApplicator()

	wrongType := usg.NewInMemStore()
	wrongType.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "obj.danger", "method": "danger", "recv_type": "samplepkg.OtherReceiver",
	}})
	if got := binding.Apply(wrongType); len(got) != 0 {
		t.Fatalf("receiver sink fired for conflicting receiver type: %+v", got)
	}

	rightType := usg.NewInMemStore()
	rightType.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "obj.danger", "method": "danger", "recv_type": "samplepkg.SafeReceiver",
	}})
	if got := binding.Apply(rightType); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.ReceiverSink" {
		t.Fatalf("receiver sink did not fire for matching receiver type: %+v", got)
	}
}

package parser

import (
	"fmt"
	"strings"
	"testing"
)

func TestV2LoweringToScannerIRDecls(t *testing.T) {
	decls := parseIRFiles(t, `
module core;
concept SqlParameterization : check { neutralizes: [code.SqlExecution] }
`, `
module bindings.python.dbapi;
binding cursorExecuteQuery {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
  fidelity: resolved
  confidence: high
}
binding requestBody {
  query pattern callExpr where callee.path ~= "request.json"
  emit source code.HttpInput at call.result
}
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute"
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`, `
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}
`)
	var adapter *BindingSet
	var rule *Rule
	var concept *ConceptDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *BindingSet:
			adapter = x
		case *Rule:
			rule = x
		case *ConceptDecl:
			concept = x
		}
	}
	if concept == nil || concept.QualifiedName() != "core.SqlParameterization" || concept.Kind != "check" {
		t.Fatalf("concept lowering wrong: %+v", concept)
	}
	if adapter == nil || adapter.Name != "python" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Concept != "code.SqlExecution" || got.ArgIndex != 0 {
		t.Fatalf("sink lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[0]; got.Fidelity != "resolved" || got.Confidence != "high" {
		t.Fatalf("binding evidence attrs not lowered: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "source" || got.Pattern != "request.json" || got.Concept != "code.HttpInput" {
		t.Fatalf("source lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "control_method_arg" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" || got.ArgIndex != 0 {
		t.Fatalf("check lowering wrong: %+v", got)
	}
	if rule == nil || rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("rule lowering wrong: %+v", rule)
	}
	flow := rule.Body.(*FlowStmt)
	if flow.Verb != "taint" || flow.Src.Concept != "code.HttpInput" || flow.Src.Binding != "input" || flow.Dst.Binding != "sqlSink" {
		t.Fatalf("flow lowering wrong: %+v", flow)
	}
	if sb, ok := rule.Clauses[0].Unless.(PathCoveredBy); !ok || sb.Concept != "core.SqlParameterization" {
		t.Fatalf("coveredBy lowering wrong: %+v", rule.Clauses[0])
	}
}

func TestParseV2DefinitionsRejectsAuthoredFlowRuleVerb(t *testing.T) {
	_, err := ParseV2Definitions(`
module rules.test;
rule CustomFlow {
  flow code.HttpInput -> code.SqlExecution
}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown v2 rule verb "flow"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored flow rejection", err)
	}
}

func TestLowerV2DefinitionSourcesValidatesCorpus(t *testing.T) {
	rules, err := ParseV2(`
module rules.test;
rule IssueAsFlow {
  issue code.HttpInput as input
}
`)
	if err != nil {
		t.Fatalf("ParseV2 rules: %v", err)
	}
	_, err = LowerV2DefinitionSources([]V2Source{
		{Name: "mechanics.vyql", Program: &V2Program{
			Module: "mechanics.test",
			Decls: []V2Decl{
				&V2MechanicDecl{Kind: "ruleVerb", Name: "issue"},
			},
		}},
		{Name: "rules.vyql", Program: rules},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicate v2 mechanic ruleVerb.issue; first declared in <builtin>`) {
		t.Fatalf("LowerV2DefinitionSources error = %v, want built-in mechanic reservation diagnostic", err)
	}
}

func TestV2DefinitionSourcesFromTextPreservesSingleSource(t *testing.T) {
	src := "module one;\nconcept A : source {}\n\n  module two;\nconcept B : sink {}\n"
	got := V2DefinitionSourcesFromText("inline.vyql", src)
	if len(got) != 1 {
		t.Fatalf("source count = %d, want 1", len(got))
	}
	if got[0].Name != "inline.vyql" || got[0].Source != src {
		t.Fatalf("source = %#v, want original text and name", got[0])
	}
	_, err := ParseV2(got[0].Source)
	if err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("ParseV2 error = %v, want duplicate module rejection", err)
	}
}

func TestParseV2DefinitionSourcesValidatesCorpus(t *testing.T) {
	_, err := ParseV2DefinitionSources([]V2DefinitionSource{
		{Name: "code.vyql", Source: `
module code;
concept Problem : issue {}
`},
		{Name: "core.vyql", Source: `
module core;
concept Guard : check { covers: [path] }
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule BadCoverage {
  issue code.Problem as p
  unless p.endpoint coveredBy core.Guard
}
`},
	})
	if err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("ParseV2DefinitionSources error = %v, want corpus coverage validation", err)
	}
}

func TestParseV2DefinitionSourcesSelectedLowersOnlySelectedSources(t *testing.T) {
	decls, err := ParseV2DefinitionSourcesSelected([]V2DefinitionSource{
		{Name: "code.vyql", Source: `
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule SelectedOnly {
  taint code.HttpInput -> code.SqlExecution
}
`},
	}, func(src V2DefinitionSource) bool {
		return src.Name == "rules.vyql"
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decl count = %d, want only selected rule decl: %+v", len(decls), decls)
	}
	if _, ok := decls[0].(*Rule); !ok {
		t.Fatalf("decl = %T, want *Rule", decls[0])
	}
}

func TestV2ScannerIRPreservesPolicies(t *testing.T) {
	decls, err := ParseV2Definitions(`
module mechanics.sast;
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want policy: %+v", len(decls), decls)
	}
	policy, ok := decls[0].(*V2PolicyDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want *V2PolicyDecl", decls[0])
	}
	if policy.Module != "mechanics.sast" || policy.Kind != "resultIdentity" || policy.Name != "default" {
		t.Fatalf("policy identity wrong: %+v", policy)
	}
	if got := policy.QualifiedName(); got != "mechanics.sast.policy:resultIdentity:default" {
		t.Fatalf("policy qualified name = %q", got)
	}
}

func TestParseV2DefinitionSourcesSelectedPreservesSelectedPolicies(t *testing.T) {
	decls, err := ParseV2DefinitionSourcesSelected([]V2DefinitionSource{
		{Name: "policy.vyql", Source: `
module policies.default;
policy display default {
  scanAll: [findings, flags, checks, advisoryEvidence, requirementDiagnostics]
  flagSort: [severity, category, location, concept]
  includeNearbyChecks: true
  nearbyCheckLimit: 5
}
`},
		{Name: "code.vyql", Source: `
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`},
		{Name: "rules.vyql", Source: `
module rules.test;
rule SelectedOnly {
  taint code.HttpInput -> code.SqlExecution
}
`},
	}, func(src V2DefinitionSource) bool {
		return src.Name == "policy.vyql"
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want selected policy: %+v", len(decls), decls)
	}
	if _, ok := decls[0].(*V2PolicyDecl); !ok {
		t.Fatalf("decl[0] = %T, want *V2PolicyDecl", decls[0])
	}
}

func TestV2LoweringUsesLocalPatternWhere(t *testing.T) {
	decls := parseIRFiles(t, `
module bindings.javascript.express;
pattern requestBodyCall as call {
  node: call
  bind callee = call.callee
  where callee.path ~= "req.body"
}
binding requestBody {
  query pattern requestBodyCall
  emit source code.HttpInput at call.result
}
`)
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "req.body" || got.Concept != "code.HttpInput" {
		t.Fatalf("pattern where did not lower to source mapping: %+v", got)
	}
}

func TestV2LoweringRewritesPatternBindAliases(t *testing.T) {
	decls := parseIRFiles(t, `
module bindings.javascript.sql;
pattern dbCall as call {
  node: call
  bind target = call.callee
}
binding execute {
  query pattern dbCall where target.method == "execute"
  emit sink code.SqlExecution at args[0]
}
`)
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.ArgIndex != 0 {
		t.Fatalf("pattern bind alias did not lower to sink mapping: %+v", got)
	}
}

func TestRewriteV2PatternRefsUsesFirstPathSegment(t *testing.T) {
	expr := V2BinaryExpr{
		Op: "and",
		Left: V2BinaryExpr{
			Op:    "==",
			Left:  V2RefExpr{Name: "target.method"},
			Right: V2LiteralExpr{Value: "execute"},
		},
		Right: V2BinaryExpr{
			Op:    "==",
			Left:  V2RefExpr{Name: "targetExtra.method"},
			Right: V2LiteralExpr{Value: "query"},
		},
	}
	got := rewriteV2PatternRefs(expr, map[string]string{
		"target":      "call.callee",
		"targetExtra": "call.extra",
	})
	and, ok := got.(V2BinaryExpr)
	if !ok || and.Op != "and" {
		t.Fatalf("rewritten expression = %#v, want conjunction", got)
	}
	left := and.Left.(V2BinaryExpr).Left.(V2RefExpr)
	right := and.Right.(V2BinaryExpr).Left.(V2RefExpr)
	if left.Name != "call.callee.method" || right.Name != "call.extra.method" {
		t.Fatalf("rewritten refs = %q, %q", left.Name, right.Name)
	}
}

func TestV2BindingTechnologyScansModuleSegments(t *testing.T) {
	cases := map[string]string{
		"bindings.javascript.express":      "javascript",
		"stdlib.bindings.python.dbapi":     "python",
		"stdlib.notbindings.python.dbapi":  "",
		"stdlib.bindings":                  "",
		"stdlib.bindings.typescript.react": "typescript",
	}
	for module, want := range cases {
		if got := v2BindingTechnology(module); got != want {
			t.Fatalf("v2BindingTechnology(%q) = %q, want %q", module, got, want)
		}
	}
}

func TestV2LoweringAllowsImportedBuiltinCallExprPattern(t *testing.T) {
	decls := parseIRFiles(t, `
module bindings.javascript.express;
uses patterns.javascript.callExpr as jsCall;
binding requestBody {
  query pattern jsCall where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`)
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "req.body" {
		t.Fatalf("builtin imported callExpr pattern did not lower: %+v", got)
	}
}

func TestV2LoweringRejectsMissingCustomPattern(t *testing.T) {
	prog, err := ParseV2(`
module bindings.javascript.routes;
binding routeSource {
  query pattern routeExpr where route.path ~= "/user"
  emit source code.HttpInput at route
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	_, err = lowerV2ProgramToDeclarations(prog)
	if err == nil || !strings.Contains(err.Error(), "pattern routeExpr is not declared") {
		t.Fatalf("lowerV2ProgramToDeclarations error = %v, want missing pattern diagnostic", err)
	}
}

func TestV2LoweringResolvesUsesAliasesToScannerIRConcepts(t *testing.T) {
	decls := parseIRFiles(t, `
module bindings.javascript.express;
uses code.HttpInput as Input;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source Input at call.result
}
`, `
module rules.aliases;
uses code.HttpInput as Input;
uses code.SqlExecution as Exec;
uses core.SqlParameterization as Guard;
rule SqlInjectionAlias {
  taint Input as input -> Exec as sink
  unless sink.endpoint coveredBy Guard
  where sink is Exec
}
`)
	var adapter *BindingSet
	var rule *Rule
	for _, d := range decls {
		switch x := d.(type) {
		case *BindingSet:
			adapter = x
		case *Rule:
			rule = x
		}
	}
	if adapter == nil || len(adapter.Mappings) != 1 || adapter.Mappings[0].Concept != "code.HttpInput" {
		t.Fatalf("alias in binding did not lower to canonical concept: %+v", adapter)
	}
	if rule == nil {
		t.Fatalf("rule did not lower")
	}
	flow := rule.Body.(*FlowStmt)
	if flow.Src.Concept != "code.HttpInput" || flow.Dst.Concept != "code.SqlExecution" {
		t.Fatalf("alias in rule endpoints did not lower: %+v", flow)
	}
	if gb, ok := rule.Clauses[0].Unless.(EndpointCoveredBy); !ok || gb.Concept != "core.SqlParameterization" {
		t.Fatalf("alias in coveredBy did not lower: %+v", rule.Clauses[0])
	}
	if is, ok := rule.Clauses[1].Where.(Is); !ok || is.Concept != "code.SqlExecution" {
		t.Fatalf("alias in is did not lower: %+v", rule.Clauses[1].Where)
	}
}

func TestV2LoweringRejectsLegacyHasWhereCall(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.legacy;
rule LegacyHas {
  issue runtime.Connection as c
  where has(c.dst, threat.MiningPool)
}
`)
	if err == nil || !strings.Contains(err.Error(), `unsupported call "has"`) {
		t.Fatalf("ParseV2Definitions error = %v, want unsupported has diagnostic", err)
	}
}

func TestV2LoweringSupportsSameReceiverCoveredBy(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.aliases;
rule SameReceiverCoverage {
  taint code.HttpInput as input -> code.SqlExecution as sink
  unless sink.sameReceiver coveredBy core.SqlParameterization
}
`)
	rule := decls[0].(*Rule)
	if _, ok := rule.Clauses[0].Unless.(SameReceiverCoveredBy); !ok {
		t.Fatalf("sameReceiver coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
	}
}

func TestV2LoweringUsesBuiltinCoverageMechanicForCoveredBy(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule GuardedIssue {
  issue code.Problem as p
  unless p.path coveredBy core.Guard
}
`)
	rule := decls[0].(*Rule)
	if _, ok := rule.Clauses[0].Unless.(PathCoveredBy); !ok {
		t.Fatalf("path coveredBy did not lower with builtin coverage mechanic: %+v", rule.Clauses[0])
	}
}

func TestV2LoweringUsesBuiltinCoverageMechanicForCheckEmission(t *testing.T) {
	decls, err := ParseV2Definitions(`
module bindings.python.dbapi;
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute"
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	got := decls[0].(*BindingSet).Mappings[0]
	if got.Kind != "control_method_arg" || got.Coverage != "path" || got.ArgIndex != 0 {
		t.Fatalf("check emission did not lower with builtin coverage mechanic: %+v", got)
	}
	if got.CoverageDetail["from"] != "args[0]" || got.CoverageDetail["to"] != "call" {
		t.Fatalf("coverage metadata was not preserved: %+v", got.CoverageDetail)
	}
}

func TestParseV2DefinitionsCompilesV2BindingSet(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.dbapi;
binding cursorExecuteQuery {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	bindings := decls[0].(*BindingSet)
	if bindings.Name != "python" || len(bindings.Mappings) != 1 {
		t.Fatalf("binding compilation wrong: %+v", bindings)
	}
	if got := bindings.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Concept != "code.SqlExecution" {
		t.Fatalf("binding action compilation wrong: %+v", got)
	}
}

func TestParseV2DefinitionsLowersPackDeclarations(t *testing.T) {
	decls, err := ParseV2Definitions(`
module packs.web;
pack webSecurity {
  includes: [profile web, pack base, rules.injection.SqlInjection]
  excludes: [rules.experimental.NoisyRule]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	pack, ok := decls[0].(*PackDecl)
	if !ok {
		t.Fatalf("decl = %T, want *PackDecl", decls[0])
	}
	if pack.Name != "webSecurity" {
		t.Fatalf("pack name = %q, want webSecurity", pack.Name)
	}
	if got := pack.Fields["includes"]; !stringListFieldEqual(got, []string{"profile.web", "pack.base", "rules.injection.SqlInjection"}) {
		t.Fatalf("pack includes = %#v", got)
	}
	if got := pack.Fields["excludes"]; !stringListFieldEqual(got, []string{"rules.experimental.NoisyRule"}) {
		t.Fatalf("pack excludes = %#v", got)
	}
}

func TestParseV2DefinitionsRejectsV1FallbackAndMultipleModules(t *testing.T) {
	if _, err := ParseV2Definitions(`
adapter javascript {
  source "req.body" -> code.HttpInput
}
`); err == nil {
		t.Fatalf("ParseV2Definitions accepted legacy adapter syntax")
	}

	if _, err := ParseV2Definitions(`
module code;
concept HttpInput : source {}

module bindings.javascript.express;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`); err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("ParseV2Definitions multi-module error = %v, want one-module rejection", err)
	}

	decls, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "code.vyql", Source: `module code;
concept HttpInput : source {}
`},
		{Name: "bindings/javascript/express.vyql", Source: `module bindings.javascript.express;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`},
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSources: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("decls = %d, want concept + adapter mapping", len(decls))
	}
}

func TestParseV2DefinitionsAllowsStandaloneMatcherDeclarations(t *testing.T) {
	decls, err := ParseV2Definitions(`
module patterns.javascript;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 0 {
		t.Fatalf("matcher declarations lowered to scanner IR decls: %+v", decls)
	}
}

func TestV2RequirementLowersToPackageHintsAndRequirementTree(t *testing.T) {
	cases := []struct {
		name     string
		req      string
		wantPkgs []string
		wantOp   string
	}{
		{
			name:     "dependency",
			req:      `dependency("express")`,
			wantPkgs: []string{"express"},
			wantOp:   "dependency",
		},
		{
			name:     "any dependency",
			req:      `any(dependency("express"), dependency("koa"), dependency("express"))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "any",
		},
		{
			name:     "all dependency",
			req:      `all(dependency("express"), dependency("koa"))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "all",
		},
		{
			name:     "dependency range",
			req:      `dependency("express", range: ">=4 <6")`,
			wantPkgs: []string{"express"},
			wantOp:   "dependency",
		},
		{
			name:     "import",
			req:      `import("express")`,
			wantPkgs: []string{"express"},
			wantOp:   "import",
		},
		{
			name:   "project fact",
			req:    `project.has("npm:publishable")`,
			wantOp: "project.has",
		},
		{
			name:     "soft nested any",
			req:      `soft(any(dependency("express"), import("koa")))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "soft",
		},
		{
			name:     "multiple top-level requirements",
			req:      `dependency("express")` + "\n    " + `language("javascript")`,
			wantPkgs: []string{"express"},
			wantOp:   "all",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.express;
binding requestBody {
  requires {
    ` + tc.req + `
  }
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
`)
			if err != nil {
				t.Fatalf("ParseV2Definitions: %v", err)
			}
			adapter := decls[0].(*BindingSet)
			got := adapter.Mappings[0]
			if !stringSlicesEqual(got.Packages, tc.wantPkgs) {
				t.Fatalf("packages = %#v, want %#v", got.Packages, tc.wantPkgs)
			}
			if got.Requirement == nil || got.Requirement.Op != tc.wantOp {
				t.Fatalf("requirement = %#v, want op %q", got.Requirement, tc.wantOp)
			}
			if tc.name == "dependency range" && got.Requirement.Range != ">=4 <6" {
				t.Fatalf("requirement range = %q, want >=4 <6", got.Requirement.Range)
			}
		})
	}
}

func TestV2RequirementLoweringRejectsMalformedCombinators(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "empty any",
			req:  `any()`,
			want: "at least one child",
		},
		{
			name: "empty all",
			req:  `all()`,
			want: "at least one child",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseV2Definitions(`
module bindings.javascript.express;
binding requestBody {
  requires {
    ` + tc.req + `
  }
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
`)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseV2Definitions error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseV2DefinitionsRejectsConcatenatedV2Modules(t *testing.T) {
	_, err := ParseV2Definitions(`
module rules.one;
rule One {
  issue code.First as first
}

module rules.two;
rule Two {
  issue code.Second as second
}
`)
	if err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("ParseV2Definitions multi-module error = %v, want one-module rejection", err)
	}
}

func TestV2ArgAnySinkLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.bash.migration;
binding catPath {
  query pattern callExpr where callee.path ~= "cat"
  emit sink code.FilePathAccess at args.any
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "bash" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_path" || got.Pattern != "cat" || got.ArgIndex != -1 {
		t.Fatalf("arg-any sink lowering wrong: %+v", got)
	}
}

func TestV2ExactPathSinkLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
binding jqueryRoot {
  query pattern callExpr where callee.path == "$"
  emit sink code.HtmlRender at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_path" || got.Pattern != "$" || !got.Exact {
		t.Fatalf("exact sink lowering wrong: %+v", got)
	}
}

func TestV2AnalysisCallAliasLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.http;
binding controllerParam {
  query pattern callExpr where callee.analysis == "parameter.entry" and args.any.context.annotation contains "GetMapping" and not args.any.context.paramType contains "Parser"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "analysis.parameter.entry" || got.ValMatches[0] != "annotation:GetMapping" || got.ValAbsents[0] != "param_type:Parser" {
		t.Fatalf("analysis alias lowering wrong: %+v", got)
	}
}

func TestV2MemberAccessPatternLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.dom;
pattern domValue as member {
  node: memberAccess
  where member.property == "value"
}
binding domValueSource {
  query pattern domValue
  emit source code.DomInput at member
}
binding secretAttr {
  query memberAccess as attr where attr.path ~= "config.secret"
  emit issue code.SecretValue at attr
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_method" || got.Pattern != "value" || got.NodeType != "code.Attr" {
		t.Fatalf("memberAccess property lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "mark" || got.Pattern != "config.secret" || got.NodeType != "code.Attr" {
		t.Fatalf("memberAccess path lowering wrong: %+v", got)
	}
}

func TestV2BinaryExprPatternLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.compare;
pattern equalityComparison as cmp {
  node: binaryExpr
  where cmp.operator in ["==", "==="]
}
binding secretComparison {
  query pattern equalityComparison
  emit issue code.SecretComparisonReview at cmp
}
binding weakCompare {
  query binaryExpr as op where op.op == "!="
  emit issue code.SecretComparisonReview at op
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "mark_method" || got.Pattern != "eq" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr equality lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "mark_method" || got.Pattern != "===" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr strict equality lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "mark_method" || got.Pattern != "ne" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr inline lowering wrong: %+v", got)
	}
}

func TestV2ComposedSingleNodePatternLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.composed;
pattern evalCall as c {
  use callExpr as call
  where call.callee.method == "eval"
}
pattern secretMember as attr {
  use memberBase as member
  where member.path ~= "config.secret"
}
pattern memberBase as member {
  node: memberAccess
}
binding evalSink {
  query pattern evalCall
  emit sink code.CodeEval at args[0]
}
binding secretIssue {
  query pattern secretMember
  emit issue code.SecretValue at attr
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "eval" {
		t.Fatalf("composed call pattern lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "mark" || got.Pattern != "config.secret" || got.NodeType != "code.Attr" {
		t.Fatalf("composed member pattern lowering wrong: %+v", got)
	}
}

func TestV2ComposedPatternCycleRejected(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module bindings.javascript.bad;
pattern a {
  use b as b
}
pattern b {
  use a as a
}
binding bad {
  query pattern a
  emit sink code.CodeEval at args[0]
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded for cyclic pattern use")
	}
	if !strings.Contains(err.Error(), "cyclic use") {
		t.Fatalf("error = %v, want cyclic use diagnostic", err)
	}
}

func TestV2CollectionSinkLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding subprocessCall {
  query pattern callExpr where callee.path ~= "subprocess.call"
  emit sink code.CommandExecution at args[0].collection[0]
}
binding writerow {
  query pattern callExpr where callee.method == "writerow"
  emit sink code.CsvCell at args[0].collection
}
binding execAll {
  query pattern callExpr where callee.path ~= "asyncio.create_subprocess_exec"
  emit sink code.CommandExecution at args.any.collection
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "python" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; !got.Collection || !got.CollectionFirst || got.CollectionIndex != 0 || got.ArgIndex != 0 {
		t.Fatalf("collection first lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; !got.Collection || got.CollectionFirst || got.ArgIndex != 0 {
		t.Fatalf("collection lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; !got.Collection || got.ArgIndex != -1 {
		t.Fatalf("arg-any collection lowering wrong: %+v", got)
	}
}

func TestV2ReceiverConstraintLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.migration;
binding servletParam {
  query pattern callExpr where callee.method == "getParameter" and callee.receiver.type == "HttpServletRequest"
  emit source code.HttpInput at call.result
}
binding statementExecute {
  query pattern callExpr where callee.method == "execute" and callee.receiver.type == "java.sql.Statement"
  emit sink code.SqlExecution at args[0]
}
binding urlOpen {
  query pattern callExpr where callee.method == "openConnection"
  emit sink code.UrlFetch at callee.receiver
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "java" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_receiver" || got.Pattern != "getParameter" || got.Constraint != "HttpServletRequest" {
		t.Fatalf("source receiver lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Constraint != "java.sql.Statement" {
		t.Fatalf("sink constraint lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "sink_receiver" || got.Pattern != "openConnection" {
		t.Fatalf("sink receiver lowering wrong: %+v", got)
	}
}

func TestV2CallPredicateInExpandsMappings(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.sql;
binding sqlExecMethods {
  query pattern callExpr where callee.method in ["execute", "executeQuery"] and args.any.literal contains "SELECT"
  emit sink code.SqlExecution at args[0]
  emit check core.SqlParameterization at call {
    covers endpoint { anchor: call }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "java" || len(adapter.Mappings) != 4 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	want := []struct {
		kind    string
		pattern string
	}{
		{"sink_method", "execute"},
		{"control_method", "execute"},
		{"sink_method", "executeQuery"},
		{"control_method", "executeQuery"},
	}
	for i, w := range want {
		got := adapter.Mappings[i]
		if got.Kind != w.kind || got.Pattern != w.pattern || got.ValMatches[0] != "SELECT" {
			t.Fatalf("mapping %d = %+v, want kind=%s pattern=%s val SELECT", i, got, w.kind, w.pattern)
		}
	}
}

func TestV2BindingQueryEnclosesLiteralLowersToValueMatch(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.sql;
binding sqlLiteralQuery {
  query call as c where c.callee.method == "query"
    encloses literal as lit where lit.value contains "SELECT" and not lit.raw contains "SafeQuery"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "query" {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 1 || got.ValMatches[0] != "SELECT" {
		t.Fatalf("ValMatches = %+v, want SELECT", got.ValMatches)
	}
	if len(got.ValAbsents) != 1 || got.ValAbsents[0] != "SafeQuery" {
		t.Fatalf("ValAbsents = %+v, want SafeQuery", got.ValAbsents)
	}
}

func TestV2BindingQueryRejectsUnsupportedRelationStep(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.javascript.composed;
binding bad {
  query call as c where c.callee.method == "danger" references call as other where other.callee.method == "safe"
  emit sink code.CommandExecution at args[0]
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want unsupported relation diagnostic")
	}
	if !strings.Contains(err.Error(), "query relation step references call needs native production v2 lowering") {
		t.Fatalf("error = %v, want relation diagnostic", err)
	}
}

func TestV2CallPredicateOrExpandsWithSharedConstraints(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.web;
binding requestBodies {
  query pattern callExpr where (callee.path ~= "request.json" or callee.path ~= "request.get_json") and not args.any.literal contains "safe"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "python" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	for i, want := range []string{"request.json", "request.get_json"} {
		got := adapter.Mappings[i]
		if got.Kind != "source" || got.Pattern != want || len(got.ValAbsents) != 1 || got.ValAbsents[0] != "safe" {
			t.Fatalf("mapping %d = %+v, want source %s with nval safe", i, got, want)
		}
	}
}

func TestV2CallPredicateExpansionBudget(t *testing.T) {
	longList := func(prefix string, n int) string {
		values := make([]string, 0, n)
		for i := 0; i < n; i++ {
			values = append(values, fmt.Sprintf("%q", fmt.Sprintf("%s%d", prefix, i)))
		}
		return "[" + strings.Join(values, ", ") + "]"
	}
	intList := func(n int) string {
		values := make([]string, 0, n)
		for i := 0; i < n; i++ {
			values = append(values, fmt.Sprintf("%d", i))
		}
		return "[" + strings.Join(values, ", ") + "]"
	}
	manyMethods := longList("method", maxV2CallShapeExpansion+1)
	if _, err := ParseV2Definitions(`
module bindings.javascript.generated;
binding tooManyMethods {
  query pattern callExpr where callee.method in ` + manyMethods + `
  emit sink code.CommandExecution at args[0]
}
`); err == nil || !strings.Contains(err.Error(), "query predicate expansion for callee.method produced 257 call shapes, limit 256") {
		t.Fatalf("oversized callee list error = %v", err)
	}

	seventeenMethods := longList("m", 17)
	seventeenCounts := intList(17)
	if _, err := ParseV2Definitions(`
module bindings.javascript.generated;
binding cartesian {
  query pattern callExpr where callee.method in ` + seventeenMethods + ` and args.count in ` + seventeenCounts + `
  emit sink code.CommandExecution at args[0]
}
`); err == nil || !strings.Contains(err.Error(), "query predicate expansion for and produced 289 call shapes, limit 256") {
		t.Fatalf("cartesian expansion error = %v", err)
	}
}

func TestV2PropagateValueTaintAndIdentityLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.c.migration;
binding decodeOutParam {
  query call as c where c.callee.method == "decode"
  propagate value from c.args[0] to c.args[1].pointee
}
binding parseResult {
  query pattern callExpr where callee.path ~= "parse"
  propagate value from call.result to args[0].pointee
}
binding copyTaint {
  query pattern callExpr where callee.method == "copy"
  propagate taint from args[0] to args[1].pointee
}
binding aliasOutParam {
  query pattern callExpr where callee.method == "alias"
  propagate identity from args[0] to args[1].pointee
}
binding fluentBuilder {
  query pattern callExpr where callee.method == "setOption"
  propagate receiver from callee.receiver to call.result
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "c" || len(adapter.Mappings) != 5 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "flow_method" || got.Pattern != "decode" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 {
		t.Fatalf("arg-to-out-param propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "flow_path" || got.Pattern != "parse" || !got.FlowSourceResult || got.FlowSourceArg != -1 || got.FlowDestArg != 0 {
		t.Fatalf("result-to-out-param propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "flow_method" || got.Pattern != "copy" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 {
		t.Fatalf("taint propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[3]; got.Kind != "flow_method" || got.Pattern != "alias" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 || !got.FlowIdentity {
		t.Fatalf("identity propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[4]; got.Kind != "flow_method" || got.Pattern != "setOption" || !got.FlowReceiver {
		t.Fatalf("receiver propagation wrong: %+v", got)
	}
}

func TestV2PropagateValueRejectsUnsupportedShape(t *testing.T) {
	cases := []string{
		`propagate receiver from args[0] to args[1].pointee`,
		`propagate value from args[0].field to args[1].pointee`,
		`propagate value from args[0] to call.result`,
	}
	for _, output := range cases {
		_, err := ParseV2Definitions(`
module bindings.c.migration;
binding badFlow {
  query pattern callExpr where callee.method == "decode"
  ` + output + `
}
`)
		if err == nil {
			t.Fatalf("unsupported propagation lowered without diagnostic: %s", output)
		}
	}
}

func TestV2ReceiverTypeFactLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.migration;
binding sqlOpenType {
  query pattern callExpr where callee.path ~= "sql.Open"
  emit fact runtime.ReceiverType at call.result {
    about: sql.DB
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "go" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "type" || got.Pattern != "sql.Open" || got.Concept != "sql.DB" {
		t.Fatalf("receiver type fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersToPresenceLabel(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept PublicEndpoint : fact {}
binding expressRoute {
  query pattern callExpr where callee.method == "get"
  emit fact PublicEndpoint at call
}
binding routerUse {
  query pattern callExpr where callee.path ~= "router.use"
  emit fact PublicEndpoint at call
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[1].(*BindingSet)
	if len(adapter.Mappings) != 2 {
		t.Fatalf("mappings = %d, want 2: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_method" || got.Pattern != "get" || got.Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("method fact lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "fact" || got.Pattern != "router.use" || got.Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("path fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersArgumentLocation(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept RoutePath : fact {}
binding routeArg {
  query pattern callExpr where callee.method == "get"
  emit fact RoutePath at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[1].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_method_arg" || got.Pattern != "get" || got.Concept != "bindings.javascript.facts.RoutePath" || got.ArgIndex != 0 {
		t.Fatalf("argument fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersArgsAnyLocation(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.facts;
concept RoutePart : fact {}
binding routeArgs {
  query pattern callExpr where callee.path ~= "router.route"
  emit fact RoutePart at args.any
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[1].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_arg" || got.Pattern != "router.route" || got.Concept != "bindings.javascript.facts.RoutePart" || got.ArgIndex != -1 {
		t.Fatalf("args.any fact lowering wrong: %+v", got)
	}
}

func TestV2ValueGuardLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding yamlLoad {
  query pattern callExpr where callee.path == "yaml.load" and args.any.literal contains "Loader" and not args.any.literal contains "SafeLoader"
  emit sink code.Deserialization at args[0]
}
binding escapeSql {
  query pattern callExpr where callee.method == "escape" and args.any.literal contains "sql"
  emit check core.SqlParameterization at call {
    covers path {
      from: call
      to: call
    }
  }
}
binding unsafeMarker {
  query pattern callExpr where callee.path ~= "danger" and not args.any.literal contains "safe"
  emit issue code.DangerousCall at call
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 3 {
		t.Fatalf("adapter mappings = %d, want 3: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.ValMatches[0] != "Loader" || got.ValAbsents[0] != "SafeLoader" {
		t.Fatalf("sink value guards lost: %+v", got)
	}
	if got := adapter.Mappings[1]; got.ValMatches[0] != "sql" {
		t.Fatalf("check value guard lost: %+v", got)
	}
	if got := adapter.Mappings[2]; got.ValAbsents[0] != "safe" {
		t.Fatalf("issue value absence lost: %+v", got)
	}
}

func TestV2AdvisoryNeutralizerCheckLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding startsWithGuard {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.InputValidation at call {
    advisory: true
    about: code.FilePathAccess
    covers dominates {
      from: call
      to: call
    }
  }
}
binding normpathSanitizer {
  query pattern callExpr where callee.path ~= "os.path.normpath"
  emit check core.PathCanonicalization at call {
    advisory: true
    about: code.FilePathAccess
    covers path {
      from: call
      to: call
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 2 {
		t.Fatalf("adapter mappings = %d, want 2: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "advisory_guard_method" || got.Pattern != "startswith" || got.About != "code.FilePathAccess" || got.ValMatches[0] != "os.sep" {
		t.Fatalf("advisory guard lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "advisory_sanitizer_path" || got.Pattern != "os.path.normpath" || got.About != "code.FilePathAccess" {
		t.Fatalf("advisory sanitizer lowering wrong: %+v", got)
	}
}

func TestV2AdvisoryCheckLowersToNonSuppressingMark(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding possiblePathValidation {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.PathCanonicalization at call {
    advisory: true
    about: code.FilePathAccess
    covers sameScope {
      anchor: call.scope
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "mark_method" || got.Pattern != "startswith" || got.Concept != "core.PathCanonicalization" {
		t.Fatalf("advisory check lowering wrong: %+v", got)
	}
	if !got.Advisory || got.About != "code.FilePathAccess" || got.Coverage != "sameScope" {
		t.Fatalf("advisory metadata lost: %+v", got)
	}
}

func TestV2AdvisoryCheckLowersArgumentLocation(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding possiblePathValidation {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.PathCanonicalization at args[0] {
    advisory: true
    about: code.FilePathAccess
    covers sameScope {
      anchor: call.scope
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "mark_method_arg" || got.Pattern != "startswith" || got.Concept != "core.PathCanonicalization" || got.ArgIndex != 0 {
		t.Fatalf("argument advisory check lowering wrong: %+v", got)
	}
	if !got.Advisory || got.About != "code.FilePathAccess" || got.Coverage != "sameScope" {
		t.Fatalf("argument advisory metadata lost: %+v", got)
	}
}

func TestV2GlobalCheckLowersToExplicitGlobalEvidence(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding globalHardening {
  query pattern callExpr where callee.method == "enableHardening"
  emit check core.XmlHardening at call {
    covers global {}
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "mark_method" || got.Pattern != "enableHardening" || got.Concept != "core.XmlHardening" || got.Coverage != "global" {
		t.Fatalf("global check lowering wrong: %+v", got)
	}
}

func TestV2ParamSourceLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.library.migration;
binding externalEntryInput {
  query param as param
  emit source code.ExternalEntryInput at param
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "library" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_param" || got.Concept != "code.ExternalEntryInput" {
		t.Fatalf("param source lowering wrong: %+v", got)
	}
}

func TestV2ReceiverCheckLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding relativeTo {
  query pattern callExpr where callee.method == "relative_to"
  emit check core.PathCanonicalization at callee.receiver {
    covers sameReceiver {
      anchor: callee.receiver
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "python" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "control_receiver_method" || got.Pattern != "relative_to" || got.Concept != "core.PathCanonicalization" {
		t.Fatalf("receiver check lowering wrong: %+v", got)
	}
}

func TestV2CharFilterCheckLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.ruby.migration;
binding gsubFilter {
  query pattern callExpr where callee.method == "gsub" and call.filter.global == true
  emit check threat.CharFilter at call {
    covers path {
      from: call
      to: call
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "ruby" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "filter_method" || got.Pattern != "gsub" || got.Constraint != "global" {
		t.Fatalf("char filter lowering wrong: %+v", got)
	}
}

func TestV2NonGlobalCharFilterCheckLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
binding replaceFilter {
  query pattern callExpr where callee.method == "replace"
  emit check threat.CharFilter at call {
    covers path {
      from: call
      to: call
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "filter_method" || got.Pattern != "replace" || got.Constraint != "" {
		t.Fatalf("non-global char filter lowering wrong: %+v", got)
	}
}

func TestV2UnstablePrivateGuardRejected(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.java.migration;
binding containmentCheck {
  unstable: {
    owner: "test"
    reason: "obsolete private query family should not lower"
  }
  query unstable.privateGuard as call where call.path == "analysis.guard.containment_check"
  emit check core.InputValidation at call {
    advisory: true
    about: code.FilePathAccess
    covers dominates {
      from: call
      to: call
    }
  }
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded for unstable.privateGuard")
	}
	if !strings.Contains(err.Error(), `unsupported unstable query family "unstable.privateGuard"`) {
		t.Fatalf("ParseV2Definitions error = %v", err)
	}
}

func TestV2PresenceNodeTokenAndKindLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.perl.migration;
binding cleartextChannel {
  query pattern presenceNode where node.kind == "any" and node.analysis == "text_pattern.credential_literal" and node.context.literal contains "http://" and not (node.context.literal contains "127.0")
  emit issue code.CleartextChannel at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "perl" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	m := adapter.Mappings[0]
	if m.Kind != "flag" || m.Concept != "code.CleartextChannel" || m.Flag == nil {
		t.Fatalf("presenceNode mapping wrong: %+v", m)
	}
	if m.Flag.NodeKind != "any" || len(m.Flag.Predicates) != 3 {
		t.Fatalf("presenceNode shape wrong: %+v", m.Flag)
	}
	if got := m.Flag.Predicates[0]; got.Property != "path" || got.Op != "match" || !got.Exact || got.Values[0] != "analysis.text_pattern.credential_literal" {
		t.Fatalf("analysis path predicate wrong: %+v", got)
	}
	if got := m.Flag.Predicates[2]; got.Property != "tokens" || got.Op != "contains" || !got.Negative || got.Values[0] != "literal:127.0" {
		t.Fatalf("negative context literal predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeContextFieldPrefixes(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
matcher sensitiveName {
  containsAny: ["token", "secret"]
}
binding contextFields {
  query pattern presenceNode where node.scope == "function" and node.context.language == "javascript" and containsAny(node.context.callPath, ["parseOut", "crypto.timingSafeEqual"]) and node.context.selector contains "data.x-csrf-token" and node.context.identifier is sensitiveName and node.context.advisoryCwe == "CWE-444" and node.context.decoratorPath contains "require_POST" and containsAny(node.context.assignItem, ["viewer_scopes:CONFIG_READ", "guest_scopes:CONFIG_READ"])
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	flag := decls[0].(*BindingSet).Mappings[0].Flag
	if flag.Scope != "function" || len(flag.Predicates) != 7 {
		t.Fatalf("flag predicates wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "lang=javascript" {
		t.Fatalf("language predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "call_path:parseOut" || got.Values[1] != "call_path:crypto.timingSafeEqual" {
		t.Fatalf("callPath predicate wrong: %+v", got)
	}
	if got := flag.Predicates[2]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "selector:data.x-csrf-token" {
		t.Fatalf("selector predicate wrong: %+v", got)
	}
	if got := flag.Predicates[3]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "identifier:token" || got.Values[1] != "identifier:secret" {
		t.Fatalf("matcher predicate wrong: %+v", got)
	}
	if got := flag.Predicates[4]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "advisory_cwe=CWE-444" {
		t.Fatalf("advisory CWE predicate wrong: %+v", got)
	}
	if got := flag.Predicates[5]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "decorator_path:require_POST" {
		t.Fatalf("decorator path predicate wrong: %+v", got)
	}
	if got := flag.Predicates[6]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "assign_item:viewer_scopes:CONFIG_READ" || got.Values[1] != "assign_item:guest_scopes:CONFIG_READ" {
		t.Fatalf("assign item predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodePatternLowersToFlag(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.bash.crypto;
binding weakRandom {
  query pattern presenceNode where node.path ~= "RANDOM"
  emit issue code.WeakRandomValue at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "bash" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	m := adapter.Mappings[0]
	if m.Kind != "flag" || m.Concept != "code.WeakRandomValue" || m.Flag == nil {
		t.Fatalf("presenceNode mapping wrong: %+v", m)
	}
	if m.Flag.NodeKind != "any" || len(m.Flag.Predicates) != 1 {
		t.Fatalf("presenceNode flag wrong: %+v", m.Flag)
	}
	if got := m.Flag.Predicates[0]; got.Subject != "node" || got.Property != "path" || got.Op != "match" || got.Exact || got.Values[0] != "RANDOM" {
		t.Fatalf("presenceNode path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeExactPathLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.dart.crypto;
binding weakRandom {
  query pattern presenceNode where node.path == "Random"
  emit issue code.WeakRandomValue at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	flag := decls[0].(*BindingSet).Mappings[0].Flag
	if flag == nil || len(flag.Predicates) != 1 {
		t.Fatalf("presenceNode flag wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "path" || got.Op != "match" || !got.Exact || got.Values[0] != "Random" {
		t.Fatalf("presenceNode exact path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeMethodPackagesAndMultipleEmits(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.ruby.logging;
binding logWrite {
  requires {
    dependency("rails")
  }
  query pattern presenceNode where node.method == "warn"
  emit issue code.LogWrite at node
  emit sink code.LogOutput at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "ruby" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	for _, m := range adapter.Mappings {
		if m.Kind != "flag" || m.Flag == nil || len(m.Flag.Predicates) != 1 || len(m.Packages) != 1 || m.Packages[0] != "rails" {
			t.Fatalf("presenceNode mapping wrong: %+v", m)
		}
		if got := m.Flag.Predicates[0]; got.Subject != "node" || got.Property != "method" || got.Op != "equals" || got.Values[0] != "warn" {
			t.Fatalf("presenceNode method predicate wrong: %+v", got)
		}
	}
}

func TestV2PresenceNodePreservesAdvisoryCheckMetadata(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.go.memory;
binding memoryBounds {
  query pattern presenceNode where node.kind == "any" and node.path ~= "__binop.ne"
  emit check core.MemoryBoundsCheck at node {
    advisory: true
    about: code.BufferAccess
    covers sameScope {
      anchor: node
    }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	m := decls[0].(*BindingSet).Mappings[0]
	if m.Kind != "flag" || !m.Advisory || m.About != "code.BufferAccess" || m.Coverage != "sameScope" {
		t.Fatalf("presenceNode metadata not preserved: %+v", m)
	}
}

func TestV2ImportedPresenceNodePatternLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.lua.crypto;
uses patterns.core.presenceNode;
binding weakHash {
  query pattern presenceNode where node.path ~= "ngx.md5"
  emit issue code.WeakHash at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	flag := decls[0].(*BindingSet).Mappings[0].Flag
	if flag == nil || len(flag.Predicates) != 1 {
		t.Fatalf("presenceNode import flag wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "path" || got.Values[0] != "ngx.md5" {
		t.Fatalf("imported presenceNode path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeRejectsUnknownPredicates(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.javascript.web;
binding unsupported {
  query pattern presenceNode where node.receiver == "req"
  emit issue code.SecretValue at node
}
`)
	if err == nil {
		t.Fatal("presenceNode lowered unsupported predicate")
	}
	if !strings.Contains(err.Error(), `unsupported predicate field "receiver"`) {
		t.Fatalf("presenceNode error = %v", err)
	}
}

func TestV2PresenceNodeOperandAndPseudoSubjectLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
matcher csrfHeaderName {
  equalsAny: ["x-csrf-token", "csrf-token"]
}
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and node.op in ["==", "==="] and not (containsAny(node.context.scopeCall, ["scmp", "timingSafeEqual"])) and operand(node, where: operand.path ~= "__binop.operand" and operand.identifier is secretTokenName and operand.key is csrfHeaderName)
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	flag := adapter.Mappings[0].Flag
	if flag == nil || flag.NodeKind != "binop" || len(flag.Operands) != 1 {
		t.Fatalf("flag lowering wrong: %+v", flag)
	}
	if got := flag.Predicates[1]; got.Subject != "scope_call" || got.Property != "any" || got.Op != "contains_any" || !got.Negative {
		t.Fatalf("scope_call predicate wrong: %+v", got)
	}
	if got := flag.Operands[0].Predicates[1]; got.Subject != "operand" || got.Property != "identifier" || got.Op != "contains_any" {
		t.Fatalf("operand predicate wrong: %+v", got)
	}
	if got := flag.Operands[0].Predicates[2]; got.Subject != "operand" || got.Property != "key" || got.Op != "equals_any" || got.Values[0] != "x-csrf-token" {
		t.Fatalf("operand matcher equality predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeMatcherImportsUseAliasesAndRejectUnimportedSimpleNames(t *testing.T) {
	decls, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "patterns/javascript/matchers.vyql", Source: `
module patterns.javascript.matchers;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`},
		{Name: "bindings/javascript/migration.vyql", Source: `
module bindings.javascript.migration;
uses patterns.javascript.matchers.secretTokenName as SecretName;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is SecretName)
  emit issue code.SecretComparisonReview at node
}
`},
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSources: %v", err)
	}
	flag := decls[0].(*BindingSet).Mappings[0].Flag
	if got := flag.Operands[0].Predicates[0]; got.Subject != "operand" || got.Property != "identifier" || got.Op != "contains_any" || got.Values[0] != "token" {
		t.Fatalf("imported matcher predicate wrong: %+v", got)
	}

	_, err = parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "patterns/javascript/matchers.vyql", Source: `
module patterns.javascript.matchers;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`},
		{Name: "bindings/javascript/migration.vyql", Source: `
module bindings.javascript.migration;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is secretTokenName)
  emit issue code.SecretComparisonReview at node
}
`},
	})
	if err == nil || !strings.Contains(err.Error(), `unknown matcher "secretTokenName"`) {
		t.Fatalf("ParseV2DefinitionSources error = %v, want unknown matcher diagnostic", err)
	}
}

func TestV2PresenceNodeRejectsRegexMatcherInvocationUntilScannerSupport(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
matcher riskyName {
  matches: "token|secret"
}
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is riskyName)
  emit issue code.SecretComparisonReview at node
}
`)
	if err == nil || !strings.Contains(err.Error(), "regex matcher invocation requires reviewed scanner support") {
		t.Fatalf("ParseV2Definitions error = %v, want regex matcher diagnostic", err)
	}
}

func TestV2PresenceNodeContextScopeCallAndFlowToLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and not (containsAny(node.context.inScopeCall, [scmp])) and containsAny(node.flow_to.op, [return])
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	flag := decls[0].(*BindingSet).Mappings[0].Flag
	if got := flag.Predicates[0]; got.Subject != "scope_call" || got.Property != "any" || !got.Negative {
		t.Fatalf("scope_call predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Subject != "flow_to" || got.Property != "op" {
		t.Fatalf("flow_to predicate wrong: %+v", got)
	}
}

func TestV2RuleWhereLowering(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.migrated;
rule ToxicWorkloadExposure {
  issue identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and grant(w, identity.AdminPrivilege)
}
rule PublicSensitiveDatabase {
  reach cloud.Internet -> cloud.Database
  where holdsAssetKind(cloud.Database, [data.Pii])
}
rule CryptoMiningEgress {
  query concept as c where c.concept == runtime.Connection
    references concept as dst where dst.concept == threat.MiningPool and dst.id == c.dst
    select c
}
rule WorkloadDrift {
  issue runtime.Process as p
  where p.image not in [nginx, redis, postgres]
}
rule Confidence {
  issue code.Review as r
  where r.confidence == high
}
`)
	if len(decls) != 5 {
		t.Fatalf("decls = %d, want 5", len(decls))
	}
	toxic := decls[0].(*Rule)
	and, ok := toxic.Clauses[0].Where.(And)
	if !ok || len(and.Parts) != 2 {
		t.Fatalf("toxic where = %#v, want two-part And", toxic.Clauses[0].Where)
	}
	if sc, ok := and.Parts[0].(SolverCall); !ok || sc.Verb != "reach" || len(sc.Args) != 2 {
		t.Fatalf("first toxic where part = %#v, want reach solver call", and.Parts[0])
	}
	asset := decls[1].(*Rule)
	if got, ok := asset.Clauses[0].Where.(HoldsAssetKind); !ok || got.Ref.String() != "cloud.Database" || len(got.Kinds) != 1 || got.Kinds[0] != "data.Pii" {
		t.Fatalf("asset where = %#v, want HoldsAssetKind", asset.Clauses[0].Where)
	}
	irRule := decls[2].(*Rule).Body.(*MatchStmt)
	if irRule.TargetKind != "concept" || irRule.Concept != "runtime.Connection" || irRule.Binding != "c" || irRule.Relation != "references" || irRule.RelationProp != "dst" || irRule.RelatedConcept != "threat.MiningPool" {
		t.Fatalf("semantic reference query lowering wrong: %+v", irRule)
	}
	drift := decls[3].(*Rule)
	if got, ok := drift.Clauses[0].Where.(NotIn); !ok || got.Ref.String() != "p.image" || !got.Negate || len(got.Values) != 3 {
		t.Fatalf("drift where = %#v, want NotIn", drift.Clauses[0].Where)
	}
	conf := decls[4].(*Rule)
	if got, ok := conf.Clauses[0].Where.(Cmp); !ok || got.Ref.String() != "r.confidence" || got.Op != "==" || got.Value != "high" {
		t.Fatalf("confidence where = %#v, want Cmp", conf.Clauses[0].Where)
	}
}

func TestV2RuleConfidenceClauseLowersToScannerIRFloor(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`)
	rule := decls[0].(*Rule)
	if got := rule.Meta["confidence_floor"]; got != "high" {
		t.Fatalf("confidence floor = %#v, want high", got)
	}
}

func TestV2RuleConfidenceClauseRequiresLoadedConfidencePolicy(t *testing.T) {
	_, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "policies/empty.vyql", Source: `module policies.empty;`},
		{Name: "rules/review.vyql", Source: `module rules.review;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`},
	})
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataRequiresLoadedConfidencePolicy(t *testing.T) {
	_, err := parseV2DefinitionSourcesForTest([]V2DefinitionSource{
		{Name: "policies/empty.vyql", Source: `module policies.empty;`},
		{Name: "rules/review.vyql", Source: `module rules.review;
rule HighConfidenceReview {
  meta { confidenceFloor: high }
  issue code.Review as r
}
`},
	})
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataLowersToScannerIRFloor(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.review;
rule HighConfidenceReview {
  meta { confidenceFloor: high }
  issue code.Review as r
}
`)
	rule := decls[0].(*Rule)
	if got := rule.Meta["confidence_floor"]; got != "high" {
		t.Fatalf("confidence floor = %#v, want high", got)
	}
}

func TestV2RawSemanticQueryLowering(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.migrated;
rule FileToctou {
  query concept as first where first.concept == code.FileCheck reaches concept as second where second.concept == code.FileUse select second
}

rule LateralReachToSecretStore {
  query principal as actor where actor.concept == cloud.ExternalPrincipal
    reaches asset as store where store.concept == cloud.SecretStore
    select store
}

rule InvalidRefundTransition {
  query state as t where t.machine == Order and t.from == "*" and t.to == Refunded select t
}

rule StateReachability {
  query state as start where start.concept == workflow.Open
    reaches state as done where done.concept == workflow.Closed
    select done
}

rule ReachableVulnerableDependency {
  query concept as p where p.concept == sbom.VulnerableDependency
    labeledAs concept as reachable where reachable.concept == sbom.ReachableSymbol
    select p
}

rule CryptoMiningEgress {
  query concept as c where c.concept == runtime.Connection
    references concept as dst where dst.concept == threat.MiningPool and dst.id == c.dst
    select c
}
`)
	order := decls[0].(*Rule).Body.(*OrderStmt)
	if order.First.Concept != "code.FileCheck" || order.First.Binding != "first" || order.Second.Concept != "code.FileUse" || order.Second.Binding != "second" {
		t.Fatalf("order lowering wrong: %+v", order)
	}
	reach := decls[1].(*Rule).Body.(*OrderStmt)
	if reach.First.Concept != "cloud.ExternalPrincipal" || reach.First.Binding != "actor" || reach.Second.Concept != "cloud.SecretStore" || reach.Second.Binding != "store" {
		t.Fatalf("semantic reach lowering wrong: %+v", reach)
	}
	transition := decls[2].(*Rule).Body.(*MatchStmt)
	if transition.TargetKind != "transition" || transition.Binding != "t" || transition.Machine != "Order" || transition.FromState != "*" || transition.ToState != "Refunded" {
		t.Fatalf("transition lowering wrong: %+v", transition)
	}
	stateReach := decls[3].(*Rule).Body.(*OrderStmt)
	if stateReach.First.Concept != "workflow.Open" || stateReach.First.Binding != "start" || stateReach.Second.Concept != "workflow.Closed" || stateReach.Second.Binding != "done" {
		t.Fatalf("state reach lowering wrong: %+v", stateReach)
	}
	labeled := decls[4].(*Rule).Body.(*MatchStmt)
	if labeled.TargetKind != "concept" || labeled.Concept != "sbom.VulnerableDependency" || labeled.Binding != "p" || labeled.Relation != "labeledAs" || labeled.RelatedConcept != "sbom.ReachableSymbol" {
		t.Fatalf("labeledAs lowering wrong: %+v", labeled)
	}
	reference := decls[5].(*Rule).Body.(*MatchStmt)
	if reference.TargetKind != "concept" || reference.Concept != "runtime.Connection" || reference.Binding != "c" || reference.Relation != "references" || reference.RelationProp != "dst" || reference.RelatedConcept != "threat.MiningPool" {
		t.Fatalf("references lowering wrong: %+v", reference)
	}
}

func TestV2LoweringRejectsUnsupportedBindingShape(t *testing.T) {
	prog, err := ParseV2(`
module bindings.javascript.express;
binding unsupported {
  query pattern callExpr where args.count >= 2
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if _, err := lowerV2ProgramToDeclarations(prog); err == nil || !strings.Contains(err.Error(), "needs a callee.method/path predicate") {
		t.Fatalf("unsupported binding query error = %v, want callee predicate diagnostic", err)
	}
}

func TestV2LoweringSupportsArgsCountBindingPredicate(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.express;
binding executeWithParams {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	ad := decls[0].(*BindingSet)
	if len(ad.Mappings) != 1 {
		t.Fatalf("mappings = %#v, want one", ad.Mappings)
	}
	got := ad.Mappings[0]
	if got.Kind != "control_method_arg" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" || got.ArgIndex != 0 ||
		!got.ArgCountSet || got.ArgCountMin != 2 || got.ArgCountMax != -1 {
		t.Fatalf("args.count mapping = %#v, want arity-gated control_method_arg", got)
	}
}

func TestV2LoweringExpandsArgsCountInList(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.express;
binding executeWithParamCounts {
  query pattern callExpr where callee.method == "execute" and args.count in [1, 3]
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	mappings := decls[0].(*BindingSet).Mappings
	if len(mappings) != 2 {
		t.Fatalf("mappings = %#v, want two exact arity mappings", mappings)
	}
	got := []int{mappings[0].ArgCountMin, mappings[1].ArgCountMin}
	if got[0] != 1 || got[1] != 3 ||
		mappings[0].ArgCountMax != 1 || mappings[1].ArgCountMax != 3 {
		t.Fatalf("args.count in list mappings = %#v, want exact 1 and 3", mappings)
	}
}

func TestV2ConcreteCoverageChecksLowerWithExplicitCoverageMode(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.java.xml;
binding endpointHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers endpoint { anchor: call }
  }
}
binding sameReceiverHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers sameReceiver { anchor: callee.receiver }
  }
}
binding sameScopeHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers sameScope { anchor: call.scope }
  }
}
binding dominatingHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers dominates { from: call to: candidate }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*BindingSet)
	if len(adapter.Mappings) != 4 {
		t.Fatalf("adapter mappings = %d, want 4: %+v", len(adapter.Mappings), adapter)
	}
	want := map[string]bool{"endpoint": true, "sameReceiver": true, "sameScope": true, "dominates": true}
	for _, got := range adapter.Mappings {
		if got.Kind != "control_method" || got.Pattern != "setFeature" || got.Concept != "core.XmlHardening" {
			t.Fatalf("coverage check lowering wrong: %+v", got)
		}
		if !want[got.Coverage] {
			t.Fatalf("unexpected or missing coverage mode in mapping: %+v", got)
		}
		switch got.Coverage {
		case "endpoint":
			if got.CoverageDetail["anchor"] != "call" {
				t.Fatalf("endpoint coverage detail = %#v, want anchor call", got.CoverageDetail)
			}
		case "sameReceiver":
			if got.CoverageDetail["anchor"] != "callee.receiver" {
				t.Fatalf("sameReceiver coverage detail = %#v, want anchor callee.receiver", got.CoverageDetail)
			}
		case "sameScope":
			if got.CoverageDetail["anchor"] != "call.scope" {
				t.Fatalf("sameScope coverage detail = %#v, want anchor call.scope", got.CoverageDetail)
			}
		case "dominates":
			if got.CoverageDetail["from"] != "call" || got.CoverageDetail["to"] != "candidate" {
				t.Fatalf("dominates coverage detail = %#v, want from call/to candidate", got.CoverageDetail)
			}
		}
		delete(want, got.Coverage)
	}
	if len(want) != 0 {
		t.Fatalf("missing coverage modes: %#v", want)
	}
}

func TestV2RuleSupportedCoveredByModesLowerToScannerIRClauseKinds(t *testing.T) {
	decls := parseIRFiles(t, `
module rules.xml;
rule UnhardenedXmlParser {
  issue code.XmlParserCreate as parser
  unless parser.endpoint coveredBy core.XmlHardening
}
rule SameReceiverParser {
  issue code.XmlParserCreate as parser
  unless parser.sameReceiver coveredBy core.XmlHardening
}
rule SameScopeParser {
  issue code.XmlParserCreate as parser
  unless parser.sameScope coveredBy core.XmlHardening
}
rule GlobalParser {
  issue code.XmlParserCreate as parser
  unless parser.global coveredBy core.XmlHardening
}
rule DominatedParser {
  issue code.XmlParserCreate as parser
  unless parser.dominates coveredBy core.XmlHardening
}
`, `
module rules.lifecycle;
rule LockNotReleased {
  issue code.LockAcquire as l
  unless l.postDominates coveredBy core.LockRelease
}
`)
	for _, decl := range decls {
		rule := decl.(*Rule)
		if len(rule.Clauses) != 1 {
			t.Fatalf("rule clauses wrong: %+v", rule)
		}
		switch rule.Name {
		case "UnhardenedXmlParser":
			if _, ok := rule.Clauses[0].Unless.(EndpointCoveredBy); !ok {
				t.Fatalf("endpoint coveredBy did not lower to EndpointCoveredBy: %+v", rule.Clauses[0])
			}
		case "SameReceiverParser":
			if _, ok := rule.Clauses[0].Unless.(SameReceiverCoveredBy); !ok {
				t.Fatalf("sameReceiver coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "SameScopeParser":
			if _, ok := rule.Clauses[0].Unless.(SameScopeCoveredBy); !ok {
				t.Fatalf("sameScope coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "GlobalParser":
			if _, ok := rule.Clauses[0].Unless.(GlobalCoveredBy); !ok {
				t.Fatalf("global coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "DominatedParser":
			if _, ok := rule.Clauses[0].Unless.(DominatesCoveredBy); !ok {
				t.Fatalf("dominates coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		case "LockNotReleased":
			if _, ok := rule.Clauses[0].Unless.(PostDominatesCoveredBy); !ok {
				t.Fatalf("postDominates coveredBy did not preserve coverage mode: %+v", rule.Clauses[0])
			}
		default:
			t.Fatalf("unexpected rule %s", rule.Name)
		}
	}
}

func TestV2LoweringPreservesRequiredProfileClause(t *testing.T) {
	decls := parseIRFiles(t, `
module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  require profile web
}
`)
	rule := decls[0].(*Rule)
	got, ok := rule.Meta["required_profiles"].([]string)
	if !ok || len(got) != 1 || got[0] != "web" {
		t.Fatalf("required profile metadata = %#v, want [web]", rule.Meta["required_profiles"])
	}
}

func TestParseV2RejectsUnknownConfidenceLevel(t *testing.T) {
	_, err := ParseV2(`
module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  with confidence >= certain
}
`)
	if err == nil || !strings.Contains(err.Error(), "unknown confidence level") {
		t.Fatalf("ParseV2 error = %v, want unknown confidence level", err)
	}
}

func TestV2AdapterMetadataLowersToScannerIRAdapterMeta(t *testing.T) {
	decls := parseIRFiles(t, `
module bindings.textpattern.migration;
pattern adapterMetadata {
  adapter: {
    name: "textpattern"
    meta: {
      cross_language: true
      text_pattern_event: "analysis.text_pattern.credential_literal"
      text_pattern_extensions: [".go", ".py"]
    }
  }
}
`)
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want metadata adapter only", len(decls))
	}
	ad := decls[0].(*BindingSet)
	if ad.Name != "textpattern" || len(ad.Mappings) != 0 {
		t.Fatalf("adapter metadata decl wrong: %+v", ad)
	}
	if ad.Meta["cross_language"] != true || ad.Meta["text_pattern_event"] != "analysis.text_pattern.credential_literal" {
		t.Fatalf("adapter metadata missing: %+v", ad.Meta)
	}
	if got, ok := ad.Meta["text_pattern_extensions"].([]string); !ok || len(got) != 2 || got[1] != ".py" {
		t.Fatalf("adapter metadata list wrong: %#v", ad.Meta["text_pattern_extensions"])
	}
}

func TestV2UnstableAdapterMetadataRejected(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.textpattern.migration;
pattern adapterMetadata {
  unstable: {
    owner: "test"
    reason: "unstable adapter metadata"
    adapter: "textpattern"
    meta: {
      cross_language: true
    }
  }
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions accepted unstable adapter metadata")
	}
	if !strings.Contains(err.Error(), "unstable adapter metadata must use stable adapter item") {
		t.Fatalf("ParseV2Definitions error = %v", err)
	}
}

func TestV2ConceptFieldsLowerToScannerIRFieldNames(t *testing.T) {
	decls := parseIRFiles(t, `
module code;
concept SqlExecution : sink {
  vulnerableTo: [injection.SqlInjection]
  reviewCondition: "inspect query construction"
}
`)
	c := decls[0].(*ConceptDecl)
	if _, ok := c.Fields["vulnerable_to"]; !ok {
		t.Fatalf("vulnerableTo did not lower to vulnerable_to: %+v", c.Fields)
	}
	if c.Fields["review_condition"] != "inspect query construction" {
		t.Fatalf("reviewCondition did not lower: %+v", c.Fields)
	}
}

func TestV2ScannerIRSupportsGrantRulesAndContextFactConcepts(t *testing.T) {
	decls := parseIRFiles(t, `
module custom;
concept External : principal {}
concept Elevated : privilege {
  grantMinLevel: ADMIN
}
concept PublicEdgeObservation : fact {
  contextConfirmFlagValue: true
}
`, `
module rules.identity;
rule ExternalGrant {
  grant custom.External -> custom.Elevated
}
`)
	var sawFact, sawGrant bool
	for _, decl := range decls {
		switch d := decl.(type) {
		case *ConceptDecl:
			if d.QualifiedName() == "custom.PublicEdgeObservation" {
				sawFact = true
				if d.Kind != "fact" || d.Fields["context_confirm_flag_value"] != true {
					t.Fatalf("context fact concept lowering wrong: %+v", d)
				}
			}
		case *Rule:
			if d.QualifiedName() == "rules.identity.ExternalGrant" {
				body, ok := d.Body.(*FlowStmt)
				if !ok || body.Verb != "grant" {
					t.Fatalf("grant rule lowering wrong: %+v", d.Body)
				}
				sawGrant = true
			}
		}
	}
	if !sawFact || !sawGrant {
		t.Fatalf("missing context fact=%v grant=%v in decls: %+v", sawFact, sawGrant, decls)
	}
}

func TestV2ScannerIRRejectsAuthoredAssumeRuleVerb(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.identity;
rule ExternalAssume {
  assume custom.External -> custom.Elevated
}
`)
	if err == nil || !strings.Contains(err.Error(), `unknown v2 rule verb "assume"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored assume rejection", err)
	}
}

func TestV2ScannerIRRejectsAuthoredAssumeSolverCall(t *testing.T) {
	_, err := parseV2DefinitionsForTest(`
module rules.identity;
rule ExternalAssume {
  issue custom.Marker as m
  where assume(custom.External, custom.Elevated)
}
`)
	if err == nil || !strings.Contains(err.Error(), `unsupported call "assume"`) {
		t.Fatalf("ParseV2Definitions error = %v, want authored assume solver rejection", err)
	}
}

func TestLowerV2DefinitionSourcesRejectsParsedGoOwnedMechanic(t *testing.T) {
	_, err := LowerV2DefinitionSources([]V2Source{{
		Name: "mechanics/bad.vyql",
		Program: &V2Program{
			Module: "mechanics.bad",
			Decls: []V2Decl{
				&V2MechanicDecl{Kind: "ruleVerb", Name: "assume"},
			},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "mechanic ruleVerb.assume is Go-owned") {
		t.Fatalf("LowerV2DefinitionSources error = %v, want Go-owned mechanic diagnostic", err)
	}
}

const v2CorePoliciesForLoweringTest = `
module policies.core;
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
policy confidence default {
  values: [low, medium, high]
  order: [low, medium, high]
  aggregate: min(rule, endpoints, propagation, requirements)
  softRequirement missing: downgrade(1)
  softRequirement unknown: downgrade(1) annotate("uninspected evidence")
  softRequirement conflicting: downgrade(1) annotate("conflicting evidence")
  softRequirement satisfied: keep
}
`

func parseV2DefinitionsWithCoreMechanics(t *testing.T, src string) []Decl {
	t.Helper()
	return parseIRFiles(t, src)
}

func parseV2DefinitionsForTest(src string) ([]Decl, error) {
	return parseV2DefinitionSourcesForTest(V2DefinitionSourcesFromText("test.vyql", src))
}

func parseV2DefinitionSourcesForTest(sources []V2DefinitionSource) ([]Decl, error) {
	allSources := make([]V2DefinitionSource, 0, len(sources)+1)
	keep := make([]bool, 0, len(sources)+1)
	hasPolicies := false
	for _, source := range sources {
		hasPolicies = hasPolicies || strings.HasPrefix(source.Name, "policies/")
	}
	if !hasPolicies {
		allSources = append(allSources, V2DefinitionSource{Name: "policies/core.vyql", Source: v2CorePoliciesForLoweringTest})
		keep = append(keep, false)
	}
	allSources = append(allSources, sources...)
	for range sources {
		keep = append(keep, true)
	}
	parsed := make([]V2Source, 0, len(allSources))
	for _, source := range allSources {
		prog, err := ParseV2(source.Source)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, V2Source{Name: source.Name, Program: prog})
	}
	decls, err := lowerV2DefinitionSourcesSelected(parsed, keep)
	if err != nil {
		return nil, err
	}
	out := decls[:0]
	for _, decl := range decls {
		switch decl.(type) {
		case *V2MechanicDecl, *V2PolicyDecl:
			continue
		default:
			out = append(out, decl)
		}
	}
	return out, nil
}

func parseIRFiles(t *testing.T, srcs ...string) []Decl {
	t.Helper()
	sources := []V2Source{parseV2SourceForLoweringTest(t, "policies/core.vyql", v2CorePoliciesForLoweringTest)}
	keep := []bool{false}
	for i, src := range srcs {
		for _, raw := range V2DefinitionSourcesFromText("test", src) {
			source := parseV2SourceForLoweringTest(t, raw.Name, raw.Source)
			source.Name = "test/module" + string(rune('A'+i)) + "/" + raw.Name
			sources = append(sources, source)
			keep = append(keep, true)
		}
	}
	decls, err := lowerV2DefinitionSourcesSelected(sources, keep)
	if err != nil {
		t.Fatalf("lowerV2DefinitionSourcesSelected: %v", err)
	}
	return decls
}

func parseV2SourceForLoweringTest(t *testing.T, name, src string) V2Source {
	t.Helper()
	prog, err := ParseV2(src)
	if err != nil {
		t.Fatalf("ParseV2 %s: %v", name, err)
	}
	return V2Source{Name: name, Program: prog}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringListFieldEqual(got any, want []string) bool {
	items, ok := got.([]string)
	if !ok || len(items) != len(want) {
		return false
	}
	for i := range items {
		if items[i] != want[i] {
			return false
		}
	}
	return true
}

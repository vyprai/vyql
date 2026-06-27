package parser

import (
	"strings"
	"testing"
)

func TestV2LoweringToRuntimeDecls(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
	var adapter *AdapterDecl
	var rule *Rule
	var concept *ConceptDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
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
	if got := adapter.Mappings[1]; got.Kind != "source" || got.Pattern != "request.json" || got.Concept != "code.HttpInput" {
		t.Fatalf("source lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "control_method" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" {
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

func TestV2LoweringUsesAuthoredRuleVerbSolver(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module mechanics.test;
mechanic ruleVerb flow {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy]
}

module rules.test;
rule CustomFlow {
  flow code.HttpInput -> code.SqlExecution
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	var rule *Rule
	for _, d := range decls {
		if r, ok := d.(*Rule); ok {
			rule = r
		}
	}
	if rule == nil {
		t.Fatalf("lowered decls missing rule: %+v", decls)
	}
	body, ok := rule.Body.(*FlowStmt)
	if !ok || body.Verb != "taint" {
		t.Fatalf("authored solver did not drive runtime flow verb: %+v", rule.Body)
	}
}

func TestV2CorpusLoweringUsesMechanicsAcrossSources(t *testing.T) {
	mechanics, err := ParseV2(`
module mechanics.test;
mechanic ruleVerb issue {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy]
}
`)
	if err != nil {
		t.Fatalf("ParseV2 mechanics: %v", err)
	}
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
		{Name: "mechanics.vyql", Program: mechanics},
		{Name: "rules.vyql", Program: rules},
	})
	if err == nil || !strings.Contains(err.Error(), "rules.vyql") {
		t.Fatalf("LowerV2DefinitionSources error = %v, want contextual lowering failure", err)
	}
}

func TestSplitV2ModuleChunks(t *testing.T) {
	if got := splitV2ModuleChunks("module one;\nconcept A : source {}\n"); got != nil {
		t.Fatalf("single module split = %#v, want nil", got)
	}
	src := "module one;\nconcept A : source {}\n\n  module two;\nconcept B : sink {}\n"
	got := splitV2ModuleChunks(src)
	if len(got) != 2 {
		t.Fatalf("split chunks = %d, want 2: %#v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "module one;") || !strings.HasPrefix(got[1], "module two;") {
		t.Fatalf("split chunks wrong: %#v", got)
	}
}

func TestParseV2DefinitionSourcesValidatesCorpus(t *testing.T) {
	_, err := ParseV2DefinitionSources([]V2DefinitionSource{
		{Name: "mechanics.vyql", Source: `
module mechanics.test;
mechanic ruleVerb issue {
  solver: fact.exists
  fromKinds: [issue]
  allowedClauses: [coveredBy]
}
mechanic coverage path {
  capability: coverage.path
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
  targetParts: [path]
}
mechanic coverage endpoint {
  capability: coverage.endpoint
  coversWhen: solver.sameEndpoint(check.anchor, candidate.endpoint)
  targetParts: [endpoint]
}
`},
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
		{Name: "mechanics.vyql", Source: `
module mechanics.test;
mechanic ruleVerb flow {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [coveredBy]
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
  flow code.HttpInput -> code.SqlExecution
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

func TestV2RuntimePreservesMechanicsAndPolicies(t *testing.T) {
	decls, err := ParseV2Definitions(`
module mechanics.sast;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy, confidence]
}
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
	if len(decls) != 2 {
		t.Fatalf("decls = %d, want mechanic + policy: %+v", len(decls), decls)
	}
	mech, ok := decls[0].(*V2MechanicDecl)
	if !ok {
		t.Fatalf("decl[0] = %T, want *V2MechanicDecl", decls[0])
	}
	if mech.Module != "mechanics.sast" || mech.Kind != "ruleVerb" || mech.Name != "taint" {
		t.Fatalf("mechanic identity wrong: %+v", mech)
	}
	if got := mech.QualifiedName(); got != "mechanics.sast.mechanic:ruleVerb:taint" {
		t.Fatalf("mechanic qualified name = %q", got)
	}
	policy, ok := decls[1].(*V2PolicyDecl)
	if !ok {
		t.Fatalf("decl[1] = %T, want *V2PolicyDecl", decls[1])
	}
	if policy.Module != "mechanics.sast" || policy.Kind != "resultIdentity" || policy.Name != "default" {
		t.Fatalf("policy identity wrong: %+v", policy)
	}
	if got := policy.QualifiedName(); got != "mechanics.sast.policy:resultIdentity:default" {
		t.Fatalf("policy qualified name = %q", got)
	}
}

func TestParseV2DefinitionSourcesSelectedPreservesSelectedMechanicsAndPolicies(t *testing.T) {
	decls, err := ParseV2DefinitionSourcesSelected([]V2DefinitionSource{
		{Name: "mechanics.vyql", Source: `
module mechanics.sast;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy, confidence]
}
`},
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
		return src.Name == "mechanics.vyql" || src.Name == "policy.vyql"
	})
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("decls = %d, want selected mechanic + policy: %+v", len(decls), decls)
	}
	if _, ok := decls[0].(*V2MechanicDecl); !ok {
		t.Fatalf("decl[0] = %T, want *V2MechanicDecl", decls[0])
	}
	if _, ok := decls[1].(*V2PolicyDecl); !ok {
		t.Fatalf("decl[1] = %T, want *V2PolicyDecl", decls[1])
	}
}

func TestV2LoweringUsesLocalPatternWhere(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
	adapter := decls[0].(*AdapterDecl)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "req.body" || got.Concept != "code.HttpInput" {
		t.Fatalf("pattern where did not lower to source mapping: %+v", got)
	}
}

func TestV2LoweringRewritesPatternBindAliases(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
	adapter := decls[0].(*AdapterDecl)
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
	decls := parseRuntimeFiles(t, `
module bindings.javascript.express;
uses patterns.javascript.callExpr as jsCall;
binding requestBody {
  query pattern jsCall where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`)
	adapter := decls[0].(*AdapterDecl)
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

func TestV2LoweringResolvesUsesAliasesToRuntimeConcepts(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
  where has(sink, Guard) and sink is Exec
}
`)
	var adapter *AdapterDecl
	var rule *Rule
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
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
	where, ok := rule.Clauses[1].Where.(And)
	if !ok || len(where.Parts) != 2 {
		t.Fatalf("where did not lower to two-part conjunction: %+v", rule.Clauses[1])
	}
	if has, ok := where.Parts[0].(Has); !ok || has.Concept != "core.SqlParameterization" {
		t.Fatalf("alias in has() did not lower: %+v", where.Parts[0])
	}
	if is, ok := where.Parts[1].(Is); !ok || is.Concept != "code.SqlExecution" {
		t.Fatalf("alias in is did not lower: %+v", where.Parts[1])
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

func TestV2LoweringRequiresLoadedCoverageMechanicForCoveredBy(t *testing.T) {
	_, err := ParseV2Definitions(`
module mechanics.test;
mechanic ruleVerb issue { solver: fact.exists }

module rules.review;
rule GuardedIssue {
  issue code.Problem as p
  unless p.path coveredBy core.Guard
}
`)
	if err == nil || !strings.Contains(err.Error(), `no loaded mechanic coverage "path"`) {
		t.Fatalf("ParseV2Definitions error = %v, want missing coverage mechanic", err)
	}
}

func TestV2LoweringRequiresLoadedCoverageMechanicForCheckEmission(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.python.dbapi;
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute"
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	if err == nil || !strings.Contains(err.Error(), `no loaded mechanic coverage "path"`) {
		t.Fatalf("ParseV2Definitions error = %v, want missing coverage mechanic", err)
	}
}

func TestParseV2DefinitionsFallsThroughToV2Lowering(t *testing.T) {
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
	adapter := decls[0].(*AdapterDecl)
	if adapter.Name != "python" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Concept != "code.SqlExecution" {
		t.Fatalf("mapping lowering wrong: %+v", got)
	}
}

func TestParseV2DefinitionsRejectsV1FallbackAndAllowsV2Modules(t *testing.T) {
	if _, err := ParseV2Definitions(`
adapter javascript {
  source "req.body" -> code.HttpInput
}
`); err == nil || !strings.Contains(err.Error(), "v1 syntax") {
		t.Fatalf("ParseV2Definitions v1 error = %v, want v1 syntax rejection", err)
	}

	decls, err := parseV2DefinitionsForTest(`
module code;
concept HttpInput : source {}

module bindings.javascript.express;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions concatenated v2 modules: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("decls = %d, want concept + adapter mapping", len(decls))
	}
}

func TestV2DependencyRequirementLowersToLegacyPackageGate(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want []string
	}{
		{
			name: "dependency",
			req:  `dependency("express")`,
			want: []string{"express"},
		},
		{
			name: "any dependency",
			req:  `any(dependency("express"), dependency("koa"), dependency("express"))`,
			want: []string{"express", "koa"},
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
			adapter := decls[0].(*AdapterDecl)
			if got := adapter.Mappings[0].Packages; !stringSlicesEqual(got, tc.want) {
				t.Fatalf("packages = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestV2RequirementLoweringRejectsUnsupportedSemantics(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "version range",
			req:  `dependency("express", range: ">=4 <6")`,
			want: "version ranges",
		},
		{
			name: "negated dependency",
			req:  `not(dependency("express"))`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "soft dependency",
			req:  `soft(dependency("express"))`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "all dependency",
			req:  `all(dependency("express"), dependency("koa"))`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "top-level import",
			req:  `import("express")`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "empty any",
			req:  `any()`,
			want: "at least one child",
		},
		{
			name: "nested any",
			req:  `any(any(dependency("express"), dependency("koa")))`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "any non-dependency",
			req:  `any(dependency("express"), import("koa"))`,
			want: "native v2 requirement evaluation",
		},
		{
			name: "any dependency with range",
			req:  `any(dependency("express", range: ">=4 <6"), dependency("koa"))`,
			want: "version ranges",
		},
		{
			name: "multiple top-level requirements",
			req:  `dependency("express")` + "\n    " + `dependency("koa")`,
			want: "multiple requirements",
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

func TestParseV2DefinitionsSplitsConcatenatedV2Modules(t *testing.T) {
	decls := parseV2DefinitionsWithCoreMechanics(t, `
module rules.one;
rule One {
  issue code.First as first
}

module rules.two;
rule Two {
  issue code.Second as second
}
`)
	if len(decls) != 2 {
		t.Fatalf("decls = %d, want 2: %+v", len(decls), decls)
	}
	if decls[0].(*Rule).QualifiedName() != "rules.one.One" || decls[1].(*Rule).QualifiedName() != "rules.two.Two" {
		t.Fatalf("rules lowered wrong: %+v", decls)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_path" || got.Pattern != "$" || !got.Exact {
		t.Fatalf("exact sink lowering wrong: %+v", got)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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

func TestV2PropagateValueLowering(t *testing.T) {
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
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*AdapterDecl)
	if adapter.Name != "c" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "flow_method" || got.Pattern != "decode" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 {
		t.Fatalf("arg-to-out-param propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "flow_path" || got.Pattern != "parse" || !got.FlowSourceResult || got.FlowSourceArg != -1 || got.FlowDestArg != 0 {
		t.Fatalf("result-to-out-param propagation wrong: %+v", got)
	}
}

func TestV2PropagateValueRejectsUnsupportedShape(t *testing.T) {
	cases := []string{
		`propagate taint from args[0] to args[1].pointee`,
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
	adapter := decls[0].(*AdapterDecl)
	if adapter.Name != "go" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "type" || got.Pattern != "sql.Open" || got.Concept != "sql.DB" {
		t.Fatalf("receiver type fact lowering wrong: %+v", got)
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
	adapter := decls[0].(*AdapterDecl)
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

func TestV2AssumptionCheckLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.python.migration;
binding startsWithGuard {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.Assumption at call {
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
  emit check core.Assumption at call {
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
	adapter := decls[0].(*AdapterDecl)
	if len(adapter.Mappings) != 2 {
		t.Fatalf("adapter mappings = %d, want 2: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "assume_guard_method" || got.Pattern != "startswith" || got.About != "code.FilePathAccess" || got.ValMatches[0] != "os.sep" {
		t.Fatalf("guard assumption lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "assume_sanitizer_path" || got.Pattern != "os.path.normpath" || got.About != "code.FilePathAccess" {
		t.Fatalf("sanitizer assumption lowering wrong: %+v", got)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
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
	adapter := decls[0].(*AdapterDecl)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "filter_method" || got.Pattern != "replace" || got.Constraint != "" {
		t.Fatalf("non-global char filter lowering wrong: %+v", got)
	}
}

func TestV2UnstableAnalysisAssumeGuardRejected(t *testing.T) {
	_, err := ParseV2Definitions(`
module bindings.java.migration;
binding containmentCheck {
  unstable: {
    owner: "test"
    reason: "obsolete private query family should not lower"
  }
  query unstable.analysisAssumeGuard as call where call.path == "analysis.guard.containment_check"
  emit check core.Assumption at call {
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
		t.Fatal("ParseV2Definitions succeeded for unstable.analysisAssumeGuard")
	}
	if !strings.Contains(err.Error(), `unsupported unstable query family "unstable.analysisAssumeGuard"`) {
		t.Fatalf("ParseV2Definitions error = %v", err)
	}
}

func TestV2PresenceNodeTokenAndKindLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.perl.migration;
binding cleartextChannel {
  query pattern presenceNode where node.kind == "any" and node.path ~= "getstore" and node.token contains "http://" and not (node.token contains "127.0")
  emit issue code.CleartextChannel at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(decls))
	}
	adapter := decls[0].(*AdapterDecl)
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
	if got := m.Flag.Predicates[0]; got.Property != "path" || got.Op != "match" || got.Values[0] != "getstore" {
		t.Fatalf("path predicate wrong: %+v", got)
	}
	if got := m.Flag.Predicates[2]; got.Property != "tokens" || got.Op != "contains" || !got.Negative || got.Values[0] != "127.0" {
		t.Fatalf("negative token predicate wrong: %+v", got)
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
	adapter := decls[0].(*AdapterDecl)
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
	flag := decls[0].(*AdapterDecl).Mappings[0].Flag
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
	adapter := decls[0].(*AdapterDecl)
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
	m := decls[0].(*AdapterDecl).Mappings[0]
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
	flag := decls[0].(*AdapterDecl).Mappings[0].Flag
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
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and node.op in ["==", "==="] and not (containsAny(node.scopeCall.any, ["scmp", "timingSafeEqual"])) and operand(node, where: operand.path ~= "__binop.operand" and containsAny(operand.identifier, ["token", "secret"]))
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	adapter := decls[0].(*AdapterDecl)
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
}

func TestV2PresenceNodeSnakeCasePseudoSubjectLowering(t *testing.T) {
	decls, err := parseV2DefinitionsForTest(`
module bindings.javascript.migration;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and not (containsAny(node.scope_call.any, [scmp])) and containsAny(node.flow_to.op, [return])
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("ParseV2Definitions: %v", err)
	}
	flag := decls[0].(*AdapterDecl).Mappings[0].Flag
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
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}
rule PublicSensitiveDatabase {
  reach cloud.Internet -> cloud.Database
  where holdsAssetKind(cloud.Database, [data.Pii])
}
rule CryptoMiningEgress {
  issue runtime.Connection as c
  where has(c.dst, threat.MiningPool)
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
	runtimeRule := decls[2].(*Rule)
	if got, ok := runtimeRule.Clauses[0].Where.(Has); !ok || got.Ref.String() != "c.dst" || got.Concept != "threat.MiningPool" {
		t.Fatalf("runtime where = %#v, want Has", runtimeRule.Clauses[0].Where)
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

func TestV2RuleConfidenceClauseLowersToRuntimeFloor(t *testing.T) {
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
	_, err := ParseV2Definitions(`
module mechanics.core;
mechanic ruleVerb issue { solver: fact.exists }
module rules.review;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataRequiresLoadedConfidencePolicy(t *testing.T) {
	_, err := ParseV2Definitions(`
module mechanics.core;
mechanic ruleVerb issue { solver: fact.exists }
module rules.review;
rule HighConfidenceReview {
  meta { confidenceFloor: high }
  issue code.Review as r
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded, want missing confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "no loaded policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestV2RuleConfidenceMetadataLowersToRuntimeFloor(t *testing.T) {
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

rule InvalidRefundTransition {
  query state as t where t.machine == Order and t.from == "*" and t.to == Refunded select t
}
`)
	order := decls[0].(*Rule).Body.(*OrderStmt)
	if order.First.Concept != "code.FileCheck" || order.First.Binding != "first" || order.Second.Concept != "code.FileUse" || order.Second.Binding != "second" {
		t.Fatalf("order lowering wrong: %+v", order)
	}
	transition := decls[1].(*Rule).Body.(*MatchStmt)
	if transition.TargetKind != "transition" || transition.Binding != "t" || transition.Machine != "Order" || transition.FromState != "*" || transition.ToState != "Refunded" {
		t.Fatalf("transition lowering wrong: %+v", transition)
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
	ad := decls[0].(*AdapterDecl)
	if len(ad.Mappings) != 1 {
		t.Fatalf("mappings = %#v, want one", ad.Mappings)
	}
	got := ad.Mappings[0]
	if got.Kind != "control_method" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" ||
		!got.ArgCountSet || got.ArgCountMin != 2 || got.ArgCountMax != -1 {
		t.Fatalf("args.count mapping = %#v, want arity-gated control_method", got)
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
	mappings := decls[0].(*AdapterDecl).Mappings
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
	adapter := decls[0].(*AdapterDecl)
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
		delete(want, got.Coverage)
	}
	if len(want) != 0 {
		t.Fatalf("missing coverage modes: %#v", want)
	}
}

func TestV2RuleSupportedCoveredByModesLowerToLegacyClauseKinds(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
  unless l.dominates coveredBy core.LockRelease
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
			if _, ok := rule.Clauses[0].Unless.(ClosedBy); !ok {
				t.Fatalf("release-style dominates coveredBy did not preserve closed_by semantics: %+v", rule.Clauses[0])
			}
		default:
			t.Fatalf("unexpected rule %s", rule.Name)
		}
	}
}

func TestV2LoweringPreservesRequiredProfileClause(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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

func TestV2AdapterMetadataLowersToRuntimeAdapterMeta(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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
	ad := decls[0].(*AdapterDecl)
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

func TestV2ConceptFieldsLowerToRuntimeFieldNames(t *testing.T) {
	decls := parseRuntimeFiles(t, `
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

func TestV2RuntimeSupportsGrantAssumeRulesAndObservationConcepts(t *testing.T) {
	decls := parseRuntimeFiles(t, `
module custom;
concept External : principal {}
concept Elevated : privilege {
  assumeMinLevel: ADMIN
}
concept PublicEdgeObservation : observation {
  contextConfirmFlagValue: true
}
`, `
module rules.identity;
rule ExternalToElevated {
  assume custom.External -> custom.Elevated
}
rule ExternalGrant {
  grant custom.External -> custom.Elevated
}
`)
	var sawObservation, sawAssume, sawGrant bool
	for _, decl := range decls {
		switch d := decl.(type) {
		case *ConceptDecl:
			if d.QualifiedName() == "custom.PublicEdgeObservation" {
				sawObservation = true
				if d.Kind != "observation" || d.Fields["context_confirm_flag_value"] != true {
					t.Fatalf("observation concept lowering wrong: %+v", d)
				}
			}
		case *Rule:
			if d.QualifiedName() == "rules.identity.ExternalToElevated" {
				body, ok := d.Body.(*FlowStmt)
				if !ok || body.Verb != "assume" {
					t.Fatalf("assume rule lowering wrong: %+v", d.Body)
				}
				sawAssume = true
			}
			if d.QualifiedName() == "rules.identity.ExternalGrant" {
				body, ok := d.Body.(*FlowStmt)
				if !ok || body.Verb != "grant" {
					t.Fatalf("grant rule lowering wrong: %+v", d.Body)
				}
				sawGrant = true
			}
		}
	}
	if !sawObservation || !sawAssume || !sawGrant {
		t.Fatalf("missing observation=%v assume=%v grant=%v in decls: %+v", sawObservation, sawAssume, sawGrant, decls)
	}
}

const v2CoreMechanicsForLoweringTest = `
module mechanics.core;
mechanic ruleVerb taint { solver: dataflow.taint }
mechanic ruleVerb flow { solver: dataflow.flow }
mechanic ruleVerb reach { solver: graph.reach }
mechanic ruleVerb grant { solver: graph.grant }
mechanic ruleVerb assume { solver: graph.assume }
mechanic ruleVerb issue { solver: fact.exists }
mechanic ruleVerb fact { solver: fact.exists }
mechanic ruleVerb query { solver: query.semantic }
mechanic coverage path { capability: coverage.path requiresAnchor: true targetParts: [path] }
mechanic coverage endpoint { capability: coverage.endpoint requiresAnchor: true targetParts: [endpoint] }
mechanic coverage sameReceiver { capability: coverage.sameReceiver requiresAnchor: true targetParts: [sameReceiver] }
mechanic coverage sameScope { capability: coverage.sameScope requiresAnchor: true targetParts: [sameScope] }
mechanic coverage dominates { capability: coverage.dominates requiresAnchor: true targetParts: [dominates] }
mechanic coverage global { capability: coverage.global requiresAnchor: false targetParts: [global] }
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
	return parseRuntimeFiles(t, src)
}

func parseV2DefinitionsForTest(src string) ([]Decl, error) {
	decls, err := ParseV2Definitions(v2CoreMechanicsForLoweringTest + "\n" + src)
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

func parseRuntimeFiles(t *testing.T, srcs ...string) []Decl {
	t.Helper()
	sources := []V2Source{parseV2SourceForLoweringTest(t, "mechanics/core.vyql", v2CoreMechanicsForLoweringTest)}
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

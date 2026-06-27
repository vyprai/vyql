package parser

import (
	"fmt"
	"strings"
	"testing"
)

const v2Program = `
module sample.v2;

uses patterns.javascript.callExpr as jsCall;
uses patterns.javascript.routeExpr;

concept SqlParameterization : check {
  neutralizes: [code.SqlExecution]
  covers: [path]
}

pattern callExpr as call {
  node: call
  bind callee = call.callee
  bind args = call.args
  where callee.path ~= "db.query"
}

matcher secretTokenName {
  containsAny: ["token", "secret", "key"]
}

binding requestBody {
  requires {
    language("javascript")
    soft(any(dependency("express"), import("express")))
  }

  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result

  fidelity: resolved
  confidence: high
}

binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path {
      from: args[0]
      to: call
    }
  }
  fidelity: resolved
  confidence: high
}

binding decodeOutParam {
  query call as c where c.callee.path ~= "json.Unmarshal"
  propagate value from c.args[0] to c.args[1].pointee
  fidelity: resolved
}

rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint taint.UntrustedData as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}

rule LateralReachToSecretStore {
  meta { id: "VYQL-CLOUD-014" severity: high cwe: [CWE285] }
  query principal as actor where actor.concept == cloud.ExternalPrincipal
    reaches asset as store where store.concept == cloud.SecretStore
    select store
  unless store.endpoint coveredBy core.AuthorizationCheck
}

review code.SecretComparisonReview {
  mode: flag
  category: security
  text: "verify secret comparisons use constant time comparison"
}
`

func TestParseV2ProgramContract(t *testing.T) {
	prog, err := ParseV2(v2Program)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if prog.Module != "sample.v2" || len(prog.Uses) != 2 || prog.Uses[0].Alias != "jsCall" {
		t.Fatalf("program module/uses wrong: module=%q uses=%+v", prog.Module, prog.Uses)
	}
	if len(prog.Decls) != 9 {
		t.Fatalf("decl count = %d, want 9", len(prog.Decls))
	}
	concept := prog.Decls[0].(*V2ConceptDecl)
	if concept.Name != "SqlParameterization" || concept.Module != "sample.v2" || concept.Kind != "check" {
		t.Fatalf("concept header wrong: %+v", concept)
	}
	if got := concept.Fields["covers"].([]string); len(got) != 1 || got[0] != "path" {
		t.Fatalf("concept covers wrong: %#v", concept.Fields["covers"])
	}
	pattern := prog.Decls[1].(*V2PatternDecl)
	if pattern.Name != "callExpr" || pattern.Alias != "call" || len(pattern.Items) != 4 {
		t.Fatalf("pattern wrong: %+v", pattern)
	}
	matcher := prog.Decls[2].(*V2MatcherDecl)
	if matcher.Name != "secretTokenName" || matcher.Items[0].Kind != "containsAny" {
		t.Fatalf("matcher wrong: %+v", matcher)
	}
	requestBody := prog.Decls[3].(*V2BindingDecl)
	if requestBody.Query.Pattern != "callExpr" {
		t.Fatalf("pattern query not captured: %+v", requestBody.Query)
	}
	if len(requestBody.Requirements) != 2 || requestBody.Requirements[1].Name != "soft" {
		t.Fatalf("requirements wrong: %+v", requestBody.Requirements)
	}
	if out := requestBody.Outputs[0]; out.Kind != "emit source" || out.Concept != "code.HttpInput" || out.Location != "call.result" {
		t.Fatalf("source emit wrong: %+v", out)
	}
	param := prog.Decls[4].(*V2BindingDecl)
	if len(param.Outputs[0].Covers) != 1 || param.Outputs[0].Covers[0].Mode != "path" {
		t.Fatalf("coverage wrong: %+v", param.Outputs[0])
	}
	propagate := prog.Decls[5].(*V2BindingDecl)
	if propagate.Query.Expr == nil || propagate.Query.Expr.Family != "call" {
		t.Fatalf("inline query wrong: %+v", propagate.Query)
	}
	if out := propagate.Outputs[0]; out.Kind != "propagate value" || out.From != "c.args[0]" || out.To != "c.args[1].pointee" {
		t.Fatalf("propagate wrong: %+v", out)
	}
	rule := prog.Decls[6].(*V2RuleDecl)
	if rule.Body.Verb != "taint" || rule.Body.From.Alias != "input" || rule.Clauses[0].Coverage != "path" {
		t.Fatalf("taint rule wrong: %+v", rule)
	}
	raw := prog.Decls[7].(*V2RuleDecl)
	if raw.Body.Query == nil || raw.Body.Select != "store" || len(raw.Body.Query.Steps) != 1 {
		t.Fatalf("raw query rule wrong: %+v", raw.Body)
	}
	review := prog.Decls[8].(*V2ReviewDecl)
	if review.Concept != "code.SecretComparisonReview" || review.Fields["mode"] != "flag" {
		t.Fatalf("review wrong: %+v", review)
	}
}

func TestParseV2RejectsV1Syntax(t *testing.T) {
	bad := []string{
		`adapter javascript { source "req.body" -> code.HttpInput }`,
		`adapter javascript { sink method "query" -> code.SqlExecution }`,
		`adapter javascript { flag code.SecretComparisonReview on binop { has "token" } }`,
		`adapter javascript { mark method "danger" -> code.DynamicCodeExecution }`,
		`adapter javascript { package "express" { source "req.body" -> code.HttpInput } }`,
		`import code.HttpInput;`,
		`module rules.old; rule OldUnless { taint code.HttpInput -> code.SqlExecution unless sanitized_by core.SqlParameterization }`,
		`module rules.old; rule OldMatch { match code.XmlParserCreate as parser }`,
	}
	for _, src := range bad {
		_, err := ParseV2(src)
		if err == nil {
			t.Fatalf("ParseV2(%q) succeeded, want v1 rejection", src)
		}
	}
}

func TestParseV2RejectsAmbiguousPatternQuery(t *testing.T) {
	src := `module bindings.javascript.express; binding bad { query callExpr where callee.method == "query" emit sink code.SqlExecution at args[0] }`
	_, err := ParseV2(src)
	if err == nil {
		t.Fatal("ambiguous named pattern query succeeded")
	}
	if !strings.Contains(err.Error(), "query pattern") {
		t.Fatalf("error = %v, want query pattern guidance", err)
	}
}

func TestParseV2RejectsSecondModule(t *testing.T) {
	_, err := ParseV2(`module one; module two; concept X : issue {}`)
	if err == nil {
		t.Fatal("second module declaration succeeded")
	}
	if !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("error = %v, want one-module diagnostic", err)
	}
}

func TestParseV2RejectsUsesAfterDeclaration(t *testing.T) {
	_, err := ParseV2(`module sample; concept X : issue {} uses code.HttpInput;`)
	if err == nil {
		t.Fatal("uses after declaration succeeded")
	}
	if !strings.Contains(err.Error(), "uses declarations must appear before") {
		t.Fatalf("error = %v, want uses-before-declarations diagnostic", err)
	}
}

func TestParseV2RejectsWildcardUses(t *testing.T) {
	_, err := ParseV2(`module sample; uses code.*; concept X : issue {}`)
	if err == nil {
		t.Fatal("wildcard uses succeeded")
	}
	if !strings.Contains(err.Error(), "wildcard uses") {
		t.Fatalf("error = %v, want wildcard uses diagnostic", err)
	}
}

func TestParseV2RejectsImportNameConflicts(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "implicit import duplicate",
			src: `module sample;
uses one.HttpInput;
uses two.HttpInput;
concept X : issue {}`,
			want: "local import name",
		},
		{
			name: "alias duplicate",
			src: `module sample;
uses one.HttpInput as Input;
uses two.BodyInput as Input;
concept X : issue {}`,
			want: "local import name",
		},
		{
			name: "import shadows declaration",
			src: `module sample;
uses code.HttpInput;
concept HttpInput : source {}`,
			want: "shadows declaration",
		},
		{
			name: "duplicate declaration",
			src: `module sample;
concept X : issue {}
rule X { issue code.StaticIssue }`,
			want: "local name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseV2(tc.src)
			if err == nil {
				t.Fatal("ParseV2 succeeded, want name-resolution error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseV2RequirementNamedArgsAndExpressionPrecedence(t *testing.T) {
	prog, err := ParseV2(`
module bindings.javascript.express;
binding bounded {
  requires {
    dependency("express", range: ">=4 <6")
  }
  query pattern callExpr where callee.method == "execute" and (args.count >= 2 or args.count in [3])
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	b := prog.Decls[0].(*V2BindingDecl)
	req := b.Requirements[0]
	if got := req.Args[1].(V2NamedArg); got.Name != "range" || got.Value != ">=4 <6" {
		t.Fatalf("named requirement arg wrong: %+v", req.Args[1])
	}
	and, ok := b.Query.Where.(V2BinaryExpr)
	if !ok || and.Op != "and" {
		t.Fatalf("top-level expr = %+v, want and", b.Query.Where)
	}
	or, ok := and.Right.(V2BinaryExpr)
	if !ok || or.Op != "or" {
		t.Fatalf("right expr = %+v, want parenthesized or", and.Right)
	}
	ge, ok := or.Left.(V2BinaryExpr)
	if !ok || ge.Op != ">=" {
		t.Fatalf("left expr = %+v, want >=", or.Left)
	}
	if lit, ok := ge.Right.(V2LiteralExpr); !ok || lit.Value != 2 {
		t.Fatalf("numeric literal = %+v", ge.Right)
	}
}

func TestParseV2PatternOperatorsAndNamedCallArgs(t *testing.T) {
	prog, err := ParseV2(`
module patterns.javascript;
pattern sensitiveHandler as handler {
  node: call
  where callee.path startsWith "app."
  where callee.path endsWith ".get"
  where callee.path matches "^app\\."
  where operands.any.identifier is secretTokenName
  where scope.hasCall(path: "escapeHtml")
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	pat := prog.Decls[0].(*V2PatternDecl)
	if len(pat.Items) != 6 {
		t.Fatalf("pattern items = %d, want 6", len(pat.Items))
	}
	for i, want := range []string{"startsWith", "endsWith", "matches", "is"} {
		expr, ok := pat.Items[i+1].Expr.(V2BinaryExpr)
		if !ok || expr.Op != want {
			t.Fatalf("where %d expr = %+v, want %s binary", i+1, pat.Items[i+1].Expr, want)
		}
	}
	call, ok := pat.Items[5].Expr.(V2CallExpr)
	if !ok || call.Name != "scope.hasCall" || len(call.NamedArgs) != 1 {
		t.Fatalf("named call expr = %+v", pat.Items[5].Expr)
	}
	if call.NamedArgs[0].Name != "path" {
		t.Fatalf("named arg = %+v, want path", call.NamedArgs[0])
	}
	if lit, ok := call.NamedArgs[0].Expr.(V2LiteralExpr); !ok || lit.Value != "escapeHtml" {
		t.Fatalf("named arg value = %+v, want escapeHtml literal", call.NamedArgs[0].Expr)
	}
}

func TestParseV2MechanicAndPolicyDeclarations(t *testing.T) {
	prog, err := ParseV2(`
module mechanics.sast;

mechanic coverage path {
  capability: coverage.path
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
  targetParts: [path]
  suppresses: true
}

policy priority default {
  score severity {
    critical: 4
    high: 3
    medium: 2
    low: 1
    info: 0
    default: 1
  }

  factor exposure {
    when context.internetReachable
    weight: 2
  }

  bands: [
    { band: "P0", min: 8 },
    { band: "P1", min: 6 }
  ]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if len(prog.Decls) != 2 {
		t.Fatalf("decl count = %d, want 2", len(prog.Decls))
	}
	mech := prog.Decls[0].(*V2MechanicDecl)
	if mech.Kind != "coverage" || mech.Name != "path" || len(mech.Items) != 4 {
		t.Fatalf("mechanic header/items wrong: %+v", mech)
	}
	if got := mech.Items[1].Value.(V2CallExpr); got.Name != "solver.pathCovered" || len(got.Args) != 2 {
		t.Fatalf("coversWhen = %+v, want solver.pathCovered call", mech.Items[1].Value)
	}
	pol := prog.Decls[1].(*V2PolicyDecl)
	if pol.Kind != "priority" || pol.Name != "default" || len(pol.Items) != 3 {
		t.Fatalf("policy header/items wrong: %+v", pol)
	}
	score := pol.Items[0]
	if strings.Join(score.Key, ".") != "score.severity" || len(score.Block) != 6 {
		t.Fatalf("score block wrong: %+v", score)
	}
	factor := pol.Items[1]
	if strings.Join(factor.Key, ".") != "factor.exposure" || len(factor.Block) != 2 {
		t.Fatalf("factor block wrong: %+v", factor)
	}
	bands, ok := pol.Items[2].Value.([]any)
	if !ok || len(bands) != 2 {
		t.Fatalf("bands = %#v, want two block entries", pol.Items[2].Value)
	}
}

func TestParseV2PriorityPolicyAllowsNegativeWeights(t *testing.T) {
	prog, err := ParseV2(`
module mechanics.policy;
policy priority default {
  factor confidenceLow {
    when finding.confidence == low
    weight: -2
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	pol := prog.Decls[0].(*V2PolicyDecl)
	weight, ok := pol.Items[0].Block[1].Value.(V2LiteralExpr)
	if !ok || weight.Value != -2 {
		t.Fatalf("weight = %#v, want -2 literal", pol.Items[0].Block[1].Value)
	}
}

func TestParseV2PolicyActionSequence(t *testing.T) {
	prog, err := ParseV2(`
module mechanics.sast;
policy confidence default {
  softRequirement missing: downgrade(1) annotate("missing evidence")
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	pol := prog.Decls[0].(*V2PolicyDecl)
	seq, ok := pol.Items[0].Value.(V2SequenceExpr)
	if !ok || len(seq.Items) != 2 {
		t.Fatalf("softRequirement value = %#v, want two action expressions", pol.Items[0].Value)
	}
	if call, ok := seq.Items[1].(V2CallExpr); !ok || call.Name != "annotate" {
		t.Fatalf("second action = %#v, want annotate call", seq.Items[1])
	}
}

func TestParseV2ValidatesPolicyContracts(t *testing.T) {
	_, err := ParseV2(`
module mechanics.policy;
policy resultLifecycle default {
  flagWhen: emitted(issue) and hasReview(concept)
  candidateWhen: matched(rule)
  findingWhen: candidate and not covered
  checkWhen: emitted(check) and (hasReview(concept) or explainsFinding)
}
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
  softRequirement conflicting: downgrade(1)
  softRequirement satisfied: keep
}
policy display default {
  scanAll: [findings, flags, checks, advisoryEvidence, requirementDiagnostics]
  flagSort: [severity, category, location, concept]
  includeNearbyChecks: true
  nearbyCheckLimit: 5
}
`)
	if err != nil {
		t.Fatalf("ParseV2 valid policies: %v", err)
	}
}

func TestParseV2RejectsInvalidPolicyContracts(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "unknown lifecycle builtin",
			src: `module mechanics.policy;
policy resultLifecycle default { findingWhen: heuristic(candidate) }`,
			want: `unknown policy builtin "heuristic"`,
		},
		{
			name: "unknown confidence state",
			src: `module mechanics.policy;
policy confidence default { softRequirement stale: downgrade(1) }`,
			want: `unknown softRequirement state "stale"`,
		},
		{
			name: "bad confidence action",
			src: `module mechanics.policy;
policy confidence default { softRequirement missing: downgrade("one") }`,
			want: "downgrade argument must be an integer",
		},
		{
			name: "priority factor missing weight",
			src: `module mechanics.policy;
policy priority default { factor exposure { when context.internetReachable } }`,
			want: "requires integer weight",
		},
		{
			name: "display wrong boolean",
			src: `module mechanics.policy;
policy display default { includeNearbyChecks: maybe }`,
			want: "includeNearbyChecks must be boolean",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseV2(tc.src)
			if err == nil {
				t.Fatal("ParseV2 succeeded, want policy validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseV2ValidatesCoverageMechanicIndexedSolverForms(t *testing.T) {
	src := `
module mechanics.sast;

mechanic coverage path {
  capability: coverage.path
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
  targetParts: [path]
  suppresses: true
}

mechanic coverage endpoint {
  capability: coverage.endpoint
  coversWhen: solver.sameEndpoint(check.anchor, candidate.endpoint)
  targetParts: [endpoint]
  suppresses: true
}

mechanic coverage sameReceiver {
  capability: coverage.sameReceiver
  coversWhen: solver.sameValue(check.anchor, candidate.sameReceiver)
  targetParts: [sameReceiver]
  suppresses: true
}

mechanic coverage sameScope {
  capability: coverage.sameScope
  coversWhen: solver.sameScope(check.anchor, candidate.sameScope)
  targetParts: [sameScope]
  suppresses: true
}
`
	prog, err := ParseV2(src)
	if err != nil {
		t.Fatalf("ParseV2 indexed mechanics: %v", err)
	}
	if len(prog.Decls) != 4 {
		t.Fatalf("decl count = %d, want 4", len(prog.Decls))
	}
}

func TestParseV2RejectsNonIndexedCoverageMechanicCoversWhen(t *testing.T) {
	cases := []string{
		`module mechanics.sast; mechanic coverage path { capability: coverage.path coversWhen: project.has("custom") }`,
		`module mechanics.sast; mechanic coverage path { capability: coverage.path coversWhen: solver.sameEndpoint(check.anchor, candidate.path) }`,
		`module mechanics.sast; mechanic coverage path { capability: coverage.path coversWhen: solver.pathCovered(allChecks, candidate.path) }`,
		`module mechanics.sast; mechanic coverage sameReceiver { capability: coverage.sameReceiver coversWhen: solver.sameValue(check.anchor) }`,
		`module mechanics.sast; mechanic coverage path { capability: coverage.endpoint coversWhen: solver.pathCovered(check.anchor, candidate.path) targetParts: [path] }`,
		`module mechanics.sast; mechanic coverage path { capability: coverage.path coversWhen: solver.pathCovered(check.anchor, candidate.path) }`,
		`module mechanics.sast; mechanic coverage path { capability: coverage.path coversWhen: solver.pathCovered(check.anchor, candidate.endpoint) targetParts: [path] }`,
		`module mechanics.sast; mechanic coverage global { capability: coverage.global coversWhen: solver.always(check.anchor) targetParts: [global] }`,
		`module mechanics.sast; mechanic coverage endpoint { capability: coverage.endpoint requiresAnchor: false targetParts: [endpoint] }`,
	}
	for _, src := range cases {
		_, err := ParseV2(src)
		if err == nil {
			t.Fatalf("ParseV2(%q) succeeded, want coverage mechanic validation error", src)
		}
		if !strings.Contains(err.Error(), "mechanic coverage") {
			t.Fatalf("ParseV2(%q) error = %v, want mechanic coverage diagnostic", src, err)
		}
	}
}

func TestValidateV2CorpusRejectsRuleCoverageTargetOutsideMechanicTargetParts(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module mechanics.custom;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [coveredBy]
}
mechanic coverage endpoint {
  capability: coverage.endpoint
  coversWhen: solver.sameEndpoint(check.anchor, candidate.path)
  targetParts: [path]
}
`, `
module code;
concept Input : source {}
concept Sink : sink {}
concept Guard : check { covers: [endpoint] }
`, `
module rules.custom;
rule BadCoverageTarget {
  taint code.Input -> code.Sink as sink
  unless sink.endpoint coveredBy code.Guard
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want targetParts diagnostic")
	}
	if !strings.Contains(err.Error(), `coverage part "endpoint" not declared by mechanic coverage endpoint targetParts [path]`) {
		t.Fatalf("error = %v, want targetParts diagnostic", err)
	}
}

func TestValidateV2CorpusRejectsConfidenceWithoutPolicy(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module mechanics.custom;
mechanic ruleVerb issue {
  solver: fact.exists
  fromKinds: [issue]
  allowedClauses: [confidence]
}
`, `
module code;
concept Review : issue {}
`, `
module rules.custom;
rule HighConfidenceReview {
  issue code.Review as r
  with confidence >= high
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want confidence policy diagnostic")
	}
	if !strings.Contains(err.Error(), "confidence floor requires policy confidence default") {
		t.Fatalf("error = %v, want confidence policy diagnostic", err)
	}
}

func TestParseV2QueryWhereContainsIsExpressionOperator(t *testing.T) {
	prog, err := ParseV2(`
module rules.query;
rule TagsContainHigh {
  query concept as c where c.tags contains high select c
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	rule := prog.Decls[0].(*V2RuleDecl)
	if len(rule.Body.Query.Steps) != 0 {
		t.Fatalf("contains parsed as query relation step: %+v", rule.Body.Query.Steps)
	}
	cmp, ok := rule.Body.Query.Where.(V2BinaryExpr)
	if !ok || cmp.Op != "contains" {
		t.Fatalf("where = %#v, want contains expression", rule.Body.Query.Where)
	}
}

func TestParseV2ValidationRejectsContractViolations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "requirement in query",
			src: `module bindings.javascript.express;
binding bad {
  query pattern callExpr where dependency("express")
  emit source code.HttpInput at call.result
}`,
			want: "belong in requires",
		},
		{
			name: "non advisory check without coverage",
			src: `module bindings.javascript.express;
binding bad {
  query pattern callExpr where callee.method == "sanitize"
  emit check core.HtmlEscape at call
}`,
			want: "requires concrete covers",
		},
		{
			name: "raw rule query over code family",
			src: `module rules.bad;
rule Bad {
  query call as c where c.callee.method == "danger" select c
}`,
			want: "not allowed in semantic-tier query",
		},
		{
			name: "unknown requirement",
			src: `module bindings.javascript.express;
binding bad {
  requires { call("execute") }
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
}`,
			want: "unknown requirement",
		},
		{
			name: "unknown policy kind",
			src: `module mechanics.sast;
policy notARealPolicy default { findingWhen: candidate }`,
			want: "unknown policy kind",
		},
		{
			name: "unknown mechanic capability",
			src: `module mechanics.sast;
mechanic coverage path {
  capability: coverage.magic
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
}`,
			want: "unknown capability",
		},
		{
			name: "missing coverage mechanic capability",
			src: `module mechanics.sast;
mechanic coverage path {
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
}`,
			want: "missing capability",
		},
		{
			name: "legacy control concept kind",
			src: `module core;
concept Assumption : control {}`,
			want: "unknown v2 concept kind",
		},
		{
			name: "emit source with check concept",
			src: `module sample;
concept Sanitized : check { covers: [path] }
binding bad {
  query pattern callExpr where callee.method == "sanitize"
  emit source Sanitized at call.result
}`,
			want: "emit source uses concept Sanitized of kind check",
		},
		{
			name: "emit fact with source concept",
			src: `module sample;
concept HttpInput : source {}
binding bad {
  query pattern callExpr where callee.method == "source"
  emit fact HttpInput at call
}`,
			want: "emit fact uses concept HttpInput of kind source",
		},
		{
			name: "issue rule with check concept",
			src: `module sample;
concept Sanitized : check { covers: [path] }
rule Bad {
  issue Sanitized
}`,
			want: "issue rule uses concept Sanitized of kind check",
		},
		{
			name: "unknown concept coverage mode",
			src: `module sample;
concept Sanitized : check { covers: [magic] }`,
			want: "unknown coverage mode",
		},
		{
			name: "path coverage without endpoints",
			src: `module sample;
concept Sanitized : check { covers: [path] }
binding bad {
  query pattern callExpr where callee.method == "sanitize"
  emit check Sanitized at call {
    covers path {}
  }
}`,
			want: "covers path requires from and to",
		},
		{
			name: "same receiver coverage without anchor",
			src: `module sample;
concept Sanitized : check { covers: [sameReceiver] }
binding bad {
  query pattern callExpr where callee.method == "sanitize"
  emit check Sanitized at call {
    covers sameReceiver {}
  }
}`,
			want: "covers sameReceiver requires anchor",
		},
		{
			name: "global coverage with anchor",
			src: `module sample;
concept Sanitized : check { covers: [global] }
binding bad {
  query pattern callExpr where callee.method == "sanitize"
  emit check Sanitized at call {
    covers global { anchor: call }
  }
}`,
			want: "covers global must not declare",
		},
		{
			name: "unstable binding query without metadata",
			src: `module bindings.javascript.migration;
binding bad {
  query unstable.legacyFlag as node where node.kind == "any"
  emit issue code.Review at node
}`,
			want: "requires owner and reason metadata",
		},
		{
			name: "unstable pattern node without metadata",
			src: `module patterns.javascript;
pattern bad {
  node: unstable.frameworkRoute
}`,
			want: "requires owner and reason metadata",
		},
		{
			name: "unstable pattern metadata missing reason",
			src: `module patterns.javascript;
pattern bad {
  unstable: { owner: "frontend" }
  node: unstable.frameworkRoute
}`,
			want: "unstable metadata requires owner and reason",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseV2(tc.src)
			if err == nil {
				t.Fatal("ParseV2 succeeded, want validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseV2AllowsGlobalCoverageWithoutFields(t *testing.T) {
	_, err := ParseV2(`
module sample;
concept Sanitized : check { covers: [global] }
binding good {
  query pattern callExpr where callee.method == "sanitize"
  emit check Sanitized at call {
    covers global {}
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2 rejected empty global coverage: %v", err)
	}
}

func TestValidateV2CorpusRejectsCoverageNotDeclaredByCheckConcept(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module core;
concept SqlParameterization : check { covers: [path] }
concept HttpInput : source {}
concept SqlExecution : sink {}
`, `
module bindings.javascript.sql;
binding parameterized {
  query pattern callExpr where callee.method == "execute"
  emit check core.SqlParameterization at call {
    covers endpoint { anchor: call }
  }
}
`, `
module rules.sql;
rule SqlInjection {
  taint core.HttpInput -> core.SqlExecution as sink
  unless sink.endpoint coveredBy core.SqlParameterization
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want coverage mode diagnostic")
	}
	if !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("error = %v, want declared covers diagnostic", err)
	}
}

func TestValidateV2CorpusRejectsCoverageWhenCheckDeclaresNoCovers(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module core;
concept AuthorizationCheck : check {}
concept HttpInput : source {}
concept StateChange : sink {}
`, `
module rules.authz;
rule MissingAuthorization {
  taint core.HttpInput -> core.StateChange as op
  unless op.endpoint coveredBy core.AuthorizationCheck
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want missing covers diagnostic")
	}
	if !strings.Contains(err.Error(), `check core.AuthorizationCheck uses coverage mode "endpoint" but the concept declares no covers modes`) {
		t.Fatalf("error = %v, want missing covers diagnostic", err)
	}
}

func TestValidateV2CorpusChecksCoverageThroughUsesAlias(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module core;
concept XmlHardening : check { covers: [sameReceiver] }
concept XmlInput : source {}
concept XmlParser : sink {}
`, `
module rules.xml;
uses core.XmlHardening as Hardening;
rule XmlParserHardening {
  taint core.XmlInput -> core.XmlParser as parser
  unless parser.path coveredBy Hardening
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want alias coverage diagnostic")
	}
	if !strings.Contains(err.Error(), `coveredBy check Hardening uses coverage mode "path" not declared in concept covers [sameReceiver]`) {
		t.Fatalf("error = %v, want alias coverage diagnostic", err)
	}
}

func TestValidateV2CorpusUsesRuleVerbMechanicEndpointKinds(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module mechanics.custom;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [asset]
  toKinds: [sink]
  allowedClauses: [where, coveredBy]
}
`, `
module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
`, `
module rules.sql;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want mechanic-authored endpoint kind diagnostic")
	}
	if !strings.Contains(err.Error(), `from uses concept code.HttpInput of kind source; want asset`) {
		t.Fatalf("error = %v, want endpoint kind from authored mechanic", err)
	}
}

func TestParseV2RejectsMechanicUnknownEndpointKind(t *testing.T) {
	_, err := ParseV2(`
module mechanics.bad;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source, widget]
  toKinds: [sink]
  allowedClauses: [where, coveredBy]
}
`)
	if err == nil {
		t.Fatal("ParseV2 succeeded, want mechanic endpoint kind diagnostic")
	}
	if !strings.Contains(err.Error(), `unknown endpoint kind "widget"`) {
		t.Fatalf("error = %v, want unknown endpoint kind diagnostic", err)
	}
}

func TestValidateV2CorpusUsesRuleVerbMechanicAllowedClauses(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module mechanics.custom;
mechanic ruleVerb fact {
  solver: fact.exists
  fromKinds: [fact]
  allowedClauses: [where]
}
mechanic coverage path {
  capability: coverage.path
  coversWhen: solver.pathCovered(check.anchor, candidate.path)
  targetParts: [path]
}
`, `
module code;
concept ConfigFact : fact {}
concept Guard : check { covers: [path] }
`, `
module rules.config;
rule ConfigGuard {
  fact code.ConfigFact as f
  unless f.path coveredBy code.Guard
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want allowed clause diagnostic")
	}
	if !strings.Contains(err.Error(), `clause "coveredBy" is not allowed by mechanic ruleVerb fact`) {
		t.Fatalf("error = %v, want allowed clause diagnostic", err)
	}
}

func TestValidateV2CorpusAllowsEmitFactObservation(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module mechanics.custom;
mechanic coverage global {
  capability: coverage.global
  coversWhen: solver.always()
  targetParts: [global]
}
`, `
module code;
concept PublicRouteObservation : observation {}
`, `
module bindings.web;
binding publicRoute {
  query pattern route where route.public == true
  emit fact code.PublicRouteObservation at route
}
`)
	if err := ValidateV2Corpus(sources); err != nil {
		t.Fatalf("ValidateV2Corpus rejected observation fact emit: %v", err)
	}
}

func TestValidateV2CorpusRejectsUnknownModelReferences(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module injection;
threat SqlInjection {
  cwe: [CWE_89]
}
`, `
module code;
concept SqlExecution : sink {
  vulnerableTo: [injection.DoesNotExist]
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want model reference diagnostic")
	}
	if !strings.Contains(err.Error(), `vulnerableTo references unknown model injection.DoesNotExist`) {
		t.Fatalf("error = %v, want unknown model diagnostic", err)
	}
}

func TestValidateV2CorpusChecksReviewAndExpectedConceptReferences(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module code;
concept SqlExecution : sink {}
concept HttpInput : source {}
`, `
module review;
review code.SqlExecution {
  expected: [code.HttpInput]
}
`)
	err := ValidateV2Corpus(sources)
	if err == nil {
		t.Fatal("ValidateV2Corpus succeeded, want expected check-kind diagnostic")
	}
	if !strings.Contains(err.Error(), `expected references concept code.HttpInput of kind source; want check`) {
		t.Fatalf("error = %v, want expected kind diagnostic", err)
	}
}

func TestValidateV2CorpusResolvesThreatUsesAliasesInModelReferences(t *testing.T) {
	sources := parseV2CorpusForTest(t, `
module injection;
threat SqlInjection {
  cwe: [CWE_89]
}
`, `
module code;
uses injection.SqlInjection as SQLi;
concept SqlExecution : sink {
  vulnerableTo: [SQLi]
}
`)
	if err := ValidateV2Corpus(sources); err != nil {
		t.Fatalf("ValidateV2Corpus rejected threat alias model reference: %v", err)
	}
}

func TestParseV2RejectsMechanicUnknownAllowedClause(t *testing.T) {
	_, err := ParseV2(`
module mechanics.bad;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, sparkle]
}
`)
	if err == nil {
		t.Fatal("ParseV2 succeeded, want mechanic allowed clause diagnostic")
	}
	if !strings.Contains(err.Error(), `unknown allowed clause "sparkle"`) {
		t.Fatalf("error = %v, want unknown allowed clause diagnostic", err)
	}
}

func TestValidateV2CorpusHandlesManyFilesWithoutGlobalScopeCopies(t *testing.T) {
	const n = 250
	sources := make([]V2Source, 0, n+2)
	sources = append(sources, v2CoreMechanicsSourceForTest(t))
	concepts := `module code;
concept HttpInput : source {}
concept SqlExecution : sink {}
concept SqlParameterization : check { covers: [path] }
`
	for i := 0; i < n; i++ {
		concepts += fmt.Sprintf("concept Extra%d : fact {}\n", i)
	}
	prog, err := ParseV2(concepts)
	if err != nil {
		t.Fatalf("ParseV2 concepts: %v", err)
	}
	sources = append(sources, V2Source{Name: "concepts.vyql", Program: prog})
	for i := 0; i < n; i++ {
		src := fmt.Sprintf(`
module rules.generated%d;
uses code.SqlParameterization as Param;
rule SqlInjection%d {
  taint code.HttpInput -> code.SqlExecution as sink
  unless sink.path coveredBy Param
}
`, i, i)
		prog, err := ParseV2(src)
		if err != nil {
			t.Fatalf("ParseV2 generated %d: %v", i, err)
		}
		sources = append(sources, V2Source{Name: fmt.Sprintf("rule%d.vyql", i), Program: prog})
	}
	if err := ValidateV2Corpus(sources); err != nil {
		t.Fatalf("ValidateV2Corpus: %v", err)
	}
}

func parseV2CorpusForTest(t *testing.T, srcs ...string) []V2Source {
	t.Helper()
	sources := make([]V2Source, 0, len(srcs))
	for i, src := range srcs {
		prog, err := ParseV2(src)
		if err != nil {
			t.Fatalf("ParseV2 source %d: %v\n%s", i, err, src)
		}
		sources = append(sources, V2Source{Name: "source.vyql", Program: prog})
	}
	return sources
}

func v2CoreMechanicsSourceForTest(t *testing.T) V2Source {
	t.Helper()
	src := `module mechanics.core;
mechanic ruleVerb taint {
  solver: dataflow.taint
  fromKinds: [source]
  toKinds: [sink]
  allowedClauses: [where, coveredBy, confidence]
}
mechanic ruleVerb issue {
  solver: fact.exists
  fromKinds: [issue]
  allowedClauses: [where, coveredBy, confidence]
}
mechanic ruleVerb fact {
  solver: fact.exists
  fromKinds: [fact, asset, exposure, principal, privilege, state, observation]
  allowedClauses: [where, coveredBy, confidence]
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
	prog, err := ParseV2(src)
	if err != nil {
		t.Fatalf("ParseV2 core mechanics fixture: %v", err)
	}
	return V2Source{Name: "mechanics/core.vyql", Program: prog}
}

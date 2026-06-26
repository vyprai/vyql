package parser

import (
	"strings"
	"testing"
)

const v2Program = `
module sample.v2;

uses patterns.javascript.callExpr as jsCall;

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

uses patterns.javascript.callExpr;

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
		`rule OldUnless { taint code.HttpInput -> code.SqlExecution unless sanitized_by core.SqlParameterization }`,
		`rule OldMatch { match code.XmlParserCreate as parser }`,
	}
	for _, src := range bad {
		_, err := ParseV2(src)
		if err == nil {
			t.Fatalf("ParseV2(%q) succeeded, want v1 rejection", src)
		}
		if !strings.Contains(err.Error(), "v1 syntax") {
			t.Fatalf("ParseV2(%q) error = %v, want v1 syntax diagnostic", src, err)
		}
	}
}

func TestParseV2RejectsAmbiguousPatternQuery(t *testing.T) {
	src := `binding bad { query callExpr where callee.method == "query" emit sink code.SqlExecution at args[0] }`
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
	if !strings.Contains(err.Error(), "only one module") {
		t.Fatalf("error = %v, want one-module diagnostic", err)
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

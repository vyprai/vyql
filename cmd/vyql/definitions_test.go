package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefinitionsShowPolicyDefault(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"show-policy", "resultIdentity.default"})
	})
	if err != nil {
		t.Fatalf("show-policy: %v", err)
	}
	for _, want := range []string{
		"policy resultIdentity.default",
		"source: policies/core.vyql",
		"findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]",
		"stableAcross: [formatting, requirementDiagnosticText, traversalOrder]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show-policy output missing %q:\n%s", want, out)
		}
	}
}

func TestDefinitionsShowMechanicBuiltinRuleVerb(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"show-mechanic", "ruleVerb.taint"})
	})
	if err != nil {
		t.Fatalf("show-mechanic: %v", err)
	}
	for _, want := range []string{
		"mechanic ruleVerb.taint",
		"source: <builtin:go>",
		"capability: dataflow.taint",
		"authored: false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("show-mechanic output missing %q:\n%s", want, out)
		}
	}
}

func TestDefinitionsShowPolicyJSON(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"show-policy", "-format", "json", "diagnostic.default"})
	})
	if err != nil {
		t.Fatalf("show-policy json: %v", err)
	}
	var got struct {
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode json: %v\n%s", err, out)
	}
	if got.Kind != "diagnostic" || got.Name != "default" || got.Source != "policies/core.vyql" {
		t.Fatalf("policy json = %+v, want diagnostic.default from policies/core.vyql", got)
	}
}

func TestDefinitionsSearch(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"search", "-kind", "concepts", "-limit", "5", "SqlParameterization"})
	})
	if err != nil {
		t.Fatalf("definitions search: %v", err)
	}
	if !strings.Contains(out, "core.SqlParameterization") {
		t.Fatalf("search output missing core.SqlParameterization:\n%s", out)
	}
}

func TestDefinitionsRefs(t *testing.T) {
	dir := t.TempDir()
	writeTestVYQL(t, dir, "core.vyql", `
module core;
concept SqlParameterization : check {}
`)
	writeTestVYQL(t, dir, "rules.vyql", `
module rules.injection;
rule SqlInjection {
  taint code.HttpInput as input -> code.SqlExecution as sql
  unless sql.path coveredBy core.SqlParameterization
}
`)
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"refs", "-in", dir, "core.SqlParameterization"})
	})
	if err != nil {
		t.Fatalf("definitions refs: %v", err)
	}
	for _, want := range []string{
		"refs core.SqlParameterization: 1",
		"rule SqlInjection",
		"unless.concept =core.SqlParameterization",
		"rules.vyql",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("refs output missing %q:\n%s", want, out)
		}
	}
}

func TestDefinitionsValidate(t *testing.T) {
	dir := t.TempDir()
	writeTestVYQL(t, dir, "core.vyql", `
module core;
concept HttpInput : source {}
`)
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"validate", dir})
	})
	if err != nil {
		t.Fatalf("definitions validate: %v", err)
	}
	if !strings.Contains(out, "validated 1 v2 definition file(s)") {
		t.Fatalf("validate output wrong:\n%s", out)
	}
}

func TestDefinitionsInspectV2(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"-kind", "concepts", "-query", "SqlParameterization", "-limit", "5"})
	})
	if err != nil {
		t.Fatalf("definitions inspect: %v", err)
	}
	for _, want := range []string{
		"VyQL definitions:",
		"== concepts",
		"core.SqlParameterization",
		"kind=check",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect output missing %q:\n%s", want, out)
		}
	}
}

func TestDefinitionsExplainBinding(t *testing.T) {
	dir := t.TempDir()
	writeTestVYQL(t, dir, "concepts.vyql", `
module core;
concept HttpInput : source {}
concept SqlExecution : sink {}
concept SqlParameterization : check { neutralizes: [SqlInjection] }
`)
	writeTestVYQL(t, dir, "bindings.vyql", `
module bindings.python.dbapi;
binding cursorExecute {
  query pattern callExpr where callee.method == "execute"
  emit sink core.SqlExecution at args[0]
}
binding parameterizedQuery {
  requires { dependency("psycopg2") }
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	writeTestVYQL(t, dir, "rules.vyql", `
module rules.injection;
rule SqlInjection {
  meta { id: "py.sqli" }
  taint core.HttpInput as input -> core.SqlExecution as sql
  unless sql.path coveredBy core.SqlParameterization
}
`)

	// Explain a binding by name: shows its pattern, dependency predicate, emits.
	out, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"explain", "-in", dir, "parameterizedQuery"})
	})
	if err != nil {
		t.Fatalf("explain binding: %v", err)
	}
	for _, want := range []string{
		"explain parameterizedQuery",
		"resolves to: binding",
		"parameterizedQuery [named]",
		"pattern: callExpr",
		"depends_on: dependency(\"psycopg2\")",
		"check core.SqlParameterization",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain binding output missing %q:\n%s", want, out)
		}
	}

	// Explain a concept: shows the model concept, the emitting bindings, and the
	// rules that consume it.
	conceptOut, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"explain", "-in", dir, "-format", "json", "core.SqlParameterization"})
	})
	if err != nil {
		t.Fatalf("explain concept: %v", err)
	}
	var view explainView
	if err := json.Unmarshal([]byte(conceptOut), &view); err != nil {
		t.Fatalf("decode explain json: %v\n%s", err, conceptOut)
	}
	if view.Concept == nil || view.Concept.Name != "core.SqlParameterization" {
		t.Fatalf("explain concept missing model concept: %+v", view.Concept)
	}
	if len(view.Concept.Neutralizes) == 0 {
		t.Fatalf("explain concept should surface neutralizes: %+v", view.Concept)
	}
	foundEmitter := false
	for _, b := range view.Bindings {
		if b.Name == "parameterizedQuery" && b.Role == "emitter" {
			foundEmitter = true
		}
	}
	if !foundEmitter {
		t.Fatalf("explain concept should list emitting binding, got %+v", view.Bindings)
	}
	foundRule := false
	for _, r := range view.Rules {
		if r.Name == "SqlInjection" {
			foundRule = true
		}
	}
	if !foundRule {
		t.Fatalf("explain concept should list consuming rule, got %+v", view.Rules)
	}
}

func TestDefinitionsExplainUnknownErrors(t *testing.T) {
	dir := t.TempDir()
	writeTestVYQL(t, dir, "concepts.vyql", "module core;\nconcept HttpInput : source {}\n")
	_, err := captureStdout(t, func() error {
		return cmdDefinitions([]string{"explain", "-in", dir, "core.NoSuchConcept"})
	})
	if err == nil {
		t.Fatal("explain on an unknown target should error")
	}
}

func writeTestVYQL(t *testing.T, dir, name, src string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

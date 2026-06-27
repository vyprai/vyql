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
		return cmdDefinitions([]string{"search", "-kind", "concepts", "-max", "5", "SqlParameterization"})
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
		return cmdDefinitions([]string{"validate", "-in", dir})
	})
	if err != nil {
		t.Fatalf("definitions validate: %v", err)
	}
	if !strings.Contains(out, "validated 1 v2 definition file(s)") {
		t.Fatalf("validate output wrong:\n%s", out)
	}
}

func writeTestVYQL(t *testing.T, dir, name, src string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

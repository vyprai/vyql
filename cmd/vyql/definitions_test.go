package main

import (
	"encoding/json"
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

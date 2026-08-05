package main

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/findings"
)

func TestParseFailOnDefaultsToNoGating(t *testing.T) {
	for _, v := range []string{"", "none", "NONE", "  none  "} {
		rank, err := parseFailOn(v)
		if err != nil {
			t.Fatalf("parseFailOn(%q) errored: %v", v, err)
		}
		if rank != 0 {
			t.Errorf("parseFailOn(%q) = %d, want 0 (gating off)", v, rank)
		}
	}
}

// Dropping the scanner into a pipeline must gate that pipeline. If this default
// ever moves back to "none", a CI user gets a green build over CRITICAL findings
// and nothing tells them.
func TestDefaultFailOnGatesOnHigh(t *testing.T) {
	rank, err := parseFailOn(defaultFailOn)
	if err != nil {
		t.Fatalf("the default %q is not a valid -fail-on: %v", defaultFailOn, err)
	}
	if rank == 0 {
		t.Fatalf("the default %q disables gating", defaultFailOn)
	}
	all := []*findings.Finding{{Severity: "medium"}, {Severity: "high"}, {Severity: "critical"}}
	n, highest := gateFindings(all, rank)
	if n != 2 {
		t.Errorf("default gate matched %d finding(s), want 2 (high + critical)", n)
	}
	if highest != "critical" {
		t.Errorf("highest = %q, want critical", highest)
	}
	// Nothing at or above the threshold must not gate.
	if n, _ := gateFindings([]*findings.Finding{{Severity: "medium"}}, rank); n != 0 {
		t.Errorf("default gate matched %d medium finding(s), want 0", n)
	}
}

func TestParseFailOnOrdersSeverities(t *testing.T) {
	var last int
	for _, name := range severityOrder {
		rank, err := parseFailOn(name)
		if err != nil {
			t.Fatalf("parseFailOn(%q) errored: %v", name, err)
		}
		if rank <= last {
			t.Errorf("parseFailOn(%q) = %d, not above the previous %d", name, rank, last)
		}
		last = rank
	}
}

func TestParseFailOnRejectsUnknownAndNamesTheOptions(t *testing.T) {
	_, err := parseFailOn("bogus")
	if err == nil {
		t.Fatal("parseFailOn(\"bogus\") returned no error")
	}
	// The message has to carry the options: a rejected flag with no way to
	// discover the right value just moves the guesswork.
	for _, want := range severityOrder {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestGateFindingsCountsAtOrAboveThreshold(t *testing.T) {
	all := []*findings.Finding{
		{Severity: "info"},
		{Severity: "medium"},
		{Severity: "high"},
		{Severity: "critical"},
	}
	high, _ := parseFailOn("high")
	n, highest := gateFindings(all, high)
	if n != 2 {
		t.Errorf("count = %d, want 2 (high + critical)", n)
	}
	if highest != "critical" {
		t.Errorf("highest = %q, want critical", highest)
	}

	crit, _ := parseFailOn("critical")
	if n, _ := gateFindings(all, crit); n != 1 {
		t.Errorf("count at critical = %d, want 1", n)
	}
}

// A severity outside the known set must not gate a build: failing someone's
// pipeline on a value the tool does not understand is worse than not gating.
func TestGateFindingsIgnoresUnknownSeverity(t *testing.T) {
	all := []*findings.Finding{{Severity: "catastrophic"}, {Severity: ""}}
	low, _ := parseFailOn("info")
	if n, _ := gateFindings(all, low); n != 0 {
		t.Errorf("count = %d, want 0 for unrecognised severities", n)
	}
}

func TestThresholdMetCarriesExitCodeAndCounts(t *testing.T) {
	e := &thresholdMet{code: 3, count: 2, highest: "critical", failOn: "high"}
	if e.code != 3 {
		t.Errorf("code = %d, want 3", e.code)
	}
	msg := e.Error()
	for _, want := range []string{"2 finding(s)", "high", "critical"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not mention %q", msg, want)
		}
	}
}

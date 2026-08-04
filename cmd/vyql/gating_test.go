package main

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/findings"
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

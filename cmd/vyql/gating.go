package main

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/findings"
)

// Severity ordering for -fail-on, lowest first. These are the severities rules
// carry; a finding whose severity is outside this set never gates a build,
// because silently failing someone's pipeline on an unrecognised value is worse
// than not gating at all.
var severityOrder = []string{"info", "low", "medium", "high", "critical"}

func severityRank(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, name := range severityOrder {
		if name == s {
			return i + 1
		}
	}
	return 0
}

// parseFailOn resolves -fail-on to a minimum rank. "none" -- the default --
// disables gating, which is why a plain `vyql scan` exits 0 even with critical
// findings: a scanner that fails a build by default breaks every pipeline that
// adds it. Opting in is a deliberate act.
func parseFailOn(v string) (int, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "none" {
		return 0, nil
	}
	if r := severityRank(v); r > 0 {
		return r, nil
	}
	return 0, fmt.Errorf("unknown -fail-on %q; use none | %s", v, strings.Join(severityOrder, " | "))
}

// gateFindings reports how many findings sit at or above the threshold, and the
// highest severity among them.
func gateFindings(all []*findings.Finding, minRank int) (count int, highest string) {
	best := 0
	for _, f := range all {
		r := severityRank(f.Severity)
		if r >= minRank && r > 0 {
			count++
			if r > best {
				best = r
			}
		}
	}
	if best > 0 {
		highest = severityOrder[best-1]
	}
	return count, highest
}

// thresholdMet reports a successful scan whose findings met -fail-on. It is not
// a failure of the tool, so main prints it without the diagnostic prefix it
// gives real errors, and exits with the status -exit-code asked for.
type thresholdMet struct {
	code    int
	count   int
	highest string
	failOn  string
}

func (e *thresholdMet) Error() string {
	return fmt.Sprintf("%d finding(s) at or above %s (highest: %s)", e.count, e.failOn, e.highest)
}

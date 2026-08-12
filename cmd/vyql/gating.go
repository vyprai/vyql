package main

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/findings"
)

// Severity ordering for -fail-on, lowest first. These are the severities rules
// carry; a finding whose severity is outside this set never gates a build,
// because silently failing someone's pipeline on an unrecognised value is worse
// than not gating at all.
var severityOrder = []string{"info", "low", "medium", "high", "critical"}

// baselineFailOn is the threshold a run gates on when it applies a baseline and
// -fail-on was not given.
//
// A baseline changes the question. Without one the scan asks "is anything in this
// code wrong", and a severity floor is how a team declines to fix the long tail.
// With one it asks "did this change add anything", and every addition counts: a
// new medium is a regression this branch introduced, not part of the backlog
// somebody already accepted.
//
// Keeping the plain default there passes the build on exactly those findings,
// while the report above it lists them. An explicit -fail-on still wins, so a
// pipeline that wants only new criticals asks for that.
const baselineFailOn = "info"

// gateForBaseline resolves the threshold for a run that applies a baseline. It is
// the caller's rank unless -fail-on was left unset.
func gateForBaseline(rank int, name string, explicit bool) (int, string) {
	if explicit {
		return rank, name
	}
	return severityRank(baselineFailOn), baselineFailOn
}

// defaultFailOn is the threshold a plain `vyql scan` gates on. Dropping the
// scanner into a pipeline should gate that pipeline without further
// configuration; `-fail-on none` opts back out.
const defaultFailOn = "high"

func severityRank(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, name := range severityOrder {
		if name == s {
			return i + 1
		}
	}
	return 0
}

// parseFailOn resolves -fail-on to a minimum rank. "none" disables gating and
// returns 0; the default is "high", so a plain `vyql scan` exits non-zero on a
// HIGH or CRITICAL finding. A pipeline that wants the report without the gate
// asks for `-fail-on none` explicitly.
func parseFailOn(v string) (int, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "none" {
		return 0, nil
	}
	if r := severityRank(v); r > 0 {
		return r, nil
	}
	return 0, usageWith(fmt.Sprintf("unknown -fail-on %q", v),
		"valid: none | "+strings.Join(severityOrder, " | "))
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

// thresholdMet reports a successful scan whose findings met -fail-on. It is not a
// failure of the tool, so it carries no diagnostic prefix and exits 3 -- the code
// for a check that ran and did not pass, which a pipeline can tell apart from the
// scanner having been unable to run.
func thresholdMet(count int, failOn, highest string) error {
	return checkFailedf("%d finding(s) at or above %s (highest: %s)", count, failOn, highest)
}

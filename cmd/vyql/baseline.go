package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/findings"
)

// Triage is expensive and, without somewhere to record it, worthless the moment
// the scan ends: the next run reports the same findings and the reasoning is
// gone. A baseline is that record, keyed on the finding fingerprint -- which is
// anchored to rule and location rather than line number, so a verdict survives
// edits elsewhere in the file.

// Verdicts a baseline entry may carry. They are not the same claim and should
// not be recorded as if they were: one says the finding is wrong, the other says
// it is right and accepted anyway.
const (
	verdictFalsePositive = "false-positive"
	verdictAccepted      = "accepted"
)

var baselineVerdicts = []string{verdictFalsePositive, verdictAccepted}

type baselineEntry struct {
	FP      string `json:"fp"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// Rule and Loc are for the human reading the file. Matching is on FP alone,
	// so these going stale costs nothing.
	Rule string `json:"rule,omitempty"`
	Loc  string `json:"loc,omitempty"`
}

type baselineFile struct {
	Version int             `json:"version"`
	Entries []baselineEntry `json:"entries"`
}

const baselineVersion = 1

// loadBaseline reads and validates a baseline. An unreadable or malformed
// baseline is an error rather than an empty one: silently treating it as "no
// suppressions" turns a typo in a path into a wall of findings the user thought
// they had triaged, and silently treating it as "suppress everything" is worse.
func loadBaseline(path string) (map[string]baselineEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	var bf baselineFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if bf.Version != baselineVersion {
		return nil, fmt.Errorf("baseline %s: version %d, this build understands %d",
			path, bf.Version, baselineVersion)
	}
	out := make(map[string]baselineEntry, len(bf.Entries))
	for i, e := range bf.Entries {
		if strings.TrimSpace(e.FP) == "" {
			return nil, fmt.Errorf("baseline %s: entry %d has no fp", path, i)
		}
		if !validVerdict(e.Verdict) {
			return nil, fmt.Errorf("baseline %s: entry %s has verdict %q; use %s",
				path, e.FP, e.Verdict, strings.Join(baselineVerdicts, " | "))
		}
		out[e.FP] = e
	}
	return out, nil
}

func validVerdict(v string) bool {
	for _, ok := range baselineVerdicts {
		if v == ok {
			return true
		}
	}
	return false
}

// applyBaseline splits findings into those still to report and those a verdict
// already covers, and names baseline entries that matched nothing.
//
// The stale list is the part that keeps a baseline honest. A suppression that
// outlives the code it excused is how these files become dangerous: the code
// moved, the excuse did not, and nobody looked again.
func applyBaseline(all []*findings.Finding, base map[string]baselineEntry) (report []*findings.Finding, covered []*findings.Finding, stale []baselineEntry) {
	seen := map[string]bool{}
	for _, f := range all {
		fp := f.Fingerprint()
		if _, ok := base[fp]; ok {
			seen[fp] = true
			covered = append(covered, f)
			continue
		}
		report = append(report, f)
	}
	for fp, e := range base {
		if !seen[fp] {
			stale = append(stale, e)
		}
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].FP < stale[j].FP })
	return report, covered, stale
}

// printBaselineSummary states what the baseline did. A run that quietly drops
// findings is indistinguishable from a run that found nothing.
func printBaselineSummary(path string, covered []*findings.Finding, stale []baselineEntry) {
	if len(covered) > 0 {
		fmt.Printf("baseline %s: %d finding(s) already triaged and not reported\n", path, len(covered))
	}
	if len(stale) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %d baseline entr%s match nothing in this scan\n",
		len(stale), plural(len(stale), "y", "ies"))
	fmt.Fprintln(os.Stderr, "         the code they excused may have changed; re-triage or remove them:")
	for i, e := range stale {
		if i == 5 {
			fmt.Fprintf(os.Stderr, "         ... and %d more\n", len(stale)-5)
			break
		}
		where := e.Loc
		if where == "" {
			where = "(no location recorded)"
		}
		fmt.Fprintf(os.Stderr, "           %s  %s  %s\n", e.FP, e.Rule, where)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// writeBaseline records every current finding as accepted, which is how a team
// adopts the scanner on a codebase that already has findings: take the backlog
// as given, and fail only on what comes next. Reasons are left empty on purpose
// -- a reason nobody wrote is better left visibly blank than auto-filled with
// something that reads like judgment.
func writeBaseline(path string, all []*findings.Finding) error {
	bf := baselineFile{Version: baselineVersion}
	for _, f := range all {
		loc := ""
		if len(f.Bindings) > 0 {
			loc = f.Bindings[len(f.Bindings)-1].Loc
		}
		bf.Entries = append(bf.Entries, baselineEntry{
			FP:      f.Fingerprint(),
			Verdict: verdictAccepted,
			Rule:    f.RuleID,
			Loc:     loc,
		})
	}
	sort.Slice(bf.Entries, func(i, j int) bool { return bf.Entries[i].FP < bf.Entries[j].FP })
	b, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d finding(s) recorded as %q\n", path, len(bf.Entries), verdictAccepted)
	fmt.Fprintln(os.Stderr, "each entry has an empty reason; fill them in as they are triaged")
	return nil
}

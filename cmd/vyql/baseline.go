package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/graphjson"
	"github.com/vyprai/vyql/internal/resultpolicy"
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
	// Sig lists the path signatures this entry was triaged against (adr/0004).
	// An entry with sigs suppresses only a finding whose witness still hashes
	// to one of them; the same fingerprint on a new path re-fires as drifted
	// and goes back to verification. Empty means legacy behaviour: the verdict
	// is anchored to the finding alone and never drifts.
	Sig []string `json:"sig,omitempty"`
	// Rule and Loc are for the human reading the file. Matching is on FP (and
	// Sig when present), so these going stale costs nothing.
	Rule string `json:"rule,omitempty"`
	Loc  string `json:"loc,omitempty"`
}

type baselineFile struct {
	Version int             `json:"version"`
	Entries []baselineEntry `json:"entries"`
}

// Version 2 changed what a fingerprint is: entries are keyed on the identity policy declared in
// vyql/policies (rule id + primary target location + concept) rather than on a hash of every
// binding's name and location. A v1 file's keys cannot match, and silently matching nothing would
// un-suppress a whole triaged backlog with no explanation -- so loadBaseline rejects it and says
// how to migrate.
const baselineVersion = 2

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
		if bf.Version == 1 {
			return nil, fmt.Errorf("baseline %s: version 1 is keyed on the old fingerprint and cannot match; "+
				"re-record it with -baseline-write after reviewing the current findings", path)
		}
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
		for _, sig := range e.Sig {
			if !validSignature(sig) {
				return nil, fmt.Errorf("baseline %s: entry %s has malformed path signature %q; "+
					"signatures are 16 hex characters copied from a scan's graph-json sig field", path, e.FP, sig)
			}
		}
		out[e.FP] = e
	}
	return out, nil
}

// resolvePath is the strongest identity available for a path that may not exist
// yet. A record target routinely does not, and EvalSymlinks fails on a missing
// file, so an absolute cleaned path is the fallback.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

func sameFile(a, b string) bool { return resolvePath(a) == resolvePath(b) }

// checkBaselineFlags rejects recording a baseline onto the one being applied.
//
// Recording writes every current finding as accepted with an empty reason. Onto
// the file being applied, that replaces the false-positive verdicts someone
// triaged and the reasoning behind them with a blank acceptance, and the run
// that did it exits 0. Recording to a different path is how a baseline is rolled
// forward, and stays allowed.
func checkBaselineFlags(baseline, baselineWrite string) error {
	if baseline == "" || baselineWrite == "" {
		return nil
	}
	if !sameFile(baseline, baselineWrite) {
		return nil
	}
	return fmt.Errorf("-baseline and -baseline-write both name %s: recording writes every finding as "+
		"accepted with an empty reason, which would overwrite the verdicts in it; "+
		"record to a different path and diff it", baseline)
}

func validVerdict(v string) bool {
	for _, ok := range baselineVerdicts {
		if v == ok {
			return true
		}
	}
	return false
}

// validSignature accepts exactly the shape resultpolicy.PathSignature emits:
// 16 lowercase hex characters, like the fingerprint itself. Anything else in
// a hand-edited file is a typo that would silently never match — the wall of
// findings that follows is worse than refusing to run.
func validSignature(sig string) bool {
	if len(sig) != 16 {
		return false
	}
	for _, r := range sig {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// applyBaseline splits findings into those still to report and those a verdict
// already covers, names baseline entries that matched nothing, and names the
// findings whose fingerprint matched but whose path did not.
//
// The stale list is the part that keeps a baseline honest. A suppression that
// outlives the code it excused is how these files become dangerous: the code
// moved, the excuse did not, and nobody looked again. Drifted is the other
// half of that honesty, pointed the other way: the code under the finding
// changed enough that the recorded verdict may no longer describe it, so the
// finding is reported again and the entry's fingerprint is returned for the
// re-verify list.
func applyBaseline(all []*findings.Finding, base map[string]baselineEntry) (report []*findings.Finding, covered []*findings.Finding, stale []baselineEntry, drifted []string) {
	matched := map[string]bool{}
	for _, f := range all {
		fp := resultpolicy.Fingerprint(f)
		e, ok := base[fp]
		if ok && entryCovers(e, f) {
			matched[fp] = true
			covered = append(covered, f)
			continue
		}
		if ok {
			matched[fp] = true
			drifted = append(drifted, fp)
		}
		report = append(report, f)
	}
	for fp, e := range base {
		if !matched[fp] {
			stale = append(stale, e)
		}
	}
	sort.Strings(drifted)
	sort.Slice(stale, func(i, j int) bool { return stale[i].FP < stale[j].FP })
	return report, covered, stale, drifted
}

// entryCovers is the whole suppression rule: the fingerprint must match, and
// if the entry carries path signatures the finding's must be one of them. A
// sig-carrying entry never covers a finding without a signature — that is a
// different witness under the same fingerprint, which is drift, not cover.
func entryCovers(e baselineEntry, f *findings.Finding) bool {
	if len(e.Sig) == 0 {
		return true
	}
	for _, sig := range e.Sig {
		if sig != "" && sig == f.Sig {
			return true
		}
	}
	return false
}

// printBaselineSummary states what the baseline did. A run that quietly drops
// findings is indistinguishable from a run that found nothing.
func printBaselineSummary(path string, covered []*findings.Finding, stale []baselineEntry, drifted []string) {
	if len(covered) > 0 {
		fmt.Printf("baseline %s: %d finding(s) already triaged and not reported\n", path, len(covered))
	}
	if len(drifted) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d triaged finding(s) re-reported: the taint path under them changed\n",
			len(drifted))
		fmt.Fprintln(os.Stderr, "         the recorded verdict may no longer describe them; re-triage to record the new path:")
		for i, fp := range drifted {
			if i == 5 {
				fmt.Fprintf(os.Stderr, "         ... and %d more\n", len(drifted)-5)
				break
			}
			fmt.Fprintf(os.Stderr, "           %s  vyql triage add -fp %s ...\n", fp, fp)
		}
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

// baselineSection is the machine-readable form of printBaselineSummary: what a
// consumer of graph-json needs to keep triage records alive (covered), archive
// them (stale) and re-verify them (drifted) without parsing stderr (adr/0004 §5).
func baselineSection(applied int, covered []*findings.Finding, stale []baselineEntry, drifted []string) *graphjson.BaselineSection {
	cov := make([]string, 0, len(covered))
	for _, f := range covered {
		cov = append(cov, resultpolicy.Fingerprint(f))
	}
	sort.Strings(cov)
	st := make([]string, 0, len(stale))
	for _, e := range stale {
		st = append(st, e.FP)
	}
	// already sorted by applyBaseline
	if drifted == nil {
		drifted = []string{}
	}
	if cov == nil {
		cov = []string{}
	}
	if st == nil {
		st = []string{}
	}
	return &graphjson.BaselineSection{Applied: applied, Covered: cov, Drifted: drifted, Stale: st}
}

// writeBaseline records the findings a run is prepared to carry forward, which
// is how a team adopts the scanner on a codebase that already has findings: take
// the backlog as given, and fail only on what comes next. Reasons are left empty
// on purpose -- a reason nobody wrote is better left visibly blank than
// auto-filled with something that reads like judgment.
//
// prior is the baseline this run applied, if any. Its entries keep their verdict
// and reason, so a roll forward does not flatten someone's triaged
// false-positive into a blank acceptance one push at a time. Entries in prior
// that no current finding matches are simply absent from the result, which is
// how a rolled baseline sheds suppressions whose code is gone.
//
// failOnRank is the gate, and 0 means record everything. A finding new to this
// run that meets the gate is left out: recording what just failed the build
// would leave the next run green with the finding absorbed and nobody told.
// Findings already in prior are exempt, because the gate never saw them.
func writeBaseline(path string, all []*findings.Finding, prior map[string]baselineEntry, failOnRank int) error {
	bf := baselineFile{Version: baselineVersion}
	for _, f := range all {
		fp := resultpolicy.Fingerprint(f)
		loc := ""
		if len(f.Bindings) > 0 {
			loc = f.Bindings[len(f.Bindings)-1].Loc
		}
		e := baselineEntry{FP: fp, Verdict: verdictAccepted, Rule: f.RuleID, Loc: loc}
		if f.Sig != "" {
			// Record the path the acceptance was made against, so the acceptance
			// drifts like a triaged verdict would: still honoured while the path
			// holds, re-reported when it changes.
			e.Sig = []string{f.Sig}
		}
		if p, ok := prior[fp]; ok {
			e.Verdict, e.Reason, e.Sig = p.Verdict, p.Reason, p.Sig
		} else if failOnRank > 0 && severityRank(f.Severity) >= failOnRank {
			continue
		}
		bf.Entries = append(bf.Entries, e)
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
	fmt.Fprintf(os.Stderr, "wrote %s: %d finding(s) recorded\n", path, len(bf.Entries))
	if held := len(all) - len(bf.Entries); held > 0 {
		fmt.Fprintf(os.Stderr, "%d new finding(s) at or above the gate were not recorded; "+
			"fix them or triage them into the baseline by hand\n", held)
	}
	fmt.Fprintln(os.Stderr, "newly recorded entries have an empty reason; fill them in as they are triaged")
	return nil
}

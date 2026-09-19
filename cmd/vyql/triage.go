package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/graphjson"
)

// Triage is how a verdict recorded outside a scan gets back into one. The
// platform records verdicts in its database and materializes a baseline for
// each scan; a CLI user records them here, into the same file format with the
// same matching semantics (adr/0004). One workflow, two storage backends, and
// a baseline produced by either suppresses identically.
//
// `triage add` unions path signatures rather than replacing them: after a
// drift re-fires and is re-verified as benign, the entry carries both paths,
// so representative-path churn in the solver cannot keep resurrecting it.

func cmdTriage(args []string) error {
	// The subcommand is pulled out before flag parsing, so
	// `triage add -fp ...` works; flag.Parse stops at the first non-flag
	// argument and would silently ignore every flag after it.
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "add":
		return triageAdd(args)
	case "remove":
		return triageRemove(args)
	case "list":
		return triageList(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: vyql triage <add|remove|list> [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  add      record a verdict against a finding fingerprint, optionally")
		fmt.Fprintln(os.Stderr, "           capturing its taint-path signature from a scan's graph-json")
		fmt.Fprintln(os.Stderr, "  remove   drop an entry (e.g. one the scan reports as stale)")
		fmt.Fprintln(os.Stderr, "  list     print the baseline's entries")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "flags common to every subcommand:")
		fmt.Fprintln(os.Stderr, "  -baseline <file>   the triage list to operate on")
		if sub == "" {
			return &usageError{msg: "triage needs a subcommand: add | remove | list"}
		}
		return &usageError{msg: "unknown triage subcommand " + sub}
	}
}

func triageAdd(args []string) error {
	fs := newFlagSet("triage add")
	fp := fs.String("fp", "", "finding fingerprint, as printed by scan reports and graph-json")
	baselinePath := fs.String("baseline", "", "the triage list to add to (created if absent)")
	verdict := fs.String("verdict", verdictFalsePositive, "what this finding is: "+strings.Join(baselineVerdicts, " | "))
	reason := fs.String("reason", "", "why; read by the next person who wonders why this is quiet")
	from := fs.String("from", "", "graph-json output of a scan of this finding, to capture its path signature")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*fp) == "" || *baselinePath == "" {
		return &usageError{msg: "triage add needs -fp and -baseline"}
	}
	if !validVerdict(*verdict) {
		return &usageError{msg: fmt.Sprintf("verdict %q is not one of %s", *verdict, strings.Join(baselineVerdicts, " | "))}
	}
	// A baseline that does not exist yet is not an error here: the first
	// triage on a codebase should not require hand-creating a file. Reading
	// one that exists but is malformed still is -- see loadBaseline.
	entries := map[string]baselineEntry{}
	if _, err := os.Stat(*baselinePath); err == nil {
		entries, err = loadBaseline(*baselinePath)
		if err != nil {
			return err
		}
	}

	e := baselineEntry{FP: strings.TrimSpace(*fp), Verdict: *verdict, Reason: *reason}
	if prior, ok := entries[e.FP]; ok {
		// The sig list is the one field carried over: a re-triage after drift
		// is a new verdict about a new path, and both paths stay suppressed.
		e.Sig = prior.Sig
		e.Rule, e.Loc = prior.Rule, prior.Loc
	}
	if *from != "" {
		f, err := findingFromGraphJSON(*from, e.FP)
		if err != nil {
			return err
		}
		if f.Sig != "" && !containsString(e.Sig, f.Sig) {
			e.Sig = append(e.Sig, f.Sig)
		}
		if f.Rule != "" {
			e.Rule = f.Rule
		}
		if f.Loc != "" {
			e.Loc = f.Loc
		}
	}
	entries[e.FP] = e
	if err := writeBaselineEntries(*baselinePath, entries); err != nil {
		return err
	}
	how := ""
	if len(e.Sig) > 0 {
		how = fmt.Sprintf(" with %d path signature(s)", len(e.Sig))
	}
	fmt.Fprintf(os.Stderr, "triaged %s as %s in %s%s\n", e.FP, e.Verdict, *baselinePath, how)
	return nil
}

func triageRemove(args []string) error {
	fs := newFlagSet("triage remove")
	fp := fs.String("fp", "", "fingerprint of the entry to remove")
	stale := fs.Bool("stale", false, "remove every entry the -from scan reports as stale (the code it excused is gone)")
	from := fs.String("from", "", "graph-json output of a scan, to decide what is stale")
	baselinePath := fs.String("baseline", "", "the triage list to remove from")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stale {
		return triageRemoveStale(*from, *baselinePath)
	}
	if strings.TrimSpace(*fp) == "" || *baselinePath == "" {
		return &usageError{msg: "triage remove needs -fp and -baseline (or -stale with -from)"}
	}
	entries, err := loadBaseline(*baselinePath)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(*fp)
	if _, ok := entries[key]; !ok {
		// Refusing beats quietly succeeding: a typo'd fingerprint would leave
		// the reader believing an entry is gone that never was.
		return fmt.Errorf("triage remove: %s is not in %s", key, *baselinePath)
	}
	delete(entries, key)
	if err := writeBaselineEntries(*baselinePath, entries); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed %s from %s\n", key, *baselinePath)
	return nil
}

// triageRemoveStale drops every entry the scan says matches nothing. The same
// semantic a rolled baseline applies on its own ("does not keep suppressions
// for code that is gone"), on demand: point it at the scan you just ran with
// this baseline, and the verdicts whose findings no longer fire leave the file.
// What was removed is printed, because a cleanup that silently edits N lines of
// a committed file is a review burden; naming them makes the diff checkable.
func triageRemoveStale(from, baselinePath string) error {
	if from == "" || baselinePath == "" {
		return &usageError{msg: "triage remove -stale needs -from <scan.graph.json> and -baseline: " +
			"stale means a finding no longer fires, and without a scan that is a guess, " +
			"not a fact"}
	}
	entries, err := loadBaseline(baselinePath)
	if err != nil {
		return err
	}
	ref, err := loadScanRef(from)
	if err != nil {
		return err
	}
	removed := make([]string, 0)
	for _, fp := range sortedEntryKeys(entries) {
		if entryState(fp, ref) == triageStale {
			removed = append(removed, fp)
			delete(entries, fp)
		}
	}
	if len(removed) == 0 {
		fmt.Fprintf(os.Stderr, "no stale entries in %s (against %s); nothing removed\n", baselinePath, from)
		return nil
	}
	if err := writeBaselineEntries(baselinePath, entries); err != nil {
		return err
	}
	for _, fp := range removed {
		fmt.Fprintf(os.Stderr, "removed %s from %s\n", fp, baselinePath)
	}
	fmt.Fprintf(os.Stderr, "removed %d stale entr%s; the code they excused is gone\n",
		len(removed), plural(len(removed), "y", "ies"))
	return nil
}

func triageList(args []string) error {
	fs := newFlagSet("triage list")
	baselinePath := fs.String("baseline", ".vyql-baseline.json", "the triage list to print")
	from := fs.String("from", "", "graph-json output of a scan (ideally run with -baseline): marks each entry covered, drifted, reported or stale")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	entries, err := loadBaseline(*baselinePath)
	if err != nil {
		return err
	}
	var ref *scanRef
	if *from != "" {
		if ref, err = loadScanRef(*from); err != nil {
			return err
		}
	}
	counts := map[string]int{}
	for _, fp := range sortedEntryKeys(entries) {
		e := entries[fp]
		sig := ""
		if len(e.Sig) > 0 {
			sig = fmt.Sprintf(" sig=%d", len(e.Sig))
		}
		state := ""
		if ref != nil {
			state = entryState(fp, ref)
			counts[state]++
			state = "  [" + state + "]"
		}
		fmt.Printf("%s  %-13s %s%s%s\n", fp, e.Verdict, e.locLabel(), sig, state)
		if e.Reason != "" {
			fmt.Printf("    %s\n", e.Reason)
		}
	}
	if len(entries) == 0 {
		fmt.Printf("%s has no entries\n", *baselinePath)
		return nil
	}
	if ref != nil {
		fmt.Printf("%d entr%s against %s: %d covered, %d drifted, %d reported, %d stale\n",
			len(entries), plural(len(entries), "y", "ies"), *from,
			counts[triageCovered], counts[triageDrifted], counts[triageReported], counts[triageStale])
		if counts[triageStale] > 0 {
			fmt.Printf("drop the stale ones: vyql triage remove -stale -baseline %s -from %s\n",
				*baselinePath, *from)
		}
	}
	return nil
}

func (e baselineEntry) locLabel() string {
	switch {
	case e.Rule != "" && e.Loc != "":
		return e.Rule + " " + e.Loc
	case e.Rule != "":
		return e.Rule
	case e.Loc != "":
		return e.Loc
	default:
		return "(no rule or location recorded; triage add -from records them)"
	}
}

// Entry states against a scan (triageStale is the one remove -stale acts on).
const (
	triageCovered  = "covered"  // suppressed by this scan: verdict still applies
	triageDrifted  = "drifted"  // same fp, new path: re-reported, re-triage
	triageStale    = "stale"    // matches nothing: the code it excused is gone
	triageReported = "reported" // fingerprint is in the findings but this scan did not apply this entry
)

// scanRef is what a baseline entry is judged against: the fingerprints a scan
// reported, and — when that scan ran with -baseline — vyql's own accounting of
// what the applied file did.
type scanRef struct {
	findingFPs map[string]bool
	section    *graphjson.BaselineSection
}

func loadGraphJSONDoc(path, flag string) (graphjson.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return graphjson.Document{}, fmt.Errorf("triage %s: %w", flag, err)
	}
	var doc graphjson.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return graphjson.Document{}, fmt.Errorf("triage %s %s: not graph-json (%w)", flag, path, err)
	}
	return doc, nil
}

func loadScanRef(path string) (*scanRef, error) {
	doc, err := loadGraphJSONDoc(path, "-from")
	if err != nil {
		return nil, err
	}
	ref := &scanRef{findingFPs: make(map[string]bool, len(doc.Findings)), section: doc.Baseline}
	for _, f := range doc.Findings {
		ref.findingFPs[f.FP] = true
	}
	return ref, nil
}

// entryState names what a scan says about one baseline entry.
//
// With a baseline section (the scan ran with -baseline) the answer is vyql's
// own: covered, drifted or stale. An entry absent from every list was not in
// the file that scan applied — judge it by its fingerprint: reported if the
// finding still fires (the verdict does not cover what is there now), stale if
// nothing fires. Without a section the same fallback decides every entry, and
// "reported" rather than "covered" is the honest word: this scan never
// suppressed anything, so whether the entry's signatures still match is
// something only a -baseline run can say.
func entryState(fp string, ref *scanRef) string {
	if ref.section != nil {
		for _, c := range ref.section.Covered {
			if c == fp {
				return triageCovered
			}
		}
		for _, d := range ref.section.Drifted {
			if d == fp {
				return triageDrifted
			}
		}
		for _, s := range ref.section.Stale {
			if s == fp {
				return triageStale
			}
		}
	}
	if ref.findingFPs[fp] {
		return triageReported
	}
	return triageStale
}

// graphJSONFinding is the slice of graphjson a triage needs: fingerprint,
// signature, rule and where the sink sits.
type graphJSONFinding struct {
	FP   string
	Sig  string
	Rule string
	Loc  string
}

func findingFromGraphJSON(path, fp string) (graphJSONFinding, error) {
	doc, err := loadGraphJSONDoc(path, "add -from")
	if err != nil {
		return graphJSONFinding{}, err
	}
	for _, f := range doc.Findings {
		if f.FP != fp {
			continue
		}
		out := graphJSONFinding{FP: f.FP, Sig: f.Sig, Rule: f.Rule}
		if f.Sink != nil {
			out.Loc = fmt.Sprintf("%s:%d", f.Sink.File, f.Sink.Line)
		}
		return out, nil
	}
	return graphJSONFinding{}, fmt.Errorf("triage add -from %s: no finding with fp %s in that scan; "+
		"the fingerprint is copied from the same output you are triaging", path, fp)
}

// writeBaselineEntries is the canonical writer triage shares with scan's
// -baseline-write: version 2, sorted by fingerprint, one stable shape, so a
// file edited by triage and a file rolled forward by a scan diff cleanly.
func writeBaselineEntries(path string, entries map[string]baselineEntry) error {
	bf := baselineFile{Version: baselineVersion, Entries: make([]baselineEntry, 0, len(entries))}
	for _, e := range entries {
		bf.Entries = append(bf.Entries, e)
	}
	sort.Slice(bf.Entries, func(i, j int) bool { return bf.Entries[i].FP < bf.Entries[j].FP })
	b, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("triage: %w", err)
	}
	return nil
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sortedEntryKeys(m map[string]baselineEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/graphjson"
	"github.com/vyprai/vyql/internal/resultpolicy"
)

func graphJSONScan(t *testing.T, dir string, f graphjson.Finding) string {
	t.Helper()
	p := filepath.Join(dir, "scan.graph.json")
	doc := graphjson.Document{SchemaVersion: graphjson.SchemaVersion, Findings: []graphjson.Finding{f}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func signedScanFinding() graphjson.Finding {
	return graphjson.Finding{
		Rule: "VYQL-INJ-002", Kind: "taint", FP: "aaaa1111aaaa1111", Sig: "bbbb2222bbbb2222",
		Sink: &graphjson.Sink{File: "server.js", Line: 5},
	}
}

// The platform stores verdicts in a database and materializes the file; a CLI
// user records them here. Both must land in the same shape, because both are
// consumed by the same `-baseline` — these tests pin the CLI half of that
// contract (adr/0004 §4, §6).
func TestTriageAddCapturesSignatureFromScan(t *testing.T) {
	dir := t.TempDir()
	from := graphJSONScan(t, dir, signedScanFinding())
	base := filepath.Join(dir, "baseline.json")

	if err := triageAdd([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base, "-from", from, "-reason", "build-time constant"}); err != nil {
		t.Fatal(err)
	}
	entries, err := loadBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := entries["aaaa1111aaaa1111"]
	if !ok {
		t.Fatal("entry not recorded")
	}
	if e.Verdict != verdictFalsePositive {
		t.Errorf("verdict = %q, want the default false-positive", e.Verdict)
	}
	if e.Reason != "build-time constant" {
		t.Errorf("reason = %q", e.Reason)
	}
	if len(e.Sig) != 1 || e.Sig[0] != "bbbb2222bbbb2222" {
		t.Errorf("sigs = %v, want the scan's path signature", e.Sig)
	}
	if e.Rule != "VYQL-INJ-002" || e.Loc != "server.js:5" {
		t.Errorf("rule/loc = %q/%q, want them recorded for the human reading the file", e.Rule, e.Loc)
	}
}

// Re-triaging after a drift joins the new path to the old one instead of
// replacing it: representative-path churn in the solver must not keep
// resurrecting a verdict that was already re-paid (adr/0004 §1).
func TestTriageAddUnionsSignatures(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "baseline.json")
	existing := `{"version":2,"entries":[{"fp":"aaaa1111aaaa1111","verdict":"false-positive",` +
		`"sig":["cccc3333cccc3333"],"rule":"VYQL-INJ-002","loc":"server.js:5"}]}`
	if err := os.WriteFile(base, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	from := graphJSONScan(t, dir, signedScanFinding())

	if err := triageAdd([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base, "-from", from}); err != nil {
		t.Fatal(err)
	}
	entries, err := loadBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	got := entries["aaaa1111aaaa1111"].Sig
	if len(got) != 2 || !containsString(got, "bbbb2222bbbb2222") || !containsString(got, "cccc3333cccc3333") {
		t.Errorf("sigs = %v, want both the old and the new path", got)
	}
}

func TestTriageAddUnknownFpInScanFails(t *testing.T) {
	dir := t.TempDir()
	from := graphJSONScan(t, dir, signedScanFinding())
	base := filepath.Join(dir, "baseline.json")
	err := triageAdd([]string{"-fp", "dddd4444dddd4444", "-baseline", base, "-from", from})
	if err == nil {
		t.Fatal("a fingerprint absent from the -from scan is a typo, not a triage")
	}
	if _, statErr := os.Stat(base); !os.IsNotExist(statErr) {
		t.Error("a failed add must not leave a baseline behind")
	}
}

func TestTriageAddRejectsUnknownVerdict(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if err := triageAdd([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base, "-verdict", "wont-fix"}); err == nil {
		t.Fatal("wont-fix is not a verdict; it is a feeling")
	}
}

func TestTriageRemoveRoundtrip(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if err := triageAdd([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base}); err != nil {
		t.Fatal(err)
	}
	// Removing a fingerprint that is not there refuses rather than succeeding
	// quietly: a typo would leave the reader believing an entry is gone that
	// never was.
	if err := triageRemove([]string{"-fp", "ffff0000ffff0000", "-baseline", base}); err == nil {
		t.Fatal("removing an absent entry must fail")
	}
	if err := triageRemove([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base}); err != nil {
		t.Fatal(err)
	}
	entries, err := loadBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want empty", entries)
	}
}

// The file triage writes is the file scan applies: same version, same shape,
// so a team can triage by hand or by subcommand and never wonder which tool
// owns the format.
func TestTriageWritesCanonicalFile(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if err := triageAdd([]string{"-fp", "bbbb2222bbbb2222", "-baseline", base}); err != nil {
		t.Fatal(err)
	}
	if err := triageAdd([]string{"-fp", "aaaa1111aaaa1111", "-baseline", base}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(string(raw), `"aaaa1111aaaa1111"`)
	second := strings.Index(string(raw), `"bbbb2222bbbb2222"`)
	if first == -1 || second == -1 || first > second {
		t.Error("entries must be sorted by fingerprint so files diff cleanly")
	}
	if !strings.HasPrefix(string(raw), "{\n  \"version\": 2") {
		t.Error("file must declare version 2 like -baseline-write does")
	}
}

// The section a platform consumes to know which records to keep alive, which
// to archive, and which to send back through verification (adr/0004 §5).
func TestBaselineSectionShape(t *testing.T) {
	covered := fixture("VYQL-INJ-001", "a.py:1")
	sec := baselineSection(3, []*findings.Finding{covered},
		[]baselineEntry{{FP: "deadbeefdeadbeef"}}, []string{"cafebabecafebabe"})
	b, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"applied":3`,
		`"covered":["` + resultpolicy.Fingerprint(covered) + `"]`,
		`"drifted":["cafebabecafebabe"]`,
		`"stale":["deadbeefdeadbeef"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section %s missing %s", got, want)
		}
	}
}

// scanRefDoc builds a graph-json document carrying findings and (optionally) a
// baseline section — the two things entryState judges against.
func scanRefDoc(t *testing.T, dir string, fps []string, section *graphjson.BaselineSection) string {
	t.Helper()
	doc := graphjson.Document{SchemaVersion: graphjson.SchemaVersion}
	for _, fp := range fps {
		doc.Findings = append(doc.Findings, graphjson.Finding{FP: fp, Kind: "taint"})
	}
	doc.Baseline = section
	p := filepath.Join(dir, "scan.graph.json")
	if err := os.WriteFile(p, mustJSON(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// The state machine triage list reports and remove -stale acts on. With a
// baseline section vyql's own accounting decides; an entry absent from every
// list falls back to its fingerprint; without a section, "reported" — not
// "covered" — is the honest word for a finding that still fires, because this
// scan suppressed nothing.
func TestEntryStateAgainstScan(t *testing.T) {
	section := &graphjson.BaselineSection{
		Applied: 3,
		Covered: []string{"c0ffee0000000000"},
		Drifted: []string{"baadf00d00000000"},
		Stale:   []string{"dead000000000000"},
	}
	ref, err := loadScanRef(scanRefDoc(t, t.TempDir(), []string{"baadf00d00000000", "feed000000000000"}, section))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"c0ffee0000000000": triageCovered,  // section says suppressed
		"baadf00d00000000": triageDrifted,  // section says re-fired
		"dead000000000000": triageStale,    // section says matches nothing
		"feed000000000000": triageReported, // in findings, unknown to the section
		"0f0f0f0f0f0f0f0f": triageStale,    // fires nowhere, unknown to the section
	}
	for fp, want := range cases {
		if got := entryState(fp, ref); got != want {
			t.Errorf("entryState(%s) = %q, want %q", fp, got, want)
		}
	}

	// no baseline section: the scan ran without -baseline
	plain, err := loadScanRef(scanRefDoc(t, t.TempDir(), []string{"feed000000000000"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := entryState("feed000000000000", plain); got != triageReported {
		t.Errorf("firing finding without a section = %q, want reported", got)
	}
	if got := entryState("0f0f0f0f0f0f0f0f", plain); got != triageStale {
		t.Errorf("absent finding without a section = %q, want stale", got)
	}
}

func TestTriageRemoveStaleDropsOnlyStale(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "baseline.json")
	// covered, drifted and two stale entries; one stale is section-listed, the
	// other fires nowhere (the fallback must catch it too)
	entries := baselineFile{Version: baselineVersion, Entries: []baselineEntry{
		{FP: "c0ffee0000000000", Verdict: verdictFalsePositive},
		{FP: "baadf00d00000000", Verdict: verdictFalsePositive},
		{FP: "dead000000000000", Verdict: verdictFalsePositive},
		{FP: "0f0f0f0f0f0f0f0f", Verdict: verdictFalsePositive},
	}}
	if err := os.WriteFile(base, mustJSON(entries), 0o644); err != nil {
		t.Fatal(err)
	}
	from := scanRefDoc(t, dir, []string{"baadf00d00000000"}, &graphjson.BaselineSection{
		Applied: 2,
		Covered: []string{"c0ffee0000000000"},
		Drifted: []string{"baadf00d00000000"},
		Stale:   []string{"dead000000000000"},
	})

	if err := triageRemove([]string{"-stale", "-baseline", base, "-from", from}); err != nil {
		t.Fatal(err)
	}
	left, err := loadBaseline(base)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"c0ffee0000000000": true, "baadf00d00000000": true}
	if len(left) != len(want) {
		t.Fatalf("entries left = %v, want %v", left, want)
	}
	for fp := range want {
		if _, ok := left[fp]; !ok {
			t.Errorf("%s should have survived (not stale)", fp)
		}
	}
}

// Staleness without a scan is a guess, and remove must not delete verdicts on
// vibes: -stale without -from is a usage error.
func TestTriageRemoveStaleNeedsScan(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(base, mustJSON(baselineFile{Version: baselineVersion}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := triageRemove([]string{"-stale", "-baseline", base}); err == nil {
		t.Fatal("-stale without -from must be refused")
	}
}

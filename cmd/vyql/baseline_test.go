package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/resultpolicy"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBaselineAcceptsBothVerdicts(t *testing.T) {
	p := writeTemp(t, "b.json", `{"version":2,"entries":[
	  {"fp":"aaa","verdict":"false-positive","reason":"source is a constant"},
	  {"fp":"bbb","verdict":"accepted","reason":"known, tracked elsewhere"}]}`)
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatalf("loadBaseline errored: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d entries, want 2", len(got))
	}
	if got["aaa"].Reason != "source is a constant" {
		t.Errorf("reason lost: %q", got["aaa"].Reason)
	}
}

// Every one of these must fail loudly. Treating a broken baseline as "no
// suppressions" buries the user in findings they thought they had triaged;
// treating it as "suppress everything" hides real ones. Both are worse than
// stopping.
func TestLoadBaselineRejectsBrokenFiles(t *testing.T) {
	cases := []struct {
		name, body, wantIn string
	}{
		{"malformed", `not json`, "invalid character"},
		{"wrong version", `{"version":99,"entries":[]}`, "this build understands"},
		// v1 keys are the old per-binding fingerprint. They cannot match, and silently
		// matching nothing would un-suppress a whole triaged backlog, so the error has to
		// say how to migrate rather than just report a version mismatch.
		{"v1 needs re-recording", `{"version":1,"entries":[{"fp":"a","verdict":"accepted"}]}`, "re-record it with -baseline-write"},
		{"unknown verdict", `{"version":2,"entries":[{"fp":"a","verdict":"probably-fine"}]}`, "false-positive"},
		{"missing fp", `{"version":2,"entries":[{"verdict":"accepted"}]}`, "has no fp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadBaseline(writeTemp(t, "b.json", c.body))
			if err == nil {
				t.Fatal("accepted a broken baseline")
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("error %q does not mention %q", err, c.wantIn)
			}
		})
	}
	if _, err := loadBaseline(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing baseline was accepted")
	}
}

func fixture(rule, loc string) *findings.Finding {
	return &findings.Finding{RuleID: rule, Severity: "high", Bindings: []findings.Binding{{Name: "sink", Loc: loc}}}
}

func TestApplyBaselineSplitsReportedFromCovered(t *testing.T) {
	old, fresh := fixture("VYQL-INJ-001", "a.py:1"), fixture("VYQL-INJ-002", "b.py:2")
	base := map[string]baselineEntry{
		resultpolicy.Fingerprint(old): {FP: resultpolicy.Fingerprint(old), Verdict: verdictAccepted},
	}
	report, covered, stale := applyBaseline([]*findings.Finding{old, fresh}, base)
	if len(report) != 1 || report[0].RuleID != "VYQL-INJ-002" {
		t.Errorf("report = %v, want only the un-baselined finding", report)
	}
	if len(covered) != 1 || covered[0].RuleID != "VYQL-INJ-001" {
		t.Errorf("covered = %v, want the baselined finding", covered)
	}
	if len(stale) != 0 {
		t.Errorf("stale = %v, want none", stale)
	}
}

// The safety property. A suppression that outlives the code it excused is how
// these files become dangerous, so an entry matching nothing must be named.
func TestApplyBaselineReportsStaleEntries(t *testing.T) {
	present := fixture("VYQL-INJ-001", "a.py:1")
	base := map[string]baselineEntry{
		resultpolicy.Fingerprint(present): {FP: resultpolicy.Fingerprint(present), Verdict: verdictAccepted},
		"deadbeefdeadbeef":                {FP: "deadbeefdeadbeef", Verdict: verdictFalsePositive, Rule: "VYQL-OLD-001", Loc: "gone.py:9"},
	}
	_, _, stale := applyBaseline([]*findings.Finding{present}, base)
	if len(stale) != 1 {
		t.Fatalf("stale = %d, want 1", len(stale))
	}
	if stale[0].FP != "deadbeefdeadbeef" {
		t.Errorf("stale entry = %q, want the one that matched nothing", stale[0].FP)
	}
}

func TestApplyBaselineWithNoEntriesChangesNothing(t *testing.T) {
	f := fixture("VYQL-INJ-001", "a.py:1")
	report, covered, stale := applyBaseline([]*findings.Finding{f}, map[string]baselineEntry{})
	if len(report) != 1 || len(covered) != 0 || len(stale) != 0 {
		t.Errorf("empty baseline altered the result: %d/%d/%d", len(report), len(covered), len(stale))
	}
}

// A written baseline must load back. The two halves are the whole feature, and
// a format that only round-trips by accident is a format that will not.
func TestWriteBaselineRoundTrips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	all := []*findings.Finding{fixture("VYQL-INJ-001", "a.py:1"), fixture("VYQL-INJ-002", "b.py:2")}
	if err := writeBaseline(p, all); err != nil {
		t.Fatalf("writeBaseline errored: %v", err)
	}
	loaded, err := loadBaseline(p)
	if err != nil {
		t.Fatalf("written baseline does not load: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("round-tripped %d entries, want 2", len(loaded))
	}
	for _, f := range all {
		e, ok := loaded[resultpolicy.Fingerprint(f)]
		if !ok {
			t.Errorf("finding %s missing from the written baseline", f.RuleID)
			continue
		}
		if e.Verdict != verdictAccepted {
			t.Errorf("verdict = %q, want %q", e.Verdict, verdictAccepted)
		}
		if e.Reason != "" {
			t.Errorf("reason = %q, want empty so it is visibly untriaged", e.Reason)
		}
	}
	// Applying what was just written must silence exactly those findings.
	report, covered, stale := applyBaseline(all, loaded)
	if len(report) != 0 || len(covered) != 2 || len(stale) != 0 {
		t.Errorf("round-trip did not cover its own findings: %d/%d/%d", len(report), len(covered), len(stale))
	}
}

// writeVulnerablePy lays down a tree the shipped policies find something in, so
// the -baseline-write tests below are about what a recording run reports rather
// than about an empty result set.
func writeVulnerablePy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := "import os\n\n" +
		"def handler(request):\n" +
		"    cmd = request.args.get(\"cmd\")\n" +
		"    os.system(\"ls \" + cmd)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Recording a baseline is not a reason to withhold the report. A CI job that
// adopts the scanner still has to upload SARIF for that run, and a recording run
// that prints nothing gives its operator no way to see what it just accepted.
func TestBaselineWriteStillReports(t *testing.T) {
	dir := writeVulnerablePy(t)
	p := filepath.Join(t.TempDir(), "b.json")
	out, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{BaselineWrite: p})
	})
	if err != nil {
		t.Fatalf("run(-baseline-write, sarif) errored: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not SARIF: %v\n%s", err, out)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("SARIF has %d run(s), want 1", len(doc.Runs))
	}
	results := doc.Runs[0].Results
	if len(results) == 0 {
		t.Fatal("SARIF carries no results — the recording run reported nothing")
	}
	loaded, err := loadBaseline(p)
	if err != nil {
		t.Fatalf("baseline was not recorded: %v", err)
	}
	// The two halves must describe the same scan: everything reported is
	// everything recorded, or the operator is reading one set and the next run
	// suppresses another.
	if len(loaded) != len(results) {
		t.Errorf("recorded %d entries but reported %d results", len(loaded), len(results))
	}
	for _, r := range results {
		fp := r.PartialFingerprints["vyqlFingerprint/v2"]
		if _, ok := loaded[fp]; !ok {
			t.Errorf("reported finding %s is not in the baseline it just wrote", fp)
		}
	}
}

// The backlog a recording run accepts is the backlog it must not fail on:
// -baseline-write exists to adopt the scanner on code that already has findings,
// and gating the adoption run defeats the adoption.
func TestBaselineWriteDoesNotGateOnWhatItRecorded(t *testing.T) {
	dir := writeVulnerablePy(t)
	p := filepath.Join(t.TempDir(), "b.json")
	rank, err := parseFailOn("info")
	if err != nil {
		t.Fatal(err)
	}
	_, err = captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", scanRunOptions{
			BaselineWrite: p,
			FailOnRank:    rank,
			FailOnName:    "info",
			ExitCode:      1,
		})
	})
	if err != nil {
		t.Fatalf("recording run gated on its own backlog: %v", err)
	}
}

// A baseline that cannot be written is the point of the run failing, and it must
// fail loudly rather than printing a report that implies the record was kept.
func TestBaselineWriteFailureStopsTheRun(t *testing.T) {
	dir := writeVulnerablePy(t)
	p := filepath.Join(t.TempDir(), "no-such-dir", "b.json")
	_, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{BaselineWrite: p})
	})
	if err == nil {
		t.Fatal("run succeeded despite an unwritable baseline path")
	}
}

func TestWriteBaselineIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	all := []*findings.Finding{fixture("VYQL-B", "b.py:2"), fixture("VYQL-A", "a.py:1")}
	p1, p2 := filepath.Join(dir, "1.json"), filepath.Join(dir, "2.json")
	if err := writeBaseline(p1, all); err != nil {
		t.Fatal(err)
	}
	// Reversed input must produce the same file, or the baseline churns in git
	// on every run and nobody can review a change to it.
	if err := writeBaseline(p2, []*findings.Finding{all[1], all[0]}); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(p1)
	b, _ := os.ReadFile(p2)
	if string(a) != string(b) {
		t.Error("baseline output depends on finding order")
	}
	var bf baselineFile
	if err := json.Unmarshal(a, &bf); err != nil {
		t.Fatalf("written baseline is not valid JSON: %v", err)
	}
	if bf.Version != baselineVersion {
		t.Errorf("version = %d, want %d", bf.Version, baselineVersion)
	}
}

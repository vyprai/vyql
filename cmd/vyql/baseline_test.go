package main

import (
	"encoding/json"
	"errors"
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
	if err := writeBaseline(p, all, nil, 0); err != nil {
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

// Recording overwrites: every finding goes in as accepted, with an empty
// reason. Run over an existing baseline that someone triaged, it would replace
// their false-positive verdicts and the reasoning behind them with a blank
// acceptance, and the run that did it would look like a success.
func TestBaselineFlagsRejectRecordingOverAnExistingBaseline(t *testing.T) {
	err := checkBaselineFlags("b.json", "b.json")
	if err == nil {
		t.Fatal("-baseline with -baseline-write was accepted")
	}
	for _, want := range []string{"-baseline", "-baseline-write"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	// Either alone is the normal case and must stay usable.
	if err := checkBaselineFlags("b.json", ""); err != nil {
		t.Errorf("-baseline alone was rejected: %v", err)
	}
	if err := checkBaselineFlags("", "b.json"); err != nil {
		t.Errorf("-baseline-write alone was rejected: %v", err)
	}
	if err := checkBaselineFlags("", ""); err != nil {
		t.Errorf("neither flag was rejected: %v", err)
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
	if err := writeBaseline(p1, all, nil, 0); err != nil {
		t.Fatal(err)
	}
	// Reversed input must produce the same file, or the baseline churns in git
	// on every run and nobody can review a change to it.
	if err := writeBaseline(p2, []*findings.Finding{all[1], all[0]}, nil, 0); err != nil {
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

// Rolling a baseline forward records to a new file while applying the old one.
// It is the supported way to keep a suppression set current, and the check that
// guards a triaged file from being overwritten must not stand in its way.
func TestBaselineFlagsAllowRecordingToADifferentPath(t *testing.T) {
	dir := t.TempDir()
	err := checkBaselineFlags(filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json"))
	if err != nil {
		t.Fatalf("recording to a different path was rejected: %v", err)
	}
}

// Identity, not string equality. The same file reached by an uncleaned path or
// through a symlink is still the file whose verdicts would be destroyed.
func TestBaselineFlagsRejectTheSameFileUnderAnotherName(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "b.json")
	if err := os.WriteFile(real, []byte(`{"version":2,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := checkBaselineFlags(real, dir+"/./b.json"); err == nil {
		t.Error("an uncleaned path to the applied baseline was accepted as a record target")
	}

	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	if err := checkBaselineFlags(real, link); err == nil {
		t.Error("a symlink to the applied baseline was accepted as a record target")
	}
}

// A record target routinely does not exist yet, and a path-identity check that
// cannot cope with that would reject every first roll forward.
func TestSameFileHandlesAPathThatDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "not-created-yet.json")
	if !sameFile(absent, dir+"/./not-created-yet.json") {
		t.Error("two spellings of the same missing path were treated as different files")
	}
	if sameFile(absent, filepath.Join(dir, "other.json")) {
		t.Error("two different missing paths were treated as the same file")
	}
}

// A roll forward must not flatten triage. An entry someone marked
// false-positive, and the reasoning that got it there, has to come out the other
// side unchanged; otherwise every push erases a little more of the review that
// made the baseline worth trusting.
func TestWriteBaselineCarriesPriorVerdicts(t *testing.T) {
	kept := fixture("VYQL-INJ-001", "a.py:1")
	fp := resultpolicy.Fingerprint(kept)
	prior := map[string]baselineEntry{
		fp: {FP: fp, Verdict: verdictFalsePositive, Reason: "source is a constant"},
	}
	p := filepath.Join(t.TempDir(), "next.json")

	if err := writeBaseline(p, []*findings.Finding{kept}, prior, 0); err != nil {
		t.Fatalf("writeBaseline errored: %v", err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatalf("wrote a baseline that will not load: %v", err)
	}
	if got[fp].Verdict != verdictFalsePositive {
		t.Errorf("verdict = %q, want %q", got[fp].Verdict, verdictFalsePositive)
	}
	if got[fp].Reason != "source is a constant" {
		t.Errorf("reason = %q, want it carried over", got[fp].Reason)
	}
}

// The rule that stops a failure healing itself. A finding new to this run that
// meets the gate is failing the build; recording it would leave the next run
// green with the finding absorbed and nobody told.
func TestWriteBaselineOmitsNewFindingsThatMeetTheGate(t *testing.T) {
	gating := fixture("VYQL-INJ-002", "b.py:2") // fixture() builds these at "high"
	quiet := fixture("VYQL-INJ-003", "c.py:3")
	quiet.Severity = "low"
	high, err := parseFailOn("high")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "next.json")

	if err := writeBaseline(p, []*findings.Finding{gating, quiet}, nil, high); err != nil {
		t.Fatalf("writeBaseline errored: %v", err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[resultpolicy.Fingerprint(gating)]; ok {
		t.Error("a new HIGH that meets the gate was recorded")
	}
	if _, ok := got[resultpolicy.Fingerprint(quiet)]; !ok {
		t.Error("a new LOW below the gate was not recorded")
	}
}

// A finding the applied baseline already covers was filtered out before the gate
// ever saw it, so it keeps rolling forward at any severity. Without this, an
// accepted HIGH would drop out of the baseline and resurrect on the next run.
func TestWriteBaselineCarriesAcceptedFindingsThatMeetTheGate(t *testing.T) {
	acceptedHigh := fixture("VYQL-INJ-001", "a.py:1")
	fp := resultpolicy.Fingerprint(acceptedHigh)
	prior := map[string]baselineEntry{
		fp: {FP: fp, Verdict: verdictAccepted, Reason: "tracked in the backlog"},
	}
	high, err := parseFailOn("high")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "next.json")

	if err := writeBaseline(p, []*findings.Finding{acceptedHigh}, prior, high); err != nil {
		t.Fatalf("writeBaseline errored: %v", err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[fp]; !ok {
		t.Error("an already-accepted HIGH was dropped from the roll")
	}
}

// A suppression that outlives the code it excused is the hazard these files
// carry. The roll drops it: only findings the scan actually produced are written.
func TestWriteBaselineDropsPriorEntriesThatMatchNothing(t *testing.T) {
	present := fixture("VYQL-INJ-001", "a.py:1")
	fp := resultpolicy.Fingerprint(present)
	prior := map[string]baselineEntry{
		fp:                 {FP: fp, Verdict: verdictAccepted},
		"deadbeefdeadbeef": {FP: "deadbeefdeadbeef", Verdict: verdictAccepted, Rule: "VYQL-OLD-001", Loc: "gone.py:9"},
	}
	p := filepath.Join(t.TempDir(), "next.json")

	if err := writeBaseline(p, []*findings.Finding{present}, prior, 0); err != nil {
		t.Fatal(err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["deadbeefdeadbeef"]; ok {
		t.Error("an entry matching nothing in this scan was carried forward")
	}
	if len(got) != 1 {
		t.Errorf("wrote %d entries, want 1", len(got))
	}
}

// sarifFingerprints reads the fingerprints out of a SARIF report, which is how
// these tests tell which findings a run actually reported.
func sarifFingerprints(t *testing.T, out string) []string {
	t.Helper()
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
	var fps []string
	for _, r := range doc.Runs {
		for _, res := range r.Results {
			fps = append(fps, res.PartialFingerprints["vyqlFingerprint/v2"])
		}
	}
	return fps
}

// Mode B, the whole point of the change: apply a baseline and record a new one in
// the same run. Over an unchanged tree every finding is already covered, so the
// run reports nothing, gates on nothing, and rolls the same set forward.
func TestBaselineRollForwardReportsAndGatesOnWhatIsNew(t *testing.T) {
	dir := writeVulnerablePy(t)
	tmp := t.TempDir()
	adopted := filepath.Join(tmp, "adopted.json")

	if _, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{BaselineWrite: adopted})
	}); err != nil {
		t.Fatalf("adoption run errored: %v", err)
	}
	prior, err := loadBaseline(adopted)
	if err != nil {
		t.Fatal(err)
	}
	if len(prior) == 0 {
		t.Fatal("adoption recorded nothing; the fixture produces no findings")
	}

	rank, err := parseFailOn("info")
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(tmp, "next.json")
	out, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{
			Baseline:      prior,
			BaselinePath:  adopted,
			BaselineWrite: next,
			FailOnRank:    rank,
			FailOnName:    "info",
			ExitCode:      1,
		})
	})
	if err != nil {
		t.Fatalf("roll forward gated on findings the baseline already covered: %v", err)
	}
	if fps := sarifFingerprints(t, out); len(fps) != 0 {
		t.Errorf("reported %d finding(s); every one was covered by the baseline", len(fps))
	}
	rolled, err := loadBaseline(next)
	if err != nil {
		t.Fatalf("roll forward wrote no usable baseline: %v", err)
	}
	if len(rolled) != len(prior) {
		t.Errorf("rolled %d entries forward from %d", len(rolled), len(prior))
	}
}

// An applied baseline with no entries is still an applied baseline. Choosing the
// mode on the entry count would call this a recording run, skip the gate, and
// pass a build that should have failed. The action reaches this state on the
// first roll forward after an adoption that found nothing.
func TestBaselineRollForwardGatesWhenTheAppliedBaselineIsEmpty(t *testing.T) {
	dir := writeVulnerablePy(t)
	tmp := t.TempDir()
	empty := filepath.Join(tmp, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"version":2,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadBaseline(empty)
	if err != nil {
		t.Fatal(err)
	}
	rank, err := parseFailOn("info")
	if err != nil {
		t.Fatal(err)
	}
	_, err = captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{
			Baseline:      loaded,
			BaselinePath:  empty,
			BaselineWrite: filepath.Join(tmp, "next.json"),
			FailOnRank:    rank,
			FailOnName:    "info",
			ExitCode:      1,
		})
	})
	var met *thresholdMet
	if !errors.As(err, &met) {
		t.Fatalf("an empty applied baseline disabled the gate; err = %v", err)
	}
}

// Mode A is unchanged, and must stay so. Adoption exists to absorb a backlog
// including its HIGHs, so the gate rank must not reach writeBaseline here.
func TestBaselineAdoptionRecordsFindingsThatMeetTheGate(t *testing.T) {
	dir := writeVulnerablePy(t)
	p := filepath.Join(t.TempDir(), "adopted.json")
	rank, err := parseFailOn("info")
	if err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "sarif", "auto", scanRunOptions{
			BaselineWrite: p,
			FailOnRank:    rank,
			FailOnName:    "info",
			ExitCode:      1,
		})
	})
	if err != nil {
		t.Fatalf("adoption gated on the backlog it exists to absorb: %v", err)
	}
	reported := sarifFingerprints(t, out)
	adopted, err := loadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(adopted) != len(reported) {
		t.Errorf("adoption reported %d finding(s) but recorded %d", len(reported), len(adopted))
	}
}

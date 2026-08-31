package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// mislabelKey identifies one case of a benchmark corpus.
type mislabelKey struct{ test, category string }

// loadMislabelled reads the cases a corpus labels wrongly, so that scoring does
// not charge a scanner for reporting them.
//
// A benchmark's expectedresults file is treated as truth everywhere else, and it
// is not always right. BenchmarkPython's xpathi case 00014 round-trips its input
// through base64 and hands the identical string to the query, and is labelled
// safe; a scanner that reports it is correct and is scored a false positive for
// it.
//
// The path comes from BENCH_EXCLUDE. With none set nothing is excluded, so the
// scores are the corpus's own.
//
// Format is one case per line: test, category and a reason, tab separated. The
// reason is required and is not read here. It is required because an entry
// without one cannot be reviewed, and this list is the one place where a
// disagreement with the corpus is recorded rather than argued.
func loadMislabelled(t *testing.T) map[mislabelKey]bool {
	t.Helper()
	path := os.Getenv("BENCH_EXCLUDE")
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("BENCH_EXCLUDE=%s cannot be read: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	out, err := parseMislabelled(f, path)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// parseMislabelled reads the list. Separate from the file so that what it
// refuses can be tested without one.
func parseMislabelled(r io.Reader, path string) (map[mislabelKey]bool, error) {
	out := map[mislabelKey]bool{}
	s := bufio.NewScanner(r)
	for line := 1; s.Scan(); line++ {
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 3 || strings.TrimSpace(fields[2]) == "" {
			return nil, fmt.Errorf("%s:%d needs test, category and a reason, tab separated: %q",
				path, line, text)
		}
		out[mislabelKey{strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])}] = true
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

func TestMislabelListNeedsAReasonPerEntry(t *testing.T) {
	// An entry with no reason cannot be reviewed, and this list is the one place
	// a disagreement with the corpus is recorded rather than argued.
	_, err := parseMislabelled(strings.NewReader("BenchmarkTest00014\txpathi\n"), "list")
	if err == nil {
		t.Fatal("an entry with no reason was accepted")
	}
	if !strings.Contains(err.Error(), "reason") {
		t.Errorf("error does not say what is missing: %v", err)
	}
}

func TestMislabelListReadsAnEntryWithAReason(t *testing.T) {
	got, err := parseMislabelled(
		strings.NewReader("# a comment\n\nBenchmarkTest00014\txpathi\tround-trips through base64\n"),
		"list")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[mislabelKey{"BenchmarkTest00014", "xpathi"}] {
		t.Errorf("parsed %v, want the one case", got)
	}
}

func TestMislabelNoteIsSilentWithNoList(t *testing.T) {
	// With no list the scores are the corpus's own, and saying so every run
	// would be noise on every suite that has none.
	if note := mislabelNote(nil, 0); note != "" {
		t.Errorf("note = %q, want empty", note)
	}
}

func TestMislabelNoteReportsHowManyAreInForce(t *testing.T) {
	// A list that grows has to be visible in the same output as the score it
	// changed, because that is where anyone reading the score will look.
	note := mislabelNote(map[mislabelKey]bool{{"a", "b"}: true, {"c", "d"}: true}, 1)
	if !strings.Contains(note, "1 of 2") {
		t.Errorf("note = %q, want it to say 1 of 2", note)
	}
}

// mislabelNote is what the scorecard says about the exclusions in force, so that
// a list which grows is visible in the same output as the score it changed.
func mislabelNote(excluded map[mislabelKey]bool, applied int) string {
	if len(excluded) == 0 {
		return ""
	}
	return fmt.Sprintf("excluded %d of %d corpus case(s) listed as mislabelled (BENCH_EXCLUDE)",
		applied, len(excluded))
}

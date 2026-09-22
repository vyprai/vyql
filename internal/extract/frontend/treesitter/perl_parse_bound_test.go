package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parse bound's fixture: a file the claim takes outright — it opens with a
// perl shebang — whose parse runs away from it. A shebang is the one marker
// that claims any file, and prose behind it is still prose: the claim check
// cannot see past the first line, which is exactly why the bound has to hold
// for what the claim lets through. (The 338KB README the claim check was
// measured on cost near 6GB; this fixture scales the same prose down to keep
// the unbounded run — the failing case this test guards against — affordable
// in a test process.)
const boundProseHead = "#!/usr/bin/perl\n"

const honestPerl = `#!/usr/bin/perl
use strict;
use warnings;

sub greet {
    my ($name) = @_;
    print "hello $name\n";
    return 1;
}

greet($ARGV[0]);
`

// writeBoundFixture writes content at rel and returns the path.
func writeBoundFixture(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// boundProseFixture builds a shebang-claimed prose document of about size
// bytes from the README text the claim check was measured against.
func boundProseFixture(size int) string {
	var b strings.Builder
	b.WriteString(boundProseHead)
	for b.Len() < size {
		b.WriteString(proseDocForBound)
	}
	return b.String()
}

// proseDocForBound is the documentation shape from perl_claim_test: prose with
// the loose code-shaped tokens (URL arrows, %s placeholders, e-mail sigils)
// that a grammar chokes on for thousands of times its own size.
const proseDocForBound = `LMS - LAN Management System 1.11-git

   LMS Developers <lms@lists.lms.org.pl>
   Copyright (c) 2001-2013

   Spis treści
   1. Wstęp
        1.1. Czym jest LMS
   2. Instalacja i konfiguracja

   Moduły -> daemon -> konfiguracja %s %d @l @c
   Zobacz http://lms.org.pl/?page=module&action=info&id=%s po szczegóły.
   Plik konfiguracyjny: lms.ini, sekcja [daemon], opcje %s i %d.
`

// TestPerlParseHaltedAtScanStop is the parse bound itself: a Perl file whose
// parse would take the process past the scan's stop is halted and declined,
// while a file whose parse the scan affords is lowered as normal. Without the
// bound the runaway parse runs to completion — measured at ~500MB of resident
// memory for this fixture — and yields a module, which is the assertion that
// fails: a scan at this stop would have died on that file instead of
// reporting.
func TestPerlParseHaltedAtScanStop(t *testing.T) {
	rss := parseResidentBytes()
	if rss <= 0 {
		t.Skip("no resident-memory reading on this platform, so the bound is inert here")
	}
	dir := t.TempDir()
	runaway := writeBoundFixture(t, dir, "runaway.pl", boundProseFixture(96<<10))
	honest := writeBoundFixture(t, dir, "honest.pl", honestPerl)

	// A stop just above where the process sits: near enough that the runaway
	// parse crosses the halt band almost immediately, far enough that the
	// honest parse — a few hundred kilobytes of tree — never comes near it.
	restore := SetParseStopForTest(rss + 200<<20)
	defer restore()

	if !ReadsAsPerl(runaway) {
		t.Fatal("fixture must be claimed as Perl for the parse bound to be what declines it")
	}

	prog, err := ExtractPerl([]string{runaway, honest}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var haveRunaway, haveHonest bool
	for _, m := range prog.Modules {
		switch m.File {
		case "runaway.pl":
			haveRunaway = true
		case "honest.pl":
			haveHonest = true
		}
	}
	if haveRunaway {
		t.Errorf("runaway.pl was lowered: its parse crossed the scan's stop and must be declined, not run to completion")
	}
	if !haveHonest {
		t.Errorf("honest.pl was not lowered: the bound must decline only the parse that crosses the stop")
	}
}

// TestPerlParseUnboundedWithoutStop pins the other half of the behaviour: with
// no stop in force — a scan that asked for no ceiling — the bound is inert and
// every claimed file is parsed, exactly as before it existed.
func TestPerlParseUnboundedWithoutStop(t *testing.T) {
	dir := t.TempDir()
	honest := writeBoundFixture(t, dir, "honest.pl", honestPerl)
	restore := SetParseStopForTest(0)
	defer restore()

	prog, err := ExtractPerl([]string{honest}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("got %d modules, want the one file parsed: with no stop in force the bound must not decline anything", len(prog.Modules))
	}
}

// SetParseStopForTest publishes a stop for the duration of one test and
// returns the func that restores what was in force before.
func SetParseStopForTest(n int64) func() {
	prev := ParseStop()
	SetParseStop(n)
	return func() { SetParseStop(prev) }
}

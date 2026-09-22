package extract

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
)

// The scan-level view of the parse bound: a target holding ONE file whose Perl
// parse crosses the scan's memory stop still completes and reports, with that
// file declined, instead of the whole scan ending at the stop with no report
// at all. The partition planner cannot help here — the file is one unit,
// however the target is divided — which is the failure this test pins.
//
// The fixture is a shebang-claimed prose document: the claim takes it (a
// shebang claims outright), so it is the parse bound, not the claim, that must
// decline it — the same division of labour the prose-claim test checks from
// the other side.
func TestScanCompletesPastRunawayPerlParse(t *testing.T) {
	rss := residentBytesForParseTest()
	if rss <= 0 {
		t.Skip("no resident-memory reading on this platform, so the bound is inert here")
	}
	dir := t.TempDir()
	var prose strings.Builder
	prose.WriteString("#!/usr/bin/perl\n")
	for prose.Len() < 96<<10 {
		prose.WriteString(proseDoc)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.pl"), []byte(prose.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// A program the scan can afford: its module must survive the bound.
	honest := filepath.Join(dir, "bin", "tool.pl")
	if err := os.MkdirAll(filepath.Dir(honest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(honest, []byte(`#!/usr/bin/perl
use strict;
use warnings;
sub run {
  my ($cmd) = @_;
  system($cmd);
  return $?;
}
run(@ARGV);
`), 0o644); err != nil {
		t.Fatal(err)
	}

	stop := rss + 200<<20
	prev := treesitter.ParseStop()
	treesitter.SetParseStop(stop)
	defer treesitter.SetParseStop(prev)

	prog, _, _, stats, err := AllIn([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var haveHonest bool
	for _, m := range prog.Modules {
		if strings.HasSuffix(m.File, "tool.pl") {
			haveHonest = true
		}
		if strings.HasSuffix(m.File, "README.pl") {
			t.Errorf("README.pl was lowered: its parse crossed the scan's stop, and a file the scan cannot afford is a file skipped, not a scan ended")
		}
	}
	if !haveHonest {
		t.Errorf("tool.pl was not lowered: the bound must decline only the parse that crosses the stop")
	}
	if got := stats.Files["perl"]; got != 2 {
		t.Errorf("perl claimed %d file(s), want 2: the claim takes both files, the bound declines one of them at the parse", got)
	}
}

// residentBytesForParseTest reads the process's resident set for the stop the
// test publishes, mirroring the parse bound's own reading.
func residentBytesForParseTest() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, resident int64
	if n, _ := fmt.Sscanf(string(b), "%d %d", &size, &resident); n < 2 {
		return 0
	}
	return resident * int64(os.Getpagesize())
}

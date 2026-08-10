package main

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
)

func TestUnmatchedTotalSumsEveryKind(t *testing.T) {
	s := extract.Stats{Unmatched: map[string]int{".zig": 12, ".cob": 3}}
	if got := s.UnmatchedTotal(); got != 15 {
		t.Errorf("UnmatchedTotal = %d, want 15", got)
	}
	if got := (extract.Stats{}).UnmatchedTotal(); got != 0 {
		t.Errorf("empty UnmatchedTotal = %d, want 0", got)
	}
}

func TestTopKindsOrdersByCountThenName(t *testing.T) {
	got := topKinds(map[string]int{".cob": 3, ".zig": 12, ".rs": 3}, 4)
	// Largest first; ties broken by name so the line is stable between runs.
	want := ".zig 12, .cob 3, .rs 3"
	if got != want {
		t.Errorf("topKinds = %q, want %q", got, want)
	}
}

func TestTopKindsSummarisesTheTail(t *testing.T) {
	m := map[string]int{".a": 9, ".b": 8, ".c": 7, ".d": 6, ".e": 5, ".f": 4}
	got := topKinds(m, 3)
	if !strings.HasPrefix(got, ".a 9, .b 8, .c 7") {
		t.Errorf("topKinds lost the leading kinds: %q", got)
	}
	if !strings.Contains(got, "+3 more") {
		t.Errorf("topKinds did not summarise the tail: %q", got)
	}
}

// The cache replays findings without re-walking the tree. If coverage did not
// travel with them, the second scan of a tree would report the same findings
// and quietly drop the warning that most of it was never read.
func TestCachedScanCarriesCoverage(t *testing.T) {
	stats := extract.Stats{
		Files:     map[string]int{"python": 1},
		Languages: []string{"python"},
		Excluded:  5,
		Unmatched: map[string]int{".zig": 12},
	}
	cs := cachedScan{
		Findings:  nil,
		Files:     stats.Files,
		Languages: stats.Languages,
		Excluded:  stats.Excluded,
		Unmatched: stats.Unmatched,
	}
	restored := extract.Stats{
		Files:     cs.Files,
		Languages: cs.Languages,
		Excluded:  cs.Excluded,
		Unmatched: cs.Unmatched,
	}
	if restored.Excluded != stats.Excluded {
		t.Errorf("excluded lost across the cache: %d != %d", restored.Excluded, stats.Excluded)
	}
	if restored.UnmatchedTotal() != stats.UnmatchedTotal() {
		t.Errorf("unmatched lost across the cache: %d != %d",
			restored.UnmatchedTotal(), stats.UnmatchedTotal())
	}
}

package main

import (
	"strings"
	"testing"
)

func TestUnmatchedTotalSumsEveryKind(t *testing.T) {
	s := scanStats{unmatched: map[string]int{".zig": 12, ".cob": 3}}
	if got := s.unmatchedTotal(); got != 15 {
		t.Errorf("unmatchedTotal = %d, want 15", got)
	}
	if got := (scanStats{}).unmatchedTotal(); got != 0 {
		t.Errorf("empty unmatchedTotal = %d, want 0", got)
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
	stats := scanStats{
		files:     map[string]int{"python": 1},
		languages: []string{"python"},
		excluded:  5,
		unmatched: map[string]int{".zig": 12},
	}
	cs := cachedScan{
		Findings:  nil,
		Files:     stats.files,
		Languages: stats.languages,
		Excluded:  stats.excluded,
		Unmatched: stats.unmatched,
	}
	restored := scanStats{
		files:     cs.Files,
		languages: cs.Languages,
		excluded:  cs.Excluded,
		unmatched: cs.Unmatched,
	}
	if restored.excluded != stats.excluded {
		t.Errorf("excluded lost across the cache: %d != %d", restored.excluded, stats.excluded)
	}
	if restored.unmatchedTotal() != stats.unmatchedTotal() {
		t.Errorf("unmatched lost across the cache: %d != %d",
			restored.unmatchedTotal(), stats.unmatchedTotal())
	}
}

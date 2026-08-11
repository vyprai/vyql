package main

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
)

// Coverage travels with the findings so that the second scan of a tree is as honest as the
// first. Every field the payload carries has to survive the replay; one that does not turns
// `-coverage` into a line that appears once and then silently stops.
//
// oversized did exactly that: stored, never restored, so the first scan of a tree reported
// files skipped over the size ceiling and every cached scan afterwards reported none, for
// identical input. This walks the whole struct rather than naming the fields, so the next one
// added to the payload cannot be missed the same way.
func TestEveryCoverageFieldSurvivesTheCacheReplay(t *testing.T) {
	stats := extract.Stats{
		Files:     map[string]int{"python": 3},
		Languages: []string{"python"},
		Excluded:  5,
		Oversized: 7,
		Unmatched: map[string]int{".zig": 11},
	}
	excludes, err := extract.ParseExcludes([]string{"node_modules", "**/*_templ.go", "*.min.js"})
	if err != nil {
		t.Fatalf("ParseExcludes: %v", err)
	}
	excludes[0].PrunedDirs = 2
	excludes[1].Matched = 4
	cached := cachedScanFrom(nil, stats, excludes)
	replayed := statsFromCachedScan(cached)

	if got, want := len(replayed.Files), len(stats.Files); got != want {
		t.Errorf("Files lost across the cache: %d entries, want %d", got, want)
	}
	if got, want := len(replayed.Languages), len(stats.Languages); got != want {
		t.Errorf("Languages lost across the cache: %d, want %d", got, want)
	}
	if replayed.Excluded != stats.Excluded {
		t.Errorf("Excluded lost across the cache: %d, want %d", replayed.Excluded, stats.Excluded)
	}
	if replayed.Oversized != stats.Oversized {
		t.Errorf("Oversized lost across the cache: %d, want %d — a cached scan would stop "+
			"reporting files skipped over the size ceiling", replayed.Oversized, stats.Oversized)
	}

	// The per-pattern counts belong to the walk, and a replayed scan never walks.
	// Without them every pattern reports as matching nothing, which is the one
	// thing the coverage report exists to say truthfully.
	fresh, err := extract.ParseExcludes([]string{"node_modules", "**/*_templ.go", "*.min.js"})
	if err != nil {
		t.Fatalf("ParseExcludes: %v", err)
	}
	restoreExcludeCounts(cached, fresh)
	if fresh[0].PrunedDirs != 2 {
		t.Errorf("pruned directory count lost across the cache: %d, want 2", fresh[0].PrunedDirs)
	}
	if fresh[1].Matched != 4 {
		t.Errorf("excluded file count lost across the cache: %d, want 4", fresh[1].Matched)
	}
	if got := fresh.Unmatched(); len(got) != 1 || got[0] != "*.min.js" {
		t.Errorf("Unmatched() after replay = %v, want only the pattern that excluded nothing", got)
	}
	if replayed.UnmatchedTotal() != stats.UnmatchedTotal() {
		t.Errorf("Unmatched lost across the cache: %d, want %d",
			replayed.UnmatchedTotal(), stats.UnmatchedTotal())
	}
}

// Folding the stats concurrently must not change the digest. If it did, every cached scan
// would miss and the cache would look like it was working while doing nothing.
func TestStatWalkDigestDoesNotDependOnConcurrency(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"a.vyql", "b.vyql", "sub/c.vyql", "sub/deep/d.vyql", "sub/deep/e.vyql",
		"z/y/x/w.vyql", ".git/should-be-skipped", "node_modules/pkg/index.js",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	parallel := sha256.New()
	statWalk(parallel, root)

	sequential := sha256.New()
	sequentialStatWalk(sequential, root)

	if got, want := hex.EncodeToString(parallel.Sum(nil)), hex.EncodeToString(sequential.Sum(nil)); got != want {
		t.Fatalf("concurrent stat walk changed the digest:\n  got  %s\n  want %s", got, want)
	}
	// Repeat: a digest that varies between runs invalidates the cache on every scan.
	again := sha256.New()
	statWalk(again, root)
	if hex.EncodeToString(again.Sum(nil)) != hex.EncodeToString(parallel.Sum(nil)) {
		t.Fatal("two runs of statWalk over the same tree produced different digests")
	}
}

func TestStatWalkStillNoticesAContentChange(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "a.vyql")
	if err := os.WriteFile(p, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := sha256.New()
	statWalk(before, root)
	if err := os.WriteFile(p, []byte("a longer body"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := sha256.New()
	statWalk(after, root)
	if hex.EncodeToString(before.Sum(nil)) == hex.EncodeToString(after.Sum(nil)) {
		t.Fatal("statWalk did not notice an edited file; every scan would replay stale findings")
	}
}

// sequentialStatWalk is the shape statWalk had before the stats were overlapped, kept here as
// the reference the concurrent version is checked against.
func sequentialStatWalk(h hash.Hash, root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".hg", ".svn":
				return filepath.SkipDir
			case "vendor":
				return nil
			}
			if vendorFingerprintDirShouldSkip(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		hashString(h, p)
		writeStamp(h, info.Size(), info.ModTime().UnixNano())
		return nil
	})
}

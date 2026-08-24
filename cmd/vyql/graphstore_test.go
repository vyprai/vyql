package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepStaleGraphStoresRemovesOnlyTheOldOnes(t *testing.T) {
	parent := t.TempDir()
	old := filepath.Join(parent, "scan-old")
	fresh := filepath.Join(parent, "scan-fresh")
	other := filepath.Join(parent, "something-else")
	for _, d := range []string{old, fresh, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	twoDaysAgo := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, twoDaysAgo, twoDaysAgo); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, twoDaysAgo, twoDaysAgo); err != nil {
		t.Fatal(err)
	}

	sweepStaleGraphStores(parent, 24*time.Hour)

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a store two days old survived the sweep")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a store from this scan was swept")
	}
	// The sweep runs inside the user's cache directory, so it must touch only
	// what it created.
	if _, err := os.Stat(other); err != nil {
		t.Error("the sweep removed a directory it did not create")
	}
}

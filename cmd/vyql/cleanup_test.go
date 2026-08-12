package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cleanup is reachable two ways -- the deferred call on the normal path, and
// the registry on a signal. Running it twice would double-close a store or
// remove a directory another run had already recreated.
func TestOnExitRunsOnceWhicheverPathReachesItFirst(t *testing.T) {
	t.Cleanup(resetCleanups)
	runs := 0
	wrapped := onExit(func() { runs++ })

	wrapped()     // the deferred call
	runCleanups() // and then a signal
	if runs != 1 {
		t.Fatalf("cleanup ran %d times, want 1", runs)
	}

	runCleanups()
	if runs != 1 {
		t.Fatalf("cleanup ran %d times after a second signal, want 1", runs)
	}
}

// The registry unwinds the way defer does, so a cleanup that depends on an
// earlier one still holding is not surprised.
func TestRunCleanupsUnwindsInReverse(t *testing.T) {
	t.Cleanup(resetCleanups)
	var order []string
	onExit(func() { order = append(order, "first") })
	onExit(func() { order = append(order, "second") })
	runCleanups()
	if strings.Join(order, ",") != "second,first" {
		t.Fatalf("order = %v, want [second first]", order)
	}
}

func TestHumanBytes(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	} {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestDirBytesTotalsTheFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), make([]byte, 200), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := dirBytes(dir); got != 300 {
		t.Errorf("dirBytes = %d, want 300", got)
	}
	// A path that does not exist is 0 rather than an error: the number is for the
	// operator, and refusing to clear because the size could not be measured
	// would be the wrong trade.
	if got := dirBytes(filepath.Join(dir, "nope")); got != 0 {
		t.Errorf("dirBytes of a missing path = %d, want 0", got)
	}
}

// Emptying the store left badger's own files behind -- a preallocated DISCARD,
// the manifest, the key registry -- so a cache reported as cleared still occupied
// megabytes. Someone clearing a cache is reclaiming disk.
func TestClearCacheRemovesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scan-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"000001.vlog", "DISCARD", "MANIFEST"} {
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearCache(dir); err != nil {
		t.Fatalf("clearCache: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		left := dirBytes(dir)
		t.Fatalf("the cache directory survived clear, holding %d byte(s)", left)
	}
}

// Clearing an already-cleared cache is a normal thing to do twice, not an error.
func TestClearCacheOnAMissingDirectoryIsNotAnError(t *testing.T) {
	if err := clearCache(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("clearCache on a missing directory: %v", err)
	}
}

func resetCleanups() {
	cleanups.mu.Lock()
	cleanups.fns = nil
	cleanups.mu.Unlock()
}

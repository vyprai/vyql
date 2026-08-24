package main

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
)

// cacheHome points os.UserCacheDir at a directory the test owns, on both the
// XDG platforms and macOS, so a test that creates a graph store does not write
// into the developer's real cache.
func cacheHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	return dir
}

func TestApplyMaxRAMPartitionsOnceAndRestoresTheLimit(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	cleanup := applyMaxRAM("8GB")
	n, err := parseBytes("8GB")
	if err != nil {
		t.Fatalf("parseBytes: %v", err)
	}

	if lowering.DiskCacheBytes != n/2 {
		t.Errorf("DiskCacheBytes = %d, want n/2 = %d", lowering.DiskCacheBytes, n/2)
	}
	if lowering.DiskDetailBuf != n/4 {
		t.Errorf("DiskDetailBuf = %d, want n/4 = %d", lowering.DiskDetailBuf, n/4)
	}
	if got := debug.SetMemoryLimit(-1); got != n/2 {
		t.Errorf("heap limit = %d, want n/2 = %d", got, n/2)
	}
	cleanup()
	if got := debug.SetMemoryLimit(-1); got != prev {
		t.Errorf("heap limit after cleanup = %d, want restored %d", got, prev)
	}
	if lowering.DiskStorePath != "" {
		t.Error("DiskStorePath not cleared by cleanup")
	}
	if lowering.DiskCacheBytes != 0 || lowering.DiskDetailBuf != 0 {
		t.Error("disk budgets not cleared by cleanup")
	}
}

// The store must not land in $TMPDIR. On a systemd distribution /tmp is a tmpfs,
// so a graph put there is held in RAM, and the mode whose whole purpose is to
// keep the graph out of RAM would put it back.
func TestApplyMaxRAMPutsTheGraphOutsideTMPDIR(t *testing.T) {
	home := cacheHome(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	cleanup := applyMaxRAM("8GB")
	t.Cleanup(cleanup)

	dir := lowering.DiskStorePath
	if dir == "" {
		t.Fatal("DiskStorePath not set")
	}
	if strings.HasPrefix(dir, tmp) {
		t.Errorf("graph store %s is under TMPDIR %s", dir, tmp)
	}
	if !strings.HasPrefix(dir, home) {
		t.Errorf("graph store %s is not under the cache home %s", dir, home)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("graph store not created: %v", err)
	}
}

func TestRAMBackedRecognisesAMemoryFilesystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the filesystem type check is Linux-only")
	}
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("no /dev/shm on this machine")
	}
	if !ramBacked("/dev/shm") {
		t.Error("ramBacked(/dev/shm) = false, want true")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if ramBacked(wd) {
		t.Errorf("ramBacked(%s) = true for the source tree, want false", wd)
	}
}

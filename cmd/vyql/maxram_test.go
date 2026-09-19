package main

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
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

func TestApplyMaxRAMKeepsEveryPoolInsideTheBudget(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	cleanup := applyMaxRAM("8GB")
	t.Cleanup(cleanup)
	n, err := parseBytes("8GB")
	if err != nil {
		t.Fatalf("parseBytes: %v", err)
	}

	limit := debug.SetMemoryLimit(-1)
	if limit > n {
		t.Errorf("heap limit = %d, above the budget %d", limit, n)
	}
	if stopAt := memoryStopThreshold(n); limit >= stopAt {
		t.Errorf("heap limit = %d, not below resident safety threshold %d", limit, stopAt)
	}
	if limit <= n/2 {
		t.Errorf("heap limit = %d, at or below half the budget %d: the resident graph has no room", limit, n)
	}
	// Badger's block cache is ordinary Go heap, so both pools are spent from the
	// same limit as the graph itself. Together they must leave most of it free.
	pools := lowering.DiskCacheBytes + lowering.DiskDetailBuf
	if pools >= limit/2 {
		t.Errorf("caches total %d, at least half the %d heap limit they share with the graph", pools, limit)
	}
	if lowering.DiskCacheBytes <= 0 || lowering.DiskDetailBuf <= 0 {
		t.Errorf("cache = %d, detail buffer = %d: both must be funded", lowering.DiskCacheBytes, lowering.DiskDetailBuf)
	}
}

func TestApplyMaxRAMRestoresTheLimitAndClearsTheBudgets(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	cleanup := applyMaxRAM("8GB")
	dir := lowering.DiskStorePath
	if dir == "" {
		t.Fatal("DiskStorePath not set")
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
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("graph store %s survived cleanup", dir)
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

// A bounded scan of a target one graph can hold builds that graph in RAM. The disk-backed
// store the same ceiling arms costs more than the graph it spares on such a target: its
// detail buffer, write path and caches sit resident alongside a structural core that never
// leaves RAM in either store, so a dense ordinary-source file — a single 453KB Python module,
// or a 283KB file of 2000 six-line functions — was stopped at the memory safety threshold
// through the disk store while the same scan holding its graph in RAM peaked at half of it,
// and the stop left no report at all (measured: 3.3GiB stop against a 1.7GiB in-RAM peak).
func TestBoundedScanKeepsInRAMAGraphTheCeilingHolds(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	t.Cleanup(applyMaxRAM("4GB"))

	dir := partitionFixture(t, 3)
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	_, _, g, err := scanPathsWithProfileDemand([]string{dir}, rules, "", true, extract.Options{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if g == nil {
		t.Fatal("no graph was built from the fixture")
	}
	t.Cleanup(func() { _ = usg.Close(g) })
	if _, disk := g.(*usg.BadgerGraph); disk {
		t.Errorf("a target inside the one-graph limit was scanned on the disk-backed store;" +
			" its resident overhead crosses a threshold a target this size never touches")
	}
}

// The bound the disk-backed store exists to provide stays where it belongs: a target over
// the one-graph limit for its ceiling still spills, so a run that must serialise one graph
// is not handed a graph RAM cannot hold.
func TestBoundedScanStillSpillsAGraphTheCeilingCannotHold(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	t.Cleanup(applyMaxRAM("4GB"))

	prevLimit, prevBudget := scanSourceLimit, scanSourceBudget
	t.Cleanup(func() { scanSourceLimit, scanSourceBudget = prevLimit, prevBudget })
	scanSourceLimit, scanSourceBudget = 1, 1 // every target is over the limit

	dir := partitionFixture(t, 3)
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	_, _, g, err := scanPathsWithProfileDemand([]string{dir}, rules, "", true, extract.Options{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if g == nil {
		t.Fatal("no graph was built from the fixture")
	}
	t.Cleanup(func() { _ = usg.Close(g) })
	if _, disk := g.(*usg.BadgerGraph); !disk {
		t.Error("a target over the one-graph limit was held in RAM; the disk-backed store is its bound")
	}
}

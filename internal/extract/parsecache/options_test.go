package parsecache

import "testing"

func TestCacheOptionsAreSizedForACLINotAServer(t *testing.T) {
	opts := options(t.TempDir())
	if opts.MemTableSize != 16<<20 {
		t.Errorf("MemTableSize = %d, want 16MiB: the arena is eagerly allocated at Open on every scan", opts.MemTableSize)
	}
	if opts.NumMemtables != 2 {
		t.Errorf("NumMemtables = %d, want 2", opts.NumMemtables)
	}
	if opts.BlockCacheSize != 64<<20 {
		t.Errorf("BlockCacheSize = %d, want 64MiB: entries are read once per scan, a large cache buys nothing", opts.BlockCacheSize)
	}
	if opts.DetectConflicts {
		t.Error("DetectConflicts = true, want false: keys are content-addressed, conflicts are meaningless")
	}
}

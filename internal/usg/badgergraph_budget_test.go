package usg

import "testing"

func TestOpenBadgerGraphSplitsCacheFromDetailBuffer(t *testing.T) {
	g, err := OpenBadgerGraph(t.TempDir(), 1<<30, 1<<28) // 1GB cache, 256MB detail
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = g.Close() }()
	if g.detCapByte != 1<<28 {
		t.Errorf("detCapByte = %d, want the detail budget %d, not the cache budget", g.detCapByte, 1<<28)
	}
	opts := g.db.Opts()
	if opts.IndexCacheSize != 0 {
		t.Errorf("IndexCacheSize = %d, want 0: the index cache is never consulted on unencrypted DBs", opts.IndexCacheSize)
	}
	if opts.BlockCacheSize != 1<<30 {
		t.Errorf("BlockCacheSize = %d, want the full cache budget %d", opts.BlockCacheSize, 1<<30)
	}
}

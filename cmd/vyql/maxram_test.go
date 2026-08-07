package main

import (
	"runtime/debug"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
)

func TestApplyMaxRAMPartitionsOnceAndRestoresTheLimit(t *testing.T) {
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

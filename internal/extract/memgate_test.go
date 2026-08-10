package extract_test

import (
	"runtime"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// Allocation ceilings for one extract+lower pass over the deterministic
// 64-file benchmark corpus. These are a regression gate, not a target:
// measured-at-land-time with slack. A perf change that lands a win MUST
// tighten these in the same commit, or the win is unprotected — the
// --max-ram budget partition was silently lost once precisely because
// nothing in CI measured memory.
const (
	memGateCorpusFiles    = 64
	maxPipelineAllocBytes = 80 << 20  // measured 63.3MB, ×1.25 slack
	maxPipelineAllocs     = 1_300_000 // measured 1.04M, ×1.25 slack
)

func TestPipelineAllocationCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation gate needs a full pipeline pass")
	}
	files, root := benchCorpus(t, memGateCorpusFiles)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	prog, err := treesitter.ExtractJava(files, root)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := lowering.LowerTyped(prog, true, nil); err != nil {
		t.Fatalf("lower: %v", err)
	}

	runtime.ReadMemStats(&after)
	allocBytes := after.TotalAlloc - before.TotalAlloc
	allocs := after.Mallocs - before.Mallocs
	t.Logf("pipeline allocated %d bytes in %d allocations", allocBytes, allocs)
	if allocBytes > maxPipelineAllocBytes {
		t.Errorf("allocated %d bytes, ceiling %d", allocBytes, maxPipelineAllocBytes)
	}
	if allocs > maxPipelineAllocs {
		t.Errorf("%d allocations, ceiling %d", allocs, maxPipelineAllocs)
	}
}

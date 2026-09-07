package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/resultpolicy"
)

// partitionFixture writes n JavaScript files that each carry a complete taint path inside one
// file, so what a partitioned scan reports can be compared against what one graph reports
// without the comparison turning on flows that cross a partition boundary.
func partitionFixture(t *testing.T, n int) string {
	t.Helper()
	files := map[string]string{}
	for i := range n {
		files[fmt.Sprintf("pkg%d/handler%d.js", i/3, i)] = fmt.Sprintf(`
const express = require("express");
const app = express();
app.get("/r%d", function (req, res) {
  const next = req.query.next;
  res.redirect(next);
});
%s
`, i, strings.Repeat("// filler line to give the partition planner something to weigh\n", 40))
	}
	return writeFixture(t, files)
}

func partitionScanRuleIDs(t *testing.T, dir string, parts []map[string]bool) []string {
	t.Helper()
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	var ids []string
	if parts == nil {
		fs, _, _, err := scanPathsWithProfileDemand([]string{dir}, rules, "", true, extract.Options{})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
	} else {
		fs, _, err := scanPartitions([]string{dir}, rules, "", extract.Options{}, parts)
		if err != nil {
			t.Fatalf("partitioned scan: %v", err)
		}
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)
	return ids
}

// A scan holds one resident program graph for the whole target, so its peak memory tracks the
// clone rather than the ceiling it was given. A target past what one graph may cover under that
// ceiling is scanned as a sequence of graphs instead — and what that reports has to be what one
// graph would report, for every finding that does not turn on a flow crossing the boundary.
func TestPartitionedScanReportsWhatOneGraphWould(t *testing.T) {
	dir := partitionFixture(t, 12)

	var total int64
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, e := d.Info(); e == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := extract.PlanPartitions([]string{dir}, nil, total/4, total/4)
	if len(parts) < 2 {
		t.Fatalf("PlanPartitions returned %d partition(s), want several", len(parts))
	}

	whole := partitionScanRuleIDs(t, dir, nil)
	if len(whole) == 0 {
		t.Fatal("the fixture produced no findings as one graph, so there is nothing to compare")
	}
	got := partitionScanRuleIDs(t, dir, parts)

	if strings.Join(got, ",") != strings.Join(whole, ",") {
		t.Errorf("partitioned scan reported\n  %v\none graph reported\n  %v", got, whole)
	}
}

// The findings a partitioned scan merges have to be deduplicated: SCA reads the target's
// manifests from the paths the scan was given rather than from the partition, so a dependency
// finding is produced once per partition.
func TestPartitionedScanDoesNotRepeatAFindingPerPartition(t *testing.T) {
	dir := partitionFixture(t, 9)
	parts := extract.PlanPartitions([]string{dir}, nil, 4<<10, 4<<10)
	if len(parts) < 2 {
		t.Fatalf("PlanPartitions returned %d partition(s), want several", len(parts))
	}
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	fs, _, err := scanPartitions([]string{dir}, rules, "", extract.Options{}, parts)
	if err != nil {
		t.Fatalf("partitioned scan: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		fp := resultpolicy.Fingerprint(f)
		if seen[fp] {
			t.Errorf("finding %s reported twice", f.RuleID)
		}
		seen[fp] = true
	}
}

func TestSourceBudgetTracksTheCeiling(t *testing.T) {
	if got := sourceBudgetBytes(0); got != 0 {
		t.Errorf("sourceBudgetBytes(0) = %d, want 0 so no ceiling means no partitioning", got)
	}
	if got := oneGraphSourceBytes(0); got != 0 {
		t.Errorf("oneGraphSourceBytes(0) = %d, want 0 so no ceiling means no partitioning", got)
	}
	small, large := sourceBudgetBytes(4<<30), sourceBudgetBytes(32<<30)
	if small >= large {
		t.Errorf("budget for 4GiB = %d, for 32GiB = %d: a larger ceiling must hold more source", small, large)
	}
	for _, ceiling := range []int64{2 << 30, 4 << 30, 16 << 30} {
		limit, budget := oneGraphSourceBytes(ceiling), sourceBudgetBytes(ceiling)
		detail := detailBufferBytes(ceiling)
		// The limit is what one graph's node detail fits in, so a target inside it is
		// scanned as one graph and nothing about that scan changes.
		if limit*detailBytesPerSourceByte > detail {
			t.Errorf("ceiling %d: %d bytes of source needs about %d bytes of node detail, over the %d-byte buffer",
				ceiling, limit, limit*detailBytesPerSourceByte, detail)
		}
		// A partition is smaller than the limit, so it stays clear of the spill that makes
		// binding matching read every node's detail back.
		if budget >= limit {
			t.Errorf("ceiling %d: partition budget %d is not below the one-graph limit %d", ceiling, budget, limit)
		}
	}
	// A tiny ceiling still has to leave a partition able to hold a source file.
	if got := sourceBudgetBytes(64 << 20); got < 1<<20 {
		t.Errorf("budget for a 64MiB ceiling = %d, too small to hold a source file", got)
	}
}

func TestApplyMaxRAMSetsAndClearsTheSourceBudget(t *testing.T) {
	cacheHome(t)
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	prevLimit, prevBudget := scanSourceLimit, scanSourceBudget
	t.Cleanup(func() { scanSourceLimit, scanSourceBudget = prevLimit, prevBudget })
	scanSourceLimit, scanSourceBudget = 0, 0

	cleanup := applyMaxRAM("8GB")
	if scanSourceBudget <= 0 || scanSourceLimit <= 0 {
		t.Errorf("source limit = %d, budget = %d under -max-ram 8GB, want positive bounds",
			scanSourceLimit, scanSourceBudget)
	}
	if scanSourceLimit >= lowering.DiskDetailBuf {
		t.Errorf("one-graph source limit %d is not below the %d-byte node detail buffer it must fit inside",
			scanSourceLimit, lowering.DiskDetailBuf)
	}
	cleanup()
	if scanSourceLimit != 0 || scanSourceBudget != 0 {
		t.Errorf("source limit = %d, budget = %d after cleanup, want 0: a later scan with no ceiling must not partition",
			scanSourceLimit, scanSourceBudget)
	}
}

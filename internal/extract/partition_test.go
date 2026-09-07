package extract_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
)

// partitionTree writes n JavaScript files of roughly size bytes each, spread over a few
// directories, and returns the root and the total source bytes.
func partitionTree(t *testing.T, n, size int) (string, int64) {
	t.Helper()
	root := t.TempDir()
	body := strings.Repeat("const filler = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";\n", size/50+1)
	var total int64
	for i := range n {
		dir := filepath.Join(root, fmt.Sprintf("pkg%d", i/4))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, fmt.Sprintf("mod%02d.js", i))
		src := fmt.Sprintf("export function f%d(q) { return q; }\n%s", i, body)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		total += int64(len(src))
	}
	return root, total
}

func TestPlanPartitionsBoundsEachPartitionAndCoversEveryFileOnce(t *testing.T) {
	root, total := partitionTree(t, 40, 2000)
	budget := total / 5

	parts := extract.PlanPartitions([]string{root}, nil, budget, budget)
	if len(parts) < 2 {
		t.Fatalf("PlanPartitions returned %d partition(s) for %d bytes at a %d budget, want several",
			len(parts), total, budget)
	}

	seen := map[string]int{}
	for i, part := range parts {
		var bytes int64
		var files int
		for p := range part {
			seen[p]++
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("partition %d names %s, which does not exist: %v", i, p, err)
			}
			bytes += fi.Size()
			files++
		}
		if files == 0 {
			t.Errorf("partition %d is empty", i)
		}
		// One file over the budget still gets a partition, so the bound only has to hold
		// for a partition holding more than one file.
		if files > 1 && bytes > budget {
			t.Errorf("partition %d holds %d bytes over a %d budget", i, bytes, budget)
		}
	}
	for p, n := range seen {
		if n != 1 {
			t.Errorf("%s is in %d partitions, want exactly 1", p, n)
		}
	}
	if len(seen) != 40 {
		t.Errorf("partitions cover %d files, want all 40", len(seen))
	}
}

func TestPlanPartitionsIsNilWhenTheTargetFitsTheBudget(t *testing.T) {
	root, total := partitionTree(t, 8, 500)
	// Under the limit, the partition size does not matter: a target one graph can hold is
	// scanned as one graph, so nothing about such a scan changes.
	if parts := extract.PlanPartitions([]string{root}, nil, total*4, total/8); parts != nil {
		t.Errorf("PlanPartitions returned %d partition(s) for a target inside the limit, want nil", len(parts))
	}
	if parts := extract.PlanPartitions([]string{root}, nil, total*4, total*4); parts != nil {
		t.Errorf("PlanPartitions returned %d partition(s) for a target inside the budget, want nil so the scan builds one graph", len(parts))
	}
	if parts := extract.PlanPartitions([]string{root}, nil, 0, 0); parts != nil {
		t.Errorf("PlanPartitions returned %d partition(s) with no budget set, want nil", len(parts))
	}
}

// A partitioned scan reports what it read from the merged per-partition stats, so those have to
// add up to what one pass over the whole tree reports. A count that summed twice or not at all
// would show as files scanned that were not, or unanalysed files nobody is told about.
func TestPartitionStatsMergeToTheWholeTreesStats(t *testing.T) {
	root, total := partitionTree(t, 24, 1500)
	// A file no frontend claims, so the unmatched count has something to carry.
	if err := os.WriteFile(filepath.Join(root, "notes.unknownext"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, _, whole, err := extract.All([]string{root}, nil)
	if err != nil {
		t.Fatalf("whole-tree extract: %v", err)
	}

	parts := extract.PlanPartitions([]string{root}, nil, total/4, total/4)
	if len(parts) < 2 {
		t.Fatalf("PlanPartitions returned %d partition(s), want several", len(parts))
	}
	var merged extract.Stats
	for _, part := range parts {
		_, _, _, st, err := extract.AllIn([]string{root}, nil, part)
		if err != nil {
			t.Fatalf("partition extract: %v", err)
		}
		merged = extract.MergeStats(merged, st)
	}

	if merged.TotalFiles() != whole.TotalFiles() {
		t.Errorf("merged parsed files = %d, whole tree = %d", merged.TotalFiles(), whole.TotalFiles())
	}
	for lang, n := range whole.Files {
		if merged.Files[lang] != n {
			t.Errorf("merged %s files = %d, whole tree = %d", lang, merged.Files[lang], n)
		}
	}
	if merged.UnmatchedTotal() != whole.UnmatchedTotal() {
		t.Errorf("merged unmatched = %d, whole tree = %d", merged.UnmatchedTotal(), whole.UnmatchedTotal())
	}
	if merged.Excluded != whole.Excluded {
		t.Errorf("merged excluded = %d, whole tree = %d: -exclude prunes the walk every partition repeats, so it must not sum",
			merged.Excluded, whole.Excluded)
	}
}

// The point of a partition is that the graph built from it covers that partition and nothing
// else, so the resident graph is bounded by the partition rather than by the clone.
func TestAllInReadsOnlyItsOwnPartition(t *testing.T) {
	root, total := partitionTree(t, 12, 1200)
	parts := extract.PlanPartitions([]string{root}, nil, total/3, total/3)
	if len(parts) < 2 {
		t.Fatalf("PlanPartitions returned %d partition(s), want several", len(parts))
	}

	for i, part := range parts {
		prog, _, _, st, err := extract.AllIn([]string{root}, nil, part)
		if err != nil {
			t.Fatalf("partition %d: %v", i, err)
		}
		if len(prog.Modules) == 0 {
			t.Fatalf("partition %d lowered no module", i)
		}
		for _, m := range prog.Modules {
			if m.File == "" {
				continue
			}
			if !part[m.File] && !part[filepath.Join(root, m.File)] {
				t.Errorf("partition %d built module %s, which is not in it", i, m.File)
			}
		}
		// A file is routed to every frontend that claims it (a .js file is read by both the
		// JavaScript and the text-pattern frontend), so the per-language counts are files
		// routed, not distinct files.
		for lang, n := range st.Files {
			if n > len(part) {
				t.Errorf("partition %d routed %d %s files from a partition of %d", i, n, lang, len(part))
			}
		}
	}
}

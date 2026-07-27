package main

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
)

// verboseOn enables progress logging to stderr: one line before each prominent pipeline phase,
// plus per-phase wall time and the file inventory. Off by default; `scan -v` turns it on.
// Diagnostics go to stderr so `-format json|sarif` piped to a file stays machine-readable.
var verboseOn = false

// timingOn enables per-phase wall-clock logging. Implied by -v.
var timingOn = false

// listFilesOn additionally prints every file being scanned, not just the largest ones.
var listFilesOn = false

func vlog(format string, args ...any) {
	if !verboseOn {
		return
	}
	fmt.Fprintf(os.Stderr, "[vyql] "+format+"\n", args...)
}

type timer struct {
	last  time.Time
	start time.Time
}

func newTimer() *timer {
	now := time.Now()
	return &timer{last: now, start: now}
}

// mark prints the elapsed wall time of the phase since the previous mark (when timing is on).
func (t *timer) mark(phase string) {
	if !timingOn {
		return
	}
	now := time.Now()
	fmt.Fprintf(os.Stderr, "[vyql] %-12s %8.1fms (total %8.1fms)\n",
		phase, float64(now.Sub(t.last))/1e6, float64(now.Sub(t.start))/1e6)
	t.last = now
}

// humanSize renders a byte count for the file inventory.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fKB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// logFileInventory reports what the walker decided to scan, largest first, plus everything it
// dropped and why. Size order is deliberate: a pathological input is almost always the biggest
// file, and seeing the top of that list next to the skip list is how you tell whether another
// guard or ignore pattern is needed.
func logFileInventory(files []string) {
	if !verboseOn {
		return
	}
	type fi struct {
		path string
		size int64
	}
	infos := make([]fi, 0, len(files))
	var total int64
	for _, f := range files {
		var sz int64
		if st, err := os.Stat(f); err == nil {
			sz = st.Size()
		}
		infos = append(infos, fi{f, sz})
		total += sz
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].size > infos[j].size })

	vlog("scanning %d file(s), %s total", len(infos), humanSize(total))
	show := len(infos)
	if !listFilesOn && show > 15 {
		show = 15
		vlog("largest %d (use -list-files for all):", show)
	}
	for _, f := range infos[:show] {
		vlog("    %8s  %s", humanSize(f.size), f.path)
	}
	if show < len(infos) {
		vlog("    ... %d more", len(infos)-show)
	}
	logSkipped()
}

// logSkipped prints what the walker dropped, grouped by reason and largest first.
func logSkipped() {
	list, counts, truncated := treesitter.SkippedFiles()
	if len(counts) == 0 {
		return
	}
	var reasons []string
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		vlog("skipped %d file(s): %s", counts[r], r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Size > list[j].Size })
	show := len(list)
	if !listFilesOn && show > 10 {
		show = 10
	}
	for _, f := range list[:show] {
		vlog("    %-9s %8s  %s", f.Reason, humanSize(f.Size), f.Path)
	}
	if show < len(list) {
		vlog("    ... %d more skipped", len(list)-show)
	}
	if truncated > 0 {
		vlog("    (+%d further skips not recorded; counts above are exact)", truncated)
	}
}

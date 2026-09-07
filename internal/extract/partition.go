package extract

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
)

// A scan builds one resident program graph, and that graph's size tracks the target's total
// analysable source rather than the budget the scan was given. Past a few megabytes of source
// the graph alone passes a fixed per-scan ceiling, and the run ends with no report at all —
// the memory watch stops it before the first rule runs.
//
// PlanPartitions divides the target's source files into groups small enough that one group's
// graph fits the budget, so a scan under a ceiling analyses the target as a sequence of graphs
// instead of one. It is the same partition boundary docs/adr/0001 draws around a repository,
// applied inside a repository that is itself too large for the budget.
//
// The cost is stated where it is paid: a flow whose source and sink land in different groups is
// not reported. Grouping walks the tree in path order so a directory's files stay together and
// the boundary falls between directories wherever it can, which is where cross-file flow is
// rarest.
//
// It takes two figures rather than one, because where to draw a boundary and whether to draw
// one at all are different questions. limit is the most source one graph may cover under the
// ceiling; a target inside it is scanned exactly as it was before — one graph, no boundary,
// nothing to say about it — and PlanPartitions returns nil. Above it, budget is how much source
// each group holds, and it is the smaller figure: a group sized at the limit sits on the edge of
// the node detail buffer, and a group that overruns it costs several times as much to bind.
func PlanPartitions(paths []string, excludes Excludes, limit, budget int64) []map[string]bool {
	if budget <= 0 || limit <= 0 {
		return nil
	}
	type weighted struct {
		path   string
		weight int64
	}
	var files []weighted
	var total int64
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil
		}
		var entries []treesitter.Entry
		if info.IsDir() {
			entries, _ = treesitter.ListAllFilesCounted(p, pruner(excludes))
			entries, _, _ = keepAnalysable(entries)
		} else {
			entries = []treesitter.Entry{{Path: p, Ext: strings.ToLower(filepath.Ext(p)), Base: strings.ToLower(filepath.Base(p))}}
		}
		// Only what a frontend will actually lower counts against the budget. A file no
		// frontend claims still has to belong to a group — it is what the coverage report
		// counts as unanalysed, and counting it in two groups would double it — but it
		// costs no graph, so it must not shrink the group it lands in.
		claimed := map[string]bool{}
		class := frontend.ClassifyEntries(entries)
		for _, lg := range frontend.Languages() {
			for _, f := range lg.FilesFor(entries, class) {
				claimed[f] = true
			}
		}
		for _, e := range entries {
			w := int64(0)
			if claimed[e.Path] {
				if fi, err := os.Stat(e.Path); err == nil {
					w = fi.Size()
				}
			}
			files = append(files, weighted{e.Path, w})
			total += w
		}
	}
	if total <= limit {
		return nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	var groups []map[string]bool
	cur := map[string]bool{}
	var curBytes int64
	curClaimed := 0
	for _, f := range files {
		// A single file over the budget still needs a group of its own: it cannot be split,
		// and refusing it would drop source the scan was pointed at.
		if curClaimed > 0 && curBytes+f.weight > budget {
			groups = append(groups, cur)
			cur, curBytes, curClaimed = map[string]bool{}, 0, 0
		}
		cur[f.path] = true
		curBytes += f.weight
		if f.weight > 0 {
			curClaimed++
		}
	}
	switch {
	case curClaimed > 0:
		groups = append(groups, cur)
	case len(groups) > 0:
		// A trailing run of files no frontend claims is not a partition — a build over it has
		// nothing to lower and reports the target as unreadable. It still has to be counted
		// once, so it joins the last real group rather than becoming one.
		for p := range cur {
			groups[len(groups)-1][p] = true
		}
	case len(cur) > 0:
		groups = append(groups, cur)
	}
	if len(groups) < 2 {
		return nil
	}
	// Const-folding reads `.properties` from the whole tree, and a value defined in one group
	// and used in another would otherwise fold in neither. They are configuration, not source,
	// so they weigh nothing and every group can hold them all.
	var props []string
	for _, f := range files {
		if strings.HasSuffix(f.path, ".properties") {
			props = append(props, f.path)
		}
	}
	for _, g := range groups {
		for _, p := range props {
			g[p] = true
		}
	}
	return groups
}

// keepAnalysable drops the entries no frontend should read: files over the -max-file-size
// ceiling and minified bundles. It reports how many of each it dropped, which the coverage
// report shows so a skipped file is never mistaken for a clean one.
//
// It is shared with the walk in All so a partition plan weighs exactly the files that plan's
// scans will lower.
func keepAnalysable(entries []treesitter.Entry) (kept []treesitter.Entry, oversized, minified int) {
	ceiling := treesitter.MaxFileBytes()
	bundleKinds := frontend.BundleKinds()
	kept = entries[:0]
	for _, e := range entries {
		fi, err := os.Stat(e.Path)
		if err == nil {
			if ceiling > 0 && fi.Size() > ceiling {
				oversized++
				continue
			}
			// A minified bundle is build output committed as an asset, not source:
			// parsing it costs far more memory than its size, and a committed
			// frontend holds enough bundles to push a bounded scan past its
			// ceiling before any finding is reported. SCA still reads their
			// banners — it walks the tree itself, past this filter.
			if (bundleKinds[e.Ext] || bundleKinds[e.Base]) && minifiedBundle(e.Path, fi.Size()) {
				minified++
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept, oversized, minified
}

// MergeStats folds one partition's stats into an accumulator.
//
// Per-file counts (parsed, oversized, minified, unmatched) sum: a partition sees only its own
// files, so each file is counted in exactly one of them. Excluded does not sum: -exclude prunes
// the walk, which every partition repeats in full, so each reports the same figure and the
// merged one is that figure, not a multiple of it.
func MergeStats(acc, part Stats) Stats {
	if acc.Files == nil {
		acc.Files = map[string]int{}
	}
	if acc.Unmatched == nil {
		acc.Unmatched = map[string]int{}
	}
	for lang, n := range part.Files {
		acc.Files[lang] += n
	}
	for kind, n := range part.Unmatched {
		acc.Unmatched[kind] += n
	}
	acc.Oversized += part.Oversized
	acc.Minified += part.Minified
	if part.Excluded > acc.Excluded {
		acc.Excluded = part.Excluded
	}
	seen := map[string]bool{}
	for _, lang := range acc.Languages {
		seen[lang] = true
	}
	for _, lang := range part.Languages {
		if !seen[lang] {
			seen[lang] = true
			acc.Languages = append(acc.Languages, lang)
		}
	}
	return acc
}

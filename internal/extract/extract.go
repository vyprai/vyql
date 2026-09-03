// Package extract is the scan pipeline: source paths in, an analysis graph out.
//
// It runs extract → lower → SCA → bindings, in that order, and owns the ordering decisions
// between those stages. The stages themselves live in the sub-packages — frontends under
// frontend/, lowering under lowering/, dependency evidence under sca/ — and this package is
// what composes them.
//
// It sat in package main, which put one pipeline stage outside the ownership boundaries every
// other stage respects, and made the whole composition reachable only through a command's
// globals and a real filesystem.
package extract

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// Stats reports per-language file counts for the run summary, and what the
// scan did NOT look at.
//
// The counts of untouched files are the point. "scanned python:1 — 0 findings"
// is a clean bill of health for one file and says nothing about the other forty
// in the tree; without the second number a reader cannot tell the difference
// between code that is clean and code that was never read.
type Stats struct {
	Files     map[string]int // language -> files parsed
	Languages []string       // languages actually present
	Excluded  int            // files dropped by -exclude
	Oversized int            // files skipped over the -max-file-size ceiling
	Minified  int            // files skipped as machine-generated (minified bundles)
	Unmatched map[string]int // extension -> count, claimed by no frontend
}

// UnmatchedTotal is the number of files present that no frontend analysed.
func (s Stats) UnmatchedTotal() int {
	n := 0
	for _, c := range s.Unmatched {
		n += c
	}
	return n
}

// TotalFiles is the number of files a frontend actually parsed, across all languages.
func (s Stats) TotalFiles() int {
	n := 0
	for _, c := range s.Files {
		n += c
	}
	return n
}

// All routes every path to the right frontend(s), merges into one NIR
// Program, and returns the union of binding applicators + constructor→type
// tables for the languages present.
func All(paths []string, excludes Excludes) (nir.Program, []bindings.Applicator, map[string]string, Stats, error) {
	var prog nir.Program
	present := map[string]bool{}
	stats := Stats{Files: map[string]int{}, Unmatched: map[string]int{}}
	// Every path a frontend claimed, so what is left over can be counted rather
	// than assumed to be nothing.
	claimed := map[string]bool{}
	kinds := map[string]string{} // path -> extension or basename, for the report

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return prog, nil, nil, stats, err
		}
		// Walk a directory ONCE and bucket files by language, instead of one full tree walk per
		// language (24+ walks dominated extraction on a large tree).
		var entries []treesitter.Entry
		root := p
		if info.IsDir() {
			var droppedByExclude int
			entries, droppedByExclude = treesitter.ListAllFilesCounted(p, pruner(excludes))
			stats.Excluded += droppedByExclude
			// Only filtered when walking a tree. Naming a file explicitly is an
			// instruction to scan that file, whatever its size or shape.
			ceiling := treesitter.MaxFileBytes()
			bundleKinds := frontend.BundleKinds()
			kept := entries[:0]
			oversized := 0
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
						stats.Minified++
						continue
					}
				}
				kept = append(kept, e)
			}
			stats.Oversized += oversized
			entries = kept
		} else {
			root = filepath.Dir(p)
			entries = []treesitter.Entry{{Path: p, Ext: strings.ToLower(filepath.Ext(p)), Base: strings.ToLower(filepath.Base(p))}}
		}
		for _, e := range entries {
			kind := e.Ext
			if kind == "" {
				kind = e.Base
			}
			kinds[e.Path] = kind
		}
		if props := propertiesFromEntries(entries); len(props) > 0 {
			if prog.Properties == nil {
				prog.Properties = map[string]string{}
			}
			for k, v := range props {
				prog.Properties[k] = v
			}
		}
		class := frontend.ClassifyEntries(entries)
		for _, lg := range frontend.Languages() {
			if lg.Name == "textpattern" && bindings.BindingConceptPruningActive() && len(lg.Bindings()) == 0 {
				continue
			}
			files := lg.FilesFor(entries, class)
			if len(files) == 0 {
				continue
			}
			sub, err := lg.Extract(files, root)
			if err != nil {
				return prog, nil, nil, stats, err
			}
			prog.Modules = append(prog.Modules, sub.Modules...)
			present[lg.Name] = true
			stats.Files[lg.Name] += len(files)
			for _, f := range files {
				claimed[f] = true
			}
		}
	}
	for path, kind := range kinds {
		if !claimed[path] {
			stats.Unmatched[kind]++
		}
	}

	var bindingApps []bindings.Applicator
	ctorTypes := map[string]string{}
	for _, lg := range frontend.Languages() {
		if present[lg.Name] {
			bindingApps = append(bindingApps, lg.Bindings()...)
			for k, v := range bindings.CtorTypesFor(lg.Name) {
				ctorTypes[k] = v
			}
			stats.Languages = append(stats.Languages, lg.Name)
		}
	}
	if len(prog.Modules) > 0 {
		bindingApps = append(bindingApps, bindings.AutoBindings()...)
	}
	return prog, bindingApps, ctorTypes, stats, nil
}

// pruner adapts the compiled exclusions to the walk. A nil set becomes a nil
// pruner, so an unfiltered walk pays nothing per entry.
func pruner(es Excludes) treesitter.Pruner {
	if len(es) == 0 {
		return nil
	}
	return es
}

// propertiesFromEntries parses `.properties` files from the already-built source inventory.
// Last value wins on duplicate keys (adequate for const-folding).
func propertiesFromEntries(entries []treesitter.Entry) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		if e.Ext != ".properties" {
			continue
		}
		b, err := os.ReadFile(e.Path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			eq := strings.IndexAny(line, "=:")
			if eq <= 0 {
				continue
			}
			k := strings.TrimSpace(line[:eq])
			v := strings.TrimSpace(line[eq+1:])
			if k != "" {
				out[k] = v
			}
		}
	}
	return out
}

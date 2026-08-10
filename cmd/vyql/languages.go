package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// scanStats reports per-language file counts for the run summary, and what the
// scan did NOT look at.
//
// The counts of untouched files are the point. "scanned python:1 — 0 findings"
// is a clean bill of health for one file and says nothing about the other forty
// in the tree; without the second number a reader cannot tell the difference
// between code that is clean and code that was never read.
type scanStats struct {
	files     map[string]int // language -> files parsed
	languages []string       // languages actually present
	excluded  int            // files dropped by -exclude
	oversized int            // files skipped over the -max-file-size ceiling
	unmatched map[string]int // extension -> count, claimed by no frontend
}

// unmatchedTotal is the number of files present that no frontend analysed.
func (s scanStats) unmatchedTotal() int {
	n := 0
	for _, c := range s.unmatched {
		n += c
	}
	return n
}

// extractAll routes every path to the right frontend(s), merges into one NIR
// Program, and returns the union of binding applicators + constructor→type
// tables for the languages present.
func extractAll(paths []string) (nir.Program, []bindings.Applicator, map[string]string, scanStats, error) {
	var prog nir.Program
	present := map[string]bool{}
	stats := scanStats{files: map[string]int{}, unmatched: map[string]int{}}
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
			entries = treesitter.ListAllFiles(p)
			// Only filtered when walking a tree. Naming a file explicitly is an
			// instruction to scan that file, whatever its size.
			if ceiling := treesitter.MaxFileBytes(); ceiling > 0 {
				kept := entries[:0]
				for _, e := range entries {
					if fi, err := os.Stat(e.Path); err == nil && fi.Size() > ceiling {
						continue
					}
					kept = append(kept, e)
				}
				stats.oversized += len(entries) - len(kept)
				entries = kept
			}
		} else {
			root = filepath.Dir(p)
			entries = []treesitter.Entry{{Path: p, Ext: strings.ToLower(filepath.Ext(p)), Base: strings.ToLower(filepath.Base(p))}}
		}
		if len(scanExcludes) > 0 {
			kept := entries[:0]
			for _, e := range entries {
				if !pathHasExcludedSegment(e.Path, scanExcludes) {
					kept = append(kept, e)
				}
			}
			stats.excluded += len(entries) - len(kept)
			entries = kept
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
			if lg.Name == "textpattern" && frontend.BindingConceptPruningActive() && len(lg.Bindings()) == 0 {
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
			stats.files[lg.Name] += len(files)
			for _, f := range files {
				claimed[f] = true
			}
		}
	}
	for path, kind := range kinds {
		if !claimed[path] {
			stats.unmatched[kind]++
		}
	}

	var bindingApps []bindings.Applicator
	ctorTypes := map[string]string{}
	for _, lg := range frontend.Languages() {
		if present[lg.Name] {
			bindingApps = append(bindingApps, lg.Bindings()...)
			for k, v := range frontend.CtorTypesFor(lg.Name) {
				ctorTypes[k] = v
			}
			stats.languages = append(stats.languages, lg.Name)
		}
	}
	if len(prog.Modules) > 0 {
		bindingApps = append(bindingApps, frontend.AutoBindings()...)
	}
	return prog, bindingApps, ctorTypes, stats, nil
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

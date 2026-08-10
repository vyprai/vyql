package extract

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/extract/sca"
	"github.com/vyprai/vyql/internal/graphsync"
	"github.com/vyprai/vyql/internal/timing"
	"github.com/vyprai/vyql/internal/usg"
)

// Options are the per-scan inputs to BuildGraph. They are fields rather than package state:
// as globals they made two scans in one process unsafe, and neither the exclude set nor the
// overlay was visible at the call site that depended on it.
type Options struct {
	// BindingConcepts, when non-nil, restricts binding application to the concepts the active
	// rules can actually reach (demand analysis).
	BindingConcepts map[string]bool
	// BindingOverlay is a directory of extra binding data layered over the built-in set.
	BindingOverlay string
	// Excludes are path segments dropped before extraction.
	Excludes []string
	// Sync, when non-nil, collects a graph-database change-feed during the build.
	Sync *graphsync.Collector
}

// SharedDeltaCache returns the process parse cache as a lowering.DeltaCache, or nil when
// caching is off. (A nil *parsecache.Cache must become a nil interface, not a non-nil
// interface holding nil.)
func SharedDeltaCache() lowering.DeltaCache {
	if c := parsecache.Shared(); c != nil {
		return c
	}
	return nil
}

// BuildGraph runs extract → lower → SCA → bindings and returns the analysis graph (the USG
// the rule engine evaluates against), plus what the extraction pass did and did not read.
// Returns a nil store when recognized files produced nothing to analyze.
func BuildGraph(paths []string, cache lowering.DeltaCache, opts Options) (usg.Store, Stats, error) {
	restoreConcepts := bindings.SetActiveBindingConcepts(opts.BindingConcepts)
	defer restoreConcepts()

	tk := timing.New()
	prog, bindingApps, ctorTypes, stats, err := All(paths, opts.Excludes)
	if err != nil {
		return nil, stats, err
	}
	tk.Mark("extract")
	// A tree with nothing parseable can still carry dependency evidence: applySCA does its own
	// walk and reads manifests and vendored library banners without needing a parsed module. A
	// project that vendors only minified bundles lands here, because the walker skips those as
	// unparseable — so run SCA before concluding there is nothing to report.
	if len(prog.Modules) == 0 {
		g := usg.NewInMemStore()
		sca.Apply(g, paths)
		nodes, err := g.AllNodes()
		if err != nil {
			return nil, stats, err
		}
		if len(nodes) == 0 {
			// Nothing parseable AND no dependency evidence. Distinguish "you pointed me at a
			// tree I cannot read" from "I read it and it is clean", so the former stays a
			// diagnosable error rather than a silent zero-finding pass.
			if len(stats.Files) == 0 {
				return nil, stats, fmt.Errorf("no supported source found under %s", strings.Join(paths, ", "))
			}
			return nil, stats, nil
		}
		if _, _, err := bindings.Apply(g, bindings.AutoBindings(), nil); err != nil {
			return nil, stats, err
		}
		tk.Mark("sca+bindings")
		return g, stats, nil
	}
	// Incremental lowering when a cache is provided: reuse the lowered sub-graph of unchanged
	// modules, re-lowering only edited ones. Equivalent to LowerTyped (the merged graph is
	// identical), so bindings/taint/rules below are untouched. Benefits every command that
	// builds a graph (scan, trace, query, graph, …).
	var g usg.Store
	var fresh map[string]bool
	incremental := cache != nil
	if incremental {
		g, fresh, err = lowering.LowerIncremental(prog, true, ctorTypes, cache, opts.Sync)
	} else {
		g, err = lowering.LowerTyped(prog, true, ctorTypes)
	}
	if err != nil {
		return nil, stats, err
	}
	tk.Mark("lower")
	// SCA runs before binding apply so SBOM/manifest packages join the import evidence
	// that gates package-aware bindings (the generated catalog included).
	sca.Apply(g, paths)
	// Dynamic, dependency-gated package bindings: load the generated per-package catalog
	// only for packages this project actually depends on, then apply alongside the static
	// framework bindings.
	deps := bindings.DependencyEvidence(g)
	for _, lang := range stats.Languages {
		bindingApps = append(bindingApps, bindings.GeneratedPackageBindingsFor(lang, deps)...)
	}
	if overlay := strings.TrimSpace(opts.BindingOverlay); overlay != "" {
		extra, err := bindings.OverlayBindings(overlay, stats.Languages)
		if err != nil {
			return nil, stats, fmt.Errorf("binding overlay: %w", err)
		}
		bindingApps = append(bindingApps, extra...)
	}
	tk.Mark("sca+pkg")
	// Binding labeling: incremental (reuse unchanged modules' cached labels) when caching is
	// on, else a full pass. Both produce identical labels — binding precedence is per-node.
	if incremental {
		relabel, err := bindings.ApplyIncremental(g, bindingApps, ModuleHashes(prog), deps, cache)
		if err != nil {
			return nil, stats, err
		}
		// Graph DB change-feed: collect the label rows of every label-dirty module. Label-dirty
		// is the binding relabel set plus the lowering fresh set (a fresh module's labels may also
		// have changed; re-emitting unchanged ones is an idempotent upsert). Nodes come from the
		// same pass (fresh set); edges were collected creator-attributed during lowering.
		if opts.Sync != nil {
			labelDirty := map[string]bool{}
			for ns := range fresh {
				labelDirty[ns] = true
			}
			for ns := range relabel {
				labelDirty[ns] = true
			}
			for ns := range labelDirty {
				opts.Sync.MarkRelabel(ns)
			}
			if err := opts.Sync.CollectGraph(g, labelDirty); err != nil {
				return nil, stats, err
			}
		}
	} else if _, _, err := bindings.Apply(g, bindingApps, nil); err != nil {
		return nil, stats, err
	}
	tk.Mark("bindings")
	return g, stats, nil
}

// ModuleHashes maps each content-addressed module's namespace (lowering.ModuleNS) to its
// content hash, the per-module identity the incremental binding-label cache keys on. Modules
// without a Hash (native frontends) are omitted, so they are always relabeled.
func ModuleHashes(prog nir.Program) map[string]string {
	m := map[string]string{}
	for _, mod := range prog.Modules {
		if mod.Hash != "" {
			m[lowering.ModuleNS(mod)] = mod.Hash
		}
	}
	return m
}

package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/usg"
)

var scanBindingOverlay string

// scanExcludes holds path segments to skip during source discovery (e.g. "_vendor",
// "node_modules"). Set from --exclude; matched against whole path segments so
// "_vendor" skips src/pip/_vendor/... but not a file literally named my_vendor.py.
var scanExcludes []string

func parseExcludes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pathHasExcludedSegment reports whether any path segment of p equals an exclude.
func pathHasExcludedSegment(p string, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		for _, ex := range excludes {
			if seg == ex {
				return true
			}
		}
	}
	return false
}

type graphBuildOptions struct {
	BindingConcepts map[string]bool
}

// buildGraph runs extract → lower → bindings → SCA and returns the analysis graph (the
// USG the rule engine evaluates against). Shared by scanPaths and the -dump debug path.
// Returns a nil store when recognized files produced nothing to analyze.
func buildGraph(paths []string) (usg.Store, scanStats, error) {
	return buildGraphWithOptions(paths, lowerCache(), graphBuildOptions{})
}

// lowerCache returns the process cache as a lowering.DeltaCache, or nil when caching is off.
// (A nil *parsecache.Cache must become a nil interface, not a non-nil interface holding nil.)
func lowerCache() lowering.DeltaCache {
	if c := parsecache.Shared(); c != nil {
		return c
	}
	return nil
}

func buildGraphWithOptions(paths []string, cache lowering.DeltaCache, opts graphBuildOptions) (usg.Store, scanStats, error) {
	restoreConcepts := bindings.SetActiveBindingConcepts(opts.BindingConcepts)
	defer restoreConcepts()

	tk := newTimer()
	prog, bindingApps, ctorTypes, stats, err := extractAll(paths)
	if err != nil {
		return nil, stats, err
	}
	tk.mark("extract")
	// A tree with nothing parseable can still carry dependency evidence: applySCA does its own
	// walk and reads manifests and vendored library banners without needing a parsed module. A
	// project that vendors only minified bundles lands here, because the walker skips those as
	// unparseable — so run SCA before concluding there is nothing to report.
	if len(prog.Modules) == 0 {
		g := usg.NewInMemStore()
		applySCA(g, paths)
		nodes, err := g.AllNodes()
		if err != nil {
			return nil, stats, err
		}
		if len(nodes) == 0 {
			// Nothing parseable AND no dependency evidence. Distinguish "you pointed me at a
			// tree I cannot read" from "I read it and it is clean", so the former stays a
			// diagnosable error rather than a silent zero-finding pass.
			if len(stats.files) == 0 {
				return nil, stats, fmt.Errorf("no supported source found under %s", strings.Join(paths, ", "))
			}
			return nil, stats, nil
		}
		if _, _, err := bindings.Apply(g, bindings.AutoBindings(), nil); err != nil {
			return nil, stats, err
		}
		tk.mark("sca+bindings")
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
		g, fresh, err = lowering.LowerIncremental(prog, true, ctorTypes, cache, syncCollector)
	} else {
		g, err = lowering.LowerTyped(prog, true, ctorTypes)
	}
	if err != nil {
		return nil, stats, err
	}
	tk.mark("lower")
	// SCA runs before binding apply so SBOM/manifest packages join the import evidence
	// that gates package-aware bindings (the generated catalog included).
	applySCA(g, paths)
	// Dynamic, dependency-gated package bindings: load the generated per-package catalog
	// only for packages this project actually depends on, then apply alongside the static
	// framework bindings.
	deps := bindings.DependencyEvidence(g)
	for _, lang := range stats.languages {
		bindingApps = append(bindingApps, bindings.GeneratedPackageBindingsFor(lang, deps)...)
	}
	if overlay := strings.TrimSpace(scanBindingOverlay); overlay != "" {
		extra, err := bindings.OverlayBindings(overlay, stats.languages)
		if err != nil {
			return nil, stats, fmt.Errorf("binding overlay: %w", err)
		}
		bindingApps = append(bindingApps, extra...)
	}
	tk.mark("sca+pkg")
	// Binding labeling: incremental (reuse unchanged modules' cached labels) when caching is
	// on, else a full pass. Both produce identical labels — binding precedence is per-node.
	if incremental {
		relabel, err := bindings.ApplyIncremental(g, bindingApps, moduleHashes(prog), deps, cache)
		if err != nil {
			return nil, stats, err
		}
		// Graph DB change-feed: collect the label rows of every label-dirty module. Label-dirty
		// is the binding relabel set plus the lowering fresh set (a fresh module's labels may also
		// have changed; re-emitting unchanged ones is an idempotent upsert). Nodes come from the
		// same pass (fresh set); edges were collected creator-attributed during lowering.
		if syncCollector != nil {
			labelDirty := map[string]bool{}
			for ns := range fresh {
				labelDirty[ns] = true
			}
			for ns := range relabel {
				labelDirty[ns] = true
			}
			for ns := range labelDirty {
				syncCollector.MarkRelabel(ns)
			}
			if err := syncCollector.CollectGraph(g, labelDirty); err != nil {
				return nil, stats, err
			}
		}
	} else if _, _, err := bindings.Apply(g, bindingApps, nil); err != nil {
		return nil, stats, err
	}
	tk.mark("bindings")
	return g, stats, nil
}

// moduleHashes maps each content-addressed module's namespace (lowering.ModuleNS) to its
// content hash, the per-module identity the incremental binding-label cache keys on. Modules
// without a Hash (native frontends) are omitted, so they are always relabeled.
func moduleHashes(prog nir.Program) map[string]string {
	m := map[string]string{}
	for _, mod := range prog.Modules {
		if mod.Hash != "" {
			m[lowering.ModuleNS(mod)] = mod.Hash
		}
	}
	return m
}

// edgeTypes are the edge kinds dumped (data, control, guard, graph-domain).
var edgeTypes = []string{"FLOWS", "CONTROL", "PROTECTS", "CHECKS", "NET", "STEP"}

func printUSG(g usg.Store) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodeOrder(nodes[i]) < nodeOrder(nodes[j]) })
	fmt.Println("# NODES — id  type  loc  [region@order]  {concepts}  path=…")
	for _, n := range nodes {
		fmt.Println(nodeLine(g, n))
	}
	fmt.Println("\n# EDGES — src --TYPE--> dst")
	for _, n := range nodes {
		for _, et := range edgeTypes {
			es, _ := g.OutEdges(n.ID, et)
			for _, e := range es {
				fmt.Printf("%s --%s--> %s\n", e.Src, et, e.Dst)
			}
		}
	}
	return nil
}

// printTaint shows, for each source node, the set of FLOWS-reachable labelled nodes — so a
// broken taint chain (source not reaching its sink) is visible at a glance.
func printTaint(onto *ontology.Ontology, g usg.Store) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodeOrder(nodes[i]) < nodeOrder(nodes[j]) })
	for _, n := range nodes {
		if !isSource(onto, g, n.ID) {
			continue
		}
		fmt.Printf("\nSOURCE %s @ %s {%s}\n", n.ID, n.Prop("loc"), conceptsOf(g, n.ID))
		seen := map[string]bool{n.ID: true}
		queue := []string{n.ID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			es, _ := g.OutEdges(cur, "FLOWS")
			for _, e := range es {
				if !seen[e.Dst] {
					seen[e.Dst] = true
					queue = append(queue, e.Dst)
				}
			}
		}
		hits := 0
		for _, m := range nodes {
			if !seen[m.ID] || m.ID == n.ID {
				continue
			}
			if c := conceptsOf(g, m.ID); c != "" {
				kind := "·"
				if !isSource(onto, g, m.ID) {
					kind = "SINK?"
				}
				fmt.Printf("  %-5s reaches %s @ %s {%s}\n", kind, m.ID, m.Prop("loc"), c)
				hits++
			}
		}
		fmt.Printf("  (%d nodes reachable via FLOWS, %d labelled)\n", len(seen), hits)
	}
	return nil
}

func nodeLine(g usg.Store, n usg.Node) string {
	s := fmt.Sprintf("%-8s %-16s %s", n.ID, n.Type, n.Prop("loc"))
	if r := n.Prop("region"); r != "" {
		s += fmt.Sprintf("  [%s@%s]", r, n.Prop("order"))
	}
	if c := conceptsOf(g, n.ID); c != "" {
		s += "  {" + c + "}"
	}
	if p := n.Prop("callee_path"); p != "" {
		s += "  path=" + p
	} else if m := n.Prop("method"); m != "" {
		s += "  method=" + m
	}
	if v := n.Prop("vkind"); v != "" {
		s += "  vkind=" + v
	}
	return s
}

func conceptsOf(g usg.Store, id string) string {
	labels, _ := g.Labels(id)
	var cs []string
	for _, l := range labels {
		cs = append(cs, l.Concept)
	}
	return strings.Join(cs, ",")
}

// isSource reports whether a node carries a source concept label according to the loaded ontology.
func isSource(onto *ontology.Ontology, g usg.Store, id string) bool {
	labels, _ := g.Labels(id)
	for _, l := range labels {
		if isSourceConcept(onto, l.Concept) {
			return true
		}
	}
	return false
}

func nodeOrder(n usg.Node) int {
	o, err := strconv.Atoi(n.Prop("order"))
	if err != nil {
		return 1 << 30 // unordered nodes (no region) sort last
	}
	return o
}

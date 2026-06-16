package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/usg"
)

// buildGraph runs extract → lower → adapters → SCA and returns the analysis graph (the
// USG the rule engine evaluates against). Shared by scanPaths and the -dump debug path.
// Returns a nil store when recognized files produced nothing to analyze.
func buildGraph(paths []string) (usg.Store, scanStats, error) {
	return buildGraphWith(paths, lowerCache())
}

// lowerCache returns the process cache as a lowering.DeltaCache, or nil when caching is off.
// (A nil *parsecache.Cache must become a nil interface, not a non-nil interface holding nil.)
func lowerCache() lowering.DeltaCache {
	if c := parsecache.Shared(); c != nil {
		return c
	}
	return nil
}

// buildGraphWith runs extract → lower → adapters → SCA against an explicit lowering cache
// (nil = no caching / full lowering). Threading the cache makes the incremental path testable
// (a findings-equivalence harness injects its own cache).
func buildGraphWith(paths []string, cache lowering.DeltaCache) (usg.Store, scanStats, error) {
	tk := newTimer()
	prog, ads, ctorTypes, stats, err := extractAll(paths)
	if err != nil {
		return nil, stats, err
	}
	tk.mark("extract")
	if len(stats.files) == 0 {
		return nil, stats, fmt.Errorf("no supported source found under %s", strings.Join(paths, ", "))
	}
	if len(prog.Modules) == 0 {
		return nil, stats, nil
	}
	// Incremental lowering when a cache is provided: reuse the lowered sub-graph of unchanged
	// modules, re-lowering only edited ones. Equivalent to LowerTyped (the merged graph is
	// identical), so adapters/taint/rules below are untouched. Benefits every command that
	// builds a graph (scan, trace, query, graph, …).
	var g usg.Store
	incremental := cache != nil
	if incremental {
		g, _, err = lowering.LowerIncremental(prog, true, ctorTypes, cache)
	} else {
		g, err = lowering.LowerTyped(prog, true, ctorTypes)
	}
	if err != nil {
		return nil, stats, err
	}
	tk.mark("lower")
	// SCA runs before adapter apply so SBOM/manifest packages join the import evidence
	// that gates package-aware adapters (the generated catalog included).
	applySCA(g, paths)
	// Dynamic, dependency-gated package adapters: load the generated per-package catalog
	// only for packages this project actually depends on, then apply alongside the static
	// framework adapters.
	deps := frontend.DependencyEvidence(g)
	for _, lang := range stats.languages {
		ads = append(ads, frontend.GeneratedPackageAdaptersFor(lang, deps)...)
	}
	tk.mark("sca+pkg")
	// Adapter labeling: incremental (reuse unchanged modules' cached labels) when caching is
	// on, else a full pass. Both produce identical labels — adapter precedence is per-node.
	if incremental {
		if err := applyAdaptersIncremental(g, ads, moduleHashes(prog), deps, cache); err != nil {
			return nil, stats, err
		}
	} else if _, _, err := adapters.Apply(g, ads, nil); err != nil {
		return nil, stats, err
	}
	tk.mark("adapters")
	return g, stats, nil
}

// moduleHashes maps each content-addressed module's namespace (lowering.ModuleNS) to its
// content hash, the per-module identity the incremental adapter-label cache keys on. Modules
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

// dumpGraph prints the analysis graph for debugging instead of running rules.
//
//	graph — every node (id, type, loc, region@order, concept labels, callee_path) + edges
//	taint — for each source node, the FLOWS-reachable labelled nodes (shows where a taint
//	        chain reaches a sink, or dead-ends)
func dumpGraph(paths []string, mode string) error {
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	switch mode {
	case "graph":
		return printUSG(g)
	case "taint":
		return printTaint(g)
	default:
		return fmt.Errorf("unknown -dump mode %q (use: graph | taint)", mode)
	}
}

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
func printTaint(g usg.Store) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodeOrder(nodes[i]) < nodeOrder(nodes[j]) })
	for _, n := range nodes {
		if !isSource(g, n.ID) {
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
				if !isSource(g, m.ID) {
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

// isSource reports whether a node carries an input/source concept label.
func isSource(g usg.Store, id string) bool {
	labels, _ := g.Labels(id)
	for _, l := range labels {
		if strings.Contains(l.Concept, "Input") || strings.Contains(l.Concept, "UserControlled") ||
			strings.Contains(l.Concept, "Argument") || strings.Contains(l.Concept, "DatabaseRead") ||
			strings.Contains(l.Concept, "SecretValue") {
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

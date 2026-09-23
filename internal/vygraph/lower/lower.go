// Package lower is the shared, language-agnostic lowering pass over NIR: it
// runs import/name resolution once (the source of qualified_path and the CALLS
// call graph) and computes the intraprocedural FLOWS value substrate (graph
// suite 03 §4-5). Resolution resolves names and types — never frameworks, never
// security.
package lower

import (
	"fmt"
	"sort"
	"strings"

	fepython "github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Run computes resolution and FLOWS over an extracted store. imports maps each
// file to its import table (from the frontends).
func Run(g *graph.Store, imports map[string]fepython.Imports) error {
	resolution(g, imports)
	if err := childFlows(g); err != nil {
		return err
	}
	return nameThreading(g)
}

// resolution fills qualified_path on Call/Attr/Index nodes from the import
// tables and the program's own function definitions, and materializes CALLS
// edges from resolved call sites to their callees.
func resolution(g *graph.Store, imports map[string]fepython.Imports) {
	// Index the program's functions by name for intra-module resolution.
	funcs := map[string]graph.Node{}
	for _, fd := range g.NodesOfType("code.FuncDef") {
		if v, ok := fd.Fields.Get("name"); ok {
			funcs[v.S] = fd
		}
	}
	for _, typ := range []string{"code.Call", "code.Attr", "code.Index"} {
		for _, n := range g.NodesOfType(typ) {
			pathV, ok := n.Fields.Get("path")
			if !ok || pathV.S == "" {
				continue
			}
			fileV, _ := n.Fields.Get("file")
			imp := imports[fileV.S]
			segs := strings.Split(pathV.S, ".")
			head, rest := segs[0], segs[1:]

			qualify := func(q string) {
				if stored, ok := g.Node(n.ID); ok {
					sf := stored.Fields
					sf.Set("qualified_path", graph.Str(q))
					stored.Fields = sf
					_ = g.Upsert(stored)
				}
			}

			if mod, ok := imp.Modules[head]; ok {
				qualify(strings.Join(append([]string{mod}, rest...), "."))
				continue
			}
			if mod, ok := imp.From[head]; ok {
				qualify(strings.Join(append([]string{mod}, rest...), "."))
				continue
			}
			// Intra-module: a call to a locally defined function resolves to
			// this file's module and links the CALLS edge.
			if typ == "code.Call" {
				if callee, ok := n.Fields.Get("callee"); ok {
					if fd, isFn := funcs[callee.S]; isFn {
						if fileV2, ok2 := fd.Fields.Get("file"); ok2 && fileV2.S == fileV.S {
							qualify(fileV.S + ":" + callee.S)
							_ = g.AddEdge(graph.Edge{
								ID: "calls:" + n.ID + ":" + fd.ID, Type: "CALLS",
								From: n.ID, To: fd.ID,
								Prov: graph.Provenance{Producer: "lower", Build: graph.BuildResolved, Trust: graph.TrustTrusted},
							})
						}
					}
				}
			}
		}
	}
}

// childFlows materializes the expression-level value edges: every child value
// flows into its consumer (arg into call, part into format, element into
// container, key into index, base into attribute).
func childFlows(g *graph.Store) error {
	for _, layer := range []graph.Layer{graph.LayerLow} {
		for _, n := range g.NodesOfLayer(layer) {
			for _, e := range g.Out(n.ID, "child") {
				fe := graph.Edge{
					ID:   "flows:child:" + e.ID,
					Type: "FLOWS", From: e.To, To: n.ID,
					Prov: graph.Provenance{Producer: "lower", Build: graph.BuildResolved, Trust: graph.TrustTrusted},
				}
				if err := g.AddEdge(fe); err != nil {
					return fmt.Errorf("child flow: %w", err)
				}
			}
		}
	}
	return nil
}

// nameThreading links consecutive occurrences of the same local within a
// function: the value bound into a variable flows to its next use. This is the
// intraprocedural def-use substrate; interprocedural taint is the solver's
// summary job, never inlined here.
func nameThreading(g *graph.Store) error {
	type occ struct {
		id     string
		order  int64
		region string
	}
	byName := map[string][]occ{}
	for _, n := range g.NodesOfType("code.Name") {
		local, ok := n.Fields.Get("local")
		if !ok || local.S == "" {
			continue
		}
		fileV, _ := n.Fields.Get("file")
		orderV, _ := n.Fields.Get("order")
		regionV, _ := n.Fields.Get("region")
		key := fileV.S + "|" + local.S
		byName[key] = append(byName[key], occ{id: n.ID, order: orderV.I, region: regionV.S})
	}
	for _, occs := range byName {
		sort.Slice(occs, func(i, j int) bool { return occs[i].order < occs[j].order })
		for i := 1; i < len(occs); i++ {
			prev, cur := occs[i-1], occs[i]
			if !sameFunction(prev.region, cur.region) {
				continue
			}
			if err := g.AddEdge(graph.Edge{
				ID:   fmt.Sprintf("flows:thread:%s:%d", prev.id, i),
				Type: "FLOWS", From: prev.id, To: cur.id,
				Prov: graph.Provenance{Producer: "lower", Build: graph.BuildResolved, Trust: graph.TrustTrusted},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// sameFunction reports whether two region paths sit in the same function
// (their first segment — fn:name or fn — matches).
func sameFunction(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return strings.SplitN(a, "/", 2)[0] == strings.SplitN(b, "/", 2)[0]
}

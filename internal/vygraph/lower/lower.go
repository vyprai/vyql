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

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Run computes resolution and FLOWS over an extracted store. imports maps each
// file to its alias->module table (each frontend's ImportTable()).
func Run(g *graph.Store, imports map[string]map[string]string) error {
	resolution(g, imports)
	if err := childFlows(g); err != nil {
		return err
	}
	return nameThreading(g)
}

// resolution fills qualified_path on Call/Attr/Index nodes from the import
// tables and the program's own function definitions, and materializes CALLS
// edges from resolved call sites to their callees.
func resolution(g *graph.Store, imports map[string]map[string]string) {
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
			mods := imports[fileV.S]
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

			if mod, ok := mods[head]; ok {
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
	thread := func(nodes []graph.Node, keyOf func(graph.Node) (string, bool)) {
		for _, n := range nodes {
			key, ok := keyOf(n)
			if !ok || key == "" {
				continue
			}
			fileV, _ := n.Fields.Get("file")
			orderV, _ := n.Fields.Get("order")
			regionV, _ := n.Fields.Get("region")
			byName[fileV.S+"|"+key] = append(byName[fileV.S+"|"+key], occ{id: n.ID, order: orderV.I, region: regionV.S})
		}
	}
	thread(g.NodesOfType("code.Name"), func(n graph.Node) (string, bool) {
		v, ok := n.Fields.Get("local")
		return v.S, ok
	})
	// Attribute and subscript reads thread by their dotted path within the
	// file — the write-self.X-in-__init__, read-self.X-in-method shape.
	thread(g.NodesOfType("code.Index"), func(n graph.Node) (string, bool) {
		v, ok := n.Fields.Get("path")
		return v.S, ok
	})
	for _, occs := range byName {
		sort.Slice(occs, func(i, j int) bool { return occs[i].order < occs[j].order })
		for i := 1; i < len(occs); i++ {
			prev, cur := occs[i-1], occs[i]
			if strings.Contains(prev.id, ":code.Name") && !sameFunction(prev.region, cur.region) {
				continue // locals thread within their function
			}
			// subscript paths thread file-wide by design
			if redefinedThrough(g, prev.id) {
				// `x = f(x)`: the occurrence inside f is the OLD value; the
				// call's result is the continuation. Threading from the
				// argument would carry the pre-transform value past the
				// transform — the sanitized value must not inherit it.
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
	// Attribute threading is prefix-based: a value bound into `a.b` flows to
	// every later read whose path extends it (`a.b.c`) in the same file. This
	// is the write-in-__init__, read-in-method shape, and the chained-read
	// decomposition — a def on a prefix reaches its extensions. An
	// over-approximation by design (no field sensitivity), which is the safe
	// direction for taint.
	type attrOcc struct {
		id    string
		order int64
		path  string
	}
	byFile := map[string][]attrOcc{}
	for _, n := range g.NodesOfType("code.Attr") {
		pv, ok := n.Fields.Get("path")
		if !ok || pv.S == "" {
			continue
		}
		fv, _ := n.Fields.Get("file")
		ov, _ := n.Fields.Get("order")
		byFile[fv.S] = append(byFile[fv.S], attrOcc{id: n.ID, order: ov.I, path: pv.S})
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		occs := byFile[f]
		sort.Slice(occs, func(i, j int) bool { return occs[i].order < occs[j].order })
		for i := 0; i < len(occs); i++ {
			for j := i + 1; j < len(occs); j++ {
				a, b := occs[i], occs[j]
				if redefinedThrough(g, a.id) {
					continue // the transform is the continuation, not the old value
				}
				if b.path == a.path || strings.HasPrefix(b.path, a.path+".") {
					if err := g.AddEdge(graph.Edge{
						ID:   fmt.Sprintf("flows:attr:%s:%s", a.id, b.id),
						Type: "FLOWS", From: a.id, To: b.id,
						Prov: graph.Provenance{Producer: "lower", Build: graph.BuildResolved, Trust: graph.TrustTrusted},
					}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// redefinedThrough reports whether the node's value flowed into a call that
// also re-binds a variable (a def-flow out): the `x = f(x)` shape. The call's
// result is the value's continuation; threading from the argument past the
// call would let the pre-transform taint bypass the transform.
func redefinedThrough(g *graph.Store, id string) bool {
	for _, e := range g.Out(id, "FLOWS") {
		if !strings.HasPrefix(e.ID, "flows:child:") {
			continue
		}
		to, ok := g.Node(e.To)
		if !ok || to.Type != "code.Call" {
			continue
		}
		for _, de := range g.Out(to.ID, "FLOWS") {
			if strings.HasPrefix(de.ID, "flows:def:") {
				return true
			}
		}
	}
	return false
}

// sameFunction reports whether two region paths sit in the same function
// (their first segment — fn:name or fn — matches).
func sameFunction(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return strings.SplitN(a, "/", 2)[0] == strings.SplitN(b, "/", 2)[0]
}

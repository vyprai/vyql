package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/usg"
)

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

// buildGraph builds the analysis graph with this process's defaults: the shared parse cache
// and no per-scan options. Shared by the debug commands and the -dump path; `scan` goes
// through scanPathsWithProfileDemand, which has options to pass.
func buildGraph(paths []string) (usg.Store, extract.Stats, error) {
	return extract.BuildGraph(paths, extract.SharedDeltaCache(), extract.Options{Sync: syncCollector})
}

// edgeTypes are the edge kinds dumped (data, control, guard, graph-domain).
var edgeTypes = []string{"FLOWS", "CONTROL", "PROTECTS", "CHECKS", "NET", "STEP"}

func printUSG(g usg.Store) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SortOrder() < nodes[j].SortOrder() })
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

// nodeCells renders a node as tab-separated fields for a tabwriter, so a column
// sizes to the longest value present rather than to a width guessed in advance.
// Node IDs run well past any fixed width, which leaves a hand-tuned format
// misaligned exactly when a listing mixes short and long ids.
func nodeCells(g usg.Store, n usg.Node) string {
	return strings.Join([]string{n.ID, n.Type, n.Prop("loc"), nodeDetail(g, n)}, "\t")
}

// nodeDetail is the trailing annotation: region, concepts, callee path, value kind.
func nodeDetail(g usg.Store, n usg.Node) string {
	var s string
	if r := n.Prop("region"); r != "" {
		s += fmt.Sprintf("[%s@%s]  ", r, n.Prop("order"))
	}
	if c := conceptsOf(g, n.ID); c != "" {
		s += "{" + c + "}  "
	}
	if p := n.Prop("callee_path"); p != "" {
		s += "path=" + p + "  "
	} else if m := n.Prop("method"); m != "" {
		s += "method=" + m + "  "
	}
	if v := n.Prop("vkind"); v != "" {
		s += "vkind=" + v
	}
	return strings.TrimRight(s, " ")
}

// nodeLine is the fixed-width form, used by the full graph dump. That dump
// streams: a tabwriter would hold every line to measure the columns, and the
// dump is unbounded in the size of the scanned tree.
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

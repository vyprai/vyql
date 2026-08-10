package main

import (
	"fmt"
	"sort"
	"strconv"
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

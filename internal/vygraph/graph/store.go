package graph

import "fmt"

// Store holds the materialized graph: nodes, edges and labels. Nothing derived lives
// here — no taint path is an edge, no privilege closure is a node. Those are computed on
// demand by solvers.
type Store struct {
	schemas *Schemas

	nodes   map[string]Node
	byType  map[string][]string
	byLayer map[Layer][]string

	out    map[string][]Edge
	edges  map[string]Edge
	labels map[string][]Label
}

func New(s *Schemas) *Store {
	return &Store{
		schemas: s,
		nodes:   map[string]Node{},
		byType:  map[string][]string{},
		byLayer: map[Layer][]string{},
		out:     map[string][]Edge{},
		edges:   map[string]Edge{},
		labels:  map[string][]Label{},
	}
}

// AddNode validates the node against its registered schema before storing it. An
// unregistered type, a field contradicting the schema, or a Layer disagreeing with the
// schema is an error.
func (g *Store) AddNode(n Node) error {
	ts, ok := g.schemas.Lookup(n.Type)
	if !ok {
		return fmt.Errorf("node %s: unregistered type %q", n.ID, n.Type)
	}
	if ts.Layer != n.Layer {
		return fmt.Errorf("node %s: type %q is %s, node says %s", n.ID, n.Type, ts.Layer, n.Layer)
	}
	if err := ts.Validate(n.Fields); err != nil {
		return fmt.Errorf("node %s: %w", n.ID, err)
	}
	if _, dup := g.nodes[n.ID]; !dup {
		g.byType[n.Type] = append(g.byType[n.Type], n.ID)
		g.byLayer[n.Layer] = append(g.byLayer[n.Layer], n.ID)
	}
	g.nodes[n.ID] = n
	return nil
}

// AddEdge stores a relation. Both endpoints must already exist — a dangling edge is a
// bug in the producer, not a condition to tolerate at query time.
func (g *Store) AddEdge(e Edge) error {
	if _, ok := g.nodes[e.From]; !ok {
		return fmt.Errorf("edge %s: unknown From %q", e.ID, e.From)
	}
	if _, ok := g.nodes[e.To]; !ok {
		return fmt.Errorf("edge %s: unknown To %q", e.ID, e.To)
	}
	if _, ok := g.edges[e.ID]; ok {
		return fmt.Errorf("edge %q already exists", e.ID)
	}
	g.out[e.From] = append(g.out[e.From], e)
	g.edges[e.ID] = e
	return nil
}

// AddLabel attaches a concept to a node or edge. The target must exist. A label is
// keyed (Target, Concept, Provenance): re-adding the same key replaces; the same
// concept from a different provenance is a distinct label.
func (g *Store) AddLabel(l Label) error {
	_, isNode := g.nodes[l.Target]
	_, isEdge := g.edges[l.Target]
	if !isNode && !isEdge {
		return fmt.Errorf("label %q: unknown target %q", l.Concept, l.Target)
	}
	existing := g.labels[l.Target]
	for i, x := range existing {
		if x.Concept == l.Concept && x.Prov == l.Prov {
			existing[i] = l
			return nil
		}
	}
	g.labels[l.Target] = append(existing, l)
	return nil
}

func (g *Store) Node(id string) (Node, bool) { n, ok := g.nodes[id]; return n, ok }
func (g *Store) NodeCount() int              { return len(g.nodes) }

func (g *Store) NodesOfType(t string) []Node { return g.collect(g.byType[t]) }
func (g *Store) NodesOfLayer(l Layer) []Node { return g.collect(g.byLayer[l]) }

func (g *Store) collect(ids []string) []Node {
	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.nodes[id])
	}
	return out
}

// Out returns edges leaving from; edgeType "" matches every type.
func (g *Store) Out(from, edgeType string) []Edge {
	all := g.out[from]
	if edgeType == "" {
		out := make([]Edge, len(all))
		copy(out, all)
		return out
	}
	var out []Edge
	for _, e := range all {
		if e.Type == edgeType {
			out = append(out, e)
		}
	}
	return out
}

func (g *Store) LabelsOn(target string) []Label {
	out := make([]Label, len(g.labels[target]))
	copy(out, g.labels[target])
	return out
}

// Backing follows the backs edge from a high-level node to the low-level node it was
// lifted from. This is the bridge solvers use to run over low-level dataflow while being
// invoked by high-level rules.
func (g *Store) Backing(highID string) (Node, bool) {
	for _, e := range g.out[highID] {
		if e.Type == EdgeBacks {
			n, ok := g.nodes[e.To]
			return n, ok
		}
	}
	return Node{}, false
}

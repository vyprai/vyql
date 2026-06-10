// Package usg implements the Universal Security Graph (docs/04) for the Go
// production build of VyQL. It defines the node/edge/label model and a Store
// interface with two implementations: an in-memory working set (hot-path
// evaluation) and a BadgerDB-backed persistent fact store (at-rest, scale).
// This is the hybrid recorded in docs/adr/0002-go-badgerdb.md.
package usg

// Provenance records where a fact or label came from (docs/04 §provenance).
type Provenance struct {
	Extractor  string `json:"extractor,omitempty"`
	Adapter    string `json:"adapter,omitempty"`
	SourceRef  string `json:"sourceRef,omitempty"`
	Confidence string `json:"confidence,omitempty"` // high | medium | low
	Fidelity   string `json:"fidelity,omitempty"`   // syntactic | resolved | semantic
}

// Label is a concept annotation attached to a node by an adapter — the bridge
// between the graph and the ontology (docs/04, docs/06).
type Label struct {
	Concept    string            `json:"concept"`
	Provenance Provenance        `json:"provenance"`
	Detail     map[string]string `json:"detail,omitempty"`
}

// Node is a graph vertex with a namespaced type and typed properties.
type Node struct {
	ID    string            `json:"id"`
	Type  string            `json:"type"`
	Props map[string]string `json:"props,omitempty"`
	Scope string            `json:"scope,omitempty"`
}

// Prop returns a property value (empty string if absent).
func (n Node) Prop(k string) string {
	if n.Props == nil {
		return ""
	}
	return n.Props[k]
}

// Edge is a graph edge. Class A (materialized facts) and Class C (annotation)
// edges are stored; Class B virtual relations (taint/reach/assume) are never
// stored — they are computed by solvers (docs/04).
type Edge struct {
	Type  string            `json:"type"`
	Src   string            `json:"src"`
	Dst   string            `json:"dst"`
	Props map[string]string `json:"props,omitempty"`
}

// Prop returns an edge property value (empty string if absent).
func (e Edge) Prop(k string) string {
	if e.Props == nil {
		return ""
	}
	return e.Props[k]
}

// Store is the storage surface the engine and solvers depend on. Both the
// in-memory and BadgerDB backends implement it identically (verified by
// TestStoreEquivalence), so the engine is storage-agnostic.
type Store interface {
	AddNode(n Node) error
	AddEdge(e Edge) error
	AddLabel(nodeID string, l Label) error

	GetNode(id string) (Node, bool, error)
	// OutEdges returns edges leaving src. edgeType "" matches all types.
	OutEdges(src, edgeType string) ([]Edge, error)
	// InEdges returns edges entering dst. edgeType "" matches all types.
	InEdges(dst, edgeType string) ([]Edge, error)
	// NodesWithConcept returns ids of nodes carrying the concept label.
	NodesWithConcept(concept string) ([]string, error)
	// NodesOfType returns ids of nodes of the given namespaced type.
	NodesOfType(nodeType string) ([]string, error)
	// AllNodes returns every node (used by extraction adapters that match on
	// node properties, e.g. callee_path, and by the SBOM reachability linker).
	AllNodes() ([]Node, error)
	// Labels returns the labels attached to a node.
	Labels(nodeID string) ([]Label, error)

	Close() error
}

// BFS returns the set of node ids reachable from start within maxHops via the
// given edge type ("" = any), shared by both stores (reach/taint shape).
func BFS(s Store, start, edgeType string, maxHops int) (map[string]bool, error) {
	seen := map[string]bool{start: true}
	type item struct {
		id   string
		hops int
	}
	queue := []item{{start, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.hops >= maxHops {
			continue
		}
		edges, err := s.OutEdges(cur.id, edgeType)
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if !seen[e.Dst] {
				seen[e.Dst] = true
				queue = append(queue, item{e.Dst, cur.hops + 1})
			}
		}
	}
	return seen, nil
}

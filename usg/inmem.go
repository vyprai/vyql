package usg

// InMemStore is the in-memory working-set representation used for hot-path
// evaluation (docs/adr/0002). Maps + adjacency lists + a concept index.
type InMemStore struct {
	nodes      map[string]Node
	byType     map[string][]string // node type -> ids (so NodesOfType is O(result), not O(all))
	out        map[string][]Edge
	in         map[string][]Edge
	byConcpt   map[string][]string
	conceptHas map[string]map[string]bool // concept -> set of node ids (O(1) dedup for byConcpt)
	labels     map[string][]Label
}

func NewInMemStore() *InMemStore { return NewInMemStoreSized(0) }

// NewInMemStoreSized preallocates the node/edge maps for an expected node count, avoiding the
// repeated map growth (rehashing) of building a large graph from scratch — the incremental
// lowerer rebuilds the whole graph from cached deltas on every scan, so a good size hint cuts
// the insert cost. nodeHint <= 0 means "unknown" (start empty).
func NewInMemStoreSized(nodeHint int) *InMemStore {
	if nodeHint < 0 {
		nodeHint = 0
	}
	return &InMemStore{
		nodes:      make(map[string]Node, nodeHint),
		byType:     map[string][]string{},
		out:        make(map[string][]Edge, nodeHint),
		in:         make(map[string][]Edge, nodeHint),
		byConcpt:   map[string][]string{},
		conceptHas: map[string]map[string]bool{},
		labels:     make(map[string][]Label, nodeHint/4),
	}
}

// NodeCount returns the number of nodes (used as a size hint for preallocating a rebuilt graph).
func (s *InMemStore) NodeCount() int { return len(s.nodes) }

func (s *InMemStore) AddNode(n Node) error {
	if _, exists := s.nodes[n.ID]; !exists {
		s.byType[n.Type] = append(s.byType[n.Type], n.ID)
	}
	s.nodes[n.ID] = n
	return nil
}

// inIndexedTypes are the only edge types ever queried by InEdges (endpoint-guard resolution).
// Reverse-indexing only these — instead of every edge — roughly halves edge memory on large
// graphs, where FLOWS/STEP/NET edges dominate and are never traversed backwards.
var inIndexedTypes = map[string]bool{"PROTECTS": true, "CHECKS": true}

func (s *InMemStore) AddEdge(e Edge) error {
	s.out[e.Src] = append(s.out[e.Src], e)
	if inIndexedTypes[e.Type] {
		s.in[e.Dst] = append(s.in[e.Dst], e)
	}
	return nil
}

func (s *InMemStore) AddLabel(nodeID string, l Label) error {
	s.labels[nodeID] = append(s.labels[nodeID], l)
	// keep the concept index a SET of node ids: two adapters may label the same node with the
	// same concept (different provenance), but it is one node. A membership set makes the dedup
	// O(1) — a linear scan here was O(n²) on large graphs where a concept labels many nodes.
	seen := s.conceptHas[l.Concept]
	if seen == nil {
		seen = map[string]bool{}
		s.conceptHas[l.Concept] = seen
	}
	if seen[nodeID] {
		return nil
	}
	seen[nodeID] = true
	s.byConcpt[l.Concept] = append(s.byConcpt[l.Concept], nodeID)
	return nil
}

func (s *InMemStore) GetNode(id string) (Node, bool, error) {
	n, ok := s.nodes[id]
	return n, ok, nil
}

func (s *InMemStore) OutEdges(src, edgeType string) ([]Edge, error) {
	return filterEdges(s.out[src], edgeType), nil
}

// InEdges returns reverse edges of the in-indexed types only (PROTECTS/CHECKS); other types are
// not reverse-indexed (see inIndexedTypes) and return nothing.
func (s *InMemStore) InEdges(dst, edgeType string) ([]Edge, error) {
	return filterEdges(s.in[dst], edgeType), nil
}

func (s *InMemStore) NodesWithConcept(concept string) ([]string, error) {
	out := make([]string, len(s.byConcpt[concept]))
	copy(out, s.byConcpt[concept])
	return out, nil
}

func (s *InMemStore) NodesOfType(nodeType string) ([]string, error) {
	ids := s.byType[nodeType]
	out := make([]string, len(ids))
	copy(out, ids)
	return out, nil
}

func (s *InMemStore) AllNodes() ([]Node, error) {
	out := make([]Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out, nil
}

// RangeNodes streams every node to fn (stop early by returning false) WITHOUT materializing a
// full []Node copy. Adapters and SCA iterate all nodes once per pass; AllNodes' slice copy was a
// multi-GB transient allocation (and GC churn) on large graphs. fn must not retain the Node.
func (s *InMemStore) RangeNodes(fn func(Node) bool) {
	for _, n := range s.nodes {
		if !fn(n) {
			return
		}
	}
}

func (s *InMemStore) Labels(nodeID string) ([]Label, error) {
	out := make([]Label, len(s.labels[nodeID]))
	copy(out, s.labels[nodeID])
	return out, nil
}

// LabelsOf returns the node's labels WITHOUT copying — a read-only fast path for hot
// solver loops (the taint DFS touches every reachable node). Callers must not mutate the
// returned slice. Avoids the per-node allocation of Labels on million-node graphs.
func (s *InMemStore) LabelsOf(nodeID string) []Label { return s.labels[nodeID] }

// RangeOutEdges invokes fn for each out-edge of src matching edgeType ("" = all) without
// allocating a filtered slice (the hot-path complement to OutEdges). Stop early by
// returning false from fn.
func (s *InMemStore) RangeOutEdges(src, edgeType string, fn func(dst string) bool) {
	for _, e := range s.out[src] {
		if edgeType != "" && e.Type != edgeType {
			continue
		}
		if !fn(e.Dst) {
			return
		}
	}
}

func (s *InMemStore) Close() error { return nil }

func filterEdges(edges []Edge, edgeType string) []Edge {
	if edgeType == "" {
		out := make([]Edge, len(edges))
		copy(out, edges)
		return out
	}
	var out []Edge
	for _, e := range edges {
		if e.Type == edgeType {
			out = append(out, e)
		}
	}
	return out
}

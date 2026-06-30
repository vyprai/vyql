package usg

// IntStore is an int-indexed in-memory graph store: every node is referenced by a dense int32
// instead of its (long) string id, so adjacency and the type/concept indexes hold 4-byte ints
// rather than 16-byte string headers, and node payload lives in parallel slices (no per-node map
// or map-key string duplication). This is the in-RAM half of the disk-tier (design follow-up):
// stage 2 will move the id table + payload to BadgerDB, leaving only int-indexed adjacency in
// RAM. It implements usg.Store identically to InMemStore (verified by the shared suite), plus the
// hot-path fast methods (RangeOutEdges/LabelsOf/RangeNodes) the taint solver and binding applicators use.
type IntStore struct {
	idx map[string]int32 // id -> index (stage 2: replace with hash -> index, ids on disk)
	ids []string         // index -> id

	typ        []string // index -> node type
	loc        []string
	region     []string
	order      []int32
	hasOrder   []bool
	scope      []string
	method     []string // index -> hot inlined props (kept out of the props map)
	calleePath []string
	strArgs    []string
	vkind      []string
	props      []map[string]string // index -> extras (usually nil)

	out [][]iedge         // index -> outgoing edges
	in  map[int32][]iedge // reverse edges, ONLY for inIndexedTypes (sparse)

	byType     map[string][]int32
	typeIDs    map[string][]string
	byConcept  map[string][]int32
	conceptHas map[string]map[int32]bool
	labels     [][]Label // index -> labels
	epoch      uint64    // structural epoch (see usg/epoch.go); bumped on AddNode/AddEdge
}

// StructEpoch reports the store's structural epoch. See usg/epoch.go.
func (s *IntStore) StructEpoch() uint64 { return s.epoch }

type iedge struct {
	typ   string
	dst   int32
	props map[string]string
}

// IntGraph is the int-indexed fast path for hot-loop analysis (taint/reach): nodes are addressed
// by dense int32, so a solver needs no string ids or payload in its inner loop. This is what lets
// an out-of-core store keep only int adjacency + label sets resident while ids/payload live on
// disk. Implemented by IntStore (and, later, its disk-backed variant).
type IntGraph interface {
	NodeCount() int
	ConceptNodes(concept string) []int32
	RangeOut(src int32, edgeType string, fn func(dst int32) bool)
	LabelsAt(idx int32) []Label
	NodeID(idx int32) string
}

var _ IntGraph = (*IntStore)(nil)

// NewIntStore creates an int-indexed store, optionally presized for an expected node count.
func NewIntStore(nodeHint int) *IntStore {
	if nodeHint < 0 {
		nodeHint = 0
	}
	return &IntStore{
		idx:        make(map[string]int32, nodeHint),
		ids:        make([]string, 0, nodeHint),
		typ:        make([]string, 0, nodeHint),
		loc:        make([]string, 0, nodeHint),
		region:     make([]string, 0, nodeHint),
		order:      make([]int32, 0, nodeHint),
		hasOrder:   make([]bool, 0, nodeHint),
		scope:      make([]string, 0, nodeHint),
		props:      make([]map[string]string, 0, nodeHint),
		out:        make([][]iedge, 0, nodeHint),
		in:         map[int32][]iedge{},
		byType:     map[string][]int32{},
		typeIDs:    map[string][]string{},
		byConcept:  map[string][]int32{},
		conceptHas: map[string]map[int32]bool{},
		labels:     nil,
	}
}

// intern returns the index for id, creating a fresh node slot (with empty payload) if new.
func (s *IntStore) intern(id string) int32 {
	if i, ok := s.idx[id]; ok {
		return i
	}
	i := int32(len(s.ids))
	s.idx[id] = i
	s.ids = append(s.ids, id)
	s.typ = append(s.typ, "")
	s.loc = append(s.loc, "")
	s.region = append(s.region, "")
	s.order = append(s.order, 0)
	s.hasOrder = append(s.hasOrder, false)
	s.scope = append(s.scope, "")
	s.method = append(s.method, "")
	s.calleePath = append(s.calleePath, "")
	s.strArgs = append(s.strArgs, "")
	s.vkind = append(s.vkind, "")
	s.props = append(s.props, nil)
	s.out = append(s.out, nil)
	return i
}

func (s *IntStore) nodeAt(i int32) Node {
	return Node{
		ID: s.ids[i], Type: s.typ[i], Loc: s.loc[i], Region: s.region[i],
		Order: s.order[i], HasOrder: s.hasOrder[i], Scope: s.scope[i],
		Method: s.method[i], CalleePath: s.calleePath[i], StrArgs: s.strArgs[i], Vkind: s.vkind[i],
		Props: s.props[i],
	}
}

func (s *IntStore) AddNode(n Node) error {
	i, existed := s.idx[n.ID]
	if !existed {
		i = s.intern(n.ID)
	}
	if s.typ[i] != n.Type { // first set (or a retype) updates the type index
		if existed && s.typ[i] != "" {
			s.removeFromType(s.typ[i], i)
			delete(s.typeIDs, s.typ[i])
		}
		s.byType[n.Type] = append(s.byType[n.Type], i)
		delete(s.typeIDs, n.Type)
	}
	s.typ[i] = n.Type
	s.loc[i] = n.Loc
	s.region[i] = n.Region
	s.order[i] = n.Order
	s.hasOrder[i] = n.HasOrder
	s.scope[i] = n.Scope
	// Carry the hottest properties in columns and, when a node has nothing else, drop its
	// Props map entirely — leaf value nodes (the bulk of the graph) then hold no map, which
	// is the dominant heap/GC saving on large graphs.
	s.method[i] = n.Method
	s.calleePath[i] = n.CalleePath
	s.strArgs[i] = n.StrArgs
	s.vkind[i] = n.Vkind
	props := n.Props
	if props != nil {
		if v, ok := props["method"]; ok {
			s.method[i] = v
		}
		if v, ok := props["callee_path"]; ok {
			s.calleePath[i] = v
		}
		if v, ok := props["str_args"]; ok {
			s.strArgs[i] = v
		}
		if v, ok := props["vkind"]; ok {
			s.vkind[i] = v
		}
		if PropsOnlyInlined(props) {
			props = nil
		}
	}
	s.props[i] = props
	s.epoch = nextStructEpoch()
	return nil
}

func (s *IntStore) removeFromType(t string, i int32) {
	ids := s.byType[t]
	for k, v := range ids {
		if v == i {
			s.byType[t] = append(ids[:k], ids[k+1:]...)
			return
		}
	}
}

func (s *IntStore) AddEdge(e Edge) error {
	si, di := s.intern(e.Src), s.intern(e.Dst)
	s.out[si] = append(s.out[si], iedge{typ: e.Type, dst: di, props: e.Props})
	if inIndexedTypes[e.Type] {
		s.in[di] = append(s.in[di], iedge{typ: e.Type, dst: si, props: e.Props})
	}
	s.epoch = nextStructEpoch()
	return nil
}

func (s *IntStore) AddLabel(nodeID string, l Label) error {
	i := s.intern(nodeID)
	for int(i) >= len(s.labels) {
		s.labels = append(s.labels, nil)
	}
	s.labels[i] = append(s.labels[i], l)
	seen := s.conceptHas[l.Concept]
	if seen == nil {
		seen = map[int32]bool{}
		s.conceptHas[l.Concept] = seen
	}
	if seen[i] {
		return nil
	}
	seen[i] = true
	s.byConcept[l.Concept] = append(s.byConcept[l.Concept], i)
	return nil
}

func (s *IntStore) GetNode(id string) (Node, bool, error) {
	i, ok := s.idx[id]
	if !ok {
		return Node{}, false, nil
	}
	return s.nodeAt(i), true, nil
}

func (s *IntStore) OutEdges(src, edgeType string) ([]Edge, error) {
	i, ok := s.idx[src]
	if !ok {
		return nil, nil
	}
	var out []Edge
	for _, e := range s.out[i] {
		if edgeType == "" || e.typ == edgeType {
			out = append(out, Edge{Type: e.typ, Src: src, Dst: s.ids[e.dst], Props: e.props})
		}
	}
	return out, nil
}

func (s *IntStore) InEdges(dst, edgeType string) ([]Edge, error) {
	i, ok := s.idx[dst]
	if !ok {
		return nil, nil
	}
	var out []Edge
	for _, e := range s.in[i] {
		if edgeType == "" || e.typ == edgeType {
			out = append(out, Edge{Type: e.typ, Src: s.ids[e.dst], Dst: dst, Props: e.props})
		}
	}
	return out, nil
}

func (s *IntStore) RangeInEdges(dst, edgeType string, fn func(src string) bool) {
	i, ok := s.idx[dst]
	if !ok {
		return
	}
	for _, e := range s.in[i] {
		if edgeType == "" || e.typ == edgeType {
			if !fn(s.ids[e.dst]) {
				return
			}
		}
	}
}

func (s *IntStore) NodesWithConcept(concept string) ([]string, error) {
	idxs := s.byConcept[concept]
	out := make([]string, len(idxs))
	for k, i := range idxs {
		out[k] = s.ids[i]
	}
	return out, nil
}

func (s *IntStore) NodesOfType(nodeType string) ([]string, error) {
	if ids, ok := s.typeIDs[nodeType]; ok {
		return ids, nil
	}
	idxs := s.byType[nodeType]
	out := make([]string, len(idxs))
	for k, i := range idxs {
		out[k] = s.ids[i]
	}
	s.typeIDs[nodeType] = out
	return out, nil
}

func (s *IntStore) RangeNodesOfType(nodeType string, fn func(Node) bool) {
	for _, i := range s.byType[nodeType] {
		if !fn(s.nodeAt(i)) {
			return
		}
	}
}

func (s *IntStore) AllNodes() ([]Node, error) {
	out := make([]Node, len(s.ids))
	for i := range s.ids {
		out[i] = s.nodeAt(int32(i))
	}
	return out, nil
}

func (s *IntStore) Labels(nodeID string) ([]Label, error) {
	i, ok := s.idx[nodeID]
	if !ok || int(i) >= len(s.labels) {
		return nil, nil
	}
	return s.labels[i], nil
}

func (s *IntStore) Close() error { return nil }

// --- hot-path fast methods (mirror InMemStore) ----------------------------------------------

func (s *IntStore) LabelsOf(nodeID string) []Label {
	i, ok := s.idx[nodeID]
	if !ok || int(i) >= len(s.labels) {
		return nil
	}
	return s.labels[i]
}

func (s *IntStore) RangeOutEdges(src, edgeType string, fn func(dst string) bool) {
	i, ok := s.idx[src]
	if !ok {
		return
	}
	for _, e := range s.out[i] {
		if edgeType == "" || e.typ == edgeType {
			if !fn(s.ids[e.dst]) {
				return
			}
		}
	}
}

func (s *IntStore) RangeNodes(fn func(Node) bool) {
	for i := range s.ids {
		if !fn(s.nodeAt(int32(i))) {
			return
		}
	}
}

func (s *IntStore) NodeCount() int { return len(s.ids) }

// --- IntGraph: int-indexed fast path for hot-loop analysis ----------------------------------

// ConceptNodes returns the indices of nodes carrying a concept (the source/sink/kill sets the
// taint solver iterates) without materializing any strings.
func (s *IntStore) ConceptNodes(concept string) []int32 { return s.byConcept[concept] }

// RangeOut visits the indices of out-neighbours along edgeType ("" = all). No string ids touched
// — the basis for spilling ids/payload to disk while taint stays fully in RAM on int adjacency.
func (s *IntStore) RangeOut(src int32, edgeType string, fn func(dst int32) bool) {
	if int(src) >= len(s.out) {
		return
	}
	for _, e := range s.out[src] {
		if edgeType == "" || e.typ == edgeType {
			if !fn(e.dst) {
				return
			}
		}
	}
}

// LabelsAt returns the labels on a node index (for kill-control checks in the fixpoint).
func (s *IntStore) LabelsAt(idx int32) []Label {
	if int(idx) >= len(s.labels) {
		return nil
	}
	return s.labels[idx]
}

// NodeID maps an index back to its string id — used only when emitting findings (a handful),
// never in the hot loop, so it can become a disk lookup in the out-of-core store.
func (s *IntStore) NodeID(idx int32) string { return s.ids[idx] }

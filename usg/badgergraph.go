package usg

import (
	"sync"

	badger "github.com/dgraph-io/badger/v4"
)

// BadgerGraph makes BadgerDB the source of truth for the analysis graph, with RAM bounded by
// Badger's block/value cache (sized to the user's --max-ram). When RAM is ample the graph is
// fully cached → ~in-memory speed; when it's tight, cold data pages from disk → bounded RAM.
//
// Records are compact binary (no JSON/gob reflection) and INT-INDEXED — nodes are referenced by
// a dense int32, so the taint hot loop (via usg.IntGraph) reads cached int adjacency blobs with
// near-zero decode. String ids and payload are fetched only when emitting findings or matching
// adapters. Key layout (\x00 separator, "g" graph namespace to coexist with the parse cache):
//
//	gI\0<id>          -> int32                 intern: id -> index
//	gx\0<idx>         -> id string             reverse: index -> id
//	gn\0<idx>         -> node detail blob       type/loc/region/order/scope/props
//	go\0<idx>         -> out-adjacency blob     []{typeId, dstIdx[, props]}
//	gr\0<idx>         -> in-adjacency blob      (only inIndexedTypes: PROTECTS/CHECKS)
//	gl\0<idx>         -> labels blob
//	gc\0<concept>     -> []int32 (nodes w/ concept)
//	gt\0<type>        -> []int32 (nodes of type)
//
// NOTE: this is the correctness foundation (build accumulates adjacency/labels in RAM, flushed to
// badger on Finalize). Streaming the build to bound PEAK RAM, and the make-default wiring, are
// the follow-on steps. Reads after Finalize are served from badger (cache-bounded).
type BadgerGraph struct {
	db    *badger.DB
	owned bool // we opened db and must close it

	mu       sync.Mutex
	finished bool

	// build-time accumulators (freed after Finalize); reads before Finalize hit these.
	idx        map[string]int32
	ids        []string
	det        []nodeDetail
	out        [][]iedge
	in         map[int32][]iedge
	labels     [][]Label
	byType     map[string][]int32
	byConcept  map[string][]int32
	conceptHas map[string]map[int32]bool
}

type nodeDetail struct {
	typ, loc, region, scope string
	order                   int32
	hasOrder                bool
	props                   map[string]string
}

// OpenBadgerGraph opens a graph store at path (":memory:" for an in-memory Badger) with a cache
// budget in bytes (block + value cache; 0 = Badger defaults).
func OpenBadgerGraph(path string, cacheBytes int64) (*BadgerGraph, error) {
	var opts badger.Options
	if path == ":memory:" {
		opts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		opts = badger.DefaultOptions(path)
	}
	opts = opts.WithLogger(nil)
	if cacheBytes > 0 {
		opts = opts.WithBlockCacheSize(cacheBytes * 7 / 10).WithIndexCacheSize(cacheBytes * 3 / 10)
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return NewBadgerGraphDB(db, true), nil
}

// NewBadgerGraphDB wraps an existing *badger.DB (e.g. the shared parse cache db) as a graph store.
func NewBadgerGraphDB(db *badger.DB, owned bool) *BadgerGraph {
	return &BadgerGraph{
		db: db, owned: owned,
		idx: map[string]int32{}, in: map[int32][]iedge{},
		byType: map[string][]int32{}, byConcept: map[string][]int32{},
		conceptHas: map[string]map[int32]bool{},
	}
}

func (g *BadgerGraph) intern(id string) int32 {
	if i, ok := g.idx[id]; ok {
		return i
	}
	i := int32(len(g.ids))
	g.idx[id] = i
	g.ids = append(g.ids, id)
	g.det = append(g.det, nodeDetail{})
	g.out = append(g.out, nil)
	g.labels = append(g.labels, nil)
	return i
}

func (g *BadgerGraph) AddNode(n Node) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	i, existed := g.idx[n.ID]
	if !existed {
		i = g.intern(n.ID)
	}
	if g.det[i].typ != n.Type {
		if existed && g.det[i].typ != "" {
			removeIdx(g.byType, g.det[i].typ, i)
		}
		g.byType[n.Type] = append(g.byType[n.Type], i)
	}
	g.det[i] = nodeDetail{typ: n.Type, loc: n.Loc, region: n.Region, scope: n.Scope,
		order: n.Order, hasOrder: n.HasOrder, props: n.Props}
	return nil
}

func (g *BadgerGraph) AddEdge(e Edge) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	si, di := g.intern(e.Src), g.intern(e.Dst)
	g.out[si] = append(g.out[si], iedge{typ: e.Type, dst: di, props: e.Props})
	if inIndexedTypes[e.Type] {
		g.in[di] = append(g.in[di], iedge{typ: e.Type, dst: si, props: e.Props})
	}
	return nil
}

func (g *BadgerGraph) AddLabel(nodeID string, l Label) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	i := g.intern(nodeID)
	g.labels[i] = append(g.labels[i], l)
	seen := g.conceptHas[l.Concept]
	if seen == nil {
		seen = map[int32]bool{}
		g.conceptHas[l.Concept] = seen
	}
	if !seen[i] {
		seen[i] = true
		g.byConcept[l.Concept] = append(g.byConcept[l.Concept], i)
	}
	return nil
}

func removeIdx(m map[string][]int32, k string, i int32) {
	s := m[k]
	for j, v := range s {
		if v == i {
			m[k] = append(s[:j], s[j+1:]...)
			return
		}
	}
}

// --- read API: served from RAM accumulators (pre-Finalize) ----------------------------------
// (post-Finalize disk reads land in a follow-on step; the accumulators stay valid until then.)

func (g *BadgerGraph) idxOf(id string) (int32, bool) { i, ok := g.idx[id]; return i, ok }

func (g *BadgerGraph) nodeAt(i int32) Node {
	d := g.det[i]
	return Node{ID: g.ids[i], Type: d.typ, Loc: d.loc, Region: d.region, Order: d.order,
		HasOrder: d.hasOrder, Scope: d.scope, Props: d.props}
}

func (g *BadgerGraph) GetNode(id string) (Node, bool, error) {
	i, ok := g.idxOf(id)
	if !ok {
		return Node{}, false, nil
	}
	return g.nodeAt(i), true, nil
}

func (g *BadgerGraph) OutEdges(src, edgeType string) ([]Edge, error) {
	i, ok := g.idxOf(src)
	if !ok {
		return nil, nil
	}
	var out []Edge
	for _, e := range g.out[i] {
		if edgeType == "" || e.typ == edgeType {
			out = append(out, Edge{Type: e.typ, Src: src, Dst: g.ids[e.dst], Props: e.props})
		}
	}
	return out, nil
}

func (g *BadgerGraph) InEdges(dst, edgeType string) ([]Edge, error) {
	i, ok := g.idxOf(dst)
	if !ok {
		return nil, nil
	}
	var out []Edge
	for _, e := range g.in[i] {
		if edgeType == "" || e.typ == edgeType {
			out = append(out, Edge{Type: e.typ, Src: g.ids[e.dst], Dst: dst, Props: e.props})
		}
	}
	return out, nil
}

func (g *BadgerGraph) NodesWithConcept(concept string) ([]string, error) {
	return g.idsOf(g.byConcept[concept]), nil
}
func (g *BadgerGraph) NodesOfType(nodeType string) ([]string, error) {
	return g.idsOf(g.byType[nodeType]), nil
}
func (g *BadgerGraph) idsOf(idxs []int32) []string {
	out := make([]string, len(idxs))
	for k, i := range idxs {
		out[k] = g.ids[i]
	}
	return out
}

func (g *BadgerGraph) AllNodes() ([]Node, error) {
	out := make([]Node, len(g.ids))
	for i := range g.ids {
		out[i] = g.nodeAt(int32(i))
	}
	return out, nil
}

func (g *BadgerGraph) Labels(nodeID string) ([]Label, error) {
	i, ok := g.idxOf(nodeID)
	if !ok {
		return nil, nil
	}
	return g.labels[i], nil
}

func (g *BadgerGraph) Close() error {
	if g.owned {
		return g.db.Close()
	}
	return nil
}

// --- IntGraph fast path ---------------------------------------------------------------------

func (g *BadgerGraph) NodeCount() int                      { return len(g.ids) }
func (g *BadgerGraph) ConceptNodes(concept string) []int32 { return g.byConcept[concept] }
func (g *BadgerGraph) LabelsAt(idx int32) []Label          { return g.labels[idx] }
func (g *BadgerGraph) NodeID(idx int32) string             { return g.ids[idx] }
func (g *BadgerGraph) LabelsOf(nodeID string) []Label      { l, _ := g.Labels(nodeID); return l }

func (g *BadgerGraph) RangeOut(src int32, edgeType string, fn func(dst int32) bool) {
	if int(src) >= len(g.out) {
		return
	}
	for _, e := range g.out[src] {
		if edgeType == "" || e.typ == edgeType {
			if !fn(e.dst) {
				return
			}
		}
	}
}

func (g *BadgerGraph) RangeOutEdges(src, edgeType string, fn func(dst string) bool) {
	i, ok := g.idxOf(src)
	if !ok {
		return
	}
	for _, e := range g.out[i] {
		if edgeType == "" || e.typ == edgeType {
			if !fn(g.ids[e.dst]) {
				return
			}
		}
	}
}

func (g *BadgerGraph) RangeNodes(fn func(Node) bool) {
	for i := range g.ids {
		if !fn(g.nodeAt(int32(i))) {
			return
		}
	}
}

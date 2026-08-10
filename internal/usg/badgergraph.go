package usg

import (
	"encoding/binary"
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
// bindings. Key layout (\x00 separator, "g" graph namespace to coexist with the parse cache):
//
//	gI\0<id>          -> int32                 intern: id -> index
//	gx\0<idx>         -> id string             reverse: index -> id
//	gn\0<idx>         -> node detail blob       type/loc/region/order/scope/props
//	go\0<idx>         -> out-adjacency blob     []{typeId, dstIdx[, props]}
//	gr\0<idx>         -> in-adjacency blob      (only inIndexedTypes)
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

	mu sync.Mutex

	// Resident structural core (int-indexed). Node DETAIL (loc/region/props/type) is NOT kept
	// here — it is streamed to badger so peak RAM is bounded by the core + a small write buffer +
	// badger's cache, not the full payload.
	idx        map[string]int32
	ids        []string
	out        [][]iedge
	in         map[int32][]iedge
	flowOut    [][]int32
	flowIn     [][]int32
	labels     [][]Label
	byType     map[string][]int32
	byConcept  map[string][]int32
	conceptHas map[string]map[int32]bool

	// write-back buffer for node detail, held as STRUCTS so resident reads share the stored
	// strings and props map instead of decoding a blob per read — encoding happens once, at
	// spill time. detCap == 0 means UNBOUNDED (no RAM ceiling): detail stays in RAM and is
	// never written to badger, so the build pays no write or codec cost at all. With a
	// ceiling, detCap bounds the buffer and detail spills to badger when full, so RAM stays
	// under budget (cold detail pages from disk).
	det        map[int32]nodeDetail
	detBytes   int   // approx bytes buffered (for the byte-accurate spill threshold)
	detCapByte int64 // spill when detBytes exceeds this (0 = unbounded)
}

type nodeDetail struct {
	typ, loc, region, scope string
	order                   int32
	hasOrder                bool
	props                   map[string]string
}

// OpenBadgerGraph opens a graph store at path (":memory:" for an in-memory Badger) with a cache
// budget in bytes (block + value cache; 0 = Badger defaults).
func OpenBadgerGraph(path string, cacheBytes, detailBufBytes int64) (*BadgerGraph, error) {
	var opts badger.Options
	if path == ":memory:" {
		opts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		opts = badger.DefaultOptions(path)
	}
	opts = opts.WithLogger(nil).
		WithSyncWrites(false).      // a scan-scoped graph: durability not needed, speed is
		WithCompression(0).         // skip per-block (de)compression CPU
		WithNumVersionsToKeep(1).   // no MVCC history
		WithMemTableSize(32 << 20). // memtable arenas are eager Go-heap allocations inside a RAM-bounded mode
		WithDetectConflicts(false)
	if cacheBytes > 0 {
		// The whole cache budget goes to the block cache. The index cache is only
		// consulted for encrypted DBs; funding it here spends budget on a cache
		// that is never populated.
		opts = opts.WithBlockCacheSize(cacheBytes).WithIndexCacheSize(0)
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	g := NewBadgerGraphDB(db, true)
	g.detCapByte = detailBufBytes // 0 = unbounded; else spill detail to badger past this many bytes
	return g, nil
}

// NewBadgerGraphDB wraps an existing *badger.DB (e.g. the shared parse cache db) as a graph store.
func NewBadgerGraphDB(db *badger.DB, owned bool) *BadgerGraph {
	return &BadgerGraph{
		db: db, owned: owned,
		idx: map[string]int32{}, in: map[int32][]iedge{},
		byType: map[string][]int32{}, byConcept: map[string][]int32{},
		conceptHas: map[string]map[int32]bool{}, det: map[int32]nodeDetail{},
	}
}

func (g *BadgerGraph) intern(id string) int32 {
	if i, ok := g.idx[id]; ok {
		return i
	}
	i := int32(len(g.ids))
	g.idx[id] = i
	g.ids = append(g.ids, id)
	g.out = append(g.out, nil)
	g.flowOut = append(g.flowOut, nil)
	g.flowIn = append(g.flowIn, nil)
	g.labels = append(g.labels, nil)
	return i
}

// typeOf returns a node's type without decoding its full detail (type leads the detail blob).
func (g *BadgerGraph) typeOf(i int32) string {
	if d, ok := g.det[i]; ok {
		return d.typ
	}
	if b := g.rawDet(i); b != nil {
		return (&detReader{b: b}).str()
	}
	return ""
}

func (g *BadgerGraph) AddNode(n Node) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	i, existed := g.idx[n.ID]
	if !existed {
		i = g.intern(n.ID)
	}
	if t := g.typeOf(i); t != n.Type {
		if existed && t != "" {
			removeIdx(g.byType, t, i)
		}
		g.byType[n.Type] = append(g.byType[n.Type], i)
	}
	d := nodeDetail{typ: n.Type, loc: n.Loc, region: n.Region, scope: n.Scope,
		order: n.Order, hasOrder: n.HasOrder, props: n.Props}
	if old, ok := g.det[i]; ok {
		g.detBytes -= estDetBytes(old)
	}
	g.det[i] = d
	g.detBytes += estDetBytes(d)
	if g.detCapByte > 0 && int64(g.detBytes) >= g.detCapByte {
		g.flushDet() // ceiling set: spill to badger to bound RAM
	}
	return nil
}

func (g *BadgerGraph) AddEdge(e Edge) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	si, di := g.intern(e.Src), g.intern(e.Dst)
	typ := edgeTypeIDFor(e.Type)
	if typ == edgeTypeFlows && len(e.Props) == 0 {
		g.flowOut[si] = append(g.flowOut[si], di)
		g.flowIn[di] = append(g.flowIn[di], si)
		return nil
	}
	g.out[si] = append(g.out[si], iedge{typ: typ, dst: di, props: e.Props})
	if edgeTypeInIndexed(typ) {
		g.in[di] = append(g.in[di], iedge{typ: typ, dst: si, props: e.Props})
	}
	return nil
}

// AddFlowEdgeIfPresent appends a prop-less FLOWS edge only when both endpoints already exist.
func (g *BadgerGraph) AddFlowEdgeIfPresent(src, dst string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	si, ok := g.idx[src]
	if !ok {
		return false
	}
	di, ok := g.idx[dst]
	if !ok {
		return false
	}
	g.flowOut[si] = append(g.flowOut[si], di)
	g.flowIn[di] = append(g.flowIn[di], si)
	return true
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

// estDetBytes approximates a detail's resident cost — string bytes plus struct and
// map-slot overhead — so the spill threshold keeps meaning "about this many bytes
// buffered" without encoding anything to find out.
func estDetBytes(d nodeDetail) int {
	n := len(d.typ) + len(d.loc) + len(d.region) + len(d.scope) + 96
	for k, v := range d.props {
		n += len(k) + len(v) + 48
	}
	return n
}

// rawDet returns a node's encoded detail from badger (cache-served). Resident detail
// lives as structs in g.det and never takes this path.
func (g *BadgerGraph) rawDet(i int32) []byte {
	var out []byte
	_ = g.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(detKey(i))
		if err != nil {
			return err
		}
		out, err = item.ValueCopy(nil)
		return err
	})
	return out
}

func (g *BadgerGraph) nodeAt(i int32) Node {
	d, ok := g.det[i]
	if !ok {
		d = decDet(g.rawDet(i))
	}
	return Node{ID: g.ids[i], Type: d.typ, Loc: d.loc, Region: d.region, Order: d.order,
		HasOrder: d.hasOrder, Scope: d.scope, Props: d.props}
}

// flushDet writes the buffered node details to badger in one transaction and clears the buffer,
// bounding RAM to the structural core + ~detBufMax buffered blobs + badger's cache.
func (g *BadgerGraph) flushDet() {
	if len(g.det) == 0 {
		return
	}
	wb := g.db.NewWriteBatch()
	for i, d := range g.det {
		_ = wb.Set(detKey(i), encDet(d))
	}
	_ = wb.Flush()
	g.det = map[int32]nodeDetail{}
	g.detBytes = 0
}

func detKey(i int32) []byte {
	b := make([]byte, 6)
	b[0], b[1] = 'g', 'n'
	binary.BigEndian.PutUint32(b[2:], uint32(i))
	return b
}

// Has reports whether a node id exists, without decoding its detail (existence-only fast path for
// the lowerer's flow() checks, so the build never reads detail back from disk).
func (g *BadgerGraph) Has(id string) bool { _, ok := g.idx[id]; return ok }

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
	if edgeTypeMatches(edgeTypeFlows, edgeType) {
		for _, dst := range g.flowOut[i] {
			out = append(out, Edge{Type: "FLOWS", Src: src, Dst: g.ids[dst]})
		}
	}
	for _, e := range g.out[i] {
		if edgeTypeMatches(e.typ, edgeType) {
			out = append(out, Edge{Type: edgeTypeName(e.typ), Src: src, Dst: g.ids[e.dst], Props: e.props})
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
	if edgeTypeMatches(edgeTypeFlows, edgeType) {
		for _, src := range g.flowIn[i] {
			out = append(out, Edge{Type: "FLOWS", Src: g.ids[src], Dst: dst})
		}
	}
	for _, e := range g.in[i] {
		if edgeTypeMatches(e.typ, edgeType) {
			out = append(out, Edge{Type: edgeTypeName(e.typ), Src: g.ids[e.dst], Dst: dst, Props: e.props})
		}
	}
	return out, nil
}

func (g *BadgerGraph) RangeInEdges(dst, edgeType string, fn func(src string) bool) {
	i, ok := g.idxOf(dst)
	if !ok {
		return
	}
	if edgeTypeMatches(edgeTypeFlows, edgeType) {
		for _, src := range g.flowIn[i] {
			if !fn(g.ids[src]) {
				return
			}
		}
	}
	for _, e := range g.in[i] {
		if edgeTypeMatches(e.typ, edgeType) {
			if !fn(g.ids[e.dst]) {
				return
			}
		}
	}
}

func (g *BadgerGraph) NodesWithConcept(concept string) ([]string, error) {
	return g.idsOf(g.byConcept[concept]), nil
}
func (g *BadgerGraph) NodesOfType(nodeType string) ([]string, error) {
	return g.idsOf(g.byType[nodeType]), nil
}

func (g *BadgerGraph) RangeNodesOfType(nodeType string, fn func(Node) bool) {
	for _, i := range g.byType[nodeType] {
		if !fn(g.nodeAt(i)) {
			return
		}
	}
}

func (g *BadgerGraph) idsOf(idxs []int32) []string {
	out := make([]string, len(idxs))
	for k, i := range idxs {
		out[k] = g.ids[i]
	}
	return out
}

func (g *BadgerGraph) AllNodes() ([]Node, error) {
	out := make([]Node, 0, len(g.ids))
	g.RangeNodes(func(n Node) bool { out = append(out, n); return true })
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
	g.flushDet()
	if g.owned {
		return g.db.Close()
	}
	return nil
}

// --- node-detail binary codec ---------------------------------------------------------------

type detWriter struct{ b []byte }

func (w *detWriter) u(n int) {
	for n >= 0x80 {
		w.b = append(w.b, byte(n)|0x80)
		n >>= 7
	}
	w.b = append(w.b, byte(n))
}
func (w *detWriter) str(s string) { w.u(len(s)); w.b = append(w.b, s...) }
func (w *detWriter) boolean(v bool) {
	if v {
		w.b = append(w.b, 1)
	} else {
		w.b = append(w.b, 0)
	}
}

type detReader struct {
	b []byte
	i int
}

func (r *detReader) u() int {
	var x int
	var s uint
	for {
		c := r.b[r.i]
		r.i++
		x |= int(c&0x7f) << s
		if c < 0x80 {
			return x
		}
		s += 7
	}
}
func (r *detReader) str() string {
	if r.i >= len(r.b) {
		return ""
	}
	n := r.u()
	s := string(r.b[r.i : r.i+n])
	r.i += n
	return s
}
func (r *detReader) boolean() bool { v := r.b[r.i] == 1; r.i++; return v }

// encDet writes type first (so typeOf can read it cheaply), then the rest of the payload.
func encDet(d nodeDetail) []byte {
	w := &detWriter{}
	w.str(d.typ)
	w.str(d.loc)
	w.str(d.region)
	w.str(d.scope)
	w.u(int(uint32(d.order)))
	w.boolean(d.hasOrder)
	w.u(len(d.props))
	for k, v := range d.props {
		w.str(k)
		w.str(v)
	}
	return w.b
}

func decDet(b []byte) nodeDetail {
	if len(b) == 0 {
		return nodeDetail{}
	}
	r := &detReader{b: b}
	d := nodeDetail{typ: r.str(), loc: r.str(), region: r.str(), scope: r.str()}
	d.order = int32(uint32(r.u()))
	d.hasOrder = r.boolean()
	if n := r.u(); n > 0 {
		d.props = make(map[string]string, n)
		for j := 0; j < n; j++ {
			k := r.str()
			d.props[k] = r.str()
		}
	}
	return d
}

// --- IntGraph fast path ---------------------------------------------------------------------

// Asserted, not assumed: solvers.FindTaintFlows dispatches on this interface and
// silently falls back to its string-keyed implementation for a store that does not
// satisfy it. The answers stay the same, but the hot loop starts touching string ids
// and payload — which is the whole cost this store exists to avoid — so losing
// conformance would surface only as an unexplained slowdown on large scans.
var _ IntGraph = (*BadgerGraph)(nil)

func (g *BadgerGraph) NodeCount() int                      { return len(g.ids) }
func (g *BadgerGraph) ConceptNodes(concept string) []int32 { return g.byConcept[concept] }
func (g *BadgerGraph) LabelsAt(idx int32) []Label          { return g.labels[idx] }
func (g *BadgerGraph) NodeID(idx int32) string             { return g.ids[idx] }
func (g *BadgerGraph) LabelsOf(nodeID string) []Label      { l, _ := g.Labels(nodeID); return l }

func (g *BadgerGraph) RangeOut(src int32, edgeType string, fn func(dst int32) bool) {
	if int(src) >= len(g.out) {
		return
	}
	if edgeTypeMatches(edgeTypeFlows, edgeType) {
		for _, dst := range g.flowOut[src] {
			if !fn(dst) {
				return
			}
		}
	}
	for _, e := range g.out[src] {
		if edgeTypeMatches(e.typ, edgeType) {
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
	if edgeTypeMatches(edgeTypeFlows, edgeType) {
		for _, dst := range g.flowOut[i] {
			if !fn(g.ids[dst]) {
				return
			}
		}
	}
	for _, e := range g.out[i] {
		if edgeTypeMatches(e.typ, edgeType) {
			if !fn(g.ids[e.dst]) {
				return
			}
		}
	}
}

// RangeNodes streams every node. It flushes the detail buffer, then reads detail via a single
// SEQUENTIAL badger scan of the gn\0 prefix (cheap, cache-friendly) rather than a random Get per
// node — the binding applicator passes iterate all nodes, and random Gets were the dominant disk-path cost.
func (g *BadgerGraph) RangeNodes(fn func(Node) bool) {
	emit := func(idx int32, d nodeDetail) bool {
		return fn(Node{ID: g.ids[idx], Type: d.typ, Loc: d.loc, Region: d.region,
			Order: d.order, HasOrder: d.hasOrder, Scope: d.scope, Props: d.props})
	}
	if len(g.det) == len(g.ids) { // everything resident → no badger scan, no decode
		for idx := range g.ids {
			i := int32(idx)
			if !emit(i, g.det[i]) {
				return
			}
		}
		return
	}
	nextResidentScan := int32(0)
	emitResidentBefore := func(limit int32) bool {
		for nextResidentScan < limit {
			if d, ok := g.det[nextResidentScan]; ok {
				if !emit(nextResidentScan, d) {
					return false
				}
			}
			nextResidentScan++
		}
		return true
	}
	// Spilled detail: one sequential prefix scan, merging any still-resident nodes.
	pfx := []byte("gn")
	stop := false
	_ = g.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(pfx); it.ValidForPrefix(pfx); it.Next() {
			item := it.Item()
			k := item.Key()
			if len(k) != 6 {
				continue
			}
			idx := int32(binary.BigEndian.Uint32(k[2:]))
			if idx < 0 || int(idx) >= len(g.ids) {
				continue
			}
			if idx < nextResidentScan {
				continue
			}
			if !emitResidentBefore(idx) {
				stop = true
				return nil
			}
			if d, inRAM := g.det[idx]; inRAM {
				nextResidentScan = idx + 1
				if !emit(idx, d) {
					stop = true
					return nil
				}
				continue
			}
			if err := item.Value(func(v []byte) error {
				if !emit(idx, decDet(v)) {
					stop = true
				}
				nextResidentScan = idx + 1
				return nil
			}); err != nil {
				return err
			}
			if stop {
				return nil
			}
		}
		return nil
	})
	if stop {
		return
	}
	for nextResidentScan < int32(len(g.ids)) {
		if d, ok := g.det[nextResidentScan]; ok {
			if !emit(nextResidentScan, d) {
				return
			}
		}
		nextResidentScan++
	}
}

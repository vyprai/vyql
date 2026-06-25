package lowering

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/graphsync"
	"github.com/vyprai/vyql/usg"
)

var (
	timingOn = os.Getenv("VYQL_TIMING") != ""
	stderr   = os.Stderr
)

func nowNano() int64 { return time.Now().UnixNano() }

// DeltaCache is the minimal byte cache the incremental lowerer needs (satisfied by
// parsecache.Cache). A nil DeltaCache is invalid here — callers gate on cache != nil.
type DeltaCache interface {
	GetRaw(key string) ([]byte, bool)
	PutRaw(key string, val []byte)
}

// LowerIncremental lowers a program reusing the per-module body sub-graph of any module whose
// content (Module.Hash) AND the global resolution context (signature fingerprint) are
// unchanged since a previous run — the heart of incremental dataflow. The global symbol tables
// and signature/import nodes are always rebuilt (cheap); only the expensive per-module body
// lowering is cached. The merged graph is byte-identical to LowerTyped's, so adapters, taint,
// and rules run on it unchanged. Falls back to fresh body lowering for modules without a Hash.
// LowerIncremental returns the lowered store plus the set of module keys that were freshly
// lowered (cache miss or not content-addressed) — the caller uses it to drive incremental
// adapter labeling (re-label only fresh modules; replay cached labels for the rest).
func LowerIncremental(prog nir.Program, resolveImports bool, ctorTypes map[string]string, cache DeltaCache, sync *graphsync.Collector) (usg.Store, map[string]bool, error) {
	l := newLowerer(prog, resolveImports, ctorTypes)
	l.parseCache = cache
	// Preallocate the graph maps to the previous scan's node count (cached) — the whole graph is
	// rebuilt from deltas every scan, and starting from an empty map costs repeated rehashing.
	if raw, ok := cache.GetRaw(sizeHintKey); ok && len(raw) >= 1 {
		l.g = newGraphStore(decodeInt(raw))
	}
	base := l.g
	fresh := map[string]bool{}
	hits, total := 0, 0

	t0 := nowNano()
	// pass 1 (always): import tables, import nodes, signature nodes, and the cross-module symbol
	// table — into the base store. Cached per module (keyed by content + namespace, independent
	// of other modules) so an unchanged module's signatures are replayed WITHOUT re-reading its
	// NIR — the foundation for skipping the body decode of unchanged modules entirely.
	p1keys := make([]string, len(l.prog.Modules))
	for i, m := range l.prog.Modules {
		if m.Hash != "" {
			p1keys[i] = pass1Key(m.Hash, m.Key, ModuleNS(m))
		}
	}
	p1raws := batchGetRaw(cache, p1keys)
	p1writes := map[string][]byte{}
	for i, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		if m.Hash != "" {
			if raw, ok := p1raws[p1keys[i]]; ok {
				if d, err := decodePass1(raw); err == nil {
					d.replay(l, base, m.Key, l.curNS)
					continue // signatures restored from cache — no NIR body needed
				}
			}
		}
		// fresh registration: record this module's contribution for the cache.
		body := l.bodyOf(m)
		l.p1 = &pass1Delta{}
		l.importTables[m.Key] = importTable(body)
		for _, imp := range body.Imports {
			l.p1.Imports = append(l.p1.Imports, ieGob{imp.Local, imp.IsModule, imp.Module, imp.Symbol})
		}
		rec := &recordingStore{Store: base, d: &moduleDelta{}}
		l.g = rec
		for _, imp := range body.Imports {
			l.importNode(body, imp)
		}
		l.register(m.Key, body.Body, "")
		l.g = base
		l.p1.Nodes = rec.d.Nodes
		l.p1.Counter = l.modCtr[l.curNS]
		l.p1.Order = l.modOrder[l.curNS]
		if m.Hash != "" {
			p1writes[p1keys[i]] = encodePass1(l.p1)
		}
		l.p1 = nil
	}
	batchPutRaw(cache, p1writes)
	sigFP := l.sigFingerprint()
	t1 := nowNano()

	// pass 2 (per module): replay a cached body delta, or lower the body fresh while recording.
	// Read all body deltas in ONE batched transaction (thousands of individual badger reads here
	// was the dominant cost of a warm incremental scan — I/O-bound, invisible to a CPU profile).
	keys := make([]string, len(l.prog.Modules))
	for i, m := range l.prog.Modules {
		if m.Hash != "" {
			keys[i] = lowerKey(m.Hash, ModuleNS(m), sigFP)
		}
	}
	raws := batchGetRaw(cache, keys)
	writes := map[string][]byte{}
	for i, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		ns := ModuleNS(m)
		sync.Present(ns)
		if m.Hash == "" { // not content-addressed (e.g. native Go frontend) → always fresh
			// record into a throwaway delta so the sync collector gets this module's edges
			// (creator-attributed); the nodes/edges still land in base via the recordingStore.
			rec := &recordingStore{Store: base, d: &moduleDelta{}}
			l.g = rec
			body := l.bodyOf(m)
			l.block(body.Body, l.moduleScope(body))
			l.g = base
			fresh[ns] = true
			sync.MarkFresh(ns)
			sync.AddEdges(ns, rec.d.Edges)
			continue
		}
		total++
		if raw, ok := raws[keys[i]]; ok {
			if d, err := decodeDelta(raw); err == nil {
				d.replay(base)
				hits++
				continue
			}
		}
		// cache miss → lower the body fresh (decoding the stub on demand if needed).
		rec := &recordingStore{Store: base, d: &moduleDelta{}}
		l.g = rec
		body := l.bodyOf(m)
		l.block(body.Body, l.moduleScope(body))
		l.g = base
		writes[keys[i]] = encodeDelta(rec.d)
		fresh[ns] = true
		sync.MarkFresh(ns)
		sync.AddEdges(ns, rec.d.Edges)
	}
	batchPutRaw(cache, writes)
	if s, ok := base.(*usg.InMemStore); ok {
		cache.PutRaw(sizeHintKey, encodeInt(s.NodeCount()))
	}
	t2 := nowNano()
	if timingOn {
		fmt.Fprintf(stderr, "[timing] lower.pass1 %7.1fms  lower.pass2 %7.1fms  (replay %d/%d)\n",
			float64(t1-t0)/1e6, float64(t2-t1)/1e6, hits, total)
	}
	return base, fresh, nil
}

const sizeHintKey = "lower\x00graphsize"

func encodeInt(n int) []byte {
	w := &bufWriter{}
	w.uvar(n)
	return w.b
}
func decodeInt(raw []byte) int { return (&bufReader{b: raw}).uvar() }

// Store-selection knobs set by the CLI. UseIntStore forces the int-indexed in-RAM store. When
// DiskStorePath is set (a RAM ceiling is configured), the badger-backed store is used: the graph
// is the source of truth on disk and RAM is bounded by DiskCacheBytes (badger's cache).
var (
	UseIntStore    bool
	DiskStorePath  string
	DiskCacheBytes int64
)

// newGraphStore creates the analysis graph store. BadgerDB is the DEFAULT source of truth:
// on-disk when a RAM ceiling is configured (DiskStorePath, cache=DiskCacheBytes), else in-memory
// badger. VYQL_STORE=int|inmem are escape hatches to the map-based stores (faster on small repos,
// no badger overhead). hint>0 presizes the in-RAM stores.
func newGraphStore(hint int) usg.Store {
	switch os.Getenv("VYQL_STORE") {
	case "int":
		return usg.NewIntStore(hint)
	case "inmem":
		if hint > 0 {
			return usg.NewInMemStoreSized(hint)
		}
		return usg.NewInMemStore()
	}
	if UseIntStore {
		return usg.NewIntStore(hint)
	}
	path, cache := ":memory:", int64(0)
	if DiskStorePath != "" {
		path, cache = DiskStorePath, DiskCacheBytes
	}
	if g, err := usg.OpenBadgerGraph(path, cache); err == nil {
		return g
	}
	// badger unavailable → fall back to the in-RAM store.
	if hint > 0 {
		return usg.NewInMemStoreSized(hint)
	}
	return usg.NewInMemStore()
}

func lowerKey(moduleHash, moduleKey, sigFP string) string {
	return "lower\x00" + moduleHash + "\x00" + moduleKey + "\x00" + sigFP
}

// pass1Key identifies a module's signature/symbol-table contribution. It depends ONLY on the
// module's own content (hash), resolution key, and node-id namespace — register is purely
// per-module — so it is valid regardless of what other modules look like (unlike lowerKey,
// which folds in the global sigFP because pass-2 body lowering resolves against all signatures).
func pass1Key(moduleHash, moduleKey, ns string) string {
	return "p1\x00" + moduleHash + "\x00" + moduleKey + "\x00" + ns
}

// bodyOf returns a module's full NIR. For a normal (decoded) module it is the module itself;
// for a stub (Body nil but a parse-cache content key set) it decodes the cached blob on demand —
// so an unchanged module whose signatures and body sub-graph are both cached is never decoded.
func (l *lowerer) bodyOf(m nir.Module) nir.Module {
	if m.Body != nil || m.CacheKey == "" || l.parseCache == nil {
		return m
	}
	if raw, ok := l.parseCache.GetRaw(m.CacheKey); ok {
		if full, ok := decodeModule(raw); ok {
			return full
		}
	}
	return m
}

func decodeModule(raw []byte) (nir.Module, bool) {
	var m nir.Module
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&m); err != nil {
		return nir.Module{}, false
	}
	return m, true
}

// --- pass 1 (signature/symbol) cache --------------------------------------------------------

type ieGob struct {
	Local    string
	IsModule bool
	Module   string
	Symbol   string
}
type fiGob struct {
	Qual, Short        string
	ParamNames         []string
	Params, ParamTypes map[string]string
	Ret, Module, Cls   string
	Name               string
	ParamEntries       []nir.ParamEntry
	ResultEntries      []nir.ResultEntry
	Abstract           bool
}
type cfGob struct{ Key, Field, Type string }

// pass1Delta is one module's pass-1 output: the import/signature store nodes, its import table,
// the functions/classes it contributes to the global symbol table, and the post-pass-1 value of
// its per-namespace node counter (so a later fresh pass-2 of the same module continues minting
// body node ids without colliding with these signature/import ids).
type pass1Delta struct {
	Nodes       []usg.Node
	Imports     []ieGob
	Funcs       []fiGob
	ClassQual   []string
	ClassDefs   []string
	ClassFields []cfGob
	Counter     int // modCtr[ns] after pass 1 (node-id counter)
	Order       int // modOrder[ns] after pass 1 (CFG order counter)
}

func (d *pass1Delta) replay(l *lowerer, base usg.Store, modkey, ns string) {
	for _, n := range d.Nodes {
		_ = base.AddNode(n)
	}
	tbl := map[string]importEntry{}
	for _, ie := range d.Imports {
		if ie.IsModule {
			tbl[ie.Local] = importEntry{kind: "mod", module: ie.Module}
		} else {
			tbl[ie.Local] = importEntry{kind: "sym", module: ie.Module, symbol: ie.Symbol}
		}
	}
	l.importTables[modkey] = tbl
	for _, f := range d.Funcs {
		// funcID is deterministic (sigID over ns + qualified name), so recompute it on replay
		// rather than serializing it — it must match what makeFuncInfo minted, so a re-lowered
		// body (pass 2) can stamp `func_id` on its nodes (the graph-json node→function map). The
		// code.Function node itself is replayed from d.Nodes (captured during pass 1).
		rel := f.Name
		if f.Cls != "" {
			rel = f.Cls + "." + f.Name
		}
		fi := &funcInfo{
			paramNames: f.ParamNames, params: f.Params, paramTypes: f.ParamTypes, ret: f.Ret,
			module: f.Module, cls: f.Cls, name: f.Name, funcID: sigID(ns, rel, "func", ""),
			paramEntries:  f.ParamEntries,
			resultEntries: f.ResultEntries, abstract: f.Abstract,
		}
		l.funcQual[f.Qual] = fi
		l.funcShort[f.Short] = append(l.funcShort[f.Short], fi)
	}
	for _, k := range d.ClassQual {
		l.classQual[k] = true
	}
	for _, name := range d.ClassDefs {
		if l.classDefs[name] == nil {
			l.classDefs[name] = map[string]bool{}
		}
		l.classDefs[name][modkey] = true
	}
	for _, cf := range d.ClassFields {
		if l.classFields[cf.Key] == nil {
			l.classFields[cf.Key] = map[string]string{}
		}
		l.classFields[cf.Key][cf.Field] = cf.Type
	}
	if d.Counter > l.modCtr[ns] {
		l.modCtr[ns] = d.Counter
	}
	if d.Order > l.modOrder[ns] {
		l.modOrder[ns] = d.Order
	}
}

// batchReader / batchWriter are the optional fast paths a badger-backed DeltaCache implements:
// reading/writing many keys in one transaction. In-memory test caches don't, so the helpers
// fall back to per-key access.
type batchReader interface {
	GetManyRaw(keys []string) map[string][]byte
}
type batchWriter interface {
	PutManyRaw(kv map[string][]byte)
}

func batchGetRaw(cache DeltaCache, keys []string) map[string][]byte {
	if br, ok := cache.(batchReader); ok {
		// drop empty keys (modules with no hash) before the batched read.
		nz := make([]string, 0, len(keys))
		for _, k := range keys {
			if k != "" {
				nz = append(nz, k)
			}
		}
		return br.GetManyRaw(nz)
	}
	out := map[string][]byte{}
	for _, k := range keys {
		if k == "" {
			continue
		}
		if v, ok := cache.GetRaw(k); ok {
			out[k] = v
		}
	}
	return out
}

func batchPutRaw(cache DeltaCache, kv map[string][]byte) {
	if len(kv) == 0 {
		return
	}
	if bw, ok := cache.(batchWriter); ok {
		bw.PutManyRaw(kv)
		return
	}
	for k, v := range kv {
		cache.PutRaw(k, v)
	}
}

// NodeModule returns the module key a node id belongs to (ids are "<modkey>\x1f..."), or ""
// for nodes not minted by the module-namespacing lowerer (e.g. SBOM nodes). Lets the caller
// attribute graph nodes to modules for incremental adapter labeling.
func NodeModule(id string) (string, bool) {
	if i := strings.IndexByte(id, '\x1f'); i >= 0 {
		return id[:i], true
	}
	return "", false
}

// sigFingerprint hashes everything cross-module body lowering depends on besides a module's own
// NIR: the function signature table (qualified name -> param/return node ids, declared types,
// result-event/abstract metadata), import tables, class registry/fields, constructor types, and the
// self name / import-resolution mode. If this is unchanged, a module's body lowers identically.
func (l *lowerer) sigFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "self=%s resolveImports=%v ctor=%d\n", l.selfName, l.resolveImports, len(l.ctorTypes))
	for _, k := range sortedStrKeys(l.ctorTypes) {
		fmt.Fprintf(h, "C %s=%s\n", k, l.ctorTypes[k])
	}
	for _, q := range sortedFuncKeys(l.funcQual) {
		fi := l.funcQual[q]
		fmt.Fprintf(h, "F %s ret=%s abstract=%v cls=%s\n", q, fi.ret, fi.abstract, fi.cls)
		for _, entry := range fi.resultEntries {
			fmt.Fprintf(h, "  r %s\n", strings.Join(entry.Tokens, "\x00"))
		}
		for _, pn := range fi.paramNames {
			fmt.Fprintf(h, "  p %s id=%s t=%s\n", pn, fi.params[pn], fi.paramTypes[pn])
		}
	}
	for _, mk := range sortedImportKeys(l.importTables) {
		for _, local := range sortedImportEntries(l.importTables[mk]) {
			e := l.importTables[mk][local]
			fmt.Fprintf(h, "I %s %s %s %s %s\n", mk, local, e.kind, e.module, e.symbol)
		}
	}
	for _, c := range sortedSetKeys(l.classDefs) {
		fmt.Fprintf(h, "D %s %v\n", c, sortedBoolKeys(l.classDefs[c]))
	}
	for _, c := range sortedBoolKeys(l.classQual) {
		fmt.Fprintf(h, "Q %s\n", c)
	}
	for _, cf := range sortedFieldKeys(l.classFields) {
		for _, fld := range sortedStrKeys(l.classFields[cf]) {
			fmt.Fprintf(h, "L %s %s=%s\n", cf, fld, l.classFields[cf][fld])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// --- recording store: captures a module's body sub-graph writes for caching ---------------

type deltaLabel struct {
	NodeID string
	Label  usg.Label
}

type moduleDelta struct {
	Nodes  []usg.Node
	Edges  []usg.Edge
	Labels []deltaLabel
}

func (d *moduleDelta) replay(s usg.Store) {
	for _, n := range d.Nodes {
		_ = s.AddNode(n)
	}
	for _, e := range d.Edges {
		_ = s.AddEdge(e)
	}
	for _, l := range d.Labels {
		_ = s.AddLabel(l.NodeID, l.Label)
	}
}

// recordingStore forwards every operation to the base store and records the mutations, so the
// exact graph delta a module's body lowering produces can be cached and later replayed.
type recordingStore struct {
	usg.Store
	d *moduleDelta
}

func (r *recordingStore) AddNode(n usg.Node) error {
	r.d.Nodes = append(r.d.Nodes, n)
	return r.Store.AddNode(n)
}

func (r *recordingStore) AddEdge(e usg.Edge) error {
	r.d.Edges = append(r.d.Edges, e)
	return r.Store.AddEdge(e)
}

func (r *recordingStore) AddLabel(nodeID string, l usg.Label) error {
	r.d.Labels = append(r.d.Labels, deltaLabel{nodeID, l})
	return r.Store.AddLabel(nodeID, l)
}

// --- deterministic map iteration helpers for the fingerprint ------------------------------

func sortedStrKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedFuncKeys(m map[string]*funcInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedImportKeys(m map[string]map[string]importEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedImportEntries(m map[string]importEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSetKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedFieldKeys(m map[string]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

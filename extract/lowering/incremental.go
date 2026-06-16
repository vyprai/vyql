package lowering

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

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
func LowerIncremental(prog nir.Program, resolveImports bool, ctorTypes map[string]string, cache DeltaCache) (usg.Store, map[string]bool, error) {
	l := newLowerer(prog, resolveImports, ctorTypes)
	base := l.g
	fresh := map[string]bool{}
	hits, total := 0, 0

	// pass 1 (always): import tables, import nodes, and signature nodes — into the base store.
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		l.importTables[m.Key] = importTable(m)
		for _, imp := range m.Imports {
			l.importNode(m, imp)
		}
		l.register(m.Key, m.Body, "")
	}
	sigFP := l.sigFingerprint()

	// pass 2 (per module): replay a cached body delta, or lower the body fresh while recording.
	for _, m := range l.prog.Modules {
		l.curModule, l.curClass, l.curNS = m.Key, "", ModuleNS(m)
		if m.Hash == "" { // not content-addressed (e.g. native Go frontend) → always fresh
			l.g = base
			l.block(m.Body, newScope())
			fresh[ModuleNS(m)] = true
			continue
		}
		total++
		key := lowerKey(m.Hash, ModuleNS(m), sigFP)
		if raw, ok := cache.GetRaw(key); ok {
			if d, err := decodeDelta(raw); err == nil {
				d.replay(base)
				hits++
				continue
			}
		}
		rec := &recordingStore{Store: base, d: &moduleDelta{}}
		l.g = rec
		l.block(m.Body, newScope())
		l.g = base
		cache.PutRaw(key, encodeDelta(rec.d))
		fresh[ModuleNS(m)] = true
	}
	return base, fresh, nil
}

func lowerKey(moduleHash, moduleKey, sigFP string) string {
	return "lower\x00" + moduleHash + "\x00" + moduleKey + "\x00" + sigFP
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
// NIR: the function signature table (qualified name → param/return node ids, declared types,
// validator/abstract flags), import tables, class registry/fields, constructor types, and the
// self name / import-resolution mode. If this is unchanged, a module's body lowers identically.
func (l *lowerer) sigFingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "self=%s resolveImports=%v ctor=%d\n", l.selfName, l.resolveImports, len(l.ctorTypes))
	for _, k := range sortedStrKeys(l.ctorTypes) {
		fmt.Fprintf(h, "C %s=%s\n", k, l.ctorTypes[k])
	}
	for _, q := range sortedFuncKeys(l.funcQual) {
		fi := l.funcQual[q]
		fmt.Fprintf(h, "F %s ret=%s abstract=%v validator=%v cls=%s\n", q, fi.ret, fi.abstract, fi.validator, fi.cls)
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
	for _, c := range sortedStrSliceKeys(l.classDefs) {
		fmt.Fprintf(h, "D %s %v\n", c, l.classDefs[c])
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

func encodeDelta(d *moduleDelta) []byte {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(d); err != nil {
		return nil
	}
	return buf.Bytes()
}

func decodeDelta(raw []byte) (*moduleDelta, error) {
	var d moduleDelta
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
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

func sortedStrSliceKeys(m map[string][]string) []string {
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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"path/filepath"
	"sort"

	"github.com/vyprai/vyql/bindings"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/usg"
)

// encodeLabels/decodeLabels are a compact length-prefixed codec for one module's binding-label
// output - far faster than gob (no reflection, fewer allocations), the dominant cost of replaying
// thousands of modules' cached labels per warm scan. The bytes are a cache value (never hashed),
// so encoding order is free; round-trip fidelity is gated by the findings-equivalence harness.
func encodeLabels(recs []usg.LabelRec) []byte {
	w := &lblWriter{b: make([]byte, 0, 128)}
	w.uvar(len(recs))
	for _, lr := range recs {
		w.str(lr.NodeID)
		w.str(lr.Label.Concept)
		p := lr.Label.Provenance
		w.str(p.Extractor)
		w.str(p.Applicator)
		w.str(p.SourceRef)
		w.str(p.Confidence)
		w.str(p.Fidelity)
		w.smap(lr.Label.Detail)
	}
	return w.b
}

func decodeLabels(raw []byte) (recs []usg.LabelRec, ok bool) {
	defer func() {
		if recover() != nil {
			recs, ok = nil, false
		}
	}()
	r := &lblReader{b: raw}
	n := r.uvar()
	if n == 0 {
		return nil, true
	}
	recs = make([]usg.LabelRec, n)
	for i := range recs {
		nodeID := r.str()
		lbl := usg.Label{Concept: r.str()}
		lbl.Provenance = usg.Provenance{
			Extractor: r.str(), Applicator: r.str(), SourceRef: r.str(),
			Confidence: r.str(), Fidelity: r.str(),
		}
		lbl.Detail = r.smap()
		recs[i] = usg.LabelRec{NodeID: nodeID, Label: lbl}
	}
	return recs, true
}

type lblWriter struct{ b []byte }

func (w *lblWriter) uvar(n int) {
	for n >= 0x80 {
		w.b = append(w.b, byte(n)|0x80)
		n >>= 7
	}
	w.b = append(w.b, byte(n))
}
func (w *lblWriter) str(s string) { w.uvar(len(s)); w.b = append(w.b, s...) }
func (w *lblWriter) smap(m map[string]string) {
	w.uvar(len(m))
	for k, v := range m {
		w.str(k)
		w.str(v)
	}
}

type lblReader struct {
	b []byte
	i int
}

func (r *lblReader) uvar() int {
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
func (r *lblReader) str() string {
	n := r.uvar()
	s := string(r.b[r.i : r.i+n])
	r.i += n
	return s
}
func (r *lblReader) smap() map[string]string {
	n := r.uvar()
	if n == 0 {
		return nil
	}
	m := make(map[string]string, n)
	for j := 0; j < n; j++ {
		k := r.str()
		m[k] = r.str()
	}
	return m
}

// applyBindingsIncremental runs the binding labeling phase reusing the cached concept labels of
// modules whose content AND the global binding inputs are unchanged, re-running binding
// applicators only on the rest. This is the binding analogue of incremental lowering.
//
// Soundness rests on bindings.Apply resolving precedence strictly per-(node, concept): a node's
// final labels depend only on proposals targeting that exact node (its own properties plus the
// global package/import evidence), never on other code nodes. Since each node belongs to exactly
// one module, restricting the binding pass to a subset of modules yields labels byte-identical
// to a full pass for those modules. Import and SBOM nodes stay fully visible (RestrictStore),
// so package-evidence gating is unaffected by which modules are in the relabel set.
//
// The per-module cache key folds in bindingFingerprint - the active source set (profile), the
// package-evidence set, and a stat-hash of the loaded binding data - so any change to a global
// binding input misses every module and re-labels the whole graph. modHash maps each module's
// namespace (lowering.ModuleNS) to its content hash; a module absent from it (e.g. a native
// frontend with no Hash) is always relabeled and never cached.
func applyBindingsIncremental(g usg.Store, bindingApps []bindings.Applicator, modHash map[string]string, deps map[string]bool, cache lowering.DeltaCache) (map[string]bool, error) {
	fp := bindingFingerprint(deps)

	// decide which modules must be (re)labeled: those whose binding-cache key misses. Read all
	// module keys in one batched transaction - thousands of individual badger reads here was the
	// dominant cost of a large incremental scan (I/O-bound, invisible to a CPU profile).
	keys := make([]string, 0, len(modHash))
	for ns, h := range modHash {
		keys = append(keys, bindingKey(fp, ns, h))
	}
	raws := batchGet(cache, keys)
	relabel := map[string]bool{}
	cachedFor := map[string][]usg.LabelRec{}
	for ns, h := range modHash {
		if raw, ok := raws[bindingKey(fp, ns, h)]; ok {
			if recs, ok := decodeLabels(raw); ok {
				cachedFor[ns] = recs
				continue
			}
		}
		relabel[ns] = true
	}

	// Run binding applicators over a view that exposes only relabel-set modules
	// plus nodes with no module and all Import/SBOM evidence. The subset is
	// computed once; each applicator then iterates O(subset) instead of
	// re-filtering the whole graph.
	rec := &usg.RecordingStore{Store: g}
	view, err := usg.NewSubsetStore(rec, func(id, _ string) bool {
		mod, ok := lowering.NodeModule(id)
		if !ok {
			return true // not module-scoped - always process, never cached
		}
		if _, hashed := modHash[mod]; !hashed {
			return true // hashless module (native frontend, no content hash) - always relabel
		}
		return relabel[mod]
	})
	if err != nil {
		return nil, err
	}
	if _, _, err := bindings.Apply(view, bindingApps, nil); err != nil {
		return nil, err
	}

	// bucket recorded labels by module, then persist one entry per relabeled module - even an
	// empty one, so a label-free module hits next time instead of re-running every scan.
	buckets := map[string][]usg.LabelRec{}
	for _, lr := range rec.Recs {
		if mod, ok := lowering.NodeModule(lr.NodeID); ok && relabel[mod] {
			buckets[mod] = append(buckets[mod], lr)
		}
	}
	writes := make(map[string][]byte, len(relabel))
	for ns := range relabel {
		writes[bindingKey(fp, ns, modHash[ns])] = encodeLabels(buckets[ns])
	}
	batchPut(cache, writes)

	// replay cached labels for the unchanged modules onto the real store.
	for _, recs := range cachedFor {
		for _, lr := range recs {
			_ = g.AddLabel(lr.NodeID, lr.Label)
		}
	}
	return relabel, nil
}

func bindingKey(fp, moduleNS, moduleHash string) string {
	return "bind\x00" + fp + "\x00" + moduleNS + "\x00" + moduleHash
}

// batchReader / batchWriter are the optional fast paths a real (badger-backed) DeltaCache
// implements: reading/writing thousands of keys in one transaction. In-memory test caches
// don't, so batchGet/batchPut fall back to per-key access.
type batchReader interface {
	GetManyRaw(keys []string) map[string][]byte
}
type batchWriter interface {
	PutManyRaw(kv map[string][]byte)
}

func batchGet(cache lowering.DeltaCache, keys []string) map[string][]byte {
	if br, ok := cache.(batchReader); ok {
		return br.GetManyRaw(keys)
	}
	out := make(map[string][]byte, len(keys))
	for _, k := range keys {
		if v, ok := cache.GetRaw(k); ok {
			out[k] = v
		}
	}
	return out
}

func batchPut(cache lowering.DeltaCache, kv map[string][]byte) {
	if bw, ok := cache.(batchWriter); ok {
		bw.PutManyRaw(kv)
		return
	}
	for k, v := range kv {
		cache.PutRaw(k, v)
	}
}

// bindingFingerprint hashes every global input the binding phase depends on besides a module's
// own nodes: the binary salt (a rebuilt scanner re-labels everything), the active source set,
// the package-evidence set (which package-scoped bindings fire), and a stat-hash of the loaded
// binding data (static per-language bindings + the generated per-package files for present
// deps). If this is unchanged, a module's binding labels are reproducible from its content.
func bindingFingerprint(deps map[string]bool) string {
	h := sha256.New()
	if cache := parsecache.Shared(); cache != nil {
		if salt := cache.Salt(); salt != nil {
			h.Write(salt)
		}
	}
	io.WriteString(h, "\x00sources\x00")
	io.WriteString(h, frontend.ActiveSourcesKey())
	io.WriteString(h, "\x00concepts\x00")
	io.WriteString(h, frontend.ActiveBindingConceptsKey())

	io.WriteString(h, "\x00deps\x00")
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		io.WriteString(h, k)
		io.WriteString(h, "\x00")
	}

	io.WriteString(h, "\x00bdata\x00")
	statBindingData(h, deps)
	return hex.EncodeToString(h.Sum(nil))
}

// statBindingData folds the identity (path+size+mtime) of the binding data that
// actually loads into h: split v2 static bindings plus the generated per-package
// files for packages in deps. It deliberately avoids stat-walking the full
// generated corpus - only the matched generated files matter, and walking all of
// them every scan would cost what this cache saves.
func statBindingData(h hash.Hash, deps map[string]bool) {
	root := filepath.Join(datadir.Root(), "bindings")
	statStaticBindingData(h, root)
	if len(deps) == 0 {
		return
	}
	gen := frontend.GeneratedRoot()
	pkgs := make([]string, 0, len(deps))
	for p := range deps {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	langs, _ := filepath.Glob(filepath.Join(gen, "*"))
	sort.Strings(langs)
	for _, langDir := range langs {
		for _, p := range pkgs {
			statGeneratedPackageBinding(h, langDir, p)
		}
	}
}

func statGeneratedPackageBinding(h hash.Hash, langDir, pkg string) {
	dir := filepath.Join(langDir, pkg)
	statVYQLTreeExcept(h, dir, nil)
	statFile(h, dir+".vyql")
}

func statStaticBindingData(h hash.Hash, root string) {
	statVYQLTreeExcept(h, root, map[string]bool{
		"packages/generated": true,
	})
}

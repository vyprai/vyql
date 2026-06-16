package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"hash"
	"io"
	"path/filepath"
	"sort"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/usg"
)

// cachedLabels is the gob-serialized adapter-label output for one module's nodes.
type cachedLabels struct{ Recs []usg.LabelRec }

// applyAdaptersIncremental runs the adapter labeling phase reusing the cached concept labels of
// modules whose content AND the global adapter inputs are unchanged, re-running adapters only on
// the rest. This is the adapter analogue of incremental lowering.
//
// Soundness rests on adapters.Apply resolving precedence strictly per-(node, concept): a node's
// final labels depend only on proposals targeting that exact node (its own properties plus the
// global package/import evidence), never on other code nodes. Since each node belongs to exactly
// one module, restricting the adapter pass to a subset of modules yields labels byte-identical
// to a full pass for those modules. Import and SBOM nodes stay fully visible (RestrictStore),
// so package-evidence gating is unaffected by which modules are in the relabel set.
//
// The per-module cache key folds in adapterFingerprint — the active source set (profile), the
// package-evidence set, and a stat-hash of the loaded adapter data — so any change to a global
// adapter input misses every module and re-labels the whole graph. modHash maps each module's
// namespace (lowering.ModuleNS) to its content hash; a module absent from it (e.g. a native
// frontend with no Hash) is always relabeled and never cached.
func applyAdaptersIncremental(g usg.Store, ads []adapters.Adapter, modHash map[string]string, cache lowering.DeltaCache) error {
	fp := adapterFingerprint(g)

	// decide which modules must be (re)labeled: those whose adapter-cache key misses.
	relabel := map[string]bool{}
	cachedFor := map[string]cachedLabels{}
	for ns, h := range modHash {
		if raw, ok := cache.GetRaw(adapterKey(fp, ns, h)); ok {
			var cl cachedLabels
			if gob.NewDecoder(bytes.NewReader(raw)).Decode(&cl) == nil {
				cachedFor[ns] = cl
				continue
			}
		}
		relabel[ns] = true
	}

	// run adapters over a view that exposes only relabel-set modules (plus nodes with no module
	// and — via RestrictStore — all Import/SBOM evidence), recording the labels each produces.
	rec := &usg.RecordingStore{Store: g}
	view := &usg.RestrictStore{Store: rec, Allow: func(id string) bool {
		mod, ok := lowering.NodeModule(id)
		if !ok {
			return true // not module-scoped — always process, never cached
		}
		return relabel[mod]
	}}
	if _, _, err := adapters.Apply(view, ads, nil); err != nil {
		return err
	}

	// bucket recorded labels by module, then persist one entry per relabeled module — even an
	// empty one, so a label-free module hits next time instead of re-running every scan.
	buckets := map[string][]usg.LabelRec{}
	for _, lr := range rec.Recs {
		if mod, ok := lowering.NodeModule(lr.NodeID); ok && relabel[mod] {
			buckets[mod] = append(buckets[mod], lr)
		}
	}
	for ns := range relabel {
		var buf bytes.Buffer
		if gob.NewEncoder(&buf).Encode(cachedLabels{Recs: buckets[ns]}) == nil {
			cache.PutRaw(adapterKey(fp, ns, modHash[ns]), buf.Bytes())
		}
	}

	// replay cached labels for the unchanged modules onto the real store.
	for _, cl := range cachedFor {
		for _, lr := range cl.Recs {
			_ = g.AddLabel(lr.NodeID, lr.Label)
		}
	}
	return nil
}

func adapterKey(fp, moduleNS, moduleHash string) string {
	return "adapt\x00" + fp + "\x00" + moduleNS + "\x00" + moduleHash
}

// adapterFingerprint hashes every global input the adapter phase depends on besides a module's
// own nodes: the binary salt (a rebuilt scanner re-labels everything), the active source set,
// the package-evidence set (which package-gated adapters fire), and a stat-hash of the loaded
// adapter data (static per-language adapters + the generated per-package files for present
// deps). If this is unchanged, a module's adapter labels are reproducible from its content.
func adapterFingerprint(g usg.Store) string {
	h := sha256.New()
	if salt := parsecache.Shared().Salt(); salt != nil {
		h.Write(salt)
	}
	io.WriteString(h, "\x00sources\x00")
	io.WriteString(h, frontend.ActiveSourcesKey())

	deps := frontend.DependencyEvidence(g)
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

	io.WriteString(h, "\x00adata\x00")
	statAdapterData(h, deps)
	return hex.EncodeToString(h.Sum(nil))
}

// statAdapterData folds the identity (path+size+mtime) of the adapter data that actually loads
// into h: the static top-level <data>/adapters/*.vyql, plus the generated per-package files for
// packages in deps. It deliberately avoids stat-walking the full ~9k-file generated corpus —
// only the matched files matter, and walking all of them every scan would cost what this cache
// saves.
func statAdapterData(h hash.Hash, deps map[string]bool) {
	root := filepath.Join(datadir.Root(), "adapters")
	statGlob(h, filepath.Join(root, "*.vyql"))
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
			statFile(h, filepath.Join(langDir, p+".vyql"))
		}
	}
}

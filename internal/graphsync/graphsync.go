// Package graphsync turns a VyQL analysis graph into a stable, content-addressed change-feed
// for syncing to an external database. It is built on the incremental engine's per-module
// deltas: each scan emits, for the modules whose sub-graph actually changed, the FULL current
// row-set of that module (nodes, edges, labels) plus tombstones for modules that disappeared.
// A row is content-addressed by a fixed-width key, so re-emitting an unchanged row is an
// idempotent upsert and a sync client can apply a delta with "delete rows owned by module M,
// then insert the emitted rows for M".
//
// Why per-module, creator-attributed: an edge (e.g. a cross-module return flow) may have its
// Src in one module but be CREATED by another's lowering. Attributing rows to the module that
// produced them — which is exactly what the incremental lowering/binding-applicator deltas
// record — keeps the "replace module M's rows" operation sound. Attributing by Src would strand
// such edges when their creator changes but their Src module does not.
package graphsync

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/vyprai/vyql/internal/usg"
)

// idLen is the fixed key width in bytes (128-bit sha256 prefix → 32 hex chars). Collision
// probability is negligible at any realistic graph scale, and a fixed width keeps DB indexes
// uniform per the chosen key scheme.
const idLen = 16

func hashID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:idLen])
}

// mapHash is a deterministic fingerprint of a string map (sorted keys), so two rows with the
// same logical content hash identically regardless of map iteration order.
func mapHash(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:idLen])
}

// ModuleID is the fixed-width key for a module namespace (the owner of its rows).
func ModuleID(ns string) string { return hashID("mod", ns) }

// SyncNode / SyncEdge / SyncLabel are the database rows. Key is the stable primary key; Module
// is the owning module's key (for "delete where module = …"); Fingerprint is a content hash for
// change detection / no-op upserts.
type SyncNode struct {
	Key         string            `json:"key"`
	Module      string            `json:"module"`
	Type        string            `json:"type"`
	Props       map[string]string `json:"props,omitempty"`
	Fingerprint string            `json:"fp"`
}

type SyncEdge struct {
	Key         string            `json:"key"`
	Module      string            `json:"module"`
	Type        string            `json:"type"`
	Src         string            `json:"src"` // hashed source node key
	Dst         string            `json:"dst"` // hashed destination node key
	Props       map[string]string `json:"props,omitempty"`
	Fingerprint string            `json:"fp"`
}

type SyncLabel struct {
	Key         string            `json:"key"`
	Module      string            `json:"module"`
	Node        string            `json:"node"` // hashed node key the label attaches to
	Concept     string            `json:"concept"`
	Applicator  string            `json:"applicator,omitempty"`
	Detail      map[string]string `json:"detail,omitempty"`
	Fingerprint string            `json:"fp"`
}

// NodeKey is the stable key of a graph node id. Exported so edge/label rows built elsewhere
// reference nodes by the same key.
func NodeKey(nodeID string) string { return hashID("node", nodeID) }

func nodeRow(modID string, n usg.Node) SyncNode {
	// loc/region/order are inline fields on Node; fold them back into the row's Props so the DB
	// view (and the fingerprint) is identical to when they lived in the map.
	props := map[string]string{}
	if n.Loc != "" {
		props["loc"] = n.Loc
	}
	if n.Region != "" {
		props["region"] = n.Region
	}
	if n.HasOrder {
		props["order"] = strconv.Itoa(int(n.Order))
	}
	for k, v := range n.Props {
		props[k] = v
	}
	if len(props) == 0 {
		props = nil
	}
	fp := hashID(n.Type, mapHash(props))
	return SyncNode{Key: NodeKey(n.ID), Module: modID, Type: n.Type, Props: props, Fingerprint: fp}
}

func edgeRow(modID string, e usg.Edge) SyncEdge {
	src, dst := NodeKey(e.Src), NodeKey(e.Dst)
	ph := mapHash(e.Props)
	key := hashID("edge", src, e.Type, dst, ph)
	return SyncEdge{Key: key, Module: modID, Type: e.Type, Src: src, Dst: dst, Props: e.Props, Fingerprint: ph}
}

func labelRow(modID string, lr usg.LabelRec) SyncLabel {
	node := NodeKey(lr.NodeID)
	dh := mapHash(lr.Label.Detail)
	key := hashID("label", node, lr.Label.Concept, lr.Label.Provenance.Applicator, dh)
	fp := hashID(lr.Label.Concept, lr.Label.Provenance.Applicator, lr.Label.Provenance.Fidelity,
		lr.Label.Provenance.Confidence, dh)
	return SyncLabel{Key: key, Module: modID, Node: node, Concept: lr.Label.Concept,
		Applicator: lr.Label.Provenance.Applicator, Detail: lr.Label.Detail, Fingerprint: fp}
}

// Delta is one scan's change-feed. For each module key present in a *Mods map the client should
// replace all rows of that type owned by the module (delete-by-module then insert). DeletedModules
// are modules that vanished since the last sync — delete ALL their rows. A module absent from the
// maps and from DeletedModules is unchanged: nothing to do.
type Delta struct {
	NodeMods  map[string][]SyncNode  `json:"node_mods,omitempty"`
	EdgeMods  map[string][]SyncEdge  `json:"edge_mods,omitempty"`
	LabelMods map[string][]SyncLabel `json:"label_mods,omitempty"`
	Deleted   []string               `json:"deleted_modules,omitempty"`
}

// Collector accumulates per-module rows during a scan and produces the Delta. It is fed by the
// incremental lowering pass (nodes/edges/lowering-labels of changed modules) and the binding
// applicator pass (labels of relabeled modules); both are creator-attributed. A nil *Collector is
// a safe no-op so the sync path is fully opt-in.
type Collector struct {
	nodes     map[string][]SyncNode
	edges     map[string][]SyncEdge
	labels    map[string][]SyncLabel
	seenEdge  map[string]bool // dedup identical edges within a module set
	seenLabel map[string]bool
	dirtyNS   map[string]bool // module namespaces touched this scan (node/edge dirty)
	labelNS   map[string]bool // module namespaces whose labels were (re)emitted
	presentNS map[string]bool // every module namespace present this scan
}

func New() *Collector {
	return &Collector{
		nodes: map[string][]SyncNode{}, edges: map[string][]SyncEdge{}, labels: map[string][]SyncLabel{},
		seenEdge: map[string]bool{}, seenLabel: map[string]bool{},
		dirtyNS: map[string]bool{}, labelNS: map[string]bool{}, presentNS: map[string]bool{},
	}
}

// Present records that a module namespace exists in this scan (whether or not it changed), so
// tombstones can be computed against the previous manifest.
func (c *Collector) Present(ns string) {
	if c == nil {
		return
	}
	c.presentNS[ns] = true
}

// MarkFresh records that a module's body sub-graph was re-lowered this scan (the lowering
// `fresh` set) — so its nodes and edges are node/edge-dirty and must be re-synced, even if it
// ended up with zero of either (the client deletes the module's old rows first).
func (c *Collector) MarkFresh(ns string) {
	if c == nil {
		return
	}
	c.dirtyNS[ns] = true
	c.presentNS[ns] = true
}

// MarkRelabel records that a module's labels were recomputed this scan (the applicator
// `relabel` set) — so it appears in LabelMods even if it now has zero labels (client deletes the
// old ones).
func (c *Collector) MarkRelabel(ns string) {
	if c == nil {
		return
	}
	c.labelNS[ns] = true
	c.presentNS[ns] = true
}

// AddEdges records a fresh module's edge rows, creator-attributed (taken from the module's
// lowering delta), so a cross-module edge is owned by the module that produced it — not by its
// Src's module, which would strand the edge when its creator changes but its Src does not.
func (c *Collector) AddEdges(ns string, edges []usg.Edge) {
	if c == nil {
		return
	}
	modID := ModuleID(ns)
	for _, e := range edges {
		r := edgeRow(modID, e)
		if c.seenEdge[r.Key] {
			continue
		}
		c.seenEdge[r.Key] = true
		c.edges[modID] = append(c.edges[modID], r)
	}
}

// CollectGraph does ONE pass over the merged graph: emit node rows for nodes in a fresh module
// (node-dirty), and label rows for nodes in a relabel module (label-dirty). Node and label
// attribution is the labeled/owning node's module — unambiguous, unlike edges. labelDirtyNS is
// the applicator `relabel` set (a sigFP-only change makes a module fresh-but-not-relabel, and
// its labels are genuinely unchanged, so they need not re-sync).
func (c *Collector) CollectGraph(g usg.Store, labelDirtyNS map[string]bool) error {
	if c == nil {
		return nil
	}
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		ns, ok := moduleOf(n.ID)
		if !ok {
			continue
		}
		modID := ModuleID(ns)
		if c.dirtyNS[ns] {
			c.nodes[modID] = append(c.nodes[modID], nodeRow(modID, n))
		}
		if labelDirtyNS[ns] {
			c.labelNS[ns] = true
			c.presentNS[ns] = true
			labels, _ := g.Labels(n.ID)
			for _, l := range labels {
				r := labelRow(modID, usg.LabelRec{NodeID: n.ID, Label: l})
				if c.seenLabel[r.Key] {
					continue
				}
				c.seenLabel[r.Key] = true
				c.labels[modID] = append(c.labels[modID], r)
			}
		}
	}
	return nil
}

// moduleOf returns the module namespace a node id belongs to (ids are "<ns>\x1f…"). Mirrors
// lowering.NodeModule without importing lowering (which imports this package).
func moduleOf(id string) (string, bool) {
	for i := 0; i < len(id); i++ {
		if id[i] == '\x1f' {
			return id[:i], true
		}
	}
	return "", false
}

// Finalize produces the Delta and the new manifest (module ns -> "present"). prevNS is the set
// of module namespaces from the last sync; any not present now is tombstoned. Rows within each
// module are sorted by key for deterministic output.
func (c *Collector) Finalize(prevNS map[string]bool) (Delta, map[string]bool) {
	d := Delta{NodeMods: map[string][]SyncNode{}, EdgeMods: map[string][]SyncEdge{}, LabelMods: map[string][]SyncLabel{}}
	for ns := range c.dirtyNS {
		modID := ModuleID(ns)
		ns2 := c.nodes[modID]
		if ns2 == nil { // present (empty) so the client deletes the module's old rows
			ns2 = []SyncNode{}
		}
		sort.Slice(ns2, func(i, j int) bool { return ns2[i].Key < ns2[j].Key })
		d.NodeMods[modID] = ns2
		es := c.edges[modID]
		if es == nil {
			es = []SyncEdge{}
		}
		sort.Slice(es, func(i, j int) bool { return es[i].Key < es[j].Key })
		d.EdgeMods[modID] = es
	}
	for ns := range c.labelNS {
		modID := ModuleID(ns)
		ls := c.labels[modID]
		if ls == nil {
			ls = []SyncLabel{}
		}
		sort.Slice(ls, func(i, j int) bool { return ls[i].Key < ls[j].Key })
		d.LabelMods[modID] = ls
	}
	newNS := map[string]bool{}
	for ns := range c.presentNS {
		newNS[ns] = true
	}
	for ns := range prevNS {
		if !c.presentNS[ns] {
			d.Deleted = append(d.Deleted, ModuleID(ns))
		}
	}
	sort.Strings(d.Deleted)
	return d, newNS
}

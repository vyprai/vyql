package usg

// RecordingStore forwards every operation to the embedded Store and records the labels added
// through it, so a phase's label output (e.g. adapter labeling of a node subset) can be
// captured for caching. Reads and node/edge writes pass straight through. The captured labels
// live in Recs (not "Labels", which would shadow the Store.Labels(id) method).
type RecordingStore struct {
	Store
	Recs []LabelRec
}

// LabelRec is one captured (node, label) pair.
type LabelRec struct {
	NodeID string
	Label  Label
}

func (r *RecordingStore) AddLabel(nodeID string, l Label) error {
	r.Recs = append(r.Recs, LabelRec{nodeID, l})
	return r.Store.AddLabel(nodeID, l)
}

// AlwaysListed reports node types that an adapter subset view must always expose regardless of
// which modules are being relabeled: import and SBOM nodes, because package-evidence gathering
// scans all of them.
func AlwaysListed(t string) bool { return t == "code.Import" || t == "sbom.PackageVersion" }

// SubsetStore is a read view whose type-indexed listings (NodesOfType, AllNodes) return only a
// PRECOMPUTED node subset, so an adapter phase iterates O(subset) per adapter instead of
// re-filtering the whole graph on every call. Point reads (GetNode, edges, Labels) and writes
// pass through to the embedded Store unchanged, so an adapter that resolves a referenced node by
// id still sees the full graph. Build it with NewSubsetStore.
type SubsetStore struct {
	Store
	byType map[string][]string
	all    []Node
}

// NewSubsetStore builds a subset view exposing only the nodes for which keep(id, type) is true,
// plus all AlwaysListed (import/SBOM) nodes, in a single pass over the backing store. The byType
// index makes each adapter's NodesOfType O(result).
func NewSubsetStore(s Store, keep func(id, nodeType string) bool) (*SubsetStore, error) {
	all, err := s.AllNodes()
	if err != nil {
		return nil, err
	}
	byType := map[string][]string{}
	subset := make([]Node, 0, len(all))
	for _, n := range all {
		if AlwaysListed(n.Type) || keep(n.ID, n.Type) {
			byType[n.Type] = append(byType[n.Type], n.ID)
			subset = append(subset, n)
		}
	}
	return &SubsetStore{Store: s, byType: byType, all: subset}, nil
}

func (s *SubsetStore) NodesOfType(nodeType string) ([]string, error) { return s.byType[nodeType], nil }
func (s *SubsetStore) AllNodes() ([]Node, error)                     { return s.all, nil }

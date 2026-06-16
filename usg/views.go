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

// RestrictStore is a read view that hides nodes from the type-indexed listings (NodesOfType,
// AllNodes) unless Allow permits them — so an adapter phase iterates only a subset of nodes
// (e.g. freshly-lowered modules) while still resolving any node by id. Import and SBOM nodes
// are ALWAYS listed regardless of Allow, because package-evidence gathering needs all of them.
// Writes and point reads (GetNode, edges, Labels) pass through unchanged.
type RestrictStore struct {
	Store
	Allow func(nodeID string) bool
}

func alwaysListed(t string) bool { return t == "code.Import" || t == "sbom.PackageVersion" }

func (r *RestrictStore) NodesOfType(nodeType string) ([]string, error) {
	ids, err := r.Store.NodesOfType(nodeType)
	if err != nil || alwaysListed(nodeType) {
		return ids, err
	}
	out := ids[:0]
	for _, id := range ids {
		if r.Allow(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *RestrictStore) AllNodes() ([]Node, error) {
	all, err := r.Store.AllNodes()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, n := range all {
		if alwaysListed(n.Type) || r.Allow(n.ID) {
			out = append(out, n)
		}
	}
	return out, nil
}

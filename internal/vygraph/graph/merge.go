package graph

import (
	"errors"
	"fmt"
	"strings"
)

// ErrTierConflict reports two same-trust producers writing different values to one
// field. Resolving it by arrival order would make a scan non-deterministic, so it is an
// error.
var ErrTierConflict = errors.New("same-tier field conflict")

// KeyOf renders a record's identity key from its declared key fields. Key field order
// comes from the schema, not from insertion order, so the key is stable.
func KeyOf(ts *TypeSchema, f Fields) (string, error) {
	var b strings.Builder
	b.WriteString(ts.Type)
	for _, name := range ts.Key {
		v, ok := f.Get(name)
		if !ok {
			return "", fmt.Errorf("%s: missing key field %q", ts.Type, name)
		}
		b.WriteByte(0x1f)
		b.WriteString(v.String())
	}
	return b.String(), nil
}

// Upsert adds a node, or merges into an existing one with the same id. Field conflicts
// resolve by provenance trust tier: a higher tier overwrites a lower one, a lower tier
// is ignored, and an equal tier writing a different value is ErrTierConflict. (The full
// "(build, then trust)" lexicographic ordering and subordinate-evidence recording arrive
// with lift/relate in Phase 2.)
func (g *Store) Upsert(n Node) error {
	existing, ok := g.nodes[n.ID]
	if !ok {
		return g.AddNode(n)
	}
	if existing.Type != n.Type {
		return fmt.Errorf("node %s: type %q cannot become %q", n.ID, existing.Type, n.Type)
	}
	merged := existing
	var err error
	n.Fields.Each(func(name string, incoming Value) bool {
		cur, had := merged.Fields.Get(name)
		switch {
		case !had, n.Prov.Trust > existing.Prov.Trust:
			merged.Fields.Set(name, incoming)
		case n.Prov.Trust < existing.Prov.Trust:
			// keep the higher-trust value
		case cur.String() != incoming.String():
			err = fmt.Errorf("%w: node %s field %q: %q (%s) vs %q (%s)",
				ErrTierConflict, n.ID, name, cur.String(), existing.Prov.Producer,
				incoming.String(), n.Prov.Producer)
			return false
		}
		return true
	})
	if err != nil {
		return err
	}
	if n.Prov.Trust > existing.Prov.Trust {
		merged.Prov = n.Prov
	}
	ts, _ := g.schemas.Lookup(merged.Type)
	if verr := ts.Validate(merged.Fields); verr != nil {
		return fmt.Errorf("node %s: %w", n.ID, verr)
	}
	g.nodes[n.ID] = merged
	return nil
}

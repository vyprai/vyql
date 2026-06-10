// Package adapters implements the adapter layer (docs/07) for the Go build.
//
// Adapters map technology-specific pattern matches to concept LABELS on graph
// nodes, with provenance, fidelity, and precedence. The "pattern matching" is
// supplied by each adapter's Apply func, which is given the graph and returns
// the mappings it asserts. This isolates the universality test: the SAME rule
// runs over a JS and a Python graph because two different adapters produced the
// same concept labels.
//
// Precedence (docs/07): tenant override > specificity > fidelity >
// origin-trust. When two adapters label the same node with conflicting CONTROL
// judgments, the lower-precedence one is suppressed and the conflict recorded.
package adapters

import "github.com/vyprai/vyql/usg"

// FidelityRank and OriginRank realise the precedence partial orders (docs/07).
var FidelityRank = map[string]int{"syntactic": 1, "resolved": 2, "semantic": 3}
var OriginRank = map[string]int{"community": 1, "ai_generated": 2, "ai_assisted": 3, "human": 4}

// Mapping is one node getting one concept label. A negative claim sets
// Detail["negative"] to the concept it argues the node is NOT.
type Mapping struct {
	NodeID   string
	Concept  string
	Fidelity string // optional per-mapping fidelity; overrides the adapter's
	Detail   map[string]string
}

func (m Mapping) negative() string {
	if m.Detail == nil {
		return ""
	}
	return m.Detail["negative"]
}

// Adapter asserts mappings for a technology, with a precedence profile.
type Adapter struct {
	Name        string
	Technology  string
	Specificity int    // higher = more specific (version-pinned)
	Fidelity    string // syntactic | resolved | semantic
	Origin      string // community | ai_generated | ai_assisted | human
	Confidence  string // high | medium | low
	Apply       func(usg.Store) []Mapping
}

// precedenceKey is compared lexicographically: specificity, then fidelity,
// then origin trust.
func (a Adapter) precedenceKey() [3]int {
	return [3]int{a.Specificity, FidelityRank[a.Fidelity], OriginRank[a.Origin]}
}

func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ConflictRecord notes that one adapter's claim was suppressed or out-ranked.
type ConflictRecord struct {
	NodeID  string
	Concept string
	Winner  string
	Loser   string
	Reason  string
}

type proposal struct {
	ad Adapter
	m  Mapping
}

type key struct{ node, concept string }

// Apply runs adapters, resolves precedence, and attaches the winning labels to
// the store. Returns (conflicts, suppressed mappings). Faithful port of
// poc/vyql/adapters.py apply_adapters.
func Apply(store usg.Store, ads []Adapter, tenantOverrides []Mapping) ([]ConflictRecord, []Mapping, error) {
	var proposals []proposal
	for _, ad := range ads {
		for _, m := range ad.Apply(store) {
			proposals = append(proposals, proposal{ad, m})
		}
	}

	var conflicts []ConflictRecord
	var suppressed []Mapping

	// positive claims grouped by (node, concept); negative claims by the
	// (node, concept) they argue against.
	pos := map[key][]proposal{}
	neg := map[key][]Adapter{}
	for _, p := range proposals {
		if n := p.m.negative(); n != "" {
			k := key{p.m.NodeID, n}
			neg[k] = append(neg[k], p.ad)
		} else {
			k := key{p.m.NodeID, p.m.Concept}
			pos[k] = append(pos[k], p)
		}
	}

	// tenant overrides win outright.
	overrideKeys := map[key]bool{}
	tenantNeg := map[key]bool{}
	for _, m := range tenantOverrides {
		if n := m.negative(); n != "" {
			k := key{m.NodeID, n}
			overrideKeys[k] = true
			tenantNeg[k] = true
		} else {
			k := key{m.NodeID, m.Concept}
			overrideKeys[k] = true
			if err := attach(store, m, "tenant.override", "semantic", "high"); err != nil {
				return nil, nil, err
			}
		}
	}

	// deterministic iteration over positive keys
	for _, k := range sortedKeys(pos) {
		plist := pos[k]
		if overrideKeys[k] {
			if tenantNeg[k] {
				for _, p := range plist {
					suppressed = append(suppressed, p.m)
					conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
						"tenant.override", p.ad.Name, "tenant override (negative)"})
				}
				continue
			}
		}

		// resolve positive vs negative claims on the same (node, concept)
		negAds := neg[k]
		if len(negAds) > 0 {
			bestPos := maxAdapter(plist)
			bestNeg := maxNeg(negAds)
			if less(bestPos.precedenceKey(), bestNeg.precedenceKey()) {
				for _, p := range plist {
					suppressed = append(suppressed, p.m)
					conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
						bestNeg.Name, p.ad.Name, "negative claim higher precedence"})
				}
				continue
			}
			conflicts = append(conflicts, ConflictRecord{k.node, k.concept,
				bestPos.Name, bestNeg.Name, "positive claim higher precedence"})
		}

		// attach the winning positive; note out-ranked losers
		winner := maxAdapter(plist)
		for _, p := range plist {
			if p.ad.Name != winner.Name {
				conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
					winner.Name, p.ad.Name, "lower precedence (specificity/fidelity/origin)"})
			}
		}
		win := winnerProposal(plist, winner)
		if err := attach(store, win.m, win.ad.Name, win.ad.Fidelity, win.ad.Confidence); err != nil {
			return nil, nil, err
		}
	}
	return conflicts, suppressed, nil
}

func attach(store usg.Store, m Mapping, adapter, fidelity, confidence string) error {
	if m.Fidelity != "" { // per-mapping fidelity overrides the adapter default
		fidelity = m.Fidelity
	}
	if fidelity == "" {
		fidelity = "resolved"
	}
	if confidence == "" {
		confidence = "high"
	}
	return store.AddLabel(m.NodeID, usg.Label{
		Concept: m.Concept,
		Provenance: usg.Provenance{
			Adapter: adapter, Fidelity: fidelity, Confidence: confidence,
		},
		Detail: m.Detail,
	})
}

func maxAdapter(ps []proposal) Adapter {
	best := ps[0].ad
	for _, p := range ps[1:] {
		if less(best.precedenceKey(), p.ad.precedenceKey()) {
			best = p.ad
		}
	}
	return best
}

func maxNeg(ads []Adapter) Adapter {
	best := ads[0]
	for _, a := range ads[1:] {
		if less(best.precedenceKey(), a.precedenceKey()) {
			best = a
		}
	}
	return best
}

// winnerProposal returns the winning adapter's proposal for a (node, concept);
// among that adapter's proposals it prefers the highest per-mapping fidelity, so
// a type-verified (resolved) mapping isn't shadowed by an earlier syntactic one.
func winnerProposal(ps []proposal, winner Adapter) proposal {
	best := -1
	bestRank := -1
	for i, p := range ps {
		if p.ad.Name != winner.Name {
			continue
		}
		r := FidelityRank[p.m.Fidelity]
		if best < 0 || r > bestRank {
			best, bestRank = i, r
		}
	}
	if best >= 0 {
		return ps[best]
	}
	return ps[0]
}

func sortedKeys(m map[key][]proposal) []key {
	ks := make([]key, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// insertion sort by (node, concept) for determinism without importing sort
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && lessKey(ks[j], ks[j-1]); j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

func lessKey(a, b key) bool {
	if a.node != b.node {
		return a.node < b.node
	}
	return a.concept < b.concept
}

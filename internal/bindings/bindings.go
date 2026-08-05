// Package bindings applies compiled v2 binding labelers to graph nodes.
//
// Applicators map technology-specific pattern matches to concept labels on
// graph nodes, with provenance, fidelity, and precedence. The "pattern
// matching" is supplied by each applicator's Apply func, which is given the
// graph and returns the mappings it asserts. This isolates the universality
// test: the same rule runs over a JS and a Python graph because two different
// binding applicators produced the same concept labels.
//
// Precedence (docs/07): tenant override > specificity > fidelity >
// origin-trust. When two applicators label the same node with conflicting check
// judgments, the lower-precedence one is suppressed and the conflict recorded.
package bindings

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/vyprai/vyql/internal/usg"
)

// FidelityRank and OriginRank realise the precedence partial orders (docs/07).
var FidelityRank = map[string]int{"syntactic": 1, "resolved": 2, "semantic": 3}
var OriginRank = map[string]int{"community": 1, "ai_generated": 2, "ai_assisted": 3, "human": 4}
var bindingTimingOn = os.Getenv("VYQL_BINDING_TIMING") != ""

// Mapping is one node getting one concept label. A negative claim sets
// Detail["negative"] to the concept it argues the node is NOT.
type Mapping struct {
	NodeID     string
	Concept    string
	Fidelity   string // optional per-mapping fidelity; overrides the applicator's
	Confidence string // optional per-mapping confidence; overrides the applicator's
	// Specificity, when > 0, overrides the applicator's specificity for this one mapping.
	// It realises the default binding tiering: a package-specific match (3) supersedes a
	// native-runtime path match (2) which supersedes a general name-based method match (1)
	// on the same (node, concept).
	Specificity int
	Detail      map[string]string
}

func (m Mapping) negative() string {
	if m.Detail == nil {
		return ""
	}
	return m.Detail["negative"]
}

// Applicator asserts mappings for a technology, with a precedence profile.
type Applicator struct {
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
func (a Applicator) precedenceKey() [3]int {
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

// proposalKey is the per-mapping precedence: the mapping's own specificity/fidelity
// override the applicator's when set. This lets a single applicator emit mappings at different
// tiers (general method match vs native path match vs package-specific) and have the most
// specific win the (node, concept) - the default binding tiering the design calls for.
func proposalKey(p proposal) [3]int {
	spec := p.ad.Specificity
	if p.m.Specificity > 0 {
		spec = p.m.Specificity
	}
	fid := p.ad.Fidelity
	if p.m.Fidelity != "" {
		fid = p.m.Fidelity
	}
	return [3]int{spec, FidelityRank[fid], OriginRank[p.ad.Origin]}
}

// ConflictRecord notes that one applicator's claim was suppressed or out-ranked.
type ConflictRecord struct {
	NodeID  string
	Concept string
	Winner  string
	Loser   string
	Reason  string
}

type proposal struct {
	ad Applicator
	m  Mapping
}

type key struct{ node, concept string }

type proposalGroup struct {
	best proposal
	all  []proposal // nil for singleton keys; populated only when precedence must resolve conflicts.
}

func (g proposalGroup) forEach(fn func(proposal)) {
	if len(g.all) == 0 {
		fn(g.best)
		return
	}
	for _, p := range g.all {
		fn(p)
	}
}

// Apply runs binding applicators, resolves precedence, and attaches the winning
// labels to the store. Returns conflicts and suppressed mappings.
func Apply(store usg.Store, apps []Applicator, tenantOverrides []Mapping) ([]ConflictRecord, []Mapping, error) {
	start := time.Now()
	proposalCount := 0

	// positive claims grouped by (node, concept); negative claims by the
	// (node, concept) they argue against. Most claims are singletons on large
	// repos, so keep only the winning proposal unless a key actually collides.
	pos := map[key]proposalGroup{}
	neg := map[key][]Applicator{}

	// Each applicator's Apply is read-only on the store and independent, so run them
	// concurrently. The merge below stays serial and in applicator order, so the
	// per-(node,concept) tie-breaking is identical to the old sequential pass —
	// parallelism changes wall-clock only, not the result.
	results := make([][]Mapping, len(apps))
	limit := runtime.GOMAXPROCS(0)
	if limit > len(apps) {
		limit = len(apps)
	}
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range apps {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			appStart := time.Now()
			results[i] = apps[i].Apply(store)
			if bindingTimingOn {
				fmt.Fprintf(os.Stderr, "[binding] %-48s %7.1fms %7d mapping(s)\n", apps[i].Name, float64(time.Since(appStart))/1e6, len(results[i]))
			}
		}(i)
	}
	wg.Wait()

	for i := range apps {
		app := apps[i]
		mappings := results[i]
		for _, m := range mappings {
			proposalCount++
			p := proposal{app, m}
			if n := m.negative(); n != "" {
				k := key{m.NodeID, n}
				neg[k] = append(neg[k], app)
				continue
			}
			k := key{m.NodeID, m.Concept}
			group, ok := pos[k]
			if !ok {
				pos[k] = proposalGroup{best: p}
				continue
			}
			if len(group.all) == 0 {
				group.all = []proposal{group.best, p}
			} else {
				group.all = append(group.all, p)
			}
			if less(proposalKey(group.best), proposalKey(p)) {
				group.best = p
			}
			pos[k] = group
		}
	}

	var conflicts []ConflictRecord
	var suppressed []Mapping

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
		group := pos[k]
		if overrideKeys[k] {
			if tenantNeg[k] {
				group.forEach(func(p proposal) {
					suppressed = append(suppressed, p.m)
					conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
						"tenant.override", p.ad.Name, "tenant override (negative)"})
				})
				continue
			}
		}

		// the most-specific positive proposal wins (per-mapping tiering): a package
		// match supersedes a native path match supersedes a general method match.
		win := group.best

		// resolve positive vs negative claims on the same (node, concept)
		negAds := neg[k]
		if len(negAds) > 0 {
			bestNeg := maxNeg(negAds)
			if less(proposalKey(win), bestNeg.precedenceKey()) {
				group.forEach(func(p proposal) {
					suppressed = append(suppressed, p.m)
					conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
						bestNeg.Name, p.ad.Name, "negative claim higher precedence"})
				})
				continue
			}
			conflicts = append(conflicts, ConflictRecord{k.node, k.concept,
				win.ad.Name, bestNeg.Name, "positive claim higher precedence"})
		}

		// attach the winner; note out-ranked losers (lower-tier matches superseded)
		group.forEach(func(p proposal) {
			if p.ad.Name != win.ad.Name {
				conflicts = append(conflicts, ConflictRecord{p.m.NodeID, p.m.Concept,
					win.ad.Name, p.ad.Name, "lower precedence (specificity/fidelity/origin)"})
			}
		})
		if err := attach(store, win.m, win.ad.Name, win.ad.Fidelity, win.ad.Confidence); err != nil {
			return nil, nil, err
		}
	}
	if bindingTimingOn {
		fmt.Fprintf(os.Stderr, "[binding] %-48s %7.1fms %7d proposal(s)\n", "precedence+attach", float64(time.Since(start))/1e6, proposalCount)
	}
	return conflicts, suppressed, nil
}

func attach(store usg.Store, m Mapping, applicator, fidelity, confidence string) error {
	if m.Fidelity != "" { // per-mapping fidelity overrides the applicator default
		fidelity = m.Fidelity
	}
	if m.Confidence != "" { // per-mapping confidence overrides the applicator default
		confidence = m.Confidence
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
			Applicator: applicator, Fidelity: fidelity, Confidence: confidence,
		},
		Detail: m.Detail,
	})
}

func maxNeg(apps []Applicator) Applicator {
	best := apps[0]
	for _, a := range apps[1:] {
		if less(best.precedenceKey(), a.precedenceKey()) {
			best = a
		}
	}
	return best
}

func sortedKeys(m map[key]proposalGroup) []key {
	ks := make([]key, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// sort by (node, concept) for deterministic attach order. Must be O(k log k): an insertion
	// sort here was O(k^2) and dominated the binding phase on large graphs (millions of keys).
	sort.Slice(ks, func(i, j int) bool { return lessKey(ks[i], ks[j]) })
	return ks
}

func lessKey(a, b key) bool {
	if a.node != b.node {
		return a.node < b.node
	}
	return a.concept < b.concept
}

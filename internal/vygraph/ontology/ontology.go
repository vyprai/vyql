// Package ontology holds the concept vocabulary. The engine ships with NO concepts —
// every concept here arrives as VyQL data at load time. This package knows how to
// store, relate and query concepts; it knows nothing about what any of them mean.
package ontology

import (
	"fmt"
	"sort"
)

// Kind is a concept's role, drawn from the closed ten-kind set (VyQL suite 02 §1).
// The closed set is what keeps the vocabulary finite and the solvers domain-agnostic.
// Note: "threat" is deliberately NOT a kind — threats form their own subsumes lattice.
type Kind string

const (
	KindSource    Kind = "source"    // attacker-influenceable origin
	KindSink      Kind = "sink"      // dangerous operation
	KindControl   Kind = "control"   // neutralizer of a threat on a FLOW (VyQL suite 02 §2)
	KindGuard     Kind = "guard"     // presence+dominance is the invariant (VyQL suite 02 §2)
	KindAsset     Kind = "asset"     // thing worth protecting
	KindPrivilege Kind = "privilege" // capability in a privilege lattice
	KindPrincipal Kind = "principal" // actor identity
	KindExposure  Kind = "exposure"  // reachability context
	KindAction    Kind = "action"    // domain operation
	KindState     Kind = "state"     // workflow / lifecycle state
)

var closedKinds = map[Kind]bool{
	KindSource: true, KindSink: true, KindControl: true, KindGuard: true,
	KindAsset: true, KindPrivilege: true, KindPrincipal: true, KindExposure: true,
	KindAction: true, KindState: true,
}

// Concept is one vocabulary entry. Kinds may be dual-role, but ONLY [control, guard]
// (VyQL suite 02 §2.1): one shared identity projecting a control facet (Neutralizes)
// and a guard facet (Defends). Refines is the taint-lattice parent; IsA over Refines is
// what lets a rule naming a parent fire on every refinement. The threat-binding fields
// (VulnerableTo/EnabledBy/Neutralizes/Defends) are carried now and consumed by the
// Phase 2 taint/cfg solvers.
type Concept struct {
	Name         string
	Kinds        []Kind
	Refines      string
	Taint        []string // source: taint kinds it carries
	VulnerableTo []string // sink: threats it is vulnerable to
	EnabledBy    []string // sink: taint kinds that arm it
	Neutralizes  []string // control facet: threats it neutralizes
	Defends      []string // guard facet: threats it defends against
	CWE          []string // standards mappings
}

// HasKind reports facet membership. A dual-role concept answers true for both.
func (c Concept) HasKind(k Kind) bool {
	for _, x := range c.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

func validKinds(ks []Kind) error {
	if len(ks) == 0 {
		return fmt.Errorf("concept must declare at least one kind")
	}
	seen := map[Kind]bool{}
	for _, k := range ks {
		if !closedKinds[k] {
			return fmt.Errorf("kind %q is not in the closed set", k)
		}
		if seen[k] {
			return fmt.Errorf("duplicate kind %q", k)
		}
		seen[k] = true
	}
	if len(ks) == 2 && !(ks[0] == KindControl && ks[1] == KindGuard || ks[0] == KindGuard && ks[1] == KindControl) {
		return fmt.Errorf("multi-kind concepts are only [control, guard], got %v", ks)
	}
	if len(ks) > 2 {
		return fmt.Errorf("multi-kind concepts are only [control, guard], got %v", ks)
	}
	return nil
}

type Ontology struct{ byName map[string]Concept }

func New() *Ontology { return &Ontology{byName: map[string]Concept{}} }

// Add registers a concept. Every named refines parent must already exist, which makes
// cycles impossible to introduce through Add alone.
func (o *Ontology) Add(c Concept) error {
	if err := validKinds(c.Kinds); err != nil {
		return fmt.Errorf("concept %q: %w", c.Name, err)
	}
	if _, dup := o.byName[c.Name]; dup {
		return fmt.Errorf("concept %q already defined", c.Name)
	}
	if c.Refines != "" {
		if _, ok := o.byName[c.Refines]; !ok {
			return fmt.Errorf("concept %q: unknown refines parent %q", c.Name, c.Refines)
		}
	}
	o.byName[c.Name] = c
	return nil
}

// Reparent replaces a concept's refines parent, rejecting any change that would close a
// cycle. IsA walks refines parents, so a cycle would not terminate.
func (o *Ontology) Reparent(name string, refines string) error {
	c, ok := o.byName[name]
	if !ok {
		return fmt.Errorf("unknown concept %q", name)
	}
	if refines != "" {
		if _, ok := o.byName[refines]; !ok {
			return fmt.Errorf("concept %q: unknown refines parent %q", name, refines)
		}
		if refines == name || o.IsA(refines, name) {
			return fmt.Errorf("concept %q: parent %q would close a cycle", name, refines)
		}
	}
	c.Refines = refines
	o.byName[name] = c
	return nil
}

func (o *Ontology) Get(name string) (Concept, bool) { c, ok := o.byName[name]; return c, ok }

// IsA reports whether child is ancestor, or refines from it, transitively. Reflexive.
// This is the taint-lattice walk that lets a rule naming HttpInput bind QueryParam.
func (o *Ontology) IsA(child, ancestor string) bool {
	if child == ancestor {
		return true
	}
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if n == ancestor {
			return true
		}
		if seen[n] {
			return false
		}
		seen[n] = true
		if p, ok := o.byName[n]; ok && p.Refines != "" {
			if walk(p.Refines) {
				return true
			}
		}
		return false
	}
	return walk(child)
}

// OfKind returns every concept carrying kind k as a facet, name-sorted for deterministic
// output. A dual-role concept appears in both pools (VyQL suite 02 §2.1).
func (o *Ontology) OfKind(k Kind) []Concept {
	var out []Concept
	for _, c := range o.byName {
		if c.HasKind(k) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

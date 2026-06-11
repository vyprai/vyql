// Package ai is the AI-over-graph layer (B4 / docs/18): the genuinely AI-shaped rows
// (business logic, workflow/approval bypass, multi-tenant isolation, multi-step) built as
// a CONSUMER of the deterministic engines, not free-floating LLM scanning. The moat is the
// grounding: every hypothesis is anchored to a concrete, reconstructable witness produced
// by the taint/CFG/canaccess solvers.
//
// What is built here (deterministic, no model): the EvidencePack grounding extracted from
// the USG, the Reasoner seam, and a stub/scripted Reasoner so the pipeline + tests are
// complete and green. What is INFRA-GATED (a live LLM endpoint this build cannot provision):
// a real Reasoner implementation behind the same seam, configured via VYQL_LLM_*. Until then
// Reasoner is StubReasoner (yields nothing) — the engine never emits an ungrounded finding.
package ai

import (
	"sort"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/usg"
)

// Fact is one grounded node: its concept label, source location, and CFG region.
type Fact struct {
	NodeID  string
	Concept string
	Loc     string
	Region  string
}

// EvidencePack is the grounding for one candidate hotspot, assembled entirely from the
// deterministic graph. It is what a Reasoner is given — concrete witnesses, not raw source.
type EvidencePack struct {
	Hotspot   string   // stable id for the candidate (the primary binding's node id)
	RuleID    string   // the deterministic rule that surfaced this hotspot, if any
	Bindings  []Fact   // the finding's endpoints (source/sink/principal/…)
	Witness   []string // the solver witness (taint path / reach hops / dominance)
	Neighbors []Fact   // labelled nodes adjacent in the graph — local context
	Negations []string // why-not evidence (guard dominates? sanitizer present?)
}

// Hypothesis is a Reasoner's output: a candidate finding that MUST cite the deterministic
// witness it is grounded on (WitnessRef). An ungrounded hypothesis is dropped by ToFinding.
type Hypothesis struct {
	Title      string
	Rationale  string
	WitnessRef []string
	Confidence string // high | medium | low
}

// Reasoner turns grounded evidence into hypotheses. The live implementation (an LLM) is
// infra-gated; StubReasoner stands in so the rest of the pipeline is real and tested.
type Reasoner interface {
	Hypotheses(EvidencePack) ([]Hypothesis, error)
}

// StubReasoner is the default when no model is configured — it never invents a finding.
type StubReasoner struct{}

func (StubReasoner) Hypotheses(EvidencePack) ([]Hypothesis, error) { return nil, nil }

// ScriptedReasoner replays fixed hypotheses keyed by hotspot — used in tests (and as a
// record/replay cache) so the deterministic pipeline can be exercised without a model.
type ScriptedReasoner struct{ ByHotspot map[string][]Hypothesis }

func (s ScriptedReasoner) Hypotheses(p EvidencePack) ([]Hypothesis, error) {
	return s.ByHotspot[p.Hotspot], nil
}

// BuildEvidencePack assembles the grounding for one deterministic finding: its endpoints,
// the solver witness, the why-not evidence, and the labelled graph neighbourhood of each
// endpoint (FLOWS + CONTROL adjacency) as local context for the reasoner.
func BuildEvidencePack(store usg.Store, f *findings.Finding) EvidencePack {
	pack := EvidencePack{RuleID: f.RuleID, Witness: f.Witness}
	if len(f.Bindings) > 0 {
		pack.Hotspot = f.Bindings[len(f.Bindings)-1].NodeID // the sink/target anchors the hotspot
	}
	seen := map[string]bool{}
	for _, b := range f.Bindings {
		pack.Bindings = append(pack.Bindings, fact(store, b.NodeID, b.Concept, b.Loc))
		seen[b.NodeID] = true
		for _, nb := range neighbors(store, b.NodeID) {
			if seen[nb] {
				continue
			}
			seen[nb] = true
			pack.Neighbors = append(pack.Neighbors, fact(store, nb, primaryConcept(store, nb), ""))
		}
	}
	for _, ne := range f.NegationEvidence {
		pack.Negations = append(pack.Negations, ne.Clause)
	}
	sort.Slice(pack.Neighbors, func(i, j int) bool { return pack.Neighbors[i].NodeID < pack.Neighbors[j].NodeID })
	return pack
}

// Analyze runs a Reasoner over the deterministic findings' evidence packs and returns AI
// findings — each carrying the witness it is grounded on (ToFinding drops the ungrounded).
func Analyze(store usg.Store, deterministic []*findings.Finding, r Reasoner) ([]*findings.Finding, error) {
	var out []*findings.Finding
	for _, f := range deterministic {
		pack := BuildEvidencePack(store, f)
		hs, err := r.Hypotheses(pack)
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			if fnd := h.ToFinding(pack); fnd != nil {
				out = append(out, fnd)
			}
		}
	}
	return out, nil
}

// ToFinding converts a grounded hypothesis to a finding. A hypothesis with no WitnessRef is
// ungrounded — it is DROPPED (the AI layer never emits a finding no one can reconstruct).
func (h Hypothesis) ToFinding(p EvidencePack) *findings.Finding {
	if len(h.WitnessRef) == 0 {
		return nil
	}
	conf := h.Confidence
	if conf == "" {
		conf = "low"
	}
	return &findings.Finding{
		RuleID:      "VYQL-AI-001",
		Severity:    "medium",
		WitnessKind: "ai",
		Witness:     h.WitnessRef,
		Confidence:  conf,
		Context:     []string{h.Title, h.Rationale, "grounded-on:" + p.RuleID},
		Bindings: []findings.Binding{
			{Name: "hotspot", NodeID: p.Hotspot, Concept: "ai.Hypothesis", Loc: hotspotLoc(p)},
		},
	}
}

func fact(store usg.Store, id, concept, loc string) Fact {
	f := Fact{NodeID: id, Concept: concept, Loc: loc}
	if n, ok, _ := store.GetNode(id); ok {
		f.Region = n.Prop("region")
		if f.Loc == "" {
			f.Loc = n.Prop("loc")
		}
	}
	return f
}

// neighbors returns the FLOWS + CONTROL adjacency of a node (both directions).
func neighbors(store usg.Store, id string) []string {
	var out []string
	for _, et := range []string{"FLOWS", "CONTROL"} {
		o, _ := store.OutEdges(id, et)
		for _, e := range o {
			out = append(out, e.Dst)
		}
		in, _ := store.InEdges(id, et)
		for _, e := range in {
			out = append(out, e.Src)
		}
	}
	return out
}

func primaryConcept(store usg.Store, id string) string {
	ls, _ := store.Labels(id)
	if len(ls) > 0 {
		return ls[0].Concept
	}
	if n, ok, _ := store.GetNode(id); ok {
		return n.Type
	}
	return ""
}

func hotspotLoc(p EvidencePack) string {
	for _, b := range p.Bindings {
		if b.NodeID == p.Hotspot {
			return b.Loc
		}
	}
	return ""
}

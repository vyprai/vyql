package engine

import (
	"sort"
	"strings"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/solvers"
	"github.com/vyprai/vyql/usg"
)

// Engine evaluates compiled rules against a USG store.
type Engine struct {
	Onto  *ontology.Ontology
	Store usg.Store
}

func New(onto *ontology.Ontology, store usg.Store) *Engine {
	return &Engine{Onto: onto, Store: store}
}

var confOrder = map[string]int{"low": 1, "medium": 2, "high": 3}

// Evaluate runs a compiled rule, returning deduplicated findings filtered by the
// rule's confidence floor.
func (e *Engine) Evaluate(cr *CompiledRule) ([]*findings.Finding, error) {
	fs, err := e.evaluate(cr)
	if err != nil {
		return nil, err
	}
	return e.applyConfidenceFloor(cr, dedup(fs)), nil
}

func (e *Engine) evaluate(cr *CompiledRule) ([]*findings.Finding, error) {
	switch body := cr.Rule.Body.(type) {
	case *parser.FlowStmt:
		switch body.Verb {
		case "taint", "flow":
			return e.evalTaint(cr)
		case "reach":
			return e.evalReach(cr)
		case "assume":
			return e.evalAssume(cr)
		}
	case *parser.MatchStmt:
		return e.evalMatch(cr)
	}
	return nil, nil
}

func (e *Engine) evalReach(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	sources, _ := e.Store.NodesWithConcept(body.Src.Concept)
	targets, _ := e.Store.NodesWithConcept(body.Dst.Concept)
	if req := e.whereAssetKinds(cr.Rule); len(req) > 0 {
		var keep []string
		for _, t := range targets {
			if intersect(e.assetKinds(t), req) {
				keep = append(keep, t)
			}
		}
		targets = keep
	}
	paths, err := solvers.FindReach(e.Store, sources, targets, nil)
	if err != nil {
		return nil, err
	}
	var out []*findings.Finding
	for _, p := range paths {
		var w []string
		for _, h := range p.Hops {
			w = append(w, h.From+" -> "+h.To+"  ["+h.Proto+":"+h.Port+" via "+h.Rule+"]")
		}
		out = append(out, &findings.Finding{
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "reach", Witness: w,
			Confidence: e.conf(p.TargetID),
			Bindings: []findings.Binding{
				{Name: "source", NodeID: p.SourceID, Concept: body.Src.Concept, Loc: e.loc(p.SourceID)},
				{Name: "target", NodeID: p.TargetID, Concept: body.Dst.Concept, Loc: e.loc(p.TargetID), LabelProvenance: e.prov(p.TargetID, body.Dst.Concept)},
			},
		})
	}
	return out, nil
}

func (e *Engine) evalAssume(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	sources, _ := e.Store.NodesWithConcept(body.Src.Concept)
	targets, _ := e.Store.NodesWithConcept(body.Dst.Concept)
	minLevel := ""
	if body.Dst.Concept == "identity.AdminPrivilege" {
		minLevel = "ADMIN"
	}
	paths, err := solvers.FindAssume(e.Store, sources, targets, minLevel)
	if err != nil {
		return nil, err
	}
	var out []*findings.Finding
	for _, p := range paths {
		var w []string
		for _, s := range p.Steps {
			w = append(w, s.From+" -> "+s.To+"  ["+s.Ability+"]")
		}
		out = append(out, &findings.Finding{
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "assume", Witness: w,
			Confidence: e.conf(p.SourceID),
			Bindings: []findings.Binding{
				{Name: "principal", NodeID: p.SourceID, Concept: body.Src.Concept, Loc: e.loc(p.SourceID)},
				{Name: "target", NodeID: p.TargetID, Concept: body.Dst.Concept, Loc: e.loc(p.TargetID)},
			},
		})
	}
	return out, nil
}

// whereAssetKinds returns the kinds in a `where X holds_asset_kind [...]` clause.
func (e *Engine) whereAssetKinds(r *parser.Rule) map[string]bool {
	for _, cl := range r.Clauses {
		if cl.Kind != "where" {
			continue
		}
		for _, atom := range flattenAnd(cl.Where) {
			if hk, ok := atom.(parser.HoldsAssetKind); ok {
				out := map[string]bool{}
				for _, k := range hk.Kinds {
					out[k] = true
				}
				return out
			}
		}
	}
	return nil
}

func flattenAnd(e parser.Expr) []parser.Expr {
	if a, ok := e.(parser.And); ok {
		return a.Parts
	}
	return []parser.Expr{e}
}

// crossDomainContext surfaces graph context that makes a finding matter more
// where it is deployed (docs/10, /14, /17): the sink's service being
// internet-reachable, and the sink's database holding sensitive asset kinds.
// This is the cross-domain payoff at the individual-finding level and the input
// to factor-based risk — derived and witness-backed, never a fabricated score.
func (e *Engine) crossDomainContext(sinkID string) []string {
	n, ok, _ := e.Store.GetNode(sinkID)
	if !ok {
		return nil
	}
	var ctx []string
	if svc := n.Prop("service"); svc != "" {
		if _, ok, _ := e.Store.GetNode(svc); ok {
			internet, _ := e.Store.NodesWithConcept("cloud.Internet")
			if paths, _ := solvers.FindReach(e.Store, internet, []string{svc}, nil); len(paths) > 0 {
				h := paths[0].Hops
				via := ""
				if len(h) > 0 {
					via = h[len(h)-1].Rule
				}
				line := svc + " is internet-reachable (via " + via + ")"
				// static↔runtime confirmation (docs/11 Part B): a statically
				// predicted exposure observed in runtime telemetry is confirmed,
				// which the risk layer escalates (docs/17 exposure→confirmed).
				if e.observedExternalConnection(svc) {
					line += " — confirmed by runtime traffic (last 24h)"
				}
				ctx = append(ctx, line)
			}
		}
	}
	if db := n.Prop("database"); db != "" {
		if _, ok, _ := e.Store.GetNode(db); ok {
			if kinds := sortedSet(e.assetKinds(db)); len(kinds) > 0 {
				ctx = append(ctx, "sink database "+db+" holds ["+strings.Join(kinds, " ")+"]")
			}
		}
	}
	return ctx
}

// observedExternalConnection reports whether the pre-aggregated runtime snapshot
// holds a runtime.Connection observed reaching svc from outside (docs/11: an
// OBSERVED external connection). Modeled over the aggregate graph, not a live
// stream — the streaming evaluator that maintains these deltas is deferred.
func (e *Engine) observedExternalConnection(svc string) bool {
	ids, _ := e.Store.NodesWithConcept("runtime.Connection")
	for _, id := range ids {
		n, _, _ := e.Store.GetNode(id)
		if n.Prop("dst") == svc && n.Prop("external") == "true" {
			return true
		}
	}
	return false
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) assetKinds(nodeID string) map[string]bool {
	out := map[string]bool{}
	for _, l := range e.labels(nodeID) {
		if l.Detail != nil {
			if v := l.Detail["asset_kinds"]; v != "" {
				for _, k := range strings.Split(v, ",") {
					out[strings.TrimSpace(k)] = true
				}
			}
		}
	}
	return out
}

func intersect(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

func (e *Engine) evalTaint(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	srcConcepts := e.Onto.Descendants(body.Src.Concept)
	sinkConcepts := e.Onto.Descendants(body.Dst.Concept)
	taintKinds := map[string]bool{}
	for c := range srcConcepts {
		if cc, err := e.Onto.Get(c); err == nil {
			for _, t := range cc.Taint {
				taintKinds[t] = true
			}
		}
	}

	flows, err := solvers.FindTaintFlows(e.Store, srcConcepts, sinkConcepts, taintKinds, cr.KillControls)
	if err != nil {
		return nil, err
	}

	var guards []string
	var sanitizer string
	for _, cl := range cr.Rule.Clauses {
		if cl.Kind != "unless" {
			continue
		}
		switch ex := cl.Unless.(type) {
		case parser.GuardedBy:
			guards = append(guards, ex.Concept)
		case parser.SanitizedBy:
			sanitizer = ex.Concept
		}
	}

	var out []*findings.Finding
	for _, fl := range flows {
		var ne []findings.NegationEvidence
		if sanitizer != "" {
			detail := "no neutralizing control dominates the path; "
			if len(fl.NearMiss) > 0 {
				var nm []string
				for _, p := range fl.NearMiss {
					nm = append(nm, p[1]+" @ "+e.loc(p[0]))
				}
				detail += "nearest on a sibling path: " + strings.Join(nm, ", ")
			} else {
				detail += "none found anywhere on flows"
			}
			ne = append(ne, findings.NegationEvidence{Clause: "sanitized_by " + sanitizer, Satisfied: false, Detail: detail})
		}
		suppressed := false
		for _, g := range guards {
			ok := e.endpointGuarded(fl.SinkID, g)
			detail := "no guard on sink"
			if ok {
				detail = "guard covers sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: "guarded_by " + g, Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		if suppressed {
			continue
		}
		srcC := e.conceptIn(fl.SourceID, srcConcepts)
		snkC := e.conceptIn(fl.SinkID, sinkConcepts)
		f := &findings.Finding{
			RuleID:   e.ruleID(cr),
			Severity: cr.Severity,
			Bindings: []findings.Binding{
				{Name: "source", NodeID: fl.SourceID, Concept: srcC, Loc: e.loc(fl.SourceID), LabelProvenance: e.prov(fl.SourceID, srcC)},
				{Name: "sink", NodeID: fl.SinkID, Concept: snkC, Loc: e.loc(fl.SinkID), LabelProvenance: e.prov(fl.SinkID, snkC)},
			},
			Witness:          fl.Path,
			WitnessKind:      "taint",
			NegationEvidence: ne,
			Confidence:       e.conf(fl.SourceID, fl.SinkID),
			Context:          e.crossDomainContext(fl.SinkID),
		}
		out = append(out, f)
	}
	return out, nil
}

// --- helpers -------------------------------------------------------------

func (e *Engine) ruleID(cr *CompiledRule) string {
	if id, ok := cr.Rule.Meta["id"].(string); ok {
		return id
	}
	return cr.Rule.QualifiedName()
}

func (e *Engine) loc(nodeID string) string {
	if n, ok, _ := e.Store.GetNode(nodeID); ok {
		if l := n.Prop("loc"); l != "" {
			return l
		}
	}
	return nodeID
}

func (e *Engine) labels(nodeID string) []usg.Label {
	ls, _ := e.Store.Labels(nodeID)
	return ls
}

func (e *Engine) conceptIn(nodeID string, set map[string]bool) string {
	for _, l := range e.labels(nodeID) {
		if set[l.Concept] {
			return l.Concept
		}
	}
	return ""
}

func (e *Engine) prov(nodeID, concept string) string {
	for _, l := range e.labels(nodeID) {
		if l.Concept == concept && l.Provenance.Adapter != "" {
			fid := l.Provenance.Fidelity
			if fid == "" {
				fid = "resolved"
			}
			return concept + " by " + l.Provenance.Adapter + "@" + fid
		}
	}
	return ""
}

// fidelityCeil caps confidence by match fidelity (docs/07): a syntactic match
// (substring / bare method name, no receiver type) can be no better than medium;
// resolved/semantic matches may be high.
var fidelityCeil = map[string]int{"syntactic": 2, "resolved": 3, "semantic": 3}

func (e *Engine) conf(nodeIDs ...string) string {
	best := 3
	for _, id := range nodeIDs {
		for _, l := range e.labels(id) {
			c := l.Provenance.Confidence
			if c == "" {
				c = "high"
			}
			eff := confOrder[c]
			if eff == 0 {
				eff = 3
			}
			// a label is only as trustworthy as the fidelity of the match that
			// produced it
			if ceil, ok := fidelityCeil[l.Provenance.Fidelity]; ok && ceil < eff {
				eff = ceil
			}
			if eff < best {
				best = eff
			}
		}
	}
	switch best {
	case 1:
		return "low"
	case 2:
		return "medium"
	}
	return "high"
}

// endpointGuarded reports whether a guard carrying `control` covers the sink. Path-
// sensitive (B1.4): when both the guard and sink carry CFG metadata, the guard must
// DOMINATE the sink to suppress — a guard in one branch does not cover a flow through a
// sibling branch (the presence model's false-negative). Without CFG metadata (hand-built
// graphs, frontends not yet converted to structured NIR) it falls back to presence
// semantics at a lower fidelity, so existing behaviour and tests are unchanged.
func (e *Engine) endpointGuarded(sinkID, control string) bool {
	sinkCFG := hasCFG(e.Store, sinkID)
	// (1) an explicit PROTECTS/CHECKS edge (graph specs; a future endpoint-linking pass).
	for _, et := range []string{"PROTECTS", "CHECKS"} {
		edges, _ := e.Store.InEdges(sinkID, et)
		for _, ed := range edges {
			for _, l := range e.labels(ed.Src) {
				if l.Concept != control {
					continue
				}
				if sinkCFG && hasCFG(e.Store, ed.Src) {
					if solvers.Dominates(e.Store, ed.Src, sinkID) {
						return true // guard dominates → covers every path → suppress
					}
					continue // non-dominating guard → keep looking for one that does
				}
				return true // presence fallback (no CFG metadata)
			}
		}
	}
	// (2) B1: a guard-control-labelled node that DOMINATES the sink. This is what makes
	// `guarded_by` work on REAL CODE — adapters label the check (e.g. validate_csrf_token,
	// a @login_required decorator) with the control concept, and the structured CFG lets us
	// connect it to exactly the sinks it covers (path-sensitive: a check in one branch does
	// not guard a sibling branch). Requires CFG metadata, so it never fires on metadata-free
	// graphs — those rely on the explicit edge above.
	if sinkCFG {
		guards, _ := e.Store.NodesWithConcept(control)
		for _, gid := range guards {
			if gid != sinkID && hasCFG(e.Store, gid) && solvers.Dominates(e.Store, gid, sinkID) {
				return true
			}
		}
	}
	return false
}

// hasCFG reports whether a node carries structured-CFG metadata (a region tag).
func hasCFG(store usg.Store, id string) bool {
	if n, ok, _ := store.GetNode(id); ok {
		return n.Prop("region") != ""
	}
	return false
}

func dedup(fs []*findings.Finding) []*findings.Finding {
	seen := map[string]bool{}
	var out []*findings.Finding
	for _, f := range fs {
		fp := f.Fingerprint()
		if !seen[fp] {
			seen[fp] = true
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) applyConfidenceFloor(cr *CompiledRule, fs []*findings.Finding) []*findings.Finding {
	floor, _ := cr.Rule.Meta["min_confidence"].(string)
	if floor == "" {
		floor, _ = cr.Rule.Meta["confidence_floor"].(string)
	}
	if floor == "" {
		return fs
	}
	threshold := confOrder[floor]
	var out []*findings.Finding
	for _, f := range fs {
		if confOrder[f.Confidence] >= threshold {
			out = append(out, f)
		}
	}
	return out
}

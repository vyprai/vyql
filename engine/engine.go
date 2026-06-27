package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/resultpolicy"
	"github.com/vyprai/vyql/solvers"
	"github.com/vyprai/vyql/usg"
)

// Engine evaluates compiled rules against a USG store.
type Engine struct {
	Onto               *ontology.Ontology
	Store              usg.Store
	conceptRole        map[string]map[string]bool
	contextReach       []contextReachSource
	contextReachSet    bool
	contextAssets      []contextAssetConcept
	contextAssetsSet   bool
	contextConfirms    []contextConfirmation
	contextConfirmsSet bool
	cfg                map[string]bool
	labelsByNode       map[string][]usg.Label
	nodesByConcept     map[string][]string
	flowGuards         map[string][]string
	dominanceGuards    map[string][]string
	sameReceiverGuards map[string]map[string]bool
	sameScopeGuards    map[string]map[string]bool
	globalGuards       map[string]bool
}

func New(onto *ontology.Ontology, store usg.Store) *Engine {
	return &Engine{
		Onto:               onto,
		Store:              store,
		conceptRole:        map[string]map[string]bool{},
		cfg:                map[string]bool{},
		labelsByNode:       map[string][]usg.Label{},
		nodesByConcept:     map[string][]string{},
		flowGuards:         map[string][]string{},
		dominanceGuards:    map[string][]string{},
		sameReceiverGuards: map[string]map[string]bool{},
		sameScopeGuards:    map[string]map[string]bool{},
		globalGuards:       map[string]bool{},
	}
}

var confOrder = map[string]int{"possibility": 0, "low": 1, "medium": 2, "high": 3}

// Evaluate runs a compiled rule, returning deduplicated findings filtered by the
// rule's confidence floor.
func (e *Engine) Evaluate(cr *CompiledRule) ([]*findings.Finding, error) {
	fs, err := e.evaluate(cr)
	if err != nil {
		return nil, err
	}
	return e.applyConfidenceFloor(cr, resultpolicy.Dedup(fs)), nil
}

func (e *Engine) evaluate(cr *CompiledRule) ([]*findings.Finding, error) {
	if cr == nil || cr.Rule == nil {
		return nil, fmt.Errorf("cannot evaluate nil compiled rule")
	}
	switch body := cr.Rule.Body.(type) {
	case *parser.FlowStmt:
		switch body.Verb {
		case "taint":
			return e.evalTaint(cr)
		case "reach":
			return e.evalReach(cr)
		case "grant":
			return e.evalPrivilegeClosure(cr, "grant")
		default:
			return nil, fmt.Errorf("unsupported rule verb %q", body.Verb)
		}
	case *parser.MatchStmt:
		return e.evalMatch(cr)
	case *parser.OrderStmt:
		return e.evalOrder(cr)
	}
	return nil, fmt.Errorf("unsupported rule body %T", cr.Rule.Body)
}

// evalOrder evaluates `order A before B`: a finding for each (A,B) where an
// A-operation can reach a B-operation on a CFG path.
func (e *Engine) evalOrder(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.OrderStmt)
	firsts := e.nodesWithConcept(body.First.Concept)
	seconds := e.nodesWithConcept(body.Second.Concept)
	firstName := body.First.Binding
	if firstName == "" {
		firstName = "first"
	}
	secondName := body.Second.Binding
	if secondName == "" {
		secondName = "second"
	}
	var out []*findings.Finding
	for _, a := range firsts {
		for _, b := range seconds {
			if !solvers.Reaches(e.Store, a, b) {
				continue
			}
			out = append(out, &findings.Finding{
				RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "order",
				Confidence:       e.confBindings(bindingRef{nodeID: a, concept: body.First.Concept}, bindingRef{nodeID: b, concept: body.Second.Concept}),
				ReviewConditions: append(e.reviewConditions(a, body.First.Concept), e.reviewConditions(b, body.Second.Concept)...),
				Bindings: []findings.Binding{
					{Name: firstName, NodeID: a, Concept: body.First.Concept, Loc: e.loc(a), LabelProvenance: e.prov(a, body.First.Concept)},
					{Name: secondName, NodeID: b, Concept: body.Second.Concept, Loc: e.loc(b), LabelProvenance: e.prov(b, body.Second.Concept)},
				},
			})
		}
	}
	return out, nil
}

func (e *Engine) evalReach(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	sources := e.nodesWithConcept(body.Src.Concept)
	targets := e.nodesWithConcept(body.Dst.Concept)
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
	sourceName := body.Src.Binding
	if sourceName == "" {
		sourceName = "source"
	}
	targetName := body.Dst.Binding
	if targetName == "" {
		targetName = "target"
	}
	var out []*findings.Finding
	for _, p := range paths {
		var w []string
		for _, h := range p.Hops {
			w = append(w, h.From+" -> "+h.To+"  ["+h.Proto+":"+h.Port+" via "+h.Rule+"]")
		}
		out = append(out, &findings.Finding{
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: "reach", Witness: w,
			Confidence: e.confConcept(p.TargetID, body.Dst.Concept),
			Bindings: []findings.Binding{
				{Name: sourceName, NodeID: p.SourceID, Concept: body.Src.Concept, Loc: e.loc(p.SourceID), LabelProvenance: e.prov(p.SourceID, body.Src.Concept)},
				{Name: targetName, NodeID: p.TargetID, Concept: body.Dst.Concept, Loc: e.loc(p.TargetID), LabelProvenance: e.prov(p.TargetID, body.Dst.Concept)},
			},
		})
	}
	return out, nil
}

func (e *Engine) evalPrivilegeClosure(cr *CompiledRule, witnessKind string) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	sources := e.nodesWithConcept(body.Src.Concept)
	targets := e.nodesWithConcept(body.Dst.Concept)
	paths, err := solvers.FindAssume(e.Store, sources, targets, e.grantMinLevel(body.Dst.Concept))
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
			RuleID: e.ruleID(cr), Severity: cr.Severity, WitnessKind: witnessKind, Witness: w,
			Confidence: e.confConcept(p.SourceID, body.Src.Concept),
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
		var out []parser.Expr
		for _, part := range a.Parts {
			out = append(out, flattenAnd(part)...)
		}
		return out
	}
	return []parser.Expr{e}
}

func flattenOr(e parser.Expr) []parser.Expr {
	if a, ok := e.(parser.Or); ok {
		var out []parser.Expr
		for _, part := range a.Parts {
			out = append(out, flattenOr(part)...)
		}
		return out
	}
	return []parser.Expr{e}
}

func mergeWhere(existing, next parser.Expr) parser.Expr {
	if existing == nil {
		return next
	}
	parts := append([]parser.Expr{}, flattenAnd(existing)...)
	parts = append(parts, flattenAnd(next)...)
	return parser.And{Parts: parts}
}

// crossDomainContext surfaces ontology-configured graph context around a finding.
// Concepts define which sink properties point to related graph nodes and how
// evidence should be rendered; the engine only follows those links.
func (e *Engine) crossDomainContext(sinkID string) []string {
	n, ok, _ := e.Store.GetNode(sinkID)
	if !ok {
		return nil
	}
	var ctx []string
	for _, src := range e.contextReachSources() {
		target := n.Prop(src.TargetProp)
		if target == "" {
			continue
		}
		if _, ok, _ := e.Store.GetNode(target); !ok {
			continue
		}
		sourceIDs := e.nodesWithConcept(src.Concept)
		if paths, _ := solvers.FindReach(e.Store, sourceIDs, []string{target}, nil); len(paths) > 0 {
			h := paths[0].Hops
			via := ""
			if len(h) > 0 {
				via = h[len(h)-1].Rule
			}
			line := target + " is " + src.Label + " (via " + via + ")"
			for _, label := range e.contextConfirmations(target) {
				line += " — " + label
			}
			ctx = append(ctx, line)
		}
	}
	for _, ac := range e.contextAssetConcepts() {
		target := n.Prop(ac.TargetProp)
		if target == "" {
			continue
		}
		if _, ok, _ := e.Store.GetNode(target); !ok {
			continue
		}
		if !e.nodeHasConcept(target, ac.Concept) {
			continue
		}
		if kinds := sortedSet(e.assetKinds(target)); len(kinds) > 0 {
			ctx = append(ctx, renderContextLabel(ac.Label, target, kinds))
		}
	}
	return ctx
}

type contextReachSource struct {
	Concept    string
	Label      string
	TargetProp string
}

func (e *Engine) contextReachSources() []contextReachSource {
	if e.contextReachSet {
		return e.contextReach
	}
	e.contextReachSet = true
	var out []contextReachSource
	for _, c := range e.Onto.AllConcepts() {
		if c.ContextReachSource != "true" {
			continue
		}
		if c.ContextReachTargetProp == "" {
			continue
		}
		label := c.ContextReachLabel
		if label == "" {
			label = c.Name
		}
		out = append(out, contextReachSource{
			Concept:    c.QualifiedName(),
			Label:      label,
			TargetProp: c.ContextReachTargetProp,
		})
	}
	e.contextReach = out
	return e.contextReach
}

type contextAssetConcept struct {
	Concept    string
	TargetProp string
	Label      string
}

func (e *Engine) contextAssetConcepts() []contextAssetConcept {
	if e.contextAssetsSet {
		return e.contextAssets
	}
	e.contextAssetsSet = true
	var out []contextAssetConcept
	for _, c := range e.Onto.AllConcepts() {
		if c.ContextAssetTargetProp == "" {
			continue
		}
		label := c.ContextAssetLabel
		if label == "" {
			label = "{target} holds [{kinds}]"
		}
		out = append(out, contextAssetConcept{
			Concept:    c.QualifiedName(),
			TargetProp: c.ContextAssetTargetProp,
			Label:      label,
		})
	}
	e.contextAssets = out
	return e.contextAssets
}

func renderContextLabel(template, target string, kinds []string) string {
	out := strings.ReplaceAll(template, "{target}", target)
	out = strings.ReplaceAll(out, "{kinds}", strings.Join(kinds, " "))
	return out
}

func (e *Engine) contextConfirmations(target string) []string {
	var out []string
	for _, c := range e.contextConfirmationSpecs() {
		ids := e.nodesWithConcept(c.Concept)
		for _, id := range ids {
			n, _, _ := e.Store.GetNode(id)
			if n.Prop(c.DstProp) != target {
				continue
			}
			if c.FlagProp != "" && n.Prop(c.FlagProp) != c.FlagValue {
				continue
			}
			out = append(out, c.Label)
		}
	}
	return out
}

type contextConfirmation struct {
	Concept   string
	DstProp   string
	FlagProp  string
	FlagValue string
	Label     string
}

func (e *Engine) contextConfirmationSpecs() []contextConfirmation {
	if e.contextConfirmsSet {
		return e.contextConfirms
	}
	e.contextConfirmsSet = true
	var out []contextConfirmation
	for _, c := range e.Onto.AllConcepts() {
		if c.ContextConfirmDstProp == "" {
			continue
		}
		label := c.ContextConfirmLabel
		if label == "" {
			label = "confirmed by " + c.Name
		}
		out = append(out, contextConfirmation{
			Concept:   c.QualifiedName(),
			DstProp:   c.ContextConfirmDstProp,
			FlagProp:  c.ContextConfirmFlagProp,
			FlagValue: c.ContextConfirmFlagValue,
			Label:     label,
		})
	}
	e.contextConfirms = out
	return e.contextConfirms
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

func (e *Engine) grantMinLevel(concept string) string {
	if c, err := e.Onto.Get(concept); err == nil {
		return c.GrantMinLevel
	}
	return ""
}

// charFilterAdvisoryNote returns an advisory note if a character-filter (replace) lies on a
// live taint path — meaning vyql could NOT prove it excludes this sink's required
// character set (a sound allowlist filter would have killed the flow already).
func (e *Engine) charFilterAdvisoryNote(path []string, excluded string) string {
	charFilters := e.conceptsWithInternalConceptRole(ontology.InternalConceptRoleCharFilter)
	onPath := make(map[string]bool, len(path))
	for _, id := range path {
		onPath[id] = true
	}
	for _, id := range path {
		labels, _ := e.Store.Labels(id)
		for _, l := range labels {
			if !charFilters[l.Concept] {
				continue
			}
			// A replace FILTERS its subject but emits its REPLACEMENT verbatim (arg1, in both
			// `s.replace(pat,repl)` and `re.sub(pat,repl,s)`). If the taint entered through the
			// replacement, the filter never touched it: this is a direct insertion,
			// so this is a confident finding, not advisory-gated.
			if n, ok, _ := e.Store.GetNode(id); ok {
				if a1 := n.Prop("arg1"); a1 != "" && onPath[a1] {
					continue
				}
			}
			pat := l.Detail["pattern"]
			if excluded == "" {
				return "a character-filter replace(" + pat + ") is on the path but this sink declares no excluded_chars to verify against; finding holds unless the filter neutralizes by other means"
			}
			return "a character-filter replace(" + pat + ") is on the path but its bounded output is not proven to exclude [" + excluded + "]; false positive if the transform is complete for this value set"
		}
	}
	return ""
}

// neutralizerAdvisoryEvidence surfaces UNSOUND neutralizers that bear on a finding:
// a guard that DOMINATES the sink, or a sanitizer ON the taint path, whose declared `about`
// concept matches this sink's threat. Each yields an advisory note — the flow is NEVER
// suppressed (vyql cannot prove the neutralizer sound), but is flagged as a false positive
// IF it works. This generalizes the regex-CharFilter mechanism (charFilterAdvisoryNote) to arbitrary
// neutralizers: the confident bucket (findings with no advisory note) is near-zero-FP, and
// the noted bucket is the human review queue. Which calls are unsound neutralizers comes from
// v2 advisory check bindings; the mechanic itself is Go-owned and threat-agnostic.
func (e *Engine) neutralizerAdvisoryEvidence(path []string, sinkID string, sinkConcepts map[string]bool) []findings.NegationEvidence {
	var out []findings.NegationEvidence
	seen := map[string]bool{}
	add := func(mode, pat string) {
		key := mode + "|" + pat
		if seen[key] {
			return
		}
		seen[key] = true
		detail := "an unsound sanitizer " + pat + " is on the path but is not provably complete for this sink; false positive if it neutralizes correctly"
		if mode == "guard" {
			detail = "an unsound guard " + pat + " dominates the sink but is not provably complete for this target; false positive if it blocks the relevant condition"
		}
		out = append(out, findings.NegationEvidence{Clause: mode + " advisory", Satisfied: false, Detail: detail})
	}
	// sanitizer-style: an internal advisory label lying ON the taint path.
	for _, id := range path {
		for _, l := range e.labels(id) {
			if l.Concept == ontology.InternalNeutralizerAssumptionConcept && l.Detail["mode"] == "sanitizer" && sinkConcepts[l.Detail["about"]] {
				add("sanitizer", l.Detail["pattern"])
			}
		}
	}
	// guard-style: an advisory guard that DOMINATES the sink. A guard inspecting THIS
	// tainted value is, by construction, a direct FLOWS out-neighbour of a node on the path
	// (the tainted operand flows into it), so we scan those neighbours LOCALLY rather than the
	// whole store — O(path · out-degree), not O(store · findings). Found nothing globally is
	// the same as found nothing here, but cheap on large corpora.
	if e.hasCFG(sinkID) {
		guarded := map[string]bool{}
		for _, pid := range path {
			edges, _ := e.Store.OutEdges(pid, "FLOWS")
			for _, ed := range edges {
				gid := ed.Dst
				if gid == sinkID || guarded[gid] || !e.hasCFG(gid) {
					continue
				}
				guarded[gid] = true
				for _, l := range e.labels(gid) {
					if l.Concept != ontology.InternalNeutralizerAssumptionConcept || l.Detail["mode"] != "guard" {
						continue
					}
					// about=="*" is a structural guard (a `<const> in tainted` blocklist) that
					// applies to any threat; a named about must match this sink's concept.
					if about := l.Detail["about"]; about != "*" && !sinkConcepts[about] {
						continue
					}
					if solvers.Dominates(e.Store, gid, sinkID) {
						add("guard", l.Detail["pattern"])
					}
				}
			}
		}
	}
	return out
}

func (e *Engine) evalTaint(cr *CompiledRule) ([]*findings.Finding, error) {
	body := cr.Rule.Body.(*parser.FlowStmt)
	srcConcepts := cr.SourceConcepts
	if srcConcepts == nil {
		srcConcepts = e.Onto.Descendants(body.Src.Concept)
	}
	sinkConcepts := cr.SinkConcepts
	if sinkConcepts == nil {
		sinkConcepts = e.Onto.Descendants(body.Dst.Concept)
	}
	taintKinds := cr.TaintKinds
	if taintKinds == nil {
		taintKinds = taintKindsFor(e.Onto, srcConcepts)
	}
	excluded := cr.ExcludedChars
	if cr.SinkConcepts == nil {
		// excluded characters for this sink threat (declared on the sink concept(s) via
		// `excluded_chars`) — lets an allowlist character-filter be proven a sound sanitizer.
		excluded = excludedCharsFor(e.Onto, sinkConcepts)
	}

	flows, err := solvers.FindTaintFlows(e.Store, srcConcepts, sinkConcepts, taintKinds, cr.KillControls, excluded, e.conceptsWithInternalConceptRole(ontology.InternalConceptRoleCharFilter))
	if err != nil {
		return nil, err
	}

	var guards, dominanceGuards, postDominanceGuards, sameReceiverGuards, sameScopeGuards, globalGuards []string
	var sanitizer string
	for _, cl := range cr.Rule.Clauses {
		if cl.Kind != "unless" {
			continue
		}
		switch ex := cl.Unless.(type) {
		case parser.EndpointCoveredBy:
			guards = append(guards, ex.Concept)
		case parser.DominatesCoveredBy:
			dominanceGuards = append(dominanceGuards, ex.Concept)
		case parser.PostDominatesCoveredBy:
			postDominanceGuards = append(postDominanceGuards, ex.Concept)
		case parser.SameReceiverCoveredBy:
			sameReceiverGuards = append(sameReceiverGuards, ex.Concept)
		case parser.SameScopeCoveredBy:
			sameScopeGuards = append(sameScopeGuards, ex.Concept)
		case parser.GlobalCoveredBy:
			globalGuards = append(globalGuards, ex.Concept)
		case parser.PathCoveredBy:
			sanitizer = ex.Concept
		}
	}

	var out []*findings.Finding
	// One finding per (rule, sink): a target sink reachable from N sources is ONE
	// issue, not N. Reporting per source→sink path inflates real-world scans when
	// many source reads converge on one target. Keep the highest-confidence
	// source as the representative witness; bySink maps sinkID → index in `out`.
	bySink := map[string]int{}
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
			ne = append(ne, findings.NegationEvidence{Clause: "path coveredBy " + sanitizer, Satisfied: false, Detail: detail})
		}
		// A character-filter on a still-LIVE path is, by definition, not provably sound
		// for this sink (a sound one would have killed the flow). Surface it as an
		// advisory note: the finding is a false positive IF that filter actually neutralizes.
		if wf := e.charFilterAdvisoryNote(fl.Path, excluded); wf != "" {
			ne = append(ne, findings.NegationEvidence{Clause: "char-filter advisory", Satisfied: false, Detail: wf})
		}
		// Unsound guards/sanitizers are Go-owned mechanics. They never kill the flow;
		// they annotate it as advisory-gated.
		ne = append(ne, e.neutralizerAdvisoryEvidence(fl.Path, fl.SinkID, sinkConcepts)...)
		suppressed := false
		for _, g := range guards {
			ok := e.endpointGuarded(fl.SinkID, g) || e.flowGuarded(fl.Path, g)
			detail := "no guard on sink"
			if ok {
				detail = "guard covers sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: "endpoint coveredBy " + g, Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		for _, g := range dominanceGuards {
			ok := e.dominatesGuarded(fl.SinkID, g)
			detail := "no dominating guard on sink"
			if ok {
				detail = "guard dominates sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("dominates", g), Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		for _, g := range postDominanceGuards {
			ok := e.postDominatesCovered(fl.SinkID, g)
			detail := "no post-dominating check on sink"
			if ok {
				detail = "check post-dominates sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("postDominates", g), Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		for _, g := range sameReceiverGuards {
			ok := e.sameReceiverGuarded(fl.SinkID, g)
			detail := "no same-receiver guard on sink"
			if ok {
				detail = "same-receiver guard covers sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("sameReceiver", g), Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		for _, g := range sameScopeGuards {
			ok := e.sameScopeGuarded(fl.SinkID, g)
			detail := "no same-scope guard on sink"
			if ok {
				detail = "same-scope guard covers sink"
			}
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("sameScope", g), Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		for _, g := range globalGuards {
			ok := e.globalGuarded(g)
			detail := "no global guard"
			if ok {
				detail = "global guard exists"
			}
			ne = append(ne, findings.NegationEvidence{Clause: v2CoverageClause("global", g), Satisfied: ok, Detail: detail})
			suppressed = suppressed || ok
		}
		if suppressed {
			continue
		}
		srcC := e.conceptIn(fl.SourceID, srcConcepts)
		snkC := e.conceptIn(fl.SinkID, sinkConcepts)
		conf := e.confBindings(bindingRef{nodeID: fl.SourceID, concept: srcC}, bindingRef{nodeID: fl.SinkID, concept: snkC})
		review := e.reviewConditions(fl.SinkID, snkC)
		if srcMeta := e.sourceConcept(srcC); srcMeta != nil && srcMeta.SourcePolicy == "caller_conditional" {
			n, _, _ := e.Store.GetNode(fl.SourceID)
			param := ""
			if n.ID != "" {
				param = n.Prop("name")
			}
			cond := strings.ReplaceAll(srcMeta.SourceCondition, "{param}", param)
			review = append(review, findings.ReviewCondition{
				Category:   srcMeta.SourceConditionCategory,
				Condition:  cond,
				Assumption: srcMeta.SourceAssumption,
				Confidence: firstNonEmpty(srcMeta.SourceConfidence, "medium"),
			})
			ceil := firstNonEmpty(srcMeta.SourceConfidence, "medium")
			if confOrder[conf] > confOrder[ceil] {
				conf = ceil
			}
		}
		f := &findings.Finding{
			RuleID:   e.ruleID(cr),
			Severity: cr.Severity,
			Bindings: []findings.Binding{
				{Name: "source", NodeID: fl.SourceID, Concept: srcC, Loc: e.loc(fl.SourceID), LabelProvenance: e.prov(fl.SourceID, srcC)},
				{Name: "sink", NodeID: fl.SinkID, Concept: snkC, Loc: e.loc(fl.SinkID), LabelProvenance: e.prov(fl.SinkID, snkC)},
			},
			Witness:          fl.Path,
			PathLocs:         e.pathLocs(fl.Path),
			WitnessKind:      "taint",
			NegationEvidence: ne,
			Confidence:       conf,
			Context:          e.crossDomainContext(fl.SinkID),
			ReviewConditions: review,
		}
		if idx, seen := bySink[fl.SinkID]; seen {
			// same sink already reported for this rule — keep whichever source gives the
			// higher-confidence witness (strict, so ties keep the earlier/deterministic one).
			if confOrder[f.Confidence] > confOrder[out[idx].Confidence] {
				out[idx] = f
			}
			continue
		}
		bySink[fl.SinkID] = len(out)
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

// pathLocs resolves each witness node to its loc, keeping order and dropping
// consecutive duplicates. Used to expose the files the taint path traverses
// (a patch frequently lands on a helper on the flow, not the source or sink site),
// so downstream localization can match the changed file.
func (e *Engine) pathLocs(path []string) []string {
	if len(path) == 0 {
		return nil
	}
	out := make([]string, 0, len(path))
	prev := ""
	for _, id := range path {
		l := e.loc(id)
		if l == "" || l == id {
			continue
		}
		if l != prev {
			out = append(out, l)
			prev = l
		}
	}
	return out
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
	if ls, ok := e.labelsByNode[nodeID]; ok {
		return ls
	}
	ls, _ := e.Store.Labels(nodeID)
	e.labelsByNode[nodeID] = ls
	return ls
}

func (e *Engine) nodesWithConcept(concept string) []string {
	if ids, ok := e.nodesByConcept[concept]; ok {
		return ids
	}
	ids, _ := e.Store.NodesWithConcept(concept)
	e.nodesByConcept[concept] = ids
	return ids
}

func (e *Engine) conceptsWithInternalConceptRole(role string) map[string]bool {
	if e == nil || e.Onto == nil || role == "" {
		return nil
	}
	if concepts, ok := e.conceptRole[role]; ok {
		return concepts
	}
	concepts := e.Onto.ConceptsWithInternalConceptRole(role)
	e.conceptRole[role] = concepts
	return concepts
}

func (e *Engine) conceptIn(nodeID string, set map[string]bool) string {
	for _, l := range e.labels(nodeID) {
		if set[l.Concept] {
			return l.Concept
		}
	}
	return ""
}

func (e *Engine) sourceConcept(concept string) *ontology.Concept {
	if concept == "" {
		return nil
	}
	if c, err := e.Onto.Get(concept); err == nil {
		return c
	}
	return nil
}

func (e *Engine) prov(nodeID, concept string) string {
	var fallback string
	bestPriority := -1
	for _, l := range e.labels(nodeID) {
		if l.Concept == concept && l.Provenance.Adapter != "" {
			fid := l.Provenance.Fidelity
			if fid == "" {
				fid = "resolved"
			}
			s := concept + " by " + l.Provenance.Adapter + "@" + fid
			priority := labelProvenancePriority(l)
			if fallback == "" || priority > bestPriority {
				fallback = s
				bestPriority = priority
			}
		}
	}
	return fallback
}

func labelProvenancePriority(l usg.Label) int {
	if l.Detail == nil {
		return 0
	}
	n, err := strconv.Atoi(l.Detail["provenance_priority"])
	if err != nil {
		return 0
	}
	return n
}

func (e *Engine) reviewConditions(nodeID, concept string) []findings.ReviewCondition {
	var out []findings.ReviewCondition
	seen := map[string]bool{}
	for _, l := range e.labels(nodeID) {
		if l.Concept != concept || l.Detail == nil {
			continue
		}
		cond := firstNonEmpty(l.Detail["review_condition"], l.Detail["condition"])
		if cond == "" {
			continue
		}
		conf := firstNonEmpty(l.Detail["review_confidence"], l.Provenance.Confidence)
		if conf == "" {
			conf = "medium"
		}
		ec := findings.ReviewCondition{
			Category:   firstNonEmpty(l.Detail["review_category"], l.Detail["category"]),
			Condition:  cond,
			Evidence:   firstNonEmpty(l.Detail["review_evidence"], l.Detail["evidence"]),
			Assumption: firstNonEmpty(l.Detail["review_assumption"], l.Detail["assumption"]),
			Confidence: conf,
		}
		key := ec.Category + "\x00" + ec.Condition + "\x00" + ec.Evidence + "\x00" + ec.Assumption
		if !seen[key] {
			seen[key] = true
			out = append(out, ec)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// fidelityCeil caps confidence by match fidelity (docs/07): a syntactic match
// (substring / bare method name, no receiver type) can be no better than medium;
// resolved/semantic matches may be high.
var fidelityCeil = map[string]int{"syntactic": 2, "resolved": 3, "semantic": 3}

type bindingRef struct {
	nodeID  string
	concept string
}

func (e *Engine) confBindings(refs ...bindingRef) string {
	best := 3
	for _, ref := range refs {
		eff := e.confConceptRank(ref.nodeID, ref.concept)
		if eff < best {
			best = eff
		}
	}
	return confidenceName(best)
}

func (e *Engine) confConcept(nodeID, concept string) string {
	return confidenceName(e.confConceptRank(nodeID, concept))
}

func (e *Engine) confConceptRank(nodeID, concept string) int {
	best := 3
	matched := false
	for _, l := range e.labels(nodeID) {
		if concept != "" && l.Concept != concept {
			continue
		}
		matched = true
		eff := labelConfidenceRank(l)
		if eff < best {
			best = eff
		}
	}
	if matched || concept == "" {
		return best
	}
	for _, l := range e.labels(nodeID) {
		eff := labelConfidenceRank(l)
		if eff < best {
			best = eff
		}
	}
	return best
}

func labelConfidenceRank(l usg.Label) int {
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
	return eff
}

func confidenceName(rank int) string {
	switch rank {
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
	sinkCFG := e.hasCFG(sinkID)
	// (1) an explicit PROTECTS/CHECKS edge (graph specs; a future endpoint-linking pass).
	for _, et := range []string{"PROTECTS", "CHECKS"} {
		edges, _ := e.Store.InEdges(sinkID, et)
		for _, ed := range edges {
			for _, l := range e.labels(ed.Src) {
				if !labelHasConcreteCoverage(l, control, "endpoint") {
					continue
				}
				if sinkCFG && e.hasCFG(ed.Src) {
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
	// endpoint coveredBy work on real code: adapters label the check with the control concept,
	// and the structured CFG lets us
	// connect it to exactly the sinks it covers (path-sensitive: a check in one branch does
	// not guard a sibling branch). Requires CFG metadata, so it never fires on metadata-free
	// graphs — those rely on the explicit edge above.
	guards := e.nodesWithConcept(control)
	for _, gid := range guards {
		if !nodeHasConcreteCoverage(e.labels(gid), control, "endpoint") {
			continue
		}
		if gid != sinkID && e.sameFunctionContextGuarded(gid, sinkID) {
			return true
		}
	}
	if sinkCFG {
		for _, gid := range guards {
			if !nodeHasConcreteCoverage(e.labels(gid), control, "endpoint") {
				continue
			}
			if gid != sinkID && e.hasCFG(gid) && solvers.Dominates(e.Store, gid, sinkID) {
				return true
			}
		}
		for _, gid := range guards {
			if !nodeHasConcreteCoverage(e.labels(gid), control, "endpoint") {
				continue
			}
			if gid != sinkID && e.preflightLoopGuarded(gid, sinkID) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) sameFunctionContextGuarded(guardID, sinkID string) bool {
	guard, ok1, _ := e.Store.GetNode(guardID)
	sink, ok2, _ := e.Store.GetNode(sinkID)
	if !ok1 || !ok2 {
		return false
	}
	if guard.Prop("callee_path") != "analysis.function.context" {
		return false
	}
	return functionScopeKey(guard) != "" && functionScopeKey(guard) == functionScopeKey(sink)
}

func functionScopeKey(n usg.Node) string {
	scope := n.Scope
	if scope == "" {
		scope = n.Prop("region")
	}
	if at := strings.IndexByte(scope, '@'); at >= 0 {
		scope = scope[:at]
	}
	parts := strings.Split(scope, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "fn") {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return ""
}

func (e *Engine) sameReceiverGuarded(sinkID, control string) bool {
	sink, ok, _ := e.Store.GetNode(sinkID)
	if !ok {
		return false
	}
	targets := e.conceptsWithInternalConceptRole(ontology.InternalConceptRoleSameReceiverTarget)
	if len(targets) == 0 || !nodeHasAnyConcept(e.labels(sinkID), targets) {
		return false
	}
	guards := e.conceptsWithInternalConceptRole(ontology.InternalConceptRoleSameReceiverGuard)
	if len(guards) == 0 || !guards[control] {
		return false
	}
	sinkRecv := receiverPrefix(sink.Prop("callee_path"))
	if recvID := sink.Prop("recv"); recvID != "" && nodeHasConcreteCoverage(e.labels(recvID), control, "sameReceiver") {
		return true
	}
	if sinkRecv == "" {
		return false
	}
	return e.sameReceiverGuardReceivers(control)[sinkRecv]
}

func (e *Engine) dominatesGuarded(targetID, control string) bool {
	if !e.hasCFG(targetID) {
		return false
	}
	for _, gid := range e.dominanceGuardCandidates(control) {
		if gid != targetID && solvers.Dominates(e.Store, gid, targetID) {
			return true
		}
	}
	return false
}

func (e *Engine) dominanceGuardCandidates(control string) []string {
	if ids, ok := e.dominanceGuards[control]; ok {
		return ids
	}
	var out []string
	for _, gid := range e.nodesWithConcept(control) {
		if !e.hasCFG(gid) || !nodeHasConcreteCoverage(e.labels(gid), control, "dominates") {
			continue
		}
		out = append(out, gid)
	}
	e.dominanceGuards[control] = out
	return out
}

func (e *Engine) sameReceiverGuardReceivers(control string) map[string]bool {
	if receivers, ok := e.sameReceiverGuards[control]; ok {
		return receivers
	}
	receivers := map[string]bool{}
	for _, gid := range e.nodesWithConcept(control) {
		if !nodeHasConcreteCoverage(e.labels(gid), control, "sameReceiver") {
			continue
		}
		guard, ok, _ := e.Store.GetNode(gid)
		if !ok {
			continue
		}
		if recv := receiverPrefix(guard.Prop("callee_path")); recv != "" {
			receivers[recv] = true
		}
	}
	e.sameReceiverGuards[control] = receivers
	return receivers
}

func (e *Engine) sameScopeGuarded(targetID, control string) bool {
	target, ok, _ := e.Store.GetNode(targetID)
	if !ok {
		return false
	}
	targetScope := lexicalScopeKey(target)
	if targetScope == "" {
		return false
	}
	for scope := range e.sameScopeGuardScopes(control) {
		if lexicalScopeCovers(scope, targetScope) {
			return true
		}
	}
	return false
}

func (e *Engine) sameScopeGuardScopes(control string) map[string]bool {
	if scopes, ok := e.sameScopeGuards[control]; ok {
		return scopes
	}
	scopes := map[string]bool{}
	for _, gid := range e.nodesWithConcept(control) {
		if !nodeHasConcreteCoverage(e.labels(gid), control, "sameScope") {
			continue
		}
		guard, ok, _ := e.Store.GetNode(gid)
		if !ok {
			continue
		}
		if scope := lexicalScopeKey(guard); scope != "" {
			scopes[scope] = true
		}
	}
	e.sameScopeGuards[control] = scopes
	return scopes
}

func (e *Engine) globalGuarded(control string) bool {
	if ok, cached := e.globalGuards[control]; cached {
		return ok
	}
	for _, id := range e.nodesWithConcept(control) {
		for _, l := range e.labels(id) {
			if l.Concept == control && !labelIsAdvisory(l) && l.Detail["coverage"] == "global" {
				e.globalGuards[control] = true
				return true
			}
		}
	}
	e.globalGuards[control] = false
	return false
}

func lexicalScopeKey(n usg.Node) string {
	scope := n.Scope
	if scope == "" {
		scope = n.Prop("scope")
	}
	if scope == "" {
		scope = n.Prop("region")
	}
	if scope == "" {
		scope = n.Region
	}
	if at := strings.IndexByte(scope, '@'); at >= 0 {
		scope = scope[:at]
	}
	return strings.TrimRight(scope, "/")
}

func lexicalScopeCovers(guardScope, targetScope string) bool {
	if guardScope == "" || targetScope == "" {
		return false
	}
	return targetScope == guardScope || strings.HasPrefix(targetScope, guardScope+"/")
}

func nodeHasAnyConcept(labels []usg.Label, concepts map[string]bool) bool {
	for _, l := range labels {
		if concepts[l.Concept] {
			return true
		}
	}
	return false
}

func labelIsAdvisory(l usg.Label) bool {
	return l.Detail != nil && l.Detail["advisory"] == "true"
}

func nodeHasConcreteConcept(labels []usg.Label, concept string) bool {
	for _, l := range labels {
		if l.Concept == concept && !labelIsAdvisory(l) {
			return true
		}
	}
	return false
}

func labelHasConcreteCoverage(l usg.Label, concept, coverage string) bool {
	return l.Concept == concept && !labelIsAdvisory(l) && l.Detail != nil && l.Detail["coverage"] == coverage
}

func nodeHasConcreteCoverage(labels []usg.Label, concept, coverage string) bool {
	for _, l := range labels {
		if labelHasConcreteCoverage(l, concept, coverage) {
			return true
		}
	}
	return false
}

func (e *Engine) nodeHasAdvisoryConceptOnly(nodeID, concept string) bool {
	seen := false
	for _, l := range e.labels(nodeID) {
		if l.Concept != concept {
			continue
		}
		if !labelIsAdvisory(l) {
			return false
		}
		seen = true
	}
	return seen
}

func receiverPrefix(path string) string {
	i := strings.LastIndexByte(path, '.')
	if i <= 0 {
		return ""
	}
	return path[:i]
}

func nodeHasConcept(labels []usg.Label, concept string) bool {
	for _, l := range labels {
		if l.Concept == concept {
			return true
		}
	}
	return false
}

// flowGuarded reports whether a guard consumes the tainted value and dominates
// a later node on this same source-to-sink path. This covers the common shape:
//
//	v := source()
//	if !validate(v) { return }
//	wrapper(v) // endpoint is inside wrapper
//
// The guard does not dominate the callee-internal sink, so endpointGuarded cannot
// see it. It does dominate the path boundary that forwards the checked value,
// which is enough for guard-style allowlist validators.
func (e *Engine) flowGuarded(path []string, control string) bool {
	if len(path) == 0 {
		return false
	}
	for i, pid := range path {
		if i < len(path)-1 && nodeHasConcreteCoverage(e.labels(pid), control, "endpoint") {
			return true
		}
		for _, gid := range e.flowGuardCandidates(pid, control) {
			if gid == pid || !e.hasCFG(gid) {
				continue
			}
			for _, later := range path[i+1:] {
				if later != gid && e.hasCFG(later) && solvers.Dominates(e.Store, gid, later) {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) flowGuardCandidates(nodeID, control string) []string {
	key := control + "\x00" + nodeID
	if out, ok := e.flowGuards[key]; ok {
		return out
	}
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] || !nodeHasConcreteCoverage(e.labels(id), control, "endpoint") {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	edges, _ := e.Store.OutEdges(nodeID, "FLOWS")
	for _, ed := range edges {
		add(ed.Dst)
		midEdges, _ := e.Store.OutEdges(ed.Dst, "FLOWS")
		for _, mid := range midEdges {
			add(mid.Dst)
		}
	}
	e.flowGuards[key] = out
	return out
}

// preflightLoopGuarded recognizes "validate every item, then run one bulk operation"
// shapes. The guard itself does not dominate a post-loop sink because a loop body may
// execute zero times, but for bulk APIs a guard in the loop body can still be the
// program's preflight validation. Adapter data decides which calls are real guards;
// this helper only models the structured-control relation.
func (e *Engine) preflightLoopGuarded(guardID, sinkID string) bool {
	gn, ok1, _ := e.Store.GetNode(guardID)
	sn, ok2, _ := e.Store.GetNode(sinkID)
	if !ok1 || !ok2 {
		return false
	}
	parent, ok := nearestLoopParent(gn.Prop("region"))
	if !ok {
		return false
	}
	sinkRegion := sn.Prop("region")
	if sinkRegion != parent && !strings.HasPrefix(sinkRegion, parent+"/") {
		return false
	}
	return solvers.Reaches(e.Store, guardID, sinkID)
}

// postDominatesCovered reports whether a concrete check runs on every path from
// the candidate to function exit. Frontends without CFG metadata retain the
// v2-authored conservative fallback: a concrete postDominates check covers.
func (e *Engine) postDominatesCovered(candidateID, control string) bool {
	candidateCFG := e.hasCFG(candidateID)
	checks := e.nodesWithConcept(control)
	for _, checkID := range checks {
		if !nodeHasConcreteCoverage(e.labels(checkID), control, "postDominates") {
			continue
		}
		if checkID == candidateID {
			continue
		}
		if candidateCFG && e.hasCFG(checkID) {
			if solvers.PostDominates(e.Store, checkID, candidateID) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

func nearestLoopParent(region string) (string, bool) {
	parts := strings.Split(region, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasPrefix(parts[i], "loop") {
			parent := strings.Join(parts[:i], "/")
			if parent == "" {
				parent = "/"
			}
			return parent, true
		}
	}
	return "", false
}

// hasCFG reports whether a node carries structured-CFG metadata (a region tag).
func hasCFG(store usg.Store, id string) bool {
	if n, ok, _ := store.GetNode(id); ok {
		return n.Prop("region") != ""
	}
	return false
}

func (e *Engine) hasCFG(id string) bool {
	if v, ok := e.cfg[id]; ok {
		return v
	}
	v := hasCFG(e.Store, id)
	e.cfg[id] = v
	return v
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

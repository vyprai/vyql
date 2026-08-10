// Package review derives the review flags a scan reports alongside its findings: the
// conditions worth a human's attention, deduplicated, ordered, and paired with the checks
// that relate to them.
//
// It is result-shaping policy and it lived in cmd/vyql, which split policy ownership down
// the middle -- resultpolicy owned the lifecycle declaration while the display declaration,
// same file format and same validation shape, was parsed by the command.
package review

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

type Item struct {
	Category     string         `json:"category"`
	Kind         string         `json:"kind"`
	Concept      string         `json:"concept"`
	NodeID       string         `json:"node_id"`
	Type         string         `json:"type"`
	Loc          string         `json:"loc,omitempty"`
	Region       string         `json:"region,omitempty"`
	Call         string         `json:"call,omitempty"`
	Expected     []string       `json:"expected_controls,omitempty"`
	Review       string         `json:"review,omitempty"`
	Provenance   string         `json:"provenance,omitempty"`
	NearbyChecks []RelatedCheck `json:"nearby_checks,omitempty"`
}

type RelatedCheck struct {
	Concept    string `json:"concept"`
	Loc        string `json:"loc,omitempty"`
	Call       string `json:"call,omitempty"`
	Evidence   string `json:"evidence"`
	Provenance string `json:"provenance,omitempty"`
}

type ConceptInfo struct {
	category string
	kind     string
	expected []string
	review   string
}

type DisplayPolicy struct {
	scanAll             []string
	flagSort            []string
	includeNearbyChecks bool
	nearbyCheckLimit    int
}

type cachedConcepts struct {
	concepts  map[string]ConceptInfo
	display   DisplayPolicy
	lifecycle resultpolicy.LifecyclePolicy
	err       error
}

var conceptsCache sync.Map // map[data root]cachedConcepts

func loadConfig() (map[string]ConceptInfo, DisplayPolicy, resultpolicy.LifecyclePolicy, error) {
	root := datadir.Root()
	if cached, ok := conceptsCache.Load(root); ok {
		res := cached.(cachedConcepts)
		return res.concepts, res.display, res.lifecycle, res.err
	}
	concepts, display, lifecycle, err := loadConfigFromRoot(root)
	res := cachedConcepts{concepts: concepts, display: display, lifecycle: lifecycle, err: err}
	actual, _ := conceptsCache.LoadOrStore(root, res)
	actualRes := actual.(cachedConcepts)
	return actualRes.concepts, actualRes.display, actualRes.lifecycle, actualRes.err
}

func loadConfigFromRoot(dataRoot string) (map[string]ConceptInfo, DisplayPolicy, resultpolicy.LifecyclePolicy, error) {
	out := map[string]ConceptInfo{}
	var sources []parser.V2DefinitionSource
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/concepts"); err != nil {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/threatkinds"); err != nil {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "policies"); err != nil {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	selected := map[string]bool{}
	beforeReview := len(sources)
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "review"); err != nil {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	for _, source := range sources {
		if strings.HasPrefix(source.Name, "policies/") {
			selected[source.Name] = true
		}
	}
	for _, source := range sources[beforeReview:] {
		selected[source.Name] = true
	}
	decls, err := parser.ParseV2DefinitionSourcesSelected(sources, func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
	if err != nil {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	var display DisplayPolicy
	var lifecycle resultpolicy.LifecyclePolicy
	hasDisplay := false
	hasLifecycle := false
	for _, d := range decls {
		switch x := d.(type) {
		case *parser.ReviewDecl:
			out[x.Concept] = ConceptInfo{
				category: fieldString(x.Fields, "category"),
				kind:     fieldString(x.Fields, "kind"),
				expected: fieldList(x.Fields, "expected"),
				review:   fieldString(x.Fields, "text"),
			}
		case *parser.V2PolicyDecl:
			if x.Name != "default" {
				continue
			}
			switch x.Kind {
			case "display":
				policy, err := DisplayPolicyFromDecl(x)
				if err != nil {
					return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
				}
				display = policy
				hasDisplay = true
			case "resultLifecycle":
				policy, err := resultpolicy.LifecyclePolicyFromDecl(x)
				if err != nil {
					return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
				}
				lifecycle = policy
				hasLifecycle = true
			}
		}
	}
	if !hasDisplay {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, fmt.Errorf("missing policy display default")
	}
	if !hasLifecycle {
		return nil, DisplayPolicy{}, resultpolicy.LifecyclePolicy{}, fmt.Errorf("missing policy resultLifecycle default")
	}
	return out, display, lifecycle, nil
}

func appendV2DefinitionSourcesFromRoot(dst *[]parser.V2DefinitionSource, dataRoot, rel string) error {
	root := filepath.Join(dataRoot, filepath.FromSlash(rel))
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(dataRoot, path)
		if err != nil {
			name = path
		}
		*dst = append(*dst, parser.V2DefinitionSource{Name: filepath.ToSlash(name), Source: string(data)})
		return nil
	})
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func fieldString(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

func fieldList(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return v
	case string:
		return []string{v}
	}
	return nil
}

func DisplayPolicyFromDecl(p *parser.V2PolicyDecl) (DisplayPolicy, error) {
	out := DisplayPolicy{}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			continue
		}
		switch item.Key[0] {
		case "scanAll":
			out.scanAll = policyStringList(item.Value)
			if len(out.scanAll) == 0 {
				return DisplayPolicy{}, fmt.Errorf("policy display default: scanAll must be a non-empty string list")
			}
		case "flagSort":
			out.flagSort = policyStringList(item.Value)
			if len(out.flagSort) == 0 {
				return DisplayPolicy{}, fmt.Errorf("policy display default: flagSort must be a non-empty string list")
			}
		case "includeNearbyChecks":
			v, ok := policyBool(item.Value)
			if !ok {
				return DisplayPolicy{}, fmt.Errorf("policy display default: includeNearbyChecks must be boolean")
			}
			out.includeNearbyChecks = v
		case "nearbyCheckLimit":
			v, ok := policyInt(item.Value)
			if !ok {
				return DisplayPolicy{}, fmt.Errorf("policy display default: nearbyCheckLimit must be an integer")
			}
			out.nearbyCheckLimit = v
		}
	}
	if len(out.flagSort) == 0 {
		return DisplayPolicy{}, fmt.Errorf("policy display default: missing flagSort")
	}
	if len(out.scanAll) == 0 {
		return DisplayPolicy{}, fmt.Errorf("policy display default: missing scanAll")
	}
	return out, nil
}

func policyStringList(raw any) []string {
	xs, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		switch v := x.(type) {
		case string:
			out = append(out, v)
		case parser.V2RefExpr:
			out = append(out, v.Name)
		}
	}
	return out
}

func policyBool(raw any) (bool, bool) {
	lit, ok := raw.(parser.V2LiteralExpr)
	if !ok {
		return false, false
	}
	v, ok := lit.Value.(bool)
	return v, ok
}

func policyInt(raw any) (int, bool) {
	lit, ok := raw.(parser.V2LiteralExpr)
	if !ok {
		return 0, false
	}
	v, ok := lit.Value.(int)
	return v, ok
}

func Collect(g usg.Store) []Item {
	reviewConcepts, display, lifecycle, err := loadConfig()
	if err != nil {
		return nil
	}
	return CollectWithPolicy(g, reviewConcepts, display, lifecycle)
}

func Filter(rows []Item, category, kind, loc string) []Item {
	category = strings.TrimSpace(category)
	kind = strings.TrimSpace(kind)
	loc = strings.TrimSpace(loc)
	if (category == "" || category == "all") && (kind == "" || kind == "all") && loc == "" {
		return rows
	}
	// A fresh slice, not rows[:0]: filtering in place overwrites the caller's backing array,
	// so a caller that kept the unfiltered slice would find it silently rewritten.
	filtered := make([]Item, 0, len(rows))
	for _, r := range rows {
		if category != "" && category != "all" && r.Category != category {
			continue
		}
		if kind != "" && kind != "all" && r.Kind != kind {
			continue
		}
		if loc != "" && !strings.Contains(r.Loc, loc) {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

func CollectWithPolicy(g usg.Store, reviewConcepts map[string]ConceptInfo, display DisplayPolicy, lifecycle resultpolicy.LifecyclePolicy) []Item {
	if g == nil {
		return []Item{}
	}
	nodes, _ := g.AllNodes()
	byID := map[string]usg.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	out := []Item{}
	seen := map[string]bool{}
	identity := resultpolicy.MustDefaultIdentity()
	for _, n := range nodes {
		labels, _ := g.Labels(n.ID)
		for _, l := range labels {
			info, ok := reviewConcepts[l.Concept]
			if !lifecycle.FlagWhenIssue(ok) {
				continue
			}
			key := dedupKey(identity, l.Concept, n)
			if seen[key] {
				continue
			}
			seen[key] = true
			cp := Item{
				Category:   info.category,
				Kind:       info.kind,
				Concept:    l.Concept,
				NodeID:     n.ID,
				Type:       n.Type,
				Loc:        n.Prop("loc"),
				Region:     n.Prop("region"),
				Call:       n.CalleeKey(),
				Expected:   append([]string(nil), info.expected...),
				Review:     info.review,
				Provenance: labelProvenance(l),
			}
			if info.kind == "target" && display.includeNearbyChecks {
				cp.NearbyChecks = relatedChecks(g, byID, n.ID, info.expected, reviewConcepts, display.nearbyCheckLimit, lifecycle)
			}
			out = append(out, cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return itemOrder(out[i], display.flagSort) < itemOrder(out[j], display.flagSort)
	})
	return out
}

func dedupKey(identity resultpolicy.IdentityPolicy, concept string, n usg.Node) string {
	loc := n.Prop("loc")
	if loc == "" {
		loc = n.ID
	}
	return identity.FlagKeyFor(resultpolicy.FlagIdentity{
		Concept:    concept,
		Location:   loc,
		CallPath:   n.Prop("path"),
		CallMethod: n.Prop("method"),
		NodeID:     n.ID,
	})
}

func relatedChecks(g usg.Store, nodes map[string]usg.Node, targetID string, expected []string, reviewConcepts map[string]ConceptInfo, limit int, lifecycle resultpolicy.LifecyclePolicy) []RelatedCheck {
	want := map[string]bool{}
	for _, c := range expected {
		want[c] = true
	}
	if len(want) == 0 {
		for c, info := range reviewConcepts {
			if info.kind == "check" {
				want[c] = true
			}
		}
	}
	type keyed struct {
		key string
		row RelatedCheck
	}
	seen := map[string]bool{}
	var rows []keyed
	add := func(nodeID, concept, evidence string, l usg.Label) {
		n, ok := nodes[nodeID]
		if !ok || nodeID == targetID {
			return
		}
		_, hasReview := reviewConcepts[concept]
		if !lifecycle.CheckWhen(hasReview, false) {
			return
		}
		key := nodeID + "\x00" + concept + "\x00" + evidence
		if seen[key] {
			return
		}
		seen[key] = true
		row := RelatedCheck{
			Concept:    concept,
			Loc:        n.Prop("loc"),
			Call:       n.CalleeKey(),
			Evidence:   evidence,
			Provenance: labelProvenance(l),
		}
		rows = append(rows, keyed{key: relatedOrder(row), row: row})
	}

	for _, et := range []string{"PROTECTS", "CHECKS"} {
		edges, _ := g.InEdges(targetID, et)
		for _, e := range edges {
			for _, l := range labelsOfConcepts(g, e.Src, want) {
				add(e.Src, l.Concept, strings.ToLower(et)+" edge", l)
			}
		}
	}
	for concept := range want {
		ids, _ := g.NodesWithConcept(concept)
		for _, id := range ids {
			labels := labelsOfConcepts(g, id, map[string]bool{concept: true})
			if len(labels) == 0 {
				continue
			}
			if solvers.Dominates(g, id, targetID) {
				add(id, concept, "dominates target", labels[0])
			} else if precedesInSameFunction(nodes[id], nodes[targetID]) {
				add(id, concept, "same function before target", labels[0])
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]RelatedCheck, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.row)
	}
	return out
}

func labelsOfConcepts(g usg.Store, nodeID string, want map[string]bool) []usg.Label {
	labels, _ := g.Labels(nodeID)
	var out []usg.Label
	for _, l := range labels {
		if want[l.Concept] {
			out = append(out, l)
		}
	}
	return out
}

func labelProvenance(l usg.Label) string {
	var parts []string
	if l.Provenance.Applicator != "" {
		parts = append(parts, l.Provenance.Applicator)
	}
	if l.Provenance.Fidelity != "" {
		parts = append(parts, l.Provenance.Fidelity)
	}
	if l.Provenance.Confidence != "" {
		parts = append(parts, "confidence="+l.Provenance.Confidence)
	}
	return strings.Join(parts, "/")
}

func precedesInSameFunction(check, target usg.Node) bool {
	cr, tr := check.Prop("region"), target.Prop("region")
	if cr == "" || tr == "" {
		return false
	}
	croot, troot := functionRegionRoot(cr), functionRegionRoot(tr)
	if croot == "" || croot != troot {
		return false
	}
	return check.SortOrder() < target.SortOrder()
}

func functionRegionRoot(region string) string {
	if region == "" {
		return ""
	}
	parts := strings.Split(region, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "fn") {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return region
}

func itemOrder(r Item, fields []string) string {
	if len(fields) == 0 {
		fields = []string{"location", "category", "kind", "concept", "call", "nodeID"}
	}
	parts := make([]string, 0, len(fields)+3)
	for _, field := range fields {
		switch field {
		case "severity":
			parts = append(parts, "")
		case "category":
			parts = append(parts, r.Category)
		case "kind":
			parts = append(parts, r.Kind)
		case "location", "loc":
			parts = append(parts, r.Loc)
		case "concept":
			parts = append(parts, r.Concept)
		case "call":
			parts = append(parts, r.Call)
		case "nodeID", "node":
			parts = append(parts, r.NodeID)
		}
	}
	parts = append(parts, r.Loc, r.Category, r.Kind, r.Concept, r.Call, r.NodeID)
	return strings.Join(parts, "\x00")
}

func relatedOrder(r RelatedCheck) string {
	return r.Loc + "\x00" + r.Concept + "\x00" + r.Call + "\x00" + r.Evidence
}

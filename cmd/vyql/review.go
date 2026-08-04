package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/resultpolicy"
	"github.com/vyprai/vyql/solvers"
	"github.com/vyprai/vyql/usg"
)

type reviewItem struct {
	Category     string               `json:"category"`
	Kind         string               `json:"kind"`
	Concept      string               `json:"concept"`
	NodeID       string               `json:"node_id"`
	Type         string               `json:"type"`
	Loc          string               `json:"loc,omitempty"`
	Region       string               `json:"region,omitempty"`
	Call         string               `json:"call,omitempty"`
	Expected     []string             `json:"expected_controls,omitempty"`
	Review       string               `json:"review,omitempty"`
	Provenance   string               `json:"provenance,omitempty"`
	NearbyChecks []reviewRelatedCheck `json:"nearby_checks,omitempty"`
}

type reviewRelatedCheck struct {
	Concept    string `json:"concept"`
	Loc        string `json:"loc,omitempty"`
	Call       string `json:"call,omitempty"`
	Evidence   string `json:"evidence"`
	Provenance string `json:"provenance,omitempty"`
}

type reviewConceptInfo struct {
	category string
	kind     string
	expected []string
	review   string
}

type reviewDisplayPolicy struct {
	scanAll             []string
	flagSort            []string
	includeNearbyChecks bool
	nearbyCheckLimit    int
}

type cachedReviewConcepts struct {
	concepts  map[string]reviewConceptInfo
	display   reviewDisplayPolicy
	lifecycle resultpolicy.LifecyclePolicy
	err       error
}

var reviewConceptsCache sync.Map // map[data root]cachedReviewConcepts

func loadReviewConfig() (map[string]reviewConceptInfo, reviewDisplayPolicy, resultpolicy.LifecyclePolicy, error) {
	root := datadir.Root()
	if cached, ok := reviewConceptsCache.Load(root); ok {
		res := cached.(cachedReviewConcepts)
		return res.concepts, res.display, res.lifecycle, res.err
	}
	concepts, display, lifecycle, err := loadReviewConfigFromRoot(root)
	res := cachedReviewConcepts{concepts: concepts, display: display, lifecycle: lifecycle, err: err}
	actual, _ := reviewConceptsCache.LoadOrStore(root, res)
	actualRes := actual.(cachedReviewConcepts)
	return actualRes.concepts, actualRes.display, actualRes.lifecycle, actualRes.err
}

func loadReviewConfigFromRoot(dataRoot string) (map[string]reviewConceptInfo, reviewDisplayPolicy, resultpolicy.LifecyclePolicy, error) {
	out := map[string]reviewConceptInfo{}
	var sources []parser.V2DefinitionSource
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/concepts"); err != nil {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/threatkinds"); err != nil {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "policies"); err != nil {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	selected := map[string]bool{}
	beforeReview := len(sources)
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "review"); err != nil {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
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
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
	}
	var display reviewDisplayPolicy
	var lifecycle resultpolicy.LifecyclePolicy
	hasDisplay := false
	hasLifecycle := false
	for _, d := range decls {
		switch x := d.(type) {
		case *parser.ReviewDecl:
			out[x.Concept] = reviewConceptInfo{
				category: reviewString(x.Fields, "category"),
				kind:     reviewString(x.Fields, "kind"),
				expected: reviewList(x.Fields, "expected"),
				review:   reviewString(x.Fields, "text"),
			}
		case *parser.V2PolicyDecl:
			if x.Name != "default" {
				continue
			}
			switch x.Kind {
			case "display":
				policy, err := reviewDisplayPolicyFromDecl(x)
				if err != nil {
					return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
				}
				display = policy
				hasDisplay = true
			case "resultLifecycle":
				policy, err := resultpolicy.LifecyclePolicyFromDecl(x)
				if err != nil {
					return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, err
				}
				lifecycle = policy
				hasLifecycle = true
			}
		}
	}
	if !hasDisplay {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, fmt.Errorf("missing policy display default")
	}
	if !hasLifecycle {
		return nil, reviewDisplayPolicy{}, resultpolicy.LifecyclePolicy{}, fmt.Errorf("missing policy resultLifecycle default")
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

func reviewString(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

func reviewList(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return v
	case string:
		return []string{v}
	}
	return nil
}

func reviewDisplayPolicyFromDecl(p *parser.V2PolicyDecl) (reviewDisplayPolicy, error) {
	out := reviewDisplayPolicy{}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			continue
		}
		switch item.Key[0] {
		case "scanAll":
			out.scanAll = reviewPolicyStringList(item.Value)
			if len(out.scanAll) == 0 {
				return reviewDisplayPolicy{}, fmt.Errorf("policy display default: scanAll must be a non-empty string list")
			}
		case "flagSort":
			out.flagSort = reviewPolicyStringList(item.Value)
			if len(out.flagSort) == 0 {
				return reviewDisplayPolicy{}, fmt.Errorf("policy display default: flagSort must be a non-empty string list")
			}
		case "includeNearbyChecks":
			v, ok := reviewPolicyBool(item.Value)
			if !ok {
				return reviewDisplayPolicy{}, fmt.Errorf("policy display default: includeNearbyChecks must be boolean")
			}
			out.includeNearbyChecks = v
		case "nearbyCheckLimit":
			v, ok := reviewPolicyInt(item.Value)
			if !ok {
				return reviewDisplayPolicy{}, fmt.Errorf("policy display default: nearbyCheckLimit must be an integer")
			}
			out.nearbyCheckLimit = v
		}
	}
	if len(out.flagSort) == 0 {
		return reviewDisplayPolicy{}, fmt.Errorf("policy display default: missing flagSort")
	}
	if len(out.scanAll) == 0 {
		return reviewDisplayPolicy{}, fmt.Errorf("policy display default: missing scanAll")
	}
	return out, nil
}

func reviewPolicyStringList(raw any) []string {
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

func reviewPolicyBool(raw any) (bool, bool) {
	lit, ok := raw.(parser.V2LiteralExpr)
	if !ok {
		return false, false
	}
	v, ok := lit.Value.(bool)
	return v, ok
}

func reviewPolicyInt(raw any) (int, bool) {
	lit, ok := raw.(parser.V2LiteralExpr)
	if !ok {
		return 0, false
	}
	v, ok := lit.Value.(int)
	return v, ok
}

func collectReviewItems(g usg.Store) []reviewItem {
	reviewConcepts, display, lifecycle, err := loadReviewConfig()
	if err != nil {
		return nil
	}
	return collectReviewItemsWithPolicy(g, reviewConcepts, display, lifecycle)
}

func filterReviewItems(rows []reviewItem, category, kind, loc string) []reviewItem {
	category = strings.TrimSpace(category)
	kind = strings.TrimSpace(kind)
	loc = strings.TrimSpace(loc)
	if (category == "" || category == "all") && (kind == "" || kind == "all") && loc == "" {
		return rows
	}
	filtered := rows[:0]
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

func collectReviewItemsWithPolicy(g usg.Store, reviewConcepts map[string]reviewConceptInfo, display reviewDisplayPolicy, lifecycle resultpolicy.LifecyclePolicy) []reviewItem {
	if g == nil {
		return []reviewItem{}
	}
	nodes, _ := g.AllNodes()
	byID := map[string]usg.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	out := []reviewItem{}
	seen := map[string]bool{}
	identity := resultpolicy.MustDefaultIdentity()
	for _, n := range nodes {
		labels, _ := g.Labels(n.ID)
		for _, l := range labels {
			info, ok := reviewConcepts[l.Concept]
			if !lifecycle.FlagWhenIssue(ok) {
				continue
			}
			key := reviewDedupKey(identity, l.Concept, n)
			if seen[key] {
				continue
			}
			seen[key] = true
			cp := reviewItem{
				Category:   info.category,
				Kind:       info.kind,
				Concept:    l.Concept,
				NodeID:     n.ID,
				Type:       n.Type,
				Loc:        n.Prop("loc"),
				Region:     n.Prop("region"),
				Call:       calleeKey(n),
				Expected:   append([]string(nil), info.expected...),
				Review:     info.review,
				Provenance: labelProvenance(l),
			}
			if info.kind == "target" && display.includeNearbyChecks {
				cp.NearbyChecks = relatedReviewChecks(g, byID, n.ID, info.expected, reviewConcepts, display.nearbyCheckLimit, lifecycle)
			}
			out = append(out, cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return reviewItemOrder(out[i], display.flagSort) < reviewItemOrder(out[j], display.flagSort)
	})
	return out
}

func reviewDedupKey(identity resultpolicy.IdentityPolicy, concept string, n usg.Node) string {
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

func relatedReviewChecks(g usg.Store, nodes map[string]usg.Node, targetID string, expected []string, reviewConcepts map[string]reviewConceptInfo, limit int, lifecycle resultpolicy.LifecyclePolicy) []reviewRelatedCheck {
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
		row reviewRelatedCheck
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
		row := reviewRelatedCheck{
			Concept:    concept,
			Loc:        n.Prop("loc"),
			Call:       calleeKey(n),
			Evidence:   evidence,
			Provenance: labelProvenance(l),
		}
		rows = append(rows, keyed{key: relatedCheckOrder(row), row: row})
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
	out := make([]reviewRelatedCheck, 0, len(rows))
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
	return nodeOrder(check) < nodeOrder(target)
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

func reviewItemOrder(r reviewItem, fields []string) string {
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

func relatedCheckOrder(r reviewRelatedCheck) string {
	return r.Loc + "\x00" + r.Concept + "\x00" + r.Call + "\x00" + r.Evidence
}

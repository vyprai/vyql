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

type cachedReviewConcepts struct {
	concepts map[string]reviewConceptInfo
	err      error
}

var reviewConceptsCache sync.Map // map[data root]cachedReviewConcepts

func loadReviewConcepts() (map[string]reviewConceptInfo, error) {
	root := datadir.Root()
	if cached, ok := reviewConceptsCache.Load(root); ok {
		res := cached.(cachedReviewConcepts)
		return res.concepts, res.err
	}
	concepts, err := loadReviewConceptsFromRoot(root)
	res := cachedReviewConcepts{concepts: concepts, err: err}
	actual, _ := reviewConceptsCache.LoadOrStore(root, res)
	actualRes := actual.(cachedReviewConcepts)
	return actualRes.concepts, actualRes.err
}

func loadReviewConceptsFromRoot(dataRoot string) (map[string]reviewConceptInfo, error) {
	out := map[string]reviewConceptInfo{}
	var sources []parser.V2DefinitionSource
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/concepts"); err != nil {
		return nil, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "ontology/threatkinds"); err != nil {
		return nil, err
	}
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "mechanics"); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	beforeReview := len(sources)
	if err := appendV2DefinitionSourcesFromRoot(&sources, dataRoot, "review"); err != nil {
		return nil, err
	}
	if len(sources) == beforeReview {
		return out, nil
	}
	for _, source := range sources[beforeReview:] {
		selected[source.Name] = true
	}
	decls, err := parser.ParseV2DefinitionSourcesSelected(sources, func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
	if err != nil {
		return nil, err
	}
	for _, d := range decls {
		rd, ok := d.(*parser.ReviewDecl)
		if !ok {
			continue
		}
		out[rd.Concept] = reviewConceptInfo{
			category: reviewString(rd.Fields, "category"),
			kind:     reviewString(rd.Fields, "kind"),
			expected: reviewList(rd.Fields, "expected"),
			review:   reviewString(rd.Fields, "text"),
		}
	}
	return out, nil
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

func collectReviewItems(g usg.Store) []reviewItem {
	reviewConcepts, err := loadReviewConcepts()
	if err != nil {
		return nil
	}
	return collectReviewItemsWith(g, reviewConcepts)
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

func collectReviewItemsWith(g usg.Store, reviewConcepts map[string]reviewConceptInfo) []reviewItem {
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
	for _, n := range nodes {
		labels, _ := g.Labels(n.ID)
		for _, l := range labels {
			info, ok := reviewConcepts[l.Concept]
			if !ok {
				continue
			}
			key := reviewDedupKey(l.Concept, n)
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
			if info.kind == "target" {
				cp.NearbyChecks = relatedReviewChecks(g, byID, n.ID, info.expected, reviewConcepts)
			}
			out = append(out, cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return reviewItemOrder(out[i]) < reviewItemOrder(out[j])
	})
	return out
}

func reviewDedupKey(concept string, n usg.Node) string {
	loc := n.Prop("loc")
	if loc == "" {
		loc = n.ID
	}
	return concept + "\x00" + loc + "\x00" + n.Prop("path") + "\x00" + n.Prop("method")
}

func relatedReviewChecks(g usg.Store, nodes map[string]usg.Node, targetID string, expected []string, reviewConcepts map[string]reviewConceptInfo) []reviewRelatedCheck {
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
	if len(rows) > 8 {
		rows = rows[:8]
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
	if l.Provenance.Adapter != "" {
		parts = append(parts, l.Provenance.Adapter)
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

func printReviewItems(rows []reviewItem) {
	if len(rows) == 0 {
		fmt.Println("No review items found.")
		return
	}
	fmt.Printf("%d review item(s):\n", len(rows))
	for _, r := range rows {
		fmt.Printf("\n%s %-11s %s @ %s", strings.ToUpper(r.Kind), r.Category, r.Concept, r.Loc)
		if r.Call != "" {
			fmt.Printf("  call=%s", r.Call)
		}
		if r.Provenance != "" {
			fmt.Printf("  via=%s", r.Provenance)
		}
		fmt.Println()
		if len(r.Expected) > 0 {
			fmt.Printf("  expects: %s\n", strings.Join(r.Expected, ", "))
		}
		if r.Review != "" {
			fmt.Printf("  review: %s\n", r.Review)
		}
		if len(r.NearbyChecks) > 0 {
			fmt.Println("  nearby checks:")
			for _, c := range r.NearbyChecks {
				fmt.Printf("    - %s @ %s", c.Concept, c.Loc)
				if c.Call != "" {
					fmt.Printf("  call=%s", c.Call)
				}
				if c.Evidence != "" {
					fmt.Printf("  evidence=%s", c.Evidence)
				}
				if c.Provenance != "" {
					fmt.Printf("  via=%s", c.Provenance)
				}
				fmt.Println()
			}
		}
	}
}

func reviewItemOrder(r reviewItem) string {
	return r.Loc + "\x00" + r.Category + "\x00" + r.Kind + "\x00" + r.Concept + "\x00" + r.Call + "\x00" + r.NodeID
}

func relatedCheckOrder(r reviewRelatedCheck) string {
	return r.Loc + "\x00" + r.Concept + "\x00" + r.Call + "\x00" + r.Evidence
}

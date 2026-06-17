package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"

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

var reviewConcepts = map[string]reviewConceptInfo{
	"core.AuthenticationCheck": {category: "auth", kind: "check"},
	"core.AuthorizationCheck":  {category: "auth", kind: "check"},
	"core.OwnershipCheck":      {category: "auth", kind: "check"},
	"core.CsrfProtection":      {category: "request", kind: "check"},
	"core.ResourceRelease":     {category: "resource", kind: "check"},
	"core.LockRelease":         {category: "concurrency", kind: "check"},
	"core.XmlHardening":        {category: "xml", kind: "check"},
	"core.CertificateValidation": {
		category: "crypto",
		kind:     "check",
	},
	"core.EncryptionAtRest": {
		category: "crypto",
		kind:     "check",
	},
	"core.EncryptionInTransit": {
		category: "crypto",
		kind:     "check",
	},

	"code.AuthenticationRequiredOp": {
		category: "auth",
		kind:     "target",
		expected: []string{"core.AuthenticationCheck"},
		review:   "verify an authenticated user is required before this operation",
	},
	"code.ObjectLookupByUserInput": {
		category: "auth",
		kind:     "target",
		expected: []string{"core.OwnershipCheck", "core.AuthorizationCheck"},
		review:   "verify object access is constrained to the current principal",
	},
	"code.SensitiveOperation": {
		category: "auth",
		kind:     "target",
		expected: []string{"core.AuthorizationCheck"},
		review:   "verify this privileged or destructive operation enforces authorization",
	},
	"code.AccessPolicyReview": {
		category: "auth",
		kind:     "attention",
		expected: []string{"core.AuthorizationCheck"},
		review:   "review role or group policy configuration for overly broad access",
	},
	"code.WorkflowPolicyReview": {
		category: "auth",
		kind:     "attention",
		expected: []string{"core.AuthorizationCheck"},
		review:   "review workflow or status checks before this protected business action",
	},
	"code.IdorPolicyReview": {
		category: "auth",
		kind:     "attention",
		expected: []string{"core.OwnershipCheck", "core.AuthorizationCheck"},
		review:   "review object lookup or delete criteria for a current-principal ownership constraint",
	},
	"code.IncompleteIpDenylist": {
		category: "request",
		kind:     "attention",
		review:   "review network address validation for missing special-use IP ranges such as unspecified or broadcast",
	},
	"code.StateChangingOp": {
		category: "request",
		kind:     "target",
		expected: []string{"core.CsrfProtection", "core.AuthenticationCheck"},
		review:   "verify state-changing request paths have CSRF protection and auth context",
	},
	"code.CsrfDisabled": {
		category: "request",
		kind:     "target",
		expected: []string{"core.CsrfProtection"},
		review:   "review why CSRF protection is disabled or exempted here",
	},
	"code.InsecurePermission": {
		category: "permission",
		kind:     "target",
		review:   "review broad permission assignment and surrounding privilege checks",
	},
	"code.CryptoOperation": {
		category: "crypto",
		kind:     "target",
		expected: []string{"core.CertificateValidation", "core.EncryptionAtRest", "core.EncryptionInTransit"},
		review:   "verify algorithm choice, key/IV handling, and signature or certificate checks",
	},
	"code.ResourceReview": {
		category: "resource",
		kind:     "target",
		expected: []string{"core.ResourceRelease"},
		review:   "verify resource usage is bounded, timed out, and released",
	},
	"code.ConfigExposureReview": {
		category: "secret",
		kind:     "attention",
		expected: []string{"core.SecretRedaction"},
		review:   "verify config or diagnostic serialization redacts inline secrets before exposure",
	},
	"code.LockAcquire": {
		category: "concurrency",
		kind:     "target",
		expected: []string{"core.LockRelease"},
		review:   "verify the lock is released on every path",
	},
	"code.XmlParserCreate": {
		category: "xml",
		kind:     "target",
		expected: []string{"core.XmlHardening"},
		review:   "verify parser factory hardening disables dangerous XML features",
	},
	"code.UnboundedCopy": {
		category: "memory",
		kind:     "attention",
		review:   "review copy bounds and whether attacker-controlled data can reach the copied length or source",
	},
	"code.UnboundedCopySmell": {
		category: "memory",
		kind:     "attention",
		review:   "review unbounded string copy usage and surrounding length constraints",
	},
	"code.RawMemoryCopySize": {
		category: "memory",
		kind:     "attention",
		review:   "review raw memory copy size calculations and bounds checks",
	},
	"code.UnsafeMutableAlias": {
		category: "memory",
		kind:     "attention",
		review:   "review unsafe mutable reference construction from raw pointer casts and aliasing/lifetime guarantees",
	},
	"code.SizeComputation": {
		category: "memory",
		kind:     "attention",
		review:   "review allocation or size computation for overflow and untrusted dimensions",
	},
	"code.StackAllocationSmell": {
		category: "memory",
		kind:     "attention",
		review:   "review stack allocation size and whether it is bounded",
	},
	"code.IndexAccess": {
		category: "memory",
		kind:     "attention",
		review:   "review index/subscript access and the dominating bounds checks",
	},
	"code.FieldDerivedIndexAccess": {
		category: "memory",
		kind:     "attention",
		review:   "review field-derived array index access and the dominating upper-bound checks",
	},
	"code.IntegerSizeArithmetic": {
		category: "memory",
		kind:     "attention",
		review:   "review integer arithmetic used for address, size, or bounds calculations",
	},
	"code.PointerFree": {
		category: "memory",
		kind:     "attention",
		review:   "review pointer lifetime: frees, aliases, and later uses",
	},
	"code.PointerUse": {
		category: "memory",
		kind:     "attention",
		review:   "review pointer use and whether lifetime/initialization is guaranteed",
	},
	"code.NullableDeref": {
		category: "memory",
		kind:     "attention",
		review:   "review dereference and nearby null checks",
	},
}

func cmdReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text | json")
	profileName := fs.String("profile", "auto", "threat-model profile")
	category := fs.String("category", "all", "category filter: all | auth | request | crypto | resource | permission | concurrency | xml | memory | secret")
	loc := fs.String("loc", "", "location substring filter, e.g. core.c:422")
	checksOnly := fs.Bool("checks", false, "show only check/control sites")
	targetsOnly := fs.Bool("targets", false, "show only review targets")
	_ = fs.Parse(args)
	paths := fs.Args()
	if len(paths) == 0 {
		return fmt.Errorf("usage: vyql review [-format text|json] [-category all|auth|request|crypto|resource|permission|concurrency|xml|memory|secret] [-loc SUBSTR] [-checks|-targets] <path>...")
	}
	if *checksOnly && *targetsOnly {
		return fmt.Errorf("-checks and -targets are mutually exclusive")
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	rows := collectReviewItems(g)
	if *category != "" && *category != "all" {
		filtered := rows[:0]
		for _, r := range rows {
			if r.Category == *category {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	if *loc != "" {
		filtered := rows[:0]
		for _, r := range rows {
			if strings.Contains(r.Loc, *loc) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	if *checksOnly || *targetsOnly {
		filtered := rows[:0]
		for _, r := range rows {
			if *checksOnly && r.Kind == "check" {
				filtered = append(filtered, r)
			}
			if *targetsOnly && r.Kind == "target" {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	switch *format {
	case "json":
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
	case "text":
		printReviewItems(rows)
	default:
		return fmt.Errorf("unknown -format %q (use text or json)", *format)
	}
	return nil
}

func collectReviewItems(g usg.Store) []reviewItem {
	nodes, _ := g.AllNodes()
	byID := map[string]usg.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	var out []reviewItem
	for _, n := range nodes {
		labels, _ := g.Labels(n.ID)
		for _, l := range labels {
			info, ok := reviewConcepts[l.Concept]
			if !ok {
				continue
			}
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
				cp.NearbyChecks = relatedReviewChecks(g, byID, n.ID, info.expected)
			}
			out = append(out, cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return reviewItemOrder(out[i]) < reviewItemOrder(out[j])
	})
	return out
}

func relatedReviewChecks(g usg.Store, nodes map[string]usg.Node, targetID string, expected []string) []reviewRelatedCheck {
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

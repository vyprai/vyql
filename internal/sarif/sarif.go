// Package sarif emits VyQL findings as SARIF 2.1.0 (docs/14, /16) — the
// Table-stakes output for code findings and CI.
package sarif

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/resultpolicy"
)

const (
	Version = "2.1.0"
	Schema  = "https://json.schemastore.org/sarif-2.1.0.json"
)

// levelOf is the ONE severity -> SARIF level mapping. A result and its rule descriptor must
// agree; emitting a result at "note" whose rule defaults to "warning" makes one document
// contradict itself, and a consumer filtering on either field then sees a different set.
var levelOf = map[string]string{
	"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
}

func artifactLocation(loc string) map[string]any {
	uri := loc
	region := map[string]any{}
	if i := strings.LastIndex(loc, ":"); i >= 0 {
		if line, err := strconv.Atoi(loc[i+1:]); err == nil {
			uri = loc[:i]
			region["startLine"] = line
		}
	}
	phys := map[string]any{"artifactLocation": map[string]any{"uri": uri}}
	if len(region) > 0 {
		phys["region"] = region
	}
	return map[string]any{"physicalLocation": phys}
}

func nodeLoc(f *findings.Finding, nodeID string) string {
	for _, b := range f.Bindings {
		if b.NodeID == nodeID {
			return b.Loc
		}
	}
	return nodeID + ":0"
}

func findingToResult(f *findings.Finding) map[string]any {
	// The primary target comes from resultpolicy so the location a consumer sees is the same
	// binding the fingerprint was built from. This used to be a local copy that picked the LAST
	// matching sink where resultpolicy picks the first.
	var sink *findings.Binding
	if pt := resultpolicy.PrimaryTarget(f); pt.NodeID != "" || pt.Loc != "" {
		pt := pt
		sink = &pt
	}
	var source *findings.Binding
	for i := range f.Bindings {
		if b := &f.Bindings[i]; b.Name == "source" || b.Name == "principal" {
			source = b
		}
	}

	level := levelOf[f.Severity]
	if level == "" {
		level = "warning"
	}
	msg := f.RuleID
	if len(f.Bindings) >= 2 {
		msg = f.Bindings[0].Concept + " reaches " + f.Bindings[1].Concept + " (" + f.RuleID + ")"
	}

	var negEv []any
	for _, ne := range f.NegationEvidence {
		negEv = append(negEv, map[string]any{"clause": ne.Clause, "satisfied": ne.Satisfied, "detail": ne.Detail})
	}
	var prov []any
	for _, b := range f.Bindings {
		prov = append(prov, map[string]any{"binding": b.Name, "concept": b.Concept, "loc": b.Loc, "provenance": b.LabelProvenance})
	}
	var review []any
	for _, ec := range f.ReviewConditions {
		review = append(review, map[string]any{
			"category": ec.Category, "condition": ec.Condition, "evidence": ec.Evidence,
			"advisory": ec.Assumption, "confidence": ec.Confidence,
		})
	}

	result := map[string]any{
		"ruleId":              f.RuleID,
		"level":               level,
		"message":             map[string]any{"text": msg},
		"partialFingerprints": map[string]any{"vyqlFingerprint/v2": resultpolicy.Fingerprint(f)},
		"properties": map[string]any{
			"vypr.confidence":       f.Confidence,
			"vypr.witnessKind":      f.WitnessKind,
			"vypr.negationEvidence": negEv,
			"vypr.labelProvenance":  prov,
			"vypr.context":          f.Context,
			"vypr.reviewConditions": review,
		},
	}
	if sink != nil {
		result["locations"] = []any{withMessage(artifactLocation(sink.Loc), sink.Concept+" sink")}
	}
	if source != nil {
		result["relatedLocations"] = []any{withMessage(artifactLocation(source.Loc), source.Concept+" source")}
	}
	if f.WitnessKind == "taint" && len(f.Witness) > 0 {
		var locs []any
		for _, nid := range f.Witness {
			locs = append(locs, map[string]any{"location": artifactLocation(nodeLoc(f, nid))})
		}
		result["codeFlows"] = []any{map[string]any{"threadFlows": []any{map[string]any{"locations": locs}}}}
	}
	return result
}

func withMessage(loc map[string]any, text string) map[string]any {
	loc["message"] = map[string]any{"text": text}
	return loc
}

// securitySeverity maps a rule severity to the numeric string consumers rank by.
// The bands are the conventional CVSS-ish cutoffs SARIF consumers apply:
// >=9.0 critical, >=7.0 high, >=4.0 medium, else low.
func securitySeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "9.3"
	case "high":
		return "7.5"
	case "medium":
		return "5.5"
	case "low":
		return "3.5"
	default:
		return ""
	}
}

// cweTags renders a rule's CWE list in both the forms SARIF consumers look for:
// the bare identifier and the `external/cwe/cwe-nnn` taxonomy path. Accepts the
// `CWE_79` spelling used in rule metadata as well as `CWE-79` and a bare number.
func cweTags(cwes []string) []string {
	var out []string
	for _, c := range cwes {
		n := strings.TrimSpace(c)
		n = strings.TrimPrefix(strings.TrimPrefix(strings.ToUpper(n), "CWE_"), "CWE-")
		if n == "" {
			continue
		}
		out = append(out, "CWE-"+n, "external/cwe/cwe-"+fmt.Sprintf("%03s", n))
	}
	return out
}

// ruleDescriptor builds one reportingDescriptor. Publishing CWE and severity here
// is what lets a SARIF consumer — GitHub code scanning, or a benchmark scorer —
// read a finding's weakness class from the tool's own output instead of parsing
// the rule packs, whose layout and syntax are free to change.
func ruleDescriptor(f *findings.Finding, meta map[string]any) map[string]any {
	rule := map[string]any{"id": f.RuleID, "name": f.RuleID}
	props := map[string]any{}

	cwes := metaCWE(meta)
	if len(cwes) > 0 {
		props["cwe"] = cwes // retained: the pre-existing shape
		props["tags"] = cweTags(cwes)
	}
	// The rule's own metadata is the authority for a RULE descriptor, falling back to the
	// finding's resolved severity. In practice these agree -- the engine derives f.Severity from
	// this same metadata at compile time -- so the fallback matters only for a finding whose rule
	// metadata was not supplied to the writer.
	sev := f.Severity
	if s, ok := meta["severity"].(string); ok && s != "" {
		sev = s
	}
	if sev != "" {
		props["severity"] = sev
		if ss := securitySeverity(sev); ss != "" {
			props["security-severity"] = ss
		}
		if lvl, ok := levelOf[sev]; ok {
			rule["defaultConfiguration"] = map[string]any{"level": lvl}
		}
	}
	if d, ok := meta["description"].(string); ok && d != "" {
		rule["shortDescription"] = map[string]any{"text": d}
	}
	if len(props) > 0 {
		rule["properties"] = props
	}
	return rule
}

// metaCWE reads the `cwe` entry, which rule metadata carries as a string or a
// list depending on how it was authored.
func metaCWE(meta map[string]any) []string {
	switch v := meta["cwe"].(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ToSARIF serializes findings to a SARIF 2.1.0 document.
func ToSARIF(fs []*findings.Finding, toolVersion string, rulesMeta map[string]map[string]any) map[string]any {
	seen := map[string]bool{}
	var rules []any
	for _, f := range fs {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		rules = append(rules, ruleDescriptor(f, rulesMeta[f.RuleID]))
	}
	var results []any
	for _, f := range fs {
		results = append(results, findingToResult(f))
	}
	return map[string]any{
		"$schema": Schema,
		"version": Version,
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "VyQL", "informationUri": "https://vypr.security/vyql",
				"version": toolVersion, "rules": rules,
			}},
			"results": results,
		}},
	}
}

// ValidateSARIF performs dependency-free structural validation of the required
// SARIF 2.1.0 shape. Returns a list of problems ([] = valid).
func ValidateSARIF(doc map[string]any) []string {
	var errs []string
	if doc["version"] != Version {
		errs = append(errs, "version must be "+Version)
	}
	if _, ok := doc["$schema"]; !ok {
		errs = append(errs, "missing $schema")
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		return append(errs, "runs must be a non-empty list")
	}
	for _, r := range runs {
		run, _ := r.(map[string]any)
		tool, _ := run["tool"].(map[string]any)
		driver, _ := tool["driver"].(map[string]any)
		if driver == nil || driver["name"] == nil {
			errs = append(errs, "missing tool.driver.name")
		}
		results, ok := run["results"].([]any)
		if !ok {
			errs = append(errs, "results must be a list")
			continue
		}
		for i, rr := range results {
			res, _ := rr.(map[string]any)
			if res["ruleId"] == nil {
				errs = append(errs, "results["+strconv.Itoa(i)+"]: missing ruleId")
			}
			if lvl, _ := res["level"].(string); lvl != "" && lvl != "error" && lvl != "warning" && lvl != "note" && lvl != "none" {
				errs = append(errs, "results["+strconv.Itoa(i)+"]: invalid level")
			}
			msg, _ := res["message"].(map[string]any)
			if msg == nil || msg["text"] == nil {
				errs = append(errs, "results["+strconv.Itoa(i)+"]: missing message.text")
			}
		}
	}
	return errs
}

// Package sarif emits VyQL findings as SARIF 2.1.0 (docs/14, /16), ported from
// poc/vyql/sarif.py — the table-stakes output for code findings and CI.
package sarif

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/findings"
)

const (
	Version = "2.1.0"
	Schema  = "https://json.schemastore.org/sarif-2.1.0.json"
)

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
	var sink, source *findings.Binding
	for i := range f.Bindings {
		b := &f.Bindings[i]
		switch b.Name {
		case "sink", "target":
			sink = b
		case "source", "principal":
			source = b
		}
	}
	if sink == nil && len(f.Bindings) > 0 {
		sink = &f.Bindings[len(f.Bindings)-1]
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

	result := map[string]any{
		"ruleId":              f.RuleID,
		"level":               level,
		"message":             map[string]any{"text": msg},
		"partialFingerprints": map[string]any{"vyqlFingerprint/v1": f.Fingerprint()},
		"properties": map[string]any{
			"vypr.confidence":       f.Confidence,
			"vypr.witnessKind":      f.WitnessKind,
			"vypr.negationEvidence": negEv,
			"vypr.labelProvenance":  prov,
			"vypr.context":          f.Context,
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

// ToSARIF serializes findings to a SARIF 2.1.0 document.
func ToSARIF(fs []*findings.Finding, toolVersion string, rulesMeta map[string]map[string]any) map[string]any {
	seen := map[string]bool{}
	var rules []any
	for _, f := range fs {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		rule := map[string]any{"id": f.RuleID, "name": f.RuleID}
		if m := rulesMeta[f.RuleID]; m != nil {
			if cwe, ok := m["cwe"]; ok {
				rule["properties"] = map[string]any{"cwe": cwe}
			}
		}
		rules = append(rules, rule)
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

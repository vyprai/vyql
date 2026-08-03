// Package nexus emits full-fidelity finding JSON for the Nexus API
// (docs/14) — finding + proof tree + node refs, so UIs can pivot from a
// finding to its graph neighborhood. Port of the Nexus output shape.
package nexus

import (
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/resultpolicy"
)

const SchemaVersion = "1.0"

// ToNexus serializes findings to the Nexus API JSON shape (full fidelity).
func ToNexus(fs []*findings.Finding, engineVersion, ontologyVersion string) map[string]any {
	var out []any
	for _, f := range fs {
		out = append(out, findingToNexus(f))
	}
	return map[string]any{
		"schemaVersion": SchemaVersion,
		"engine":        engineVersion,
		"ontology":      ontologyVersion,
		"findings":      out,
	}
}

func findingToNexus(f *findings.Finding) map[string]any {
	var bindings []any
	for _, b := range f.Bindings {
		bindings = append(bindings, map[string]any{
			"name": b.Name, "nodeId": b.NodeID, "concept": b.Concept,
			"loc": b.Loc, "provenance": b.LabelProvenance,
		})
	}
	var negEv []any
	for _, ne := range f.NegationEvidence {
		negEv = append(negEv, map[string]any{
			"clause": ne.Clause, "satisfied": ne.Satisfied, "detail": ne.Detail,
		})
	}
	var review []any
	for _, ec := range f.ReviewConditions {
		review = append(review, map[string]any{
			"category": ec.Category, "condition": ec.Condition, "evidence": ec.Evidence,
			"advisory": ec.Assumption, "confidence": ec.Confidence,
		})
	}
	return map[string]any{
		"ruleId":           f.RuleID,
		"severity":         f.Severity,
		"confidence":       f.Confidence,
		"fingerprint":      resultpolicy.Fingerprint(f),
		"witnessKind":      f.WitnessKind,
		"witness":          f.Witness,
		"bindings":         bindings,
		"negationEvidence": negEv,
		"context":          f.Context,
		"reviewConditions": review,
	}
}

// Validate performs structural validation of a Nexus document.
func Validate(doc map[string]any) []string {
	var errs []string
	if doc["schemaVersion"] != SchemaVersion {
		errs = append(errs, "schemaVersion must be "+SchemaVersion)
	}
	fs, ok := doc["findings"].([]any)
	if !ok {
		return append(errs, "findings must be a list")
	}
	for i, raw := range fs {
		f, _ := raw.(map[string]any)
		if f["ruleId"] == nil {
			errs = append(errs, "findings["+itoa(i)+"]: missing ruleId")
		}
		if f["fingerprint"] == nil {
			errs = append(errs, "findings["+itoa(i)+"]: missing fingerprint")
		}
		if _, ok := f["bindings"].([]any); !ok {
			errs = append(errs, "findings["+itoa(i)+"]: bindings must be a list")
		}
	}
	return errs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

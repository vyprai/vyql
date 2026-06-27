// Package findings is the Finding + proof tree (docs/14), ported from
// poc/vyql/findings.py. Every finding carries its derivation: bindings (with
// provenance), the solver witness, and negation evidence (what each `unless`
// checked). Explainability is produced by the engine, not rule authors.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Binding is a bound variable in a finding (with the provenance of its concept
// label).
type Binding struct {
	Name            string
	NodeID          string
	Concept         string
	Loc             string
	LabelProvenance string
}

// NegationEvidence records what an `unless` clause checked and what it found.
type NegationEvidence struct {
	Clause    string
	Satisfied bool // true => suppressed the finding
	Detail    string
}

// ReviewCondition records what a reviewer should verify for a non-perfectly
// proven condition, and what evidence VyQL observed for it.
type ReviewCondition struct {
	Category   string
	Condition  string
	Evidence   string
	Assumption string
	Confidence string
}

// Finding is a rule match with its full derivation.
type Finding struct {
	RuleID           string
	Severity         string
	Bindings         []Binding
	Witness          []string // solver witness (node ids / hops, kind-specific)
	PathLocs         []string // distinct file:line locs along the witness (taint path), in order
	WitnessKind      string   // taint | reach | grant | assume | match
	NegationEvidence []NegationEvidence
	Confidence       string
	Context          []string
	ReviewConditions []ReviewCondition
}

// Fingerprint is content-anchored (rule + binding LOCATIONS), so equivalent
// findings collapse and survive line drift within a location key.
func (f *Finding) Fingerprint() string {
	parts := make([]string, len(f.Bindings))
	for i, b := range f.Bindings {
		parts[i] = b.Name + "=" + b.Loc
	}
	sum := sha256.Sum256([]byte(f.RuleID + "::" + strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:16]
}

func (f *Finding) RenderWithFingerprint(fp string) string {
	return f.render(fp)
}

// Render produces a human-readable proof tree from the finding's fields.
func (f *Finding) Render() string {
	return f.render(f.Fingerprint())
}

func (f *Finding) render(fp string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s  (conf=%s, fp=%s)\n",
		strings.ToUpper(f.Severity), f.RuleID, f.Confidence, fp)
	for _, bd := range f.Bindings {
		prov := ""
		if bd.LabelProvenance != "" {
			prov = "  <- " + bd.LabelProvenance
		}
		fmt.Fprintf(&b, "    %s: %s @ %s%s\n", bd.Name, bd.Concept, bd.Loc, prov)
	}
	switch f.WitnessKind {
	case "taint":
		if len(f.Witness) > 0 {
			fmt.Fprintf(&b, "    taint path: %s\n", strings.Join(f.Witness, " -> "))
		}
	case "reach", "grant", "assume":
		for _, w := range f.Witness {
			fmt.Fprintf(&b, "    %s: %s\n", f.WitnessKind, w)
		}
	}
	for _, ne := range f.NegationEvidence {
		mark := "not satisfied"
		if ne.Satisfied {
			mark = "satisfied (suppressed)"
		}
		fmt.Fprintf(&b, "    unless %s: %s", ne.Clause, mark)
		if ne.Detail != "" {
			fmt.Fprintf(&b, " — %s", ne.Detail)
		}
		b.WriteString("\n")
	}
	for _, c := range f.Context {
		fmt.Fprintf(&b, "    context: %s\n", c)
	}
	for _, ec := range f.ReviewConditions {
		fmt.Fprintf(&b, "    review condition: %s", ec.Condition)
		if ec.Category != "" {
			fmt.Fprintf(&b, " [%s]", ec.Category)
		}
		if ec.Evidence != "" {
			fmt.Fprintf(&b, " — evidence: %s", ec.Evidence)
		}
		if ec.Assumption != "" {
			fmt.Fprintf(&b, " — assumes: %s", ec.Assumption)
		}
		if ec.Confidence != "" {
			fmt.Fprintf(&b, " — conf=%s", ec.Confidence)
		}
		b.WriteString("\n")
	}
	return b.String()
}

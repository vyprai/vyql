// Package findings is the Finding + proof tree (docs/14). Every finding
// Carries its derivation: bindings (with
// provenance), the solver witness, and negation evidence (what each `unless`
// checked). Explainability is produced by the engine, not rule authors.
package findings

import (
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
	Category   string `json:"category,omitempty"`
	Condition  string `json:"condition,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Assumption string `json:"advisory,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// Finding is a rule match with its full derivation.
type Finding struct {
	RuleID           string
	Severity         string
	Bindings         []Binding
	Witness          []string // solver witness (node ids / hops, kind-specific)
	PathLocs         []string // distinct file:line locs along the witness (taint path), in order
	WitnessKind      string   // taint | reach | grant | match
	NegationEvidence []NegationEvidence
	Confidence       string
	Context          []string
	ReviewConditions []ReviewCondition
}

// Render produces a human-readable proof tree from the finding's fields.
//
// The fingerprint is a parameter rather than something this type computes. Finding identity is
// policy -- which fields make two results "the same problem" is declared in vyql/policies as
// `policy resultIdentity default` and owned by internal/resultpolicy. A second implementation
// here would be a competing answer to that question, and was: it hashed every binding's name and
// location, so the id printed in the text report disagreed with the one in SARIF for any finding
// with more than one binding. resultpolicy cannot be imported here (it imports findings), and
// that import direction is the reason the duplicate existed -- so callers pass the value in.
func (f *Finding) Render(fp string) string {
	return f.render(fp)
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
	case "reach", "grant":
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
			fmt.Fprintf(&b, " — advisory: %s", ec.Assumption)
		}
		if ec.Confidence != "" {
			fmt.Fprintf(&b, " — conf=%s", ec.Confidence)
		}
		b.WriteString("\n")
	}
	return b.String()
}

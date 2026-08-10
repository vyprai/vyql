// Package findings is the Finding + proof tree (docs/14). Every finding
// Carries its derivation: bindings (with
// provenance), the solver witness, and negation evidence (what each `unless`
// checked). Explainability is produced by the engine, not rule authors.
package findings

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

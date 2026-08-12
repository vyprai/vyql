// Package report renders findings for a terminal.
//
// This was a method on findings.Finding, which made the domain type also a fourth output format
// alongside SARIF, Nexus and graph-json -- and gave the proof tree a privileged position none of
// the others had. A formatter reads a finding; it is not part of one.
package report

import (
	"fmt"
	"strings"

	"github.com/vyprai/vyql/internal/findings"
)

// Finding renders a human-readable proof tree.
//
// One nesting level, indented two spaces. Every command indents two spaces per
// level, so the same depth reads as the same depth wherever it is printed.
//
// The fingerprint is a parameter rather than something this type computes. Finding identity is
// policy -- which fields make two results "the same problem" is declared in vyql/policies as
// `policy resultIdentity default` and owned by internal/resultpolicy. A second implementation
// here would be a competing answer to that question, and was: it hashed every binding's name and
// location, so the id printed in the text report disagreed with the one in SARIF for any finding
// with more than one binding. resultpolicy cannot be imported here (it imports findings), and
// that import direction is the reason the duplicate existed -- so callers pass the value in.
func Finding(f *findings.Finding, fp string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s  (conf=%s, fp=%s)\n",
		strings.ToUpper(f.Severity), f.RuleID, f.Confidence, fp)
	for _, bd := range f.Bindings {
		prov := ""
		if bd.LabelProvenance != "" {
			prov = "  <- " + bd.LabelProvenance
		}
		fmt.Fprintf(&b, "  %s: %s @ %s%s\n", bd.Name, bd.Concept, bd.Loc, prov)
	}
	switch f.WitnessKind {
	case "taint":
		if len(f.Witness) > 0 {
			fmt.Fprintf(&b, "  taint path: %s\n", strings.Join(f.Witness, " -> "))
		}
	case "reach", "grant":
		for _, w := range f.Witness {
			fmt.Fprintf(&b, "  %s: %s\n", f.WitnessKind, w)
		}
	}
	for _, ne := range f.NegationEvidence {
		mark := "not satisfied"
		if ne.Satisfied {
			mark = "satisfied (suppressed)"
		}
		fmt.Fprintf(&b, "  unless %s: %s", ne.Clause, mark)
		if ne.Detail != "" {
			fmt.Fprintf(&b, " — %s", ne.Detail)
		}
		b.WriteString("\n")
	}
	for _, c := range f.Context {
		fmt.Fprintf(&b, "  context: %s\n", c)
	}
	for _, ec := range f.ReviewConditions {
		fmt.Fprintf(&b, "  review condition: %s", ec.Condition)
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

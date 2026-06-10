package ontology

import "github.com/vyprai/vyql/taxonomy"

// Validate checks that every CWE/CAPEC id cited by threat kinds and concepts
// resolves in the catalog, and that concept typing references known threat kinds
// (docs/16 — bad ids fail CI). Returns a list of problems ([] = valid).
func Validate(o *Ontology, cat *taxonomy.Catalog) []string {
	var problems []string

	known := map[string]bool{}
	for _, tk := range ThreatKinds() {
		known[tk.QualifiedName()] = true
		for _, c := range tk.CWE {
			if !cat.HasCWE(c) {
				problems = append(problems, "threat kind "+tk.QualifiedName()+": unknown "+c)
			}
		}
	}

	for _, c := range o.concepts {
		q := c.QualifiedName()
		for _, cwe := range c.CWE {
			if !cat.HasCWE(cwe) {
				problems = append(problems, "concept "+q+": unknown "+cwe)
			}
		}
		for _, cap := range c.CAPEC {
			if !cat.HasCAPEC(cap) {
				problems = append(problems, "concept "+q+": unknown "+cap)
			}
		}
		// sinks' vulnerable_to and controls' neutralizes must be known threat kinds
		for _, t := range c.VulnerableTo {
			if !known[t] {
				problems = append(problems, "concept "+q+": vulnerable_to unknown threat kind "+t)
			}
		}
		for _, t := range c.Neutralizes {
			if !known[t] {
				problems = append(problems, "concept "+q+": neutralizes unknown threat kind "+t)
			}
		}
	}
	return problems
}

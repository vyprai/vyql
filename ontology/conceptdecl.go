package ontology

import "github.com/vyprai/vyql/parser"

// ConceptFromDecl converts a parsed textual concept declaration
// (`concept <Name> : <kind> { … }`, docs/06) into a Concept. The kind is the
// header type annotation; body fields map to the typing/standards attributes.
// Unknown body keys (description, examples, since, domain) are tolerated and
// ignored — they are documentation, not part of the type system.
func ConceptFromDecl(d *parser.ConceptDecl) Concept {
	c := Concept{
		Name:                    d.Name,
		Package:                 d.Package,
		Kind:                    d.Kind,
		Taint:                   list(d.Fields, "taint"),
		VulnerableTo:            list(d.Fields, "vulnerable_to"),
		Neutralizes:             list(d.Fields, "neutralizes"),
		Applies:                 str(d.Fields, "applies"),
		Refines:                 str(d.Fields, "refines"),
		EnabledBy:               list(d.Fields, "enabled_by"),
		CWE:                     list(d.Fields, "cwe"),
		CAPEC:                   list(d.Fields, "capec"),
		Attack:                  list(d.Fields, "attack"),
		Aliases:                 list(d.Fields, "aliases"),
		Deprecated:              str(d.Fields, "deprecated"),
		Possibility:             str(d.Fields, "possibility"),
		SourcePolicy:            str(d.Fields, "source_policy"),
		SourceConditionCategory: str(d.Fields, "source_condition_category"),
		SourceCondition:         str(d.Fields, "source_condition"),
		SourceAssumption:        str(d.Fields, "source_assumption"),
		SourceConfidence:        str(d.Fields, "source_confidence"),
		AssumeMinLevel:          str(d.Fields, "assume_min_level"),
		ContextReachSource:      str(d.Fields, "context_reach_source"),
		ContextReachLabel:       str(d.Fields, "context_reach_label"),
		DangerousChars:          str(d.Fields, "dangerous_chars"),
	}
	return c
}

// LoadConceptText parses VyQL ontology source (a stream of `concept` and
// `package` declarations) into Concepts. Non-concept declarations are ignored,
// so a file may mix concepts with rules.
func LoadConceptText(src string) ([]Concept, error) {
	decls, err := parser.Parse(src)
	if err != nil {
		return nil, err
	}
	var out []Concept
	for _, d := range decls {
		if cd, ok := d.(*parser.ConceptDecl); ok {
			out = append(out, ConceptFromDecl(cd))
		}
	}
	return out, nil
}

func str(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

func list(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return v
	case string:
		return []string{v}
	}
	return nil
}

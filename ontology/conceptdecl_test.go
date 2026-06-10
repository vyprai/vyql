package ontology

import (
	"reflect"
	"testing"
)

// The textual `concept <Name> : <kind> { … }` form (docs/06) must produce the
// same Concept as the JSON seed — kind as a header type annotation, typing
// fields in the body.
func TestConceptDeclMatchesSeed(t *testing.T) {
	src := `
package code;
concept Deserialization : sink {
  vulnerable_to: [deserialization.DeserializationAbuse]
  enabled_by: [taint.UntrustedData]
  cwe: [CWE_502]
}
`
	got, err := LoadConceptText(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 concept, got %d", len(got))
	}
	c := got[0]
	if c.QualifiedName() != "code.Deserialization" || c.Kind != "sink" {
		t.Fatalf("header parse: got %s : %s", c.QualifiedName(), c.Kind)
	}

	seed := Seed().MustGet("code.Deserialization")
	if !reflect.DeepEqual(c.VulnerableTo, seed.VulnerableTo) ||
		!reflect.DeepEqual(c.EnabledBy, seed.EnabledBy) ||
		!reflect.DeepEqual(c.CWE, seed.CWE) {
		t.Fatalf("declared concept != seed:\n got  %+v\n seed %+v", c, *seed)
	}
}

// The dotted-header form and a `control` with neutralizes/applies both parse,
// and a loaded ontology type-checks `sanitized_by` correctly.
func TestConceptDeclDottedAndTyping(t *testing.T) {
	src := `
concept code.HttpInput : source {
  taint: [taint.UntrustedData]
}
concept code.SqlExecution : sink {
  vulnerable_to: [injection.SqlInjection]
  enabled_by: [taint.UntrustedData]
}
concept core.SqlParameterization : control {
  neutralizes: [injection.SqlInjection]
  applies: path
}
`
	concepts, err := LoadConceptText(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	o := New()
	for _, c := range concepts {
		o.Add(c)
	}
	if _, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.SqlParameterization"); err != nil {
		t.Fatalf("well-typed sanitizer rejected: %v", err)
	}
	// a control bound to the wrong threat must NOT type-check
	o.Add(Concept{Name: "HtmlEscape", Package: "core", Kind: "control", Neutralizes: []string{"injection.Xss"}})
	if _, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.HtmlEscape"); err == nil {
		t.Fatal("wrong-threat control should not defend a SQL sink")
	}
	// applies defaulted to "path" on Add for a control with no explicit applies
	if c := o.MustGet("core.HtmlEscape"); c.Applies != "path" {
		t.Fatalf("control applies should default to path, got %q", c.Applies)
	}
}

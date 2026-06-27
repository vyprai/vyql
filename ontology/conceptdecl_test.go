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
module code;
concept Deserialization : sink {
  vulnerableTo: [deserialization.DeserializationAbuse]
  enabledBy: [taint.UntrustedData]
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

// Multi-file v2 concept text and a neutralizing `check` both parse, and a
// loaded ontology type-checks v2 path coveredBy controls correctly.
func TestConceptDeclDottedAndTyping(t *testing.T) {
	sources := []string{`
module code;
concept HttpInput : source {
  taint: [taint.UntrustedData]
}
concept SqlExecution : sink {
  vulnerableTo: [injection.SqlInjection]
  enabledBy: [taint.UntrustedData]
}
`, `
module core;
concept SqlParameterization : check {
  neutralizes: [injection.SqlInjection]
  applies: path
}
`}
	var concepts []Concept
	for _, src := range sources {
		loaded, err := LoadConceptText(src)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		concepts = append(concepts, loaded...)
	}
	o := New()
	for _, c := range concepts {
		o.Add(c)
	}
	if _, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.SqlParameterization"); err != nil {
		t.Fatalf("well-typed sanitizer rejected: %v", err)
	}
	// a neutralizing check bound to the wrong threat must NOT type-check
	o.Add(Concept{Name: "HtmlEscape", Package: "core", Kind: "check", Neutralizes: []string{"injection.Xss"}})
	if _, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.HtmlEscape"); err == nil {
		t.Fatal("wrong-threat check should not defend a SQL sink")
	}
	// applies defaulted to "path" on Add for a neutralizing check with no explicit applies
	if c := o.MustGet("core.HtmlEscape"); c.Applies != "path" {
		t.Fatalf("neutralizing check applies should default to path, got %q", c.Applies)
	}
}

func TestConceptDeclUsesV2MechanicMetadataNames(t *testing.T) {
	sources := []string{`
module identity;
concept AdminPrivilege : privilege {
  grantMinLevel: ADMIN
}
`, `
module core;
concept CharFilter : check {
  covers: [path]
}
`}
	var got []Concept
	for _, src := range sources {
		loaded, err := LoadConceptText(src)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got = append(got, loaded...)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 concepts, got %d", len(got))
	}
	if got[0].GrantMinLevel != "ADMIN" {
		t.Fatalf("grantMinLevel = %q, want ADMIN", got[0].GrantMinLevel)
	}
	if got[1].AnalysisRole != "" {
		t.Fatalf("analysisRole should be Go-owned, got authored value %q", got[1].AnalysisRole)
	}
}

func TestOntologyResolvesGoOwnedAnalysisRoles(t *testing.T) {
	o := Seed()
	for role, want := range map[string]string{
		AnalysisRoleAttributeSink:      "code.ProtoPollute",
		AnalysisRoleCharFilter:         "threat.CharFilter",
		AnalysisRoleDomInput:           "code.DomInput",
		AnalysisRolePathAccessCheck:    "core.PathAccessCheck",
		AnalysisRoleProcessArgVector:   "core.ProcessArgVector",
		AnalysisRoleSameReceiverGuard:  "core.XmlHardening",
		AnalysisRoleSameReceiverTarget: "code.XmlParserCreate",
	} {
		if got := o.ConceptsWithAnalysisRole(role); !got[want] {
			t.Fatalf("role %s concepts = %v, want %s", role, got, want)
		}
	}
}

package ontology

import (
	"strings"
	"testing"
)

// Control<->threat<->sink typing.
// Names follow VyQL conventions: <namespace>.<PascalCase>, threat kinds
// <family>.<PascalCase>, CWE refs CWE_NNN.
func TestSanitizerTyping(t *testing.T) {
	o := Seed()

	// well-typed: core.SqlParameterization defends code.SqlExecution
	if threat, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.SqlParameterization"); err != nil {
		t.Fatalf("well-typed sanitizer rejected: %v", err)
	} else if threat != "injection.SqlInjection" {
		t.Fatalf("expected threat injection.SqlInjection, got %s", threat)
	}

	// ill-typed: core.HtmlEscape does NOT defend code.SqlExecution -> error
	_, err := o.CheckSanitizerTyping("code.HttpInput", "code.SqlExecution", "core.HtmlEscape")
	if err == nil || !strings.Contains(err.Error(), "does not defend") {
		t.Fatalf("expected 'does not defend' error, got %v", err)
	}

	// well-typed CSRF guard pairing
	if _, err := o.CheckSanitizerTyping("code.HttpInput", "code.StateChangingOp", "core.CsrfProtection"); err != nil {
		t.Fatalf("core.CsrfProtection should defend code.StateChangingOp: %v", err)
	}
}

// Unknown concept resolution.
func TestUnknownConcept(t *testing.T) {
	o := Seed()
	if o.Exists("aws_s3_bucket") {
		t.Fatal("aws_s3_bucket should not exist")
	}
	if _, err := o.Get("aws_s3_bucket"); err == nil {
		t.Fatal("Get of unknown concept should error")
	}
}

// Refinement matching is downward-closed.
func TestRefinement(t *testing.T) {
	o := Seed()
	d := o.Descendants("core.UserControlledData")
	if !d["code.HttpInput"] || !d["code.HttpHeader"] || !d["core.UserControlledData"] {
		t.Fatalf("core.UserControlledData should match its refinements, got %v", d)
	}
	if d["code.SqlExecution"] {
		t.Fatal("descendants must not include unrelated concepts")
	}
}

// Aliases + deprecation.
func TestAliasDeprecation(t *testing.T) {
	o := Seed()
	o.Alias("code.HttpInput", "code.UserInput")
	o.Deprecate("code.HttpHeader", "merged into code.HttpInput")

	if !o.Exists("code.UserInput") {
		t.Fatal("alias should resolve to existing concept")
	}
	if c, _ := o.Get("code.UserInput"); c.QualifiedName() != "code.HttpInput" {
		t.Fatalf("alias Get should return canonical, got %v", c.QualifiedName())
	}
	if o.Canonical("code.UserInput") != "code.HttpInput" {
		t.Fatal("Canonical should map alias->canonical")
	}
	if !strings.Contains(o.DeprecationWarning("code.UserInput"), "alias of 'code.HttpInput'") {
		t.Fatalf("alias warning expected, got %q", o.DeprecationWarning("code.UserInput"))
	}
	if !strings.Contains(o.DeprecationWarning("code.HttpHeader"), "deprecated") {
		t.Fatalf("deprecation warning expected, got %q", o.DeprecationWarning("code.HttpHeader"))
	}
	if o.DeprecationWarning("code.HttpInput") != "" {
		t.Fatal("canonical non-deprecated concept should have no warning")
	}
	if d := o.Descendants("code.UserInput"); !d["code.HttpInput"] {
		t.Fatal("descendants of an alias should resolve to the canonical's set")
	}
}

// Seed sanity: namespaced concepts exist; control default applies = path.
func TestSeedShape(t *testing.T) {
	o := Seed()
	for _, name := range []string{"code.HttpInput", "code.SqlExecution", "core.SqlParameterization",
		"cloud.Internet", "identity.AdminPrivilege", "code.Deserialization", "sbom.VulnerableDependency"} {
		if !o.Exists(name) {
			t.Fatalf("seed missing %s", name)
		}
	}
	if c, _ := o.Get("core.SqlParameterization"); c.Applies != "path" {
		t.Fatalf("control default applies should be path, got %s", c.Applies)
	}
}

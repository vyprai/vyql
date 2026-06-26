package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

func TestCompileLoweredV2Rule(t *testing.T) {
	decls, err := parser.ParseV2Runtime(`
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}
`)
	if err != nil {
		t.Fatalf("ParseV2Runtime: %v", err)
	}
	compiled, errs := CompileRules(decls, ontology.Seed())
	if len(errs) > 0 {
		t.Fatalf("CompileRules errors: %+v", errs)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(compiled))
	}
	cr := compiled[0]
	if cr.Rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("qualified name = %q", cr.Rule.QualifiedName())
	}
	if !cr.KillControls["core.SqlParameterization"] {
		t.Fatalf("coveredBy check did not become a kill control: %+v", cr.KillControls)
	}
}

package vyql

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

func testSchemas(t *testing.T) *graph.Schemas {
	t.Helper()
	s := graph.NewSchemas()
	must := func(ts *graph.TypeSchema) {
		if err := s.Register(ts); err != nil {
			t.Fatalf("Register(%s): %v", ts.Type, err)
		}
	}
	must(&graph.TypeSchema{Type: "code.Call", Layer: graph.LayerLow,
		Fields: []graph.FieldSpec{{Name: "callee", Kind: graph.KindString}}, Key: []string{"callee"}})
	must(&graph.TypeSchema{Type: "code.DataAccess", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "table", Kind: graph.KindString},
			{Name: "op", Kind: graph.KindEnum, Enum: []string{"read", "write"}},
		}, Key: []string{"table", "op"}})
	return s
}

const validKB = `module toy;
concept code.UntrustedData : source { taint: [UntrustedData] }
concept code.HttpInput : source { refines: code.UntrustedData taint: [UntrustedData] }
concept code.SqlExecution : sink { vulnerable_to: [Injection] enabled_by: [UntrustedData] }
concept code.SqlParameterization : control { neutralizes: [Injection] }
threat Injection { }
adapter flask {
  meta { fidelity: resolved }
  source code.path("request.args.get") -> code.HttpInput
}
rule SqlInjection {
  meta { id: "TOY-001" severity: high }
  taint code.HttpInput -> code.SqlExecution -> finding unless sanitized_by code.SqlParameterization
}
rule LowLevel {
  meta { id: "TOY-002" severity: low }
  match (n: code.Call) where n.callee == "db.Exec" -> finding
}
`

func buildValid(t *testing.T) (*Knowledge, *File) {
	t.Helper()
	f, err := Parse(validKB)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kb, errs := BuildKnowledge([]*File{f}, testSchemas(t))
	if len(errs) > 0 {
		t.Fatalf("BuildKnowledge errors: %v", errs)
	}
	if errs := Validate(f, kb); len(errs) > 0 {
		t.Fatalf("Validate errors: %v", errs)
	}
	return kb, f
}

func TestValidateCleanFixtureAndCaps(t *testing.T) {
	kb, _ := buildValid(t)

	// A rule naming a low-level NIR type is capped at medium, not rejected.
	if got, ok := kb.RuleCaps["LowLevel"]; !ok || got != CapLowLevelType || CapLowLevelType != ConfMedium {
		t.Fatalf("LowLevel cap = %+v (ok=%v), want medium", got, ok)
	}
	if _, capped := kb.RuleCaps["SqlInjection"]; capped {
		t.Fatal("a concept-only rule must not be capped")
	}
	if FidelityCap("resolved") != ConfHigh || FidelityCap("syntactic") != ConfMedium {
		t.Fatal("fidelity caps: resolved=high, syntactic=medium")
	}
	if _, ok := ParseConfidence("extreme"); ok {
		t.Fatal("extreme is not on the ladder")
	}
}

func TestValidateNegatives(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		mentions []string
	}{
		{"kind outside closed set",
			"module toy; concept A : threat { }",
			[]string{"threat", "closed set"}},
		{"dual-role other than control|guard",
			"module toy; concept B : source | sink { }",
			[]string{"control, guard"}},
		{"binding keyword contradicts concept kind",
			"module toy; concept code.HttpInput : source { }\nadapter t { sink code.path(\"x\") -> code.HttpInput }",
			[]string{"sink", "HttpInput"}},
		{"rule names undefined concept",
			"module toy; rule R { taint A -> Missing -> finding }",
			[]string{"Missing"}},
		{"bool literal against string field",
			"module toy; rule R { match (n: code.Call) where n.callee == true -> finding }",
			[]string{"compares"}},
		{"ordering on string field",
			"module toy; rule R { match (n: code.Call) where n.callee < 3 -> finding }",
			[]string{"ordering"}},
		{"unknown enum member",
			"module toy; rule R { match (d: code.DataAccess) where d.op == drop -> finding }",
			[]string{"drop"}},
		{"duplicate rule id",
			"module toy; rule A { meta { id: \"X\" } present C -> signal }\nrule B { meta { id: \"X\" } present C -> signal }",
			[]string{"already used"}},
		{"concept missing rule id",
			"module toy; rule R { present C -> signal }",
			[]string{"meta"}},
		{"bad severity",
			"module toy; rule R { meta { id: \"X\" severity: ultra } present C -> signal }",
			[]string{"severity"}},
		{"bad confidence floor",
			"module toy; rule R { meta { id: \"X\" confidence_floor: extreme } present C -> signal }",
			[]string{"confidence_floor"}},
		{"undefined refines parent",
			"module toy; concept A : source { refines: code.Nope }",
			[]string{"Nope"}},
		{"threat subsumes unknown",
			"module toy; threat T { subsumes: [Nope] }",
			[]string{"Nope"}},
		{"threat cycle",
			"module toy; threat A { subsumes: [B] }\nthreat B { subsumes: [A] }",
			[]string{"cycle"}},
		{"unless names undefined concept",
			"module toy; rule R { taint A -> B -> finding unless sanitized_by Nope }",
			[]string{"Nope"}},
		{"pattern names neither type nor concept",
			"module toy; rule R { match (x: Neither) -> finding }",
			[]string{"Neither"}},
	}
	for _, tc := range cases {
		f, err := Parse(tc.src)
		if err != nil {
			t.Errorf("%s: unexpected parse error: %v", tc.name, err)
			continue
		}
		kb, buildErrs := BuildKnowledge([]*File{f}, testSchemas(t))
		errs := append(buildErrs, Validate(f, kb)...)
		if len(errs) == 0 {
			t.Errorf("%s: validation accepted invalid input", tc.name)
			continue
		}
		joined := ""
		for _, e := range errs {
			joined += e.Error() + "\n"
		}
		for _, m := range tc.mentions {
			if !strings.Contains(joined, m) {
				t.Errorf("%s: error %q does not mention %q", tc.name, joined, m)
			}
		}
	}
}

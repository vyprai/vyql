package vyql

import "testing"

const parserFixture = `module toy;
concept code.HttpInput : source { refines: code.UntrustedData taint: [UntrustedData] cwe: [CWE_20] }
concept code.SqlExecution : sink { vulnerable_to: [Injection] enabled_by: [UntrustedData] }
concept code.SqlParameterization : control { neutralizes: [Injection] }
concept code.AuthGate : control | guard { neutralizes: [MissingAuthorization] defends: [Idor] }
threat Injection { subsumes: [SqlInjection CommandInjection] }
adapter flask {
  meta { fidelity: resolved }
  source code.path("request.args.get") -> code.HttpInput
  sink "db.session.execute" where n.argc > 1 -> code.SqlExecution
  label code.func("helper") -> code.AuthGate
}
query tagged(x) { match (x: code.HttpInput) yield x or { match (x: code.HttpInput) yield x } }
rule SqlInjection {
  meta { id: "TOY-001" severity: high cwe: [CWE_89] confidence_floor: high }
  taint code.HttpInput -> code.SqlExecution -> finding unless sanitized_by code.SqlParameterization
}
rule DirectMatch {
  match (a: code.HttpInput), (b: code.SqlExecution) where a.depth > 2 and not b.checked -> signal
}
rule EdgeChain {
  match (x: code.HttpInput) -[:FLOWS]-> (y: code.Call) <-[:calls]- (z: code.SqlExecution)
    where x has code.Tainted -> finding unless guarded_by code.AuthGate
}
rule ReachSugar { reach code.HttpInput -> code.SqlExecution -> finding unless anchored }
rule PresentRule { present code.SqlParameterization -> signal }
`

func parseOrDie(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func TestParserConceptsThreatsAdaptersRules(t *testing.T) {
	f := parseOrDie(t, parserFixture)

	if f.Module != "toy" {
		t.Fatalf("module = %q", f.Module)
	}
	if len(f.Concepts) != 4 || len(f.Threats) != 1 || len(f.Adapters) != 1 ||
		len(f.Rules) != 5 || len(f.Queries) != 1 {
		t.Fatalf("counts: concepts=%d threats=%d adapters=%d rules=%d queries=%d",
			len(f.Concepts), len(f.Threats), len(f.Adapters), len(f.Rules), len(f.Queries))
	}

	c := f.Concepts[0]
	if c.Name != "code.HttpInput" || len(c.Kinds) != 1 || c.Kinds[0] != "source" ||
		c.Refines != "code.UntrustedData" || len(c.Taint) != 1 || c.Taint[0] != "UntrustedData" {
		t.Fatalf("concept 0 = %+v", c)
	}
	dual := f.Concepts[3]
	if dual.Name != "code.AuthGate" || len(dual.Kinds) != 2 || dual.Kinds[0] != "control" || dual.Kinds[1] != "guard" {
		t.Fatalf("dual-role concept = %+v", dual)
	}

	th := f.Threats[0]
	if th.Name != "Injection" || len(th.Subsumes) != 2 || th.Subsumes[1] != "CommandInjection" {
		t.Fatalf("threat = %+v", th)
	}

	a := f.Adapters[0]
	if a.Tech != "flask" || a.Fidelity != "resolved" || len(a.Bindings) != 3 {
		t.Fatalf("adapter = %+v", a)
	}
	b0, b1, b2 := a.Bindings[0], a.Bindings[1], a.Bindings[2]
	if b0.Keyword != "source" || b0.Concept != "code.HttpInput" {
		t.Fatalf("binding 0 = %+v", b0)
	}
	if call, ok := b0.Matcher.(*Call); !ok || call.Name != "code.path" || len(call.Args) != 1 {
		t.Fatalf("binding 0 matcher = %+v", b0.Matcher)
	}
	// Bare string sugar desugars to code.path("db.session.execute").
	if call, ok := b1.Matcher.(*Call); !ok || call.Name != "code.path" {
		t.Fatalf("string sugar not desugared: %+v", b1.Matcher)
	}
	if b1.Where == nil {
		t.Fatal("binding 1 where clause missing")
	}
	if b2.Keyword != "label" || b2.Concept != "code.AuthGate" {
		t.Fatalf("binding 2 = %+v", b2)
	}

	q := f.Queries[0]
	if q.Name != "tagged" || len(q.Params) != 1 || q.Params[0] != "x" || len(q.Alts) != 1 {
		t.Fatalf("query = %+v", q)
	}

	r := f.Rules[0]
	if r.Name != "SqlInjection" || r.Meta.ID != "TOY-001" || r.Meta.Severity != "high" ||
		r.Meta.ConfidenceFloor != "high" || len(r.Meta.CWE) != 1 {
		t.Fatalf("rule 0 meta = %+v", r.Meta)
	}
	if r.Body.Sugar == nil || r.Body.Sugar.Verb != "taint" ||
		r.Body.Sugar.From != "code.HttpInput" || r.Body.Sugar.To != "code.SqlExecution" {
		t.Fatalf("rule 0 sugar = %+v", r.Body.Sugar)
	}
	if r.Body.Emit != EmitFinding || r.Body.Unless == nil ||
		r.Body.Unless.Kind != "sanitized_by" || r.Body.Unless.Concept != "code.SqlParameterization" {
		t.Fatalf("rule 0 emit/unless = %+v %+v", r.Body.Emit, r.Body.Unless)
	}

	dm := f.Rules[1]
	if len(dm.Body.Match) != 2 || dm.Body.Match[0].Nodes[0].Var != "a" ||
		dm.Body.Match[1].Nodes[0].TypeOrConcept != "code.SqlExecution" || dm.Body.Where == nil ||
		dm.Body.Emit != EmitSignal {
		t.Fatalf("DirectMatch body = %+v", dm.Body)
	}

	ec := f.Rules[2].Body.Match[0]
	if len(ec.Nodes) != 3 || len(ec.Edges) != 2 || ec.Edges[0].Type != "FLOWS" ||
		!ec.Edges[1].Reverse || ec.Edges[1].Type != "calls" {
		t.Fatalf("edge chain pattern = %+v", ec)
	}
	if u := f.Rules[2].Body.Unless; u.Kind != "guarded_by" || u.Concept != "code.AuthGate" {
		t.Fatalf("guarded_by = %+v", u)
	}

	if rs := f.Rules[3].Body.Sugar; rs.Verb != "reach" {
		t.Fatalf("reach sugar = %+v", rs)
	}
	if ps := f.Rules[4].Body.Sugar; ps.Verb != "present" || ps.From != "code.SqlParameterization" || ps.To != "" {
		t.Fatalf("present sugar = %+v", ps)
	}
}

func TestParserRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"missing semicolon after module", "module toy concept A : source { }"},
		{"unclosed brace", "module toy; rule R { match (x: A)"},
		{"arrow without concept", "module toy; rule R { taint A -> -> finding }"},
		{"unknown statement keyword", "module toy; frobnicate x"},
		{"matcher not a call or string", "module toy; adapter t { source 42 -> A }"},
		{"emit missing", "module toy; rule R { taint A -> B }"},
		{"unless without verb", "module toy; rule R { taint A -> B -> signal unless }"},
		{"node pattern missing type", "module toy; rule R { match (x: ) -> finding }"},
		{"bad edge direction", "module toy; rule R { match (x: A) :FLOWS (y: B) -> finding }"},
	}
	for _, tc := range cases {
		_, err := Parse(tc.src)
		if err == nil {
			t.Errorf("%s: Parse accepted invalid input", tc.name)
			continue
		}
		if posPrefix(err) == "" {
			t.Errorf("%s: error lacks position: %v", tc.name, err)
		}
	}
}

// posPrefix reports "line:col:" when err carries a position.
func posPrefix(err error) string {
	s := err.Error()
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i+1]
		}
	}
	return ""
}

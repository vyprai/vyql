package parser

import "testing"

func TestV2LoweringToLegacyRuntimeDecls(t *testing.T) {
	decls := parseV2RuntimeFiles(t, `
module core;
concept SqlParameterization : check { neutralizes: [code.SqlExecution] }
`, `
module bindings.python.dbapi;
binding cursorExecuteQuery {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
  fidelity: resolved
  confidence: high
}
binding requestBody {
  query pattern callExpr where callee.path ~= "request.json"
  emit source code.HttpInput at call.result
}
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`, `
module rules.injection;
rule SqlInjection {
  meta { id: "VYQL-INJ-001" severity: high cwe: [CWE89] }
  taint code.HttpInput as input -> code.SqlExecution as sqlSink
  unless sqlSink.path coveredBy core.SqlParameterization
}
`)
	var adapter *AdapterDecl
	var rule *Rule
	var concept *ConceptDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
			adapter = x
		case *Rule:
			rule = x
		case *ConceptDecl:
			concept = x
		}
	}
	if concept == nil || concept.QualifiedName() != "core.SqlParameterization" || concept.Kind != "check" {
		t.Fatalf("concept lowering wrong: %+v", concept)
	}
	if adapter == nil || adapter.Name != "python" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Concept != "code.SqlExecution" || got.ArgIndex != 0 {
		t.Fatalf("sink lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "source" || got.Pattern != "request.json" || got.Concept != "code.HttpInput" {
		t.Fatalf("source lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "control_method" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" {
		t.Fatalf("check lowering wrong: %+v", got)
	}
	if rule == nil || rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("rule lowering wrong: %+v", rule)
	}
	flow := rule.Body.(*FlowStmt)
	if flow.Verb != "taint" || flow.Src.Concept != "code.HttpInput" || flow.Src.Binding != "input" || flow.Dst.Binding != "sqlSink" {
		t.Fatalf("flow lowering wrong: %+v", flow)
	}
	if sb, ok := rule.Clauses[0].Unless.(SanitizedBy); !ok || sb.Concept != "core.SqlParameterization" {
		t.Fatalf("coveredBy lowering wrong: %+v", rule.Clauses[0])
	}
}

func TestV2LoweringRejectsUnsupportedBindingShape(t *testing.T) {
	prog, err := ParseV2(`
module bindings.javascript.express;
binding unsupported {
  query pattern callExpr where args.count >= 2
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if _, err := LowerV2ToRuntime(prog); err == nil {
		t.Fatal("unsupported binding query lowered without diagnostic")
	}
}

func TestV2LoweringRejectsNonPathCoverage(t *testing.T) {
	prog, err := ParseV2(`
module bindings.java.xml;
binding parserHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers sameReceiver { anchor: callee.receiver }
  }
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if _, err := LowerV2ToRuntime(prog); err == nil {
		t.Fatal("sameReceiver check lowered without native coverage support")
	}
}

func TestV2LoweringRejectsNonPathCoveredByAndRuleMetadataClauses(t *testing.T) {
	cases := []string{
		`module rules.xml;
rule UnhardenedXmlParser {
  issue code.XmlParserCreate as parser
  unless parser.sameReceiver coveredBy core.XmlHardening
}`,
		`module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  with confidence >= high
}`,
		`module rules.injection;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
  require profile web
}`,
	}
	for _, src := range cases {
		prog, err := ParseV2(src)
		if err != nil {
			t.Fatalf("ParseV2: %v", err)
		}
		if _, err := LowerV2ToRuntime(prog); err == nil {
			t.Fatalf("unsupported rule clause lowered without diagnostic:\n%s", src)
		}
	}
}

func parseV2RuntimeFiles(t *testing.T, srcs ...string) []Decl {
	t.Helper()
	var out []Decl
	for _, src := range srcs {
		decls, err := ParseV2Runtime(src)
		if err != nil {
			t.Fatalf("ParseV2Runtime: %v", err)
		}
		out = append(out, decls...)
	}
	return out
}

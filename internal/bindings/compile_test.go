package bindings

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/parser"
)

// The compiler's tests, which lived in internal/parser because the compiler did.

func TestV2LoweringToScannerIRDecls(t *testing.T) {
	decls, sets := parseAndCompileIRFilesForTest(t, `
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
  query pattern callExpr where callee.method == "execute"
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
	adapter := firstBindingSetForTest(t, sets)
	var rule *parser.Rule
	var concept *parser.ConceptDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *parser.Rule:
			rule = x
		case *parser.ConceptDecl:
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
	if got := adapter.Mappings[0]; got.Fidelity != "resolved" || got.Confidence != "high" {
		t.Fatalf("binding evidence attrs not lowered: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "source" || got.Pattern != "request.json" || got.Concept != "code.HttpInput" {
		t.Fatalf("source lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "check_method_arg" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" || got.ArgIndex != 0 {
		t.Fatalf("check lowering wrong: %+v", got)
	}
	if rule == nil || rule.QualifiedName() != "rules.injection.SqlInjection" {
		t.Fatalf("rule lowering wrong: %+v", rule)
	}
	flow := rule.Body.(*parser.FlowStmt)
	if flow.Verb != "taint" || flow.Src.Concept != "code.HttpInput" || flow.Src.Binding != "input" || flow.Dst.Binding != "sqlSink" {
		t.Fatalf("flow lowering wrong: %+v", flow)
	}
	if sb, ok := rule.Clauses[0].Unless.(parser.PathCoveredBy); !ok || sb.Concept != "core.SqlParameterization" {
		t.Fatalf("coveredBy lowering wrong: %+v", rule.Clauses[0])
	}
}

func TestV2CoversV1AdapterCapabilityLedger(t *testing.T) {
	_, sets := parseAndCompileIRFilesForTest(t, `
module threat;
concept CharFilter : check {
  covers: [path]
  internalRoles: [char_filter]
}
`, `
module bindings.javascript.v1capability;
binding sourcePath {
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
binding sourceMethodReceiver {
  query pattern callExpr where callee.method == "getParameter" and callee.receiver.type == "Request"
  emit source code.HttpInput at call.result
}
binding sourceParam {
  query param as param
  emit source code.HttpInput at param
}
binding sinkMethodArg {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
}
binding sinkPathAny {
  query pattern callExpr where callee.path ~= "child_process.exec"
  emit sink code.CommandExecution at args.any
}
binding sinkReceiver {
  query pattern callExpr where callee.method == "openConnection"
  emit sink code.UrlFetch at callee.receiver
}
binding issueAtCall {
  query pattern callExpr where callee.method == "dangerous"
  emit issue code.AuthenticationRequiredOp at call
}
binding presenceIssue {
  query pattern presenceNode where node.kind == "any" and node.path ~= "Random" and node.token contains "seed" and not (node.token contains "SecureRandom")
  emit issue code.WeakRandomValue at node
}
binding checkPath {
  query pattern callExpr where callee.method == "escape"
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
binding checkEndpoint {
  query pattern callExpr where callee.path ~= "requireAuth"
  emit check core.AuthenticationCheck at call {
    covers endpoint { anchor: call }
  }
}
binding checkSameReceiver {
  query pattern callExpr where callee.method == "relative_to"
  emit check core.PathCanonicalization at callee.receiver {
    covers sameReceiver { anchor: callee.receiver }
  }
}
binding checkGlobal {
  query pattern callExpr where callee.method == "enableHardening"
  emit check core.XmlHardening at args[0] {
    covers global {}
  }
}
binding advisoryGuard {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "safe"
  emit check core.PathCanonicalization at call {
    advisory: true
    about: code.FilePathAccess
    covers dominates { from: call to: candidate }
  }
}
binding charFilter {
  query pattern callExpr where callee.method == "replace" and call.filter.global == true
  emit check threat.CharFilter at call {
    covers path { from: call to: candidate }
  }
}
binding packageScoped {
  requires {
    dependency("express", range: ">=4 <6")
    language("javascript")
    soft(import("express"))
  }
  query pattern callExpr where callee.method == "json"
  emit source code.HttpInput at call.result
}
binding typeFact {
  query pattern callExpr where callee.path ~= "sql.Open"
  emit fact runtime.ReceiverType at call.result {
    about: sql.DB
  }
}
binding localFact {
  query pattern callExpr where callee.method == "route"
  emit fact runtime.HttpRequest at args[0]
}
binding outParamFlow {
  query pattern callExpr where callee.method == "decode"
  propagate value from args[0] to args[1].pointee
}
binding identityFlow {
  query pattern callExpr where callee.method == "alias"
  propagate identity from args[0] to args[1].pointee
}
binding receiverFlow {
  query pattern callExpr where callee.method == "setOption"
  propagate receiver from callee.receiver to call.result
}
`)
	adapter := firstBindingSetForTest(t, sets)
	seen := map[string]Action{}
	for _, m := range adapter.Mappings {
		key := m.Kind
		switch {
		case strings.HasPrefix(m.Kind, "check") && m.Coverage != "":
			key += ":" + m.Coverage
		case strings.HasPrefix(m.Kind, "advisory_"):
			key = m.Kind
		case m.Kind == "flow_method":
			switch {
			case m.FlowReceiver:
				key += ":receiver"
			case m.FlowIdentity:
				key += ":identity"
			default:
				key += ":value"
			}
		}
		seen[key] = m
	}
	for _, want := range []string{
		"source", "source_receiver", "source_param",
		"sink_method", "sink_path", "sink_receiver",
		"issue_method", "presence_issue",
		"check_method_arg:path", "check:endpoint", "check_receiver_method:sameReceiver", "check_method_arg:global",
		"advisory_guard_method", "filter_method",
		"type", "fact_method_arg",
		"flow_method:value", "flow_method:identity", "flow_method:receiver",
	} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("v1 capability ledger missing lowered %s; mappings: %+v", want, adapter.Mappings)
		}
	}
	if got := seen["source_receiver"]; got.Pattern != "getParameter" || got.Constraint != "Request" {
		t.Fatalf("receiver-constrained source did not preserve method and type: %+v", got)
	}
	if got := seen["presence_issue"]; got.Flag == nil || len(got.Flag.Predicates) < 3 || got.Flag.Predicates[2].Negative != true {
		t.Fatalf("presence/flag predicates did not preserve positive and negative tests: %+v", got)
	}
	for _, m := range adapter.Mappings {
		if m.Pattern == "json" {
			if m.Requirement == nil || m.Requirement.Op != "all" || !stringSlicesEqual(m.Packages, []string{"express"}) {
				t.Fatalf("dependency/language/soft import requirement did not lower: %+v", m)
			}
		}
	}
}

func TestV2LoweringUsesLocalPatternWhere(t *testing.T) {
	sets := compileIRFilesForTest(t, `
module bindings.javascript.express;
pattern requestBodyCall as call {
  node: call
  bind callee = call.callee
  where callee.path ~= "req.body"
}
binding requestBody {
  query pattern requestBodyCall
  emit source code.HttpInput at call.result
}
`)
	adapter := firstBindingSetForTest(t, sets)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "req.body" || got.Concept != "code.HttpInput" {
		t.Fatalf("pattern where did not lower to source mapping: %+v", got)
	}
}

func TestV2LoweringRewritesPatternBindAliases(t *testing.T) {
	sets := compileIRFilesForTest(t, `
module bindings.javascript.sql;
pattern dbCall as call {
  node: call
  bind target = call.callee
}
binding execute {
  query pattern dbCall where target.method == "execute"
  emit sink code.SqlExecution at args[0]
}
`)
	adapter := firstBindingSetForTest(t, sets)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.ArgIndex != 0 {
		t.Fatalf("pattern bind alias did not lower to sink mapping: %+v", got)
	}
}

func TestV2LoweringAllowsImportedBuiltinCallExprPattern(t *testing.T) {
	sets := compileIRFilesForTest(t, `
module bindings.javascript.express;
uses patterns.javascript.callExpr as jsCall;
binding requestBody {
  query pattern jsCall where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`)
	adapter := firstBindingSetForTest(t, sets)
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %+v, want one", adapter.Mappings)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "req.body" {
		t.Fatalf("builtin imported callExpr pattern did not lower: %+v", got)
	}
}

func TestV2LoweringResolvesUsesAliasesToScannerIRConcepts(t *testing.T) {
	decls, sets := parseAndCompileIRFilesForTest(t, `
module bindings.javascript.express;
uses code.HttpInput as Input;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source Input at call.result
}
`, `
module rules.aliases;
uses code.HttpInput as Input;
uses code.SqlExecution as Exec;
uses core.SqlParameterization as Guard;
rule SqlInjectionAlias {
  taint Input as input -> Exec as sink
  unless sink.endpoint coveredBy Guard
  where sink is Exec
}
`)
	adapter := firstBindingSetForTest(t, sets)
	var rule *parser.Rule
	for _, d := range decls {
		if x, ok := d.(*parser.Rule); ok {
			rule = x
		}
	}
	if adapter == nil || len(adapter.Mappings) != 1 || adapter.Mappings[0].Concept != "code.HttpInput" {
		t.Fatalf("alias in binding did not lower to canonical concept: %+v", adapter)
	}
	if rule == nil {
		// The return is redundant after Fatalf and is there for the analyzer: without
		// it, every dereference below reads as a possible nil dereference.
		t.Fatalf("rule did not lower")
		return
	}
	flow := rule.Body.(*parser.FlowStmt)
	if flow.Src.Concept != "code.HttpInput" || flow.Dst.Concept != "code.SqlExecution" {
		t.Fatalf("alias in rule endpoints did not lower: %+v", flow)
	}
	if gb, ok := rule.Clauses[0].Unless.(parser.EndpointCoveredBy); !ok || gb.Concept != "core.SqlParameterization" {
		t.Fatalf("alias in coveredBy did not lower: %+v", rule.Clauses[0])
	}
	if is, ok := rule.Clauses[1].Where.(parser.Is); !ok || is.Concept != "code.SqlExecution" {
		t.Fatalf("alias in is did not lower: %+v", rule.Clauses[1].Where)
	}
}

func TestV2LoweringUsesBuiltinCoverageMechanicForCheckEmission(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.dbapi;
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute"
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	got := sets[0].Mappings[0]
	if got.Kind != "check_method_arg" || got.Coverage != "path" || got.ArgIndex != 0 {
		t.Fatalf("check emission did not lower with builtin coverage mechanic: %+v", got)
	}
	if got.CoverageDetail["from"] != "args[0]" || got.CoverageDetail["to"] != "call" {
		t.Fatalf("coverage metadata was not preserved: %+v", got.CoverageDetail)
	}
}

func TestParseV2DefinitionsCompilesV2BindingSet(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.dbapi;
binding cursorExecuteQuery {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("sets = %d, want 1", len(sets))
	}
	bindings := sets[0]
	if bindings.Name != "python" || len(bindings.Mappings) != 1 {
		t.Fatalf("binding compilation wrong: %+v", bindings)
	}
	if got := bindings.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Concept != "code.SqlExecution" {
		t.Fatalf("binding action compilation wrong: %+v", got)
	}
}

func TestParseV2DefinitionsRejectsV1FallbackAndMultipleModules(t *testing.T) {
	if _, err := compileV2BindingsForTest(`
adapter javascript {
  source "req.body" -> code.HttpInput
}
`); err == nil {
		t.Fatalf("parser.ParseV2Definitions accepted legacy adapter syntax")
	}

	if _, err := compileV2BindingsForTest(`
module code;
concept HttpInput : source {}

module bindings.javascript.express;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`); err == nil || !strings.Contains(err.Error(), "module declaration must appear once") {
		t.Fatalf("parser.ParseV2Definitions multi-module error = %v, want one-module rejection", err)
	}

	// Split across two sources it is accepted, and both halves come through: the concept
	// from the parser, the binding from the compiler.
	decls, sets := parseAndCompileIRFilesForTest(t, `module code;
concept HttpInput : source {}
`, `module bindings.javascript.express;
binding requestBody {
  query pattern callExpr where callee.path ~= "req.body"
  emit source code.HttpInput at call.result
}
`)
	concepts := 0
	for _, d := range decls {
		if _, ok := d.(*parser.ConceptDecl); ok {
			concepts++
		}
	}
	if concepts != 1 {
		t.Fatalf("concept declarations = %d, want 1", concepts)
	}
	if len(sets) != 1 || len(sets[0].Mappings) != 1 {
		t.Fatalf("compiled sets = %+v, want one set with one mapping", sets)
	}
}

func TestV2RequirementLowersToPackageHintsAndRequirementTree(t *testing.T) {
	cases := []struct {
		name     string
		req      string
		wantPkgs []string
		wantOp   string
	}{
		{
			name:     "dependency",
			req:      `dependency("express")`,
			wantPkgs: []string{"express"},
			wantOp:   "dependency",
		},
		{
			name:     "any dependency",
			req:      `any(dependency("express"), dependency("koa"), dependency("express"))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "any",
		},
		{
			name:     "all dependency",
			req:      `all(dependency("express"), dependency("koa"))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "all",
		},
		{
			name:     "dependency range",
			req:      `dependency("express", range: ">=4 <6")`,
			wantPkgs: []string{"express"},
			wantOp:   "dependency",
		},
		{
			name:     "import",
			req:      `import("express")`,
			wantPkgs: []string{"express"},
			wantOp:   "import",
		},
		{
			name:   "project fact",
			req:    `project.has("npm:publishable")`,
			wantOp: "project.has",
		},
		{
			name:     "soft nested any",
			req:      `soft(any(dependency("express"), import("koa")))`,
			wantPkgs: []string{"express", "koa"},
			wantOp:   "soft",
		},
		{
			name:     "multiple top-level requirements",
			req:      `dependency("express")` + "\n    " + `language("javascript")`,
			wantPkgs: []string{"express"},
			wantOp:   "all",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sets, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding requestBody {
  requires {
    ` + tc.req + `
  }
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
`)
			if err != nil {
				t.Fatalf("parser.ParseV2Definitions: %v", err)
			}
			adapter := sets[0]
			got := adapter.Mappings[0]
			if !stringSlicesEqual(got.Packages, tc.wantPkgs) {
				t.Fatalf("packages = %#v, want %#v", got.Packages, tc.wantPkgs)
			}
			if got.Requirement == nil || got.Requirement.Op != tc.wantOp {
				t.Fatalf("requirement = %#v, want op %q", got.Requirement, tc.wantOp)
			}
			if tc.name == "dependency range" && got.Requirement.Range != ">=4 <6" {
				t.Fatalf("requirement range = %q, want >=4 <6", got.Requirement.Range)
			}
		})
	}
}

func TestV2ArgAnySinkLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.bash.native;
binding catPath {
  query pattern callExpr where callee.path ~= "cat"
  emit sink code.FilePathAccess at args.any
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := firstBindingSetForTest(t, sets)
	if adapter.Name != "bash" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_path" || got.Pattern != "cat" || got.ArgIndex != -1 {
		t.Fatalf("arg-any sink lowering wrong: %+v", got)
	}
}

func TestV2ExactPathSinkLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
binding jqueryRoot {
  query pattern callExpr where callee.path == "$"
  emit sink code.HtmlRender at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := firstBindingSetForTest(t, sets)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_path" || got.Pattern != "$" || !got.Exact {
		t.Fatalf("exact sink lowering wrong: %+v", got)
	}
}

func TestV2AnalysisCallAliasLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.http;
binding controllerParam {
  query pattern callExpr where callee.analysis == "parameter.entry" and args.any.context.annotation contains "GetMapping" and not args.any.context.paramType contains "Parser"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := firstBindingSetForTest(t, sets)
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source" || got.Pattern != "analysis.parameter.entry" || got.ValMatches[0] != "annotation:GetMapping" || got.ValAbsents[0] != "param_type:Parser" {
		t.Fatalf("analysis alias lowering wrong: %+v", got)
	}
}

func TestV2MemberAccessPatternLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.dom;
pattern domValue as member {
  node: memberAccess
  where member.property == "value"
}
binding domValueSource {
  query pattern domValue
  emit source code.DomInput at member
}
binding secretAttr {
  query memberAccess as attr where attr.path ~= "config.secret"
  emit issue code.SecretValue at attr
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_method" || got.Pattern != "value" || got.NodeType != "code.Attr" {
		t.Fatalf("memberAccess property lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "issue" || got.Pattern != "config.secret" || got.NodeType != "code.Attr" {
		t.Fatalf("memberAccess path lowering wrong: %+v", got)
	}
}

func TestV2BinaryExprPatternLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.compare;
pattern equalityComparison as cmp {
  node: binaryExpr
  where cmp.operator in ["==", "==="]
}
binding secretComparison {
  query pattern equalityComparison
  emit issue code.SecretComparisonReview at cmp
}
binding weakCompare {
  query binaryExpr as op where op.op == "!="
  emit issue code.SecretComparisonReview at op
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "issue_method" || got.Pattern != "eq" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr equality lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "issue_method" || got.Pattern != "===" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr strict equality lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "issue_method" || got.Pattern != "ne" || got.NodeType != "code.BinOp" {
		t.Fatalf("binaryExpr inline lowering wrong: %+v", got)
	}
}

func TestV2AssignmentInlineQueryLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.assignments;
binding secretAssignment {
  query assignment as a where a.target contains "token" and a.value contains "secret"
  emit issue code.SecretValue at a
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "issue" || got.Pattern != "analysis.function.context" || !got.Exact || got.Concept != "code.SecretValue" {
		t.Fatalf("assignment mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 3 || got.ValMatches[0] != "assign:" || got.ValMatches[1] != "assign:token" || got.ValMatches[2] != "=secret" {
		t.Fatalf("assignment val predicates wrong: %+v", got.ValMatches)
	}
}

func TestV2AssignmentNegativeMembershipLowersToConjunctiveAbsence(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.assignments;
binding secretAssignment {
  query assignment as a where a.item not in ["viewer_scopes:CONFIG_READ", "guest_scopes:CONFIG_READ"]
  emit issue code.SecretValue at a
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	mappings := sets[0].Mappings
	if len(mappings) != 1 {
		t.Fatalf("mappings = %#v, want one conjunction with all absences", mappings)
	}
	got := mappings[0]
	if got.Kind != "issue" || got.Pattern != "analysis.function.context" || len(got.ValMatches) != 1 || got.ValMatches[0] != "assign:" {
		t.Fatalf("assignment not in mapping wrong: %+v", got)
	}
	if len(got.ValAbsents) != 2 || got.ValAbsents[0] != "assign_item:viewer_scopes:CONFIG_READ" || got.ValAbsents[1] != "assign_item:guest_scopes:CONFIG_READ" {
		t.Fatalf("assignment ValAbsents wrong: %+v", got.ValAbsents)
	}
}

func TestV2AssignmentPatternLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.assignments;
pattern secretAssignmentPattern as a {
  node: assignment
  where a.targetValue contains "config.secret"
}
binding secretAssignment {
  query pattern secretAssignmentPattern
  emit issue code.SecretValue at a
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "issue" || got.Pattern != "analysis.function.context" || !got.Exact || got.Concept != "code.SecretValue" {
		t.Fatalf("assignment pattern mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 2 || got.ValMatches[0] != "assign:" || got.ValMatches[1] != "assign:config.secret" {
		t.Fatalf("assignment pattern val predicates wrong: %+v", got.ValMatches)
	}
}

func TestV2ComposedSingleNodePatternLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
pattern evalCall as c {
  use callExpr as call
  where call.callee.method == "eval"
}
pattern secretMember as attr {
  use memberBase as member
  where member.path ~= "config.secret"
}
pattern memberBase as member {
  node: memberAccess
}
binding evalSink {
  query pattern evalCall
  emit sink code.CodeEval at args[0]
}
binding secretIssue {
  query pattern secretMember
  emit issue code.SecretValue at attr
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "sink_method" || got.Pattern != "eval" {
		t.Fatalf("composed call pattern lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "issue" || got.Pattern != "config.secret" || got.NodeType != "code.Attr" {
		t.Fatalf("composed member pattern lowering wrong: %+v", got)
	}
}

func TestV2CollectionSinkLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding subprocessCall {
  query pattern callExpr where callee.path ~= "subprocess.call"
  emit sink code.CommandExecution at args[0].collection[0]
}
binding writerow {
  query pattern callExpr where callee.method == "writerow"
  emit sink code.CsvCell at args[0].collection
}
binding execAll {
  query pattern callExpr where callee.path ~= "asyncio.create_subprocess_exec"
  emit sink code.CommandExecution at args.any.collection
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "python" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; !got.Collection || !got.CollectionFirst || got.CollectionIndex != 0 || got.ArgIndex != 0 {
		t.Fatalf("collection first lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; !got.Collection || got.CollectionFirst || got.ArgIndex != 0 {
		t.Fatalf("collection lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; !got.Collection || got.ArgIndex != -1 {
		t.Fatalf("arg-any collection lowering wrong: %+v", got)
	}
}

func TestV2ReceiverConstraintLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.native;
binding servletParam {
  query pattern callExpr where callee.method == "getParameter" and callee.receiver.type == "HttpServletRequest"
  emit source code.HttpInput at call.result
}
binding statementExecute {
  query pattern callExpr where callee.method == "execute" and callee.receiver.type == "java.sql.Statement"
  emit sink code.SqlExecution at args[0]
}
binding urlOpen {
  query pattern callExpr where callee.method == "openConnection"
  emit sink code.UrlFetch at callee.receiver
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_receiver" || got.Pattern != "getParameter" || got.Constraint != "HttpServletRequest" {
		t.Fatalf("source receiver lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "sink_method" || got.Pattern != "execute" || got.Constraint != "java.sql.Statement" {
		t.Fatalf("sink constraint lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "sink_receiver" || got.Pattern != "openConnection" {
		t.Fatalf("sink receiver lowering wrong: %+v", got)
	}
}

func TestV2CallPredicateInExpandsMappings(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlExecMethods {
  query pattern callExpr where callee.method in ["execute", "executeQuery"] and args.any.literal contains "SELECT"
  emit sink code.SqlExecution at args[0]
  emit check core.SqlParameterization at call {
    covers endpoint { anchor: call }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 4 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	want := []struct {
		kind    string
		pattern string
	}{
		{"sink_method", "execute"},
		{"check_method", "execute"},
		{"sink_method", "executeQuery"},
		{"check_method", "executeQuery"},
	}
	for i, w := range want {
		got := adapter.Mappings[i]
		if got.Kind != w.kind || got.Pattern != w.pattern || got.ValMatches[0] != "SELECT" {
			t.Fatalf("mapping %d = %+v, want kind=%s pattern=%s val SELECT", i, got, w.kind, w.pattern)
		}
	}
}

func TestV2BindingQueryEnclosesLiteralLowersToValueMatch(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlLiteralQuery {
  query call as c where c.callee.method == "query"
    encloses literal as lit where lit.value contains "SELECT" and not lit.raw contains "SafeQuery"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "query" {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 1 || got.ValMatches[0] != "SELECT" {
		t.Fatalf("ValMatches = %+v, want SELECT", got.ValMatches)
	}
	if len(got.ValAbsents) != 1 || got.ValAbsents[0] != "SafeQuery" {
		t.Fatalf("ValAbsents = %+v, want SafeQuery", got.ValAbsents)
	}
}

func TestV2BindingQueryEnclosesStringLiteralLowersToValueMatch(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlLiteralQuery {
  query call as c where c.callee.method == "query"
    encloses stringLiteral as lit where lit.value contains "SELECT"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "query" {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 1 || got.ValMatches[0] != "SELECT" {
		t.Fatalf("ValMatches = %+v, want SELECT", got.ValMatches)
	}
}

func TestV2BindingQueryContainsLiteralAfterWhereLowersToValueMatch(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlLiteralQuery {
  query call as c where c.callee.method == "query"
    contains literal as lit where lit.value contains "SELECT"
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "query" {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	if len(got.ValMatches) != 1 || got.ValMatches[0] != "SELECT" {
		t.Fatalf("ValMatches = %+v, want SELECT", got.ValMatches)
	}
}

func TestV2BindingQueryReferencesCallLowersToScopePredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
binding dangerAfterGuard {
  query call as c where c.callee.method == "danger" references call as other where other.callee.method == "safe"
  emit sink code.CommandExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "danger" || len(got.ScopePredicates) != 1 {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	pred := got.ScopePredicates[0]
	if pred.Subject != "scope_call" || pred.Property != "method" || len(pred.Values) != 1 || pred.Values[0] != "safe" {
		t.Fatalf("scope predicate wrong: %+v", pred)
	}
}

func TestV2BindingQueryDeclaredInCallLowersToScopePredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
binding dangerInHandler {
  query call as c where c.callee.method == "danger" declaredIn call as other where other.callee.path == "router.post"
  emit sink code.CommandExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "danger" || len(got.ScopePredicates) != 1 {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	pred := got.ScopePredicates[0]
	if pred.Subject != "scope_call" || pred.Property != "path" || !pred.Exact || len(pred.Values) != 1 || pred.Values[0] != "router.post" {
		t.Fatalf("scope predicate wrong: %+v", pred)
	}
}

func TestV2BindingQueryContainsCallLowersToScopePredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
binding dangerousHandler {
  query call as c where c.callee.method == "handler" contains call as inner where inner.callee.method == "danger"
  emit issue code.DynamicCodeLoad at c
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	got := sets[0].Mappings[0]
	if got.Kind != "issue_method" || got.Pattern != "handler" || len(got.ScopePredicates) != 1 {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	pred := got.ScopePredicates[0]
	if pred.Subject != "scope_call" || pred.Property != "method" || pred.Negative || len(pred.Values) != 1 || pred.Values[0] != "danger" {
		t.Fatalf("contains scope predicate wrong: %+v", pred)
	}
}

func TestV2BindingQueryEnclosesCallLowersToScopePredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
binding handlerUnderRoute {
  query call as c where c.callee.method == "handler" encloses call as outer where outer.callee.path == "router.post"
  emit fact code.PublicEndpoint at c
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	got := sets[0].Mappings[0]
	if got.Kind != "fact_method" || got.Pattern != "handler" || len(got.ScopePredicates) != 1 {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	pred := got.ScopePredicates[0]
	if pred.Subject != "scope_call" || pred.Property != "path" || !pred.Exact || pred.Negative || len(pred.Values) != 1 || pred.Values[0] != "router.post" {
		t.Fatalf("encloses scope predicate wrong: %+v", pred)
	}
}

func TestV2BindingQueryScopeCallNotInLowersToNegativeScopePredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
binding dangerWithoutGuard {
  query call as c where c.callee.method == "danger" references call as other where other.callee.method not in ["safe", "sanitize"]
  emit sink code.CommandExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	got := sets[0].Mappings[0]
	if got.Kind != "sink_method" || got.Pattern != "danger" || len(got.ScopePredicates) != 1 {
		t.Fatalf("relation mapping wrong: %+v", got)
	}
	pred := got.ScopePredicates[0]
	if pred.Subject != "scope_call" || pred.Property != "method" || !pred.Negative || len(pred.Values) != 2 || pred.Values[0] != "safe" || pred.Values[1] != "sanitize" {
		t.Fatalf("negative scope predicate wrong: %+v", pred)
	}
}

func TestV2CallPredicateOrExpandsWithSharedConstraints(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.web;
binding requestBodies {
  query pattern callExpr where (callee.path ~= "request.json" or callee.path ~= "request.get_json") and not args.any.literal contains "safe"
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "python" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	for i, want := range []string{"request.json", "request.get_json"} {
		got := adapter.Mappings[i]
		if got.Kind != "source" || got.Pattern != want || len(got.ValAbsents) != 1 || got.ValAbsents[0] != "safe" {
			t.Fatalf("mapping %d = %+v, want source %s with nval safe", i, got, want)
		}
	}
}

func TestV2PropagateValueTaintAndIdentityLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.c.native;
binding decodeOutParam {
  query call as c where c.callee.method == "decode"
  propagate value from c.args[0] to c.args[1].pointee
}
binding parseResult {
  query pattern callExpr where callee.path ~= "parse"
  propagate value from call.result to args[0].pointee
}
binding copyTaint {
  query pattern callExpr where callee.method == "copy"
  propagate taint from args[0] to args[1].pointee
}
binding aliasOutParam {
  query pattern callExpr where callee.method == "alias"
  propagate identity from args[0] to args[1].pointee
}
binding fluentBuilder {
  query pattern callExpr where callee.method == "setOption"
  propagate receiver from callee.receiver to call.result
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "c" || len(adapter.Mappings) != 5 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "flow_method" || got.Pattern != "decode" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 {
		t.Fatalf("arg-to-out-param propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "flow_path" || got.Pattern != "parse" || !got.FlowSourceResult || got.FlowSourceArg != -1 || got.FlowDestArg != 0 {
		t.Fatalf("result-to-out-param propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[2]; got.Kind != "flow_method" || got.Pattern != "copy" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 {
		t.Fatalf("taint propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[3]; got.Kind != "flow_method" || got.Pattern != "alias" || got.FlowSourceArg != 0 || got.FlowSourceResult || got.FlowDestArg != 1 || !got.FlowIdentity {
		t.Fatalf("identity propagation wrong: %+v", got)
	}
	if got := adapter.Mappings[4]; got.Kind != "flow_method" || got.Pattern != "setOption" || !got.FlowReceiver {
		t.Fatalf("receiver propagation wrong: %+v", got)
	}
}

func TestV2CallPredicateContainsAnyExpandsValueMatches(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlLiteralKinds {
  query pattern callExpr where callee.method == "query" and containsAny(args.any.literal, ["SELECT", "UPDATE"])
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	seen := map[string]bool{}
	for _, got := range adapter.Mappings {
		if got.Kind != "sink_method" || got.Pattern != "query" || len(got.ValMatches) != 1 {
			t.Fatalf("containsAny mapping wrong: %+v", got)
		}
		seen[got.ValMatches[0]] = true
	}
	if !seen["SELECT"] || !seen["UPDATE"] {
		t.Fatalf("containsAny values missing from mappings: %+v", seen)
	}
}

func TestV2CallPredicateContainsAnyRetainsAlternativesWithSharedValueConstraints(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.authorization;
binding correlatedOwnerRelation {
  query pattern callExpr where callee.analysis == "function.local.end"
    and args.any.literal contains "param_name:target_id"
    and args.any.literal contains ".query.get(target_id)"
    and args.any.literal contains "call_path:session.get"
    and containsAny(args.any.literal, ["target.owner", "target.owner_id", "target.company_id"])
    and not (containsAny(args.any.literal, ["abort(", "raise "]))
  emit issue code.SecretComparisonReview at call
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "python" || len(adapter.Mappings) != 3 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	seen := map[string]bool{}
	for _, got := range adapter.Mappings {
		if got.Kind != "issue" || got.Pattern != "analysis.function.local.end" || !got.Exact {
			t.Fatalf("call issue mapping wrong: %+v", got)
		}
		if len(got.ValMatches) != 4 || got.ValMatches[0] != "param_name:target_id" || got.ValMatches[1] != ".query.get(target_id)" || got.ValMatches[2] != "call_path:session.get" {
			t.Fatalf("shared value constraints missing: %+v", got.ValMatches)
		}
		seen[got.ValMatches[3]] = true
		if len(got.ValAbsents) != 2 || got.ValAbsents[0] != "abort(" || got.ValAbsents[1] != "raise " {
			t.Fatalf("shared value absences missing: %+v", got.ValAbsents)
		}
		if got.Requirement != nil {
			t.Fatalf("regular call mapping acquired a content requirement: %+v", got.Requirement)
		}
	}
	for _, want := range []string{"target.owner", "target.owner_id", "target.company_id"} {
		if !seen[want] {
			t.Fatalf("containsAny alternative %q missing from mappings: %+v", want, seen)
		}
	}
}

func TestV2CallPredicateNegatedContainsAnyLowersValueAbsents(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding unsafeLoader {
  query pattern callExpr where callee.path == "yaml.load" and not containsAny(args.any.literal, ["SafeLoader", "CSafeLoader"])
  emit sink code.Deserialization at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "sink_path" || got.Pattern != "yaml.load" || !got.Exact {
		t.Fatalf("negated containsAny mapping wrong: %+v", got)
	}
	if len(got.ValAbsents) != 2 || got.ValAbsents[0] != "SafeLoader" || got.ValAbsents[1] != "CSafeLoader" {
		t.Fatalf("ValAbsents = %+v, want SafeLoader and CSafeLoader", got.ValAbsents)
	}
}

func TestV2CallPredicateContainsAnyPrefixesContextValues(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.http;
binding routeParams {
  query pattern callExpr where callee.analysis == "parameter.entry" and containsAny(args.any.context.annotation, ["GetMapping", "PostMapping"])
  emit source code.HttpInput at call.result
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "java" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	seen := map[string]bool{}
	for _, got := range adapter.Mappings {
		if got.Kind != "source" || got.Pattern != "analysis.parameter.entry" || len(got.ValMatches) != 1 {
			t.Fatalf("context containsAny mapping wrong: %+v", got)
		}
		seen[got.ValMatches[0]] = true
	}
	if !seen["annotation:GetMapping"] || !seen["annotation:PostMapping"] {
		t.Fatalf("prefixed context values missing from mappings: %+v", seen)
	}
}

func TestV2ContainsAnySupportsNodeValueFields(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding sqlLiteral {
  query stringLiteral as lit where containsAny(lit.value, ["SELECT", "UPDATE"])
  emit issue code.SqlLiteral at lit
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	mappings := sets[0].Mappings
	if len(mappings) != 2 {
		t.Fatalf("mappings = %#v, want two value alternatives", mappings)
	}
	seen := map[string]bool{}
	for _, got := range mappings {
		if got.Kind != "issue" || got.NodeType != "code.Literal" || len(got.ValMatches) != 1 {
			t.Fatalf("literal containsAny mapping wrong: %+v", got)
		}
		seen[got.ValMatches[0]] = true
	}
	if !seen["SELECT"] || !seen["UPDATE"] {
		t.Fatalf("literal containsAny values missing from mappings: %+v", seen)
	}
}

func TestV2NodeValueNegativeMembershipLowersToConjunctiveAbsence(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.sql;
binding nonSqlLiteral {
  query stringLiteral as lit where lit.value not in ["SELECT", "UPDATE"]
  emit issue code.SqlLiteral at lit
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	mappings := sets[0].Mappings
	if len(mappings) != 1 {
		t.Fatalf("mappings = %#v, want one conjunction with all absences", mappings)
	}
	got := mappings[0]
	if got.Kind != "issue" || got.NodeType != "code.Literal" || len(got.ValAbsents) != 2 || got.ValAbsents[0] != "SELECT" || got.ValAbsents[1] != "UPDATE" {
		t.Fatalf("literal not in mapping wrong: %+v", got)
	}
}

func TestV2ContainsAnySupportsAssignmentTokenFields(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.assignments;
binding secretAssignment {
  query assignment as a where containsAny(a.item, ["viewer_scopes:CONFIG_READ", "guest_scopes:CONFIG_READ"])
  emit issue code.SecretValue at a
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	mappings := sets[0].Mappings
	if len(mappings) != 2 {
		t.Fatalf("mappings = %#v, want two assignment alternatives", mappings)
	}
	seen := map[string]bool{}
	for _, got := range mappings {
		if got.Kind != "issue" || got.Pattern != "analysis.function.context" || len(got.ValMatches) != 2 {
			t.Fatalf("assignment containsAny mapping wrong: %+v", got)
		}
		seen[got.ValMatches[1]] = true
	}
	if !seen["assign_item:viewer_scopes:CONFIG_READ"] || !seen["assign_item:guest_scopes:CONFIG_READ"] {
		t.Fatalf("assignment containsAny values missing from mappings: %+v", seen)
	}
}

func TestV2ReceiverTypeFactLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.go.native;
binding sqlOpenType {
  query pattern callExpr where callee.path ~= "sql.Open"
  emit fact runtime.ReceiverType at call.result {
    about: sql.DB
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "go" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "type" || got.Pattern != "sql.Open" || got.Concept != "sql.DB" {
		t.Fatalf("receiver type fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersToPresenceLabel(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.facts;
concept PublicEndpoint : fact {}
binding expressRoute {
  query pattern callExpr where callee.method == "get"
  emit fact PublicEndpoint at call
}
binding routerUse {
  query pattern callExpr where callee.path ~= "router.use"
  emit fact PublicEndpoint at call
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 2 {
		t.Fatalf("mappings = %d, want 2: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_method" || got.Pattern != "get" || got.Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("method fact lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "fact" || got.Pattern != "router.use" || got.Concept != "bindings.javascript.facts.PublicEndpoint" {
		t.Fatalf("path fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersArgumentLocation(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.facts;
concept RoutePath : fact {}
binding routeArg {
  query pattern callExpr where callee.method == "get"
  emit fact RoutePath at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_method_arg" || got.Pattern != "get" || got.Concept != "bindings.javascript.facts.RoutePath" || got.ArgIndex != 0 {
		t.Fatalf("argument fact lowering wrong: %+v", got)
	}
}

func TestV2FactEmitLowersArgsAnyLocation(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.facts;
concept RoutePart : fact {}
binding routeArgs {
  query pattern callExpr where callee.path ~= "router.route"
  emit fact RoutePart at args.any
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "fact_arg" || got.Pattern != "router.route" || got.Concept != "bindings.javascript.facts.RoutePart" || got.ArgIndex != -1 {
		t.Fatalf("args.any fact lowering wrong: %+v", got)
	}
}

func TestV2ValueGuardLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding yamlLoad {
  query pattern callExpr where callee.path == "yaml.load" and args.any.literal contains "Loader" and not args.any.literal contains "SafeLoader"
  emit sink code.Deserialization at args[0]
}
binding escapeSql {
  query pattern callExpr where callee.method == "escape" and args.any.literal contains "sql"
  emit check core.SqlParameterization at call {
    covers path {
      from: call
      to: call
    }
  }
}
binding unsafeMarker {
  query pattern callExpr where callee.path ~= "danger" and not args.any.literal contains "safe"
  emit issue code.DangerousCall at call
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 3 {
		t.Fatalf("adapter mappings = %d, want 3: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.ValMatches[0] != "Loader" || got.ValAbsents[0] != "SafeLoader" {
		t.Fatalf("sink value guards lost: %+v", got)
	}
	if got := adapter.Mappings[1]; got.ValMatches[0] != "sql" {
		t.Fatalf("check value guard lost: %+v", got)
	}
	if got := adapter.Mappings[2]; got.ValAbsents[0] != "safe" {
		t.Fatalf("issue value absence lost: %+v", got)
	}
}

func TestV2AdvisoryNeutralizerCheckLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding startsWithGuard {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.InputValidation at call {
    advisory: true
    about: code.FilePathAccess
    covers dominates {
      from: call
      to: call
    }
  }
}
binding normpathSanitizer {
  query pattern callExpr where callee.path ~= "os.path.normpath"
  emit check core.PathCanonicalization at call {
    advisory: true
    about: code.FilePathAccess
    covers path {
      from: call
      to: call
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 2 {
		t.Fatalf("adapter mappings = %d, want 2: %+v", len(adapter.Mappings), adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "advisory_guard_method" || got.Pattern != "startswith" || got.About != "code.FilePathAccess" || got.ValMatches[0] != "os.sep" {
		t.Fatalf("advisory guard lowering wrong: %+v", got)
	}
	if got := adapter.Mappings[1]; got.Kind != "advisory_sanitizer_path" || got.Pattern != "os.path.normpath" || got.About != "code.FilePathAccess" {
		t.Fatalf("advisory sanitizer lowering wrong: %+v", got)
	}
}

func TestV2AdvisoryCheckLowersToNonSuppressingMark(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding possiblePathValidation {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.PathCanonicalization at call {
    advisory: true
    about: code.FilePathAccess
    covers sameScope {
      anchor: call.scope
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "check_method" || got.Pattern != "startswith" || got.Concept != "core.PathCanonicalization" {
		t.Fatalf("advisory check lowering wrong: %+v", got)
	}
	if !got.Advisory || got.About != "code.FilePathAccess" || got.Coverage != "sameScope" {
		t.Fatalf("advisory metadata lost: %+v", got)
	}
}

func TestV2AdvisoryCheckLowersArgumentLocation(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding possiblePathValidation {
  query pattern callExpr where callee.method == "startswith" and args.any.literal contains "os.sep"
  emit check core.PathCanonicalization at args[0] {
    advisory: true
    about: code.FilePathAccess
    covers sameScope {
      anchor: call.scope
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "check_method_arg" || got.Pattern != "startswith" || got.Concept != "core.PathCanonicalization" || got.ArgIndex != 0 {
		t.Fatalf("argument advisory check lowering wrong: %+v", got)
	}
	if !got.Advisory || got.About != "code.FilePathAccess" || got.Coverage != "sameScope" {
		t.Fatalf("argument advisory metadata lost: %+v", got)
	}
}

func TestV2GlobalCheckLowersToExplicitGlobalEvidence(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding globalHardening {
  query pattern callExpr where callee.method == "enableHardening"
  emit check core.XmlHardening at call {
    covers global {}
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "check_method" || got.Pattern != "enableHardening" || got.Concept != "core.XmlHardening" || got.Coverage != "global" {
		t.Fatalf("global check lowering wrong: %+v", got)
	}
}

func TestV2GlobalCheckLowersArgumentLocation(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding globalHardening {
  query pattern callExpr where callee.method == "enableHardening"
  emit check core.XmlHardening at args[0] {
    covers global {}
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 1 {
		t.Fatalf("adapter mappings = %d, want 1: %+v", len(adapter.Mappings), adapter)
	}
	got := adapter.Mappings[0]
	if got.Kind != "check_method_arg" || got.Pattern != "enableHardening" || got.Concept != "core.XmlHardening" || got.Coverage != "global" || got.ArgIndex != 0 {
		t.Fatalf("argument global check lowering wrong: %+v", got)
	}
}

func TestV2ParamSourceLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.library.native;
binding externalEntryInput {
  query param as param
  emit source code.ExternalEntryInput at param
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "library" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "source_param" || got.Concept != "code.ExternalEntryInput" {
		t.Fatalf("param source lowering wrong: %+v", got)
	}
}

func TestV2ReceiverCheckLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.python.native;
binding relativeTo {
  query pattern callExpr where callee.method == "relative_to"
  emit check core.PathCanonicalization at callee.receiver {
    covers sameReceiver {
      anchor: callee.receiver
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "python" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "check_receiver_method" || got.Pattern != "relative_to" || got.Concept != "core.PathCanonicalization" {
		t.Fatalf("receiver check lowering wrong: %+v", got)
	}
}

func TestV2CharFilterCheckLowering(t *testing.T) {
	sets, err := compileV2BindingSourcesForTest(nil, []parser.V2DefinitionSource{
		{Name: "ontology/threat/char_filter.vyql", Source: `
module threat;
concept CharFilter : check {
  covers: [path]
  internalRoles: [char_filter]
}
`},
		{Name: "bindings/ruby/native.vyql", Source: `
module bindings.ruby.native;
binding gsubFilter {
  query pattern callExpr where callee.method == "gsub" and call.filter.global == true
  emit check threat.CharFilter at call {
    covers path {
      from: call
      to: call
    }
  }
}
`},
	})
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := firstBindingSetForTest(t, sets)
	if adapter.Name != "ruby" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "filter_method" || got.Pattern != "gsub" || got.Constraint != "global" {
		t.Fatalf("char filter lowering wrong: %+v", got)
	}
}

func TestV2NonGlobalCharFilterCheckLowering(t *testing.T) {
	sets, err := compileV2BindingSourcesForTest(nil, []parser.V2DefinitionSource{
		{Name: "ontology/threat/char_filter.vyql", Source: `
module threat;
concept CharFilter : check {
  covers: [path]
  internalRoles: [char_filter]
}
`},
		{Name: "bindings/javascript/native.vyql", Source: `
module bindings.javascript.native;
binding replaceFilter {
  query pattern callExpr where callee.method == "replace"
  emit check threat.CharFilter at call {
    covers path {
      from: call
      to: call
    }
  }
}
`},
	})
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := firstBindingSetForTest(t, sets)
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	if got := adapter.Mappings[0]; got.Kind != "filter_method" || got.Pattern != "replace" || got.Constraint != "" {
		t.Fatalf("non-global char filter lowering wrong: %+v", got)
	}
}

func TestV2PresenceNodeTokenAndKindLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.perl.native;
binding cleartextChannel {
  query pattern presenceNode where node.kind == "any" and node.analysis == "text_pattern.credential_literal" and node.context.literal contains "http://" and not (node.context.literal contains "127.0")
  emit issue code.CleartextChannel at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("sets = %d, want 1", len(sets))
	}
	adapter := sets[0]
	if adapter.Name != "perl" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	m := adapter.Mappings[0]
	if m.Kind != "presence_issue" || m.Concept != "code.CleartextChannel" || m.Flag == nil {
		t.Fatalf("presenceNode mapping wrong: %+v", m)
	}
	if m.Flag.NodeKind != "any" || len(m.Flag.Predicates) != 3 {
		t.Fatalf("presenceNode shape wrong: %+v", m.Flag)
	}
	if got := m.Flag.Predicates[0]; got.Property != "path" || got.Op != "match" || !got.Exact || got.Values[0] != "analysis.text_pattern.credential_literal" {
		t.Fatalf("analysis path predicate wrong: %+v", got)
	}
	if got := m.Flag.Predicates[2]; got.Property != "tokens" || got.Op != "contains" || !got.Negative || got.Values[0] != "literal:127.0" {
		t.Fatalf("negative context literal predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeContextFieldPrefixes(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
matcher sensitiveName {
  containsAny: ["token", "secret"]
}
binding contextFields {
  query pattern presenceNode where node.scope == "function" and node.context.language == "javascript" and containsAny(node.context.callPath, ["parseOut", "crypto.timingSafeEqual"]) and node.context.callArgAt contains "krb5_get_init_creds_password:7:NULL" and node.context.callArgShapeAt contains "krb5_get_init_creds_password:7:NULL" and node.context.selector contains "data.x-csrf-token" and node.context.identifier is sensitiveName and node.context.advisoryCwe == "CWE-444" and node.context.status == "vulnerable" and node.context.reachable == "true" and node.context.indexKind == "field_derived" and node.context.guard == "missing_upper_bound" and node.context.shellBridge == "python_triple_quote_stdin_interpolation" and node.context.startupOrder == "clearance_policy_before_adapter_start" and node.context.csrfValidation == "double_submit_missing_nonempty_guard" and node.context.redirectFlow == "checksum_error_uses_default_logout" and node.context.rsaPkcs1 == "digest_suffix_sha256" and node.context.portProtocol == "request_response_missing_correlation" and node.context.rubyReview == "tls_ca_file_without_verify_mode" and node.context.rustReview == "uninitialized_buffer_exposure" and node.context.pythonReview == "flask_hardcoded_secret_key" and node.context.template == "erb" and node.context.attr == "href" and node.context.erbValue == "url-like" and node.context.decoratorPath contains "require_POST" and containsAny(node.context.assignItem, ["viewer_scopes:CONFIG_READ", "guest_scopes:CONFIG_READ"]) and node.context.zeroStepSequenceRisk == "true" and node.context.convertSvgMultiSvgSanitizerBypass == "true" and node.context.incompleteGeneratedJsIdentifierReservedWords == "true" and node.context.ajaxBackslashProtocolRelativeUrlXss == "true"
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if flag.Scope != "function" || len(flag.Predicates) != 29 {
		t.Fatalf("flag predicates wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "lang=javascript" {
		t.Fatalf("language predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "call_path:parseOut" || got.Values[1] != "call_path:crypto.timingSafeEqual" {
		t.Fatalf("callPath predicate wrong: %+v", got)
	}
	if got := flag.Predicates[2]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "call_arg_at:krb5_get_init_creds_password:7:NULL" {
		t.Fatalf("callArgAt predicate wrong: %+v", got)
	}
	if got := flag.Predicates[3]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "call_arg_shape_at:krb5_get_init_creds_password:7:NULL" {
		t.Fatalf("callArgShapeAt predicate wrong: %+v", got)
	}
	if got := flag.Predicates[4]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "selector:data.x-csrf-token" {
		t.Fatalf("selector predicate wrong: %+v", got)
	}
	if got := flag.Predicates[5]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "identifier:token" || got.Values[1] != "identifier:secret" {
		t.Fatalf("matcher predicate wrong: %+v", got)
	}
	if got := flag.Predicates[6]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "advisory_cwe=CWE-444" {
		t.Fatalf("advisory CWE predicate wrong: %+v", got)
	}
	if got := flag.Predicates[7]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "status=vulnerable" {
		t.Fatalf("status predicate wrong: %+v", got)
	}
	if got := flag.Predicates[8]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "reachable=true" {
		t.Fatalf("reachable predicate wrong: %+v", got)
	}
	if got := flag.Predicates[9]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "index_kind=field_derived" {
		t.Fatalf("index kind predicate wrong: %+v", got)
	}
	if got := flag.Predicates[10]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "guard=missing_upper_bound" {
		t.Fatalf("guard predicate wrong: %+v", got)
	}
	if got := flag.Predicates[11]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "shell_bridge:python_triple_quote_stdin_interpolation" {
		t.Fatalf("shell bridge predicate wrong: %+v", got)
	}
	if got := flag.Predicates[12]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "startup_order:clearance_policy_before_adapter_start" {
		t.Fatalf("startup order predicate wrong: %+v", got)
	}
	if got := flag.Predicates[13]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "csrf_validation:double_submit_missing_nonempty_guard" {
		t.Fatalf("csrf validation predicate wrong: %+v", got)
	}
	if got := flag.Predicates[14]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "redirect_flow:checksum_error_uses_default_logout" {
		t.Fatalf("redirect flow predicate wrong: %+v", got)
	}
	if got := flag.Predicates[15]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "rsa_pkcs1:digest_suffix_sha256" {
		t.Fatalf("rsa pkcs1 predicate wrong: %+v", got)
	}
	if got := flag.Predicates[16]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "port_protocol:request_response_missing_correlation" {
		t.Fatalf("port protocol predicate wrong: %+v", got)
	}
	if got := flag.Predicates[17]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "ruby_review:tls_ca_file_without_verify_mode" {
		t.Fatalf("ruby review predicate wrong: %+v", got)
	}
	if got := flag.Predicates[18]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "rust_review:uninitialized_buffer_exposure" {
		t.Fatalf("rust review predicate wrong: %+v", got)
	}
	if got := flag.Predicates[19]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "python_review:flask_hardcoded_secret_key" {
		t.Fatalf("python review predicate wrong: %+v", got)
	}
	if got := flag.Predicates[20]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "template=erb" {
		t.Fatalf("template predicate wrong: %+v", got)
	}
	if got := flag.Predicates[21]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "attr=href" {
		t.Fatalf("attr predicate wrong: %+v", got)
	}
	if got := flag.Predicates[22]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "value=url-like" {
		t.Fatalf("ERB value predicate wrong: %+v", got)
	}
	if got := flag.Predicates[23]; got.Property != "tokens" || got.Op != "contains" || got.Values[0] != "decorator_path:require_POST" {
		t.Fatalf("decorator path predicate wrong: %+v", got)
	}
	if got := flag.Predicates[24]; got.Property != "tokens" || got.Op != "contains_any" || got.Values[0] != "assign_item:viewer_scopes:CONFIG_READ" || got.Values[1] != "assign_item:guest_scopes:CONFIG_READ" {
		t.Fatalf("assign item predicate wrong: %+v", got)
	}
	if got := flag.Predicates[25]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "zero_step_sequence_risk=true" {
		t.Fatalf("zero-step sequence risk predicate wrong: %+v", got)
	}
	if got := flag.Predicates[26]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "convert_svg_multi_svg_sanitizer_bypass=true" {
		t.Fatalf("convert-svg sanitizer bypass predicate wrong: %+v", got)
	}
	if got := flag.Predicates[27]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "incomplete_generated_js_identifier_reserved_words=true" {
		t.Fatalf("incomplete generated JS identifier reserved words predicate wrong: %+v", got)
	}
	if got := flag.Predicates[28]; got.Property != "tokens" || got.Op != "equals" || got.Values[0] != "ajax_backslash_protocol_relative_url_xss=true" {
		t.Fatalf("AJAX backslash URL predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeBoundaryTextOperators(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
binding boundaryFields {
  query pattern presenceNode where node.context.functionName startsWith "validate" and node.context.literal endsWith ".html"
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if len(flag.Predicates) != 2 {
		t.Fatalf("flag predicates wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "tokens" || got.Op != "starts_with" || got.Values[0] != "function_name:validate" {
		t.Fatalf("startsWith predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Property != "tokens" || got.Op != "ends_with" || got.Values[0] != "literal:.html" {
		t.Fatalf("endsWith predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeNonMembershipOperators(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
binding negativeFields {
  query pattern presenceNode where node.method != "safe" and node.context.language not in ["go", "python"]
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if len(flag.Predicates) != 2 {
		t.Fatalf("flag predicates wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "method" || got.Op != "equals" || !got.Negative || got.Values[0] != "safe" {
		t.Fatalf("!= predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Property != "tokens" || got.Op != "equals_any" || !got.Negative || got.Values[0] != "lang=go" || got.Values[1] != "lang=python" {
		t.Fatalf("not in predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeExistsOperator(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
binding presentFields {
  query pattern presenceNode where node.path exists and node.context.functionName exists
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if len(flag.Predicates) != 2 {
		t.Fatalf("flag predicates wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "path" || got.Op != "exists" || got.Negative || len(got.Values) != 0 {
		t.Fatalf("path exists predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Property != "tokens" || got.Op != "exists" || got.Negative || len(got.Values) != 1 || got.Values[0] != "function_name:" {
		t.Fatalf("context exists predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodePatternLowersToPresenceIssue(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.bash.crypto;
binding weakRandom {
  query pattern presenceNode where node.path ~= "RANDOM"
  emit issue code.WeakRandomValue at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "bash" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	m := adapter.Mappings[0]
	if m.Kind != "presence_issue" || m.Concept != "code.WeakRandomValue" || m.Flag == nil {
		t.Fatalf("presenceNode mapping wrong: %+v", m)
	}
	if m.Flag.NodeKind != "any" || len(m.Flag.Predicates) != 1 {
		t.Fatalf("presenceNode flag wrong: %+v", m.Flag)
	}
	if got := m.Flag.Predicates[0]; got.Subject != "node" || got.Property != "path" || got.Op != "match" || got.Exact || got.Values[0] != "RANDOM" {
		t.Fatalf("presenceNode path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeExactPathLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.dart.crypto;
binding weakRandom {
  query pattern presenceNode where node.path == "Random"
  emit issue code.WeakRandomValue at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if flag == nil || len(flag.Predicates) != 1 {
		t.Fatalf("presenceNode flag wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "path" || got.Op != "match" || !got.Exact || got.Values[0] != "Random" {
		t.Fatalf("presenceNode exact path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeMethodPackagesAndMultipleEmits(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.ruby.logging;
binding logWrite {
  requires {
    dependency("rails")
  }
  query pattern presenceNode where node.method == "warn"
  emit issue code.LogWrite at node
  emit sink code.LogOutput at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "ruby" || len(adapter.Mappings) != 2 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	for _, m := range adapter.Mappings {
		if (m.Kind != "presence_issue" && m.Kind != "presence_sink") || m.Flag == nil || len(m.Flag.Predicates) != 1 || len(m.Packages) != 1 || m.Packages[0] != "rails" {
			t.Fatalf("presenceNode mapping wrong: %+v", m)
		}
		if got := m.Flag.Predicates[0]; got.Subject != "node" || got.Property != "method" || got.Op != "equals" || got.Values[0] != "warn" {
			t.Fatalf("presenceNode method predicate wrong: %+v", got)
		}
	}
}

func TestV2PresenceNodePreservesAdvisoryCheckMetadata(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.go.memory;
binding memoryBounds {
  query pattern presenceNode where node.kind == "any" and node.path ~= "__binop.ne"
  emit check core.MemoryBoundsCheck at node {
    advisory: true
    about: code.BufferAccess
    covers sameScope {
      anchor: node
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	m := sets[0].Mappings[0]
	if m.Kind != "presence_check" || !m.Advisory || m.About != "code.BufferAccess" || m.Coverage != "sameScope" {
		t.Fatalf("presenceNode metadata not preserved: %+v", m)
	}
}

func TestV2ImportedPresenceNodePatternLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.lua.crypto;
uses patterns.core.presenceNode;
binding weakHash {
  query pattern presenceNode where node.path ~= "ngx.md5"
  emit issue code.WeakHash at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if flag == nil || len(flag.Predicates) != 1 {
		t.Fatalf("presenceNode import flag wrong: %+v", flag)
	}
	if got := flag.Predicates[0]; got.Property != "path" || got.Values[0] != "ngx.md5" {
		t.Fatalf("imported presenceNode path predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeOperandAndPseudoSubjectLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
matcher csrfHeaderName {
  equalsAny: ["x-csrf-token", "csrf-token"]
}
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and node.op in ["==", "==="] and not (containsAny(node.context.scopeCall, ["scmp", "timingSafeEqual"])) and operand(node, where: operand.path ~= "__binop.operand" and operand.identifier is secretTokenName and operand.key is csrfHeaderName)
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if adapter.Name != "javascript" || len(adapter.Mappings) != 1 {
		t.Fatalf("adapter lowering wrong: %+v", adapter)
	}
	flag := adapter.Mappings[0].Flag
	if flag == nil || flag.NodeKind != "binop" || len(flag.Operands) != 1 {
		t.Fatalf("flag lowering wrong: %+v", flag)
	}
	if got := flag.Predicates[1]; got.Subject != "scope_call" || got.Property != "any" || got.Op != "contains_any" || !got.Negative {
		t.Fatalf("scope_call predicate wrong: %+v", got)
	}
	if got := flag.Operands[0].Predicates[1]; got.Subject != "operand" || got.Property != "identifier" || got.Op != "contains_any" {
		t.Fatalf("operand predicate wrong: %+v", got)
	}
	if got := flag.Operands[0].Predicates[2]; got.Subject != "operand" || got.Property != "key" || got.Op != "equals_any" || got.Values[0] != "x-csrf-token" {
		t.Fatalf("operand matcher equality predicate wrong: %+v", got)
	}
}

func TestV2PresenceNodeMatcherImportsUseAliasesAndRejectUnimportedSimpleNames(t *testing.T) {
	sets, err := compileV2BindingSourcesForTest(nil, []parser.V2DefinitionSource{
		{Name: "patterns/javascript/matchers.vyql", Source: `
module patterns.javascript.matchers;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`},
		{Name: "bindings/javascript/native.vyql", Source: `
module bindings.javascript.native;
uses patterns.javascript.matchers.secretTokenName as SecretName;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is SecretName)
  emit issue code.SecretComparisonReview at node
}
`},
	})
	if err != nil {
		t.Fatalf("parser.ParseV2DefinitionSources: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if got := flag.Operands[0].Predicates[0]; got.Subject != "operand" || got.Property != "identifier" || got.Op != "contains_any" || got.Values[0] != "token" {
		t.Fatalf("imported matcher predicate wrong: %+v", got)
	}

	_, err = compileV2BindingSourcesForTest(nil, []parser.V2DefinitionSource{
		{Name: "patterns/javascript/matchers.vyql", Source: `
module patterns.javascript.matchers;
matcher secretTokenName {
  containsAny: ["token", "secret"]
}
`},
		{Name: "bindings/javascript/native.vyql", Source: `
module bindings.javascript.native;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is secretTokenName)
  emit issue code.SecretComparisonReview at node
}
`},
	})
	if err == nil || !strings.Contains(err.Error(), `unknown matcher "secretTokenName"`) {
		t.Fatalf("parser.ParseV2DefinitionSources error = %v, want unknown matcher diagnostic", err)
	}
}

func TestV2PresenceNodeContextScopeCallAndFlowToLowering(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.native;
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and not (containsAny(node.context.inScopeCall, [scmp])) and containsAny(node.flow_to.op, [return])
  emit issue code.SecretComparisonReview at node
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	flag := sets[0].Mappings[0].Flag
	if got := flag.Predicates[0]; got.Subject != "scope_call" || got.Property != "any" || !got.Negative {
		t.Fatalf("scope_call predicate wrong: %+v", got)
	}
	if got := flag.Predicates[1]; got.Subject != "flow_to" || got.Property != "op" {
		t.Fatalf("flow_to predicate wrong: %+v", got)
	}
}

func TestV2LoweringSupportsArgsCountBindingPredicate(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding executeWithParams {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	ad := sets[0]
	if len(ad.Mappings) != 1 {
		t.Fatalf("mappings = %#v, want one", ad.Mappings)
	}
	got := ad.Mappings[0]
	if got.Kind != "check_method_arg" || got.Pattern != "execute" || got.Concept != "core.SqlParameterization" || got.ArgIndex != 0 ||
		!got.ArgCountSet || got.ArgCountMin != 2 || got.ArgCountMax != -1 {
		t.Fatalf("args.count mapping = %#v, want arity-gated check_method_arg", got)
	}
}

func TestV2LoweringExpandsArgsCountInList(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding executeWithParamCounts {
  query pattern callExpr where callee.method == "execute" and args.count in [1, 3]
  emit sink code.SqlExecution at args[0]
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	mappings := sets[0].Mappings
	if len(mappings) != 2 {
		t.Fatalf("mappings = %#v, want two exact arity mappings", mappings)
	}
	got := []int{mappings[0].ArgCountMin, mappings[1].ArgCountMin}
	if got[0] != 1 || got[1] != 3 ||
		mappings[0].ArgCountMax != 1 || mappings[1].ArgCountMax != 3 {
		t.Fatalf("args.count in list mappings = %#v, want exact 1 and 3", mappings)
	}
}

func TestV2LoweringExpandsNegatedArgsCountPredicates(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want [][2]int
	}{
		{
			name: "not equal",
			expr: `args.count != 1`,
			want: [][2]int{{0, 0}, {2, -1}},
		},
		{
			name: "not in",
			expr: `args.count not in [1, 3]`,
			want: [][2]int{{0, 0}, {2, 2}, {4, -1}},
		},
		{
			name: "not comparison",
			expr: `not (args.count >= 2)`,
			want: [][2]int{{0, 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sets, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding executeWithNegatedParamCounts {
  query pattern callExpr where callee.method == "execute" and ` + tt.expr + `
  emit sink code.SqlExecution at args[0]
}
`)
			if err != nil {
				t.Fatalf("parser.ParseV2Definitions: %v", err)
			}
			mappings := sets[0].Mappings
			if len(mappings) != len(tt.want) {
				t.Fatalf("mappings = %#v, want %d arity intervals", mappings, len(tt.want))
			}
			for i, want := range tt.want {
				if !mappings[i].ArgCountSet || mappings[i].ArgCountMin != want[0] || mappings[i].ArgCountMax != want[1] {
					t.Fatalf("mapping %d = %#v, want args.count interval [%d, %d]", i, mappings[i], want[0], want[1])
				}
			}
		})
	}
}

func TestV2ConcreteCoverageChecksLowerWithExplicitCoverageMode(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.java.xml;
binding endpointHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers endpoint { anchor: call }
  }
}
binding sameReceiverHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers sameReceiver { anchor: callee.receiver }
  }
}
binding sameScopeHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers sameScope { anchor: call.scope }
  }
}
binding dominatingHardening {
  query pattern callExpr where callee.method == "setFeature"
  emit check core.XmlHardening at call {
    covers dominates { from: call to: candidate }
  }
}
binding releasingHardening {
  query pattern callExpr where callee.method == "close"
  emit check core.ResourceRelease at call {
    covers postDominates { from: call to: candidate }
  }
}
`)
	if err != nil {
		t.Fatalf("parser.ParseV2Definitions: %v", err)
	}
	adapter := sets[0]
	if len(adapter.Mappings) != 5 {
		t.Fatalf("adapter mappings = %d, want 5: %+v", len(adapter.Mappings), adapter)
	}
	want := map[string]bool{"endpoint": true, "sameReceiver": true, "sameScope": true, "dominates": true, "postDominates": true}
	for _, got := range adapter.Mappings {
		if got.Kind != "check_method" {
			t.Fatalf("coverage check lowering wrong: %+v", got)
		}
		if !want[got.Coverage] {
			t.Fatalf("unexpected or missing coverage mode in mapping: %+v", got)
		}
		switch got.Coverage {
		case "endpoint":
			if got.CoverageDetail["anchor"] != "call" {
				t.Fatalf("endpoint coverage detail = %#v, want anchor call", got.CoverageDetail)
			}
		case "sameReceiver":
			if got.CoverageDetail["anchor"] != "callee.receiver" {
				t.Fatalf("sameReceiver coverage detail = %#v, want anchor callee.receiver", got.CoverageDetail)
			}
		case "sameScope":
			if got.CoverageDetail["anchor"] != "call.scope" {
				t.Fatalf("sameScope coverage detail = %#v, want anchor call.scope", got.CoverageDetail)
			}
		case "dominates":
			if got.Pattern != "setFeature" || got.Concept != "core.XmlHardening" {
				t.Fatalf("dominates coverage check lowering wrong: %+v", got)
			}
			if got.CoverageDetail["from"] != "call" || got.CoverageDetail["to"] != "candidate" {
				t.Fatalf("dominates coverage detail = %#v, want from call/to candidate", got.CoverageDetail)
			}
		case "postDominates":
			if got.Pattern != "close" || got.Concept != "core.ResourceRelease" {
				t.Fatalf("postDominates coverage check lowering wrong: %+v", got)
			}
			if got.CoverageDetail["from"] != "call" || got.CoverageDetail["to"] != "candidate" {
				t.Fatalf("postDominates coverage detail = %#v, want from call/to candidate", got.CoverageDetail)
			}
		default:
			if got.Pattern != "setFeature" || got.Concept != "core.XmlHardening" {
				t.Fatalf("%s coverage check lowering wrong: %+v", got.Coverage, got)
			}
		}
		delete(want, got.Coverage)
	}
	if len(want) != 0 {
		t.Fatalf("missing coverage modes: %#v", want)
	}
}

func TestV2BindingMetadataLowersToScannerIRAdapterMeta(t *testing.T) {
	sets := compileIRFilesForTest(t, `
module bindings.textpattern.native;
pattern bindingMetadata {
  binding: {
    name: "textpattern"
    meta: {
      cross_language: true
      text_pattern_event: "analysis.text_pattern.credential_literal"
      text_pattern_extensions: [".go", ".py"]
    }
  }
}
`)
	if len(sets) != 1 {
		t.Fatalf("sets = %d, want metadata binding only", len(sets))
	}
	ad := sets[0]
	if ad.Name != "textpattern" || len(ad.Mappings) != 0 {
		t.Fatalf("binding metadata decl wrong: %+v", ad)
	}
	if ad.Meta["cross_language"] != true || ad.Meta["text_pattern_event"] != "analysis.text_pattern.credential_literal" {
		t.Fatalf("binding metadata missing: %+v", ad.Meta)
	}
	if got, ok := ad.Meta["text_pattern_extensions"].([]string); !ok || len(got) != 2 || got[1] != ".py" {
		t.Fatalf("binding metadata list wrong: %#v", ad.Meta["text_pattern_extensions"])
	}
}

func TestV2UnstableBindingMetadataRejected(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.textpattern.rejection;
pattern bindingMetadata {
  unstable: {
    owner: "test"
    reason: "unstable binding metadata"
    adapter: "textpattern"
    meta: {
      cross_language: true
    }
	}
}
`)
	if err == nil {
		t.Fatal("parser.ParseV2Definitions accepted unstable binding metadata")
	}
	if !strings.Contains(err.Error(), "unstable binding metadata must use stable binding item") {
		t.Fatalf("parser.ParseV2Definitions error = %v", err)
	}
}

func firstBindingSetForTest(t *testing.T, sets []*Set) *Set {
	t.Helper()
	if len(sets) == 0 {
		t.Fatal("expected a compiled binding set, got none")
	}
	return sets[0]
}

// --- harness -------------------------------------------------------------------
//
// The parser resolves the language and the compiler turns the result into actions, so
// every case here runs both steps. The core policy module is parsed but not compiled:
// bindings reference the confidence levels it declares.

func compileIRFilesForTest(t *testing.T, srcs ...string) []*Set {
	t.Helper()
	_, sets := parseAndCompileIRFilesForTest(t, srcs...)
	return sets
}

// parseAndCompileIRFilesForTest runs both passes over the same sources, for the cases that
// assert on a rule or concept alongside the binding it pairs with.
func parseAndCompileIRFilesForTest(t *testing.T, srcs ...string) ([]parser.Decl, []*Set) {
	t.Helper()
	sources := []parser.V2DefinitionSource{{Name: "policies/core.vyql", Source: v2CorePoliciesForFrontendTest}}
	keep := []bool{false}
	for i, src := range srcs {
		for _, raw := range parser.V2DefinitionSourcesFromText("test", src) {
			raw.Name = "test/module" + string(rune('A'+i)) + "/" + raw.Name
			sources = append(sources, raw)
			keep = append(keep, true)
		}
	}
	parsed := make([]parser.V2Source, 0, len(sources))
	for _, source := range sources {
		prog, err := parser.ParseV2(source.Source)
		if err != nil {
			t.Fatalf("parse %s: %v", source.Name, err)
		}
		parsed = append(parsed, parser.V2Source{Name: source.Name, Program: prog})
	}
	decls, err := parser.LowerV2SourcesSelected(parsed, keep)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	sets, err := CompileSources(parsed, keep)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return decls, sets
}

func compileV2BindingSourcesForTest(keep []bool, sources []parser.V2DefinitionSource) ([]*Set, error) {
	parsed := make([]parser.V2Source, 0, len(sources))
	for _, source := range sources {
		prog, err := parser.ParseV2(source.Source)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, parser.V2Source{Name: source.Name, Program: prog})
	}
	return CompileSources(parsed, keep)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRewriteV2PatternRefsUsesFirstPathSegment(t *testing.T) {
	expr := parser.V2BinaryExpr{
		Op: "and",
		Left: parser.V2BinaryExpr{
			Op:    "==",
			Left:  parser.V2RefExpr{Name: "target.method"},
			Right: parser.V2LiteralExpr{Value: "execute"},
		},
		Right: parser.V2BinaryExpr{
			Op:    "==",
			Left:  parser.V2RefExpr{Name: "targetExtra.method"},
			Right: parser.V2LiteralExpr{Value: "query"},
		},
	}
	got := rewriteV2PatternRefs(expr, map[string]string{
		"target":      "call.callee",
		"targetExtra": "call.extra",
	})
	and, ok := got.(parser.V2BinaryExpr)
	if !ok || and.Op != "and" {
		t.Fatalf("rewritten expression = %#v, want conjunction", got)
	}
	left := and.Left.(parser.V2BinaryExpr).Left.(parser.V2RefExpr)
	right := and.Right.(parser.V2BinaryExpr).Left.(parser.V2RefExpr)
	if left.Name != "call.callee.method" || right.Name != "call.extra.method" {
		t.Fatalf("rewritten refs = %q, %q", left.Name, right.Name)
	}
}

func TestV2CallPredicateExpansionBudget(t *testing.T) {
	longList := func(prefix string, n int) string {
		values := make([]string, 0, n)
		for i := 0; i < n; i++ {
			values = append(values, fmt.Sprintf("%q", fmt.Sprintf("%s%d", prefix, i)))
		}
		return "[" + strings.Join(values, ", ") + "]"
	}
	intList := func(n int) string {
		values := make([]string, 0, n)
		for i := 0; i < n; i++ {
			values = append(values, fmt.Sprintf("%d", i))
		}
		return "[" + strings.Join(values, ", ") + "]"
	}
	manyMethods := longList("method", maxV2CallShapeExpansion+1)
	if _, err := compileV2BindingsForTest(`
module bindings.javascript.generated;
binding tooManyMethods {
  query pattern callExpr where callee.method in ` + manyMethods + `
  emit sink code.CommandExecution at args[0]
}
`); err == nil || !strings.Contains(err.Error(), "query predicate expansion for callee.method produced 257 call shapes, limit 256") {
		t.Fatalf("oversized callee list error = %v", err)
	}

	seventeenMethods := longList("m", 17)
	seventeenCounts := intList(17)
	if _, err := compileV2BindingsForTest(`
module bindings.javascript.generated;
binding cartesian {
  query pattern callExpr where callee.method in ` + seventeenMethods + ` and args.count in ` + seventeenCounts + `
  emit sink code.CommandExecution at args[0]
}
`); err == nil || !strings.Contains(err.Error(), "query predicate expansion for and produced 289 call shapes, limit 256") {
		t.Fatalf("cartesian expansion error = %v", err)
	}
}

// The shape diagnostic belongs to the compiler: a binding query with no callee predicate
// parses fine and fails when something tries to turn it into an action.
func TestV2LoweringRejectsUnsupportedBindingShape(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding unsupported {
  query pattern callExpr where args.count >= 2
  emit sink code.SqlExecution at args[0]
}
`)
	if err == nil || !strings.Contains(err.Error(), "needs a callee.method/path predicate") {
		t.Fatalf("unsupported binding query error = %v, want callee predicate diagnostic", err)
	}
}

// Diagnostics the compiler raises. These asserted against the parser's lowering pass while
// binding compilation lived there; the message and the input are unchanged.
func TestV2LoweringRejectsMissingCustomPattern(t *testing.T) {
	prog, err := parser.ParseV2(`
module bindings.javascript.routes;
binding routeSource {
  query pattern routeExpr where route.path ~= "/user"
  emit source code.HttpInput at route
}
`)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	_, err = compileV2BindingProgramForTest(prog)
	if err == nil || !strings.Contains(err.Error(), "pattern routeExpr is not declared") {
		t.Fatalf("lowerV2ProgramToDeclarations error = %v, want missing pattern diagnostic", err)
	}
}

func TestV2RequirementLoweringRejectsMalformedCombinators(t *testing.T) {
	cases := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "empty any",
			req:  `any()`,
			want: "at least one child",
		},
		{
			name: "empty all",
			req:  `all()`,
			want: "at least one child",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileV2BindingsForTest(`
module bindings.javascript.express;
binding requestBody {
  requires {
    ` + tc.req + `
  }
  query pattern callExpr where callee.path ~= "request.body"
  emit source code.HttpInput at call.result
}
`)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseV2Definitions error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestV2ComposedMultiNodePatternNeedsNativeLowering(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.javascript.composed;
pattern routeCall as call {
  node: call
  where callee.method == "get"
}
pattern handlerFunction as fn {
  node: function
  where name == "handler"
}
pattern routeHandler as route {
  use routeCall as routeCall
  use handlerFunction as handler
}
binding publicHandler {
  query pattern routeHandler
  emit fact code.PublicEndpoint at route
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions accepted multi-node pattern composition")
	}
	if !strings.Contains(err.Error(), "multi-node pattern composition needs native pattern lowering") {
		t.Fatalf("ParseV2Definitions error = %v, want multi-node composition diagnostic", err)
	}
}

func TestV2ComposedPatternCycleRejected(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.javascript.bad;
pattern a {
  use b as b
}
pattern b {
  use a as a
}
binding bad {
  query pattern a
  emit sink code.CodeEval at args[0]
}
`)
	if err == nil {
		t.Fatal("ParseV2Definitions succeeded for cyclic pattern use")
	}
	if !strings.Contains(err.Error(), "cyclic use") {
		t.Fatalf("error = %v, want cyclic use diagnostic", err)
	}
}

func TestV2LoweringRejectsStagedRouteAndConfigFamiliesUntilRuntimeSchemaExists(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family string
		query  string
	}{
		{
			name:   "route",
			family: "route",
			query:  `query route as r where r.public == true`,
		},
		{
			name:   "config",
			family: "config",
			query:  `query config as c where c.key == "secret"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileV2BindingsForTest(`
module bindings.javascript.staged;
concept Input : source {}
binding stagedInput {
  requires {
    schema("nir", "2.0")
  }
  ` + tc.query + `
  emit source Input at node
}
`)
			if err == nil {
				t.Fatalf("ParseV2Definitions accepted staged %s query family", tc.family)
			}
			want := `query family "` + tc.family + `" requires native runtime schema("nir", "2.0") lowering`
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("ParseV2Definitions error = %v, want %q", err, want)
			}
		})
	}
}

func TestV2PropagateValueRejectsUnsupportedShape(t *testing.T) {
	cases := []string{
		`propagate receiver from args[0] to args[1].pointee`,
		`propagate value from args[0].field to args[1].pointee`,
		`propagate value from args[0] to call.result`,
	}
	for _, output := range cases {
		_, err := compileV2BindingsForTest(`
module bindings.c.native;
binding badFlow {
  query pattern callExpr where callee.method == "decode"
  ` + output + `
}
`)
		if err == nil {
			t.Fatalf("unsupported propagation lowered without diagnostic: %s", output)
		}
	}
}

func TestV2PresenceNodeRejectsUnknownPredicates(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.javascript.web;
binding unsupported {
  query pattern presenceNode where node.receiver == "req"
  emit issue code.SecretValue at node
}
`)
	if err == nil {
		t.Fatal("presenceNode lowered unsupported predicate")
	}
	if !strings.Contains(err.Error(), `unsupported predicate field "receiver"`) {
		t.Fatalf("presenceNode error = %v", err)
	}
}

func TestV2PresenceNodeRejectsRegexMatcherInvocationUntilScannerSupport(t *testing.T) {
	_, err := compileV2BindingsForTest(`
module bindings.javascript.native;
matcher riskyName {
  matches: "token|secret"
}
binding secretCompare {
  query pattern presenceNode where node.kind == "binop" and operand(node, where: operand.identifier is riskyName)
  emit issue code.SecretComparisonReview at node
}
`)
	if err == nil || !strings.Contains(err.Error(), "regex matcher invocation requires reviewed scanner support") {
		t.Fatalf("ParseV2Definitions error = %v, want regex matcher diagnostic", err)
	}
}

// compileV2BindingProgramForTest compiles one already-parsed program, for the cases that
// need to hand the compiler a program the parser accepted.
func compileV2BindingProgramForTest(prog *parser.V2Program) ([]*Set, error) {
	return CompileSources([]parser.V2Source{{Name: "test.vyql", Program: prog}}, nil)
}

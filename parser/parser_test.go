package parser

import "testing"

// Mirrors the Python parser smoke test: every docs/05 rule form parses.
// VyQL conventions: `module <ns>;` declares the namespace, rule
// names are short PascalCase, concepts are qualified cross-module refs,
// CWE refs are CWE_NNN, states are PascalCase.
const program = `
module vypr.injection;

rule Sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE_89], owasp: ["A03:2021"] }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}

module vypr.cloud;

rule PublicDatabase {
  meta { id: "VYQL-CLD-003", severity: critical }
  reach cloud.Internet -> cloud.Database
  where cloud.Database holds_asset_kind [data.CustomerData, data.Pii]
}
rule UnencryptedStorage {
  match cloud.Storage as s
  where not s has core.EncryptionAtRest
  unless guarded_by core.CompensatingEncryption
}

module vypr.identity;

rule ExternalToAdmin { assume identity.ExternalPrincipal -> identity.AdminPrivilege }
rule ToxicCombinationLateral {
  match identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}

module vypr.bizlogic;

rule UnauthorizedRefund {
  match business.Refund as a
  where a.actor is identity.User and a.resource is business.Order
  unless guarded_by core.OwnershipCheck
}
state_machine Order {
  states [Created, Paid, Shipped, Refunded]
  initial Created
  transition Created -> Paid
  transition Paid -> Shipped
  transition Paid -> Refunded
}
rule InvalidRefundTransition {
  match transition * -> Refunded on Order as t
  unless t.from == Paid
}
`

func TestParseAllForms(t *testing.T) {
	decls, err := Parse(program)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(decls) != 8 {
		t.Fatalf("expected 8 declarations, got %d", len(decls))
	}

	// rule 1: taint flow + sanitized_by
	r0 := decls[0].(*Rule)
	if r0.Name != "Sql" || r0.Package != "vypr.injection" || r0.QualifiedName() != "vypr.injection.Sql" {
		t.Fatalf("rule 0 naming wrong: name=%q pkg=%q qn=%q", r0.Name, r0.Package, r0.QualifiedName())
	}
	if r0.Meta["id"] != "VYQL-INJ-001" {
		t.Fatalf("rule 0 meta wrong: %+v", r0.Meta)
	}
	if cwe, ok := r0.Meta["cwe"].([]string); !ok || cwe[0] != "CWE_89" {
		t.Fatalf("rule 0 cwe wrong: %v", r0.Meta["cwe"])
	}
	fs := r0.Body.(*FlowStmt)
	if fs.Verb != "taint" || fs.Src.Concept != "code.HttpInput" || fs.Dst.Concept != "code.SqlExecution" {
		t.Fatalf("rule 0 flow wrong: %+v", fs)
	}
	if sb, ok := r0.Clauses[0].Unless.(SanitizedBy); !ok || sb.Concept != "core.SqlParameterization" {
		t.Fatalf("rule 0 unless wrong: %+v", r0.Clauses[0].Unless)
	}

	// rule 2: reach + holds_asset_kind where
	r1 := decls[1].(*Rule)
	wexpr := r1.Clauses[0].Where.(HoldsAssetKind)
	if len(wexpr.Kinds) != 2 || wexpr.Kinds[1] != "data.Pii" {
		t.Fatalf("rule 1 holds_asset_kind wrong: %+v", wexpr)
	}

	// toxic combination: where with two solver calls joined by `and` (decls[4])
	rtox := decls[4].(*Rule)
	if rtox.QualifiedName() != "vypr.identity.ToxicCombinationLateral" {
		t.Fatalf("toxic rule qualified name wrong: %q", rtox.QualifiedName())
	}
	andExpr, ok := rtox.Clauses[0].Where.(And)
	if !ok || len(andExpr.Parts) != 2 {
		t.Fatalf("toxic where should be And of 2, got %+v", rtox.Clauses[0].Where)
	}
	sc := andExpr.Parts[0].(SolverCall)
	if sc.Verb != "reach" || sc.Args[1].Ref.String() != "w.workload" {
		t.Fatalf("toxic solver call wrong: %+v", sc)
	}

	// state machine
	sm := decls[6].(*StateMachine)
	if sm.Name != "Order" || len(sm.States) != 4 || len(sm.Transitions) != 3 {
		t.Fatalf("state machine wrong: %+v", sm)
	}
	if sm.Transitions[2] != [2]string{"Paid", "Refunded"} {
		t.Fatalf("transition wrong: %+v", sm.Transitions)
	}

	// transition match rule with `unless expr` (t.from == Paid)
	r7 := decls[7].(*Rule)
	m := r7.Body.(*MatchStmt)
	if m.TargetKind != "transition" || m.FromState != "*" || m.ToState != "Refunded" || m.Machine != "Order" {
		t.Fatalf("transition match wrong: %+v", m)
	}
	ee := r7.Clauses[0].Unless.(ExprException)
	cmp := ee.Expr.(Cmp)
	if cmp.Ref.String() != "t.from" || cmp.Op != "==" || cmp.Value != "Paid" {
		t.Fatalf("transition unless cmp wrong: %+v", cmp)
	}
}

// Namespacing via a `module` declaration: short rule names within the module;
// cross-module concept refs stay qualified.
func TestModuleDecl(t *testing.T) {
	src := `
module vypr.injection;

rule Sql {
  meta { id: "VYQL-INJ-001" }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
rule Command {
  taint code.HttpInput -> code.CommandExecution
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(decls))
	}
	r := decls[0].(*Rule)
	if r.Name != "Sql" || r.Package != "vypr.injection" {
		t.Fatalf("package context wrong: name=%q pkg=%q", r.Name, r.Package)
	}
	if r.QualifiedName() != "vypr.injection.Sql" {
		t.Fatalf("qualified name wrong: %q", r.QualifiedName())
	}
	if decls[1].(*Rule).QualifiedName() != "vypr.injection.Command" {
		t.Fatalf("second rule qualified name wrong: %q", decls[1].(*Rule).QualifiedName())
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`rule x { taint A -> }`,             // missing endpoint
		`rule x { meta { id "no-colon" } }`, // missing colon
		`rule`,                              // truncated
		`gibberish foo`,                     // bad top-level
	}
	for _, src := range bad {
		if _, err := Parse(src); err == nil {
			t.Fatalf("expected parse error for %q", src)
		}
	}
}

// The adapter + threat declarations (docs/05/07) parse into the right AST.
func TestParseAdapterAndThreatDecls(t *testing.T) {
	src := `
module injection;
threat SqlInjection { cwe: [CWE_89], desc: "Untrusted data in a SQL command" }

adapter python {
  meta { fidelity: resolved }
  source "request.form" -> code.HttpInput
  source path "request.cookies" -> code.Cookie
  source receiver "body" on "express.Request" -> code.HttpInput
  sink method "execute" -> code.SqlExecution
  sink path "os.system" -> code.CommandExecution
  sink receiver "openConnection" -> code.UrlFetch
  mark method "setAllowsAnyHTTPSCertificate" val "true" -> code.CertValidationDisabled
  mark exact "Random" -> code.WeakRandomValue
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var ad *AdapterDecl
	var th *ThreatDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
			ad = x
		case *ThreatDecl:
			th = x
		}
	}
	if th == nil || th.QualifiedName() != "injection.SqlInjection" {
		t.Fatalf("threat decl not parsed: %+v", th)
	}
	if ad == nil || ad.Name != "python" || len(ad.Mappings) != 8 {
		t.Fatalf("adapter decl not parsed: %+v", ad)
	}
	if ad.Mappings[0].Kind != "source" || ad.Mappings[0].Concept != "code.HttpInput" {
		t.Fatalf("source mapping wrong: %+v", ad.Mappings[0])
	}
	if ad.Mappings[1].Kind != "source" || ad.Mappings[1].Pattern != "request.cookies" || ad.Mappings[1].Concept != "code.Cookie" {
		t.Fatalf("source path mapping wrong: %+v", ad.Mappings[1])
	}
	if ad.Mappings[2].Kind != "source_receiver" || ad.Mappings[2].Constraint != "express.Request" {
		t.Fatalf("source_receiver mapping wrong: %+v", ad.Mappings[2])
	}
	if ad.Mappings[3].Kind != "sink_method" || ad.Mappings[4].Kind != "sink_path" {
		t.Fatalf("sink mapping kinds wrong: %+v", ad.Mappings[3:])
	}
	if ad.Mappings[5].Kind != "sink_receiver" || ad.Mappings[5].Concept != "code.UrlFetch" {
		t.Fatalf("sink_receiver mapping wrong: %+v", ad.Mappings[5])
	}
	if ad.Mappings[6].Kind != "mark_method" || ad.Mappings[6].Pattern != "setAllowsAnyHTTPSCertificate" ||
		ad.Mappings[6].Concept != "code.CertValidationDisabled" || len(ad.Mappings[6].ValMatches) != 1 {
		t.Fatalf("mark_method mapping wrong: %+v", ad.Mappings[6])
	}
	if ad.Mappings[7].Kind != "mark" || !ad.Mappings[7].Exact || ad.Mappings[7].Pattern != "Random" {
		t.Fatalf("mark exact mapping wrong: %+v", ad.Mappings[7])
	}
}

func TestConceptImportsResolveInRulesAndAdapters(t *testing.T) {
	src := `
import code.{HttpInput, SqlExecution, FilePathAccess};
import core.SqlParameterization as SqlParam;
import core.*;

adapter python {
  source "request.form" -> HttpInput
  sink method "execute" -> SqlExecution
  package "pg" {
    sink method "raw" -> SqlExecution
  }
  control "bind" -> SqlParam
  assume guard method "startsWith" -> FilePathAccess
}

rule Sql {
  taint HttpInput -> SqlExecution
  unless sanitized_by SqlParam
}

rule Storage {
  match Storage as s
  unless guarded_by EncryptionAtRest
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad := decls[0].(*AdapterDecl)
	if got := ad.Mappings[0].Concept; got != "code.HttpInput" {
		t.Fatalf("source import = %q", got)
	}
	if got := ad.Mappings[1].Concept; got != "code.SqlExecution" {
		t.Fatalf("sink import = %q", got)
	}
	if got := ad.Mappings[2].Packages; len(got) != 1 || got[0] != "pg" {
		t.Fatalf("package gate = %#v", got)
	}
	if got := ad.Mappings[3].Concept; got != "core.SqlParameterization" {
		t.Fatalf("alias import = %q", got)
	}
	if got := ad.Mappings[4].About; got != "code.FilePathAccess" {
		t.Fatalf("assume target import = %q", got)
	}
	sql := decls[1].(*Rule)
	fs := sql.Body.(*FlowStmt)
	if fs.Src.Concept != "code.HttpInput" || fs.Dst.Concept != "code.SqlExecution" {
		t.Fatalf("rule endpoint imports wrong: %+v", fs)
	}
	if sb := sql.Clauses[0].Unless.(SanitizedBy); sb.Concept != "core.SqlParameterization" {
		t.Fatalf("rule alias import wrong: %+v", sb)
	}
	storage := decls[2].(*Rule)
	if m := storage.Body.(*MatchStmt); m.Concept != "core.Storage" {
		t.Fatalf("wildcard match import wrong: %+v", m)
	}
	if gb := storage.Clauses[0].Unless.(GuardedBy); gb.Concept != "core.EncryptionAtRest" {
		t.Fatalf("wildcard guard import wrong: %+v", gb)
	}
}

// String literals support backslash escapes: \" keeps a quote inside the string
// (without ending it), \\ a literal backslash, and \n/\t/\r the usual whitespace.
// The escape-free fast path must return the raw text unchanged.
func TestLexStringEscapes(t *testing.T) {
	cases := []struct{ src, want string }{
		{`"plain"`, "plain"},             // fast path, no escapes
		{`"a=\"b\""`, `a="b"`},           // escaped quotes don't terminate
		{`"back\\slash"`, `back\slash`},  // literal backslash
		{`"tab\tend"`, "tab\tend"},       // \t
		{`"line\nbreak"`, "line\nbreak"}, // \n
		{`"x\qy"`, "xqy"},                // unknown escape → literal char
	}
	for _, c := range cases {
		toks, err := lex(c.src)
		if err != nil {
			t.Fatalf("lex(%q) error: %v", c.src, err)
		}
		if toks[0].kind != tString || toks[0].val != c.want {
			t.Errorf("lex(%q) = %q, want %q", c.src, toks[0].val, c.want)
		}
	}
	// an unterminated string (trailing escape eats the closing quote) still errors.
	if _, err := lex(`"oops\"`); err == nil {
		t.Errorf("expected unterminated-string error")
	}
}

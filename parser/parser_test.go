package parser

import "testing"

// Mirrors the Python parser smoke test: every docs/05 rule form parses.
// VyQL conventions: `package <ns>;` declares the namespace (Go-style), rule
// names are short PascalCase, concepts are qualified cross-package refs,
// CWE refs are CWE_NNN, states are PascalCase.
const program = `
package vypr.injection;

rule Sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE_89], owasp: ["A03:2021"] }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}

package vypr.cloud;

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

package vypr.identity;

rule ExternalToAdmin { assume identity.ExternalPrincipal -> identity.AdminPrivilege }
rule ToxicCombinationLateral {
  match identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}

package vypr.bizlogic;

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

// Namespacing via a `package` declaration (Go-style): short rule names within
// the package; cross-package concept refs stay qualified.
func TestPackageDecl(t *testing.T) {
	src := `
package vypr.injection;

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
		`rule x { taint A -> }`,            // missing endpoint
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
package injection;
threat SqlInjection { cwe: [CWE_89], desc: "Untrusted data in a SQL command" }

adapter python {
  meta { fidelity: resolved }
  source "request.form" -> code.HttpInput
  sink method "execute" -> code.SqlExecution
  sink path "os.system" -> code.CommandExecution
  sink receiver "openConnection" -> code.UrlFetch
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
	if ad == nil || ad.Name != "python" || len(ad.Mappings) != 4 {
		t.Fatalf("adapter decl not parsed: %+v", ad)
	}
	if ad.Mappings[0].Kind != "source" || ad.Mappings[0].Concept != "code.HttpInput" {
		t.Fatalf("source mapping wrong: %+v", ad.Mappings[0])
	}
	if ad.Mappings[1].Kind != "sink_method" || ad.Mappings[2].Kind != "sink_path" {
		t.Fatalf("sink mapping kinds wrong: %+v", ad.Mappings[1:])
	}
	if ad.Mappings[3].Kind != "sink_receiver" || ad.Mappings[3].Concept != "code.UrlFetch" {
		t.Fatalf("sink_receiver mapping wrong: %+v", ad.Mappings[3])
	}
}

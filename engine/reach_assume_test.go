package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// Mirrors poc/cases/case_04: internet -> PII database; witness names the SG rule.
func TestReachWithAssetFilter(t *testing.T) {
	src := `
package vypr.cloud;
rule PublicDatabase {
  meta { id: "VYQL-CLD-003", severity: critical }
  reach cloud.Internet -> cloud.Database
  where cloud.Database holds_asset_kind [data.Pii]
}
`
	onto := ontology.Seed()
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet", Props: map[string]string{"loc": "0.0.0.0/0"}})
	s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
	s.AddNode(usg.Node{ID: "alb", Type: "cloud.LoadBalancer"})
	s.AddNode(usg.Node{ID: "svc", Type: "cloud.Container"})
	s.AddNode(usg.Node{ID: "db", Type: "cloud.Database", Props: map[string]string{"loc": "orders-db"}})
	s.AddLabel("db", usg.Label{Concept: "cloud.Database", Detail: map[string]string{"asset_kinds": "data.Pii"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "alb", Props: map[string]string{"rule": "sg-pub:443", "proto": "tcp", "port": "443"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "alb", Dst: "svc", Props: map[string]string{"rule": "sg-app:8080", "proto": "tcp", "port": "8080"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "svc", Dst: "db", Props: map[string]string{"rule": "sg-db:5432", "proto": "tcp", "port": "5432"}})

	eng := New(onto, s)
	fs, _ := eng.Evaluate(compiled[0])
	if len(fs) != 1 {
		t.Fatalf("expected 1 reach finding, got %d", len(fs))
	}
	named := false
	for _, w := range fs[0].Witness {
		if strings.Contains(w, "sg-db:5432") {
			named = true
		}
	}
	if !named {
		t.Fatalf("witness should name the db-port SG rule: %v", fs[0].Witness)
	}
}

// Mirrors poc/cases/case_05: external principal -> admin via an ability chain.
func TestAssumeEscalation(t *testing.T) {
	src := `
package vypr.identity;
rule ExternalToAdmin {
  meta { id: "VYQL-IDN-002", severity: critical }
  assume identity.ExternalPrincipal -> identity.AdminPrivilege
}
`
	onto := ontology.Seed()
	decls, _ := parser.Parse(src)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "ext", Type: "identity.User", Props: map[string]string{"loc": "external-user"}})
	s.AddLabel("ext", usg.Label{Concept: "identity.ExternalPrincipal"})
	s.AddNode(usg.Node{ID: "dev", Type: "identity.Role"})
	s.AddNode(usg.Node{ID: "deploy", Type: "identity.Role", Props: map[string]string{"priv_level": "WRITE"}})
	s.AddNode(usg.Node{ID: "admin", Type: "identity.Role", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("admin", usg.Label{Concept: "identity.AdminPrivilege"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "ext", Dst: "dev", Props: map[string]string{"ability": "sts:AssumeRole"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "dev", Dst: "deploy", Props: map[string]string{"ability": "iam:PassRole"}})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "deploy", Dst: "admin", Props: map[string]string{"ability": "iam:PutRolePolicy"}})

	eng := New(onto, s)
	fs, _ := eng.Evaluate(compiled[0])
	if len(fs) != 1 {
		t.Fatalf("expected 1 escalation finding, got %d", len(fs))
	}
	if len(fs[0].Witness) != 3 {
		t.Fatalf("expected a 3-step ability chain, got %v", fs[0].Witness)
	}
	if !strings.Contains(fs[0].Witness[0], "sts:AssumeRole") {
		t.Fatalf("witness first step wrong: %v", fs[0].Witness)
	}
}

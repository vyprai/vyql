package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// TestToyEndToEndSlice is the Phase-0 acceptance slice (plan/phase-0 AC4): a
// SINGLE hand-built graph exercised by FIVE rules of different forms — taint,
// command-injection taint, reach, assume, and a match composing reach+assume —
// asserting full proof trees, including label provenance (from the adapter
// layer) and negation evidence (the unsatisfied `unless`).
func TestToyEndToEndSlice(t *testing.T) {
	onto := ontology.Seed()
	s := buildToyGraph(t)

	rules := `
package vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE_89] }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
rule Command {
  meta { id: "VYQL-INJ-002", severity: critical, cwe: [CWE_78] }
  taint code.HttpInput -> code.CommandExecution
  unless sanitized_by core.ShellEscape
}

package vypr.cloud;
rule PublicPiiDatabase {
  meta { id: "VYQL-CLD-003", severity: critical }
  reach cloud.Internet -> cloud.Database
  where cloud.Database holds_asset_kind [data.Pii]
}

package vypr.identity;
rule ExternalToAdmin {
  meta { id: "VYQL-IDN-004", severity: critical }
  assume identity.ExternalPrincipal -> identity.AdminPrivilege
}
rule ToxicCombination {
  meta { id: "VYQL-IDN-005", severity: critical }
  match identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}
`
	decls, err := parser.Parse(rules)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile errors: %v", errs)
	}
	if len(compiled) != 5 {
		t.Fatalf("expected 5 compiled rules, got %d", len(compiled))
	}

	eng := New(onto, s)
	byID := map[string]int{}
	bindingProvenanceSeen := false
	negationEvidenceSeen := false
	for _, cr := range compiled {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range fs {
			byID[f.RuleID]++
			// every finding must carry a non-empty proof tree: solver witness
			// for flow rules, or where-clause context for match rules.
			if len(f.Witness) == 0 && len(f.Context) == 0 {
				t.Fatalf("%s: finding has empty proof tree (no witness or context)", f.RuleID)
			}
			if f.Render() == "" {
				t.Fatalf("%s: empty render", f.RuleID)
			}
			for _, b := range f.Bindings {
				if b.LabelProvenance != "" {
					bindingProvenanceSeen = true
				}
			}
			for _, ne := range f.NegationEvidence {
				if !ne.Satisfied && ne.Detail != "" {
					negationEvidenceSeen = true
				}
			}
		}
	}

	want := map[string]int{
		"VYQL-INJ-001": 1, // SQLi: req -> query (unsanitized)
		"VYQL-INJ-002": 1, // command injection: req -> exec
		"VYQL-CLD-003": 1, // internet -> PII database
		"VYQL-IDN-004": 1, // external principal -> admin
		"VYQL-IDN-005": 1, // toxic combination (reach + assume)
	}
	for id, n := range want {
		if byID[id] != n {
			t.Fatalf("rule %s: expected %d finding(s), got %d", id, n, byID[id])
		}
	}
	if !bindingProvenanceSeen {
		t.Fatal("no finding carried label provenance from the adapter layer")
	}
	if !negationEvidenceSeen {
		t.Fatal("no finding carried negation evidence for an unsatisfied unless-clause")
	}

	// Spot-check the SQLi proof tree names the adapter and carries the path.
	sqliFindings, _ := eng.Evaluate(compiled[0])
	render := sqliFindings[0].Render()
	if !strings.Contains(render, "taint path:") {
		t.Fatalf("SQLi render should show the taint path:\n%s", render)
	}
}

// buildToyGraph constructs one graph covering all five rule forms. Code-layer
// concept labels are attached through the adapter layer (so bindings carry
// provenance); cloud/identity facts are attached directly.
func buildToyGraph(t *testing.T) usg.Store {
	t.Helper()
	s := usg.NewInMemStore()

	// --- code layer: two tainted flows from one request ---
	for _, n := range []struct{ id, loc string }{
		{"req", "app/handlers.go:10"},
		{"query", "app/db.go:42"},
		{"exec", "app/shell.go:8"},
	} {
		s.AddNode(usg.Node{ID: n.id, Type: "code.X", Props: map[string]string{"loc": n.loc}})
	}
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "req", Dst: "query"})
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "req", Dst: "exec"})

	// label the code nodes through adapters so bindings get provenance
	codeAdapter := adapters.Adapter{
		Name: "go.nethttp+databasesql", Technology: "go", Specificity: 2,
		Fidelity: "resolved", Confidence: "high",
		Apply: func(usg.Store) []adapters.Mapping {
			return []adapters.Mapping{
				{NodeID: "req", Concept: "code.HttpInput"},
				{NodeID: "query", Concept: "code.SqlExecution"},
				{NodeID: "exec", Concept: "code.CommandExecution"},
			}
		},
	}
	if _, _, err := adapters.Apply(s, []adapters.Adapter{codeAdapter}, nil); err != nil {
		t.Fatal(err)
	}

	// --- cloud layer: internet -> ... -> PII database ---
	s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet", Props: map[string]string{"loc": "0.0.0.0/0"}})
	s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
	s.AddNode(usg.Node{ID: "alb", Type: "cloud.LoadBalancer"})
	s.AddNode(usg.Node{ID: "pod", Type: "cloud.Container", Props: map[string]string{"loc": "pod/orders"}})
	s.AddNode(usg.Node{ID: "db", Type: "cloud.Database", Props: map[string]string{"loc": "orders-db"}})
	s.AddLabel("db", usg.Label{Concept: "cloud.Database", Detail: map[string]string{"asset_kinds": "data.Pii"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "alb", Props: map[string]string{"rule": "sg-pub:443", "proto": "tcp", "port": "443"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "alb", Dst: "pod", Props: map[string]string{"rule": "sg-app:8080", "proto": "tcp", "port": "8080"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "pod", Dst: "db", Props: map[string]string{"rule": "sg-db:5432", "proto": "tcp", "port": "5432"}})

	// --- identity layer: external principal escalates to admin; the pod's
	// workload identity is internet-reachable AND escalatable (toxic combo) ---
	s.AddNode(usg.Node{ID: "ext", Type: "identity.User", Props: map[string]string{"loc": "external-user"}})
	s.AddLabel("ext", usg.Label{Concept: "identity.ExternalPrincipal"})
	s.AddNode(usg.Node{ID: "admin", Type: "identity.Role", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("admin", usg.Label{Concept: "identity.AdminPrivilege"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "ext", Dst: "admin", Props: map[string]string{"ability": "sts:AssumeRole"}})

	// workload identity bound to the internet-reachable pod, escalatable to admin
	s.AddNode(usg.Node{ID: "wid", Type: "identity.ServiceAccount", Props: map[string]string{"loc": "sa/orders", "workload": "pod"}})
	s.AddLabel("wid", usg.Label{Concept: "identity.WorkloadIdentity"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "wid", Dst: "admin", Props: map[string]string{"ability": "create-pod+mount-sa-token"}})

	return s
}

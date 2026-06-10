package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func compileEval(t *testing.T, src string, s usg.Store) []int {
	t.Helper()
	onto := ontology.Seed()
	decls, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	eng := New(onto, s)
	var counts []int
	for _, cr := range compiled {
		fs, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		counts = append(counts, len(fs))
	}
	return counts
}

// Mirrors poc/cases/case_05 toxic combination: a single match rule composes
// reach + assume through the engine.
func TestToxicCombination(t *testing.T) {
	src := `
package vypr.identity;
rule ToxicCombinationLateral {
  match identity.WorkloadIdentity as w
  where reach(cloud.Internet, w.workload) and assume(w, identity.AdminPrivilege)
}
`
	s := usg.NewInMemStore()
	// network: internet -> pod (reachable); internet -/-> batchpod
	s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet"})
	s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
	s.AddNode(usg.Node{ID: "pod", Type: "cloud.Container", Props: map[string]string{"loc": "pod/orders"}})
	s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "pod", Props: map[string]string{"rule": "sg-pub:443", "proto": "tcp", "port": "443"}})
	// workload identity for pod, escalatable to admin
	s.AddNode(usg.Node{ID: "wid", Type: "identity.ServiceAccount", Props: map[string]string{"loc": "sa/orders", "workload": "pod"}})
	s.AddLabel("wid", usg.Label{Concept: "identity.WorkloadIdentity"})
	s.AddNode(usg.Node{ID: "admin", Type: "identity.Role", Props: map[string]string{"priv_level": "ADMIN"}})
	s.AddLabel("admin", usg.Label{Concept: "identity.AdminPrivilege"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "wid", Dst: "admin", Props: map[string]string{"ability": "create-pod+mount-sa-token"}})
	// a second workload identity NOT internet-reachable
	s.AddNode(usg.Node{ID: "wid2", Type: "identity.ServiceAccount", Props: map[string]string{"workload": "batchpod"}})
	s.AddLabel("wid2", usg.Label{Concept: "identity.WorkloadIdentity"})
	s.AddNode(usg.Node{ID: "batchpod", Type: "cloud.Container"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "wid2", Dst: "admin", Props: map[string]string{"ability": "create-pod+mount-sa-token"}})

	counts := compileEval(t, src, s)
	if counts[0] != 1 {
		t.Fatalf("toxic combo should fire once (internet-reachable + escalatable), got %d", counts[0])
	}
}

// Mirrors poc/cases/case_09: business-logic refund authorization + state machine.
func TestBusinessMatchAndTransition(t *testing.T) {
	refundRule := `
package vypr.bizlogic;
rule UnauthorizedRefund {
  match business.Refund as a
  where a.actor is identity.User and a.resource is business.Order
  unless guarded_by core.OwnershipCheck
}
`
	// unguarded refund -> finding
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "refund1", Type: "business.Action", Props: map[string]string{"loc": "RefundService.execute", "actor": "identity.User", "resource": "business.Order"}})
	g.AddLabel("refund1", usg.Label{Concept: "business.Refund"})
	if c := compileEval(t, refundRule, g); c[0] != 1 {
		t.Fatalf("unguarded refund: expected 1 finding, got %d", c[0])
	}

	// ownership-checked refund -> no finding
	g2 := usg.NewInMemStore()
	g2.AddNode(usg.Node{ID: "refund1", Type: "business.Action", Props: map[string]string{"actor": "identity.User", "resource": "business.Order"}})
	g2.AddLabel("refund1", usg.Label{Concept: "business.Refund"})
	g2.AddNode(usg.Node{ID: "own", Type: "business.Control"})
	g2.AddLabel("own", usg.Label{Concept: "core.OwnershipCheck"})
	g2.AddEdge(usg.Edge{Type: "CHECKS", Src: "own", Dst: "refund1"})
	if c := compileEval(t, refundRule, g2); c[0] != 0 {
		t.Fatalf("guarded refund: expected 0 findings, got %d", c[0])
	}

	transitionRule := `
package vypr.bizlogic;
rule InvalidRefundTransition {
  match transition * -> Refunded on Order as t
  unless t.from == Paid
}
`
	// invalid: Created -> Refunded
	gt := usg.NewInMemStore()
	gt.AddNode(usg.Node{ID: "t1", Type: "business.Transition", Props: map[string]string{"machine": "Order", "from": "Created", "to": "Refunded"}})
	if c := compileEval(t, transitionRule, gt); c[0] != 1 {
		t.Fatalf("invalid transition: expected 1 finding, got %d", c[0])
	}
	// valid: Paid -> Refunded
	gv := usg.NewInMemStore()
	gv.AddNode(usg.Node{ID: "t1", Type: "business.Transition", Props: map[string]string{"machine": "Order", "from": "Paid", "to": "Refunded"}})
	if c := compileEval(t, transitionRule, gv); c[0] != 0 {
		t.Fatalf("valid transition: expected 0 findings, got %d", c[0])
	}
}

package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/risk"
	"github.com/vyprai/vyql/usg"
)

// evalOne compiles a single-rule program and evaluates it over a store.
func evalOne(t *testing.T, src string, s usg.Store) int {
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
	fs, err := New(onto, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return len(fs)
}

// Runtime rule pack (docs/11 Part B) evaluated over a PRE-AGGREGATED runtime
// snapshot — "ordinary VyQL rules… no special machinery beyond the streaming
// evaluator". The streaming evaluator + telemetry aggregation are deferred; here
// the runtime.* aggregate nodes are hand-built and the rules run on the batch
// engine, which is the oracle the streaming engine must later match.

// `match runtime.Connection as c where c.dst labeled threat.MiningPool`.
func TestRuntimeMiningEgress(t *testing.T) {
	rule := `
package vypr.runtime;
rule CryptoMiningEgress {
  meta { id: "VYQL-RTM-004", severity: high, attack: [T1496] }
  match runtime.Connection as c
  where c.dst labeled threat.MiningPool
}
`
	s := usg.NewInMemStore()
	// pool is a known mining pool (threat-intel projection); cdn is benign
	s.AddNode(usg.Node{ID: "pool", Type: "cloud.Internet"})
	s.AddLabel("pool", usg.Label{Concept: "threat.MiningPool"})
	s.AddNode(usg.Node{ID: "cdn", Type: "cloud.Internet"})
	// two observed connections; only the one to the pool should fire
	s.AddNode(usg.Node{ID: "conn1", Type: "runtime.Connection", Props: map[string]string{"dst": "pool"}})
	s.AddLabel("conn1", usg.Label{Concept: "runtime.Connection"})
	s.AddNode(usg.Node{ID: "conn2", Type: "runtime.Connection", Props: map[string]string{"dst": "cdn"}})
	s.AddLabel("conn2", usg.Label{Concept: "runtime.Connection"})

	if n := evalOne(t, rule, s); n != 1 {
		t.Fatalf("mining-egress should fire once (the pool connection), got %d", n)
	}
}

// `match runtime.Process as p where p.image not in [<declared images>]`.
func TestRuntimeWorkloadDrift(t *testing.T) {
	rule := `
package vypr.runtime;
rule WorkloadDrift {
  meta { id: "VYQL-RTM-003", severity: high }
  match runtime.Process as p
  where p.image not in [nginx, redis]
}
`
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "proc1", Type: "runtime.Process", Props: map[string]string{"image": "xmrig"}})
	s.AddLabel("proc1", usg.Label{Concept: "runtime.Process"})
	s.AddNode(usg.Node{ID: "proc2", Type: "runtime.Process", Props: map[string]string{"image": "nginx"}})
	s.AddLabel("proc2", usg.Label{Concept: "runtime.Process"})

	if n := evalOne(t, rule, s); n != 1 {
		t.Fatalf("drift should fire once (the undeclared xmrig image), got %d", n)
	}
}

// Static↔runtime confirmation (docs/11 Part B → docs/17): a statically
// predicted internet exposure that is OBSERVED in the runtime snapshot is
// "confirmed", and the risk layer escalates the finding's priority band.
func TestRuntimeConfirmationEscalatesRisk(t *testing.T) {
	onto := seededTestOntology()
	decls, _ := parser.Parse(flowRule)
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}

	build := func(observed bool) usg.Store {
		s := usg.NewInMemStore()
		s.AddNode(usg.Node{ID: "svc", Type: "cloud.Container", Props: map[string]string{"loc": "svc"}})
		s.AddNode(usg.Node{ID: "in", Type: "code.X", Props: map[string]string{"loc": "h.py:1"}})
		s.AddNode(usg.Node{ID: "q", Type: "code.X", Props: map[string]string{"loc": "h.py:2", "service": "svc"}})
		s.AddLabel("in", usg.Label{Concept: "custom.Input"})
		s.AddLabel("q", usg.Label{Concept: "custom.Target"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
		s.AddNode(usg.Node{ID: "internet", Type: "cloud.Internet", Props: map[string]string{"loc": "0.0.0.0/0"}})
		s.AddLabel("internet", usg.Label{Concept: "cloud.Internet"})
		s.AddEdge(usg.Edge{Type: "NET", Src: "internet", Dst: "svc", Props: map[string]string{"rule": "sg-pub:443"}})
		if observed {
			// a pre-aggregated runtime.Connection observed from an external src to svc
			s.AddNode(usg.Node{ID: "rconn", Type: "runtime.Connection",
				Props: map[string]string{"dst": "svc", "external": "true", "evidence_ref": "ocsf://win/2024-..."}})
			s.AddLabel("rconn", usg.Label{Concept: "runtime.Connection"})
		}
		return s
	}

	score := func(observed bool) risk.Score {
		fs, err := New(onto, build(observed)).Evaluate(compiled[0])
		if err != nil || len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d err=%v", len(fs), err)
		}
		return risk.Prioritize(fs[0])
	}

	planned := score(false)
	confirmed := score(true)

	if confirmed.Total <= planned.Total {
		t.Fatalf("runtime confirmation should escalate priority: confirmed=%d planned=%d", confirmed.Total, planned.Total)
	}
	if !strings.Contains(confirmed.Render(), "confirmed by runtime") {
		t.Fatalf("confirmed finding should cite runtime evidence:\n%s", confirmed.Render())
	}
}

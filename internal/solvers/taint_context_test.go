package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// TestContextSensitiveTaintEliminatesUnrealizablePaths tests that a shared helper
// function called by both a tainted call site and a clean call site only returns
// taint to the tainted caller, preventing false positives at the clean caller.
func TestContextSensitiveTaintEliminatesUnrealizablePaths(t *testing.T) {
	s := usg.NewInMemStore()

	// Call Site 1 (tainted)
	s.AddNode(usg.Node{ID: "src1", Type: "code.Source"})
	s.AddLabel("src1", usg.Label{Concept: "code.HttpInput"})
	s.AddNode(usg.Node{ID: "call1", Type: "code.Call"})
	s.AddNode(usg.Node{ID: "res1", Type: "code.Variable"})
	s.AddNode(usg.Node{ID: "sink1", Type: "code.Sink"})
	s.AddLabel("sink1", usg.Label{Concept: "code.SqlExecution"})

	// Call Site 2 (clean)
	s.AddNode(usg.Node{ID: "safe_lit", Type: "code.Const"})
	s.AddNode(usg.Node{ID: "call2", Type: "code.Call"})
	s.AddNode(usg.Node{ID: "res2", Type: "code.Variable"})
	s.AddNode(usg.Node{ID: "sink2", Type: "code.Sink"})
	s.AddLabel("sink2", usg.Label{Concept: "code.SqlExecution"})

	// Shared Helper Function: id(x) { return x }
	s.AddNode(usg.Node{ID: "helper_param", Type: "code.Param"})
	s.AddNode(usg.Node{ID: "helper_ret", Type: "code.Return"})
	s.AddEdge(usg.Edge{Src: "helper_param", Dst: "helper_ret", Type: "FLOWS"})

	// Call site 1 flow
	s.AddEdge(usg.Edge{Src: "src1", Dst: "call1", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "call1", Dst: "helper_param", Type: "CALLS"})
	s.AddEdge(usg.Edge{Src: "helper_ret", Dst: "call1", Type: "RETURNS"})
	s.AddEdge(usg.Edge{Src: "call1", Dst: "res1", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "res1", Dst: "sink1", Type: "FLOWS"})

	// Call site 2 flow
	s.AddEdge(usg.Edge{Src: "safe_lit", Dst: "call2", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "call2", Dst: "helper_param", Type: "CALLS"})
	s.AddEdge(usg.Edge{Src: "helper_ret", Dst: "call2", Type: "RETURNS"})
	s.AddEdge(usg.Edge{Src: "call2", Dst: "res2", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "res2", Dst: "sink2", Type: "FLOWS"})

	sourceConcepts := map[string]bool{"code.HttpInput": true}
	sinkConcepts := map[string]bool{"code.SqlExecution": true}

	flows, err := FindContextSensitiveTaintFlows(s, sourceConcepts, sinkConcepts, nil, 2)
	if err != nil {
		t.Fatalf("FindContextSensitiveTaintFlows failed: %v", err)
	}

	foundSink1 := false
	foundSink2 := false
	for _, f := range flows {
		if f.SinkID == "sink1" {
			foundSink1 = true
		}
		if f.SinkID == "sink2" {
			foundSink2 = true
		}
	}

	if !foundSink1 {
		t.Errorf("expected taint flow reaching sink1 from src1")
	}
	if foundSink2 {
		t.Errorf("unrealizable path: taint leaked from src1 into sink2 via shared helper!")
	}
}

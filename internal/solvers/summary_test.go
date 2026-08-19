package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

func TestComputeFunctionSummaryDirectReturn(t *testing.T) {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "fn1", Type: "code.Function"})
	s.AddNode(usg.Node{ID: "p0", Type: "code.Param"})
	s.AddNode(usg.Node{ID: "p1", Type: "code.Param"})
	s.AddNode(usg.Node{ID: "mid", Type: "code.Variable"})
	s.AddNode(usg.Node{ID: "ret", Type: "code.Return"})

	// p0 -> mid -> ret
	s.AddEdge(usg.Edge{Src: "p0", Dst: "mid", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "mid", Dst: "ret", Type: "FLOWS"})
	// p1 has no outgoing edges

	summary := ComputeFunctionSummary(s, "fn1", []string{"p0", "p1"}, "ret", nil)

	if !summary.ParamToReturn[0] {
		t.Errorf("expected param 0 to flow to return")
	}
	if summary.ParamToReturn[1] {
		t.Errorf("param 1 should not flow to return")
	}
}

func TestComputeFunctionSummaryWithNeutralizingControl(t *testing.T) {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "fn2", Type: "code.Function"})
	s.AddNode(usg.Node{ID: "p0", Type: "code.Param"})
	s.AddNode(usg.Node{ID: "sanitizer", Type: "code.Call"})
	s.AddNode(usg.Node{ID: "ret", Type: "code.Return"})

	s.AddLabel("sanitizer", usg.Label{
		Concept: "core.SqlParameterization",
	})

	// p0 -> sanitizer -> ret
	s.AddEdge(usg.Edge{Src: "p0", Dst: "sanitizer", Type: "FLOWS"})
	s.AddEdge(usg.Edge{Src: "sanitizer", Dst: "ret", Type: "FLOWS"})

	killControls := map[string]bool{
		"core.SqlParameterization": true,
	}

	summary := ComputeFunctionSummary(s, "fn2", []string{"p0"}, "ret", killControls)

	if summary.ParamToReturn[0] {
		t.Errorf("param 0 flow to return should be killed by sanitizer")
	}
	if !summary.KilledThreats[0]["core.SqlParameterization"] {
		t.Errorf("expected KilledThreats to record core.SqlParameterization for param 0")
	}
}

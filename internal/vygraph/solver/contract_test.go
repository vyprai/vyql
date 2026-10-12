package solver

import (
	"strings"
	"testing"
)

func TestFlowResultExposesTheContract(t *testing.T) {
	f := Flow{Src: "src1", Dst: "sink1", Path: []Step{
		{From: "src1", To: "mid", Via: "FLOWS"},
		{From: "mid", To: "sink1", Via: "FLOWS"},
	}}
	var r Result = f
	if r.Source() != "src1" || r.Target() != "sink1" || len(r.Witness()) != 2 {
		t.Fatalf("contract not satisfied: %+v", r)
	}
}

func TestAbsenceResultIsDegenerateButWellDefined(t *testing.T) {
	// An absence solver (deviate) has no originating endpoint: Source() is empty, Target()
	// is the outlier, Witness() carries the peer group and the missing feature.
	a := Absence{
		Outlier:  "handler7",
		Missing:  "AuthzCheck",
		Peers:    []string{"handler1", "handler2", "handler3"},
		Exemplar: "handler1",
	}
	var r Result = a
	if r.Source() != "" {
		t.Errorf("Source() = %q, want empty for an absence result", r.Source())
	}
	if r.Target() != "handler7" {
		t.Errorf("Target() = %q, want the outlier", r.Target())
	}
	w := r.Witness()
	if len(w) == 0 {
		t.Fatal("an absence result must still carry a witness")
	}
	joined := renderSteps(w)
	for _, want := range []string{"AuthzCheck", "handler1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("witness %q missing %q", joined, want)
		}
	}
}

func TestProofTreeRebuildsFromWitness(t *testing.T) {
	f := Flow{Src: "src1", Dst: "sink1", Path: []Step{
		{From: "src1", To: "mid", Via: "FLOWS", Note: "param"},
		{From: "mid", To: "sink1", Via: "FLOWS", Note: "concat"},
	}}
	p := ProofTree(f)
	out := p.Render()
	for _, want := range []string{"src1", "mid", "sink1", "param", "concat"} {
		if !strings.Contains(out, want) {
			t.Errorf("proof %q missing %q", out, want)
		}
	}
}

func TestProofTreeRejectsWitnesslessResult(t *testing.T) {
	// "A finding with no rebuildable witness is not a finding."
	if p := ProofTree(Flow{Src: "a", Dst: "b"}); p != nil {
		t.Fatal("a result with no witness must not yield a proof tree")
	}
}

func renderSteps(steps []Step) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(s.From + "->" + s.To + "(" + s.Via + ":" + s.Note + ") ")
	}
	return b.String()
}

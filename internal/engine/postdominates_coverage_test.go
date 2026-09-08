package engine

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

const releasedActionRule = `
module test;
rule ReleasedAction {
  issue custom.Action as a
  unless a.postDominates coveredBy custom.Transform
}
`

// A release written after a branch that returns does not run on the path that branch
// takes, so it does not cover the acquisition — the region/order relation alone says it
// does, because nothing in it records that a branch can end the function.
func TestPostDominatesCoveredEarlyReturnLeavesActionUncovered(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "app.go:2", Region: "app.go/fn1", Order: 2, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})
	g.AddNode(usg.Node{ID: "exit", Type: usg.ExitNodeType, Loc: "app.go:4", Region: "app.go/fn1/if3.t", Order: 4, HasOrder: true})
	g.AddNode(usg.Node{ID: "release", Type: "code.Call", Loc: "app.go:6", Region: "app.go/fn1", Order: 6, HasOrder: true})
	g.AddLabel("release", coverageLabel("custom.Transform", "postDominates"))

	if c := compileEvalV2(t, releasedActionRule, g); c[0] != 1 {
		t.Fatalf("a release the early return skips must not cover the action, got %d findings", c[0])
	}
}

// The same shape with the branch releasing before it returns: every path out of the
// function runs a release, so the action stays covered.
func TestPostDominatesCoveredBranchThatReleasesBeforeReturning(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "app.go:2", Region: "app.go/fn1", Order: 2, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})
	g.AddNode(usg.Node{ID: "bail", Type: "code.Call", Loc: "app.go:4", Region: "app.go/fn1/if3.t", Order: 4, HasOrder: true})
	g.AddLabel("bail", coverageLabel("custom.Transform", "postDominates"))
	g.AddNode(usg.Node{ID: "exit", Type: usg.ExitNodeType, Loc: "app.go:5", Region: "app.go/fn1/if3.t", Order: 5, HasOrder: true})
	g.AddNode(usg.Node{ID: "release", Type: "code.Call", Loc: "app.go:7", Region: "app.go/fn1", Order: 7, HasOrder: true})
	g.AddLabel("release", coverageLabel("custom.Transform", "postDominates"))

	if c := compileEvalV2(t, releasedActionRule, g); c[0] != 0 {
		t.Fatalf("an error block that releases before returning covers its own path, got %d findings", c[0])
	}
}

// A release the language runs while unwinding — a `finally` body, a Go/Swift `defer` —
// is reached by the early return as well.
func TestPostDominatesCoveredUnwindReleaseCoversEarlyReturn(t *testing.T) {
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "action", Type: "code.Call", Loc: "app.go:2", Region: "app.go/fn1", Order: 2, HasOrder: true})
	g.AddLabel("action", usg.Label{Concept: "custom.Action"})
	g.AddNode(usg.Node{ID: "exit", Type: usg.ExitNodeType, Loc: "app.go:4", Region: "app.go/fn1/if3.t", Order: 4, HasOrder: true})
	g.AddNode(usg.Node{ID: "release", Type: "code.Call", Loc: "app.go:6", Region: "app.go/fn1", Order: 6, HasOrder: true,
		Props: map[string]string{usg.UnwindProp: "1"}})
	g.AddLabel("release", coverageLabel("custom.Transform", "postDominates"))

	if c := compileEvalV2(t, releasedActionRule, g); c[0] != 0 {
		t.Fatalf("a deferred release runs on every path out, got %d findings", c[0])
	}
}

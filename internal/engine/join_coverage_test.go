package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

const joinCoverageRule = `
module test;
rule GuardedFlow {
  meta { id: "TEST-JOIN", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.endpoint coveredBy custom.Transform
}
`

// runRuleOnStore evaluates a single-rule program against an already-built store.
func runRuleOnStore(t *testing.T, src string, g usg.Store) int {
	t.Helper()
	onto := testOntology()
	decls, err := parseV2DefinitionsForTest(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return len(fs)
}

// A check written inside one arm of a branch dominates nothing after the branch — the sibling
// arm reaches the same code without it — so endpoint coverage, which asks for a dominating
// guard, could not see it at all. That is the right answer when one arm screens the value and
// the wrong one when they all do, and it made a guard added to one arm of a join invisible.
//
// The merge records which branches can deliver the joined value; a merge is covered when each
// of them carries a guard, and only then.
func TestJoinCoverageRequiresEveryIncomingBranch(t *testing.T) {
	const fn = "sample.rs/fn1"
	build := func(guardRegions ...string) func(usg.Store) {
		return func(s usg.Store) {
			s.AddNode(usg.Node{ID: "src", Type: "code.Attr", Loc: "sample.rs:3", Region: fn, Order: 1, HasOrder: true})
			s.AddLabel("src", usg.Label{Concept: "custom.Input"})
			s.AddNode(usg.Node{ID: "armA", Type: "code.Name", Loc: "sample.rs:4", Region: fn + "/sw2.c0", Order: 2, HasOrder: true})
			s.AddNode(usg.Node{ID: "armB", Type: "code.Name", Loc: "sample.rs:5", Region: fn + "/sw2.c1", Order: 3, HasOrder: true})
			s.AddNode(usg.Node{ID: "join", Type: "code.Phi", Loc: "?:0", Region: fn, Order: 4, HasOrder: true,
				Props: map[string]string{"merge_branches": fn + "/sw2.c0\x00" + fn + "/sw2.c1"}})
			s.AddNode(usg.Node{ID: "sink", Type: "code.Call", Loc: "sample.rs:8", Region: fn, Order: 5, HasOrder: true})
			s.AddLabel("sink", usg.Label{Concept: "custom.Target"})
			for _, e := range [][2]string{{"src", "armA"}, {"src", "armB"}, {"armA", "join"}, {"armB", "join"}, {"join", "sink"}} {
				s.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]})
			}
			for i, r := range guardRegions {
				id := "guard" + string(rune('A'+i))
				s.AddNode(usg.Node{ID: id, Type: "code.Call", Loc: "sample.rs:6", Region: r, Order: int32(10 + i), HasOrder: true})
				s.AddLabel(id, coverageLabel("custom.Transform", "endpoint"))
			}
		}
	}

	for _, tc := range []struct {
		name    string
		guards  []string
		want    int
		because string
	}{
		{"no arm screens the value", nil, 1, "nothing guards the join"},
		{"one arm screens the value", []string{fn + "/sw2.c0"}, 1,
			"the sibling arm delivers the value unscreened"},
		{"a sibling branch outside the join screens it", []string{fn + "/sw2.c0", fn + "/if9.t"}, 1,
			"a branch that does not feed this join covers nothing"},
		{"every arm screens the value", []string{fn + "/sw2.c0", fn + "/sw2.c1"}, 0,
			"no unscreened value can reach the join"},
		{"a screen nested inside an arm", []string{fn + "/sw2.c0", fn + "/sw2.c1/loop3"}, 0,
			"a screen written in a loop inside the arm is still the arm's screen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := usg.NewInMemStore()
			build(tc.guards...)(g)
			if got := runRuleOnStore(t, joinCoverageRule, g); got != tc.want {
				t.Fatalf("got %d findings, want %d: %s", got, tc.want, tc.because)
			}
		})
	}
}

// A merge whose value can also arrive from before the branch records no regions, so no guard
// inside the branches can cover it: the pre-branch value never passed one.
func TestJoinCoverageSkipsMergesWithAPreBranchOperand(t *testing.T) {
	const fn = "sample.rs/fn1"
	g := usg.NewInMemStore()
	g.AddNode(usg.Node{ID: "src", Type: "code.Attr", Loc: "sample.rs:3", Region: fn, Order: 1, HasOrder: true})
	g.AddLabel("src", usg.Label{Concept: "custom.Input"})
	// no merge_branches: the lowering leaves it off when an operand survives from before the branch
	g.AddNode(usg.Node{ID: "join", Type: "code.Phi", Loc: "?:0", Region: fn, Order: 4, HasOrder: true})
	g.AddNode(usg.Node{ID: "sink", Type: "code.Call", Loc: "sample.rs:8", Region: fn, Order: 5, HasOrder: true})
	g.AddLabel("sink", usg.Label{Concept: "custom.Target"})
	g.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "join"})
	g.AddEdge(usg.Edge{Type: "FLOWS", Src: "join", Dst: "sink"})
	g.AddNode(usg.Node{ID: "guard", Type: "code.Call", Loc: "sample.rs:6", Region: fn + "/if2.t", Order: 10, HasOrder: true})
	g.AddLabel("guard", coverageLabel("custom.Transform", "endpoint"))

	if got := runRuleOnStore(t, joinCoverageRule, g); got != 1 {
		t.Fatalf("got %d findings, want 1: an unattributed merge must not be branch-covered", got)
	}
}

func lowerRustForEngineTest(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "forwarder.rs")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRust([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// labelRustNode attaches a label to every node whose callee path is path.
func labelRustNode(t *testing.T, g usg.Store, path string, l usg.Label) {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range all {
		if n.Prop("callee_path") != path {
			continue
		}
		if err := g.AddLabel(n.ID, l); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no node with callee path %q to label", path)
	}
}

// The gap end to end, on the shape it was found in (CVE-2026-24902, a TCP forwarder whose
// destination comes from the client): the fix adds the private-address screen the other arm
// already had to the arm that had none. Taint reaches TcpStream::connect either way — the
// screen rejects the value instead of transforming it, so it is not on the flow — and the
// screen dominates nothing after the match, so before this the two revisions were reported
// identically and the fix had nothing to prove.
func TestRustMatchArmScreenCoversTheSinkOnlyWhenEveryArmHasIt(t *testing.T) {
	const unguarded = `
fn forward(meta: Meta) {
    let peer = match meta.destination {
        TcpDestination::Address(addr) => addr,
        TcpDestination::HostName(host) => {
            let resolved = lookup_host(host);
            if !is_global_ip(&resolved) {
                return;
            }
            resolved
        }
    };
    TcpStream::connect(peer);
}
`
	const guarded = `
fn forward(meta: Meta) {
    let peer = match meta.destination {
        TcpDestination::Address(addr) => {
            if !is_global_ip(&addr) {
                return;
            }
            addr
        }
        TcpDestination::HostName(host) => {
            let resolved = lookup_host(host);
            if !is_global_ip(&resolved) {
                return;
            }
            resolved
        }
    };
    TcpStream::connect(peer);
}
`
	for _, tc := range []struct {
		name string
		src  string
		want int
	}{
		{"one arm screened", unguarded, 1},
		{"every arm screened", guarded, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := lowerRustForEngineTest(t, tc.src)
			labelRustNode(t, g, "meta.destination", usg.Label{Concept: "custom.Input"})
			labelRustNode(t, g, "TcpStream.connect", usg.Label{Concept: "custom.Target"})
			labelRustNode(t, g, "is_global_ip", coverageLabel("custom.Transform", "endpoint"))
			if got := runRuleOnStore(t, joinCoverageRule, g); got != tc.want {
				t.Fatalf("got %d findings, want %d", got, tc.want)
			}
		})
	}
}

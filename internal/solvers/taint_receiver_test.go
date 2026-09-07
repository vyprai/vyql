package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// receiverCase is one call-node shape: a sink label on a call, the receiver it was
// bound at, and the edges that carry taint into the call.
type receiverCase struct {
	name string
	// labels on the sink node, in order; an empty recv means "no receiver anchor".
	sinkLabels []usg.Label
	nodes      []string
	edges      [][2]string
	kills      map[string]bool // node id -> carries the kill control
	wantFlows  int
	wantPath   []string
}

// receiverDetailKey is usg.TaintReceiverDetail spelled out: writing the literal into
// the graph and letting the solver read it through the constant pins the key itself,
// and keeps this test compiling — so it fails on BEHAVIOUR, not on a missing
// identifier — against a tree that has no receiver anchor at all.
const receiverDetailKey = "taint_receiver"

func anchored(concept, recv string) usg.Label {
	return usg.Label{Concept: concept, Detail: map[string]string{receiverDetailKey: recv}}
}

// A receiver-anchored sink is labelled on the CALL node, which is also where every
// argument's taint arrives. These cases pin which of those taints may fire it.
func receiverCases() []receiverCase {
	return []receiverCase{
		{
			// Path("/const").write_bytes(tainted) — the tainted value is the CONTENT.
			name:       "taint from an argument does not fire a receiver sink",
			sinkLabels: []usg.Label{anchored("test.Sink", "recv")},
			nodes:      []string{"src", "arg", "recv", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}, {"recv", "call"}},
			wantFlows:  0,
		},
		{
			// Path(tainted).read_bytes() — the receiver is the tainted path.
			name:       "taint through the receiver fires and roots the witness",
			sinkLabels: []usg.Label{anchored("test.Sink", "recv")},
			nodes:      []string{"src", "recv", "call"},
			edges:      [][2]string{{"src", "recv"}, {"recv", "call"}},
			wantFlows:  1,
			wantPath:   []string{"src", "recv", "call"},
		},
		{
			// both: the receiver justifies the finding, so it also roots the witness
			// rather than the argument that happens to be reported first.
			name:       "a tainted receiver is the witness even when an argument is tainted too",
			sinkLabels: []usg.Label{anchored("test.Sink", "recv")},
			nodes:      []string{"src", "arg", "recv", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}, {"src", "recv"}, {"recv", "call"}},
			wantFlows:  1,
			wantPath:   []string{"src", "recv", "call"},
		},
		{
			// the fact must be LIVE at the receiver: a sanitized receiver leaves only the
			// argument's taint, which this sink is not about.
			name:       "a neutralized receiver does not fire on argument taint",
			sinkLabels: []usg.Label{anchored("test.Sink", "recv")},
			nodes:      []string{"src", "arg", "recv", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}, {"src", "recv"}, {"recv", "call"}},
			kills:      map[string]bool{"recv": true},
			wantFlows:  0,
		},
		{
			// unchanged for every sink that is not receiver-anchored.
			name:       "a sink with no receiver anchor still fires on argument taint",
			sinkLabels: []usg.Label{{Concept: "test.Sink"}},
			nodes:      []string{"src", "arg", "recv", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}, {"recv", "call"}},
			wantFlows:  1,
			wantPath:   []string{"src", "arg", "call"},
		},
		{
			// the anchor is recorded per label but a flow is emitted per NODE: another
			// rule's unconstrained sink on the same call must not be narrowed by it.
			name:       "an unconstrained sink concept on the same node keeps its meaning",
			sinkLabels: []usg.Label{anchored("test.Sink", "recv"), {Concept: "test.Sink2"}},
			nodes:      []string{"src", "arg", "recv", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}, {"recv", "call"}},
			wantFlows:  1,
			wantPath:   []string{"src", "arg", "call"},
		},
		{
			// a binding that could not resolve the receiver records no anchor, so the
			// label keeps the meaning it had before: no constraint, no lost recall.
			name:       "an unresolved receiver leaves the sink unconstrained",
			sinkLabels: []usg.Label{{Concept: "test.Sink", Detail: map[string]string{receiverDetailKey: ""}}},
			nodes:      []string{"src", "arg", "call"},
			edges:      [][2]string{{"src", "arg"}, {"arg", "call"}},
			wantFlows:  1,
			wantPath:   []string{"src", "arg", "call"},
		},
	}
}

func (rc receiverCase) build(t *testing.T, s usg.Store) usg.Store {
	t.Helper()
	for _, id := range rc.nodes {
		if err := s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddLabel("src", usg.Label{Concept: "test.Source"}); err != nil {
		t.Fatal(err)
	}
	for _, l := range rc.sinkLabels {
		if err := s.AddLabel("call", l); err != nil {
			t.Fatal(err)
		}
	}
	for id := range rc.kills {
		if err := s.AddLabel(id, usg.Label{Concept: "test.Kill"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range rc.edges {
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func samePath(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// Both implementations of the fixpoint must enforce the anchor identically —
// production only ever runs the int one.
func TestReceiverAnchoredSinkRequiresTaintedReceiver(t *testing.T) {
	for _, rc := range receiverCases() {
		t.Run(rc.name, func(t *testing.T) {
			for _, impl := range []struct {
				name  string
				store func() usg.Store
			}{
				{"string", func() usg.Store { return usg.NewInMemStore() }},
				{"int", func() usg.Store { return usg.NewIntStore(len(rc.nodes)) }},
			} {
				flows, err := FindTaintFlows(rc.build(t, impl.store()),
					set("test.Source"), set("test.Sink", "test.Sink2"),
					set("test.Kind"), set("test.Kill"), "", set())
				if err != nil {
					t.Fatalf("%s path: %v", impl.name, err)
				}
				if len(flows) != rc.wantFlows {
					t.Fatalf("%s path: %d flow(s), want %d: %+v", impl.name, len(flows), rc.wantFlows, flows)
				}
				if rc.wantFlows == 1 && !samePath(flows[0].Path, rc.wantPath) {
					t.Fatalf("%s path: witness %v, want %v", impl.name, flows[0].Path, rc.wantPath)
				}
			}
		})
	}
}

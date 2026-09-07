package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A binding describes one call with two outputs: the sink lands on the argument
// node, the check on the call node the argument flows into. Java's `Paths.get`
// is both — a code.FilePathAccess sink at its arguments and a
// core.PathCanonicalization check at the call — so a path built from tainted
// components used to end the flow at the construction itself. Everything the
// constructed path was then handed to (`Files.newInputStream`) was never
// reported, and a containment check placed at that real guarded operation had
// no finding of its own to cover.
//
// The graph below is that shape: ctor is the neutralizer, and the tainted node
// that reaches it is the rule's own sink at the same call.
func taintedConstructionGraph() taintGraph {
	return taintGraph{
		name:  "neutralizer reached by the rule's own tainted sink at the same call",
		nodes: []string{"src", "ctorArg", "ctor", "use", "useArg"},
		labels: map[string]string{
			"src":     "test.Source",
			"ctorArg": "test.Sink",
			"ctor":    "test.Kill",
			"useArg":  "test.Sink",
		},
		edges: [][2]string{{"src", "ctorArg"}, {"ctorArg", "ctor"}, {"ctor", "use"}, {"use", "useArg"}},
		kills: map[string]bool{"test.Kill": true},
	}
}

func TestNeutralizerAtItsOwnTaintedSinkDoesNotAbsorbTaint(t *testing.T) {
	tg := taintedConstructionGraph()
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		got := map[string]bool{}
		for _, f := range flows {
			got[f.SinkID] = true
		}
		// Whether the construction itself is reported is the other half of the
		// contradiction, pinned by TestSinkNeutralizedAtItsOwnCallIsNotReported.
		if !got["useArg"] {
			t.Errorf("sink downstream of the neutralizing construction was not reported: %v", got)
		}
		for _, f := range flows {
			for _, nm := range f.NearMiss {
				if nm[0] == "ctor" {
					t.Errorf("neutralizer the flow ran straight through is still offered as near-miss evidence: %v", f.NearMiss)
				}
			}
		}
	})
}

// The other half of the same contradiction. The call the tainted sink is an
// argument of is declared a neutralizing control for this very rule, so it
// decides nothing here: with the operation the constructed value is handed to
// reported on the same witness path, the construction is not a second finding.
// jmix's CVE-2025-32950 fix inserts
// `path.toRealPath().startsWith(root.toRealPath())` immediately before
// `Files.newInputStream`; while the `Paths.get` inside an untouched helper was
// reported as well, no check at that operation — the fix's own idiom or any
// other — could cover it, and the report was identical on both revisions.
func TestSinkNeutralizedAtItsOwnCallIsNotReported(t *testing.T) {
	tg := taintedConstructionGraph()
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		got := map[string]bool{}
		for _, f := range flows {
			got[f.SinkID] = true
		}
		if got["ctorArg"] {
			t.Errorf("sink whose own call is a neutralizer for this rule is still reported: %v", got)
		}
		if !got["useArg"] {
			t.Errorf("the operation the constructed value is used in was not reported: %v", got)
		}
	})
}

// And it is a witness of last resort, not a witness the engine throws away.
// Where the flow reports nothing further along, the construction is the whole of
// the dangerous operation and stays the finding: jQuery's `$("<span>" + label +
// "</span>")` parses the markup at that very call, and javascript.controls also
// labels it core.HtmlEscape, so a rule that dropped it would lose the jQuery UI
// datepicker XSS (cve_rank1239) outright. Dropping the sink unconditionally does
// exactly that, measured in the spec suite.
func TestSinkNeutralizedAtItsOwnCallWithNothingDownstreamIsStillReported(t *testing.T) {
	tg := taintedConstructionGraph()
	tg.nodes = []string{"src", "ctorArg", "ctor"}
	tg.edges = [][2]string{{"src", "ctorArg"}, {"ctorArg", "ctor"}}
	delete(tg.labels, "useArg")
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		if len(flows) != 1 || flows[0].SinkID != "ctorArg" {
			t.Errorf("construction is the only sink the flow reaches and must still be reported: %v", flows)
		}
	})
}

// Supersession is keyed on the call, not on the one argument the witness path
// runs through. `Paths.get(parts[0], parts[1], parts[2], parts[3])` labels every
// argument a sink and jmix taints all four; keying it on the argument left the
// other three reported at the same line in the same helper, which is the whole
// of what the guard could not dominate.
func TestEveryArgumentOfANeutralizingCallIsSuperseded(t *testing.T) {
	tg := taintGraph{
		name:  "two tainted sink arguments of one neutralizing call",
		nodes: []string{"src", "argA", "argB", "ctor", "use", "useArg"},
		labels: map[string]string{
			"src": "test.Source", "argA": "test.Sink", "argB": "test.Sink",
			"ctor": "test.Kill", "useArg": "test.Sink",
		},
		edges: [][2]string{
			{"src", "argA"}, {"src", "argB"}, {"argA", "ctor"}, {"argB", "ctor"},
			{"ctor", "use"}, {"use", "useArg"},
		},
		kills: map[string]bool{"test.Kill": true},
	}
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		got := map[string]bool{}
		for _, f := range flows {
			got[f.SinkID] = true
		}
		if got["argA"] || got["argB"] {
			t.Errorf("an argument of the neutralizing call the witness path missed is still reported: %v", got)
		}
		if !got["useArg"] {
			t.Errorf("the operation the constructed value is used in was not reported: %v", got)
		}
	})
}

// The supersession is per witness path, not per run: an unrelated flow's sink
// elsewhere in the graph does not stand in for this one.
func TestSinkNeutralizedAtItsOwnCallSurvivesAnUnrelatedSink(t *testing.T) {
	tg := taintedConstructionGraph()
	tg.nodes = []string{"src", "ctorArg", "ctor", "other", "otherArg"}
	tg.edges = [][2]string{{"src", "ctorArg"}, {"ctorArg", "ctor"}, {"src", "other"}, {"other", "otherArg"}}
	delete(tg.labels, "useArg")
	tg.labels["otherArg"] = "test.Sink"
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		got := map[string]bool{}
		for _, f := range flows {
			got[f.SinkID] = true
		}
		if !got["ctorArg"] || !got["otherArg"] {
			t.Errorf("a sink on a sibling path is not this flow's witness: %v", got)
		}
	})
}

// The disqualification is threat-scoped. A neutralizer reached by a sink the
// rule does not ask about is an ordinary sanitizer and still absorbs the taint,
// so a rule keeps the precision every unrelated `check` binding buys it.
func TestNeutralizerReachedByAnotherRulesSinkStillAbsorbsTaint(t *testing.T) {
	tg := taintedConstructionGraph()
	tg.labels["ctorArg"] = "test.OtherSink"
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		if len(flows) != 0 {
			t.Errorf("neutralizer stopped absorbing taint for a sink concept this rule does not report: %v", flows)
		}
	})
}

// And it is taint-sensitive, which is what keeps a real sanitizer real. jQuery's
// `$("<div/>", {text: t})` is a core.HtmlEscape check whose code.HtmlRender sink
// label sits on the constant markup argument, not on the escaped one: the sink
// is a sibling of the tainted value, never tainted itself, so the escape still
// neutralizes and the flow stops there.
func TestNeutralizerWithAnUntaintedSiblingSinkStillAbsorbsTaint(t *testing.T) {
	tg := taintGraph{
		name:  "neutralizer whose sink label is on an untainted sibling argument",
		nodes: []string{"src", "taintedArg", "constArg", "escape", "use", "useArg"},
		labels: map[string]string{
			"src":      "test.Source",
			"constArg": "test.Sink",
			"escape":   "test.Kill",
			"useArg":   "test.Sink",
		},
		edges: [][2]string{
			{"src", "taintedArg"}, {"taintedArg", "escape"}, {"constArg", "escape"},
			{"escape", "use"}, {"use", "useArg"},
		},
		kills: map[string]bool{"test.Kill": true},
	}
	forEachStore(t, tg, func(t *testing.T, flows []TaintFlow) {
		if len(flows) != 0 {
			t.Errorf("a sanitizer stopped absorbing taint because an untainted sibling argument carries a sink label: %v", flows)
		}
	})
}

// forEachStore runs one scenario through both fixpoint implementations — the
// string-keyed one and the int-indexed twin production always takes.
func forEachStore(t *testing.T, tg taintGraph, check func(*testing.T, []TaintFlow)) {
	t.Helper()
	for _, tc := range []struct {
		name  string
		store usg.Store
	}{
		{"string path", usg.NewInMemStore()},
		{"int path", usg.NewIntStore(len(tg.nodes))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flows, err := FindTaintFlows(tg.build(t, tc.store), set("test.Source"), set("test.Sink"),
				set("test.Kind"), set("test.Kill"), "", set())
			if err != nil {
				t.Fatal(err)
			}
			check(t, flows)
		})
	}
}

package solvers

import (
	"reflect"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// callSiteGraph is a scenario in the shape the shared Param/Return pair of a lowered
// function produces: one helper invoked at two call sites, its parameter fed by a
// different value at each. The builder mints REAL node types — code.Call carrying its
// argument ids, code.Arg, code.Param, code.Return — because the witness walk keys on
// exactly those.
type callSiteGraph struct {
	name    string
	nodes   []usg.Node
	labels  [][2]string // node -> concept
	edges   [][2]string
	wantSrc string   // the origin a witness must report
	wantArg string   // the entry the witness must run through ("" = no repair expected)
	wantNo  []string // nodes the witness must NOT run through
}

func (cg callSiteGraph) build(t *testing.T, s usg.Store) usg.Store {
	t.Helper()
	for _, n := range cg.nodes {
		if err := s.AddNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range cg.labels {
		if err := s.AddLabel(l[0], usg.Label{Concept: l[1]}); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range cg.edges {
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// callSiteScenarios returns the helper-invoked-twice shape in three variants. src1 is the
// value entering at the SECOND call site (argB), src2 the value entering at the FIRST
// (argA); the sink consumes the FIRST call's result, so the origin that can actually
// reach it in the program is src2 — the value that entered at the same site the witness
// exits through.
func callSiteScenarios() []callSiteGraph {
	shape := func(name string, src1, src2, wantSrc, wantArg string, wantNo []string) callSiteGraph {
		return callSiteGraph{
			name: name,
			nodes: []usg.Node{
				{ID: src1, Type: "code.Call", Loc: "app.go:9"},
				{ID: src2, Type: "code.Call", Loc: "http_client.go:36"},
				{ID: "argA", Type: "code.Arg", Loc: "app.go:2", Props: map[string]string{"slot": "0"}},
				{ID: "argB", Type: "code.Arg", Loc: "app.go:3", Props: map[string]string{"slot": "0"}},
				{ID: "param", Type: "code.Param", Loc: "app.go:10", Props: map[string]string{"func": "helper", "name": "v"}},
				{ID: "body", Type: "code.Name", Loc: "app.go:11"},
				{ID: "ret", Type: "code.Return", Loc: "app.go:12", Props: map[string]string{"func": "helper"}},
				{ID: "callA", Type: "code.Call", Loc: "app.go:2", Props: map[string]string{"arg0": "argA"}},
				{ID: "callB", Type: "code.Call", Loc: "app.go:3", Props: map[string]string{"arg0": "argB"}},
				{ID: "sink", Type: "code.Arg", Loc: "app.go:4"},
			},
			labels: [][2]string{
				{src1, "test.Source"}, {src2, "test.Source"}, {"sink", "test.Sink"},
			},
			edges: [][2]string{
				{src1, "argB"}, {src2, "argA"},
				{"argA", "param"}, {"argB", "param"},
				{"param", "body"}, {"body", "ret"},
				{"ret", "callA"}, {"ret", "callB"},
				{"callA", "sink"},
			},
			wantSrc: wantSrc, wantArg: wantArg, wantNo: wantNo,
		}
	}
	return []callSiteGraph{
		// The gap: the second site's value tainted the shared parameter first, so the
		// blind pred walk reports the OTHER invocation's argument — the crossing witness.
		shape("crossing witness is re-anchored to the exiting call site", "src1", "src2", "src2", "argA", []string{"argB"}),
		// When the first tainter already entered at the site the witness exits through,
		// the walk must not disturb the chain.
		shape("already-consistent witness is kept", "srcB", "srcA", "srcA", "argA", []string{"argB"}),
		// The site-consistent argument carries no taint: there is no real path through it,
		// so the crossing stands and today's witness is the only one there is.
		shape("no site-consistent taint keeps the crossing witness", "src1", "src2-untainted", "src1", "argB", []string{"argA"}),
	}
}

// The untainted-entry variant needs src2's edge dropped: callSiteScenarios wires both
// sources in, so the third scenario is rebuilt without the src2 -> argA edge.
func crossingOnlyScenarios() []callSiteGraph {
	gs := callSiteScenarios()
	edges := make([][2]string, 0, len(gs[2].edges))
	for _, e := range gs[2].edges {
		if e[0] == "src2-untainted" {
			continue
		}
		edges = append(edges, e)
	}
	gs[2].edges = edges
	return gs
}

func TestWitnessExitsThroughTheCallSiteItEntered(t *testing.T) {
	for _, cg := range crossingOnlyScenarios() {
		t.Run(cg.name, func(t *testing.T) {
			for _, build := range []struct {
				name string
				mk   func() usg.Store
			}{
				{"string path", func() usg.Store { return usg.NewInMemStore() }},
				{"int path", func() usg.Store { return usg.NewIntStore(len(cg.nodes)) }},
			} {
				t.Run(build.name, func(t *testing.T) {
					flows, err := FindTaintFlows(cg.build(t, build.mk()),
						set("test.Source"), set("test.Sink"), set("test.Kind"), nil, "", set())
					if err != nil {
						t.Fatal(err)
					}
					if len(flows) != 1 {
						t.Fatalf("want exactly one flow, got %d: %+v", len(flows), flows)
					}
					f := flows[0]
					if f.SourceID != cg.wantSrc {
						t.Fatalf("reported source = %q, want %q (path %v)", f.SourceID, cg.wantSrc, f.Path)
					}
					if f.SinkID != "sink" {
						t.Fatalf("reported sink = %q, want sink", f.SinkID)
					}
					onPath := map[string]bool{}
					for _, id := range f.Path {
						onPath[id] = true
					}
					if cg.wantArg != "" && !onPath[cg.wantArg] {
						t.Fatalf("witness does not enter through %q: %v", cg.wantArg, f.Path)
					}
					for _, id := range cg.wantNo {
						if onPath[id] {
							t.Fatalf("witness runs through %q: %v", id, f.Path)
						}
					}
					if len(f.Path) < 2 || f.Path[0] != f.SourceID || f.Path[len(f.Path)-1] != f.SinkID {
						t.Fatalf("witness path is not source..sink: %v", f.Path)
					}
				})
			}
		})
	}
}

// nestedCallSiteGraphs is the wrapper idiom the flat shape abstracts away: a helper
// whose body calls a SECOND helper and returns its result (`func (s httpClient) get(e)
// { return s.do(req) }`), invoked at two sites. The inner call sits between entering
// the outer helper and leaving it, so a walk that carries only the innermost call site
// loses the outer one before it reaches the outer param — and reports the other
// invocation's value there, the same crossing the flat repair exists to undo.
func nestedCallSiteGraphs() []callSiteGraph {
	shape := func(name, src1, src2, wantSrc, wantArg string) callSiteGraph {
		return callSiteGraph{
			name: name,
			nodes: []usg.Node{
				{ID: src1, Type: "code.Call", Loc: "app.go:9"},
				{ID: src2, Type: "code.Call", Loc: "http_client.go:36"},
				{ID: "argA", Type: "code.Arg", Loc: "app.go:2", Props: map[string]string{"slot": "0"}},
				{ID: "argB", Type: "code.Arg", Loc: "app.go:3", Props: map[string]string{"slot": "0"}},
				{ID: "param", Type: "code.Param", Loc: "app.go:10", Props: map[string]string{"func": "outer", "name": "v"}},
				// the inner invocation, inside outer's body: outer passes its own param on
				{ID: "argI", Type: "code.Arg", Loc: "app.go:11", Props: map[string]string{"slot": "0"}},
				{ID: "paramI", Type: "code.Param", Loc: "app.go:20", Props: map[string]string{"func": "inner", "name": "w"}},
				{ID: "bodyI", Type: "code.Name", Loc: "app.go:21"},
				{ID: "retI", Type: "code.Return", Loc: "app.go:22", Props: map[string]string{"func": "inner"}},
				{ID: "callI", Type: "code.Call", Loc: "app.go:11", Props: map[string]string{"arg0": "argI"}},
				{ID: "ret", Type: "code.Return", Loc: "app.go:12", Props: map[string]string{"func": "outer"}},
				{ID: "callA", Type: "code.Call", Loc: "app.go:2", Props: map[string]string{"arg0": "argA"}},
				{ID: "callB", Type: "code.Call", Loc: "app.go:3", Props: map[string]string{"arg0": "argB"}},
				{ID: "sink", Type: "code.Arg", Loc: "app.go:4"},
			},
			labels: [][2]string{
				{src1, "test.Source"}, {src2, "test.Source"}, {"sink", "test.Sink"},
			},
			edges: [][2]string{
				{src1, "argB"}, {src2, "argA"},
				{"argA", "param"}, {"argB", "param"},
				{"param", "argI"},
				{"argI", "paramI"},
				{"paramI", "bodyI"}, {"bodyI", "retI"},
				{"retI", "callI"}, // inner return attributed to the call inside outer
				{"callI", "ret"},  // outer returns the inner call's result
				{"ret", "callA"}, {"ret", "callB"},
				{"callA", "sink"},
			},
			wantSrc: wantSrc, wantArg: wantArg, wantNo: []string{"argB"},
		}
	}
	gs := []callSiteGraph{
		// The second site's value tainted the outer param first and the inner call
		// sits between the outer entry and the outer param: the walk must still
		// re-anchor at the OUTER param to the first site's argument.
		shape("crossing witness re-anchors at the outer level past an inner call", "src1", "src2", "src2", "argA"),
	}
	// The fallback twin: with no site-consistent taint at the outer level (src2 cut),
	// the crossing witness is the only real one and must stand.
	fb := shape("no site-consistent outer taint keeps the crossing witness", "src1", "src2-gone", "src1", "argB")
	fb.wantNo = []string{"argA"}
	edges := make([][2]string, 0, len(fb.edges))
	for _, e := range fb.edges {
		if e[0] == "src2-gone" {
			continue
		}
		edges = append(edges, e)
	}
	fb.edges = edges
	return append(gs, fb)
}

// The witness keeps the call site it entered a helper through even when the helper's
// body passes through another helper call on the way to its parameter: the frames nest
// rather than replace each other. Both solver twins, and the re-anchored path must be
// real edges all the way.
func TestWitnessKeepsTheOuterFrameThroughANestedCall(t *testing.T) {
	for _, cg := range nestedCallSiteGraphs() {
		t.Run(cg.name, func(t *testing.T) {
			for _, build := range []struct {
				name string
				mk   func() usg.Store
			}{
				{"string path", func() usg.Store { return usg.NewInMemStore() }},
				{"int path", func() usg.Store { return usg.NewIntStore(len(cg.nodes)) }},
			} {
				t.Run(build.name, func(t *testing.T) {
					flows, err := FindTaintFlows(cg.build(t, build.mk()),
						set("test.Source"), set("test.Sink"), set("test.Kind"), nil, "", set())
					if err != nil {
						t.Fatal(err)
					}
					if len(flows) != 1 {
						t.Fatalf("want exactly one flow, got %d: %+v", len(flows), flows)
					}
					f := flows[0]
					if f.SourceID != cg.wantSrc {
						t.Fatalf("reported source = %q, want %q (path %v)", f.SourceID, cg.wantSrc, f.Path)
					}
					adj := map[string]bool{}
					for _, e := range cg.edges {
						adj[e[0]+"->"+e[1]] = true
					}
					p := f.Path
					if len(p) < 2 || p[0] != f.SourceID || p[len(p)-1] != f.SinkID {
						t.Fatalf("witness path is not source..sink: %v", p)
					}
					for i := 0; i+1 < len(p); i++ {
						if !adj[p[i]+"->"+p[i+1]] {
							t.Fatalf("witness step %s -> %s is not an edge in the graph", p[i], p[i+1])
						}
					}
					for _, id := range cg.wantNo {
						if containsID(p, id) {
							t.Fatalf("witness runs through %q: %v", id, p)
						}
					}
					if cg.wantArg != "" && !containsID(p, cg.wantArg) {
						t.Fatalf("witness does not enter through %q: %v", cg.wantArg, p)
					}
				})
			}
		})
	}
}

// The one shape the re-anchor can chase forever: one helper invoked at three sites
// whose results feed each other's arguments — site 2's result is site 3's argument and
// site 3's is site 2's — with the source entering at site 1. The fixpoint is untroubled
// (taint is a fixpoint; cycles are its daily work), but the witness walk re-anchors at
// the shared param every time it passes: pred(param) is site 1's argument, which
// belongs to neither rotating frame, so each pass jumps to the exiting frame's own
// argument — whose pred chain then runs back to the param through the OTHER frame's
// call, pushing that frame in turn. The walk rotates param -> a3 -> c2 -> ret -> body
// -> param -> a2 -> c3 -> ret -> ... without end, and the step budget is what stops
// it. The finding must still carry a witness — the recorded pred chain, itself a real
// source->sink path — rather than hang the scan or drop the flow.
func TestMutualWrapRotationFallsBackToTheRecordedWitness(t *testing.T) {
	cg := callSiteGraph{
		nodes: []usg.Node{
			{ID: "src", Type: "code.Call", Loc: "app.go:9"},
			{ID: "a1", Type: "code.Arg", Loc: "app.go:2", Props: map[string]string{"slot": "0"}},
			{ID: "a2", Type: "code.Arg", Loc: "app.go:3", Props: map[string]string{"slot": "0"}},
			{ID: "a3", Type: "code.Arg", Loc: "app.go:4", Props: map[string]string{"slot": "0"}},
			{ID: "param", Type: "code.Param", Loc: "app.go:10", Props: map[string]string{"func": "helper", "name": "v"}},
			{ID: "body", Type: "code.Name", Loc: "app.go:11"},
			{ID: "ret", Type: "code.Return", Loc: "app.go:12", Props: map[string]string{"func": "helper"}},
			{ID: "c1", Type: "code.Call", Loc: "app.go:2", Props: map[string]string{"arg0": "a1"}},
			{ID: "c2", Type: "code.Call", Loc: "app.go:3", Props: map[string]string{"arg0": "a2"}},
			{ID: "c3", Type: "code.Call", Loc: "app.go:4", Props: map[string]string{"arg0": "a3"}},
			{ID: "sink", Type: "code.Arg", Loc: "app.go:5"},
		},
		labels: [][2]string{{"src", "test.Source"}, {"sink", "test.Sink"}},
		edges: [][2]string{
			{"src", "a1"},
			{"a1", "param"}, {"a2", "param"}, {"a3", "param"},
			{"param", "body"}, {"body", "ret"},
			{"ret", "c1"}, {"ret", "c2"}, {"ret", "c3"},
			{"c2", "a3"}, {"c3", "a2"}, // the rotating sites feed each other's arguments
			{"c3", "sink"},
		},
	}
	// The witness the fallback must produce, exactly: the fixpoint's own pred chain from
	// the sink. It is forced regardless of taint order — param is tainted by a1 before
	// a2 or a3 can exist as taint sources (both hang off calls reached only THROUGH
	// param), and every other node on the chain has exactly one tainter — so both twins
	// must report this path and nothing else.
	want := []string{"src", "a1", "param", "body", "ret", "c3", "sink"}
	for _, build := range []struct {
		name string
		mk   func() usg.Store
	}{
		{"string path", func() usg.Store { return usg.NewInMemStore() }},
		{"int path", func() usg.Store { return usg.NewIntStore(len(cg.nodes)) }},
	} {
		t.Run(build.name, func(t *testing.T) {
			flows, err := FindTaintFlows(cg.build(t, build.mk()),
				set("test.Source"), set("test.Sink"), set("test.Kind"), nil, "", set())
			if err != nil {
				t.Fatal(err)
			}
			if len(flows) != 1 {
				t.Fatalf("want exactly one flow, got %d: %+v", len(flows), flows)
			}
			f := flows[0]
			if f.SourceID != "src" || f.SinkID != "sink" {
				t.Fatalf("reported %q -> %q, want src -> sink", f.SourceID, f.SinkID)
			}
			if !reflect.DeepEqual(f.Path, want) {
				t.Fatalf("witness = %v, want the recorded pred chain %v", f.Path, want)
			}
		})
	}
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// The re-anchored witness is still a path in the graph: every consecutive pair is a real
// FLOWS edge. The repair may only choose among edges that exist; this pins that it does.
func TestReanchoredWitnessIsARealPath(t *testing.T) {
	for _, cg := range callSiteScenarios() {
		t.Run(cg.name, func(t *testing.T) {
			s := cg.build(t, usg.NewIntStore(len(cg.nodes)))
			flows, err := FindTaintFlows(s, set("test.Source"), set("test.Sink"), set("test.Kind"), nil, "", set())
			if err != nil {
				t.Fatal(err)
			}
			if len(flows) != 1 {
				t.Fatalf("want exactly one flow, got %d", len(flows))
			}
			adj := map[string]bool{}
			for _, e := range cg.edges {
				adj[e[0]+"->"+e[1]] = true
			}
			p := flows[0].Path
			for i := 0; i+1 < len(p); i++ {
				if !adj[p[i]+"->"+p[i+1]] {
					t.Fatalf("witness step %s -> %s is not an edge in the graph", p[i], p[i+1])
				}
			}
		})
	}
}

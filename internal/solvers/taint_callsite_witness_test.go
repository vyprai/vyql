package solvers

import (
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

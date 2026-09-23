package taint

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/lower"
	"github.com/vyprai/vyql/internal/vygraph/nir"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

func onto(t *testing.T) *ontology.Ontology {
	t.Helper()
	o := ontology.New()
	for _, c := range []ontology.Concept{
		{Name: "code.HttpInput", Kinds: []ontology.Kind{ontology.KindSource}, Taint: []string{"UntrustedData"}},
		{Name: "code.PathTaint", Kinds: []ontology.Kind{ontology.KindSource}, Taint: []string{"PathData"}},
		{Name: "code.SqlExecution", Kinds: []ontology.Kind{ontology.KindSink}, VulnerableTo: []string{"Injection"}, EnabledBy: []string{"UntrustedData"}},
		{Name: "code.FilePathAccess", Kinds: []ontology.Kind{ontology.KindSink}, VulnerableTo: []string{"Traversal"}, EnabledBy: []string{"PathData"}},
	} {
		if err := o.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

// program builds the NIR graph for a source string with the real pipeline:
// frontend extraction + shared lowering.
func program(t *testing.T, src string) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	fe := python.New(g)
	if err := fe.Extract("app.py", []byte(src)); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if err := lower.Run(g, fe.Imports); err != nil {
		t.Fatalf("lower: %v", err)
	}
	return g
}

func label(t *testing.T, g *graph.Store, id, concept string) {
	t.Helper()
	if err := g.AddLabel(graph.Label{Target: id, Concept: concept, Confidence: 1,
		Prov: graph.Provenance{Producer: "t", Build: graph.BuildLabeled, Trust: graph.TrustTrusted}}); err != nil {
		t.Fatal(err)
	}
}

func callByPath(t *testing.T, g *graph.Store, path string) graph.Node {
	t.Helper()
	for _, n := range g.NodesOfType("code.Call") {
		if v, ok := n.Fields.Get("path"); ok && v.S == path {
			return n
		}
	}
	t.Fatalf("no Call with path %q", path)
	return graph.Node{}
}

func TestArmedFlowCarriesWitness(t *testing.T) {
	g := program(t, `def h(req):
    q = req.args.get("q")
    sql = "SELECT * FROM t WHERE n = " + q
    session.execute(sql)
`)
	src := callByPath(t, g, "req.args.get")
	snk := callByPath(t, g, "session.execute")
	label(t, g, src.ID, "code.HttpInput")
	label(t, g, snk.ID, "code.SqlExecution")

	s := New(onto(t))
	res, err := s.Solve(g, solver.Input{Sources: []string{src.ID}, Targets: []string{snk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1 armed flow", len(res))
	}
	f := res[0].(solver.Flow)
	rendered := solver.ProofTree(f).Render()
	for _, want := range []string{"FLOWS"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("witness %q missing %q", rendered, want)
		}
	}
}

// The arming gate: a path-tainted source reaching a SQL sink reaches it but
// never arms — there is nothing to suppress.
func TestArmingGateKindMismatchNeverArms(t *testing.T) {
	g := program(t, `def h(req):
    p = req.args.get("p")
    sql = "SELECT * FROM t WHERE n = " + p
    session.execute(sql)
`)
	src := callByPath(t, g, "req.args.get")
	snk := callByPath(t, g, "session.execute")
	label(t, g, src.ID, "code.PathTaint")
	label(t, g, snk.ID, "code.SqlExecution")

	s := New(onto(t))
	res, err := s.Solve(g, solver.Input{Sources: []string{src.ID}, Targets: []string{snk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("a path-tainted flow into a SQL sink must not arm, got %d", len(res))
	}
}

// Interprocedural reach by summary instantiation: taint into a helper's
// argument reaches the sink inside the callee.
func TestInterproceduralThroughCallSummary(t *testing.T) {
	g := program(t, `def run_query(sql):
    session.execute(sql)

def h(req):
    q = req.args.get("q")
    run_query("SELECT 1 WHERE x = " + q)
`)
	src := callByPath(t, g, "req.args.get")
	snk := callByPath(t, g, "session.execute")
	label(t, g, src.ID, "code.HttpInput")
	label(t, g, snk.ID, "code.SqlExecution")

	s := New(onto(t))
	res, err := s.Solve(g, solver.Input{Sources: []string{src.ID}, Targets: []string{snk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("interprocedural results = %d, want 1", len(res))
	}
	if !strings.Contains(solver.ProofTree(res[0].(solver.Flow)).Render(), "CALLS") {
		t.Fatal("the witness must record the CALLS instantiation step")
	}
}

// Mutual recursion terminates by fixpoint (the visited-pair cut), not by
// inlining, and still finds reachable sinks.
func TestMutualRecursionTerminatesByFixpoint(t *testing.T) {
	g := program(t, `def a(x):
    return b(x)

def b(x):
    return a(x)

def sink_side(v):
    session.execute(v)

def h(req):
    q = req.args.get("q")
    r = a(q)
    sink_side(r)
`)
	src := callByPath(t, g, "req.args.get")
	snk := callByPath(t, g, "session.execute")
	label(t, g, src.ID, "code.HttpInput")
	label(t, g, snk.ID, "code.SqlExecution")

	s := New(onto(t))
	res, err := s.Solve(g, solver.Input{Sources: []string{src.ID}, Targets: []string{snk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("recursive results = %d, want 1 through the a/b cycle", len(res))
	}
}

// The taint-through conduit: a tainted write of a column joins a later read of
// the same table+column — column-granular over-approximation.
func TestConduitJoinsColumnWriteToRead(t *testing.T) {
	s := graph.NewSchemas()
	nir.Register(s)
	if err := s.Register(&graph.TypeSchema{Type: "code.DataAccess", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "table", Kind: graph.KindString},
			{Name: "op", Kind: graph.KindEnum, Enum: []string{"read", "write"}},
			{Name: "filters", Kind: graph.KindList, Elem: graph.KindString},
		}, Key: []string{"table", "op"}}); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	mk := func(id, table string, filters ...string) {
		var f graph.Fields
		f.Set("op", graph.Value{Kind: graph.KindEnum, S: "read"})
		f.Set("table", graph.Str(table))
		lst := graph.Value{Kind: graph.KindList, Elem: graph.KindString}
		for _, fl := range filters {
			lst.L = append(lst.L, graph.Str(fl))
		}
		f.Set("filters", lst)
		if err := g.AddNode(graph.Node{ID: id, Type: "code.DataAccess", Layer: graph.LayerHigh, Fields: f}); err != nil {
			t.Fatal(err)
		}
	}
	mk("w1", "users", "bio")
	mk("r1", "users", "bio")
	mk("r2", "users", "created_at")
	mk("r3", "orders", "bio")
	if !Conduit(g, "w1", "r1") {
		t.Fatal("same table + same column must join")
	}
	if Conduit(g, "w1", "r2") {
		t.Fatal("same table, different column must not join")
	}
	if Conduit(g, "w1", "r3") {
		t.Fatal("different table must not join")
	}
}

// A witness crossing an approx_lowered node carries the fidelity marker, so
// downstream clamps cap confidence and emit a coverage signal.
func TestApproxLoweredMarksWitness(t *testing.T) {
	g := program(t, `def h(req):
    p = match_case(req.args.get("p"))
    session.execute("SELECT " + p)
`)
	// Stamp the unknown-construct wrapper approx (the frontend already stamps
	// unknown constructs; match_case is an unresolvable call, its arg chain is
	// exact — so force one node approx to exercise the marker path).
	for _, n := range g.NodesOfType("code.Call") {
		if v, _ := n.Fields.Get("path"); v.S == "match_case" {
			stored, _ := g.Node(n.ID)
			var f graph.Fields = stored.Fields
			f.Set("approx_lowered", graph.Bool(true))
			stored.Fields = f
			_ = g.Upsert(stored)
		}
	}
	src := callByPath(t, g, "req.args.get")
	snk := callByPath(t, g, "session.execute")
	label(t, g, src.ID, "code.HttpInput")
	label(t, g, snk.ID, "code.SqlExecution")

	s := New(onto(t))
	res, err := s.Solve(g, solver.Input{Sources: []string{src.ID}, Targets: []string{snk.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d", len(res))
	}
	rendered := solver.ProofTree(res[0].(solver.Flow)).Render()
	if !strings.Contains(rendered, "approx_lowered") {
		t.Fatalf("witness must carry the approx marker: %q", rendered)
	}
}

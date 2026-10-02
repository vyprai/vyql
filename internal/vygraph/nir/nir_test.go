package nir

import (
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

func TestRegistersClosedExprSet(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, m := range ExprMembers {
		ts, ok := s.Lookup(m)
		if !ok {
			t.Fatalf("closed-set member %s not registered", m)
		}
		if ts.Layer != graph.LayerLow {
			t.Fatalf("%s must be a low-level node, got %v", m, ts.Layer)
		}
	}
	// The ISA is closed: registering anything beyond the named members under the
	// code. prefix is an extension, not a frontend's private business.
	for _, m := range []string{"code.NotARealExpr"} {
		if _, ok := s.Lookup(m); ok {
			t.Fatalf("%s registered — the Expr set leaked", m)
		}
	}
	// Edge types: the value substrate, the call graph, and parse containment.
	for _, e := range []string{"FLOWS", "CALLS", "child"} {
		if _, ok := s.Lookup(e); !ok {
			t.Fatalf("edge type %s not registered", e)
		}
	}
}

func TestPathFieldsAreTypedAndSplit(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	ts, _ := s.Lookup("code.Call")
	spec, ok := func() (graph.FieldSpec, bool) {
		for _, f := range ts.Fields {
			if f.Name == "path" {
				return f, true
			}
		}
		return graph.FieldSpec{}, false
	}()
	if !ok || spec.Kind != graph.KindString {
		t.Fatalf("path spec = %+v — must be a declared string", spec)
	}
	qp, ok := func() (graph.FieldSpec, bool) {
		for _, f := range ts.Fields {
			if f.Name == "qualified_path" {
				return f, true
			}
		}
		return graph.FieldSpec{}, false
	}()
	if !ok || qp.Kind != graph.KindString {
		t.Fatalf("qualified_path spec = %+v — the two path fields are load-bearing", qp)
	}
}

// The store must accept a stamped, resolved call node and reject kind violations.
func TestStampedNodesRoundTrip(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)

	var f graph.Fields
	Stamp(&f, "app.py", 12, 5, "fn", 7, false)
	f.Set("callee", graph.Str("execute"))
	f.Set("path", graph.Str("db.session.execute"))
	f.Set("qualified_path", graph.Str("sqlalchemy.orm.session.execute"))
	f.Set("region", graph.Str("fn"))
	f.Set("order", graph.Int(7))
	if err := g.AddNode(graph.Node{ID: "c1", Type: "code.Call", Layer: graph.LayerLow, Fields: f}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	var bad graph.Fields
	Stamp(&bad, "app.py", 13, 1, "fn", 8, false)
	bad.Set("order", graph.Str("eight")) // order is an int
	if err := g.AddNode(graph.Node{ID: "c2", Type: "code.Call", Layer: graph.LayerLow, Fields: bad}); err == nil {
		t.Fatal("a string in the int order field must be rejected — never a silent miss")
	}
}

// approx_lowered is the fidelity marker: it must be a declared bool on every
// code node so an approximately-lowered region can never mint a high-confidence
// finding silently.
func TestApproxLoweredIsDeclared(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	for _, m := range ExprMembers {
		ts, _ := s.Lookup(m)
		found := false
		for _, f := range ts.Fields {
			if f.Name == "approx_lowered" && f.Kind == graph.KindBool {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s lacks the approx_lowered bool", m)
		}
	}
}

// ParamEntry carries the generic decorator facts the frontend records and the
// framework model interprets — never a domain meaning.
func TestFuncDefWithParamEntries(t *testing.T) {
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)

	var fd graph.Fields
	Stamp(&fd, "app.py", 3, 1, "fn", 0, false)
	fd.Set("name", graph.Str("handler"))
	if err := g.AddNode(graph.Node{ID: "f1", Type: "code.FuncDef", Layer: graph.LayerLow, Fields: fd}); err != nil {
		t.Fatal(err)
	}
	var pe graph.Fields
	Stamp(&pe, "app.py", 3, 14, "fn", 1, false)
	pe.Set("name", graph.Str("req"))
	pe.Set("decorators", graph.List(graph.KindString, graph.Str("app.route")))
	if err := g.AddNode(graph.Node{ID: "p1", Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pe}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(graph.Edge{ID: "pc1", Type: "child", From: "f1", To: "p1"}); err != nil {
		t.Fatal(err)
	}

	n, _ := g.Node("p1")
	d, ok := n.Fields.Get("decorators")
	if !ok || d.Kind != graph.KindList || len(d.L) != 1 || d.L[0].S != "app.route" {
		t.Fatalf("decorators = %+v", d)
	}
}

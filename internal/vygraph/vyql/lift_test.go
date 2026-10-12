package vyql

import (
	"fmt"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

// liftSchemas registers the low-level NIR set plus the high-level domain types
// the lifts of this suite target. Domain schemas arrive as knowledge in the
// full design; in the engine test suite the fixtures declare them.
func liftSchemas(t *testing.T) *graph.Schemas {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	must := func(ts *graph.TypeSchema) {
		if err := s.Register(ts); err != nil {
			t.Fatalf("Register(%s): %v", ts.Type, err)
		}
	}
	must(&graph.TypeSchema{Type: "code.Entrypoint", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "httpMethod", Kind: graph.KindString},
			{Name: "httpPath", Kind: graph.KindString},
			{Name: "handler", Kind: graph.KindString},
		}, Key: []string{"handler"}})
	must(&graph.TypeSchema{Type: "code.DataAccess", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "table", Kind: graph.KindString},
			{Name: "op", Kind: graph.KindEnum, Enum: []string{"read", "write"}},
			{Name: "filters", Kind: graph.KindList, Elem: graph.KindString},
		}, Key: []string{"table", "op"}})
	must(&graph.TypeSchema{Type: "code.Function", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{{Name: "name", Kind: graph.KindString}}, Key: []string{"name"}})
	return s
}

func addFunc(t *testing.T, g *graph.Store, id, name string, line int) graph.Node {
	t.Helper()
	var f graph.Fields
	nir.Stamp(&f, "app.py", line, 1, "fn", 0, false)
	f.Set("name", graph.Str(name))
	if err := g.AddNode(graph.Node{ID: id, Type: "code.FuncDef", Layer: graph.LayerLow, Fields: f}); err != nil {
		t.Fatal(err)
	}
	n, _ := g.Node(id)
	return n
}

func addResolvedCall(t *testing.T, g *graph.Store, id, qualPath, method string, line int, args ...graph.Node) graph.Node {
	t.Helper()
	var f graph.Fields
	nir.Stamp(&f, "app.py", line, 1, "fn", 1, false)
	f.Set("path", graph.Str(qualPath))
	f.Set("qualified_path", graph.Str(qualPath))
	if method != "" {
		f.Set("method", graph.Str(method))
	}
	if err := g.AddNode(graph.Node{ID: id, Type: "code.Call", Layer: graph.LayerLow, Fields: f}); err != nil {
		t.Fatal(err)
	}
	for i, a := range args {
		if err := g.AddEdge(graph.Edge{ID: fmt.Sprintf("%s:arg%d", id, i), Type: "child", From: id, To: a.ID}); err != nil {
			t.Fatal(err)
		}
	}
	n, _ := g.Node(id)
	return n
}

func addName(t *testing.T, g *graph.Store, id, local string, line int) graph.Node {
	t.Helper()
	var f graph.Fields
	nir.Stamp(&f, "app.py", line, 3, "fn", 2, false)
	f.Set("local", graph.Str(local))
	if err := g.AddNode(graph.Node{ID: id, Type: "code.Name", Layer: graph.LayerLow, Fields: f}); err != nil {
		t.Fatal(err)
	}
	n, _ := g.Node(id)
	return n
}

func TestLiftBuildsHighNodeWithBacks(t *testing.T) {
	kb := kbOf(t, `module toy;
lift code.Function from code.func() { name: .name }
`)
	g := graph.New(liftSchemas(t))
	addFunc(t, g, "f1", "handler", 3)

	if err := ApplyLifts(kb, g); err != nil {
		t.Fatalf("ApplyLifts: %v", err)
	}
	highs := g.NodesOfType("code.Function")
	if len(highs) != 1 {
		t.Fatalf("lifted nodes = %d, want 1", len(highs))
	}
	h := highs[0]
	if v, _ := h.Fields.Get("name"); v.S != "handler" {
		t.Fatalf("name = %q", v.S)
	}
	if h.Layer != graph.LayerHigh || h.Prov.Build != graph.BuildLifted {
		t.Fatalf("lifted node = %+v", h)
	}
	b, ok := g.Backing(h.ID)
	if !ok || b.ID != "f1" {
		t.Fatalf("backs = %+v ok=%v — the automatic backs edge is load-bearing", b, ok)
	}

	// Re-applying the same lift merges (upsert by identity), not duplicates.
	if err := ApplyLifts(kb, g); err != nil {
		t.Fatal(err)
	}
	if got := len(g.NodesOfType("code.Function")); got != 1 {
		t.Fatalf("second application must merge, got %d nodes", got)
	}
}

func TestFrameworkRouteLiftsEntrypoints(t *testing.T) {
	kb := kbOf(t, `module toy;
framework express {
  route on code.call("app.get") {
    method: "GET"
    path:   arg(0)
    handler: arg(-1)
  }
}
lift code.Entrypoint from framework express {
  httpMethod: .method
  httpPath:   .path
  handler:    .handler
}
`)
	g := graph.New(liftSchemas(t))
	handler := addFunc(t, g, "f1", "listUsers", 5)
	p := addName(t, g, "npath", "/users", 6)
	h := addName(t, g, "nfn", "listUsers", 7)
	reg := addResolvedCall(t, g, "c1", "app.get", "get", 8, p, h)
	_ = reg

	if err := ApplyLifts(kb, g); err != nil {
		t.Fatalf("ApplyLifts: %v", err)
	}
	eps := g.NodesOfType("code.Entrypoint")
	if len(eps) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(eps))
	}
	e := eps[0]
	if v, _ := e.Fields.Get("httpMethod"); v.S != "GET" {
		t.Fatalf("httpMethod = %q", v.S)
	}
	if v, _ := e.Fields.Get("httpPath"); v.S != "/users" {
		t.Fatalf("httpPath = %q", v.S)
	}
	b, ok := g.Backing(e.ID)
	if !ok || b.ID != "f1" || b.ID != handler.ID {
		t.Fatalf("entrypoint must back the resolved handler FuncDef, got %+v", b)
	}
}

func TestDataAccessLiftCopiesFiltersFromFlows(t *testing.T) {
	kb := kbOf(t, `module toy;
lift code.DataAccess from code.call("db.filter") {
  table: .path
  op: "read"
  filters: from flows(self) by resolution
}
`)
	g := graph.New(liftSchemas(t))
	val := addName(t, g, "n1", "tenant_id", 10)
	call := addResolvedCall(t, g, "c1", "db.filter", "filter", 11, val)
	if err := g.AddEdge(graph.Edge{ID: "fl1", Type: "FLOWS", From: "n1", To: "c1"}); err != nil {
		t.Fatal(err)
	}
	_ = call

	if err := ApplyLifts(kb, g); err != nil {
		t.Fatalf("ApplyLifts: %v", err)
	}
	das := g.NodesOfType("code.DataAccess")
	if len(das) != 1 {
		t.Fatalf("data accesses = %d, want 1", len(das))
	}
	da := das[0]
	if v, _ := da.Fields.Get("table"); v.S != "db.filter" {
		t.Fatalf("table = %q", v.S)
	}
	if v, _ := da.Fields.Get("op"); v.S != "read" {
		t.Fatalf("op = %q", v.S)
	}
	fl, ok := da.Fields.Get("filters")
	if !ok || fl.Kind != graph.KindList || len(fl.L) != 1 || fl.L[0].S != "tenant_id" {
		t.Fatalf("filters = %+v — the copy form must copy the resolved FLOWS provenance", fl)
	}
}

func TestRelateByResolutionAndOverFlows(t *testing.T) {
	kb := kbOf(t, `module toy;
lift code.Function from code.func() { name: .name }
relate calls from code.Function to code.Function by resolution
relate flows_to from code.Function to code.Function over FLOWS
`)
	g := graph.New(liftSchemas(t))
	addFunc(t, g, "f1", "outer", 3)
	addFunc(t, g, "f2", "inner", 8)
	if err := g.AddEdge(graph.Edge{ID: "cal1", Type: "CALLS", From: "f1", To: "f2"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(graph.Edge{ID: "flo1", Type: "FLOWS", From: "f2", To: "f1"}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLifts(kb, g); err != nil {
		t.Fatal(err)
	}
	if err := ApplyRelates(kb, g); err != nil {
		t.Fatal(err)
	}
	highs := g.NodesOfType("code.Function")
	var calls, flows int
	for _, h := range highs {
		calls += len(g.Out(h.ID, "calls"))
		flows += len(g.Out(h.ID, "flows_to"))
	}
	if calls != 1 || flows != 1 {
		t.Fatalf("calls=%d flows_to=%d — relate must derive from the backings' CALLS/FLOWS", calls, flows)
	}
}

func TestDecoratedByPredicate(t *testing.T) {
	g := graph.New(liftSchemas(t))
	fd := addFunc(t, g, "f1", "handler", 3)
	var pe graph.Fields
	nir.Stamp(&pe, "app.py", 2, 1, "fn", 0, false)
	pe.Set("name", graph.Str("req"))
	pe.Set("decorators", graph.List(graph.KindString, graph.Str("app.route")))
	if err := g.AddNode(graph.Node{ID: "p1", Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pe}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(graph.Edge{ID: "pc", Type: "child", From: "f1", To: "p1"}); err != nil {
		t.Fatal(err)
	}

	lit := &Literal{Kind: TokString, Text: `"*.route"`}
	ok, err := evalWhere(g, &Call{Name: "decorated_by", Args: []Expr{lit}}, fd)
	if err != nil || !ok {
		t.Fatalf("decorated_by(*.route) = %v, %v — want true", ok, err)
	}
	lit2 := &Literal{Kind: TokString, Text: `"*.command"`}
	ok, err = evalWhere(g, &Call{Name: "decorated_by", Args: []Expr{lit2}}, fd)
	if err != nil || ok {
		t.Fatalf("decorated_by(*.command) = %v, %v — want false", ok, err)
	}
}

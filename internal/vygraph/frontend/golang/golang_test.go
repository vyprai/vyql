package golang

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

const fixture = `package app

import (
	"database/sql"
	nethttp "net/http"
)

func listUsers(w nethttp.ResponseWriter, r *nethttp.Request) {
	q := r.URL.Query().Get("q")
	stmt := "SELECT * FROM users WHERE name = " + q
	rows, err := db.Query(stmt)
	if err != nil {
		for i := 0; i < 3; i++ {
			nethttp.Error(w, "failed", 500)
		}
		return
	}
	defer rows.Close()
	_ = rows
}
`

func extract(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	fe := New(g)
	if err := fe.Extract("app.go", []byte(fixture)); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return g
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

func TestImportsCollected(t *testing.T) {
	s := graph.NewSchemas()
	nir.Register(s)
	g := graph.New(s)
	fe := New(g)
	if err := fe.Extract("app.go", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	imp := fe.Imports["app.go"]
	if imp.Modules["sql"] != "database/sql" || imp.Modules["nethttp"] != "net/http" {
		t.Fatalf("imports = %v", imp.Modules)
	}
}

func TestFuncAndParams(t *testing.T) {
	g := extract(t)
	var fn graph.Node
	for _, n := range g.NodesOfType("code.FuncDef") {
		if v, _ := n.Fields.Get("name"); v.S == "listUsers" {
			fn = n
		}
	}
	if fn.ID == "" {
		t.Fatal("listUsers must emit a FuncDef")
	}
	params := 0
	for _, e := range g.Out(fn.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.ParamEntry" {
			if v, _ := n.Fields.Get("name"); v.S == "w" || v.S == "r" {
				params++
			}
		}
	}
	if params != 2 {
		t.Fatalf("params = %d, want w and r", params)
	}
}

func TestCallShapesAndFormat(t *testing.T) {
	g := extract(t)
	get := callByPath(t, g, "r.URL.Query.Get")
	if v, _ := get.Fields.Get("method"); v.S != "Get" {
		t.Fatalf("method = %q", v.S)
	}
	// The concatenation is a Format with const + tainted parts.
	var fmtNode graph.Node
	for _, n := range g.NodesOfType("code.Format") {
		if txt, _ := n.Fields.Get("text"); strings.Contains(txt.S, "SELECT") {
			fmtNode = n
		}
	}
	if fmtNode.ID == "" {
		t.Fatal("the SQL concatenation must be a Format")
	}
	parts := 0
	for _, e := range g.Out(fmtNode.ID, "child") {
		if n, ok := g.Node(e.To); ok && (n.Type == "code.Name" || n.Type == "code.Const") {
			parts++
		}
	}
	if parts < 2 {
		t.Fatalf("format parts = %d", parts)
	}
	// Multi-assign: db.Query flows into rows and err.
	rows := func() graph.Node {
		for _, n := range g.NodesOfType("code.Name") {
			if v, _ := n.Fields.Get("local"); v.S == "rows" {
				return n
			}
		}
		return graph.Node{}
	}()
	hasFlow := false
	for _, e := range g.In(rows.ID, "FLOWS") {
		if from, ok := g.Node(e.From); ok && from.Type == "code.Call" {
			if v, _ := from.Fields.Get("path"); v.S == "db.Query" {
				hasFlow = true
			}
		}
	}
	if !hasFlow {
		t.Fatal("db.Query must def-flow into rows")
	}
}

func TestRegionsIncludeControlFlow(t *testing.T) {
	g := extract(t)
	errCall := callByPath(t, g, "nethttp.Error")
	reg, _ := errCall.Fields.Get("region")
	if !strings.Contains(reg.S, "/if#") || !strings.Contains(reg.S, "/then") ||
		!strings.Contains(reg.S, "/loop#") || !strings.Contains(reg.S, "/body") {
		t.Fatalf("nethttp.Error region = %q — the structured walk must encode the chain", reg.S)
	}
}

func TestDeterministicExtraction(t *testing.T) {
	g1 := extract(t)
	s := graph.NewSchemas()
	nir.Register(s)
	g2 := graph.New(s)
	if err := New(g2).Extract("app.go", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	if g1.NodeCount() != g2.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", g1.NodeCount(), g2.NodeCount())
	}
}

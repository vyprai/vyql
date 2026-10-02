package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

const fixture = `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    sql = "SELECT * FROM users WHERE name = " + q
    rows = session.execute(sql)
    if rows:
        for r in rows:
            print(r["name"])
    try:
        flush(rows)
    except Exception as e:
        log("failed", e)
    return rows
`

func extract(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	fe := New(g)
	if err := fe.Extract("app.py", []byte(fixture)); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return g
}

func findCall(t *testing.T, g *graph.Store, path string) graph.Node {
	t.Helper()
	for _, n := range g.NodesOfType("code.Call") {
		if v, ok := n.Fields.Get("path"); ok && v.S == path {
			return n
		}
	}
	t.Fatalf("no code.Call with path %q", path)
	return graph.Node{}
}

func TestImportsCollected(t *testing.T) {
	s := graph.NewSchemas()
	nir.Register(s)
	g := graph.New(s)
	fe := New(g)
	if err := fe.Extract("app.py", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	imp := fe.Imports["app.py"]
	if imp.Modules["flask"] != "flask" {
		t.Fatalf("flask import = %v", imp.Modules)
	}
	if imp.From["session"] != "db.session" {
		t.Fatalf("from import = %v", imp.From)
	}
}

func TestFuncDefWithDecoratedParamEntry(t *testing.T) {
	g := extract(t)
	fds := g.NodesOfType("code.FuncDef")
	if len(fds) != 1 {
		t.Fatalf("FuncDefs = %d, want 1", len(fds))
	}
	fd := fds[0]
	if v, _ := fd.Fields.Get("name"); v.S != "list_users" {
		t.Fatalf("name = %q", v.S)
	}
	// The ParamEntry carries the raw decorator token — a generic fact for a
	// framework model to interpret (never domain meaning in the frontend).
	var pe graph.Node
	for _, e := range g.Out(fd.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.ParamEntry" {
			pe = n
		}
	}
	if pe.ID == "" {
		t.Fatal("FuncDef has no ParamEntry child")
	}
	if v, _ := pe.Fields.Get("name"); v.S != "req" {
		t.Fatalf("param name = %q", v.S)
	}
	d, ok := pe.Fields.Get("decorators")
	if !ok || len(d.L) != 1 || !strings.HasPrefix(d.L[0].S, "flask.route") {
		t.Fatalf("decorators = %+v", d)
	}
}

func TestCallShapeAndArgs(t *testing.T) {
	g := extract(t)
	get := findCall(t, g, "req.args.get")
	if v, _ := get.Fields.Get("method"); v.S != "get" {
		t.Fatalf("method = %q", v.S)
	}
	args := 0
	for _, e := range g.Out(get.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.Const" {
			args++
		}
	}
	if args != 1 {
		t.Fatalf("call args = %d consts, want 1", args)
	}

	ex := findCall(t, g, "session.execute")
	// execute's argument is the variable sql (a Name); the string construction
	// lives in the prior statement as a Format with const + tainted parts.
	hasArg := false
	for _, e := range g.Out(ex.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.Name" {
			if v, _ := n.Fields.Get("local"); v.S == "sql" {
				hasArg = true
			}
		}
	}
	if !hasArg {
		t.Fatal("session.execute's argument must be the Name sql")
	}
	var fmtNode *graph.Node
	for _, n := range g.NodesOfType("code.Format") {
		nn := n
		fmtNode = &nn
	}
	if fmtNode == nil {
		t.Fatal("the concatenation must lower to a code.Format")
	}
	parts := 0
	for _, pe := range g.Out(fmtNode.ID, "child") {
		if pn, ok := g.Node(pe.To); ok {
			if pn.Type == "code.Name" || pn.Type == "code.Const" {
				parts++
			}
		}
	}
	if parts < 2 {
		t.Fatalf("format parts = %d, want the const and the tainted name", parts)
	}
}

func TestRegionsAndOrder(t *testing.T) {
	g := extract(t)
	ex := findCall(t, g, "session.execute")
	reg, _ := ex.Fields.Get("region")
	if reg.S != "fn:list_users" {
		t.Fatalf("call region = %q, want the function region", reg.S)
	}

	// A node inside the if/then → for/body chain carries both segments.
	print := findCall(t, g, "print")
	reg, _ = print.Fields.Get("region")
	if !strings.Contains(reg.S, "/if#") || !strings.Contains(reg.S, "/then") ||
		!strings.Contains(reg.S, "/loop#") || !strings.Contains(reg.S, "/body") {
		t.Fatalf("print region = %q — structured walk must encode the path", reg.S)
	}

	// The except handler sits under /try#/except.
	logCall := findCall(t, g, "log")
	reg, _ = logCall.Fields.Get("region")
	if !strings.Contains(reg.S, "/try#") || !strings.Contains(reg.S, "/except") {
		t.Fatalf("log region = %q", reg.S)
	}

	// Order is monotonic along the emission walk.
	get := findCall(t, g, "req.args.get")
	go1, _ := get.Fields.Get("order")
	go2, _ := print.Fields.Get("order")
	if go1.I >= go2.I {
		t.Fatalf("order not monotonic: get=%d print=%d", go1.I, go2.I)
	}
}

func TestSubscriptAndDottedPaths(t *testing.T) {
	g := extract(t)
	idxs := g.NodesOfType("code.Index")
	found := false
	for _, n := range idxs {
		if v, ok := n.Fields.Get("path"); ok && v.S == "r" {
			found = true
		}
	}
	if !found {
		t.Fatal("subscript r[\"name\"] must lower to a code.Index with path r")
	}
}

// Golden determinism: extracting the same source twice yields identical node
// sets (location-keyed identity).
func TestDeterministicExtraction(t *testing.T) {
	g1 := extract(t)
	s := graph.NewSchemas()
	nir.Register(s)
	g2 := graph.New(s)
	if err := New(g2).Extract("app.py", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	if g1.NodeCount() != g2.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", g1.NodeCount(), g2.NodeCount())
	}
}

func TestExtractFileFromDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.py")
	if err := os.WriteFile(p, []byte("def f(x):\n    return g(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := graph.NewSchemas()
	nir.Register(s)
	g := graph.New(s)
	if err := New(g).Extract("m.py", data); err != nil {
		t.Fatal(err)
	}
	if len(g.NodesOfType("code.FuncDef")) != 1 {
		t.Fatal("FuncDef missing")
	}
	if len(g.NodesOfType("code.Call")) != 1 {
		t.Fatal("call g(x) missing")
	}
}

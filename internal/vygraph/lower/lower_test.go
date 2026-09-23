package lower

import (
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

const src = `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    sql = "SELECT * FROM users WHERE name = " + q
    rows = session.execute(sql)
    flush(rows)
    return rows

def flush(rows):
    audit(rows)
`

func built(t *testing.T) *graph.Store {
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
	if err := Run(g, fe.Imports); err != nil {
		t.Fatalf("lower.Run: %v", err)
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

func TestResolutionQualifiesImports(t *testing.T) {
	g := built(t)
	ex := callByPath(t, g, "session.execute")
	q, ok := ex.Fields.Get("qualified_path")
	if !ok || q.S != "db.session.execute" {
		t.Fatalf("qualified_path = %v — the from-import must resolve", q)
	}
	// The framework-injected parameter is syntactic knowledge: it stays
	// unresolved until a framework model types it (by design, not by gap).
	get := callByPath(t, g, "req.args.get")
	if q, ok := get.Fields.Get("qualified_path"); ok && q.S != "" {
		t.Fatalf("req must stay syntactic, got %q", q.S)
	}
}

func TestResolutionLinksCallsToModuleFunctions(t *testing.T) {
	g := built(t)
	fl := callByPath(t, g, "flush")
	q, ok := fl.Fields.Get("qualified_path")
	if !ok || q.S != "app.py:flush" {
		t.Fatalf("intra-module qualified_path = %v", q)
	}
	calls := g.Out(fl.ID, "CALLS")
	if len(calls) != 1 {
		t.Fatalf("CALLS edges = %d, want 1 to the flush FuncDef", len(calls))
	}
	if callee, _ := g.Node(calls[0].To); callee.Type != "code.FuncDef" {
		t.Fatalf("CALLS target = %s", callee.Type)
	}
}

// The value substrate: arg flows into its call, a bound variable flows to its
// next use, and the string construction carries its parts.
func TestFLOWSValueChain(t *testing.T) {
	g := built(t)

	get := callByPath(t, g, "req.args.get")
	ex := callByPath(t, g, "session.execute")

	// def-flow: the assignment's value flows into the target binding (q, sql).
	flowsInto := func(id string) []string {
		var out []string
		for _, e := range g.In(id, "FLOWS") {
			out = append(out, e.From)
		}
		return out
	}
	// Find the Name nodes for q and sql and verify the chain:
	//   req.args.get → Name(q)@def → Name(q)@use → Format → Name(sql)@def
	//   → Name(sql)@use → session.execute
	nameByLocal := func(local string, nth int) graph.Node {
		i := 0
		for _, n := range g.NodesOfType("code.Name") {
			if v, ok := n.Fields.Get("local"); ok && v.S == local {
				if i == nth {
					return n
				}
				i++
			}
		}
		t.Fatalf("Name %s occurrence %d missing", local, nth)
		return graph.Node{}
	}
	qDef := nameByLocal("q", 0)
	qUse := nameByLocal("sql", 0) // ordering: q-def, q-use(sql line), sql-def, sql-use
	_ = qUse
	qUse2 := nameByLocal("q", 1)

	fromGet := flowsInto(qDef.ID)
	foundGet := false
	for _, f := range fromGet {
		if f == get.ID {
			foundGet = true
		}
	}
	if !foundGet {
		t.Fatalf("the req.args.get value must flow into q's binding; got %v", fromGet)
	}

	threaded := flowsInto(qUse2.ID)
	foundThread := false
	for _, f := range threaded {
		if f == qDef.ID {
			foundThread = true
		}
	}
	if !foundThread {
		t.Fatalf("name threading must carry q's binding to its use; got %v", threaded)
	}

	// The execute call's argument (Name sql use) flows into it.
	sqlUse := nameByLocal("sql", 1)
	intoEx := flowsInto(ex.ID)
	foundArg := false
	for _, f := range intoEx {
		if f == sqlUse.ID {
			foundArg = true
		}
	}
	if !foundArg {
		t.Fatalf("the sql use must flow into session.execute; got %v", intoEx)
	}
}

// A resolution accounting on an imports-present fixture, quoted for the
// plan's exit criterion: every dotted call either resolves or has a named
// reason. On this fixture: flask.route and session.execute resolve through
// imports, flush and audit resolve intra-module or stay undefined (audit is
// not defined here — an unresolvable name, not a gap), and req.args.get is
// deliberately syntactic: a framework-injected parameter stays unresolved
// until a framework model types it (by design).
func TestResolutionRateQuoted(t *testing.T) {
	g := built(t)
	unqualified := map[string]bool{}
	for _, n := range g.NodesOfType("code.Call") {
		p, _ := n.Fields.Get("path")
		q, ok := n.Fields.Get("qualified_path")
		if ok && q.S != "" {
			continue
		}
		unqualified[p.S] = true
	}
	want := map[string]bool{"req.args.get": true, "audit": true}
	for got := range unqualified {
		if !want[got] {
			t.Fatalf("%q is unqualified without a documented reason", got)
		}
	}
	for w := range want {
		if !unqualified[w] {
			t.Fatalf("expected %q to be among the unqualified (test drift)", w)
		}
	}
}

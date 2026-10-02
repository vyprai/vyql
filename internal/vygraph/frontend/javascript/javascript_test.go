package javascript

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

const fixture = `import { Router } from "express";
import db from "./db";

const router = Router();

router.get("/users", function listUsers(req, res) {
  const q = req.query.q;
  const sql = "SELECT * FROM users WHERE name = " + q;
  db.query(sql, (rows) => {
    if (rows.length > 0) {
      for (const r of rows) {
        console.log(r.name);
      }
    }
  });
  try {
    flush(rows);
  } catch (e) {
    console.error("failed", e);
  }
});
`

func extract(t *testing.T) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	fe := New(g)
	if err := fe.Extract("app.js", []byte(fixture)); err != nil {
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
	if err := fe.Extract("app.js", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	imp := fe.Imports["app.js"]
	if imp.Modules["Router"] != "express" || imp.Modules["db"] != "./db" {
		t.Fatalf("imports = %v", imp.Modules)
	}
}

func TestFunctionAndParams(t *testing.T) {
	g := extract(t)
	var named graph.Node
	for _, n := range g.NodesOfType("code.FuncDef") {
		if v, _ := n.Fields.Get("name"); v.S == "listUsers" {
			named = n
		}
	}
	if named.ID == "" {
		t.Fatal("named function expression listUsers must emit a FuncDef")
	}
	params := 0
	for _, e := range g.Out(named.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.ParamEntry" {
			if v, _ := n.Fields.Get("name"); v.S == "req" || v.S == "res" {
				params++
			}
		}
	}
	if params != 2 {
		t.Fatalf("params = %d, want req and res", params)
	}
}

func TestCallShapesAndFormat(t *testing.T) {
	g := extract(t)
	// The registration call carries the handler as an argument.
	reg := callByPath(t, g, "router.get")
	if v, _ := reg.Fields.Get("method"); v.S != "get" {
		t.Fatalf("method = %q", v.S)
	}
	args := 0
	for _, e := range g.Out(reg.ID, "child") {
		if _, ok := g.Node(e.To); ok {
			args++
		}
	}
	if args < 2 {
		t.Fatalf("registration args = %d, want path and handler", args)
	}

	// The concatenation lowers to a Format with const + tainted parts.
	var fmtNode graph.Node
	for _, n := range g.NodesOfType("code.Format") {
		txt, _ := n.Fields.Get("text")
		if strings.Contains(txt.S, "SELECT") {
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
}

func TestRegionsIncludeControlFlow(t *testing.T) {
	g := extract(t)
	log := callByPath(t, g, "console.log")
	reg, _ := log.Fields.Get("region")
	if !strings.Contains(reg.S, "/if#") || !strings.Contains(reg.S, "/then") ||
		!strings.Contains(reg.S, "/loop#") || !strings.Contains(reg.S, "/body") {
		t.Fatalf("console.log region = %q — the structured walk must encode the chain", reg.S)
	}
	errLog := callByPath(t, g, "console.error")
	reg, _ = errLog.Fields.Get("region")
	if !strings.Contains(reg.S, "/try#") || !strings.Contains(reg.S, "/except") {
		t.Fatalf("console.error region = %q", reg.S)
	}
}

func TestDeterministicExtraction(t *testing.T) {
	g1 := extract(t)
	s := graph.NewSchemas()
	nir.Register(s)
	g2 := graph.New(s)
	if err := New(g2).Extract("app.js", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	if g1.NodeCount() != g2.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", g1.NodeCount(), g2.NodeCount())
	}
}

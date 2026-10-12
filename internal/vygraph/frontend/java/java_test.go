package java

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

const fixture = `package app;

import java.sql.Connection;
import org.example.db;

public class UserController {
    @GetMapping("/users")
    public String listUsers(HttpServletRequest req) {
        String q = req.getParameter("q");
        String sql = "SELECT * FROM users WHERE name = " + q;
        ResultSet rows = db.query(sql);
        if (rows.next()) {
            for (int i = 0; i < 10; i++) {
                System.out.println(rows);
            }
        }
        try {
            flush(rows);
        } catch (Exception e) {
            System.err.println("failed");
        }
        return rows.toString();
    }
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
	if err := fe.Extract("UserController.java", []byte(fixture)); err != nil {
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
	if err := fe.Extract("UserController.java", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	imp := fe.Imports["UserController.java"]
	if imp.Modules["Connection"] != "java.sql.Connection" || imp.Modules["db"] != "org.example.db" {
		t.Fatalf("imports = %v", imp.Modules)
	}
}

func TestMethodAndParams(t *testing.T) {
	g := extract(t)
	var method graph.Node
	for _, n := range g.NodesOfType("code.FuncDef") {
		if v, _ := n.Fields.Get("name"); v.S == "listUsers" {
			method = n
		}
	}
	if method.ID == "" {
		t.Fatal("method listUsers must emit a FuncDef")
	}
	params := 0
	for _, e := range g.Out(method.ID, "child") {
		if n, ok := g.Node(e.To); ok && n.Type == "code.ParamEntry" {
			if v, _ := n.Fields.Get("name"); v.S == "req" {
				params++
			}
		}
	}
	if params != 1 {
		t.Fatalf("param req = %d", params)
	}
}

func TestCallShapesAndConcatenation(t *testing.T) {
	g := extract(t)
	get := callByPath(t, g, "req.getParameter")
	if v, _ := get.Fields.Get("method"); v.S != "getParameter" {
		t.Fatalf("method = %q", v.S)
	}
	q := callByPath(t, g, "db.query")

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
	_ = q
}

func TestRegionsIncludeControlFlow(t *testing.T) {
	g := extract(t)
	out := callByPath(t, g, "System.out.println")
	reg, _ := out.Fields.Get("region")
	if !strings.Contains(reg.S, "/if#") || !strings.Contains(reg.S, "/then") ||
		!strings.Contains(reg.S, "/loop#") || !strings.Contains(reg.S, "/body") {
		t.Fatalf("println region = %q", reg.S)
	}
	err := callByPath(t, g, "System.err.println")
	reg, _ = err.Fields.Get("region")
	if !strings.Contains(reg.S, "/try#") || !strings.Contains(reg.S, "/except") {
		t.Fatalf("err.println region = %q", reg.S)
	}
}

func TestDeterministicExtraction(t *testing.T) {
	g1 := extract(t)
	s := graph.NewSchemas()
	nir.Register(s)
	g2 := graph.New(s)
	if err := New(g2).Extract("UserController.java", []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	if g1.NodeCount() != g2.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", g1.NodeCount(), g2.NodeCount())
	}
}

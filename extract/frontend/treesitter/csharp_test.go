package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// The REAL tree-sitter C# frontend finds an ADO.NET SQLi (user input from
// Request.QueryString concatenated into a `new SqlCommand(...)`) and a
// Process.Start command injection.
func TestTreeSitterCSharp(t *testing.T) {
	src := `using System.Data.SqlClient;
class Handler {
  void Get(HttpRequest Request, SqlConnection conn) {
    string name = Request.QueryString["name"];
    var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
    cmd.ExecuteReader();
    System.Diagnostics.Process.Start("ping " + name);
  }
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "H.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := treesitter.ExtractCSharp([]string{filepath.Join(dir, "H.cs")}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.CSharpAdapters(), nil)

	onto := ontology.Seed()
	decls, _ := parser.Parse(twoSinkRules)
	compiled, _ := engine.CompileRules(decls, onto)
	eng := engine.New(onto, g)
	byRule := map[string]int{}
	for _, cr := range compiled {
		fs, _ := eng.Evaluate(cr)
		for _, f := range fs {
			byRule[f.RuleID]++
		}
	}
	if byRule["VYQL-INJ-001"] == 0 {
		t.Fatalf("expected ADO.NET SQLi (new SqlCommand), got %v", byRule)
	}
	if byRule["VYQL-INJ-002"] == 0 {
		t.Fatalf("expected Process.Start command injection, got %v", byRule)
	}
}

// ASP.NET Core MVC: a controller action's parameter is model-bound from the
// request, so it's user input even with no explicit Request.* call. The frontend
// seeds controller-action params as HttpInput sources.
func TestCSharpControllerParamSource(t *testing.T) {
	src := `using Microsoft.AspNetCore.Mvc;
[ApiController]
[Route("[controller]")]
public class Sqli : ControllerBase {
  [HttpGet("{id}")]
  public string DoSqli(string id) {
    using (SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE userId = '" + id + "'")) {
      return cmd.ExecuteReader().ToString();
    }
  }
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Sqli.cs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := treesitter.ExtractCSharp([]string{filepath.Join(dir, "Sqli.cs")}, dir)
	g, _ := lowering.Lower(prog, true)
	adapters.Apply(g, frontend.CSharpAdapters(), nil)
	onto := ontology.Seed()
	decls, _ := parser.Parse(twoSinkRules)
	compiled, _ := engine.CompileRules(decls, onto)
	var n int
	for _, cr := range compiled {
		fs, _ := engine.New(onto, g).Evaluate(cr)
		n += len(fs)
	}
	if n == 0 {
		t.Fatal("expected SQLi from a controller-action param (model-bound source), got 0")
	}
}

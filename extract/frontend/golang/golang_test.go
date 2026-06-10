package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

const sqliRule = `
package vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
`

const vulnerableGo = `package app

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`

const safeGo = `package app

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = $1", name)
}
`

// scan parses real Go source from a temp dir and runs the full pipeline:
// go/ast -> NIR -> lowering -> adapters -> SQLi rule.
func scan(t *testing.T, src string) []*findings.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := golang.ExtractDir(dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if _, _, err := adapters.Apply(g, frontend.GoAdapters(), nil); err != nil {
		t.Fatalf("adapters: %v", err)
	}
	onto := ontology.Seed()
	decls, err := parser.Parse(sqliRule)
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := engine.New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return fs
}

// The native Go frontend finds a real SQLi in real Go source — a string-built
// query reaching db.Query — and reports zero on the parameterized version with
// the SAME rule (parameterization handled by sink-argument precision).
func TestNativeGoSQLi(t *testing.T) {
	vuln := scan(t, vulnerableGo)
	if len(vuln) == 0 {
		t.Fatalf("expected the string-built query to be flagged, got 0 findings")
	}
	// sink should sit at the db.Query call in app.go
	sinkLocOK := false
	for _, f := range vuln {
		if strings.HasPrefix(f.Bindings[1].Loc, "app.go:") {
			sinkLocOK = true
		}
	}
	if !sinkLocOK {
		t.Fatalf("finding sink should be located in app.go, got %s", vuln[0].Bindings[1].Loc)
	}

	if safe := scan(t, safeGo); len(safe) != 0 {
		t.Fatalf("parameterized query ($1 placeholder) should be clean, got %d findings", len(safe))
	}
}

// AllNodes is reachable on the lowered store (sanity for the adapter scan path).
func TestExtractProducesNodes(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.go"), []byte(vulnerableGo), 0o644)
	prog, _ := golang.ExtractDir(dir)
	if len(prog.Modules) == 0 {
		t.Fatal("expected at least one module from the Go source")
	}
	g, _ := lowering.Lower(prog, true)
	nodes, _ := g.(interface {
		AllNodes() ([]usg.Node, error)
	}).AllNodes()
	if len(nodes) == 0 {
		t.Fatal("lowering produced no graph nodes")
	}
}

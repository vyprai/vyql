package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// Phase 1b — receiver-type resolution + type-constrained sinks. A `Query` on a
// real *sql.DB (constructed via sql.Open) is a SQL sink at high confidence; the
// SAME method on a graphql client (a known, conflicting type) is NOT a SQL sink.
func TestTypeConstrainedSinks(t *testing.T) {
	src := `package app

import (
	"database/sql"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db, _ := sql.Open("mysql", "dsn")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	gql := graphql.NewClient("http://x")
	gql.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, _ := golang.ExtractDir(dir)
	g, _ := lowering.LowerTyped(prog, true, frontend.CtorTypesFor("go"))
	adapters.Apply(g, frontend.GoAdapters(), nil)

	// Exactly one SQL sink is labeled — the *sql.DB Query. The graphql.Client
	// Query (a known, conflicting type) is NOT labeled (constraint suppressed it).
	sinks, _ := g.NodesWithConcept("code.SqlExecution")
	if len(sinks) != 1 {
		t.Fatalf("expected 1 SQL sink (sql.DB only; graphql.Client suppressed), got %d", len(sinks))
	}
	// and the type-verified sink is RESOLVED fidelity, not the syntactic medium of
	// an unverified bare-method match.
	labs, _ := g.Labels(sinks[0])
	var fid string
	for _, l := range labs {
		if l.Concept == "code.SqlExecution" {
			fid = l.Provenance.Fidelity
		}
	}
	if fid != "resolved" {
		t.Fatalf("type-verified sql.DB sink should be resolved fidelity, got %q", fid)
	}

	// end-to-end: exactly one finding (graphql suppressed)
	onto := ontology.Seed()
	decls, _ := parser.Parse(`
package vypr.injection;
rule Sql { meta { id: "VYQL-INJ-001", severity: high } taint code.HttpInput -> code.SqlExecution }
`)
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	if fs, _ := engine.New(onto, g).Evaluate(compiled[0]); len(fs) != 1 {
		t.Fatalf("expected 1 SQLi finding (graphql.Client suppressed), got %d", len(fs))
	}
}

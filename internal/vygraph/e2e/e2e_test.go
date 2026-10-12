// Package e2e holds the full-pipeline acceptance tests: real source through
// the frontend, the shared lowering, lifts and adapters, and rules evaluated
// by the real solvers — the Phase 2 gate.
package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/lower"
	"github.com/vyprai/vyql/internal/vygraph/nir"
	"github.com/vyprai/vyql/internal/vygraph/solvers/taint"
	"github.com/vyprai/vyql/internal/vygraph/vyql"
)

func domainSchemas(t *testing.T) *graph.Schemas {
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
			{Name: "handler", Kind: graph.KindString},
		}, Key: []string{"handler"}})
	must(&graph.TypeSchema{Type: "code.DataAccess", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "table", Kind: graph.KindString},
			{Name: "op", Kind: graph.KindEnum, Enum: []string{"read", "write"}},
			{Name: "filters", Kind: graph.KindList, Elem: graph.KindString},
		}, Key: []string{"table", "op"}})
	return s
}

func runFull(t *testing.T) *vyql.Output {
	t.Helper()
	s := domainSchemas(t)
	g := graph.New(s)

	src, err := os.ReadFile("testdata/full/app.py")
	if err != nil {
		t.Fatal(err)
	}
	fe := python.New(g)
	if err := fe.Extract("app.py", src); err != nil {
		t.Fatalf("frontend: %v", err)
	}
	if err := lower.Run(g, fe.ImportTable()); err != nil {
		t.Fatalf("lower: %v", err)
	}

	kb, err := vyql.LoadDir("testdata/full")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if err := vyql.ApplyLifts(kb, g); err != nil {
		t.Fatalf("ApplyLifts: %v", err)
	}
	if err := vyql.ApplyAdapters(kb, g); err != nil {
		t.Fatalf("ApplyAdapters: %v", err)
	}
	prog, err := vyql.Compile(kb)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, err := prog.Run(g, vyql.SolverRegistry{"taint": taint.New(kb.Onto)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out
}

func TestFullPipelineFindingAndSignal(t *testing.T) {
	out := runFull(t)

	if len(out.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (FULL-INJ-001):\n%s", len(out.Findings), out.Render())
	}
	f := out.Findings[0]
	if f.RuleID != "FULL-INJ-001" {
		t.Fatalf("finding rule = %s", f.RuleID)
	}
	if f.Proof == nil {
		t.Fatal("the finding must carry a proof tree")
	}
	rendered := f.Proof.Render()
	if !strings.Contains(rendered, "FLOWS") {
		t.Fatalf("witness must walk the value substrate:\n%s", rendered)
	}
	// The syntactic source binding caps at medium: the fixture's adapter is
	// syntactic fidelity, so the finding cannot mint high confidence.
	if f.Confidence > 0.75 {
		t.Fatalf("syntactic-only source caps the finding at medium, got %.2f", f.Confidence)
	}

	if len(out.Signals) != 1 || out.Signals[0].RuleID != "FULL-CRYPTO-001" {
		t.Fatalf("signals = %+v, want one FULL-CRYPTO-001", out.Signals)
	}
}

func TestFullPipelineDataAccessAndEntrypoint(t *testing.T) {
	s := domainSchemas(t)
	g := graph.New(s)
	src, err := os.ReadFile("testdata/full/app.py")
	if err != nil {
		t.Fatal(err)
	}
	fe := python.New(g)
	if err := fe.Extract("app.py", src); err != nil {
		t.Fatal(err)
	}
	if err := lower.Run(g, fe.ImportTable()); err != nil {
		t.Fatal(err)
	}
	kb, err := vyql.LoadDir("testdata/full")
	if err != nil {
		t.Fatal(err)
	}
	if err := vyql.ApplyLifts(kb, g); err != nil {
		t.Fatal(err)
	}
	// Entrypoint: the framework model interprets the flask.route decorator
	// registration, backing the lifted node to the handler FuncDef.
	eps := g.NodesOfType("code.Entrypoint")
	if len(eps) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(eps))
	}
	if v, _ := eps[0].Fields.Get("handler"); v.S != "list_users" {
		t.Fatalf("handler = %q", v.S)
	}
	if _, ok := g.Backing(eps[0].ID); !ok {
		t.Fatal("entrypoint must back the handler FuncDef")
	}
	// DataAccess: lifted with filters copied from the resolved FLOWS.
	das := g.NodesOfType("code.DataAccess")
	if len(das) != 1 {
		t.Fatalf("data accesses = %d, want 1", len(das))
	}
	da := das[0]
	if v, _ := da.Fields.Get("table"); v.S != "users" {
		t.Fatalf("table = %q", v.S)
	}
	fl, ok := da.Fields.Get("filters")
	if !ok || fl.Kind != graph.KindList || len(fl.L) == 0 {
		t.Fatalf("filters = %+v — the copy form must carry the flow provenance", fl)
	}
}

func TestFullPipelineByteIdentical(t *testing.T) {
	a := runFull(t).Render()
	b := runFull(t).Render()
	if a != b {
		t.Fatalf("two full-pipeline runs differ:\n%s\n---\n%s", a, b)
	}
}

// The sanitizing control on the flow suppresses: labelling the mid-flow with
// the parameterization control is a proof of safety.
func TestFullPipelineSanitizerSuppresses(t *testing.T) {
	s := domainSchemas(t)
	g := graph.New(s)
	src, _ := os.ReadFile("testdata/full/app.py")
	fe := python.New(g)
	if err := fe.Extract("app.py", src); err != nil {
		t.Fatal(err)
	}
	if err := lower.Run(g, fe.ImportTable()); err != nil {
		t.Fatal(err)
	}
	kb, err := vyql.LoadDir("testdata/full")
	if err != nil {
		t.Fatal(err)
	}
	// Find the format node (the flow's mid-step) and label it as the
	// parameterizing control.
	for _, n := range g.NodesOfType("code.Format") {
		if err := g.AddLabel(graph.Label{Target: n.ID, Concept: "code.SqlParameterization",
			Confidence: 1, Prov: graph.Provenance{Producer: "binding:full", Build: graph.BuildLabeled, Trust: graph.TrustReviewed}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := vyql.ApplyLifts(kb, g); err != nil {
		t.Fatal(err)
	}
	prog, err := vyql.Compile(kb)
	if err != nil {
		t.Fatal(err)
	}
	out, err := prog.Run(g, vyql.SolverRegistry{"taint": taint.New(kb.Onto)})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("a sanitized flow must not fire:\n%s", out.Render())
	}
}

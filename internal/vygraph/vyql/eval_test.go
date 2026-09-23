package vyql

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// stubTaint walks FLOWS edges from each source until it reaches a target —
// the same contract stub the Phase-1a toy used; the point is that the program
// treats the solver call as opaque.
type stubTaint struct{}

func (stubTaint) Name() string { return "taint" }

func (stubTaint) Solve(g *graph.Store, in solver.Input) ([]solver.Result, error) {
	want := map[string]bool{}
	for _, t := range in.Targets {
		want[t] = true
	}
	var out []solver.Result
	for _, src := range in.Sources {
		var path []solver.Step
		cur := src
		for {
			edges := g.Out(cur, "FLOWS")
			if len(edges) == 0 {
				break
			}
			e := edges[0]
			path = append(path, solver.Step{From: e.From, To: e.To, Via: "FLOWS"})
			cur = e.To
			if want[cur] {
				out = append(out, solver.Flow{Src: src, Dst: cur, Path: path})
				break
			}
		}
	}
	return out, nil
}

func pathSchemas(t *testing.T) *graph.Schemas {
	t.Helper()
	s := graph.NewSchemas()
	if err := s.Register(&graph.TypeSchema{Type: "code.Call", Layer: graph.LayerLow,
		Fields: []graph.FieldSpec{{Name: "path", Kind: graph.KindString}}, Key: []string{"path"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func toyGraph(t *testing.T) *graph.Store {
	t.Helper()
	g := pathStore(t)
	addCall(t, g, "n1", "request.args.get")
	addCall(t, g, "n2", "fmt.Sprintf")
	addCall(t, g, "n3", "db.session.execute")
	for _, e := range []graph.Edge{
		{ID: "e1", Type: "FLOWS", From: "n1", To: "n2"},
		{ID: "e2", Type: "FLOWS", From: "n2", To: "n3"},
	} {
		if err := g.AddEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func runToy(t *testing.T) *Output {
	t.Helper()
	kb, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	prog, err := Compile(kb)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	g := toyGraph(t)
	if err := ApplyAdapters(kb, g); err != nil {
		t.Fatalf("ApplyAdapters: %v", err)
	}
	out, err := prog.Run(g, SolverRegistry{"taint": stubTaint{}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out
}

func TestFixtureKBDrivesGraphEndToEnd(t *testing.T) {
	out := runToy(t)

	if len(out.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (TOY-001):\n%s", len(out.Findings), out.Render())
	}
	f := out.Findings[0]
	if f.RuleID != "TOY-001" || f.Source != "n1" || f.Target != "n3" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Proof == nil {
		t.Fatal("a finding must carry a rebuildable proof tree")
	}
	rendered := f.Proof.Render()
	for _, want := range []string{"n1", "n2", "n3", "FLOWS"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("proof %q missing %q", rendered, want)
		}
	}

	// The present-rule routes to signals, never findings.
	if len(out.Signals) != 1 || out.Signals[0].RuleID != "TOY-002" {
		t.Fatalf("signals = %+v, want one TOY-002", out.Signals)
	}
}

func TestSanitizingControlOnTheFlowSuppresses(t *testing.T) {
	kb, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := Compile(kb)
	if err != nil {
		t.Fatal(err)
	}
	g := toyGraph(t)
	// A neutralizing control on the witnessed flow (the mid node) is a proof of
	// safety: the discharge relation evaluates before the rule's stratum and
	// the finding is suppressed.
	if err := g.AddLabel(graph.Label{Target: "n2", Concept: "code.SqlParameterization",
		Confidence: 1, Prov: graph.Provenance{Producer: "binding:toy", Build: graph.BuildLabeled, Trust: graph.TrustReviewed}}); err != nil {
		t.Fatal(err)
	}
	out, err := prog.Run(g, SolverRegistry{"taint": stubTaint{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("sanitized flow must not fire:\n%s", out.Render())
	}
}

func TestRunIsByteIdenticalAcrossRuns(t *testing.T) {
	a := runToy(t).Render()
	b := runToy(t).Render()
	if a != b {
		t.Fatalf("two runs differ:\n%q\n%q", a, b)
	}
}

func TestQuerySetsFeedStratifiedRules(t *testing.T) {
	kb := kbOf(t, `module toy;
concept code.H : source { }
query q(x) { match (x: code.H) yield x }
rule InQuery { meta { id: "Q1" } match (x: code.H) where q(x) -> signal }
rule NotInQuery { meta { id: "Q2" } match (x: code.H) where not q(x) -> signal }
`)
	prog, err := Compile(kb)
	if err != nil {
		t.Fatal(err)
	}
	g := pathStore(t)
	addCall(t, g, "n1", "a.b")
	if err := g.AddLabel(graph.Label{Target: "n1", Concept: "code.H", Confidence: 1,
		Prov: graph.Provenance{Producer: "t", Build: graph.BuildLabeled, Trust: graph.TrustTrusted}}); err != nil {
		t.Fatal(err)
	}
	out, err := prog.Run(g, SolverRegistry{"taint": stubTaint{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Signals) != 1 || out.Signals[0].RuleID != "Q1" {
		t.Fatalf("signals = %+v, want exactly Q1 (positive membership)", out.Signals)
	}
}

// TestDryRunPort is the Phase-1b exit gate: a representative sample of real
// detection families, authored in v3 grammar, passes the full compiler —
// parse, validate, stratify — with zero errors and no engine involved. This is
// the grammar-fitness signal for the v3 language surface.
func TestDryRunPort(t *testing.T) {
	kb, err := LoadDir("testdata/dryrun")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	prog, err := Compile(kb)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := len(kb.Rules()); got != 8 {
		t.Fatalf("rules = %d, want 8", got)
	}
	if got := len(prog.Queries) / 2; got != 2 { // bare + module-qualified entries
		t.Fatalf("queries = %d, want 2", got)
	}
	// The dual-role concept survives the round trip into the ontology.
	c, ok := kb.Onto.Get("code.AuthzGate")
	if !ok || !c.HasKind("control") || !c.HasKind("guard") {
		t.Fatalf("dual-role concept lost its facets: %+v", c)
	}
	// Threat subsumption is declared and acyclic.
	if _, ok := kb.Threats["CommandInjection"]; !ok {
		t.Fatal("threat CommandInjection missing")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		mention string
	}{
		{"undefined concept",
			"module toy; rule R { taint A -> Missing -> finding }",
			"Missing"},
		{"unstratifiable negation",
			"module toy; concept A : source { }\nquery q1(x) { match (x: A) where not q2(x) yield x }\nquery q2(y) { match (y: A) where q1(y) yield y }",
			"unstratifiable"},
		{"typed-operand mismatch",
			"module toy; rule R { match (n: code.Call) where n.path == true -> finding }",
			"compares"},
		{"binding-kind mismatch",
			"module toy; concept code.H : source { }\nadapter t { sink code.path(\"x\") -> code.H }",
			"must target"},
	}
	for _, tc := range cases {
		f, err := Parse(tc.src)
		if err != nil {
			t.Errorf("%s: parse: %v", tc.name, err)
			continue
		}
		kb, berrs := KBFromFiles([]*File{f}, pathSchemas(t))
		joined := ""
		for _, e := range berrs {
			joined += e.Error() + "; "
		}
		if joined == "" && kb != nil {
			if _, cerr := Compile(kb); cerr != nil {
				joined = cerr.Error()
			}
		}
		if joined == "" {
			t.Errorf("%s: Compile accepted invalid input", tc.name)
			continue
		}
		if !strings.Contains(joined, tc.mention) {
			t.Errorf("%s: error %q does not mention %q", tc.name, joined, tc.mention)
		}
	}
}

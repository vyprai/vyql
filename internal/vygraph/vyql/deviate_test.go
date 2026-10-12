package vyql

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/deviate"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
	"github.com/vyprai/vyql/internal/vygraph/solver"
)

// The deviation clause: peers by the frozen selector keys, outliers as
// signal-only results with the degenerate witness (empty Source, the outlier
// as Target, the group + missing feature + exemplars as evidence).
func deviateSchemas(t *testing.T) *graph.Schemas {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(&graph.TypeSchema{Type: "code.Entrypoint", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "httpMethod", Kind: graph.KindString},
			{Name: "handler", Kind: graph.KindString},
		}, Key: []string{"handler"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(&graph.TypeSchema{Type: "code.Handler", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{{Name: "handler", Kind: graph.KindString}}, Key: []string{"handler"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

const deviateKB = `module toy;
concept code.AuthenticationCheck : guard { defends: [Idor] }
concept code.Handler : principal { }
guard_hint identifier matches "*auth*" -> code.AuthenticationCheck
rule MissingAuth {
  meta { id: "DEV-001" severity: high }
  match (h: code.Handler)
  deviates from peers by same_annotation_class missing guard code.AuthenticationCheck
    min_group 3 threshold 0.75
  -> signal
}
`

func buildDeviateGraph(t *testing.T) *graph.Store {
	t.Helper()
	g := graph.New(deviateSchemas(t))
	// Nine functions: six carry an @route decorator and call auth (conforming),
	// three carry @route without auth (outliers).
	mk := func(name, decorator string, withAuth bool) {
		var ff graph.Fields
		nir.Stamp(&ff, "app.py", 1, 1, "fn:"+name, 0, false)
		ff.Set("name", graph.Str(name))
		if err := g.AddNode(graph.Node{ID: "f:" + name, Type: "code.FuncDef", Layer: graph.LayerLow, Fields: ff,
			Prov: graph.Provenance{Producer: "t", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}); err != nil {
			t.Fatal(err)
		}
		var pf graph.Fields
		nir.Stamp(&pf, "app.py", 1, 10, "fn:"+name, 1, false)
		pf.Set("name", graph.Str("req"))
		pf.Set("scope", graph.Str(name))
		lst := graph.Value{Kind: graph.KindList, Elem: graph.KindString}
		lst.L = append(lst.L, graph.Str(decorator))
		pf.Set("decorators", lst)
		if err := g.AddNode(graph.Node{ID: "p:" + name, Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pf,
			Prov: graph.Provenance{Producer: "t", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}); err != nil {
			t.Fatal(err)
		}
		if err := g.AddEdge(graph.Edge{ID: "c:" + name, Type: "child", From: "f:" + name, To: "p:" + name}); err != nil {
			t.Fatal(err)
		}
		if withAuth {
			if err := g.AddLabel(graph.Label{Target: "f:" + name, Concept: "code.AuthenticationCheck",
				Confidence: 1, Prov: graph.Provenance{Producer: "hint", Build: graph.BuildLabeled, Trust: graph.TrustTrusted}}); err != nil {
				t.Fatal(err)
			}
		}
		// The high-level member the rule matches on, backing the function.
		var hf graph.Fields
		hf.Set("handler", graph.Str(name))
		if err := g.Upsert(graph.Node{ID: "h:" + name, Type: "code.Handler", Layer: graph.LayerHigh, Fields: hf,
			Prov: graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: graph.TrustTrusted}}); err != nil {
			t.Fatal(err)
		}
		_ = g.AddEdge(graph.Edge{ID: "b:" + name, Type: graph.EdgeBacks, From: "h:" + name, To: "f:" + name,
			Prov: graph.Provenance{Producer: "lift", Build: graph.BuildLifted, Trust: graph.TrustTrusted}})
	}
	mk("list", "app.route", true)
	mk("get", "app.route", true)
	mk("put", "app.route", true)
	mk("del", "app.route", true)
	mk("post", "app.route", true)
	mk("patch", "app.route", true)
	mk("unauth1", "app.route", false)
	mk("unauth2", "app.route", false)
	mk("mostly", "app.route", true) // 7 of 9 carry — above the 0.75 threshold
	return g
}

func TestDeviateEmitsSignalsWithDegenerateWitness(t *testing.T) {
	f, err := Parse(deviateKB)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kb, berrs := KBFromFiles([]*File{f}, deviateSchemas(t))
	if len(berrs) > 0 {
		t.Fatalf("KBFromFiles: %v", berrs)
	}
	prog, err := Compile(kb)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	g := buildDeviateGraph(t)
	out, err := prog.Run(g, SolverRegistry{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The two unauthenticated handlers are signals; nothing is a finding.
	if len(out.Signals) != 2 {
		t.Fatalf("signals = %d, want 2:\n%s", len(out.Signals), out.Render())
	}
	if len(out.Findings) != 0 {
		t.Fatalf("deviation output must never reach findings:\n%s", out.Render())
	}
	s := out.Signals[0]
	if s.RuleID != "DEV-001" {
		t.Fatalf("signal rule = %s", s.RuleID)
	}
	if s.Proof == nil {
		t.Fatal("a signal must carry the degenerate witness")
	}
	rendered := s.Proof.Render()
	if !strings.Contains(rendered, "deviates") {
		t.Fatalf("witness must record the deviation: %q", rendered)
	}
	if !strings.Contains(rendered, "exemplar") {
		t.Fatalf("witness must carry conforming exemplars: %q", rendered)
	}
	if s.Confidence != 0 {
		t.Fatalf("deviation output is signal-clamped by construction, got %.2f", s.Confidence)
	}
}

func TestDeviateFindingEmitIsACompileError(t *testing.T) {
	src := strings.Replace(deviateKB, "-> signal", "-> finding", 1)
	f, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := KBFromFiles([]*File{f}, deviateSchemas(t))
	if _, err := Compile(kb); err == nil {
		t.Fatal("a deviates body with -> finding must be rejected at compile")
	} else if !strings.Contains(err.Error(), "signal") {
		t.Fatalf("error must name the signal-only clamp: %v", err)
	}
}

func TestDeviateValidatesFeatureKindAndSelector(t *testing.T) {
	cases := []struct {
		name, src, mention string
	}{
		{"feature not a guard",
			"module toy; concept code.H : principal { }\nrule R { meta { id: \"X\" } match (h: code.H) deviates from peers by same_annotation_class missing guard code.H -> signal }",
			"guard or control"},
		{"unknown selector",
			"module toy; concept code.G : guard { }\nrule R { meta { id: \"X\" } match (h: code.G) deviates from peers by same_file missing guard code.G -> signal }",
			"same_router"},
	}
	for _, tc := range cases {
		f, err := Parse(tc.src)
		if err != nil {
			t.Errorf("%s: parse: %v", tc.name, err)
			continue
		}
		kb, _ := KBFromFiles([]*File{f}, graph.NewSchemas())
		_, cerr := Compile(kb)
		if cerr == nil || !strings.Contains(cerr.Error(), tc.mention) {
			t.Errorf("%s: err = %v, want mention %q", tc.name, cerr, tc.mention)
		}
	}
}

func TestGuardHintParsesAndValidates(t *testing.T) {
	f, err := Parse(`module toy;
concept code.AuthenticationCheck : guard { defends: [Idor] }
guard_hint identifier matches "*auth*" -> code.AuthenticationCheck
guard_hint identifier matches "*perm*" -> code.Nope
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.GuardHints) != 2 {
		t.Fatalf("guard hints = %d", len(f.GuardHints))
	}
	if f.GuardHints[0].Glob != "*auth*" || f.GuardHints[0].Concept != "code.AuthenticationCheck" {
		t.Fatalf("hint 0 = %+v", f.GuardHints[0])
	}
	kb, _ := KBFromFiles([]*File{f}, graph.NewSchemas())
	_, cerr := Compile(kb)
	if cerr == nil || !strings.Contains(cerr.Error(), "Nope") {
		t.Fatalf("undefined hint concept must fail compile: %v", cerr)
	}
}

// The solver-level degenerate contract, independent of the language layer.
func TestDeviateSolverContractShape(t *testing.T) {
	res := solver.Result(deviate.Absence{Outlier: "h7", Missing: "Auth", Group: "app.route", Peers: []string{"h1", "h2", "h3"}, Exemplar: "h1"})
	if res.Source() != "" || res.Target() != "h7" {
		t.Fatalf("contract: Source=%q Target=%q", res.Source(), res.Target())
	}
	if len(res.Witness()) == 0 {
		t.Fatal("absence results carry witnesses")
	}
}

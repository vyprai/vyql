package parser

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Mirrors the Python parser smoke test: every docs/05 rule form parses.
// VyQL conventions: `module <ns>;` declares the namespace, rule
// names are short PascalCase, concepts are qualified cross-module refs,
// refs are uppercase words, states are PascalCase.
const program = `
module vypr.flow;

rule Flow {
  meta { id: "VYQL-TST-001", severity: high, refs: [REF_001], tags: ["core"] }
  taint custom.Source -> custom.Target
  unless sanitized_by custom.Transform
}

module vypr.graph;

rule PublicNode {
  meta { id: "VYQL-TST-002", severity: critical }
  reach graph.External -> graph.Store
  where graph.Store holds_asset_kind [data.Record, data.Profile]
}
rule MissingMarker {
  match graph.Container as s
  where not s has core.Marker
  unless guarded_by core.CompensatingMarker
}

module vypr.actor;

rule ExternalToCapability { assume actor.External -> actor.Capability }
rule CombinedCondition {
  match actor.Workload as w
  where reach(graph.External, w.item) and assume(w, actor.Capability)
}

module vypr.workflow;

rule ActionNeedsRelation {
  match workflow.Action as a
  where a.actor is actor.User and a.resource is workflow.Item
  unless guarded_by core.RelationshipCheck
}
state_machine Ticket {
  states [Created, Opened, Closed, Reopened]
  initial Created
  transition Created -> Opened
  transition Opened -> Closed
  transition Opened -> Reopened
}
rule InvalidReopenTransition {
  match transition * -> Reopened on Ticket as t
  unless t.from == Opened
}
`

func TestParserDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	concepts := parserOntologyConceptNeedles(t)
	var hits []string
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, needle := range concepts {
			if strings.Contains(text, needle) {
				hits = append(hits, filepath.Base(path)+": "+needle)
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("parser must not hardcode ontology concepts; keep concept selection in VyQL data: %s", strings.Join(hits, ", "))
	}
}

func parserOntologyConceptNeedles(t *testing.T) []string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	files, err := filepath.Glob(filepath.Join(root, "vyql", "ontology", "*.vyql"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		decls, err := Parse(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range decls {
			cd, ok := decl.(*ConceptDecl)
			if !ok {
				continue
			}
			if role, _ := cd.Fields["analysis_role"].(string); role != "" {
				continue
			}
			seen["\""+cd.Name+"\""] = true
			seen["\""+cd.QualifiedName()+"\""] = true
		}
	}
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

func TestParseAllForms(t *testing.T) {
	decls, err := Parse(program)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(decls) != 8 {
		t.Fatalf("expected 8 declarations, got %d", len(decls))
	}

	// rule 1: taint flow + sanitized_by
	r0 := decls[0].(*Rule)
	if r0.Name != "Flow" || r0.Package != "vypr.flow" || r0.QualifiedName() != "vypr.flow.Flow" {
		t.Fatalf("rule 0 naming wrong: name=%q pkg=%q qn=%q", r0.Name, r0.Package, r0.QualifiedName())
	}
	if r0.Meta["id"] != "VYQL-TST-001" {
		t.Fatalf("rule 0 meta wrong: %+v", r0.Meta)
	}
	if refs, ok := r0.Meta["refs"].([]string); !ok || refs[0] != "REF_001" {
		t.Fatalf("rule 0 refs wrong: %v", r0.Meta["refs"])
	}
	fs := r0.Body.(*FlowStmt)
	if fs.Verb != "taint" || fs.Src.Concept != "custom.Source" || fs.Dst.Concept != "custom.Target" {
		t.Fatalf("rule 0 flow wrong: %+v", fs)
	}
	if sb, ok := r0.Clauses[0].Unless.(SanitizedBy); !ok || sb.Concept != "custom.Transform" {
		t.Fatalf("rule 0 unless wrong: %+v", r0.Clauses[0].Unless)
	}

	// rule 2: reach + holds_asset_kind where
	r1 := decls[1].(*Rule)
	wexpr := r1.Clauses[0].Where.(HoldsAssetKind)
	if len(wexpr.Kinds) != 2 || wexpr.Kinds[1] != "data.Profile" {
		t.Fatalf("rule 1 holds_asset_kind wrong: %+v", wexpr)
	}

	// toxic combination: where with two solver calls joined by `and` (decls[4])
	rtox := decls[4].(*Rule)
	if rtox.QualifiedName() != "vypr.actor.CombinedCondition" {
		t.Fatalf("combined rule qualified name wrong: %q", rtox.QualifiedName())
	}
	andExpr, ok := rtox.Clauses[0].Where.(And)
	if !ok || len(andExpr.Parts) != 2 {
		t.Fatalf("combined where should be And of 2, got %+v", rtox.Clauses[0].Where)
	}
	sc := andExpr.Parts[0].(SolverCall)
	if sc.Verb != "reach" || sc.Args[1].Ref.String() != "w.item" {
		t.Fatalf("combined solver call wrong: %+v", sc)
	}

	// state machine
	sm := decls[6].(*StateMachine)
	if sm.Name != "Ticket" || len(sm.States) != 4 || len(sm.Transitions) != 3 {
		t.Fatalf("state machine wrong: %+v", sm)
	}
	if sm.Transitions[2] != [2]string{"Opened", "Reopened"} {
		t.Fatalf("transition wrong: %+v", sm.Transitions)
	}

	// transition match rule with `unless expr` (t.from == Opened)
	r7 := decls[7].(*Rule)
	m := r7.Body.(*MatchStmt)
	if m.TargetKind != "transition" || m.FromState != "*" || m.ToState != "Reopened" || m.Machine != "Ticket" {
		t.Fatalf("transition match wrong: %+v", m)
	}
	ee := r7.Clauses[0].Unless.(ExprException)
	cmp := ee.Expr.(Cmp)
	if cmp.Ref.String() != "t.from" || cmp.Op != "==" || cmp.Value != "Opened" {
		t.Fatalf("transition unless cmp wrong: %+v", cmp)
	}
}

// Namespacing via a `module` declaration: short rule names within the module;
// cross-module concept refs stay qualified.
func TestModuleDecl(t *testing.T) {
	src := `
module vypr.flow;

rule Flow {
  meta { id: "VYQL-TST-001" }
  taint custom.Source -> custom.Target
  unless sanitized_by custom.Transform
}
rule AlternateFlow {
  taint custom.Source -> custom.AlternateTarget
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(decls) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(decls))
	}
	r := decls[0].(*Rule)
	if r.Name != "Flow" || r.Package != "vypr.flow" {
		t.Fatalf("package context wrong: name=%q pkg=%q", r.Name, r.Package)
	}
	if r.QualifiedName() != "vypr.flow.Flow" {
		t.Fatalf("qualified name wrong: %q", r.QualifiedName())
	}
	if decls[1].(*Rule).QualifiedName() != "vypr.flow.AlternateFlow" {
		t.Fatalf("second rule qualified name wrong: %q", decls[1].(*Rule).QualifiedName())
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`rule x { taint A -> }`,             // missing endpoint
		`rule x { meta { id "no-colon" } }`, // missing colon
		`rule`,                              // truncated
		`gibberish foo`,                     // bad top-level
	}
	for _, src := range bad {
		if _, err := Parse(src); err == nil {
			t.Fatalf("expected parse error for %q", src)
		}
	}
}

// The adapter + threat declarations (docs/05/07) parse into the right AST.
func TestParseAdapterAndThreatDecls(t *testing.T) {
	src := `
module sample;
threat Condition { refs: [REF_001], desc: "Generic condition" }

adapter neutral {
  meta { fidelity: resolved }
  source "entry.value" -> custom.Source
  source path "entry.meta" -> custom.Context
  source receiver "value" on "sample.Request" -> custom.Source
  sink method "emit" -> custom.Target
  sink path "runtime.run" -> custom.Action
  sink path "runtime.execv" collection first -> custom.Action
  sink receiver "open" -> custom.Target
  flow path "copy_into" arg 0 from args 1
  flow path "read_into" arg 0 from result
  flow prefix "parse" arg 1 from args 0
  control receiver method "checked" -> custom.Transform
  mark method "setMode" val "true" -> custom.Marker
  mark exact "Widget" -> custom.Marker
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var ad *AdapterDecl
	var th *ThreatDecl
	for _, d := range decls {
		switch x := d.(type) {
		case *AdapterDecl:
			ad = x
		case *ThreatDecl:
			th = x
		}
	}
	if th == nil || th.QualifiedName() != "sample.Condition" {
		t.Fatalf("threat decl not parsed: %+v", th)
	}
	if ad == nil || ad.Name != "neutral" || len(ad.Mappings) != 13 {
		t.Fatalf("adapter decl not parsed: %+v", ad)
	}
	if ad.Mappings[0].Kind != "source" || ad.Mappings[0].Concept != "custom.Source" {
		t.Fatalf("source mapping wrong: %+v", ad.Mappings[0])
	}
	if ad.Mappings[1].Kind != "source" || ad.Mappings[1].Pattern != "entry.meta" || ad.Mappings[1].Concept != "custom.Context" {
		t.Fatalf("source path mapping wrong: %+v", ad.Mappings[1])
	}
	if ad.Mappings[2].Kind != "source_receiver" || ad.Mappings[2].Constraint != "sample.Request" {
		t.Fatalf("source_receiver mapping wrong: %+v", ad.Mappings[2])
	}
	if ad.Mappings[3].Kind != "sink_method" || ad.Mappings[4].Kind != "sink_path" {
		t.Fatalf("sink mapping kinds wrong: %+v", ad.Mappings[3:])
	}
	if ad.Mappings[5].Kind != "sink_path" || !ad.Mappings[5].Collection || !ad.Mappings[5].CollectionFirst {
		t.Fatalf("collection first sink mapping wrong: %+v", ad.Mappings[5])
	}
	if ad.Mappings[6].Kind != "sink_receiver" || ad.Mappings[6].Concept != "custom.Target" {
		t.Fatalf("sink_receiver mapping wrong: %+v", ad.Mappings[6])
	}
	if ad.Mappings[7].Kind != "flow_path" || ad.Mappings[7].FlowDestArg != 0 || ad.Mappings[7].FlowSourceArg != 1 {
		t.Fatalf("flow args mapping wrong: %+v", ad.Mappings[7])
	}
	if ad.Mappings[8].Kind != "flow_path" || ad.Mappings[8].FlowDestArg != 0 || !ad.Mappings[8].FlowSourceResult {
		t.Fatalf("flow result mapping wrong: %+v", ad.Mappings[8])
	}
	if ad.Mappings[9].Kind != "flow_prefix" || ad.Mappings[9].Pattern != "parse" || ad.Mappings[9].FlowDestArg != 1 || ad.Mappings[9].FlowSourceArg != 0 {
		t.Fatalf("flow prefix mapping wrong: %+v", ad.Mappings[9])
	}
	if ad.Mappings[10].Kind != "control_receiver_method" || ad.Mappings[10].Concept != "custom.Transform" {
		t.Fatalf("control_receiver_method mapping wrong: %+v", ad.Mappings[10])
	}
	if ad.Mappings[11].Kind != "mark_method" || ad.Mappings[11].Pattern != "setMode" ||
		len(ad.Mappings[11].ValMatches) != 1 || ad.Mappings[11].ValMatches[0] != "true" {
		t.Fatalf("value-matched mark wrong: %+v", ad.Mappings[11])
	}
	if ad.Mappings[12].Kind != "mark" || !ad.Mappings[12].Exact {
		t.Fatalf("exact mark wrong: %+v", ad.Mappings[12])
	}
}

func TestConceptImportsResolveInRulesAndAdapters(t *testing.T) {
	src := `
import custom.{Source, Target, Context};
import core.Transform as Tx;
import core.*;

adapter neutral {
  source "entry.value" -> Source
  sink method "emit" -> Target
  package "pkg" {
    sink method "raw" -> Target
  }
  control "bind" -> Tx
  assume guard method "startsWith" -> Context
}

rule Flow {
  taint Source -> Target
  unless sanitized_by Tx
}

rule ContainerRule {
  match Storage as s
  unless guarded_by Marker
}
`
	decls, err := Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad := decls[0].(*AdapterDecl)
	if got := ad.Mappings[0].Concept; got != "custom.Source" {
		t.Fatalf("source import = %q", got)
	}
	if got := ad.Mappings[1].Concept; got != "custom.Target" {
		t.Fatalf("sink import = %q", got)
	}
	if got := ad.Mappings[2].Packages; len(got) != 1 || got[0] != "pkg" {
		t.Fatalf("package gate = %#v", got)
	}
	if got := ad.Mappings[3].Concept; got != "core.Transform" {
		t.Fatalf("alias import = %q", got)
	}
	if got := ad.Mappings[4].About; got != "custom.Context" {
		t.Fatalf("assume target import = %q", got)
	}
	sql := decls[1].(*Rule)
	fs := sql.Body.(*FlowStmt)
	if fs.Src.Concept != "custom.Source" || fs.Dst.Concept != "custom.Target" {
		t.Fatalf("rule endpoint imports wrong: %+v", fs)
	}
	if sb := sql.Clauses[0].Unless.(SanitizedBy); sb.Concept != "core.Transform" {
		t.Fatalf("rule alias import wrong: %+v", sb)
	}
	storage := decls[2].(*Rule)
	if m := storage.Body.(*MatchStmt); m.Concept != "core.Storage" {
		t.Fatalf("wildcard match import wrong: %+v", m)
	}
	if gb := storage.Clauses[0].Unless.(GuardedBy); gb.Concept != "core.Marker" {
		t.Fatalf("wildcard guard import wrong: %+v", gb)
	}
}

// String literals support backslash escapes: \" keeps a quote inside the string
// (without ending it), \\ a literal backslash, and \n/\t/\r the usual whitespace.
// The escape-free fast path must return the raw text unchanged.
func TestLexStringEscapes(t *testing.T) {
	cases := []struct{ src, want string }{
		{`"plain"`, "plain"},             // fast path, no escapes
		{`"a=\"b\""`, `a="b"`},           // escaped quotes don't terminate
		{`"back\\slash"`, `back\slash`},  // literal backslash
		{`"tab\tend"`, "tab\tend"},       // \t
		{`"line\nbreak"`, "line\nbreak"}, // \n
		{`"x\qy"`, "xqy"},                // unknown escape → literal char
	}
	for _, c := range cases {
		toks, err := lex(c.src)
		if err != nil {
			t.Fatalf("lex(%q) error: %v", c.src, err)
		}
		if toks[0].kind != tString || toks[0].val != c.want {
			t.Errorf("lex(%q) = %q, want %q", c.src, toks[0].val, c.want)
		}
	}
	// an unterminated string (trailing escape eats the closing quote) still errors.
	if _, err := lex(`"oops\"`); err == nil {
		t.Errorf("expected unterminated-string error")
	}
}

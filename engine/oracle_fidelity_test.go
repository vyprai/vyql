package engine

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// Mirrors poc/cases/case_03 (guard half): a well-typed `unless guarded_by`
// endpoint guard suppresses through the engine. CSRF_PROTECTION neutralizes the
// CSRF threat that StateChangingOp carries, so a PROTECTS edge on the sink
// suppresses; removing it brings the finding back.
func TestGuardedByCsrfEndpoint(t *testing.T) {
	rule := `
package vypr.web;
rule Csrf {
  meta { id: "VYQL-WEB-001", severity: high }
  taint code.HttpInput -> code.StateChangingOp
  unless guarded_by core.CsrfProtection
}
`
	// guarded: csrf PROTECTS the op endpoint -> no finding
	guarded := func(s usg.Store) {
		for _, id := range []string{"in", "op", "csrf"} {
			s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
		}
		s.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
		s.AddLabel("op", usg.Label{Concept: "code.StateChangingOp"})
		s.AddLabel("csrf", usg.Label{Concept: "core.CsrfProtection"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "op"})
		s.AddEdge(usg.Edge{Type: "PROTECTS", Src: "csrf", Dst: "op"})
	}
	counts, errs := runRule(t, rule, guarded)
	if len(errs) != 0 {
		t.Fatalf("well-typed CSRF guard should compile, got %v", errs)
	}
	if counts[0] != 0 {
		t.Fatalf("CSRF guard on the endpoint should suppress, got %d", counts[0])
	}

	// unguarded: drop the PROTECTS edge -> finding returns
	unguarded := func(s usg.Store) {
		for _, id := range []string{"in", "op"} {
			s.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
		}
		s.AddLabel("in", usg.Label{Concept: "code.HttpInput"})
		s.AddLabel("op", usg.Label{Concept: "code.StateChangingOp"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "op"})
	}
	counts, _ = runRule(t, rule, unguarded)
	if counts[0] != 1 {
		t.Fatalf("removing the guard should restore the finding, got %d", counts[0])
	}
}

// Mirrors poc/cases/case_11: (a) a rule over a PARENT source concept
// (core.UserControlledData) matches a node labeled with a CHILD concept
// (code.HttpInput) — refinement matching through the engine; (b) multiple
// `unless sanitized_by` clauses are DISJUNCTIVE — any listed control on the path
// suppresses (command injection: shell-escape OR allowlist).
func TestRefinementAndDisjunctiveSanitizers(t *testing.T) {
	rule := `
package vypr.injection;
rule Command {
  meta { id: "VYQL-INJ-002", severity: critical }
  taint core.UserControlledData -> code.CommandExecution
  unless sanitized_by core.ShellEscape
  unless sanitized_by core.AllowlistValidation
}
`
	// (a) child-labeled source caught by the parent-concept rule
	counts, errs := runRule(t, rule, func(s usg.Store) {
		label(s, "in", "code.HttpInput") // child of core.UserControlledData
		label(s, "exec", "code.CommandExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "exec"})
	})
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	if counts[0] != 1 {
		t.Fatalf("parent-concept rule should match child-labeled source, got %d", counts[0])
	}

	// (b1) suppressed by the FIRST sanitizer on the path
	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "esc", "core.ShellEscape")
		label(s, "exec", "code.CommandExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "esc"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "esc", Dst: "exec"})
	})
	if counts[0] != 0 {
		t.Fatalf("shell-escape on the path should suppress, got %d", counts[0])
	}

	// (b2) suppressed by the SECOND sanitizer (disjunction)
	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "allow", "core.AllowlistValidation")
		label(s, "exec", "code.CommandExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "allow"})
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "allow", Dst: "exec"})
	})
	if counts[0] != 0 {
		t.Fatalf("allowlist-validation on the path should also suppress (disjunction), got %d", counts[0])
	}

	// (c) no relevant control on the path -> finding
	counts, _ = runRule(t, rule, func(s usg.Store) {
		label(s, "in", "code.HttpInput")
		label(s, "exec", "code.CommandExecution")
		s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "exec"})
	})
	if counts[0] != 1 {
		t.Fatalf("no relevant control -> finding, got %d", counts[0])
	}
}

// Mirrors poc/cases/case_23 (the end-to-end half): a rule written against an
// ALIAS of a concept compiles and matches CANONICAL-labeled nodes through the
// engine — concept renames must not break rules (docs/06, /15).
func TestAliasResolutionThroughEngine(t *testing.T) {
	o := ontology.Seed()
	o.Alias("code.HttpInput", "core.UserInput") // core.UserInput -> code.HttpInput
	o.Deprecate("code.HttpHeader", "merged into code.HttpInput")

	if !o.Exists("core.UserInput") {
		t.Fatal("alias should resolve to an existing concept")
	}
	if w := o.DeprecationWarning("core.UserInput"); !strings.Contains(w, "alias of 'code.HttpInput'") {
		t.Fatalf("alias use should warn, got %q", w)
	}
	if w := o.DeprecationWarning("code.HttpInput"); w != "" {
		t.Fatalf("canonical, non-deprecated concept should not warn, got %q", w)
	}

	rule := `
package vypr.injection;
rule SqlAlias {
  meta { id: "ALIAS-1", severity: high }
  taint core.UserInput -> code.SqlExecution
  unless sanitized_by core.SqlParameterization
}
`
	decls, err := parser.Parse(rule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, o)
	if len(errs) != 0 {
		t.Fatalf("alias rule should compile, got %v", errs)
	}
	s := usg.NewInMemStore()
	label(s, "in", "code.HttpInput") // canonical label, not the alias
	label(s, "q", "code.SqlExecution")
	s.AddEdge(usg.Edge{Type: "FLOWS", Src: "in", Dst: "q"})
	fs, err := New(o, s).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("alias rule should match the canonical-labeled node (1 finding), got %d", len(fs))
	}
}

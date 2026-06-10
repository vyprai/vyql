package engine

import (
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// nSql builds a graph from a label map and an edge list, runs the SQLI rule, and
// returns the finding count. Nodes referenced only by edges (no concept) are
// created bare. Mirrors case_20's _g/_n helpers.
func nSql(t *testing.T, labels map[string]string, edges [][2]string) int {
	t.Helper()
	onto := ontology.Seed()
	decls, err := parser.Parse(sqliRule)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	store := usg.NewInMemStore()
	ids := map[string]bool{}
	for _, e := range edges {
		ids[e[0]] = true
		ids[e[1]] = true
	}
	for id := range labels {
		ids[id] = true
	}
	for id := range ids {
		store.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}})
	}
	for id, concept := range labels {
		store.AddLabel(id, usg.Label{Concept: concept})
	}
	for _, e := range edges {
		store.AddEdge(usg.Edge{Type: "FLOWS", Src: e[0], Dst: e[1]})
	}
	fs, err := New(onto, store).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return len(fs)
}

// Mirrors poc/cases/case_20_sanitizer_conformance.py — the normative docs/08
// sanitizer table, each row a discrete check through the full compile+evaluate
// path. Rows the solver implements must match ideal semantics; the field-
// sensitivity row is recorded as a documented known limitation, not a silent pass.
func TestSanitizerConformanceTable(t *testing.T) {
	in, q, san, sqlParam := "code.HttpInput", "code.SqlExecution", "core.SqlParameterization", "core.SqlParameterization"

	// Row 1: sanitizer exists elsewhere, not on the path -> FINDING
	if n := nSql(t, map[string]string{"in": in, "q": q, "san": sqlParam}, [][2]string{{"in", "q"}}); n != 1 {
		t.Fatalf("row1 sanitizer-exists-elsewhere -> finding, got %d", n)
	}
	// Row 2: sanitizer on one branch, tainted value flows around -> FINDING
	if n := nSql(t, map[string]string{"in": in, "san": san, "q": q},
		[][2]string{{"in", "san"}, {"san", "q"}, {"in", "q"}}); n != 1 {
		t.Fatalf("row2 branch-around -> finding, got %d", n)
	}
	// Row 3: only path passes through the sanitizer -> NO FINDING
	if n := nSql(t, map[string]string{"in": in, "san": san, "q": q},
		[][2]string{{"in", "san"}, {"san", "q"}}); n != 0 {
		t.Fatalf("row3 fully-sanitized -> no finding, got %d", n)
	}
	// Row 4: sanitize, then re-taint with a distinct source -> FINDING
	if n := nSql(t, map[string]string{"in": in, "san": san, "in2": in, "q": q},
		[][2]string{{"in", "san"}, {"san", "cat"}, {"in2", "cat"}, {"cat", "q"}}); n != 1 {
		t.Fatalf("row4 re-taint (distinct source) -> finding, got %d", n)
	}
	// Row 5: sanitizer wraps the sink boundary (parameterized) -> NO FINDING
	if n := nSql(t, map[string]string{"in": in, "bind": sqlParam, "q": q},
		[][2]string{{"in", "bind"}, {"bind", "q"}}); n != 0 {
		t.Fatalf("row5 parameterized-wrap -> no finding, got %d", n)
	}
	// Row 6: wrong-type sanitizer (HtmlEscape on SQLi) -> COMPILE ERROR
	wrong := `
package bad;
rule WrongSanitizer {
  taint code.HttpInput -> code.SqlExecution
  unless sanitized_by core.HtmlEscape
}
`
	decls, _ := parser.Parse(wrong)
	_, errs := CompileRules(decls, ontology.Seed())
	if len(errs) != 1 || !contains(errs[0].Msg, "does not defend") {
		t.Fatalf("row6 wrong-type sanitizer -> compile error, got %v", errs)
	}
	// Row 7: sanitizer on a DIFFERENT FIELD of the same object -> ideal=finding.
	// The solver is field-INSENSITIVE (one node per value), so it treats the
	// object as sanitized and suppresses. Recorded as a documented limitation
	// (docs/08 precision profile: field sensitivity), NOT a silent pass.
	if n := nSql(t, map[string]string{"obj": in, "san": san, "q": q},
		[][2]string{{"obj", "san"}, {"san", "q"}}); n != 0 {
		t.Fatalf("row7 different-field KNOWN LIMITATION (field-insensitive suppresses; ideal=finding), got %d", n)
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
)

const jsTryCatchSrc = `
module.exports = function run(target) {
  try {
    attempt(target);
  } catch (err) {
    recover(err.message);
  } finally {
    cleanup();
  }
  finish(target);
};
`

func writeJsTryCatchFixture(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(jsTryCatchSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// findJsTry returns the single nir.Try inside the named function's body.
func findJsTry(t *testing.T, prog nir.Program, fn string) nir.Try {
	t.Helper()
	def, ok := findFuncDef(prog, fn)
	if !ok {
		t.Fatalf("function %s was not extracted; program=%#v", fn, prog)
	}
	var found []nir.Try
	var walk func(stmts []nir.Stmt)
	walk = func(stmts []nir.Stmt) {
		for _, st := range stmts {
			switch s := st.(type) {
			case nir.Try:
				found = append(found, s)
				walk(s.Body)
				for _, h := range s.Handlers {
					walk(h)
				}
				walk(s.Finally)
			case nir.Block:
				walk(s.Stmts)
			case nir.If:
				walk(s.Then)
				walk(s.Else)
			case nir.Loop:
				walk(s.Body)
			}
		}
	}
	walk(def.Body)
	if len(found) != 1 {
		t.Fatalf("want exactly one try in %s, got %d; body=%#v", fn, len(found), def.Body)
	}
	return found[0]
}

// The catch body must land in nir.Try's Handlers and `finally` in Finally — not
// flattened into Body, which collapses the try body and the exception handler into one
// control region, leaving no rule able to tell a statement that runs on both paths from
// one that runs only when the try body succeeded.
func TestJavaScriptTryStatementLowersCatchIntoHandlers(t *testing.T) {
	path := writeJsTryCatchFixture(t, "runner.js")
	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	tr := findJsTry(t, prog, "run")

	if !funcBodyHasCall(tr.Body, "attempt") {
		t.Fatalf("try body lost its statements; body=%#v", tr.Body)
	}
	if funcBodyHasCall(tr.Body, "recover") || funcBodyHasCall(tr.Body, "cleanup") {
		t.Fatalf("catch/finally statements collapsed into try Body; body=%#v", tr.Body)
	}
	if len(tr.Handlers) != 1 {
		t.Fatalf("want one catch handler, got %d; try=%#v", len(tr.Handlers), tr)
	}
	if !funcBodyHasCall(tr.Handlers[0], "recover") {
		t.Fatalf("catch body did not keep its statements; handler=%#v", tr.Handlers[0])
	}
	if !funcBodyHasCall(tr.Finally, "cleanup") {
		t.Fatalf("finally body did not keep its statements; Finally=%#v", tr.Finally)
	}
	// HandlerParams stays empty BY DESIGN. The lowering binds a handler parameter to
	// the try's exception node, which every guarded call's receiver, arguments and
	// result flow into — so a handler answering with `err.message` would carry the
	// guarded body's taint out through the parameter, and no shipped JavaScript rule
	// consumes that fact (the specs pinned on this frontend read a handler that echoes
	// an error message as silent). Binding the parameter is a behaviour change beyond
	// the region split and waits for a rule that asks for it.
	if len(tr.HandlerParams) != 0 {
		t.Fatalf("catch parameter was bound to the exception node; HandlerParams=%#v", tr.HandlerParams)
	}
}

// With the handler in its own region, a call only the exception path reaches is no
// longer in the same control region as one that runs when the try body succeeds — the
// distinction a rule needs to tell "runs on both paths" from "runs only on success".
func TestJavaScriptTryCatchHandlerIsSeparateControlRegion(t *testing.T) {
	path := writeJsTryCatchFixture(t, "runner.js")
	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := graph.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	regions := map[string]string{}
	for _, n := range nodes {
		if n.Type == "code.Call" {
			regions[n.Prop("callee_path")] = n.Prop("region")
		}
	}
	for _, callee := range []string{"attempt", "recover", "cleanup", "finish"} {
		if regions[callee] == "" {
			t.Fatalf("call %s was not lowered; nodes=%#v", callee, nodes)
		}
	}
	// The handler's region must be its own branch (the `.h0` segment off the try's),
	// not equal to the try body's: one region for body and catch is exactly the collapse
	// that hides which path a statement ran on.
	if regions["recover"] != regions["attempt"]+".h0" {
		t.Fatalf("catch call region %q is not its own branch off the try body region %q",
			regions["recover"], regions["attempt"])
	}
	// `finally` runs on every path out of the statement, so it stays in the region the
	// try statement sits in — the same region as the statement that follows the try.
	if regions["cleanup"] != regions["finish"] {
		t.Fatalf("finally call region %q should share the enclosing region of post-try call %q",
			regions["cleanup"], regions["finish"])
	}
}

// Splitting the control regions must not split the lexical scope the try statement
// gives its clauses: a handler is an alternative arm of the try (its own region) while
// still being WRITTEN in the try, and the scope predicates a rule reads —
// node.scopeCall, sameScope coverage — pair the handler's nodes with the try body's
// calls. Without the scope override a validation fetch in the body falls out of the
// handler's scope and a rule that credits a handler for denying on the error path
// (auth-check fail-open) stops seeing the check it covers.
func TestJavaScriptTryClausesKeepTheTrysLexicalScope(t *testing.T) {
	path := writeJsTryCatchFixture(t, "runner.js")
	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := graph.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	type callNode struct{ region, scope string }
	callRegions := map[string]callNode{}
	for _, n := range nodes {
		if n.Type == "code.Call" {
			callRegions[n.Prop("callee_path")] = callNode{region: n.Prop("region"), scope: n.Scope}
		}
	}
	tryRegion := callRegions["attempt"].region
	if tryRegion == "" {
		t.Fatalf("try body call was not lowered; nodes=%#v", nodes)
	}
	for _, callee := range []string{"recover", "cleanup"} {
		if got := callRegions[callee].scope; got != tryRegion {
			t.Fatalf("call %s reports lexical scope %q, want the try's region %q", callee, got, tryRegion)
		}
	}
	// The body keeps the try's region as its scope too (no override needed — the region
	// IS the scope there), and a statement after the try is back in the enclosing scope.
	if got := callRegions["attempt"].scope; got != "" {
		t.Fatalf("try body call reports lexical scope %q, want none (region fallback)", got)
	}
	if got := callRegions["finish"].scope; got != "" {
		t.Fatalf("post-try call reports lexical scope %q, want none (region fallback)", got)
	}
}

// The try's analysis.exception node is a sink for the guarded body's calls, and only a
// sink: binding a handler parameter to it (HandlerParams) would hand the guarded
// body's taint to the handler through `err`, which no shipped rule consumes and the
// specs on this frontend reject. With the parameter unbound, nothing flows back out.
func TestJavaScriptTryExceptionNodeIsASink(t *testing.T) {
	path := writeJsTryCatchFixture(t, "runner.js")
	prog, err := treesitter.ExtractJavaScript([]string{path}, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := graph.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var exnID string
	for _, n := range nodes {
		if n.Prop("callee_path") == "analysis.exception" {
			exnID = n.ID
			break
		}
	}
	if exnID == "" {
		t.Fatalf("exception node was not lowered; nodes=%#v", nodes)
	}
	if out, err := graph.OutEdges(exnID, "FLOWS"); err != nil {
		t.Fatal(err)
	} else if len(out) != 0 {
		t.Fatalf("exception node flows out to %d node(s) — the guarded body's taint escapes through it: %v", len(out), out)
	}
}

// TypeScript keeps the same catch_clause shape (with an optional type annotation), so
// .ts files get the same handler split.
func TestTypeScriptTryStatementLowersCatchIntoHandlers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.ts")
	src := []byte(`
export function run(target: string): void {
  try {
    attempt(target);
  } catch (err: unknown) {
    recover(err);
  }
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tr := findJsTry(t, prog, "run")
	if len(tr.Handlers) != 1 {
		t.Fatalf("TS catch handler was not captured; try=%#v", tr)
	}
	if funcBodyHasCall(tr.Body, "recover") || !funcBodyHasCall(tr.Handlers[0], "recover") {
		t.Fatalf("TS catch body did not land in its handler; body=%#v handlers=%#v", tr.Body, tr.Handlers)
	}
}

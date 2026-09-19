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

// The catch body must land in nir.Try's Handlers (with the catch parameter bound) and
// `finally` in Finally — not flattened into Body, which collapses the try body and the
// exception handler into one control region.
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
	if len(tr.HandlerParams) != 1 || tr.HandlerParams[0] != "err" {
		t.Fatalf("catch parameter was not captured; HandlerParams=%#v", tr.HandlerParams)
	}
	if !funcBodyHasCall(tr.Finally, "cleanup") {
		t.Fatalf("finally body did not keep its statements; Finally=%#v", tr.Finally)
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
	if len(tr.Handlers) != 1 || len(tr.HandlerParams) != 1 || tr.HandlerParams[0] != "err" {
		t.Fatalf("TS catch handler/parameter was not captured; try=%#v", tr)
	}
	if funcBodyHasCall(tr.Body, "recover") || !funcBodyHasCall(tr.Handlers[0], "recover") {
		t.Fatalf("TS catch body did not land in its handler; body=%#v handlers=%#v", tr.Body, tr.Handlers)
	}
}

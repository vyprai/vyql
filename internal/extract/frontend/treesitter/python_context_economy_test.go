package treesitter

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// extractAndLowerPython extracts one Python source and lowers it, the way a scan
// of that repository would.
func extractAndLowerPython(t *testing.T, name, src string) (nir.Program, usg.Store) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractPython([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	return prog, g
}

// TestPythonFunctionEndModuleTokensAreOneLiteral pins the node economy of the
// module-fact re-carriage: a function's .end call carries the module's context
// tokens (capped at pyContextBaseTokenLimit) as ONE joined literal, not one
// literal per token. One literal per token costs a Const+Arg node pair per token
// per function — the 512-token cap over thousands of functions is millions of
// nodes, a graph quadratic in the module — and that term is what pushed a dense
// multi-package Python repository past a whole-repository scan's memory safety
// stop before any finding was emitted.
func TestPythonFunctionEndModuleTokensAreOneLiteral(t *testing.T) {
	prog, _ := extractAndLowerPython(t, "mod.py", moduleTokenSource(3))
	var endCalls, otherCalls, endWithModuleLiteral, otherCallsWithModuleLiteral int
	var walk func([]nir.Stmt)
	walk = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ExprStmt:
				c, ok := s.Value.(nir.Call)
				if !ok || !strings.HasPrefix(c.Path, "analysis.function.context") {
					continue
				}
				var blob string
				moduleLiterals := 0
				for _, a := range c.Args {
					lit, ok := a.(nir.Const)
					if !ok || !strings.HasPrefix(lit.Value, "module_") {
						continue
					}
					moduleLiterals++
					blob = lit.Value
				}
				if c.Path == "analysis.function.context.end" {
					endCalls++
					// The joined literal still carries every module token, \x00
					// separated and module_ prefixed, so str_args (value matching)
					// and the \x00-splitting presence walk see the same tokens
					// one-literal-per-token produced.
					segments := strings.Split(blob, "\x00")
					known := map[string]bool{
						"module_function_name:module":  false,
						"module_identifier:handler_0":  false,
						"module_call_path:request.get": false,
						"module_literal:field_0":       false,
					}
					for _, seg := range segments {
						if !strings.HasPrefix(seg, "module_") {
							t.Fatalf("re-carriage segment %q is not module_ prefixed", seg)
						}
						if _, ok := known[seg]; ok {
							known[seg] = true
						}
					}
					complete := moduleLiterals == 1
					for seg, present := range known {
						if !present {
							t.Errorf("end call re-carriage is missing module token %q (blob has %d segments)", seg, len(segments))
							complete = false
						}
					}
					if complete {
						endWithModuleLiteral++
					}
				} else {
					otherCalls++
					if moduleLiterals > 0 {
						otherCallsWithModuleLiteral++
					}
				}
			case nir.FuncDef:
				walk(s.Body)
			case nir.Block:
				walk(s.Stmts)
			}
		}
	}
	for _, m := range prog.Modules {
		walk(m.Body)
	}
	if endCalls == 0 {
		t.Fatal("no analysis.function.context.end call was emitted")
	}
	if endWithModuleLiteral != endCalls {
		t.Fatalf("module re-carriage is not one joined literal carrying every module token on %d of %d end calls", endCalls-endWithModuleLiteral, endCalls)
	}
	if otherCallsWithModuleLiteral != 0 {
		t.Fatalf("%d non-end context calls carry module_ literals; the re-carriage is the end call's alone", otherCallsWithModuleLiteral)
	}
}

// TestPythonManyFunctionModuleGraphBudget pins what the economy buys: a module
// of many small functions lowers to a graph whose size is linear in the module,
// not linear in functions × module tokens. At one literal per token the same
// source lowered to 529031 nodes, 1322 per function (each of the 400 functions
// re-carried the capped 512-token module list as 512 Const+Arg pairs); the
// budget leaves headroom over the joined-literal shape's ~300.
func TestPythonManyFunctionModuleGraphBudget(t *testing.T) {
	const funcs = 400
	_, g := extractAndLowerPython(t, "dense.py", moduleTokenSource(funcs))
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	// The module facts must still be on every function's end call.
	var endCalls, endWithModule int
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context.end" {
			continue
		}
		endCalls++
		if strings.Contains(n.Prop("str_args"), "module_identifier:handler_0") {
			endWithModule++
		}
	}
	if endCalls == 0 {
		t.Fatal("no analysis.function.context.end call was lowered")
	}
	if endWithModule != endCalls {
		t.Fatalf("module context tokens missing from %d of %d end calls' str_args", endCalls-endWithModule, endCalls)
	}
	if perFunc := len(nodes) / funcs; perFunc > 500 {
		t.Fatalf("%d functions lowered to %d nodes (%d per function); the module re-carriage must not mint a node per token per function", funcs, len(nodes), perFunc)
	}
}

// moduleTokenSource builds a module of same-shaped functions: every function
// gets the frontend's five context calls, and the module's own token list (each
// module-level def contributes identifiers) is re-carried on each .end call.
func moduleTokenSource(funcs int) string {
	var src bytes.Buffer
	for i := range funcs {
		fmt.Fprintf(&src, "def handler_%d(request, response):\n    data = request.get('field_%d')\n    response.write('<b>' + data + '</b>')\n\n", i, i)
	}
	return src.String()
}

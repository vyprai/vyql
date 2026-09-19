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

// moduleLiteralMarker is a string literal that exists only at module scope, so a
// case can tell the module's literal context apart from each function's own.
const moduleLiteralMarker = "zz_module_literal_marker_zz"

// TestPythonModuleLiteralContextRidesTheEndCallAlone pins where the module's
// raw literal context rides: on every function's .end call alone, the same
// carrier as the module's structured tokens, and on none of the other four
// context calls each function mints. The bindings that ask for module facts
// anchor on callee.analysis == "function.context.end", so the end call is where
// the facts belong; riding the other calls cost a fresh str_args join of the
// module's whole literal mass per call per function, and a many-function
// module's literal mass grows with its functions — functions x module literals,
// the quadratic term that pushed dense multi-package Python past a
// whole-repository scan's memory safety stop before any finding was emitted.
func TestPythonModuleLiteralContextRidesTheEndCallAlone(t *testing.T) {
	src := "MARKER = \"" + moduleLiteralMarker + "\"\n\n" + moduleTokenSource(3)
	prog, _ := extractAndLowerPython(t, "mod.py", src)
	var endCalls, endWithMarker, otherCalls, otherCallsWithMarker int
	var walk func([]nir.Stmt)
	walk = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ExprStmt:
				c, ok := s.Value.(nir.Call)
				if !ok || !strings.HasPrefix(c.Path, "analysis.function.context") {
					continue
				}
				// The function's own literals never carry the module-level marker,
				// so any Const carrying it here is the module's literal context.
				carriesMarker := false
				for _, a := range c.Args {
					if lit, ok := a.(nir.Const); ok && strings.Contains(lit.Value, moduleLiteralMarker) {
						carriesMarker = true
					}
				}
				if c.Path == "analysis.function.context.end" {
					endCalls++
					if carriesMarker {
						endWithMarker++
					}
				} else {
					otherCalls++
					if carriesMarker {
						otherCallsWithMarker++
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
	if endWithMarker != endCalls {
		t.Fatalf("the module's literal context is missing from %d of %d end calls; every module fact must still ride the end call", endCalls-endWithMarker, endCalls)
	}
	if otherCallsWithMarker != 0 {
		t.Fatalf("%d non-end context calls carry the module's literal context; the end call is its carrier, and riding the other calls re-joins the module's whole literal mass on each of a function's context calls", otherCallsWithMarker)
	}
}

// TestPythonManyFunctionModuleLiteralJoinBudget pins what that economy buys: a
// module of many functions, each with its own literals, lowers so that the
// per-function context calls carry only that function's own text — their joined
// arguments stay small no matter how many literals the module holds — while the
// end call still carries the module's literal context (every literal, not a
// truncation of it).
func TestPythonManyFunctionModuleLiteralJoinBudget(t *testing.T) {
	const funcs = 400
	var src bytes.Buffer
	fmt.Fprintf(&src, "MARKER = %q\n\n", moduleLiteralMarker)
	for i := 0; i < funcs; i++ {
		fmt.Fprintf(&src, "def handler_%d(request):\n    data = request.get('field_%d_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')\n    return data\n\n", i, i)
	}
	_, g := extractAndLowerPython(t, "dense.py", src.String())
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var endCalls, endWithMarker int
	var otherContextBytes int
	for _, n := range nodes {
		if n.Type != "code.Call" {
			continue
		}
		switch n.Prop("callee_path") {
		case "analysis.function.context.end":
			endCalls++
			if strings.Contains(n.Prop("str_args"), moduleLiteralMarker) {
				endWithMarker++
			}
		case "analysis.function.context", "analysis.function.context.source", "analysis.function.context.sink":
			// Each of these carries one function's own body text and tokens —
			// kilobytes — never the module's literal mass, which grows with the
			// module's functions.
			otherContextBytes += len(n.StrArgs)
		}
	}
	if endCalls == 0 {
		t.Fatal("no analysis.function.context.end call was lowered")
	}
	if endWithMarker != endCalls {
		t.Fatalf("the module's literal context is missing from %d of %d end calls' str_args", endCalls-endWithMarker, endCalls)
	}
	// 3 calls per function, each at most a couple of kilobytes of the function's
	// own text: the budget is 2.5 MiB. Carrying the module's literal context
	// instead measured an order of magnitude more (the module's ~16 KiB of
	// literals joined into each of the 1200 calls).
	const budget = funcs * 3 * (2 << 10)
	if otherContextBytes > budget {
		t.Fatalf("%d non-end context calls joined %d bytes (%d over the %d-byte budget); the module's literal mass must not ride them", funcs*3, otherContextBytes, otherContextBytes-budget, budget)
	}
}

// TestPythonModuleLiteralContextIsBounded pins the bound on the module literal
// context itself: a module whose literal mass exceeds pyModuleLiteralMaxBytes
// keeps a source-order PREFIX of it on every end call — the earliest literals
// whole, none of the mass past the bound — because the blob is re-joined into
// each function's end-call str_args and scanned by every value matcher over it;
// unbounded, a many-function module's cost grew with functions x module
// literals, the term that pushed dense multi-package Python past a
// whole-repository scan's memory safety stop and its 180s timeout.
func TestPythonModuleLiteralContextIsBounded(t *testing.T) {
	const earlyMarker = "zz_early_module_literal_zz"
	// The fill and the late marker are longer than pyContextCompact's 160-byte
	// token bound, so they contribute no module_literal: token — the only surface
	// they can ride is the raw literal context this case bounds.
	fill := strings.Repeat("x", 1024)
	lateMarker := "zz_late_" + strings.Repeat("y", 256)
	var src bytes.Buffer
	fmt.Fprintf(&src, "EARLY = %q\n", earlyMarker)
	// ~200KB of literal mass: well past the 64KB bound, reached before the late
	// marker, which must fall out of the prefix.
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&src, "CONST_%d = %q\n", i, fill)
	}
	fmt.Fprintf(&src, "LATE = %q\n\ndef handler(request):\n    return request.get('field')\n", lateMarker)
	_, g := extractAndLowerPython(t, "fat.py", src.String())
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	endCalls, withEarly, withLate := 0, 0, 0
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context.end" {
			continue
		}
		endCalls++
		args := n.Prop("str_args")
		if len(args) > (64<<10)+pyContextBaseTokenLimit*64 {
			t.Fatalf("end call str_args is %d bytes; the module literal context must be bounded at %d", len(args), 64<<10)
		}
		if strings.Contains(args, earlyMarker) {
			withEarly++
		}
		if strings.Contains(args, lateMarker) {
			withLate++
		}
	}
	if endCalls == 0 {
		t.Fatal("no analysis.function.context.end call was lowered")
	}
	if withEarly != endCalls {
		t.Fatalf("the earliest module literal is missing from %d of %d end calls; the bound keeps a prefix, not a sample", endCalls-withEarly, endCalls)
	}
	if withLate != 0 {
		t.Fatalf("the module literal context past the bound rides %d of %d end calls; a %d-byte literal mass must not ride every function", withLate, endCalls, 64<<10)
	}
}

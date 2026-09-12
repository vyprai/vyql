package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// ccExtract parses one C source into NIR.
func ccExtract(t *testing.T, src string) nir.Program {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "handler.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

// nodeByProps returns the one node of a type carrying every property given, failing
// when none or several match.
func nodeByProps(t *testing.T, g usg.Store, typ string, props ...string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	var hit string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		match := true
		for i := 0; i+1 < len(props); i += 2 {
			if n.Prop(props[i]) != props[i+1] {
				match = false
				break
			}
		}
		if match {
			if hit != "" {
				t.Fatalf("several %s nodes match %v", typ, props)
			}
			hit = n.ID
		}
	}
	if hit == "" {
		t.Fatalf("no %s node matches %v", typ, props)
	}
	return hit
}

// The shape the gap is: a callee declared in a header fills the caller's variable
// through the pointer the caller passes, and the variable is read afterwards. A
// binding saying so -- `propagate value from args[0] to args[1].pointee` -- is the
// only place that knowledge exists, because the file's own text types neither the
// callee nor its parameters, so the two lowerings the frontend applies on its own
// (the reader table and the void-mutator declaration scan) both refuse the call.
const ccDeclaredOutParamSrc = `
int fill_from(void *src, int *out);

void handler(void *src) {
    int out = 0;
    if (fill_from(src, &out) != 0)
        return;
    emit(out);
}
`

// The declared flow re-binds `out` to what the call wrote through it, so a read
// after the call runs through the call: whatever reached its source argument is on
// that read's path.
func TestCDeclaredOutParamFlowReachesTheDestinationVariable(t *testing.T) {
	restore := stubCallEffects(t, []nir.CallEffect{{DestArg: 1, SourceArg: 0}})
	defer restore()

	g, err := lowering.Lower(ccExtract(t, ccDeclaredOutParamSrc), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := nodeByProps(t, g, "code.Param", "name", "src")
	read := nodeByProps(t, g, "code.Arg", "loc", "handler.c:8")

	reachable, err := usg.BFS(g, src, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[read] {
		t.Fatal("the read of the out-parameter's variable is not downstream of the value the call was handed")
	}
}

// With nothing declared the call stays opaque in the ordinary way: its arguments
// flow into its result, and the variable it filled keeps what it held. This is the
// behaviour that lost the label.
func TestCWithoutADeclaredFlowTheOutParamVariableStaysUnfilled(t *testing.T) {
	restore := stubCallEffects(t, nil)
	defer restore()

	g, err := lowering.Lower(ccExtract(t, ccDeclaredOutParamSrc), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := nodeByProps(t, g, "code.Param", "name", "src")
	read := nodeByProps(t, g, "code.Arg", "loc", "handler.c:8")

	reachable, err := usg.BFS(g, src, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[read] {
		t.Fatal("an undeclared out-parameter must not carry the call's arguments into the variable")
	}
}

// The effect reaches the call the frontend builds, where the lowering applies it.
func TestCDeclaredOutParamEffectIsCarriedOnTheCall(t *testing.T) {
	restore := stubCallEffects(t, []nir.CallEffect{{DestArg: 1, SourceArg: 0}})
	defer restore()

	var got []nir.CallEffect
	var walkExpr func(e nir.Expr) bool
	walkExpr = func(e nir.Expr) bool {
		switch x := e.(type) {
		case nir.Call:
			if x.Path == "fill_from" {
				got = x.Effects
				return true
			}
			for _, a := range x.Args {
				if walkExpr(a) {
					return true
				}
			}
		case nir.BinOp:
			return walkExpr(x.Left) || walkExpr(x.Right)
		case nir.Thru:
			return walkExpr(x.Inner)
		case nir.Unary:
			return walkExpr(x.Operand)
		}
		return false
	}
	var walk func(stmts []nir.Stmt) bool
	walk = func(stmts []nir.Stmt) bool {
		for _, s := range stmts {
			switch st := s.(type) {
			case nir.FuncDef:
				if walk(st.Body) {
					return true
				}
			case nir.Block:
				if walk(st.Stmts) {
					return true
				}
			case nir.If:
				if walkExpr(st.Cond) || walk(st.Then) || walk(st.Else) {
					return true
				}
			case nir.Loop:
				if walk(st.Body) {
					return true
				}
			case nir.ExprStmt:
				if walkExpr(st.Value) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range ccExtract(t, ccDeclaredOutParamSrc).Modules {
		walk(mod.Body)
	}
	if len(got) != 1 || got[0] != (nir.CallEffect{DestArg: 1, SourceArg: 0}) {
		t.Fatalf("fill_from carries %v, want one {DestArg:1 SourceArg:0}", got)
	}
}

// stubCallEffects installs a lookup that answers for the `fill_from` callee only --
// nil effects meaning nothing is declared -- and restores the previous one when the
// test ends.
func stubCallEffects(t *testing.T, effects []nir.CallEffect) func() {
	t.Helper()
	prev := callEffectLookup
	callEffectLookup = func(tech, path, method string) []nir.CallEffect {
		if tech != "c" || path != "fill_from" {
			return nil
		}
		return effects
	}
	return func() { callEffectLookup = prev }
}

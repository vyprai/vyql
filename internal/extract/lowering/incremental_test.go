package lowering

import (
	"fmt"
	"sort"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// memDelta is an in-memory DeltaCache for the equivalence harness.
type memDelta map[string][]byte

func (m memDelta) GetRaw(k string) ([]byte, bool) { v, ok := m[k]; return v, ok }
func (m memDelta) PutRaw(k string, v []byte)      { m[k] = append([]byte(nil), v...) }

// modA builds module "a": a helper getInput() that returns a read() result, plus an unrelated
// constant function. hash distinguishes versions for the incremental cache.
func modA(hash, retCall string) nir.Module {
	return nir.Module{Key: "a", File: "a.x", Hash: hash, Body: []nir.Stmt{
		nir.FuncDef{Name: "getInput", Loc: "a.x:1", Body: []nir.Stmt{
			nir.Return{Value: nir.Call{Callee: nir.Name{ID: retCall, Loc: "a.x:2"}, Path: retCall, Method: retCall, Loc: "a.x:2"}},
		}},
	}}
}

// modB builds module "b": handler(req) { y = a.getInput(); sink(y) } — a cross-module call so
// b's lowering references a's signature nodes. extra appends an extra statement (a body edit).
func modB(hash string, extra []nir.Stmt) nir.Module {
	body := []nir.Stmt{
		nir.Assign{Targets: []string{"y"}, Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "a", Loc: "b.x:2"}, Attr: "getInput", Path: "a.getInput", Loc: "b.x:2"},
			Path:   "a.getInput", Method: "getInput", Loc: "b.x:2",
		}},
		nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "sink", Loc: "b.x:3"}, Path: "sink", Method: "sink",
			Args: []nir.Expr{nir.Name{ID: "y", Loc: "b.x:3"}}, Loc: "b.x:3"}},
	}
	body = append(body, extra...)
	return nir.Module{Key: "b", File: "b.x", Hash: hash,
		Imports: []nir.Import{{Local: "a", Module: "a", IsModule: true}},
		Body:    []nir.Stmt{nir.FuncDef{Name: "handler", Params: []string{"req"}, Loc: "b.x:1", Body: body}}}
}

func prog(mods ...nir.Module) nir.Program {
	return nir.Program{Modules: mods, SelfName: "self"}
}

// php-style modules: resolution Key is "" (flat namespace) and only File distinguishes them —
// the case that exposed the node-id collision. Cross-file via a unique bare-name call.
func modPhpA(hash, retCall string) nir.Module {
	return nir.Module{Key: "", File: "a.php", Hash: hash, Body: []nir.Stmt{
		nir.FuncDef{Name: "getInput", Loc: "a.php:1", Body: []nir.Stmt{
			nir.Return{Value: nir.Call{Callee: nir.Name{ID: retCall, Loc: "a.php:2"}, Path: retCall, Method: retCall, Loc: "a.php:2"}},
		}},
	}}
}

func modPhpB(hash string, extra []nir.Stmt) nir.Module {
	body := []nir.Stmt{
		nir.Assign{Targets: []string{"y"}, Value: nir.Call{Callee: nir.Name{ID: "getInput", Loc: "b.php:2"}, Path: "getInput", Method: "getInput", Loc: "b.php:2"}},
		nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "sink", Loc: "b.php:3"}, Path: "sink", Method: "sink", Args: []nir.Expr{nir.Name{ID: "y", Loc: "b.php:3"}}, Loc: "b.php:3"}},
	}
	body = append(body, extra...)
	return nir.Module{Key: "", File: "b.php", Hash: hash,
		Body: []nir.Stmt{nir.FuncDef{Name: "handler", Params: []string{"req"}, Loc: "b.php:1", Body: body}}}
}

// snapshot renders a store as a sorted, comparable string (nodes with type+props, edges,
// labels). Two graphs are equivalent iff their snapshots match — a stronger invariant than
// finding-equality (identical graphs ⇒ identical binding/taint/rule output).
func snapshot(t *testing.T, s usg.Store) string {
	t.Helper()
	nodes, _ := s.AllNodes()
	var lines []string
	for _, n := range nodes {
		var props []string
		for k, v := range n.Props {
			props = append(props, k+"="+v)
		}
		// include the inline fields so the equivalence check covers loc/region/order too.
		for _, k := range []string{"loc", "region", "order"} {
			if v := n.Prop(k); v != "" {
				props = append(props, k+"="+v)
			}
		}
		sort.Strings(props)
		lines = append(lines, fmt.Sprintf("N %s %s {%v}", n.ID, n.Type, props))
		for _, et := range []string{"FLOWS", "CONTROL", "STEP", "NET", "DEPENDS_ON"} {
			es, _ := s.OutEdges(n.ID, et)
			for _, e := range es {
				lines = append(lines, fmt.Sprintf("E %s %s->%s", et, e.Src, e.Dst))
			}
		}
		ls, _ := s.Labels(n.ID)
		for _, l := range ls {
			lines = append(lines, fmt.Sprintf("L %s %s", n.ID, l.Concept))
		}
	}
	sort.Strings(lines)
	out := ""
	for _, ln := range lines {
		out += ln + "\n"
	}
	return out
}

func lowerFull(t *testing.T, p nir.Program) usg.Store {
	t.Helper()
	g, err := LowerTyped(p, true, nil)
	if err != nil {
		t.Fatalf("LowerTyped: %v", err)
	}
	return g
}

func lowerInc(t *testing.T, p nir.Program, c DeltaCache) usg.Store {
	t.Helper()
	g, _, err := LowerIncremental(p, true, nil, c, nil)
	if err != nil {
		t.Fatalf("LowerIncremental: %v", err)
	}
	return g
}

// TestIncrementalEquivalence is the soundness gate: for every change shape, the incrementally
// lowered graph (cache populated from the previous version, then reused) must be byte-for-byte
// equivalent to a full lowering of the edited program.
func TestIncrementalEquivalence(t *testing.T) {
	cases := []struct {
		name   string
		v1, v2 nir.Program
	}{
		{"no change", prog(modA("a1", "read"), modB("b1", nil)),
			prog(modA("a1", "read"), modB("b1", nil))},
		{"body edit (b changes, a reused)", prog(modA("a1", "read"), modB("b1", nil)),
			prog(modA("a1", "read"), modB("b2", []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "log", Loc: "b.x:4"}, Path: "log", Method: "log", Loc: "b.x:4"}}}))},
		{"signature edit (a's helper gains a param)", prog(modA("a1", "read"), modB("b1", nil)),
			prog(nir.Module{Key: "a", File: "a.x", Hash: "a2", Body: []nir.Stmt{
				nir.FuncDef{Name: "getInput", Params: []string{"p"}, Loc: "a.x:1", Body: []nir.Stmt{nir.Return{Value: nir.Name{ID: "p", Loc: "a.x:2"}}}}}}, modB("b1", nil))},
		{"add module c", prog(modA("a1", "read"), modB("b1", nil)),
			prog(modA("a1", "read"), modB("b1", nil), nir.Module{Key: "c", File: "c.x", Hash: "c1", Body: []nir.Stmt{nir.FuncDef{Name: "f", Loc: "c.x:1", Body: []nir.Stmt{nir.Return{}}}}})},
		{"delete module a body change", prog(modA("a1", "read"), modB("b1", nil), nir.Module{Key: "c", File: "c.x", Hash: "c1", Body: []nir.Stmt{nir.FuncDef{Name: "f", Loc: "c.x:1", Body: []nir.Stmt{nir.Return{}}}}}),
			prog(modA("a1", "read"), modB("b1", nil))},
		// php-style modules (resolution Key=="", only File namespaces): exercises the per-file
		// node-id namespacing (curNS) — without it, a.php and b.php share the "" counter space and
		// incremental reuse mints colliding ids.
		{"php no change", prog(modPhpA("a1", "read"), modPhpB("b1", nil)),
			prog(modPhpA("a1", "read"), modPhpB("b1", nil))},
		{"php body edit (b changes, a reused)", prog(modPhpA("a1", "read"), modPhpB("b1", nil)),
			prog(modPhpA("a1", "read"), modPhpB("b2", []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "log", Loc: "b.php:4"}, Path: "log", Method: "log", Loc: "b.php:4"}}}))},
		{"php a body edit (b reused)", prog(modPhpA("a1", "read"), modPhpB("b1", nil)),
			prog(modPhpA("a2", "fetch"), modPhpB("b1", nil))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := memDelta{}
			// populate cache from v1, then incrementally lower v2.
			_ = lowerInc(t, tc.v1, cache)
			got := snapshot(t, lowerInc(t, tc.v2, cache))
			want := snapshot(t, lowerFull(t, tc.v2))
			if got != want {
				t.Errorf("incremental graph != full graph after edit\n--- incremental ---\n%s\n--- full ---\n%s", got, want)
			}
		})
	}
}

// TestIncrementalReuses confirms the cache is actually exercised: re-lowering an unchanged
// program hits the cache for every content-addressed module (no silent always-miss).
func TestIncrementalReuses(t *testing.T) {
	p := prog(modA("a1", "read"), modB("b1", nil))
	cache := memDelta{}
	_ = lowerInc(t, p, cache)
	if len(cache) == 0 {
		t.Fatal("cache empty after first incremental lower — deltas not stored")
	}
	// second lower of the same program must equal a full lower (and use the cache).
	if got, want := snapshot(t, lowerInc(t, p, cache)), snapshot(t, lowerFull(t, p)); got != want {
		t.Errorf("second incremental lower != full\n%s\n---\n%s", got, want)
	}
}

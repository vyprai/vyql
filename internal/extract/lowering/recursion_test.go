package lowering

import (
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/usg"
)

// recursionCycles returns the str_args of every analysis.recursion.cycle event in a lowered
// program, sorted so a test can compare the set rather than the emission order.
func recursionCycles(t *testing.T, prog nir.Program) []string {
	t.Helper()
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatalf("all nodes: %v", err)
	}
	var out []string
	for _, n := range nodes {
		if n.Prop("callee_path") == analysisRecursionCyclePath {
			out = append(out, strings.ReplaceAll(n.Prop("str_args"), "\x00", " "))
		}
	}
	sort.Strings(out)
	return out
}

// recursionCallStmt is a bare call to a top-level function of the same module, which is what
// every cycle below is built from.
func cycleEventCount(t *testing.T, g usg.Store) int {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatalf("all nodes: %v", err)
	}
	n := 0
	for _, node := range nodes {
		if node.Prop("callee_path") == analysisRecursionCyclePath {
			n++
		}
	}
	return n
}

func recursionCallStmt(name, loc string, args ...nir.Expr) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: name, Loc: loc},
		Args:   args,
		Path:   name,
		Method: name,
		Loc:    loc,
	}}
}

// A function that calls itself is a cycle of one, and nothing in the body bounds how deep it
// goes.
func TestRecursionCycleRecordsAnUnboundedSelfCall(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "walk", Params: []string{"node"}, Loc: "app.go:1", Body: []nir.Stmt{
				recursionCallStmt("walk", "app.go:2", nir.Name{ID: "node", Loc: "app.go:2"}),
			}},
		},
	}}}
	got := recursionCycles(t, prog)
	if len(got) != 1 ||
		!strings.Contains(got[0], "cycle=self") ||
		!strings.Contains(got[0], "depth_budget=absent") ||
		!strings.Contains(got[0], "function=walk") ||
		!strings.Contains(got[0], "callee=walk") ||
		!strings.Contains(got[0], "cycle_length=1") {
		t.Fatalf("self recursion not recorded as an unbounded cycle: %q", got)
	}
}

// The same walk with a depth counter compared against a ceiling carries its budget.
func TestRecursionCycleReadsADepthGuardAsTheBudget(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "walk", Params: []string{"node", "depth"}, Loc: "app.go:1", Body: []nir.Stmt{
				nir.If{
					Cond: nir.BinOp{Op: ">", Left: nir.Name{ID: "depth", Loc: "app.go:2"},
						Right: nir.Name{ID: "maxDepth", Loc: "app.go:2"}, Loc: "app.go:2"},
					Then: []nir.Stmt{nir.Return{}},
					Loc:  "app.go:2",
				},
				recursionCallStmt("walk", "app.go:3", nir.Name{ID: "node", Loc: "app.go:3"}),
			}},
		},
	}}}
	got := recursionCycles(t, prog)
	if len(got) != 1 || !strings.Contains(got[0], "depth_budget=present") || !strings.Contains(got[0], "budget=depth") {
		t.Fatalf("depth guard not read as a budget: %q", got)
	}
}

// A loop bounds an iteration, not a descent. `for i := 0; i < n.count; i++` is how most
// recursive walks are written, and reading its condition as a budget would silence them all.
func TestRecursionCycleDoesNotReadALoopConditionAsABudget(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "walk", Params: []string{"node"}, Loc: "app.go:1", Body: []nir.Stmt{
				nir.Loop{
					Cond: nir.BinOp{Op: "<", Left: nir.Name{ID: "i", Loc: "app.go:2"},
						Right: nir.Attr{Base: nir.Name{ID: "node", Loc: "app.go:2"}, Attr: "count", Path: "node.count", Loc: "app.go:2"},
						Loc:   "app.go:2"},
					Body: []nir.Stmt{recursionCallStmt("walk", "app.go:3", nir.Name{ID: "node", Loc: "app.go:3"})},
					Loc:  "app.go:2",
				},
			}},
		},
	}}}
	got := recursionCycles(t, prog)
	if len(got) != 1 || !strings.Contains(got[0], "depth_budget=absent") {
		t.Fatalf("loop condition wrongly read as a depth budget: %q", got)
	}
}

// The budget usually lives in a helper: the counter and its ceiling are fields of the object,
// and the function on the cycle calls the one that compares them. A guard the cycle never
// reaches is not its budget, which is exactly what separates a fixed revision from a
// vulnerable one whose file already declares the helper.
func TestRecursionCycleFindsADelegatedBudgetAndOnlyOnTheCycle(t *testing.T) {
	guard := nir.FuncDef{Name: "incr", Loc: "app.go:1", Body: []nir.Stmt{
		nir.If{
			Cond: nir.BinOp{Op: ">=",
				Left:  nir.Attr{Base: nir.Name{ID: "self", Loc: "app.go:2"}, Attr: "level", Path: "self.level", Loc: "app.go:2"},
				Right: nir.Attr{Base: nir.Name{ID: "self", Loc: "app.go:2"}, Attr: "limit", Path: "self.limit", Loc: "app.go:2"},
				Loc:   "app.go:2"},
			Then: []nir.Stmt{nir.Return{}},
			Loc:  "app.go:2",
		},
	}}
	cycle := func(guarded bool) nir.Program {
		body := []nir.Stmt{recursionCallStmt("skipField", "app.go:11")}
		if guarded {
			body = append([]nir.Stmt{recursionCallStmt("incr", "app.go:12")}, body...)
		}
		return nir.Program{Modules: []nir.Module{{
			Key:  "app",
			File: "app.go",
			Body: []nir.Stmt{
				guard,
				nir.FuncDef{Name: "skipGroup", Loc: "app.go:10", Body: body},
				nir.FuncDef{Name: "skipField", Loc: "app.go:20", Body: []nir.Stmt{
					recursionCallStmt("skipGroup", "app.go:21"),
				}},
				// A second caller of the guard that is NOT on the cycle: the vulnerable
				// revision of the shape declares one, and it must not bound the cycle.
				nir.FuncDef{Name: "mergeMessage", Loc: "app.go:30", Body: []nir.Stmt{
					recursionCallStmt("incr", "app.go:12"),
				}},
			},
		}}}
	}

	unguarded := recursionCycles(t, cycle(false))
	if len(unguarded) != 2 {
		t.Fatalf("expected one observation per cycle edge, got %q", unguarded)
	}
	for _, ev := range unguarded {
		if !strings.Contains(ev, "cycle=mutual") || !strings.Contains(ev, "depth_budget=absent") ||
			!strings.Contains(ev, "cycle_length=2") {
			t.Fatalf("a guard the cycle never calls wrongly bounded it: %q", ev)
		}
	}

	guarded := recursionCycles(t, cycle(true))
	if len(guarded) != 2 {
		t.Fatalf("expected one observation per cycle edge, got %q", guarded)
	}
	for _, ev := range guarded {
		if !strings.Contains(ev, "depth_budget=present") || !strings.Contains(ev, "budget=self.level") {
			t.Fatalf("delegated budget not credited: %q", ev)
		}
	}
}

// Nothing is emitted for a program whose calls never come back.
func TestRecursionCycleIsSilentWithoutOne(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "a", Loc: "app.go:1", Body: []nir.Stmt{recursionCallStmt("b", "app.go:1")}},
			nir.FuncDef{Name: "b", Loc: "app.go:2", Body: []nir.Stmt{recursionCallStmt("c", "app.go:2")}},
			nir.FuncDef{Name: "c", Loc: "app.go:3", Body: nil},
		},
	}}}
	if got := recursionCycles(t, prog); len(got) != 0 {
		t.Fatalf("straight-line calls reported as a cycle: %q", got)
	}
}

// The observation sits on the call site that closes the cycle and takes the call's taint, so
// a rule that wants the recursion an untrusted value reaches can ask for it.
func TestRecursionCycleObservationFlowsFromTheCallSite(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "walk", Params: []string{"node"}, Loc: "app.go:1", Body: []nir.Stmt{
				recursionCallStmt("walk", "app.go:2", nir.Name{ID: "node", Loc: "app.go:2"}),
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	nodes, _ := g.AllNodes()
	var observation usg.Node
	for _, n := range nodes {
		if n.Prop("callee_path") == analysisRecursionCyclePath {
			observation = n
		}
	}
	if observation.ID == "" {
		t.Fatal("no recursion observation")
	}
	if observation.Loc != "app.go:2" {
		t.Fatalf("observation is not at the recursive call site: %q", observation.Loc)
	}
	in, err := g.InEdges(observation.ID, "FLOWS")
	if err != nil || len(in) == 0 {
		t.Fatalf("observation takes no flow from the call site: %v %v", in, err)
	}
}

func TestThresholdCompare(t *testing.T) {
	name := func(id string) nir.Expr { return nir.Name{ID: id} }
	field := func(path string) nir.Expr {
		return nir.Attr{Base: nir.Name{ID: "self"}, Attr: path, Path: "self." + path}
	}
	call := nir.Call{Callee: nir.Name{ID: "len"}, Path: "buf.len", Method: "len"}
	for _, tc := range []struct {
		name string
		expr nir.Expr
		want string
	}{
		{"counter against a named ceiling", nir.BinOp{Op: ">", Left: name("depth"), Right: name("MAX_DEPTH")}, "depth"},
		{"counter against a literal", nir.BinOp{Op: ">=", Left: name("level"), Right: nir.Const{}}, "level"},
		{"ceiling written first", nir.BinOp{Op: "<", Left: nir.Const{}, Right: name("level")}, "level"},
		{"two fields of the receiver", nir.BinOp{Op: ">=", Left: field("recursion_level"), Right: field("recursion_limit")}, "self.recursion_level"},
		{"one conjunct is a threshold", nir.BinOp{Op: "&&",
			Left:  nir.BinOp{Op: "==", Left: name("kind"), Right: name("group")},
			Right: nir.BinOp{Op: ">", Left: name("depth"), Right: name("max")}}, "depth"},
		{"negated", nir.Unary{Op: "!", Operand: nir.BinOp{Op: "<", Left: name("depth"), Right: name("max")}}, "depth"},
		// An equality is a case label, not a threshold.
		{"equality", nir.BinOp{Op: "==", Left: name("wireType"), Right: name("endGroup")}, ""},
		// Whatever the input says about itself bounds nothing.
		{"against a call result", nir.BinOp{Op: "<", Left: field("pos"), Right: call}, ""},
		{"two literals", nir.BinOp{Op: "<", Left: nir.Const{}, Right: nir.Const{}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := thresholdCompare(tc.expr)
			if !ok {
				got = ""
			}
			if got != tc.want {
				t.Fatalf("thresholdCompare = %q, want %q", got, tc.want)
			}
		})
	}
}

// The observations are emitted at the end of a module's own lowering, which is what lets the
// incremental lowerer replay them: a module whose body is served from the delta cache, or from
// the parse cache one chunk at a time, must carry the same cycle facts as a full lowering.
func TestRecursionCycleSurvivesTheCaches(t *testing.T) {
	cycle := nir.Module{Key: "c", File: "c.x", Hash: "c1", Body: []nir.Stmt{
		nir.FuncDef{Name: "skipGroup", Loc: "c.x:1", Body: []nir.Stmt{
			recursionCallStmt("skipField", "c.x:2"),
		}},
		nir.FuncDef{Name: "skipField", Loc: "c.x:5", Body: []nir.Stmt{
			recursionCallStmt("skipGroup", "c.x:6"),
		}},
	}}
	p := prog(modA("a1", "read"), cycle)
	full := lowerFull(t, p)
	want := snapshot(t, full)
	if n := cycleEventCount(t, full); n != 2 {
		t.Fatalf("fixture should carry both edges of the cycle, got %d", n)
	}

	cache := memDelta{}
	_ = lowerInc(t, p, cache)
	replayed := lowerInc(t, p, cache)
	if n := cycleEventCount(t, replayed); n != 2 {
		t.Fatalf("replayed module carries %d cycle events, want 2", n)
	}
	if got := snapshot(t, replayed); got != want {
		t.Errorf("replayed module lost its cycle facts\n--- incremental ---\n%s\n--- full ---\n%s", got, want)
	}

	deferredProg := prog(modA("a1", "read"), cycle)
	c, err := parsecache.OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for i := range deferredProg.Modules {
		c.DeferModuleBodies(&deferredProg.Modules[i])
	}
	g, err := LowerTypedDeferred(deferredProg, true, nil, c)
	if err != nil {
		t.Fatalf("LowerTypedDeferred: %v", err)
	}
	if n := cycleEventCount(t, g); n != 2 {
		t.Fatalf("deferred bodies carry %d cycle events, want 2", n)
	}
	if got := snapshot(t, g); got != want {
		t.Errorf("deferred bodies lost their cycle facts\n--- deferred ---\n%s\n--- full ---\n%s", got, want)
	}
}

package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// jsCall is `recv.method(args…)`, the receiver being the plain name a module-level variable
// or a function local is bound to.
func jsCall(loc, recv, method string, args ...nir.Expr) nir.Call {
	return nir.Call{
		Callee: nir.Attr{Base: nir.Name{ID: recv, Loc: loc}, Attr: method, Path: recv + "." + method, Loc: loc},
		Args:   args, Path: recv + "." + method, Method: method, Loc: loc,
	}
}

// jsCtor is `new Name(args…)` as JavaScript's frontend lowers it: a call whose callee is the
// constructed name, carrying no construction marker of its own.
func jsCtor(loc, name string, args ...nir.Expr) nir.Call {
	return nir.Call{Callee: nir.Name{ID: name, Loc: loc}, Args: args, Path: name, Method: name, Loc: loc}
}

// jsStrLit is a string argument.
func jsStrLit(loc, v string) nir.Expr {
	return nir.Const{Loc: loc, Value: "'" + v + "'"}
}

// jsModule is one JavaScript file: its top-level statements, lowered with the module-global
// slots a .js module resolves its top-level names to.
func jsModule(file string, body ...nir.Stmt) nir.Program {
	return nir.Program{Modules: []nir.Module{{Key: file, File: file, Body: body}}}
}

// recvTypeOf finds one method call and returns the receiver type stamped on it.
func recvTypeOf(t *testing.T, g usg.Store, recv, method string) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Prop("callee_path") == recv+"."+method {
			return n.Prop("recv_type")
		}
	}
	return ""
}

// The shape the gap names: a class the scan declares, constructed into a module-level
// variable, read at module scope. The name resolves to the module's slot rather than to the
// construction, so before the global carried a type the call was labelled nothing at all --
// the same construction assigned inside a function already stamped `recv_type`.
func TestLowerTypesAMethodCallOnAModuleLevelVariableBuiltByAConstructor(t *testing.T) {
	prog := jsModule("app.js",
		nir.ClassDef{Name: "MyQuery", Body: []nir.Stmt{
			nir.FuncDef{Name: "get", Params: []string{"k"}, Loc: "app.js:3"},
		}, Loc: "app.js:2"},
		nir.Assign{Targets: []string{"q"}, Value: jsCtor("app.js:5", "MyQuery"), Decl: true},
		nir.ExprStmt{Value: jsCall("app.js:6", "q", "get", jsStrLit("app.js:6", "title"))},
	)
	g, err := LowerTyped(prog, true, nil)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "q", "get"); got != "MyQuery" {
		t.Fatalf("recv_type = %q, want MyQuery: the module's own variable is typed by the class that filled it", got)
	}
}

// A constructor a binding's ReceiverType fact names -- the redis_client_reads pattern -- typed
// the local a function assigned. The module-level spelling of the same setup is the one
// JavaScript actually writes, and it is the spelling a documentation-derived source needs.
func TestLowerTypesAModuleLevelVariableABindingNamesTheConstructorOf(t *testing.T) {
	prog := jsModule("app.js",
		nir.Assign{Targets: []string{"q"}, Value: jsCtor("app.js:2", "AV.Query", jsStrLit("app.js:2", "Todo")), Decl: true},
		nir.ExprStmt{Value: jsCall("app.js:3", "q", "find")},
	)
	g, err := LowerTyped(prog, true, map[string]string{"AV.Query": "AV.Query"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "q", "find"); got != "AV.Query" {
		t.Fatalf("recv_type = %q, want AV.Query", got)
	}
}

// The constructor chain: a factory the binding types hands back a CLASS, the module keeps it
// in a variable, and the instances are made by constructing through that variable's name.
// Neither the constructor table -- which keys on the callee path a binding can name -- nor
// the class table -- which knows only classes the scan declares -- can express the one
// indirection between them.
func TestLowerTypesAConstructionThroughAFactoryReturnedModuleGlobal(t *testing.T) {
	prog := jsModule("app.js",
		nir.Assign{Targets: []string{"Todo"}, Value: jsCtor("app.js:2", "AV.Object.extend", jsStrLit("app.js:2", "Todo")), Decl: true},
		nir.Assign{Targets: []string{"todo"}, Value: jsCtor("app.js:3", "Todo"), Decl: true},
		nir.ExprStmt{Value: jsCall("app.js:4", "todo", "get", jsStrLit("app.js:4", "title"))},
	)
	g, err := LowerTyped(prog, true, map[string]string{"AV.Object.extend": "AV.Object"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "todo", "get"); got != "AV.Object" {
		t.Fatalf("recv_type = %q, want AV.Object: new Todo() constructs what AV.Object.extend handed back", got)
	}
}

// The same chain read inside a function: the local holding the construction is the call node
// itself, so the indirection is resolved on the receiver rather than on the slot.
func TestLowerTypesAConstructionThroughAFactoryReturnedGlobalInsideAFunction(t *testing.T) {
	prog := jsModule("app.js",
		nir.Assign{Targets: []string{"Todo"}, Value: jsCtor("app.js:2", "AV.Object.extend", jsStrLit("app.js:2", "Todo")), Decl: true},
		nir.FuncDef{Name: "read", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"todo"}, Value: jsCtor("app.js:4", "Todo"), Decl: true},
			nir.Return{Value: jsCall("app.js:5", "todo", "get", jsStrLit("app.js:5", "title"))},
		}, Loc: "app.js:3"},
	)
	g, err := LowerTyped(prog, true, map[string]string{"AV.Object.extend": "AV.Object"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "todo", "get"); got != "AV.Object" {
		t.Fatalf("recv_type = %q, want AV.Object", got)
	}
}

// A module global any write builds from something else is not a global of one type, and a type
// withheld is the only honest answer: a sink reading this stamp to REJECT a receiver must
// never reject one on a type the variable may not have.
func TestLowerWithholdsAModuleGlobalTypeItsWritesDisagreeOn(t *testing.T) {
	prog := jsModule("app.js",
		nir.Assign{Targets: []string{"q"}, Value: jsCtor("app.js:2", "AV.Query"), Decl: true},
		nir.Assign{Targets: []string{"q"}, Value: nir.Name{ID: "elsewhere", Loc: "app.js:3"}},
		nir.ExprStmt{Value: jsCall("app.js:4", "q", "find")},
	)
	g, err := LowerTyped(prog, true, map[string]string{"AV.Query": "AV.Query"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "q", "find"); got != "" {
		t.Fatalf("recv_type = %q, want empty: the variable is also written from a value no constructor names", got)
	}
}

// A declaration inside a body is that body's binding, not a write to the module's variable:
// shadowing the global with a parameter leaves the call on the parameter's own node, which
// carries nothing about the global it happens to be named after.
func TestLowerLeavesAParameterThatShadowsAModuleGlobalOnItsOwnNode(t *testing.T) {
	prog := jsModule("app.js",
		nir.Assign{Targets: []string{"q"}, Value: jsCtor("app.js:2", "AV.Query"), Decl: true},
		nir.FuncDef{Name: "read", Params: []string{"q"}, Body: []nir.Stmt{
			nir.Return{Value: jsCall("app.js:4", "q", "find")},
		}, Loc: "app.js:3"},
	)
	g, err := LowerTyped(prog, true, map[string]string{"AV.Query": "AV.Query"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if got := recvTypeOf(t, g, "q", "find"); got != "" {
		t.Fatalf("recv_type = %q, want empty: the parameter q is not the module's q", got)
	}
}

// A module global is the file's, not the program's: two files binding the same name to
// different constructions must not read each other's type.
func TestLowerKeepsOneModuleGlobalTypePerFile(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{Key: "a.js", File: "a.js", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"q"}, Value: jsCtor("a.js:2", "AV.Query"), Decl: true},
			nir.ExprStmt{Value: jsCall("a.js:3", "q", "find")},
		}},
		{Key: "b.js", File: "b.js", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"q"}, Value: jsCtor("b.js:2", "Other.Kind"), Decl: true},
			nir.ExprStmt{Value: jsCall("b.js:3", "q", "find")},
		}},
	}}
	g, err := LowerTyped(prog, true, map[string]string{"AV.Query": "AV.Query", "Other.Kind": "Other.Kind"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a.js:3": "AV.Query", "b.js:3": "Other.Kind"}
	seen := map[string]string{}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Prop("callee_path") == "q.find" {
			seen[n.Prop("loc")] = n.Prop("recv_type")
		}
	}
	for loc, typ := range want {
		if seen[loc] != typ {
			t.Fatalf("%s: recv_type = %q, want %q (all: %v)", loc, seen[loc], typ, seen)
		}
	}
}

// A `.mts`/`.cts` file is a TypeScript ES module, and the JavaScript frontend claims it —
// CVE-2026-25931 lives in packages/_server/src/config/documentSettings.mts. Being claimed is
// not enough: the module has to lower as the JS-family module it is, so its top-level
// bindings are the module's globals — the one slot a function writing the name and a function
// reading it meet on. Lowered as a file outside the JS module family, `load`'s write and
// `use`'s read become unrelated nodes and the taint between them stops at module scope,
// which is how a claimed file answers a binding for the wrong reason.
func TestLowerFlowsThroughAModuleLevelBindingInATypeScriptESModule(t *testing.T) {
	for _, file := range []string{"app.mts", "app.cts"} {
		prog := jsModule(file,
			nir.Assign{Targets: []string{"current"}, Value: jsStrLit(file+":1", "seed"), Decl: true},
			// `current = u` inside a function: the write must land on the module's slot,
			// not on a node private to `load`.
			nir.FuncDef{Name: "load", Params: []string{"u"}, Loc: file + ":2", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"current"}, Value: nir.Name{ID: "u", Loc: file + ":3"}},
			}},
			nir.FuncDef{Name: "use", Loc: file + ":5", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: file + ":6"},
					Args:   []nir.Expr{nir.Name{ID: "current", Loc: file + ":6"}},
					Path:   "sink", Method: "sink", Loc: file + ":6",
				}},
			}},
		)
		g, err := LowerTyped(prog, true, nil)
		if err != nil {
			t.Fatalf("%s: lower: %v", file, err)
		}
		src := findNodeID(t, g, "code.Param", "name", "u", "func", "load")
		reach, err := usg.BFS(g, src, "FLOWS", 40)
		if err != nil {
			t.Fatalf("%s: bfs: %v", file, err)
		}
		if !reach[findNodeID(t, g, "code.Call", "callee_path", "sink")] {
			t.Errorf("%s: what `load` writes to the module-level `current` does not reach the sink in `use`; a TypeScript ES module resolves its top-level bindings through the module global the .ts/.mjs forms do", file)
		}
	}
}

// The tech a module answers decides which other modules' declarations its calls may resolve
// to, and an answer of "" is compatible with every language — a .mts module would take a
// candidate from a Java or Python module of the same name. A TypeScript ES module answers
// typescript, so it stays inside the JS family with the .ts/.mjs siblings it lowers beside.
func TestTypeScriptESModulesResolveInsideTheJSFamily(t *testing.T) {
	own := moduleTech("packages/_server/src/config/documentSettings.mts")
	if own != "typescript" {
		t.Fatalf("moduleTech(.mts) = %q, want typescript", own)
	}
	if moduleTech("documentSettings.cts") != "typescript" {
		t.Fatalf("moduleTech(.cts) = %q, want typescript", moduleTech("documentSettings.cts"))
	}
	for _, other := range []string{"loader.ts", "loader.tsx", "loader.js", "loader.mjs", "loader.cjs"} {
		if !compatibleTech(own, moduleTech(other)) {
			t.Errorf("a .mts module cannot resolve a declaration in %s; the JS family is one family", other)
		}
	}
	for _, other := range []string{"Loader.java", "loader.py", "loader.rb"} {
		if compatibleTech(own, moduleTech(other)) {
			t.Errorf("a .mts module may resolve a declaration in %s; a TypeScript module is not compatible with another language's module", other)
		}
	}
}

package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// aliasProg builds the module shape a JS/TS frontend emits for
//
//	import { exec } from "node:child_process";
//	import { promisify } from "node:util";
//	<decls>
//	function handler(cmd) { <callee>(cmd); }
//
// with the callee written as a bare identifier.
func aliasProg(decls []nir.Stmt, callee string, extra ...nir.Stmt) nir.Program {
	body := append([]nir.Stmt{}, decls...)
	body = append(body, extra...)
	body = append(body, nir.FuncDef{Name: "handler", Params: []string{"cmd"}, Body: []nir.Stmt{
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: callee, Loc: "app.ts:9"},
			Args:   []nir.Expr{nir.Name{ID: "cmd", Loc: "app.ts:9"}},
			Path:   callee, Method: callee, Loc: "app.ts:9",
		}},
	}, Loc: "app.ts:8"})
	return nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.ts",
		Imports: []nir.Import{
			{Local: "exec", Module: "node:child_process", Symbol: "exec"},
			{Local: "promisify", Module: "node:util", Symbol: "promisify"},
			{Local: "cp", Module: "child_process", IsModule: true},
		},
		Body: body,
	}}}
}

func decl(target string, value nir.Expr) nir.Stmt {
	return nir.Assign{Targets: []string{target}, Value: value, Decl: true}
}

func name(id string) nir.Expr { return nir.Name{ID: id, Loc: "app.ts:4"} }

func attr(base, a string) nir.Expr {
	return nir.Attr{Base: nir.Name{ID: base, Loc: "app.ts:4"}, Attr: a, Path: base + "." + a, Loc: "app.ts:4"}
}

func call1(path string, arg nir.Expr) nir.Expr {
	return nir.Call{Callee: nir.Name{ID: path, Loc: "app.ts:4"}, Args: []nir.Expr{arg},
		Path: path, Method: path, Loc: "app.ts:4"}
}

// calleePathAt returns the callee path of the lowered call at loc.
func calleePathAt(t *testing.T, prog nir.Program, loc string) string {
	t.Helper()
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("loc") == loc {
			return n.Prop("callee_path")
		}
	}
	t.Fatalf("no code.Call lowered at %s", loc)
	return ""
}

// The gap: a call through a name a const initialiser bound carried only that
// name, so no binding naming the library API it stands for could match it.
func TestCalleeAliasResolvesThroughConstInitialiser(t *testing.T) {
	cases := []struct {
		name  string
		decls []nir.Stmt
		call  string
		want  string
	}{
		{
			// const runIt = exec;
			name:  "direct alias of an imported symbol",
			decls: []nir.Stmt{decl("runIt", name("exec"))},
			call:  "runIt",
			want:  "node:child_process.exec",
		},
		{
			// const execAsync = promisify(exec);   -- CVE-2026-8112's shape
			name:  "one-argument wrapping call over an imported symbol",
			decls: []nir.Stmt{decl("execAsync", call1("promisify", name("exec")))},
			call:  "execAsync",
			want:  "node:child_process.exec",
		},
		{
			// const direct2 = cp.exec;
			name:  "member of an imported module",
			decls: []nir.Stmt{decl("direct2", attr("cp", "exec"))},
			call:  "direct2",
			want:  "cp.exec", // exactly what a direct `cp.exec(cmd)` call carries
		},
		{
			// const a = exec; const b = a;
			name:  "alias chain",
			decls: []nir.Stmt{decl("a", name("exec")), decl("b", name("a"))},
			call:  "b",
			want:  "node:child_process.exec",
		},
		{
			// const execAsync = promisify(cp.exec);
			name:  "wrapping call over a member of an imported module",
			decls: []nir.Stmt{decl("execAsync", call1("promisify", attr("cp", "exec")))},
			call:  "execAsync",
			want:  "cp.exec",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := calleePathAt(t, aliasProg(c.decls, c.call), "app.ts:9"); got != c.want {
				t.Fatalf("callee_path = %q, want %q", got, c.want)
			}
		})
	}
}

// The alias is only followed where the initialiser really names a library
// callable; everything else keeps the call exactly as it was lowered before.
func TestCalleeAliasLeavesEverythingElseAlone(t *testing.T) {
	localMakeSafe := nir.FuncDef{Name: "makeSafe", Params: []string{"fn"}, Body: []nir.Stmt{
		nir.Return{Value: nir.Name{ID: "fn", Loc: "app.ts:2"}},
	}, Loc: "app.ts:1"}

	cases := []struct {
		name  string
		decls []nir.Stmt
		extra []nir.Stmt
		call  string
		want  string
	}{
		{
			// A wrapper the scan can see into is the interprocedural resolver's
			// question: `makeSafe` may escape its argument before calling it.
			name:  "wrapper defined in the scanned program",
			decls: []nir.Stmt{decl("safeExec", call1("makeSafe", name("exec")))},
			extra: []nir.Stmt{localMakeSafe},
			call:  "safeExec",
			want:  "safeExec",
		},
		{
			// createHandler(config) computes a value; config is not a library
			// callable, so the result does not stand for one.
			name:  "wrapped argument is not an imported callable",
			decls: []nir.Stmt{decl("handlerFn", call1("createHandler", name("config")))},
			call:  "handlerFn",
			want:  "handlerFn",
		},
		{
			name:  "more than one argument is a value being computed",
			decls: []nir.Stmt{decl("bound", nir.Call{Callee: nir.Name{ID: "partial"}, Args: []nir.Expr{name("exec"), name("cmd")}, Path: "partial", Method: "partial"})},
			call:  "bound",
			want:  "bound",
		},
		{
			name:  "no arguments at all",
			decls: []nir.Stmt{decl("app", nir.Call{Callee: nir.Name{ID: "express"}, Path: "express", Method: "express"})},
			call:  "app",
			want:  "app",
		},
		{
			name:  "initialiser is a literal, not a callable",
			decls: []nir.Stmt{decl("mode", nir.Const{Loc: "app.ts:4", Value: "exec"})},
			call:  "mode",
			want:  "mode",
		},
		{
			// let runIt = exec; runIt = spawn;  -- the name stands for neither.
			name: "rebound at module level",
			decls: []nir.Stmt{
				decl("runIt", name("exec")),
				nir.Assign{Targets: []string{"runIt"}, Value: name("spawn")},
			},
			call: "runIt",
			want: "runIt",
		},
		{
			// An assignment that is not a declaration binds nothing stable.
			name:  "assignment without a declaration",
			decls: []nir.Stmt{nir.Assign{Targets: []string{"runIt"}, Value: name("exec")}},
			call:  "runIt",
			want:  "runIt",
		},
		{
			// const { StringPrototypeSplit, ArrayPrototypeSome } = primordials;
			// lowers to one declaration per name, all of `primordials`. The
			// object is not imported, so none of them is read as an alias.
			name: "destructured from an object the module did not import",
			decls: []nir.Stmt{
				decl("StringPrototypeSplit", nir.Name{ID: "primordials", Loc: "app.ts:4"}),
				decl("ArrayPrototypeSome", nir.Name{ID: "primordials", Loc: "app.ts:4"}),
			},
			call: "StringPrototypeSplit",
			want: "StringPrototypeSplit",
		},
		{
			// const { execFile, spawn } = cp; -- destructuring an imported
			// module, told apart by the initialiser the two names share.
			name: "destructured from an imported module",
			decls: []nir.Stmt{
				decl("execFile", nir.Name{ID: "cp", Loc: "app.ts:4"}),
				decl("spawn", nir.Name{ID: "cp", Loc: "app.ts:4"}),
			},
			call: "execFile",
			want: "execFile",
		},
		{
			// const { execFile } = cp; -- one property, so there is no second
			// binding to tell it apart by. A bare binding of an imported module
			// is read as the destructure it usually is, not as an alias.
			name:  "single-property destructure of an imported module",
			decls: []nir.Stmt{decl("execFile", nir.Name{ID: "cp", Loc: "app.ts:4"})},
			call:  "execFile",
			want:  "execFile",
		},
		{
			// `const helper = localHelper` names nothing the module imported, so
			// there is no library API for the call to carry.
			name:  "bound to a name the module did not import",
			decls: []nir.Stmt{decl("helper", name("localHelper"))},
			call:  "helper",
			want:  "helper",
		},
		{
			// `const cp = require("child_process")` is recorded as an import AND
			// as a top-level declaration; the import wins, as it always has.
			name:  "an import of the same name shadows the declaration",
			decls: []nir.Stmt{decl("cp", call1("require", nir.Const{Loc: "app.ts:4", Value: "child_process"}))},
			call:  "cp",
			want:  "child_process",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := calleePathAt(t, aliasProg(c.decls, c.call, c.extra...), "app.ts:9"); got != c.want {
				t.Fatalf("callee_path = %q, want %q", got, c.want)
			}
		})
	}
}

// A cyclic chain terminates rather than spinning.
func TestCalleeAliasCycleTerminates(t *testing.T) {
	prog := aliasProg([]nir.Stmt{decl("a", name("b")), decl("b", name("a"))}, "a")
	if got := calleePathAt(t, prog, "app.ts:9"); got != "a" && got != "b" {
		t.Fatalf("callee_path = %q, want the local name", got)
	}
}

// The resolved path is also what the receiver package is read from, so a
// binding gated on the package sees the call as being on that package -- as it
// does for the direct `cp.exec(cmd)` this alias stands for.
func TestCalleeAliasCarriesReceiverPackage(t *testing.T) {
	prog := aliasProg([]nir.Stmt{decl("direct2", attr("cp", "exec"))}, "direct2")
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("loc") == "app.ts:9" {
			if got := n.Prop("recv_package"); got != "child_process" {
				t.Fatalf("recv_package = %q, want %q", got, "child_process")
			}
			return
		}
	}
	t.Fatal("no code.Call lowered at app.ts:9")
}

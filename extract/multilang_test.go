package extract_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/findings"
)

// attrRead models `<base>.<attr>` (e.g. JS `req.body`) — one labelable node.
func attrRead(base, attr, loc string) nir.Attr {
	return nir.Attr{Base: nm(base, loc), Attr: attr, Path: base + "." + attr, Loc: loc}
}

// subRead models `<base>[...]` (e.g. Ruby `params[:id]`) — one labelable node.
func subRead(base, loc string) nir.Index {
	return nir.Index{Base: nm(base, loc), Path: base, Loc: loc}
}

func thru(e nir.Expr) nir.Thru { return nir.Thru{Inner: e} }

// langSpec is one framework's idiom: how it reads request input and which
// receiver/method is its raw-SQL sink, plus its adapter set.
type langSpec struct {
	name               string
	routesFile, dbFile string
	read               func(loc string) nir.Expr
	sinkRecv, sinkMeth string
	ads                []adapters.Adapter
}

// buildSQLiProgram builds an interprocedural routes→db program. Vulnerable: the
// tainted value is concatenated into the query (arg0). Parameterized: arg0 is a
// constant query and the value goes to the params argument (arg1), which is not
// a sink — so the SAME rule yields zero with no sanitizer label.
func buildSQLiProgram(l langSpec, vulnerable bool) nir.Program {
	var sinkBody []nir.Stmt
	if vulnerable {
		sinkBody = []nir.Stmt{exprStmt(methodCall(l.sinkRecv, l.sinkMeth, l.dbFile+":2",
			concat(cst(l.dbFile+":2"), nm("value", l.dbFile+":2"))))}
	} else {
		sinkBody = []nir.Stmt{exprStmt(methodCall(l.sinkRecv, l.sinkMeth, l.dbFile+":2",
			cst(l.dbFile+":2"), nir.Seq{Parts: []nir.Expr{nm("value", l.dbFile+":2")}, Loc: l.dbFile + ":2"}))}
	}
	db := nir.Module{Key: "db", File: l.dbFile, Body: []nir.Stmt{
		nir.FuncDef{Name: "run_query", Params: []string{"value"}, Loc: l.dbFile + ":1", Body: sinkBody},
	}}
	routes := nir.Module{Key: "routes", File: l.routesFile,
		Imports: []nir.Import{{Local: "db", Module: "db", IsModule: true}},
		Body: []nir.Stmt{nir.FuncDef{Name: "handler", Loc: l.routesFile + ":1", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"u1"}, Value: l.read(l.routesFile + ":2")},
			nir.Assign{Targets: []string{"u2"}, Value: l.read(l.routesFile + ":3")},
			exprStmt(methodCall("db", "run_query", l.routesFile+":4", nm("u1", l.routesFile+":4"))),
			exprStmt(methodCall("db", "run_query", l.routesFile+":5", nm("u2", l.routesFile+":5"))),
		}}}}
	return nir.Program{Modules: []nir.Module{routes, db}}
}

func crossesFile(fs []*findings.Finding) bool {
	for _, f := range fs {
		if strings.Split(f.Bindings[0].Loc, ":")[0] != strings.Split(f.Bindings[1].Loc, ":")[0] {
			return true
		}
	}
	return false
}

// Mirrors poc/cases/case_15_multilang.py — ONE rule + ONE ontology over THREE
// frontends (Python/Flask, JavaScript/Express, Ruby/Rails). Only the per-language
// adapters and input/sink idioms differ; the compiled SQLi rule is unchanged.
// Each: vulnerable fixture → interprocedural cross-file findings; parameterized
// fixture → zero.
func TestCrossLanguageOneRule(t *testing.T) {
	langs := []langSpec{
		{"Python", "routes.py", "db.py",
			func(loc string) nir.Expr { return httpRead("form", loc) },
			"cursor", "execute", frontend.PythonAdapters()},
		{"JavaScript", "routes.js", "db.js",
			func(loc string) nir.Expr { return attrRead("req", "body", loc) },
			"conn", "query", frontend.JsAdapters()},
		{"Ruby", "routes.rb", "db.rb",
			func(loc string) nir.Expr { return subRead("params", loc) },
			"connection", "execute", frontend.RubyAdapters()},
	}
	for _, l := range langs {
		gBad, err := lowering.Lower(buildSQLiProgram(l, true), true)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := adapters.Apply(gBad, l.ads, nil); err != nil {
			t.Fatal(err)
		}
		bad := runRule(t, sqliRule, gBad)
		// the routes share one DB-API sink; findings dedup to one per sink, so the
		// cross-file SQLi is a single finding (not one per source route).
		if len(bad) != 1 {
			t.Fatalf("%s: expected 1 deduped interprocedural SQLi finding, got %d", l.name, len(bad))
		}
		if !crossesFile(bad) {
			t.Fatalf("%s: the finding should cross the file boundary", l.name)
		}

		gGood, err := lowering.Lower(buildSQLiProgram(l, false), true)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := adapters.Apply(gGood, l.ads, nil); err != nil {
			t.Fatal(err)
		}
		if good := runRule(t, sqliRule, gGood); len(good) != 0 {
			t.Fatalf("%s: parameterized fixture should be clean, got %d", l.name, len(good))
		}
	}
}

// signature is the sorted set of source->sink location pairs for a graph's SQLi
// findings — the comparable "finding fingerprint" case 17 asserts is parser-
// independent.
func signature(t *testing.T, prog nir.Program) []string {
	t.Helper()
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
		t.Fatal(err)
	}
	fs := runRule(t, sqliRule, g)
	var sig []string
	for _, f := range fs {
		sig = append(sig, f.Bindings[0].Loc+"->"+f.Bindings[1].Loc)
	}
	sort.Strings(sig)
	return sig
}

// astFrontend is the compact NIR a CPython-ast-style frontend would emit.
func astFrontend() nir.Program {
	db := nir.Module{Key: "db", File: "db.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "run_query", Params: []string{"value"}, Loc: "db.py:1", Body: []nir.Stmt{
			exprStmt(methodCall("cursor", "execute", "db.py:2",
				concat(cst("db.py:2"), nm("value", "db.py:2")))),
		}},
	}}
	routes := nir.Module{Key: "routes", File: "routes.py",
		Imports: []nir.Import{{Local: "db", Module: "db", IsModule: true}},
		Body: []nir.Stmt{nir.FuncDef{Name: "login", Loc: "routes.py:1", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"u"}, Value: httpRead("form", "routes.py:2")},
			exprStmt(methodCall("db", "run_query", "routes.py:3", nm("u", "routes.py:3"))),
		}}}}
	return nir.Program{Modules: []nir.Module{routes, db}}
}

// treeSitterFrontend is the SAME program with incidental structural differences
// a tree-sitter (CST) frontend would carry — extra Thru wrappers and a temp var
// for the query — but the SAME source/sink locations. It must lower to identical
// findings.
func treeSitterFrontend() nir.Program {
	db := nir.Module{Key: "db", File: "db.py", Body: []nir.Stmt{
		nir.FuncDef{Name: "run_query", Params: []string{"value"}, Loc: "db.py:1", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"q"}, Value: concat(cst("db.py:2"), thru(nm("value", "db.py:2")))},
			exprStmt(methodCall("cursor", "execute", "db.py:2", thru(nm("q", "db.py:2")))),
		}},
	}}
	routes := nir.Module{Key: "routes", File: "routes.py",
		Imports: []nir.Import{{Local: "db", Module: "db", IsModule: true}},
		Body: []nir.Stmt{nir.FuncDef{Name: "login", Loc: "routes.py:1", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"raw"}, Value: httpRead("form", "routes.py:2")},
			nir.Assign{Targets: []string{"u"}, Value: thru(nm("raw", "routes.py:2"))},
			exprStmt(methodCall("db", "run_query", "routes.py:3", thru(nm("u", "routes.py:3")))),
		}}}}
	return nir.Program{Modules: []nir.Module{routes, db}}
}

// Mirrors poc/cases/case_17_parser_swap.py — two different "parsers" (a compact
// ast-style frontend and a verbose tree-sitter/CST-style frontend) translate the
// same code into NIR that lowers, through the SAME engine and rule, to IDENTICAL
// findings. The parser is swappable; resolution and rules are untouched.
func TestParserSwapIdenticalFindings(t *testing.T) {
	astSig := signature(t, astFrontend())
	tsSig := signature(t, treeSitterFrontend())
	if len(astSig) == 0 {
		t.Fatal("ast frontend produced no findings")
	}
	if strings.Join(astSig, "|") != strings.Join(tsSig, "|") {
		t.Fatalf("parsers disagree:\n ast=%v\n ts =%v", astSig, tsSig)
	}
}

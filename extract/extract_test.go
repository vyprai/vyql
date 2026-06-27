package extract_test

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

// --- tiny NIR builders (a frontend's output, hand-constructed) -----------

func nm(id, loc string) nir.Name       { return nir.Name{ID: id, Loc: loc} }
func cst(loc string) nir.Const         { return nir.Const{Loc: loc} }
func ret(e nir.Expr) nir.Return        { return nir.Return{Value: e} }
func exprStmt(e nir.Expr) nir.ExprStmt { return nir.ExprStmt{Value: e} }

// httpRead models a framework input read `request.<attr>` (one labelable node).
func httpRead(attr, loc string) nir.Attr {
	return nir.Attr{Base: nm("request", loc), Attr: attr, Path: "request." + attr, Loc: loc}
}

// methodCall models `<recv>.<method>(args...)` with a dotted callee path.
func methodCall(recv, method, loc string, args ...nir.Expr) nir.Call {
	path := recv + "." + method
	return nir.Call{
		Callee: nir.Attr{Base: nm(recv, loc), Attr: method, Path: path, Loc: loc},
		Args:   args, Path: path, Method: method, Loc: loc,
	}
}

// concat models a taint-propagating string build.
func concat(parts ...nir.Expr) nir.Format { return nir.Format{Parts: parts, Loc: "?"} }

const sqliRule = `
module vypr.injection;
rule Sql {
  meta { id: "VYQL-INJ-001", severity: high }
  taint code.HttpInput -> code.SqlExecution as sink
  unless sink.path coveredBy core.SqlParameterization
}
`

// runRule compiles+evaluates a single-rule program over the store.
func runRule(t *testing.T, src string, g usg.Store) []*findings.Finding {
	t.Helper()
	onto := ontology.Seed()
	decls, err := parseV2DefinitionsForTest(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := engine.CompileRules(decls, onto)
	if len(errs) != 0 {
		t.Fatalf("compile: %v", errs)
	}
	fs, err := engine.New(onto, g).Evaluate(compiled[0])
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return fs
}

// libModule builds a one-function library module. If sink is true the function
// body is an execute() DB-API sink; otherwise it is a harmless len() call.
func libModule(key, file string, sink bool) nir.Module {
	var body []nir.Stmt
	if sink {
		body = []nir.Stmt{exprStmt(methodCall("cursor", "execute", file+":2",
			concat(cst(file+":2"), nm("value", file+":2"))))}
	} else {
		body = []nir.Stmt{ret(nir.Call{Callee: nm("len", file+":2"), Args: []nir.Expr{nm("value", file+":2")},
			Path: "len", Method: "len", Loc: file + ":2"})}
	}
	return nir.Module{Key: key, File: file,
		Body: []nir.Stmt{nir.FuncDef{Name: "query", Params: []string{"value"}, Loc: file + ":1", Body: body}}}
}

// appCallingLib builds `import <lib>; def handler(): u = request.args[..]; <lib>.query(u)`.
func appCallingLib(key, file, lib string) nir.Module {
	return nir.Module{Key: key, File: file,
		Imports: []nir.Import{{Local: lib, Module: lib, IsModule: true}},
		Body: []nir.Stmt{nir.FuncDef{Name: "handler", Loc: file + ":2", Body: []nir.Stmt{
			nir.Assign{Targets: []string{"u"}, Value: httpRead("args", file+":3")},
			exprStmt(methodCall(lib, "query", file+":4", nm("u", file+":4"))),
		}}}}
}

// Mirrors poc/cases/case_16_resolution.py — import/type resolution removes the
// name-collision false positive. safe_lib.query and vuln_lib.query share a short
// name; only one is a sink. Name-based resolution over-connects the safe and
// vulnerable callers to the shared sink; import resolution keeps only the true
// positive (app_vuln). Findings are deduped by sink, so the unresolved run's
// representative source can be either caller depending on traversal order.
func TestImportResolutionRemovesNameCollisionFP(t *testing.T) {
	mods := []nir.Module{
		libModule("safe_lib", "safe_lib.py", false),
		libModule("vuln_lib", "vuln_lib.py", true),
		appCallingLib("app_safe", "app_safe.py", "safe_lib"),
		appCallingLib("app_vuln", "app_vuln.py", "vuln_lib"),
	}
	prog := nir.Program{Modules: mods}

	run := func(resolve bool) (files []string, count int) {
		g, err := lowering.Lower(prog, resolve)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
			t.Fatal(err)
		}
		fs := runRule(t, sqliRule, g)
		count = len(fs)
		seen := map[string]bool{}
		for _, f := range fs {
			file := strings.Split(f.Bindings[0].Loc, ":")[0]
			if !seen[file] {
				seen[file] = true
				files = append(files, file)
			}
		}
		return files, count
	}

	nameBased, nbCount := run(false)
	resolved, rvCount := run(true)

	// Findings are deduped to one per vulnerable sink, so the shared vuln_lib.query
	// sink yields exactly one finding either way. In name-based mode the representative
	// source is nondeterministic because both callers can over-connect to the sink;
	// import resolution must remove that ambiguity and pin the true caller.
	if nbCount != 1 {
		t.Fatalf("name-based should produce 1 finding (the shared sink), got %d", nbCount)
	}
	if rvCount != 1 {
		t.Fatalf("import-resolved should produce exactly 1 finding, got %d", rvCount)
	}
	if len(nameBased) != 1 || (nameBased[0] != "app_safe.py" && nameBased[0] != "app_vuln.py") {
		t.Fatalf("name-based should choose one colliding caller as representative, got %v", nameBased)
	}
	if len(resolved) != 1 || resolved[0] != "app_vuln.py" {
		t.Fatalf("import-resolved should attribute the witness to app_vuln.py, got %v", resolved)
	}
}

const scaGated = `
module vypr.sca;
rule ReachableVulnerableDependency {
  meta { id: "VYQL-SCA-002", severity: high }
  issue sbom.VulnerableDependency as p
  where has(p, sbom.ReachableSymbol)
}
`
const scaPlain = `
module vypr.sca;
rule VulnerableDependency {
  meta { id: "VYQL-SCA-001", severity: medium }
  issue sbom.VulnerableDependency as p
}
`

// Mirrors poc/cases/case_18_sca_dependency.py — decoupled SBOM path with
// reachability-gated SCA: requests is vulnerable AND called (finding); leftpad
// is vulnerable but never called (suppressed); flask is called but not
// vulnerable. The gate is a cross-domain join over the same graph.
func TestReachabilityGatedSCA(t *testing.T) {
	// code: `import requests; def f(): requests.get(u)` — only `requests` is called
	app := nir.Module{Key: "app", File: "app.py",
		Imports: []nir.Import{{Local: "requests", Module: "requests", IsModule: true}},
		Body: []nir.Stmt{nir.FuncDef{Name: "f", Loc: "app.py:2", Body: []nir.Stmt{
			exprStmt(methodCall("requests", "get", "app.py:3", cst("app.py:3"))),
		}}}}
	g, err := lowering.Lower(nir.Program{Modules: []nir.Module{app}}, true)
	if err != nil {
		t.Fatal(err)
	}

	deps := sca.ParseRequirements("requests==2.19.0\nleftpad==1.0.0\nflask==2.0.0\n# comment\n")
	if len(deps) != 3 {
		t.Fatalf("manifest should parse 3 deps, got %v", deps)
	}
	advisories := map[sca.PkgKey]string{
		{Name: "requests", Version: "2.19.0"}: "CVE-2018-18074",
		{Name: "leftpad", Version: "1.0.0"}:   "GHSA-leftpad-xxxx",
	}
	if err := sca.BuildSBOM(g, "pypi", deps, ""); err != nil {
		t.Fatal(err)
	}
	if err := sca.MarkVulnerable(g, advisories); err != nil {
		t.Fatal(err)
	}
	if err := sca.LinkReachability(g); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.AutoAdapters(), nil); err != nil {
		t.Fatal(err)
	}

	vuln, _ := g.NodesWithConcept("sbom.VulnerableDependency")
	if len(vuln) != 2 {
		t.Fatalf("2 vulnerable deps expected (requests, leftpad), got %d", len(vuln))
	}
	reachable, _ := g.NodesWithConcept("sbom.ReachableSymbol")
	reachNames := map[string]bool{}
	for _, id := range reachable {
		n, _, _ := g.GetNode(id)
		reachNames[n.Prop("name")] = true
	}
	if !reachNames["requests"] || reachNames["leftpad"] {
		t.Fatalf("requests reachable, leftpad not; got %v", reachNames)
	}

	gated := runRule(t, scaGated, g)
	if len(gated) != 1 || !strings.HasSuffix(gated[0].Bindings[0].NodeID, "requests@2.19.0") {
		t.Fatalf("gated SCA should flag only requests, got %v", gated)
	}
	plain := runRule(t, scaPlain, g)
	if len(plain) != 2 {
		t.Fatalf("plain SCA should flag both vulnerable deps, got %d", len(plain))
	}
}

const scaExploitable = `
module vypr.sca;
rule ExploitableVulnerableDependency {
  meta { id: "VYQL-SCA-003", severity: high }
  taint code.HttpInput -> code.Deserialization
}
`

// Mirrors poc/cases/case_19_vuln_entrypoint.py — vulnerable-library entrypoint
// projected to a typed sink, the existing taint rule deciding EXPLOITABILITY.
// Funnel: present (1) ⊇ reachable (1) ⊇ exploitable (1: only the tainted site).
func TestVulnerableEntrypointExploitabilityFunnel(t *testing.T) {
	// app.py: yaml.load on tainted input, on a constant, and yaml.safe_load on input
	app := nir.Module{Key: "app", File: "app.py",
		Imports: []nir.Import{{Local: "yaml", Module: "yaml", IsModule: true}},
		Body: []nir.Stmt{
			nir.FuncDef{Name: "load_user_config", Loc: "app.py:4", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"data"}, Value: methodCall("request", "get_json", "app.py:5")},
				ret(methodCall("yaml", "load", "app.py:6", nm("data", "app.py:6"))),
			}},
			nir.FuncDef{Name: "load_static", Loc: "app.py:8", Body: []nir.Stmt{
				ret(methodCall("yaml", "load", "app.py:9", cst("app.py:9"))),
			}},
			nir.FuncDef{Name: "load_safe", Loc: "app.py:11", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"data"}, Value: methodCall("request", "get_json", "app.py:12")},
				ret(methodCall("yaml", "safe_load", "app.py:13", nm("data", "app.py:13"))),
			}},
		}}
	g, err := lowering.Lower(nir.Program{Modules: []nir.Module{app}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
		t.Fatal(err)
	}
	if err := sca.BuildSBOM(g, "pypi", []sca.Dep{{Name: "pyyaml", Version: "3.12"}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := sca.MarkVulnerable(g,
		map[sca.PkgKey]string{{Name: "pyyaml", Version: "3.12"}: "CVE-2017-18342"}); err != nil {
		t.Fatal(err)
	}
	if err := sca.ProjectEntrypoints(g, []sca.VulnerableEntrypoint{{
		Advisory: "CVE-2017-18342", Package: "pyyaml", Version: "3.12",
		Symbol: "yaml.load", VulnClass: "code.Deserialization", TaintedArg: 0, CWE: []string{"CWE_502"},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.AutoAdapters(), nil); err != nil {
		t.Fatal(err)
	}

	// advisory labeled both yaml.load sites (user_config + static), not safe_load
	sinks, _ := g.NodesWithConcept("code.Deserialization")
	if len(sinks) != 2 {
		t.Fatalf("advisory should label both yaml.load sites, got %d", len(sinks))
	}

	present := runRule(t, scaPlain, g)
	reachable := runRule(t, scaGated, g)
	exploitable := runRule(t, scaExploitable, g)
	if len(present) != 1 {
		t.Fatalf("present: pyyaml should be flagged, got %d", len(present))
	}
	if len(reachable) != 1 {
		t.Fatalf("reachable: yaml.load called, got %d", len(reachable))
	}
	if len(exploitable) != 1 {
		t.Fatalf("exploitable: exactly the tainted call site, got %d", len(exploitable))
	}
	// the exploitable finding sits at the tainted yaml.load(data) site (app.py:6)
	// and cites the CVE — load_static (constant arg) and load_safe (safe_load)
	// are correctly silent.
	sinkLoc := exploitable[0].Bindings[1].Loc
	if !strings.Contains(sinkLoc, "app.py:6") {
		t.Fatalf("exploitable finding should be at the yaml.load(data) site app.py:6, got %q", sinkLoc)
	}
	prov := exploitable[0].Bindings[1].LabelProvenance
	if !strings.Contains(prov, "CVE-2017-18342") {
		t.Fatalf("exploitable finding should cite the advisory, got %q", prov)
	}
}

// Exercises the type-map resolution tier (lowering.py §"Call resolution"):
// constructor type tracking + instance-method dispatch, and class-static
// dispatch via a symbol import. Both must resolve interprocedurally (routes.py →
// model.py). This was the resolution path the other extraction tests did not
// cover (they route through plain module-import calls).
func TestTypeMapResolution(t *testing.T) {
	sink := func(loc string) nir.Stmt {
		return exprStmt(methodCall("cursor", "execute", loc, concat(cst(loc), nm("value", loc))))
	}
	model := nir.Module{Key: "model", File: "model.py", Body: []nir.Stmt{
		nir.ClassDef{Name: "UserRepo", Loc: "model.py:1", Body: []nir.Stmt{
			nir.FuncDef{Name: "find", Params: []string{"value"}, Loc: "model.py:2", Body: []nir.Stmt{sink("model.py:3")}},
			nir.FuncDef{Name: "search", Params: []string{"value"}, Loc: "model.py:5", Body: []nir.Stmt{sink("model.py:6")}},
		}},
	}}
	routes := nir.Module{Key: "routes", File: "routes.py",
		Imports: []nir.Import{
			{Local: "model", Module: "model", IsModule: true},
			{Local: "UserRepo", Module: "model", Symbol: "UserRepo", IsModule: false},
		},
		Body: []nir.Stmt{nir.FuncDef{Name: "handler", Loc: "routes.py:1", Body: []nir.Stmt{
			// instance dispatch: repo = model.UserRepo(); repo.find(u1)
			nir.Assign{Targets: []string{"u1"}, Value: httpRead("form", "routes.py:2")},
			nir.Assign{Targets: []string{"repo"}, Value: nir.Call{
				Callee: nir.Attr{Base: nm("model", "routes.py:3"), Attr: "UserRepo", Path: "model.UserRepo", Loc: "routes.py:3"},
				Path:   "model.UserRepo", Method: "UserRepo", Loc: "routes.py:3"}},
			exprStmt(methodCall("repo", "find", "routes.py:4", nm("u1", "routes.py:4"))),
			// class-static dispatch: UserRepo.search(u2)
			nir.Assign{Targets: []string{"u2"}, Value: httpRead("args", "routes.py:5")},
			exprStmt(methodCall("UserRepo", "search", "routes.py:6", nm("u2", "routes.py:6"))),
		}}}}

	g, err := lowering.Lower(nir.Program{Modules: []nir.Module{routes, model}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
		t.Fatal(err)
	}
	fs := runRule(t, sqliRule, g)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings (instance + class-static dispatch), got %d", len(fs))
	}
	for _, f := range fs {
		if strings.Split(f.Bindings[0].Loc, ":")[0] != "routes.py" ||
			strings.Split(f.Bindings[1].Loc, ":")[0] != "model.py" {
			t.Fatalf("type-map dispatch should resolve routes.py -> model.py, got %s -> %s",
				f.Bindings[0].Loc, f.Bindings[1].Loc)
		}
	}
}

// dbQueryModule: db.py with `def run_query(value): sql = "..."+value; cursor.execute(sql)`.
func dbQueryModule() nir.Module {
	return nir.Module{
		Key: "db", File: "db.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "run_query", Params: []string{"value"}, Loc: "db.py:3", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"sql"}, Value: concat(cst("db.py:4"), nm("value", "db.py:4"))},
				exprStmt(methodCall("cursor", "execute", "db.py:5", nm("sql", "db.py:5"))),
			}},
		},
	}
}

// Mirrors poc/cases/case_14_real_extraction.py — interprocedural, cross-file
// SQLi: routes.py sources flow through to a db.py execute() sink. Built from NIR
// (a frontend's output) so this validates the lowering + resolution + adapter +
// rule pipeline exactly as the Python oracle does on real ASTs.
func TestInterproceduralCrossFileSQLi(t *testing.T) {
	routes := nir.Module{
		Key: "routes", File: "routes.py",
		Imports: []nir.Import{{Local: "db", Module: "db", IsModule: true}},
		Body: []nir.Stmt{
			nir.FuncDef{Name: "login", Loc: "routes.py:3", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"username"}, Value: httpRead("form", "routes.py:4")},
				nir.Assign{Targets: []string{"password"}, Value: httpRead("form", "routes.py:5")},
				exprStmt(methodCall("db", "run_query", "routes.py:6", nm("username", "routes.py:6"))),
				exprStmt(methodCall("db", "run_query", "routes.py:7", nm("password", "routes.py:7"))),
			}},
			nir.FuncDef{Name: "search", Loc: "routes.py:9", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"term"}, Value: httpRead("args", "routes.py:10")},
				exprStmt(methodCall("db", "run_query", "routes.py:11", nm("term", "routes.py:11"))),
			}},
		},
	}
	prog := nir.Program{Modules: []nir.Module{routes, dbQueryModule()}}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adapters.Apply(g, frontend.PythonAdapters(), nil); err != nil {
		t.Fatal(err)
	}

	// the real adapters labeled the framework inputs and the DB-API sink
	httpInputs, _ := g.NodesWithConcept("code.HttpInput")
	sqlSinks, _ := g.NodesWithConcept("code.SqlExecution")
	if len(httpInputs) != 3 {
		t.Fatalf("expected 3 HttpInput sources, got %d", len(httpInputs))
	}
	if len(sqlSinks) < 1 {
		t.Fatalf("expected the DB-API sink labeled, got %d", len(sqlSinks))
	}

	fs := runRule(t, sqliRule, g)
	// the three routes share one DB-API sink in db.py; findings dedup to one per sink,
	// so the cross-file SQLi surfaces as a single finding (not one per source route).
	if len(fs) != 1 {
		t.Fatalf("expected 1 deduped interprocedural SQLi finding, got %d", len(fs))
	}
	// the finding crosses the file boundary (routes.py -> db.py)
	for _, f := range fs {
		srcFile := strings.Split(f.Bindings[0].Loc, ":")[0]
		sinkFile := strings.Split(f.Bindings[1].Loc, ":")[0]
		if srcFile != "routes.py" || sinkFile != "db.py" {
			t.Fatalf("finding should cross routes.py -> db.py, got %s -> %s", srcFile, sinkFile)
		}
	}
}

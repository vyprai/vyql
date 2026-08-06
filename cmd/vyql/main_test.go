package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vyprai/vyql/internal/engine"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
)

func TestScanPathsNoSource(t *testing.T) {
	rules, _ := loadRules("")
	if _, _, _, err := scanPaths([]string{t.TempDir()}, rules); err == nil {
		t.Fatal("scanning a dir with no supported source should error")
	}
}

func TestCompiledRulesForCachesRulesBySource(t *testing.T) {
	compiledRulesCache = sync.Map{}
	rules := `
module rules.test;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
}
`
	first, err := compiledRulesFor(ruleSourcesFromText("rules/test.vyql", rules))
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	second, err := compiledRulesFor(ruleSourcesFromText("rules/test.vyql", rules))
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if len(first.compiled) != 1 || len(second.compiled) != 1 {
		t.Fatalf("compiled rule counts = %d, %d; want 1, 1", len(first.compiled), len(second.compiled))
	}
	if first.onto != second.onto || first.compiled[0] != second.compiled[0] {
		t.Fatalf("compiled rules were not reused from cache")
	}
}

func TestCompiledRulesForRejectsLegacyRuntimeSyntax(t *testing.T) {
	compiledRulesCache = sync.Map{}
	rules := `
module rules.test;
rule LegacyPresence {
  match code.DynamicCodeLoad as d
}
`
	if _, err := compiledRulesFor(ruleSourcesFromText("rules/test.vyql", rules)); err == nil {
		t.Fatalf("legacy compile succeeded, want v2 grammar rejection")
	}
}

func TestCompiledRulesForRunsV2CorpusValidation(t *testing.T) {
	compiledRulesCache = sync.Map{}
	rules := `
module rules.bad;
rule BadCoverageMode {
  issue code.XmlParserCreate as p
  unless p.endpoint coveredBy core.SqlParameterization
}
`
	if _, err := compiledRulesFor(ruleSourcesFromText("rules/test.vyql", rules)); err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("compile = %v, want v2 corpus coverage validation", err)
	}
}

func TestCompiledRulesForUsesGoBuiltInRuleVerbs(t *testing.T) {
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForRules(ruleSourcesFromText("rules/test.vyql", `
module rules.test;
rule SqlInjection {
  taint code.HttpInput -> code.SqlExecution
}
`)), lowerNonCoreV2DefinitionSource)
	if err != nil {
		t.Fatalf("ParseV2DefinitionSourcesSelected: %v", err)
	}
	for _, decl := range decls {
		m, ok := decl.(*parser.V2MechanicDecl)
		if ok && m.Kind == "ruleVerb" && m.Name == "taint" {
			t.Fatalf("built-in rule verb taint should not require a loaded v2 mechanic declaration")
		}
	}
}

func TestRuleActiveForProfileHonorsV2RequiredProfiles(t *testing.T) {
	rules := `
module rules.profiled;
rule WebOnly {
  issue code.LockAcquire as d
  require profile web
}
`
	compiled, err := compiledRulesFor(ruleSourcesFromText("rules/profiled.vyql", rules))
	if err != nil {
		t.Fatalf("compiledRulesFor: %v", err)
	}
	if len(compiled.compiled) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(compiled.compiled))
	}
	cr := compiled.compiled[0]
	if !ruleActiveForProfile(cr, "") {
		t.Fatal("empty profile should preserve direct helper behavior")
	}
	if !ruleActiveForProfile(cr, "web") {
		t.Fatal("web profile should activate web-required rule")
	}
	if ruleActiveForProfile(cr, "library") {
		t.Fatal("library profile should not activate web-required rule")
	}
}

func TestExtractAllSupportsJavaScriptModules(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "core.mjs")
	if err := os.WriteFile(src, []byte("export const answer = () => 42\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	_, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .mjs: %v", err)
	}
	if got := stats.files["javascript"]; got != 1 {
		t.Fatalf(".mjs should route through javascript frontend, got count %d stats=%v", got, stats.files)
	}
}

func TestExtractAllRoutesExtensionlessPythonShebangScripts(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "cloakserve")
	code := `#!/usr/bin/env python3
import asyncio
import os
import shutil

class ChromePool:
    def __init__(self, data_dir):
        self._data_dir = data_dir

    async def get_or_launch(self, seed):
        if seed is None:
            seed_key = "__default__"
        else:
            seed_key = seed
        user_data_dir = os.path.join(self._data_dir, seed_key)
        os.makedirs(user_data_dir, exist_ok=True)
        await asyncio.to_thread(shutil.rmtree, user_data_dir, True)
`
	if err := os.WriteFile(src, []byte(code), 0o755); err != nil {
		t.Fatalf("write extensionless python source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{dir})
	if err != nil {
		t.Fatalf("extractAll extensionless python: %v", err)
	}
	if got := stats.files["python"]; got != 1 {
		t.Fatalf("extensionless python shebang should route through python frontend, got count %d stats=%v", got, stats.files)
	}
	if !programHasContextToken(prog, "python_review:cloakserve_fingerprint_seed_path_traversal") {
		t.Fatalf("extensionless python shebang did not emit Cloakserve semantic context: %#v", prog.Modules)
	}
}

func programHasContextToken(prog nir.Program, want string) bool {
	for _, mod := range prog.Modules {
		if stmtsHaveContextToken(mod.Body, want) {
			return true
		}
	}
	return false
}

func stmtsHaveContextToken(stmts []nir.Stmt, want string) bool {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case nir.FuncDef:
			for _, tok := range s.ContextTokens {
				if tok == want {
					return true
				}
			}
			if stmtsHaveContextToken(s.Body, want) {
				return true
			}
		case nir.ClassDef:
			if stmtsHaveContextToken(s.Body, want) {
				return true
			}
		case nir.ExprStmt:
			if exprHasContextToken(s.Value, want) {
				return true
			}
		case nir.Assign:
			if exprHasContextToken(s.Value, want) {
				return true
			}
		}
	}
	return false
}

func exprHasContextToken(expr nir.Expr, want string) bool {
	switch e := expr.(type) {
	case nir.Call:
		for _, arg := range e.Args {
			if exprHasContextToken(arg, want) {
				return true
			}
		}
	case nir.Const:
		return e.Value == want
	case nir.Thru:
		return exprHasContextToken(e.Inner, want)
	}
	return false
}

func TestExtractAllSupportsVueSingleFileComponents(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Component.vue")
	if err := os.WriteFile(src, []byte("<script>\nexport default { mounted() { return 42 } }\n</script>\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .vue: %v", err)
	}
	if got := stats.files["javascript"]; got != 1 {
		t.Fatalf(".vue should route through javascript frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) != 1 || len(prog.Modules[0].Body) == 0 {
		t.Fatalf(".vue should extract script statements, got modules=%d body=%d", len(prog.Modules), len(prog.Modules[0].Body))
	}
}

func TestExtractAllSupportsHtmlInlineScripts(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "unit.html")
	if err := os.WriteFile(src, []byte("<html><body><script>\nconst q = location.search;\ndocument.body.innerHTML = q;\n</script></body></html>\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .html: %v", err)
	}
	if got := stats.files["javascript"]; got != 1 {
		t.Fatalf(".html should route through javascript frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) != 1 || len(prog.Modules[0].Body) == 0 {
		t.Fatalf(".html should extract inline script statements, got modules=%d body=%d", len(prog.Modules), len(prog.Modules[0].Body))
	}
}

func TestExtractAllIgnoresHtmlScriptsInsideComments(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "unit.html")
	if err := os.WriteFile(src, []byte("<!--<html><body><script>\ndocument.body.innerHTML = location.search;\n</script></body></html>-->\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll commented .html: %v", err)
	}
	if got := stats.files["javascript"]; got != 1 {
		t.Fatalf(".html should still be counted by javascript frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) != 0 {
		t.Fatalf("commented HTML script should not produce JavaScript modules, got %#v", prog.Modules)
	}
}

func TestExtractAllSupportsERBRubyIslands(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.html.erb")
	if err := os.WriteFile(src, []byte(`<p><%= raw t('.prompt', client_name: "<strong>#{ @pre_auth.client.name }</strong>") %></p>`+"\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .erb: %v", err)
	}
	if got := stats.files["ruby"]; got != 1 {
		t.Fatalf(".erb should route through ruby frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) == 0 || len(prog.Modules[0].Body) == 0 {
		t.Fatalf(".erb should extract embedded Ruby statements, got modules=%d", len(prog.Modules))
	}
	if !strings.Contains(prog.Modules[0].File, "#erb.rb") {
		t.Fatalf(".erb module should use ruby loc suffix for adapter routing, got %q", prog.Modules[0].File)
	}
}

func TestExtractAllSupportsPHPIncludes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "helpers.inc")
	if err := os.WriteFile(src, []byte("<?php function helper($p) { exec($p); }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .inc: %v", err)
	}
	if got := stats.files["php"]; got != 1 {
		t.Fatalf(".inc should route through php frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) != 1 || len(prog.Modules[0].Body) == 0 {
		t.Fatalf(".inc should extract php statements, got modules=%d body=%d", len(prog.Modules), len(prog.Modules[0].Body))
	}
}

func TestExtractAllSupportsDrupalPHPExtensions(t *testing.T) {
	dir := t.TempDir()
	for _, ext := range []string{".module", ".install", ".profile", ".theme", ".engine", ".test"} {
		src := filepath.Join(dir, "drupal"+ext)
		if err := os.WriteFile(src, []byte("<?php function helper($p) { echo $p; }\n"), 0o600); err != nil {
			t.Fatalf("write %s source: %v", ext, err)
		}
		prog, _, _, stats, err := extractAll([]string{src})
		if err != nil {
			t.Fatalf("extractAll %s: %v", ext, err)
		}
		if got := stats.files["php"]; got != 1 {
			t.Fatalf("%s should route through php frontend, got count %d stats=%v", ext, got, stats.files)
		}
		if len(prog.Modules) != 1 || len(prog.Modules[0].Body) == 0 {
			t.Fatalf("%s should extract php statements, got modules=%d body=%d", ext, len(prog.Modules), len(prog.Modules[0].Body))
		}
	}
}

func TestExtractAllSupportsPerlXSAsC(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "DBI.xs")
	if err := os.WriteFile(src, []byte("int xs_helper(void) { return 42; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	prog, _, _, stats, err := extractAll([]string{src})
	if err != nil {
		t.Fatalf("extractAll .xs: %v", err)
	}
	if got := stats.files["c"]; got != 1 {
		t.Fatalf(".xs should route through c frontend, got count %d stats=%v", got, stats.files)
	}
	if len(prog.Modules) != 1 || len(prog.Modules[0].Body) == 0 {
		t.Fatalf(".xs should extract C statements, got modules=%d body=%d", len(prog.Modules), len(prog.Modules[0].Body))
	}
}

func TestExtractAllRoutesCPPHeadersByContent(t *testing.T) {
	dir := t.TempDir()
	cppHeader := filepath.Join(dir, "web_server_base.h")
	if err := os.WriteFile(cppHeader, []byte(`
namespace esphome {
class WebServerBase {
 public:
  void add_handler(AsyncWebHandler *handler) { handlers_.push_back(handler); }
 private:
  std::vector<AsyncWebHandler *> handlers_;
};
}
`), 0o600); err != nil {
		t.Fatalf("write c++ header: %v", err)
	}
	cHeader := filepath.Join(dir, "plain.h")
	if err := os.WriteFile(cHeader, []byte(`
#define FLAG 1
int c_header_helper(char *value);
`), 0o600); err != nil {
		t.Fatalf("write c header: %v", err)
	}

	_, _, _, stats, err := extractAll([]string{dir})
	if err != nil {
		t.Fatalf("extractAll headers: %v", err)
	}
	if got := stats.files["cpp"]; got != 1 {
		t.Fatalf("C++-looking .h should route through cpp frontend, got %d stats=%v", got, stats.files)
	}
	if got := stats.files["c"]; got != 1 {
		t.Fatalf("plain .h should still route through c frontend, got %d stats=%v", got, stats.files)
	}
}

// The full default rule library (vyql/packs/*.vyql) must parse and type-check
// against the ontology with zero errors.
func TestDefaultPacksCompile(t *testing.T) {
	sources, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForRules(sources), lowerNonCoreV2DefinitionSource)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	compiled, errs := engine.CompileRules(decls, ontology.Seed())
	if len(errs) != 0 {
		t.Fatalf("default packs must compile cleanly, got %d error(s):\n%v", len(errs), errs)
	}
	if len(compiled) < 25 {
		t.Fatalf("expected an exhaustive pack library (>=25 rules), got %d", len(compiled))
	}
	t.Logf("compiled %d rules across the default pack library", len(compiled))
}

func TestLoadRulesDefault(t *testing.T) {
	sources, err := loadRules("")
	if err != nil {
		t.Fatalf("default rules should load from vyql/packs: %v", err)
	}
	foundRule := false
	for _, source := range sources {
		if strings.Contains(source.Source, "rule ") {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatalf("default rules should include authored pack rules, got %d source(s)", len(sources))
	}
}

// vyqlMain must return its exit code rather than calling os.Exit, so the deferred profile
// flushes still run. `scan` gates with a non-zero status on any HIGH finding, which is to
// say on any codebase worth profiling — exiting from inside wrote an empty cpu.prof and no
// heap profile at all.
func TestVyqlMainFlushesProfilesOnGatedNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	// A command injection from an argv-supplied value: HIGH, so -fail-on gates the scan.
	src := "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\n" +
		"func main() {\n\tcmd := exec.Command(\"sh\", \"-c\", os.Args[1])\n\t_ = cmd.Run()\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cpu := filepath.Join(dir, "cpu.prof")
	mem := filepath.Join(dir, "mem.prof")
	t.Setenv("VYQL_CPUPROFILE", cpu)
	t.Setenv("VYQL_MEMPROFILE", mem)

	saved := os.Args
	os.Args = []string{"vyql", "scan", "-cache", "off", dir}
	defer func() { os.Args = saved }()

	code := vyqlMain()
	if code == 0 {
		t.Fatalf("want a gated non-zero exit code for a HIGH finding, got %d", code)
	}
	for _, p := range []string{cpu, mem} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("profile %s was never written on a non-zero exit: %v", filepath.Base(p), err)
		}
		if st.Size() == 0 {
			t.Errorf("profile %s is empty — the deferred flush did not run", filepath.Base(p))
		}
	}
}

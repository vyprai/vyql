package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
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
	first, err := compiledRulesFor(rules)
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	second, err := compiledRulesFor(rules)
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
	if _, err := compiledRulesFor(rules); err == nil || !strings.Contains(err.Error(), "v1 syntax") {
		t.Fatalf("legacy compile = %v, want v2 syntax rejection", err)
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
	if _, err := compiledRulesFor(rules); err == nil || !strings.Contains(err.Error(), `coverage mode "endpoint" not declared in concept covers [path]`) {
		t.Fatalf("compile = %v, want v2 corpus coverage validation", err)
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
	compiled, err := compiledRulesFor(rules)
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
	src, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	decls, err := parser.ParseRuntime(src)
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
	src, err := loadRules("")
	if err != nil || !strings.Contains(src, "rule ") {
		t.Fatalf("default rules should load from vyql/packs, got %q err=%v", src, err)
	}
}

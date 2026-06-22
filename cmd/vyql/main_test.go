package main

import (
	"os"
	"path/filepath"
	"strings"
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

// The full default rule library (vyql/packs/*.vyql) must parse and type-check
// against the ontology with zero errors.
func TestDefaultPacksCompile(t *testing.T) {
	src, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	decls, err := parser.Parse(src)
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

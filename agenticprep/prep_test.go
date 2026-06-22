package agenticprep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeAndValidateProposal(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.py")
	if err := os.WriteFile(src, []byte("from flask import request\nname = request.args.get('q')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if profile.Languages["python"] != 1 {
		t.Fatalf("python files = %d", profile.Languages["python"])
	}
	if len(profile.Imports["python"]) == 0 || profile.Imports["python"][0] != "flask" {
		t.Fatalf("python imports = %#v", profile.Imports["python"])
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "python",
		Source:   "adapter python {\n  package \"flask\" {\n    source \"request.args\" -> code.HttpInput\n  }\n}\n",
		Evidence: []string{src},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err != nil {
		t.Fatalf("ValidateProposal: %v", err)
	}
}

func TestPrepareWritesScanConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/api\nrequire github.com/gin-gonic/gin v1.9.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "prep")
	res, err := Prepare(context.Background(), []string{dir}, Config{OutDir: out})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if res.ScanConfig.Profile != "api" {
		t.Fatalf("expected api profile, got %#v", res.ScanConfig)
	}
	data, err := os.ReadFile(filepath.Join(out, "scan_config.json"))
	if err != nil {
		t.Fatalf("scan_config.json: %v", err)
	}
	if !strings.Contains(string(data), `"profile": "api"`) {
		t.Fatalf("scan_config.json missing profile: %s", data)
	}
}

func TestTrustModelAndEntrypointInventory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/api\nrequire github.com/gin-gonic/gin v1.9.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainFile, []byte("package main\nimport \"net/http\"\nfunc main(){ http.HandleFunc(\"/v1/items\", handler) }\nfunc handler(w http.ResponseWriter, r *http.Request){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	model := trustModelSummary(profile)
	scanConfig, ok := model["scan_config"].(ScanConfig)
	if !ok || scanConfig.Profile != "api" {
		t.Fatalf("expected api trust model, got %#v", model["scan_config"])
	}
	entries, err := entrypointInventory(profile, "go", 10)
	if err != nil {
		t.Fatalf("entrypointInventory: %v", err)
	}
	if len(entries) == 0 || entries[0].Kind != "http_route" {
		t.Fatalf("expected http route entrypoint, got %#v", entries)
	}
}

func TestValidateProposalRequiresPackageScopeWhenPackageEvidenceExists(t *testing.T) {
	profile := Profile{
		Languages: map[string]int{"python": 1},
		Imports:   map[string][]string{"python": []string{"flask"}},
		Packages:  []string{"flask"},
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "python",
		Source:   "adapter python {\n  source \"request.args\" -> code.HttpInput\n}\n",
		Evidence: []string{"app.py"},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err == nil {
		t.Fatal("expected package-less mapping to be rejected when package evidence exists")
	}
}

func TestValidateProposalRejectsSourceOnlyParamOverlay(t *testing.T) {
	profile := Profile{
		Languages: map[string]int{"go": 1},
		Imports:   map[string][]string{"go": {"github.com/example/project/request"}},
		Packages:  []string{"github.com/example/project/request"},
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "go",
		Source: `adapter go {
  package "github.com/example/project/request" {
    source param -> code.ExternalEntryInput
    source "Request.Name" -> code.ExternalEntryInput
  }
}
`,
		Evidence: []string{"request/request.go"},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err == nil {
		t.Fatal("expected source-only source param overlay to be rejected")
	}
}

func TestValidateProposalAllowsParamSourceWithConcreteSink(t *testing.T) {
	profile := Profile{
		Languages: map[string]int{"python": 1},
		Imports:   map[string][]string{"python": {"acme_runner"}},
		Packages:  []string{"acme_runner"},
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "python",
		Source: `adapter python {
  package "acme_runner" {
    source param -> code.ExternalEntryInput
    sink path "run_script" arg 0 -> code.CommandExecution
  }
}
`,
		Evidence: []string{"acme_runner/__init__.py"},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err != nil {
		t.Fatalf("source param should be allowed when paired with a concrete sink: %v", err)
	}
}

func TestValidateProposalRejectsFirstPartyManifestPackageGate(t *testing.T) {
	dir := t.TempDir()
	cargo := filepath.Join(dir, "Cargo.toml")
	if err := os.WriteFile(cargo, []byte("[package]\nname = \"split\"\nversion = \"0.1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile := Profile{
		Roots:     []string{dir},
		Languages: map[string]int{"rust": 1},
		Packages:  []string{"split"},
		Manifests: []ManifestEvidence{{
			Path:     cargo,
			Kind:     "cargo.toml",
			Packages: []string{"split"},
		}},
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "rust",
		Source: `adapter rust {
  package "split" {
    sink path "FilterWriter::new" arg 0 -> code.CommandExecution
  }
}
`,
		Evidence: []string{"src/uu/split/src/platform/unix.rs"},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err == nil {
		t.Fatal("expected first-party manifest package overlay to be rejected")
	}
}

func TestAnalyzePrioritizesSecurityRelevantSamplesAndPHPInc(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.php"), []byte("<?php echo 'boring';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(dir, "rrd.inc")
	if err := os.WriteFile(inc, []byte("<?php function rrd_import(){ exec(\"/usr/local/bin/rrdtool restore -f '{$xml_file}' '{$rrd_file}'\"); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := profile.Languages["php"]; got != 2 {
		t.Fatalf("php files = %d", got)
	}
	if len(profile.Samples) == 0 || profile.Samples[0].Path != inc {
		t.Fatalf("security-relevant .inc should be first sample, got %#v", profile.Samples)
	}
}

func TestSecurityRelevantFilesRanksDangerousHelpers(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "restore.inc")
	if err := os.WriteFile(helper, []byte("<?php function restore(){ $name=$_POST['name']; exec(\"tar xf {$name}\"); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.php"), []byte("<?php echo 'ok';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "php", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != helper {
		t.Fatalf("expected restore helper first, got %#v", files)
	}
}

func TestSecurityRelevantFilesRanksFilesystemWarningDisclosureContexts(t *testing.T) {
	dir := t.TempDir()
	driver := filepath.Join(dir, "LocalDriver.php")
	if err := os.WriteFile(driver, []byte("<?php class LocalDriver { function deleteFile($id) { $filePath = $this->getAbsolutePath($id); $result = unlink($filePath); if ($result === false) { throw new \\RuntimeException('failed'); } } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Registry.php"), []byte("<?php function load($v) { return unserialize($v); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "php", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != driver {
		t.Fatalf("expected filesystem warning disclosure context first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "getAbsolutePath") || !strings.Contains(files[0].Snippet, "unlink") {
		t.Fatalf("snippet should show filesystem disclosure evidence, got %q", files[0].Snippet)
	}
}

func TestSecurityRelevantFilesRanksRolePermissionTables(t *testing.T) {
	dir := t.TempDir()
	authz := filepath.Join(dir, "authorization_middleware.go")
	if err := os.WriteFile(authz, []byte("package server\nvar PermissionsByRole = map[RoleID][]string{RoleNetworkManager: {PermBackup, PermRestore, PermSupportBundle}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "restore.go"), []byte("package db\nfunc restore(){ exec.Command(\"tar\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "go", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != authz {
		t.Fatalf("expected role permission table first, got %#v", files)
	}
}

func TestCoarsePackagesReadsComposerAndPackageJSONNames(t *testing.T) {
	composer := `{"name":"liftkit/database","require":{"php":">=5.4","doctrine/dbal":"^2"}}`
	got := coarsePackages("composer.json", composer)
	for _, want := range []string{"liftkit/database", "php", "doctrine/dbal"} {
		if !containsString(got, want) {
			t.Fatalf("composer packages missing %q: %#v", want, got)
		}
	}
	pkgJSON := `{"name":"demo-app","dependencies":{"express":"^4.0.0"},"devDependencies":{"jest":"^29"}}`
	got = coarsePackages("package.json", pkgJSON)
	for _, want := range []string{"demo-app", "express", "jest"} {
		if !containsString(got, want) {
			t.Fatalf("package.json packages missing %q: %#v", want, got)
		}
	}
}

func TestAnalyzeReportsDependencyGapsWithoutDefinitions(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"name":"demo-app","dependencies":{"@acme/no-vyql-def":"1.0.0","express":"^4.0.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "server.js")
	if err := os.WriteFile(src, []byte("const acme = require('@acme/no-vyql-def');\napp.post('/x', (req, res) => acme.render(req.body.html));\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !hasDependencyGap(profile.DepGaps, "javascript", "@acme/no-vyql-def") {
		t.Fatalf("expected dependency gap for unknown package, got %#v", profile.DepGaps)
	}
	if hasDependencyGap(profile.DepGaps, "javascript", "fs") {
		t.Fatalf("stdlib package should not be reported as a gap: %#v", profile.DepGaps)
	}
}

func TestProbeDependencyFindsUncoveredUsage(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"@acme/no-vyql-def":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "server.js")
	if err := os.WriteFile(src, []byte("const acme = require('@acme/no-vyql-def');\nfunction handle(req){ return acme.render(req.body.html); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	probe, err := probeDependency(profile, "javascript", "@acme/no-vyql-def", 10)
	if err != nil {
		t.Fatalf("probeDependency: %v", err)
	}
	if probe.Gap.Package != "@acme/no-vyql-def" {
		t.Fatalf("wrong probe gap: %#v", probe.Gap)
	}
	if len(probe.Matches) == 0 || probe.Matches[0].Path != src {
		t.Fatalf("expected source usage match, got %#v", probe.Matches)
	}
}

func TestVertexCachedGenerateBodyOmitsTools(t *testing.T) {
	p := &VertexProvider{temperature: 0.2}
	contents := []map[string]any{{
		"role":  "user",
		"parts": []map[string]any{{"text": "continue"}},
	}}
	uncached := p.generateAgentStepBody(contents, "")
	if _, ok := uncached["tools"]; !ok {
		t.Fatal("uncached generate body should include tool declarations")
	}
	cached := p.generateAgentStepBody(contents, "projects/p/locations/global/cachedContents/1")
	if got, _ := cached["cachedContent"].(string); got == "" {
		t.Fatalf("cached generate body missing cachedContent: %#v", cached)
	}
	if _, ok := cached["tools"]; ok {
		t.Fatalf("cached generate body must omit tools: %#v", cached)
	}
}

func TestSearchContextAndReadFilesSupportRepoExploration(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "src", "handler.js")
	if err := os.MkdirAll(filepath.Dir(a), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("function handle(req) {\n  const id = req.query.id;\n  return service.loadSession(id);\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(dir, "src", "safe.js")
	if err := os.WriteFile(b, []byte("export function ok() { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	matches, err := searchProfileContext(profile, "loadSession", false, false, 1, 1, 5)
	if err != nil {
		t.Fatalf("searchProfileContext: %v", err)
	}
	if len(matches) != 1 || !strings.Contains(matches[0].Context, "req.query.id") {
		t.Fatalf("expected surrounding context for loadSession, got %#v", matches)
	}
	files, err := readProfileFiles(profile, []string{"src/handler.js", "src/safe.js"}, 2000)
	if err != nil {
		t.Fatalf("readProfileFiles: %v", err)
	}
	if len(files) != 2 || !files[0].OK || !strings.Contains(files[0].Content, "loadSession") {
		t.Fatalf("expected batch file contents, got %#v", files)
	}
}

func TestSymbolInventoryFindsClassesMethodsAndFunctions(t *testing.T) {
	dir := t.TempDir()
	phpPath := filepath.Join(dir, "src", "Controller", "CustomerTransformerController.php")
	if err := os.MkdirAll(filepath.Dir(phpPath), 0o755); err != nil {
		t.Fatal(err)
	}
	php := `<?php
final class CustomerTransformerController {
    public function checkForNameDuplicatesAction(Request $request) {
        return $request->query->get('name');
    }
}
`
	if err := os.WriteFile(phpPath, []byte(php), 0o644); err != nil {
		t.Fatal(err)
	}
	cPath := filepath.Join(dir, "exec", "totemconfig.c")
	if err := os.MkdirAll(filepath.Dir(cPath), 0o755); err != nil {
		t.Fatal(err)
	}
	cSrc := `#include "totemconfig.h"
static int totem_get_crypto(struct totem_config *totem_config)
{
    return 0;
}
`
	if err := os.WriteFile(cPath, []byte(cSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	phpSyms, err := symbolInventory(profile, symbolInventoryQuery{Language: "php", NameContains: "customer", Max: 10})
	if err != nil {
		t.Fatalf("symbolInventory php: %v", err)
	}
	if !hasSymbol(phpSyms, "class", "CustomerTransformerController") {
		t.Fatalf("expected PHP controller class, got %#v", phpSyms)
	}
	methods, err := symbolInventory(profile, symbolInventoryQuery{Language: "php", Kind: "function", NameContains: "duplicates", Max: 10})
	if err != nil {
		t.Fatalf("symbolInventory php method: %v", err)
	}
	if !hasSymbol(methods, "function", "checkForNameDuplicatesAction") {
		t.Fatalf("expected PHP action method, got %#v", methods)
	}
	cSyms, err := symbolInventory(profile, symbolInventoryQuery{Language: "c", Kind: "function", NameContains: "crypto", Max: 10})
	if err != nil {
		t.Fatalf("symbolInventory c: %v", err)
	}
	if !hasSymbol(cSyms, "function", "totem_get_crypto") {
		t.Fatalf("expected C function, got %#v", cSyms)
	}
	if cSyms[0].Path != "exec/totemconfig.c" {
		t.Fatalf("expected display path relative to repo, got %#v", cSyms[0])
	}
}

func TestRepoStructureRanksSecurityRelevantDirectories(t *testing.T) {
	dir := t.TempDir()
	api := filepath.Join(dir, "api", "upload.php")
	if err := os.MkdirAll(filepath.Dir(api), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api, []byte("<?php move_uploaded_file($_FILES['f']['tmp_name'], $path);"), 0o644); err != nil {
		t.Fatal(err)
	}
	docs := filepath.Join(dir, "docs", "readme.js")
	if err := os.MkdirAll(filepath.Dir(docs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docs, []byte("console.log('docs');"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	dirs, err := repoStructure(profile, 5)
	if err != nil {
		t.Fatalf("repoStructure: %v", err)
	}
	if len(dirs) == 0 || dirs[0].Path != "api" {
		t.Fatalf("expected api directory first, got %#v", dirs)
	}
	if dirs[0].Languages["php"] != 1 {
		t.Fatalf("expected php language count, got %#v", dirs[0])
	}
}

func TestValidateProposalRejectsAbsentLanguage(t *testing.T) {
	profile := Profile{Languages: map[string]int{"python": 1}}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source:   "adapter javascript {\n  source \"req.body\" -> code.HttpInput\n}\n",
		Evidence: []string{"app.js"},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err == nil {
		t.Fatal("expected absent-language proposal to be rejected")
	}
}

func hasDependencyGap(gaps []DependencyGap, lang, pkg string) bool {
	for _, gap := range gaps {
		if gap.Language == lang && gap.Package == pkg {
			return true
		}
	}
	return false
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func hasSymbol(symbols []symbolEntry, kind, name string) bool {
	for _, sym := range symbols {
		if sym.Kind == kind && sym.Name == name {
			return true
		}
	}
	return false
}

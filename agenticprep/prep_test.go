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

func TestPrepRanksCorsOriginValidationFilesAndDependencies(t *testing.T) {
	dir := t.TempDir()
	goMod := `module example.com/app

require (
    github.com/example/corsguard v1.0.0
    github.com/example/plainlib v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	corsFile := filepath.Join(dir, "cors.go")
	corsSrc := `package app

import "strings"

type Config struct {
    AllowOrigins []string
    AllowWildcard bool
}

func (c Config) parseWildcardRules() [][]string {
    var rules [][]string
    if !c.AllowWildcard {
        return rules
    }
    for _, origin := range c.AllowOrigins {
        i := strings.Index(origin, "*")
        if strings.HasPrefix(origin, "https://") {
            rules = append(rules, []string{origin[:i], "*"})
        }
    }
    return rules
}
`
	if err := os.WriteFile(corsFile, []byte(corsSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	plainFile := filepath.Join(dir, "plain.go")
	if err := os.WriteFile(plainFile, []byte("package app\nfunc add(a, b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected CORS/origin profile to require symbol inventory")
	}
	files, err := securityRelevantFiles(profile, "go", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != corsFile {
		t.Fatalf("expected CORS origin parser first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "AllowOrigins") && !strings.Contains(files[0].Snippet, "wildcard") {
		t.Fatalf("expected CORS/origin snippet, got %q", files[0].Snippet)
	}
	symbols, err := symbolInventory(profile, symbolInventoryQuery{Language: "go", NameContains: "wildcard", Max: 10})
	if err != nil {
		t.Fatalf("symbolInventory: %v", err)
	}
	if !hasSymbol(symbols, "method", "parseWildcardRules") {
		t.Fatalf("expected wildcard parser symbol, got %#v", symbols)
	}
	corsScore := dependencyGapScoreForTest(profile.DepGaps, "github.com/example/corsguard")
	plainScore := dependencyGapScoreForTest(profile.DepGaps, "github.com/example/plainlib")
	if corsScore <= plainScore {
		t.Fatalf("expected CORS dependency score above plain dependency, cors=%d plain=%d gaps=%#v", corsScore, plainScore, profile.DepGaps)
	}
}

func TestPrepRanksAttestationPredicateVerificationFiles(t *testing.T) {
	dir := t.TempDir()
	goMod := `module example.com/verifier

require github.com/example/sigstore-helper v1.0.0
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	verifyFile := filepath.Join(dir, "verify_attestation.go")
	verifySrc := `package verify

import _ "github.com/example/sigstore-helper"

func VerifyImageAttestations() {}
func AttestationToPayloadJSON(predicateType string, vp any) []byte { return nil }
func PrintVerification(verified []any) {}

func Exec(predicateType string, verified []any) {
    for _, vp := range verified {
        payload := AttestationToPayloadJSON(predicateType, vp)
        if len(payload) == 0 {
            continue
        }
    }
    PrintVerification(verified)
}
`
	if err := os.WriteFile(verifyFile, []byte(verifySrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.go"), []byte("package verify\nfunc add(a, b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected attestation/predicate profile to require symbol inventory")
	}
	terms := requiredCallInventoryTerms(profile)
	if !containsString(terms, "attestation") || !containsString(terms, "predicate") {
		t.Fatalf("expected focused attestation/predicate call inventory terms, got %#v", terms)
	}
	broadLog := []AgentStep{{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"name_contains": "VerifyImageSignatures"}}}}}
	if agentLogHasCallInventoryTerm(broadLog, terms) {
		t.Fatalf("broad signature call inventory should not satisfy attestation/predicate focus")
	}
	focusedLog := []AgentStep{{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"name_contains": "AttestationToPayloadJSON"}}}}}
	if !agentLogHasCallInventoryTerm(focusedLog, terms) {
		t.Fatalf("focused attestation call inventory should satisfy required terms")
	}
	files, err := securityRelevantFiles(profile, "go", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != verifyFile {
		t.Fatalf("expected attestation verifier first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "AttestationToPayloadJSON") && !strings.Contains(files[0].Snippet, "Predicate") {
		t.Fatalf("expected attestation/predicate snippet, got %q", files[0].Snippet)
	}
	helperScore := dependencyGapScore(dependencyCandidate{Language: "go", Package: "github.com/example/sigstore-attestation-helper"})
	plainScore := dependencyGapScore(dependencyCandidate{Language: "go", Package: "github.com/example/plainlib"})
	if helperScore <= plainScore {
		t.Fatalf("expected sigstore attestation helper score above plain dependency, helper=%d plain=%d", helperScore, plainScore)
	}
}

func TestPrepRanksCommandWrapperBeforePredicateNoise(t *testing.T) {
	dir := t.TempDir()
	controllerPath := filepath.Join(dir, "Homarus", "src", "Controller", "HomarusController.php")
	if err := os.MkdirAll(filepath.Dir(controllerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	controller := `<?php
use Islandora\Crayfish\Commons\CmdExecuteService;
use Symfony\Component\HttpFoundation\Request;

final class HomarusController {
    private $cmd;
    private $executable;
    private $tempDirectory;

    public function convert(Request $request) {
        $source = $request->headers->get('Apix-Ldp-Resource');
        $args = $request->headers->get('X-Islandora-Args');
        $token = $request->headers->get('Authorization');
        $headers = "'Authorization:  $token'";
        $cmd_string = "$this->executable -headers $headers -i $source $args -f mp4 /tmp/out.mp4";
        return $this->generateDerivativeResponse($cmd_string, $source, '/tmp/out.mp4', 'video/mp4');
    }

    public function generateDerivativeResponse(string $cmd_string, string $source, string $path, string $content_type) {
        return $this->cmd->execute($cmd_string, $source);
    }
}
`
	if err := os.WriteFile(controllerPath, []byte(controller), 0o644); err != nil {
		t.Fatal(err)
	}
	noisePath := filepath.Join(dir, "Milliner", "src", "Service", "MillinerService.php")
	if err := os.MkdirAll(filepath.Dir(noisePath), 0o755); err != nil {
		t.Fatal(err)
	}
	noise := `<?php
final class MillinerService {
    public function findPredicateForObject($predicate, $object) {
        return $this->repository->getFirstPredicate($predicate, $object);
    }
}
`
	if err := os.WriteFile(noisePath, []byte(noise), 0o644); err != nil {
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
	if len(files) == 0 || files[0].Path != controllerPath {
		t.Fatalf("expected HomarusController.php first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "$cmd_string") || !strings.Contains(files[0].Snippet, "X-Islandora-Args") {
		t.Fatalf("expected command-wrapper snippet, got %q", files[0].Snippet)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected command-wrapper profile to require symbol inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	if !containsString(callTerms, "execute") || !containsString(callTerms, "command") {
		t.Fatalf("expected focused command-wrapper call terms, got %#v", callTerms)
	}
	if containsString(callTerms, "predicate") || containsString(callTerms, "provenance") {
		t.Fatalf("command-wrapper profile should outrank predicate/provenance terms, got %#v", callTerms)
	}
	assignmentTerms := requiredAssignmentInventoryTerms(profile)
	if !containsString(assignmentTerms, "cmd") || !containsString(assignmentTerms, "args") {
		t.Fatalf("expected focused command-wrapper assignment terms, got %#v", assignmentTerms)
	}
}

func TestPrepRejectsBroadCommandWrapperSink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Controller.php")
	if err := os.WriteFile(src, []byte("<?php use Islandora\\Crayfish\\Commons\\CmdExecuteService; final class C { function f($cmd) { return $this->cmd->execute($cmd); } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	composer := filepath.Join(dir, "composer.json")
	if err := os.WriteFile(composer, []byte(`{"require":{"islandora/crayfish-commons":"^4.1"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	proposal := Proposal{AdapterFiles: []AdapterFile{{
		Language: "php",
		Source: `adapter php {
  package "islandora/crayfish-commons" {
    sink path "Islandora\\Crayfish\\Commons\\CmdExecuteService" arg 0 -> code.CommandExecution
  }
}
`,
		Evidence: []string{src},
	}}}
	if err := ValidateProposal(profile, proposal, Config{}); err == nil || !strings.Contains(err.Error(), "CommandStringWrapperExecution") {
		t.Fatalf("expected broad command-wrapper sink rejection, got %v", err)
	}

	narrow := Proposal{AdapterFiles: []AdapterFile{{
		Language: "php",
		Source: `adapter php {
  mark exact "analysis.function.context" val "name=f" val "$this->cmd->execute($cmd)" nval "$cmd=array_merge" -> code.CommandStringWrapperExecution
}
`,
		Evidence: []string{src},
	}}}
	if err := ValidateProposal(profile, narrow, Config{}); err != nil {
		t.Fatalf("expected narrow command-wrapper context mark to validate: %v", err)
	}
}

func TestPrepRanksMcpToolCommandTemplates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"@modelcontextprotocol/sdk":"^1.0.0","zod":"^3.0.0","@acme/plainlib":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "src", "index.ts")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "child_process";

const server = new McpServer({ name: "Demo", version: "1.0.0" });
server.tool("which-app-on-port", { port: z.number() }, async ({ port }) => {
  exec(` + "`lsof -t -i tcp:${port}`" + `, (error, pidStdout) => {
    const pid = pidStdout.trim();
    exec(` + "`ps -p ${pid} -o comm=`" + `, () => {});
  });
});
await server.connect(new StdioServerTransport());
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	noisePath := filepath.Join(dir, "src", "predicate.ts")
	noise := `export function filterPredicate(items, predicate) {
  return items.filter(item => item.predicate === predicate);
}
`
	if err := os.WriteFile(noisePath, []byte(noise), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "javascript", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != srcPath {
		t.Fatalf("expected MCP tool index.ts first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "server.tool") || !strings.Contains(files[0].Snippet, "exec(`lsof") {
		t.Fatalf("expected MCP command snippet, got %q", files[0].Snippet)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected MCP tool profile to require symbol inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	if !containsString(callTerms, "tool") || !containsString(callTerms, "exec") {
		t.Fatalf("expected focused MCP tool call terms, got %#v", callTerms)
	}
	if containsString(callTerms, "predicate") || containsString(callTerms, "provenance") {
		t.Fatalf("MCP tool profile should outrank predicate/provenance terms, got %#v", callTerms)
	}
	assignmentTerms := requiredAssignmentInventoryTerms(profile)
	if !containsString(assignmentTerms, "port") || !containsString(assignmentTerms, "exec") {
		t.Fatalf("expected MCP assignment terms, got %#v", assignmentTerms)
	}
	mcpScore := dependencyGapScoreForTest(profile.DepGaps, "@modelcontextprotocol/sdk")
	plainScore := dependencyGapScoreForTest(profile.DepGaps, "@acme/plainlib")
	if mcpScore <= plainScore {
		t.Fatalf("expected MCP dependency score above plain dependency, mcp=%d plain=%d gaps=%#v", mcpScore, plainScore, profile.DepGaps)
	}

	broad := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source: `adapter javascript {
  mark exact "analysis.module.context" val "server.tool(\"which-app-on-port\"" val "port:z.number()" -> code.McpToolCommandTemplateExecution
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, broad, Config{}); err == nil || !strings.Contains(err.Error(), "broad MCP tool command mark") {
		t.Fatalf("expected broad MCP mark rejection, got %v", err)
	}
	narrow := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source: `adapter javascript {
  mark exact "analysis.module.context" val "server.tool" val "exec(` + "`lsof-t-itcp:${port}`" + `" nval "execFile(" -> code.McpToolCommandTemplateExecution
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, narrow, Config{}); err != nil {
		t.Fatalf("expected narrow MCP mark to validate: %v", err)
	}
	packagedExact := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source: `adapter javascript {
  package "@modelcontextprotocol/sdk" {
    mark exact "analysis.module.context" val "server.tool" val "exec(` + "`lsof-t-itcp:${port}`" + `" nval "execFile(" -> code.McpToolCommandTemplateExecution
  }
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, packagedExact, Config{}); err == nil || !strings.Contains(err.Error(), "package-scopes an exact context mark") {
		t.Fatalf("expected package-scoped exact context rejection, got %v", err)
	}
}

func TestPrepRanksJenkinsCredentialsStartupLoad(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src", "main", "java", "com", "cloudbees", "plugins", "credentials", "SystemCredentialsProvider.java")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package com.cloudbees.plugins.credentials;
import hudson.XmlFile;
import jenkins.model.Jenkins;
import java.io.File;
import java.util.List;
import java.util.Map;

public class SystemCredentialsProvider {
  private transient List<Credentials> credentials;
  private Map<Domain, List<Credentials>> domainCredentialsMap;
  public SystemCredentialsProvider() {
    XmlFile xml = getConfigFile();
    if (xml.exists()) {
      xml.unmarshal(this);
    }
    domainCredentialsMap = DomainCredentials.migrateListToMap(domainCredentialsMap, credentials);
    credentials = null;
  }
  public static XmlFile getConfigFile() {
    return new XmlFile(Jenkins.XSTREAM2, new File(Jenkins.getActiveInstance().getRootDir(), "credentials.xml"));
  }
  public static SystemCredentialsProvider getInstance() {
    return ExtensionList.lookup(SystemCredentialsProvider.class).get(SystemCredentialsProvider.class);
  }
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	noisePath := filepath.Join(dir, "src", "main", "java", "example", "JsonModel.java")
	if err := os.MkdirAll(filepath.Dir(noisePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noisePath, []byte("class JsonModel { Object serialize() { return response.data; } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "java", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != srcPath {
		t.Fatalf("expected SystemCredentialsProvider.java first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "SystemCredentialsProvider") || !strings.Contains(files[0].Snippet, "credentials") {
		t.Fatalf("expected credentials startup-load snippet, got %q", files[0].Snippet)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected Jenkins credentials startup profile to require symbol inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	if !containsString(callTerms, "unmarshal") || !containsString(callTerms, "initializer") {
		t.Fatalf("expected focused Jenkins startup call terms, got %#v", callTerms)
	}
	if containsString(callTerms, "serialize") {
		t.Fatalf("Jenkins startup profile should outrank generic serialization terms, got %#v", callTerms)
	}
	concepts := conceptReference("jenkins credentials startup")
	found := false
	for _, row := range concepts {
		if row["concept"] == "code.JenkinsCredentialsStartupLoadContextExposure" && row["surface"] == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Jenkins startup scan concept in reference, got %#v", concepts)
	}
	classPreviews, err := classContexts(profile, srcPath, "SystemCredentialsProvider", "unmarshal", 2)
	if err != nil {
		t.Fatalf("classContexts: %v", err)
	}
	if len(classPreviews) != 1 {
		t.Fatalf("expected one SystemCredentialsProvider class context, got %#v", classPreviews)
	}
	classTokens := strings.Join(classPreviews[0].SuggestedVals, "\n")
	for _, want := range []string{
		"class_name:SystemCredentialsProvider",
		"function_name:SystemCredentialsProvider",
		"function_name:getInstance",
		"call_path:xml.unmarshal",
		"call_path:DomainCredentials.migrateListToMap",
	} {
		if !strings.Contains(classTokens, want) {
			t.Fatalf("class context missing %q in:\n%s", want, classTokens)
		}
	}
	functionContext := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.function.context" val "name=SystemCredentialsProvider" val "XmlFilexml=getConfigFile();" nval "@Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, functionContext, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected Jenkins startup function-context rejection, got %v", err)
	}
	tooBroadClass := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.class.context" val "SystemCredentialsProvider" nval "@Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, tooBroadClass, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected broad Jenkins startup class-context rejection, got %v", err)
	}
	migrationOnlyClass := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.class.context" val "domainCredentialsMap=DomainCredentials.migrateListToMap" nval "@Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, migrationOnlyClass, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected migration-only Jenkins startup class-context rejection, got %v", err)
	}
	looseClassText := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.class.context" val "class SystemCredentialsProvider" val "unmarshal" nval "@Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, looseClassText, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected loose Jenkins startup class-context rejection, got %v", err)
	}
	noisyClassContext := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.class.context" val "class_name:SystemCredentialsProvider" val "class_base:AbstractDescribableImpl" val "annotation:Extension" val "call_path:xml.unmarshal" val "call_path:DomainCredentials.migrateListToMap" nval "annotation:Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, noisyClassContext, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected noisy Jenkins startup class-context rejection, got %v", err)
	}
	classContext := Proposal{AdapterFiles: []AdapterFile{{
		Language: "java",
		Source: `adapter java {
  mark exact "analysis.class.context" val "class_name:SystemCredentialsProvider" val "function_name:SystemCredentialsProvider" val "call_path:xml.unmarshal" val "call_path:DomainCredentials.migrateListToMap" val "function_name:getInstance" nval "annotation:Initializer" -> code.JenkinsCredentialsStartupLoadContextExposure
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, classContext, Config{}); err != nil {
		t.Fatalf("expected Jenkins startup class-context mark to validate: %v", err)
	}
}

func TestPrepRanksPhpSqlWrapperProfile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src", "FundRaiserEditor.php")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `<?php
$iFundRaiserID = InputUtils::legacyFilterInputArr($_GET, 'FundRaiserID', 'int');
$sSQL = "SELECT di_ID FROM donateditem_di WHERE di_FR_ID = '" . $iFundRaiserID . "'";
$rsDonatedItems = RunQuery($sSQL);
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !phpSqlWrapperProfile(profile) {
		t.Fatalf("expected PHP SQL wrapper profile")
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected PHP SQL wrapper profile to require symbol/call inventory")
	}
	terms := requiredCallInventoryTerms(profile)
	for _, want := range []string{"runquery", "sql", "legacyfilterinputarr"} {
		if !containsString(terms, want) {
			t.Fatalf("expected call inventory term %q in %#v", want, terms)
		}
	}
	files, err := securityRelevantFiles(profile, "php", 5)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != srcPath {
		t.Fatalf("expected SQL wrapper file first, got %#v", files)
	}
}

func TestPrepRanksGoArchiveOverwriteProfile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "utils.go")
	src := `package utils

func UnzipDirectory(destination string, source string) error {
	archive, _ := zip.OpenReader(source)
	for _, f := range archive.File {
		filePath := filepath.Join(destination, f.Name)
		dstFile, _ := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		_ = dstFile
	}
	return nil
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !archiveOverwriteProfile(profile) {
		t.Fatalf("expected archive overwrite profile")
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected archive overwrite profile to require symbol/call inventory")
	}
	if requiresAssignmentInventory(profile) {
		t.Fatalf("archive overwrite profile should not require unrelated assignment inventory")
	}
	terms := requiredCallInventoryTerms(profile)
	for _, want := range []string{"openreader", "openfile", "o_trunc"} {
		if !containsString(terms, want) {
			t.Fatalf("expected call inventory term %q in %#v", want, terms)
		}
	}
}

func TestPrepRanksJobOutputEventUpdateProfile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "job.js")
	src := `const cp = require('child_process');

module.exports = Class.create({
	handleChildResponse: function(job, worker, data) {
		this.logDebug(10, "Got job update from child: " + job.pid, data);
		['progress', 'complete', 'update_event'].forEach(function(key) {
			if (key in data) job[key] = data[key];
		});
	},
	finishLocalJob: function(job) {
		if (job.update_event) this.storage.listFindUpdate('global/schedule', { id: job.event }, job.update_event, function(err) {});
	}
});
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if mcpToolProfile(profile) {
		t.Fatalf("plain child_process usage should not imply MCP tool profile")
	}
	if !jobOutputEventUpdateProfile(profile) {
		t.Fatalf("expected job output event-update profile")
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected job output profile to require symbol/call inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	for _, want := range []string{"update_event", "handlechildresponse", "listfindupdate"} {
		if !containsString(callTerms, want) {
			t.Fatalf("expected call inventory term %q in %#v", want, callTerms)
		}
	}
	assignTerms := requiredAssignmentInventoryTerms(profile)
	for _, want := range []string{"update_event", "schedule", "config"} {
		if !containsString(assignTerms, want) {
			t.Fatalf("expected assignment inventory term %q in %#v", want, assignTerms)
		}
	}
	files, err := securityRelevantFiles(profile, "javascript", 5)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != srcPath {
		t.Fatalf("expected job output file first, got %#v", files)
	}
	concepts := conceptReference("job output event update")
	found := false
	for _, row := range concepts {
		if row["concept"] == "code.JobOutputEventUpdateAuthorizationBypass" && row["surface"] == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected job output event-update scan concept in reference, got %#v", concepts)
	}
	broadSinkContext := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source: `adapter javascript {
  mark exact "analysis.function.context" val "this.storage.listFindUpdate('global/schedule'" val "job.update_event" nval "allow_event_updates_from_jobs" nval "delete job.update_event" -> code.JobOutputEventUpdateAuthorizationBypass
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, broadSinkContext, Config{}); err == nil || !strings.Contains(err.Error(), "too broadly") {
		t.Fatalf("expected broad job output event-update rejection, got %v", err)
	}
	handlerContext := Proposal{AdapterFiles: []AdapterFile{{
		Language: "javascript",
		Source: `adapter javascript {
  mark exact "analysis.function.context" val "Got job update from child" val "update_event" val "job[key]=data[key]" nval "allow_event_updates_from_jobs" nval "delete data.update_event" -> code.JobOutputEventUpdateAuthorizationBypass
}
`,
		Evidence: []string{srcPath},
	}}}
	if err := ValidateProposal(profile, handlerContext, Config{}); err != nil {
		t.Fatalf("expected handler context overlay to validate: %v", err)
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

func TestPrepRequiresNativeMemoryInventoryTerms(t *testing.T) {
	dir := t.TempDir()
	cPath := filepath.Join(dir, "Objects", "unicodeobject.c")
	if err := os.MkdirAll(filepath.Dir(cPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `
typedef void PyObject;
PyObject *PyString_FromStringAndSize(char *s, int size);

static PyObject *unicodeescape_string(int size) {
    PyObject *repr = PyString_FromStringAndSize(0, 2 + 6*size + 1);
    if (size > 0) {
        char *p = 0;
        *p++ = 'U';
    }
    return repr;
}
`
	if err := os.WriteFile(cPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected native memory profile to require symbol inventory")
	}
	terms := requiredCallInventoryTerms(profile)
	if !containsString(terms, "alloc") || !containsString(terms, "size") || !containsString(terms, "escape") {
		t.Fatalf("expected focused native memory call inventory terms, got %#v", terms)
	}
	focusedLog := []AgentStep{{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"name_contains": "PyString_FromStringAndSize"}}}}}
	if !agentLogHasCallInventoryTerm(focusedLog, terms) {
		t.Fatalf("allocator call inventory should satisfy native memory terms")
	}
	if got := inventoryGateError(profile, nil, "search_text"); !strings.Contains(got, "symbol_inventory") || !strings.Contains(got, "call_inventory") {
		t.Fatalf("expected search gate to require inventories, got %q", got)
	}
	readyLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "c", "name_contains": "escape"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "c", "name_contains": "PyString_FromStringAndSize"}}}},
	}
	if got := inventoryGateError(profile, readyLog, "search_text"); got != "" {
		t.Fatalf("expected inventory gate satisfied, got %q", got)
	}
}

func TestPrepRequiresAssignmentInventoryForOutputEncodingProfiles(t *testing.T) {
	dir := t.TempDir()
	phpPath := filepath.Join(dir, "src", "services", "AuditService.php")
	if err := os.MkdirAll(filepath.Dir(phpPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `<?php
final class AuditService {
    public function onSaveElement($element) {
        $model = new AuditModel();
        $model->title = $element->username;
        $snapshot['title'] = Html::encode($element->username);
    }
}
`
	if err := os.WriteFile(phpPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !requiresAssignmentInventory(profile) {
		t.Fatalf("expected output-encoding profile to require assignment inventory")
	}
	terms := requiredAssignmentInventoryTerms(profile)
	if !containsString(terms, "title") || !containsString(terms, "encode") {
		t.Fatalf("expected focused assignment terms, got %#v", terms)
	}
	if got := inventoryGateError(profile, nil, "read_file"); !strings.Contains(got, "assignment_inventory") {
		t.Fatalf("expected read gate to require assignment inventory, got %q", got)
	}
	readyLog := []AgentStep{{ToolCalls: []AgentToolCall{{Name: "assignment_inventory", Arguments: map[string]any{"language": "php", "name_contains": "title"}}}}}
	if got := inventoryGateError(profile, readyLog, "read_file"); got != "" {
		t.Fatalf("expected assignment inventory gate satisfied, got %q", got)
	}
}

func TestPrepAllowsExactReadAfterFocusedInventory(t *testing.T) {
	profile := Profile{
		Languages: map[string]int{"java": 1},
		Packages:  []string{"com.example.PredicateValidator"},
		Samples: []FileSample{{
			Path:     "src/main/java/com/example/CronValidator.java",
			Language: "java",
			Preview:  "class CronValidator { boolean isValid(String value) { return value != null; } }",
		}},
	}
	log := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "java", "name_contains": "Validator"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "java", "name_contains": "isValid"}}}},
	}
	call := vertexToolCall{
		Name:      "read_file",
		Arguments: map[string]any{"path": "src/main/java/com/example/CronValidator.java"},
	}
	if !allowExactReadAfterFocusedInventory(profile, log, call) {
		t.Fatal("expected exact read_file to be allowed after focused symbol/call inventory")
	}
	broadCall := vertexToolCall{Name: "read_file", Arguments: map[string]any{"path": "src/main/java/com/example/CronValidator.java"}}
	broadLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "java", "name_contains": "Validator"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "java"}}}},
	}
	if allowExactReadAfterFocusedInventory(profile, broadLog, broadCall) {
		t.Fatal("broad call inventory should not unlock exact reads early")
	}
}

func TestSecurityRelevantFilesRanksBeanValidationTemplateSink(t *testing.T) {
	dir := t.TempDir()
	validatorPath := filepath.Join(dir, "src", "main", "java", "com", "example", "validation", "CronValidator.java")
	if err := os.MkdirAll(filepath.Dir(validatorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	validatorSrc := `package com.example.validation;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
class CronValidator implements ConstraintValidator<Cron, String> {
  public boolean isValid(String value, ConstraintValidatorContext context) {
    try { parser.parse(value).validate(); return true; }
    catch (IllegalArgumentException e) {
      context.buildConstraintViolationWithTemplate(e.getMessage()).addConstraintViolation();
      return false;
    }
  }
}
`
	if err := os.WriteFile(validatorPath, []byte(validatorSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	predicatePath := filepath.Join(dir, "src", "main", "java", "com", "example", "utils", "Predicates.java")
	if err := os.MkdirAll(filepath.Dir(predicatePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(predicatePath, []byte("package com.example.utils; import java.util.function.Predicate; class Predicates { static <T> Predicate<T> not(Predicate<T> p) { return p.negate(); } }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "java", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != validatorPath {
		t.Fatalf("expected Bean Validation sink first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "buildConstraintViolationWithTemplate") {
		t.Fatalf("expected violation template snippet, got %q", files[0].Snippet)
	}
}

func TestPrepRanksHostExpandedUrlSanitizerOrderProfiles(t *testing.T) {
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "src", "services", "Helper.php")
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `<?php
final class Helper {
    public static function safeCanonicalUrl(): string {
        $url = Craft::$app->getRequest()->getPathInfo();
        $url = DynamicMetaHelper::sanitizeUrl($url);
        return UrlHelper::absoluteUrlWithProtocol($url);
    }
}
`
	if err := os.WriteFile(helperPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	noisePath := filepath.Join(dir, "src", "translations", "en", "seomatic.php")
	if err := os.MkdirAll(filepath.Dir(noisePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noisePath, []byte("<?php return ['title' => 'SEOmatic Twig canonical URL helper'];\n"), 0o644); err != nil {
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
	if len(files) == 0 || files[0].Path != helperPath {
		t.Fatalf("expected Helper.php first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "absoluteUrlWithProtocol") || !strings.Contains(files[0].Snippet, "sanitizeUrl") {
		t.Fatalf("expected sanitizer-order snippet, got %q", files[0].Snippet)
	}
	if !requiresAssignmentInventory(profile) {
		t.Fatalf("expected host-expanded URL profile to require assignment inventory")
	}
	terms := requiredAssignmentInventoryTerms(profile)
	if !containsString(terms, "canonical") || !containsString(terms, "sanitize") || !containsString(terms, "host") {
		t.Fatalf("expected focused canonical URL assignment terms, got %#v", terms)
	}
	readyLog := []AgentStep{{ToolCalls: []AgentToolCall{{Name: "assignment_inventory", Arguments: map[string]any{"language": "php", "name_contains": "canonical"}}}}}
	if got := inventoryGateError(profile, readyLog, "read_file"); got != "" {
		t.Fatalf("expected assignment inventory gate satisfied, got %q", got)
	}
}

func TestPrepRanksSensitiveModelJsonSerializationProfiles(t *testing.T) {
	dir := t.TempDir()
	controllerPath := filepath.Join(dir, "src", "controllers", "VerifyController.php")
	if err := os.MkdirAll(filepath.Dir(controllerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `<?php
final class VerifyController {
    private function _handleSuccessfulLogin(\craft\elements\User $user): Response {
        if ($this->request->getAcceptsJson()) {
            $return = ['returnUrl' => $returnUrl];
            $return['csrfTokenValue'] = $this->request->getCsrfToken();
            return $this->asModelSuccess($user, modelName: 'user', data: $return);
        }
        return $this->redirectToPostedUrl($userSession->getIdentity(), $returnUrl);
    }
}
`
	if err := os.WriteFile(controllerPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(dir, "src", "services", "Response.php")
	if err := os.MkdirAll(filepath.Dir(servicePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, []byte("<?php class Response { public function getReturnUrl() { return $this->redirectToPostedUrl($u, $url); } }\n"), 0o644); err != nil {
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
	if len(files) == 0 || files[0].Path != controllerPath {
		t.Fatalf("expected VerifyController.php first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "asModelSuccess") || !strings.Contains(files[0].Snippet, "csrfTokenValue") {
		t.Fatalf("expected model serialization snippet, got %q", files[0].Snippet)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected model serialization profile to require symbol inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	if !containsString(callTerms, "asmodelsuccess") || !containsString(callTerms, "json") {
		t.Fatalf("expected focused model serialization call terms, got %#v", callTerms)
	}
	assignmentTerms := requiredAssignmentInventoryTerms(profile)
	if !containsString(assignmentTerms, "user") || !containsString(assignmentTerms, "token") {
		t.Fatalf("expected focused sensitive model assignment terms, got %#v", assignmentTerms)
	}
	broadLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "php", "name_contains": "model"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "php"}}}},
		{ToolCalls: []AgentToolCall{{Name: "assignment_inventory", Arguments: map[string]any{"language": "php"}}}},
	}
	if got := inventoryGateError(profile, broadLog, "read_file"); !strings.Contains(got, "call_inventory") {
		t.Fatalf("expected broad inventory to be rejected, got %q", got)
	}
	readyLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "php", "name_contains": "model"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "php", "name_contains": "asmodelsuccess"}}}},
		{ToolCalls: []AgentToolCall{{Name: "assignment_inventory", Arguments: map[string]any{"language": "php", "name_contains": "user"}}}},
	}
	if got := inventoryGateError(profile, readyLog, "read_file"); got != "" {
		t.Fatalf("expected inventory gate satisfied, got %q", got)
	}
}

func TestPrepRanksFilesystemImageDirentTraversalProfiles(t *testing.T) {
	dir := t.TempDir()
	checkPath := filepath.Join(dir, "cramfsck.c")
	src := `#include <string.h>
#include <stdlib.h>

struct cramfs_inode {
    int namelen;
    int size;
    unsigned long offset;
};

void *romfs_read(unsigned long offset);
struct cramfs_inode *iget(unsigned long offset);
void expand_fs(char *path, struct cramfs_inode *i);

void do_directory(char *path, struct cramfs_inode *i)
{
    int pathlen = strlen(path);
    int count = i->size;
    unsigned long offset = i->offset << 2;
    char *newpath = malloc(pathlen + 256);
    memcpy(newpath, path, pathlen);
    while (count > 0) {
        struct cramfs_inode *child = iget(offset);
        int newlen = child->namelen << 2;
        offset += sizeof(struct cramfs_inode);
        memcpy(newpath + pathlen, romfs_read(offset), newlen);
        newpath[pathlen + newlen] = 0;
        expand_fs(newpath, child);
        count -= sizeof(struct cramfs_inode) + newlen;
    }
}
`
	if err := os.WriteFile(checkPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	mkPath := filepath.Join(dir, "mkcramfs.c")
	noise := `/*
Device table entries require absolute paths, but this builder only writes
configured metadata. Keep this file noisy so extraction code must rank first.
*/
void write_table(void) {}
`
	if err := os.WriteFile(mkPath, []byte(noise), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	files, err := securityRelevantFiles(profile, "c", 10)
	if err != nil {
		t.Fatalf("securityRelevantFiles: %v", err)
	}
	if len(files) == 0 || files[0].Path != checkPath {
		t.Fatalf("expected cramfsck.c first, got %#v", files)
	}
	if !strings.Contains(files[0].Snippet, "expand_fs") || !strings.Contains(files[0].Snippet, "romfs_read") {
		t.Fatalf("expected filesystem image extraction snippet, got %q", files[0].Snippet)
	}
	if !requiresSymbolInventory(profile) {
		t.Fatalf("expected filesystem image profile to require symbol inventory")
	}
	callTerms := requiredCallInventoryTerms(profile)
	if !containsString(callTerms, "expand") || !containsString(callTerms, "romfs") {
		t.Fatalf("expected focused filesystem image call terms, got %#v", callTerms)
	}
	broadLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "c", "name_contains": "directory"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "c"}}}},
	}
	if got := inventoryGateError(profile, broadLog, "read_file"); !strings.Contains(got, "call_inventory") {
		t.Fatalf("expected broad inventory to be rejected, got %q", got)
	}
	readyLog := []AgentStep{
		{ToolCalls: []AgentToolCall{{Name: "symbol_inventory", Arguments: map[string]any{"language": "c", "name_contains": "directory"}}}},
		{ToolCalls: []AgentToolCall{{Name: "call_inventory", Arguments: map[string]any{"language": "c", "name_contains": "expand"}}}},
	}
	if got := inventoryGateError(profile, readyLog, "read_file"); got != "" {
		t.Fatalf("expected inventory gate satisfied, got %q", got)
	}
}

func TestPrepConceptReferenceIncludesFilesystemImageDirentTraversal(t *testing.T) {
	concepts := conceptReference("filesystem image")
	found := false
	for _, row := range concepts {
		if row["concept"] == "code.FilesystemImageDirentTraversal" && row["surface"] == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected filesystem image dirent traversal scan concept in reference, got %#v", concepts)
	}
}

func TestPrepConceptReferenceIncludesMcpToolCommandTemplate(t *testing.T) {
	concepts := conceptReference("mcp")
	found := false
	for _, row := range concepts {
		if row["concept"] == "code.McpToolCommandTemplateExecution" && row["surface"] == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected MCP tool command template scan concept in reference, got %#v", concepts)
	}
}

func TestFinishOverlayRequiresNotesForEmptyOverlay(t *testing.T) {
	proposal, warn := proposalFromToolArgs(map[string]any{"adapter_files": []any{}})
	if warn == "" {
		t.Fatalf("expected warning for empty overlay without notes, got proposal %#v", proposal)
	}
	if !strings.Contains(warn, "empty overlay") {
		t.Fatalf("expected empty overlay warning, got %q", warn)
	}
	_, warn = proposalFromToolArgs(map[string]any{
		"adapter_files": []any{},
		"notes":         []any{"No unmodeled dependency API was found; core scan concepts cover the observed parser surface."},
	})
	if warn != "" {
		t.Fatalf("expected empty overlay with notes to pass, got %q", warn)
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
	if got := methods[0].Container; got != "CustomerTransformerController" {
		t.Fatalf("expected method container, got %q in %#v", got, methods[0])
	}
	if !strings.Contains(methods[0].Snippet, "$request->query->get") {
		t.Fatalf("expected method snippet to include body context, got %#v", methods[0])
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

func TestCallInventoryFindsCallersWithoutReadingFilesOneByOne(t *testing.T) {
	dir := t.TempDir()
	verifyPath := filepath.Join(dir, "cmd", "verify_attestation.go")
	if err := os.MkdirAll(filepath.Dir(verifyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package verify

func Exec(policy Policy, c Config, verified []Signature) {
    for _, vp := range verified {
        payload := policy.AttestationToPayloadJSON(c.PredicateType, vp)
        if len(payload) == 0 {
            continue
        }
    }
    PrintVerification(verified)
}
`
	if err := os.WriteFile(verifyPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.go"), []byte("package verify\nfunc helper() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	calls, err := callInventory(profile, callInventoryQuery{Language: "go", NameContains: "attestation", Max: 10})
	if err != nil {
		t.Fatalf("callInventory: %v", err)
	}
	if len(calls) == 0 {
		t.Fatalf("expected attestation call inventory")
	}
	call := calls[0]
	if call.Callee != "policy.AttestationToPayloadJSON" || call.Receiver != "policy" || call.Enclosing != "Exec" {
		t.Fatalf("unexpected attestation call entry: %#v", call)
	}
	if !strings.Contains(call.Snippet, "PredicateType") {
		t.Fatalf("expected call snippet to include predicate argument, got %#v", call)
	}
	prints, err := callInventory(profile, callInventoryQuery{Language: "go", NameContains: "printverification", Max: 10})
	if err != nil {
		t.Fatalf("callInventory print: %v", err)
	}
	if len(prints) == 0 || prints[0].Callee != "PrintVerification" {
		t.Fatalf("expected PrintVerification call, got %#v", prints)
	}
}

func TestAssignmentInventoryFindsPersistentDisplayWrites(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "src", "services", "AuditService.php")
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := `<?php
final class AuditService {
    public function onSaveElement($element) {
        $model = new AuditModel();
        $title = $element->username;
        if ($title) {
            $model->title = $title;
            $snapshot['title'] = Html::encode($title);
        }
    }
}
`
	if err := os.WriteFile(auditPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := Analyze([]string{dir}, Config{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	assignments, err := assignmentInventory(profile, assignmentInventoryQuery{Language: "php", NameContains: "title", Max: 20})
	if err != nil {
		t.Fatalf("assignmentInventory: %v", err)
	}
	if !hasAssignment(assignments, "$model->title", "$title") {
		t.Fatalf("expected raw model title assignment, got %#v", assignments)
	}
	if !hasAssignment(assignments, "$snapshot['title']", "Html::encode($title)") {
		t.Fatalf("expected encoded snapshot assignment, got %#v", assignments)
	}
	for _, assignment := range assignments {
		if assignment.Target == "$model->title" {
			if assignment.Enclosing != "AuditService.onSaveElement" {
				t.Fatalf("expected enclosing method, got %#v", assignment)
			}
			if assignment.Score <= 0 {
				t.Fatalf("expected scored assignment, got %#v", assignment)
			}
		}
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

func hasAssignment(assignments []assignmentEntry, target string, valueContains string) bool {
	for _, assignment := range assignments {
		if assignment.Target == target && strings.Contains(assignment.Value, valueContains) {
			return true
		}
	}
	return false
}

func dependencyGapScoreForTest(gaps []DependencyGap, pkg string) int {
	for _, gap := range gaps {
		if gap.Package == pkg {
			return gap.Score
		}
	}
	return -1
}

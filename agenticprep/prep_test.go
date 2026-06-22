package agenticprep

import (
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

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

const vulnSrc = `package app

import (
	"database/sql"
	"net/http"
)

func search(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	q := r.URL.Query().Get("q")
	db.Query("SELECT * FROM t WHERE x = '" + q + "'")
}

func safe(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	q := r.URL.Query().Get("q")
	db.Query("SELECT * FROM t WHERE x = $1", q)
}
`

// End-to-end CLI core: scanning real Go source flags the string-built query and
// not the parameterized one, using the built-in rule pack.
func TestScanPathsBuiltinRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte(vulnSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules("") // the external default pack (vyql/packs)
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 SQLi finding (string-built, not parameterized), got %d", len(fs))
	}
	if fs[0].RuleID != "VYQL-INJ-001" {
		t.Fatalf("expected the SQLi rule, got %s", fs[0].RuleID)
	}
	if !strings.HasPrefix(fs[0].Bindings[1].Loc, "app.go:") {
		t.Fatalf("sink should be in app.go, got %s", fs[0].Bindings[1].Loc)
	}
}

const vulnPy = `from db import run_query

def login():
    name = request.form['name']
    run_query(name)
`
const vulnPyDB = `def run_query(value):
    cursor.execute("SELECT * FROM users WHERE name = '" + value + "'")
`

// The CLI dispatcher routes .py files to the tree-sitter Python frontend +
// Python adapters, finding the SQLi — proving multi-language dispatch works end
// to end through the same CLI path as Go.
func TestScanPathsPythonDispatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "routes.py"), []byte(vulnPy), 0o644)
	os.WriteFile(filepath.Join(dir, "db.py"), []byte(vulnPyDB), 0o644)
	rules, _ := loadRules("")
	fs, stats, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected a Python SQLi finding via CLI dispatch, got 0")
	}
	if stats.files["python"] != 2 {
		t.Fatalf("dispatcher should report 2 python files, got %d", stats.files["python"])
	}
}

// vulnLdapAssume runs user input through an UNSOUND sanitizer (a custom ldapEscape that
// vyql cannot prove complete) before an LDAP sink. The flow is NOT suppressed — it is
// emitted WITH an assumption note (the generalized regex-CharFilter mechanism).
const vulnLdapAssume = `const ldap = require('ldapjs');
function handler(req, res) {
  const name = req.query.name;
  const safe = ldapEscape(name);
  const client = ldap.createClient();
  client.search('ou=users', { filter: '(uid=' + safe + ')' }, function (err, r) {});
}
`

func TestScanAssumptionNote(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ldap.js"), []byte(vulnLdapAssume), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var ldapF *findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-INJ-005" {
			ldapF = f
		}
	}
	if ldapF == nil {
		t.Fatalf("expected an LDAP-injection finding (flow must NOT be suppressed by an unsound sanitizer), got %d findings", len(fs))
	}
	noted := false
	for _, ne := range ldapF.NegationEvidence {
		if strings.Contains(ne.Clause, "assumption") {
			noted = true
			t.Logf("assumption note: %s — %s", ne.Clause, ne.Detail)
		}
	}
	if !noted {
		t.Fatalf("LDAP finding through ldapEscape must carry an assumption note, got NE=%+v", ldapF.NegationEvidence)
	}
}

// vulnPathGuard guards a path-traversal sink with an UNSOUND prefix check
// (p.startsWith('/safe/')) that a crafted "/safe/../etc/passwd" bypasses. The guard
// dominates the sink, so it must NOT be suppressed — it is emitted WITH an assumption note.
const vulnPathGuard = `const fs = require('fs');
function handler(req, res) {
  const p = req.query.file;
  if (p.startsWith('/safe/')) {
    fs.readFile(p, function (e, d) {});
  }
}
`

func TestScanGuardAssumptionNote(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "read.js"), []byte(vulnPathGuard), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var pathF *findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-PATH-001" {
			pathF = f
		}
	}
	if pathF == nil {
		t.Fatalf("expected a path-traversal finding (unsound prefix guard must NOT suppress), got %d findings", len(fs))
	}
	noted := false
	for _, ne := range pathF.NegationEvidence {
		if strings.Contains(ne.Clause, "assumption") {
			noted = true
			t.Logf("guard assumption note: %s — %s", ne.Clause, ne.Detail)
		}
	}
	if !noted {
		t.Fatalf("path finding behind startsWith must carry a guard assumption note, got NE=%+v", pathF.NegationEvidence)
	}
}

// pyBlocklistGuard guards a path sink with an UNSOUND substring blocklist `if '../' in bar:
// return` (the Python OWASP idiom) — bypassable via an absolute path or encoding. The flow
// must NOT be suppressed; it carries a guard assumption note. pyAllowlist uses the sound
// `x if x in (consts) else d` membership ternary — that one IS suppressed.
const pyBlocklistGuard = `def handler():
    bar = request.cookies.get("x", "")
    if '../' in bar:
        return "bad"
    fd = open(f'/data/{bar}', 'rb')
    return fd

def allow():
    raw = request.cookies.get("y", "")
    safe = raw if raw in ('a', 'b', 'c') else 'a'
    return open(f'/data/{safe}', 'rb')
`

const pyPathlibRelativeToGuard = `from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter()
ROOT = Path("prompts").resolve()

def safe_prompt_path(filename: str) -> Path:
    try:
        resolved = (ROOT / filename).resolve()
        resolved.relative_to(ROOT)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid filename")
    return resolved

@router.get("/{filename}")
def get_prompt(filename: str):
    path = safe_prompt_path(filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
`

func TestScanPythonInOperatorIdioms(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "files.py"), []byte(pyBlocklistGuard), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// the sound allowlist ternary must be suppressed → exactly ONE path finding (the blocklist).
	var pathFs []*findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-PATH-001" {
			pathFs = append(pathFs, f)
		}
	}
	if len(pathFs) != 1 {
		t.Fatalf("expected exactly 1 path finding (allowlist ternary suppressed, blocklist kept), got %d", len(pathFs))
	}
	noted := false
	for _, ne := range pathFs[0].NegationEvidence {
		if strings.Contains(ne.Clause, "assumption") {
			noted = true
			t.Logf("py guard note: %s — %s", ne.Clause, ne.Detail)
		}
	}
	if !noted {
		t.Fatalf("blocklist `if '../' in bar` must carry a guard assumption note, got NE=%+v", pathFs[0].NegationEvidence)
	}
}

func TestScanPythonPathlibRelativeToGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prompts.py"), []byte(pyPathlibRelativeToGuard), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range fs {
		if f.RuleID == "VYQL-PATH-001" {
			t.Fatalf("pathlib resolve+relative_to containment should suppress path traversal finding: %+v", f)
		}
	}
}

// vulnReplaceInsert interpolates user input as the REPLACEMENT argument of .replace() —
// `template.replace('{{value}}', payload)`. The payload is inserted verbatim, NOT filtered,
// so this is a CONFIDENT XSS finding, not a char-filter assumption.
const vulnReplaceInsert = `function handler(req, res) {
  const payload = req.query.value;
  const html = '<article>{{value}}</article>'.replace('{{value}}', payload);
  res.type('html').send(html);
}
`

const vulnerablePhpStoredHtmlWrite = `<?php
class Standard {
  protected function fromArray($item, array $data) {
    foreach ($data as $entry) {
      if (trim($this->val($entry, 'text.content', '')) === '') {
        continue;
      }
      $refItem->fromArray($entry, true)->setType('content');
    }
  }
}`

const fixedPhpStoredHtmlWrite = `<?php
class Standard {
  protected function fromArray($item, array $data) {
    foreach ($data as $entry) {
      if (!( $content = trim($this->val($entry, 'text.content', '')))) {
        continue;
      }
      $purifier = new HTMLPurifier();
      $entry['text.content'] = $purifier->purify($content);
      $refItem->fromArray($entry, true)->setType('content');
    }
  }
}`

func TestScanPhpStoredHtmlWriteRequiresPurifier(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.php"), []byte(vulnerablePhpStoredHtmlWrite), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixed.php"), []byte(fixedPhpStoredHtmlWrite), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var stored []findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-INJ-028" {
			stored = append(stored, *f)
		}
	}
	if len(stored) != 1 {
		t.Fatalf("expected one stored HTML write finding, got %d: %#v", len(stored), fs)
	}
	if !strings.Contains(stored[0].Bindings[0].Loc, "vuln.php") {
		t.Fatalf("stored HTML write finding should be in vuln.php, got %#v", stored[0].Bindings)
	}
}

func TestScanReplaceReplacementNotFiltered(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.js"), []byte(vulnReplaceInsert), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var xss *findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-INJ-004" {
			xss = f
		}
	}
	if xss == nil {
		t.Fatalf("expected an XSS finding for replace-inserted payload, got %d findings", len(fs))
	}
	for _, ne := range xss.NegationEvidence {
		if strings.Contains(ne.Clause, "char-filter") {
			t.Fatalf("payload is the .replace() REPLACEMENT (inserted verbatim), not filtered — must NOT carry a char-filter assumption; got %q", ne.Detail)
		}
	}
}

// javaAssumeIdioms exercises Java parity for the assumption engine: an unsound `.contains()`
// substring blocklist guard (note, not suppress) and a SOUND `Arrays.asList(consts).contains`
// allowlist ternary (suppress). The blocklist case must carry a guard assumption note; the
// allowlist case must not be reported at all.
const javaAssumeIdioms = `import java.io.File;
import java.util.Arrays;
public class T {
  void blocklist(javax.servlet.http.HttpServletRequest req) throws Exception {
    String p = req.getParameter("f");
    if (p.contains("..")) return;
    java.nio.file.Files.readAllBytes(new File(p).toPath());
  }
  void allowlist(javax.servlet.http.HttpServletRequest req) throws Exception {
    String p = req.getParameter("g");
    String safe = Arrays.asList("a.txt", "b.txt").contains(p) ? p : "a.txt";
    java.nio.file.Files.readAllBytes(new File(safe).toPath());
  }
}
`

func TestScanJavaAssumeIdioms(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "T.java"), []byte(javaAssumeIdioms), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var paths []*findings.Finding
	for _, f := range fs {
		if f.RuleID == "VYQL-PATH-001" {
			paths = append(paths, f)
		}
	}
	// the sound allowlist ternary is suppressed → exactly the one blocklist-guarded finding.
	if len(paths) != 1 {
		t.Fatalf("expected exactly 1 path finding (allowlist suppressed, blocklist noted), got %d", len(paths))
	}
	noted := false
	for _, ne := range paths[0].NegationEvidence {
		if strings.Contains(ne.Clause, "assumption") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("blocklist `p.contains(\"..\")` must carry a guard assumption note, got NE=%+v", paths[0].NegationEvidence)
	}
}

// tsEsmLib/tsEsmHandler exercise ES-module `import { x } from './y'` resolution (the modern
// TS/JS idiom) — taint must flow from the source inside the imported helper, through the
// import, to the sink in the handler. (CommonJS require() already resolved; ES imports did
// not, because the specifier was not path-normalized.)
const tsEsmLib = `export function readInput(req, key) {
  return req.query[key];
}
`
const tsEsmHandler = `import { readInput } from './lib';
export function handler(req, res) {
  const raw = readInput(req, 'q');
  res.send('<div>' + raw + '</div>');
}
`

func TestScanESModuleImportResolution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.js"), []byte(tsEsmLib), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "handler.js"), []byte(tsEsmHandler), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, f := range fs {
		if f.RuleID == "VYQL-INJ-004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an XSS finding: taint via ES `import { readInput } from './lib'` must resolve, got %d findings", len(fs))
	}
}

func TestScanPathsNoSource(t *testing.T) {
	rules, _ := loadRules("")
	if _, _, err := scanPaths([]string{t.TempDir()}, rules); err == nil {
		t.Fatal("scanning a dir with no supported source should error")
	}
}

// The full default rule library (vyql/packs/*.vyql) must parse and type-check
// against the ontology with zero errors — every taint rule's source/sink/
// sanitizer is well-typed, every concept resolves.
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
	// the default rules come from the standalone vyql/packs/*.vyql files
	src, err := loadRules("")
	if err != nil || !strings.Contains(src, "code.SqlExecution") {
		t.Fatalf("default rules should load from vyql/packs, got %q err=%v", src, err)
	}
}

// SCA is wired into the live scan: a project with a dependency manifest produces
// reputation findings (malicious / vulnerable) from the shipped JSON data, alongside
// SAST findings, evaluated against the same graph.
func TestScanPathsWiresSCA(t *testing.T) {
	dir := t.TempDir()
	// a source file so the scan has SAST content too, plus a pypi manifest.
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("import flask\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("flask==0.12.2\ncolourama==0.1\nrequests==2.31.0\n"), 0o644)

	rules, _ := loadRules("")
	fs, _, err := scanPaths([]string{dir}, rules)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	byRule := map[string]int{}
	for _, f := range fs {
		byRule[f.RuleID]++
	}
	if byRule["VYQL-SCA-004"] == 0 {
		t.Errorf("expected a MaliciousDependency finding for colourama, got %v", byRule)
	}
	if byRule["VYQL-SCA-001"] == 0 {
		t.Errorf("expected a VulnerableDependency finding for flask@0.12.2, got %v", byRule)
	}
	// the trusted version of requests must NOT add a reputation finding.
	for _, f := range fs {
		for _, b := range f.Bindings {
			if strings.Contains(b.Loc, "requests") {
				t.Errorf("trusted requests should not be flagged: %s @ %s", f.RuleID, b.Loc)
			}
		}
	}
}

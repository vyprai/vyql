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

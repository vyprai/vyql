package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture materializes a throwaway project tree and returns its root.
func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scanFixture runs the same scan path the CLI runs, so a change to the matcher
// is exercised here exactly as a user would hit it.
func scanFixture(t *testing.T, dir string) []string {
	t.Helper()
	allRules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	fs, _, _, err := scanPathsWithProfileDemand([]string{dir}, allRules, "", true)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func hasDeserFinding(rules []string) bool {
	for _, r := range rules {
		if strings.Contains(r, "DESER") {
			return true
		}
	}
	return false
}

// A package whose API happens to expose parse() must not turn every .parse()
// in the project into a deserialization sink. `prettier` is a code formatter,
// and the call here is on a local module, so nothing about this reaches
// prettier at all.
//
// The receiver is deliberately not JSON, url, querystring or Date: those four
// carry exact-path SafeDeserialization checks, so they would pass without any
// receiver scoping and prove nothing.
func TestBareMethodDoesNotMatchForeignReceiver(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"t","devDependencies":{"prettier":"^3.0.0"}}`,
		"csvutil.js":   "exports.parse = function (s) { return String(s).split(','); };\n",
		"app.js": "const csv = require('./csvutil');\n" +
			"function handler(req, res) {\n" +
			"  return csv.parse(req.body);\n" +
			"}\n",
	})

	if rules := scanFixture(t, dir); hasDeserFinding(rules) {
		t.Fatalf("a local csv.parse reported as deserialization: %v", rules)
	}
}

// The four names PR #17 whitelisted must stay clean as well.
func TestBuiltinParsersAreNotDeserialization(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"t","devDependencies":{"prettier":"^3.0.0"}}`,
		"app.js": "function handler(req, res) {\n" +
			"  return JSON.parse(req.body);\n" +
			"}\n",
	})

	if rules := scanFixture(t, dir); hasDeserFinding(rules) {
		t.Fatalf("JSON.parse reported as deserialization: %v", rules)
	}
}

// The genuine case must survive: a call actually made on the gated package.
func TestBareMethodStillMatchesOwnReceiver(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"t","dependencies":{"node-serialize":"^0.0.4"}}`,
		"app.js": "const serialize = require('node-serialize');\n" +
			"function handler(req, res) {\n" +
			"  return serialize.unserialize(req.body);\n" +
			"}\n",
	})

	if rules := scanFixture(t, dir); !hasDeserFinding(rules) {
		t.Fatalf("node-serialize.unserialize is a real sink and must still be reported: %v", rules)
	}
}

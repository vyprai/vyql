package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
)

// writeBundleTree lays down the shape a committed frontend has: one minified
// bundle (a single enormous line of dense, valid JavaScript — what a bundler
// emits as umi.<hash>.async.js / index-<hash>.js) next to one ordinary
// multi-line source file.
func writeBundleTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var bundle strings.Builder
	bundle.WriteString("!function(e,t){")
	for i := 0; bundle.Len() < 32<<10; i++ {
		bundle.WriteString("e['k" + strconv.Itoa(i) + "']=function(n){return n+i*(n-i)};")
	}
	bundle.WriteString("}(window,this);")
	files := map[string]string{
		"bundle.js": bundle.String(),
		"app.js":    "function app(n) {\n\treturn n + 1;\n}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// A minified bundle is build output, not source: parsing it costs orders of
// magnitude more memory than its size (every token becomes graph nodes), and a
// committed frontend carries enough of them to push a bounded scan past its
// ceiling before any finding is reported. The walk must decline them, count
// them, and keep reading the source beside them.
func TestExtractAllSkipsMinifiedBundles(t *testing.T) {
	dir := writeBundleTree(t)
	prog, _, _, stats, err := extract.All([]string{dir}, nil)
	if err != nil {
		t.Fatalf("extract.All: %v", err)
	}
	if got := stats.Files["javascript"]; got != 1 {
		t.Errorf("parsed javascript files = %d, want 1 (only app.js)", got)
	}
	if stats.Minified != 1 {
		t.Errorf("stats.Minified = %d, want 1", stats.Minified)
	}
	// A skipped bundle is accounted for as minified, not as a file no frontend
	// understood -- otherwise the report reads as a coverage hole.
	if got := stats.Unmatched[".js"]; got != 0 {
		t.Errorf("minified file counted as unmatched (%d), want 0", got)
	}
	for _, m := range prog.Modules {
		if m.File == "bundle.js" {
			t.Error("bundle.js was parsed into a module; a minified bundle must be declined")
		}
	}
}

// Naming a file explicitly is an instruction to scan that file, whatever its
// shape — the same rule the -max-file-size ceiling follows.
func TestExtractAllScansAMinifiedFileNamedDirectly(t *testing.T) {
	dir := writeBundleTree(t)
	_, _, _, stats, err := extract.All([]string{filepath.Join(dir, "bundle.js")}, nil)
	if err != nil {
		t.Fatalf("extract.All: %v", err)
	}
	if got := stats.Files["javascript"]; got != 1 {
		t.Errorf("parsed javascript files = %d, want 1 for a directly named file", got)
	}
	if stats.Minified != 0 {
		t.Errorf("stats.Minified = %d, want 0 for a directly named file", stats.Minified)
	}
}

// The dependency pass reads vendored library banners through the plain walk,
// and a bundle's banner is exactly where a committed frontend names its
// libraries. The gate belongs to the analysis pipeline, not to the walk, so
// this pins the layer it must stay in.
func TestWalkStillListsMinifiedBundlesForSCA(t *testing.T) {
	dir := writeBundleTree(t)
	found := false
	for _, e := range treesitter.ListAllFiles(dir) {
		if strings.HasSuffix(e.Path, "bundle.js") {
			found = true
		}
	}
	if !found {
		t.Error("ListAllFiles dropped bundle.js; SCA reads vendored banners through this walk")
	}
}

// The gate is scoped to the JavaScript family, where one enormous line is a
// megabyte of code. In another language the same shape is a data blob behind a
// single literal — one node to parse, none of a bundle's cost — and a tree
// carrying one (an embedded fixture, a certificate) must keep reading it.
func TestExtractAllStillParsesAOneLineNonJavaScriptBlob(t *testing.T) {
	dir := t.TempDir()
	body := "package app\n\nvar big = `" + strings.Repeat("x", 40<<10) + "`\n"
	if err := os.WriteFile(filepath.Join(dir, "big.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write big.go: %v", err)
	}
	_, _, _, stats, err := extract.All([]string{dir}, nil)
	if err != nil {
		t.Fatalf("extract.All: %v", err)
	}
	if got := stats.Files["go"]; got != 1 {
		t.Errorf("parsed go files = %d, want 1 (a one-line Go blob is not a bundle)", got)
	}
	if stats.Minified != 0 {
		t.Errorf("stats.Minified = %d, want 0 for a non-JavaScript file", stats.Minified)
	}
}

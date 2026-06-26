package main

// T11 (plan/test-coverage-tasklist.md): CLI surface. main_test covers dispatch/no-source;
// this covers the output formats, the --profile flag, and invalid-rules error handling.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNeutralPy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := "def h():\n    value = 'hello'\n    emit(value)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunOutputFormats(t *testing.T) {
	dir := writeNeutralPy(t)
	for _, format := range []string{"text", "sarif"} {
		if err := run([]string{dir}, "", format, "auto", false, false); err != nil {
			t.Errorf("run(format=%s) errored: %v", format, err)
		}
	}
}

func TestRunWithExplicitProfile(t *testing.T) {
	dir := writeNeutralPy(t)
	for _, prof := range []string{"auto", "generic", "web", "cli"} {
		if err := run([]string{dir}, "", "text", prof, false, false); err != nil {
			t.Errorf("run(--profile %s) errored: %v", prof, err)
		}
	}
}

func TestRunInvalidRulesErrors(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "/no/such/rules.vyql", "text", "auto", false, false); err == nil {
		t.Error("run with a nonexistent --rules path should error, not panic or pass")
	}
}

func TestRunNoSourceErrors(t *testing.T) {
	dir := t.TempDir() // empty — nothing to scan
	if err := run([]string{dir}, "", "text", "auto", false, false); err == nil {
		t.Error("run on a dir with no recognized source should error")
	}
}

func TestRunAllIncludesFlags(t *testing.T) {
	dir := t.TempDir()
	src := `function verify(data, userToken) {
  return data['x-csrf-token'] === userToken;
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	defaultOut, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", false, false)
	})
	if err != nil {
		t.Fatalf("default json scan failed: %v", err)
	}
	if got := strings.TrimSpace(defaultOut); !strings.HasPrefix(got, "[") {
		t.Fatalf("default json should remain a findings array, got %q", got)
	}

	allOut, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", false, true)
	})
	if err != nil {
		t.Fatalf("scan --all json failed: %v", err)
	}
	var payload struct {
		Findings []jsonFinding `json:"findings"`
		Flags    []reviewItem  `json:"flags"`
	}
	if err := json.Unmarshal([]byte(allOut), &payload); err != nil {
		t.Fatalf("scan --all json should be an object payload: %v\n%s", err, allOut)
	}
	found := false
	for _, flag := range payload.Flags {
		if flag.Concept == "code.SecretComparisonReview" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scan --all should include review flags, got %#v", payload.Flags)
	}
}

func TestRunAllRejectsSarif(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "", "sarif", "auto", false, true); err == nil {
		t.Error("scan --all should reject SARIF until flags have a SARIF representation")
	}
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	callErr := fn()
	if err := w.Close(); err != nil && callErr == nil {
		callErr = err
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil && callErr == nil {
		callErr = err
	}
	if err := r.Close(); err != nil && callErr == nil {
		callErr = err
	}
	return buf.String(), callErr
}

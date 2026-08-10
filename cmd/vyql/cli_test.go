package main

// CLI surface. main_test covers dispatch/no-source;
// this covers the output formats, the --profile flag, and invalid-rules error handling.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/review"
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
		if err := run([]string{dir}, "", format, "auto", scanRunOptions{}); err != nil {
			t.Errorf("run(format=%s) errored: %v", format, err)
		}
	}
}

func TestRunWithExplicitProfile(t *testing.T) {
	dir := writeNeutralPy(t)
	for _, prof := range []string{"auto", "generic", "web", "cli"} {
		if err := run([]string{dir}, "", "text", prof, scanRunOptions{}); err != nil {
			t.Errorf("run(--profile %s) errored: %v", prof, err)
		}
	}
}

func TestRunInvalidRulesErrors(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "/no/such/rules.vyql", "text", "auto", scanRunOptions{}); err == nil {
		t.Error("run with a nonexistent --rules path should error, not panic or pass")
	}
}

func TestRunNoSourceErrors(t *testing.T) {
	dir := t.TempDir() // empty — nothing to scan
	if err := run([]string{dir}, "", "text", "auto", scanRunOptions{}); err == nil {
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
		return run([]string{dir}, "", "json", "auto", scanRunOptions{})
	})
	if err != nil {
		t.Fatalf("default json scan failed: %v", err)
	}
	if got := strings.TrimSpace(defaultOut); !strings.HasPrefix(got, "[") {
		t.Fatalf("default json should remain a findings array, got %q", got)
	}

	allOut, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", scanRunOptions{IncludeFlags: true})
	})
	if err != nil {
		t.Fatalf("scan --all json failed: %v", err)
	}
	var payload struct {
		Findings []jsonFinding `json:"findings"`
		Flags    []review.Item `json:"flags"`
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

func TestRunFlagsOnlyJSON(t *testing.T) {
	dir := t.TempDir()
	src := `function verify(data, userToken) {
  return data['x-csrf-token'] === userToken;
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", scanRunOptions{FlagsOnly: true, FlagCategory: "crypto"})
	})
	if err != nil {
		t.Fatalf("scan --flags json failed: %v", err)
	}
	var payload struct {
		Findings []jsonFinding `json:"findings"`
		Flags    []review.Item `json:"flags"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("scan --flags json should be an object payload: %v\n%s", err, out)
	}
	if len(payload.Findings) != 0 {
		t.Fatalf("scan --flags should not include findings, got %#v", payload.Findings)
	}
	if len(payload.Flags) == 0 {
		t.Fatalf("scan --flags should include filtered flags, got %#v", payload.Flags)
	}
	for _, flag := range payload.Flags {
		if flag.Category != "crypto" {
			t.Fatalf("scan --flags category filter leaked %#v", flag)
		}
	}
}

func TestRunAllRejectsSarif(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "", "sarif", "auto", scanRunOptions{IncludeFlags: true}); err == nil {
		t.Error("scan flags should reject SARIF until flags have a SARIF representation")
	}
}

// TestScanAllJsonShapeStable pins the documented stable shape of `scan --all`
// JSON so the contract external/AI callers depend on does not drift: a top-level
// object with exactly "findings" and "flags", and findings keyed by the stable
// field names.
func TestScanAllJsonShapeStable(t *testing.T) {
	dir := t.TempDir()
	src := `function verify(data, userToken) {
  return data['x-csrf-token'] === userToken;
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default scan stays a bare findings array.
	defaultOut, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", scanRunOptions{})
	})
	if err != nil {
		t.Fatalf("default json scan failed: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(defaultOut), &arr); err != nil {
		t.Fatalf("default json should decode as a findings array: %v\n%s", err, defaultOut)
	}

	allOut, err := captureStdout(t, func() error {
		return run([]string{dir}, "", "json", "auto", scanRunOptions{IncludeFlags: true})
	})
	if err != nil {
		t.Fatalf("scan --all json failed: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(allOut), &generic); err != nil {
		t.Fatalf("scan --all json should decode as an object: %v\n%s", err, allOut)
	}
	if _, ok := generic["findings"]; !ok {
		t.Fatalf("scan --all json missing stable key %q: %v", "findings", keysOf(generic))
	}
	if _, ok := generic["flags"]; !ok {
		t.Fatalf("scan --all json missing stable key %q: %v", "flags", keysOf(generic))
	}
	if len(generic) != 2 {
		t.Fatalf("scan --all json should expose exactly findings+flags, got keys %v", keysOf(generic))
	}

	var flags []map[string]any
	if err := json.Unmarshal(generic["flags"], &flags); err != nil {
		t.Fatalf("flags should be an array: %v", err)
	}
	if len(flags) == 0 {
		t.Fatalf("expected at least one flag in scan --all output")
	}
	for _, key := range []string{"concept", "category"} {
		if _, ok := flags[0][key]; !ok {
			t.Fatalf("flag object missing stable field %q: %v", key, flags[0])
		}
	}
}

// TestNoSarifFlagsWithoutExplicitSupport asserts SARIF stays finding-only:
// findings render to SARIF, but any request that would add flags to SARIF is
// rejected until a flags-in-SARIF design is approved.
func TestNoSarifFlagsWithoutExplicitSupport(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "", "sarif", "auto", scanRunOptions{}); err != nil {
		t.Fatalf("findings-only SARIF should succeed: %v", err)
	}
	if err := run([]string{dir}, "", "sarif", "auto", scanRunOptions{IncludeFlags: true}); err == nil {
		t.Error("scan --all SARIF must be rejected until flags have a SARIF representation")
	}
	if err := run([]string{dir}, "", "sarif", "auto", scanRunOptions{FlagsOnly: true}); err == nil {
		t.Error("scan --flags SARIF must be rejected until flags have a SARIF representation")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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

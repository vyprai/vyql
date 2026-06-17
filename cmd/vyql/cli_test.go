package main

// T11 (plan/test-coverage-tasklist.md): CLI surface. main_test covers dispatch/no-source;
// this covers the output formats, the --profile flag, and invalid-rules error handling.

import (
	"os"
	"path/filepath"
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
		if err := run([]string{dir}, "", format, "auto", false); err != nil {
			t.Errorf("run(format=%s) errored: %v", format, err)
		}
	}
}

func TestRunWithExplicitProfile(t *testing.T) {
	dir := writeNeutralPy(t)
	for _, prof := range []string{"auto", "generic", "web", "cli"} {
		if err := run([]string{dir}, "", "text", prof, false); err != nil {
			t.Errorf("run(--profile %s) errored: %v", prof, err)
		}
	}
}

func TestRunInvalidRulesErrors(t *testing.T) {
	dir := writeNeutralPy(t)
	if err := run([]string{dir}, "/no/such/rules.vyql", "text", "auto", false); err == nil {
		t.Error("run with a nonexistent --rules path should error, not panic or pass")
	}
}

func TestRunNoSourceErrors(t *testing.T) {
	dir := t.TempDir() // empty — nothing to scan
	if err := run([]string{dir}, "", "text", "auto", false); err == nil {
		t.Error("run on a dir with no recognized source should error")
	}
}

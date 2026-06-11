package main

// T11 (plan/test-coverage-tasklist.md): CLI surface. main_test covers dispatch/no-source;
// this covers the output formats, the --profile flag, and invalid-rules error handling.

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTaintedPy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := "def h():\n    x = request.args.get('q')\n    cursor.execute('SELECT ' + x)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunOutputFormats(t *testing.T) {
	dir := writeTaintedPy(t)
	for _, format := range []string{"text", "sarif"} {
		if err := run([]string{dir}, "", format, "auto"); err != nil {
			t.Errorf("run(format=%s) errored: %v", format, err)
		}
	}
}

func TestRunWithExplicitProfile(t *testing.T) {
	dir := writeTaintedPy(t)
	for _, prof := range []string{"auto", "generic", "web", "cli"} {
		if err := run([]string{dir}, "", "text", prof); err != nil {
			t.Errorf("run(--profile %s) errored: %v", prof, err)
		}
	}
}

func TestRunInvalidRulesErrors(t *testing.T) {
	dir := writeTaintedPy(t)
	if err := run([]string{dir}, "/no/such/rules.vyql", "text", "auto"); err == nil {
		t.Error("run with a nonexistent --rules path should error, not panic or pass")
	}
}

func TestRunNoSourceErrors(t *testing.T) {
	dir := t.TempDir() // empty — nothing to scan
	if err := run([]string{dir}, "", "text", "auto"); err == nil {
		t.Error("run on a dir with no recognized source should error")
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
)

func writeSizedGoFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	small := "package app\n\nfunc Small() {}\n"
	big := "package app\n\nvar big = `" + strings.Repeat("x", 3<<20) + "`\n"
	for name, body := range map[string]string{"small.go": small, "big.go": big} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func setMaxFileBytesForTest(t *testing.T, n int64) {
	t.Helper()
	prev := treesitter.MaxFileBytes()
	treesitter.SetMaxFileBytes(n)
	t.Cleanup(func() { treesitter.SetMaxFileBytes(prev) })
}

func TestExtractAllSkipsOversizedFilesByDefault(t *testing.T) {
	dir := writeSizedGoFiles(t)
	_, _, _, stats, err := extractAll([]string{dir}, nil)
	if err != nil {
		t.Fatalf("extractAll: %v", err)
	}
	if got := stats.files["go"]; got != 1 {
		t.Errorf("parsed go files = %d, want 1 (3MB file above the 2MiB default)", got)
	}
	if stats.oversized != 1 {
		t.Errorf("stats.oversized = %d, want 1", stats.oversized)
	}
	// A skipped oversized file is accounted for as oversized, not as a file no
	// frontend understood -- otherwise the report reads as a coverage hole.
	if got := stats.unmatched[".go"]; got != 0 {
		t.Errorf("oversized file counted as unmatched (%d), want 0", got)
	}
}

func TestExtractAllScansAnOversizedFileNamedDirectly(t *testing.T) {
	dir := writeSizedGoFiles(t)
	_, _, _, stats, err := extractAll([]string{filepath.Join(dir, "big.go")}, nil)
	if err != nil {
		t.Fatalf("extractAll: %v", err)
	}
	if got := stats.files["go"]; got != 1 {
		t.Errorf("parsed go files = %d, want 1 for a directly named file", got)
	}
}

func TestExtractAllHonorsDisabledCeiling(t *testing.T) {
	setMaxFileBytesForTest(t, 0) // 0 disables the guard
	dir := writeSizedGoFiles(t)
	_, _, _, stats, err := extractAll([]string{dir}, nil)
	if err != nil {
		t.Fatalf("extractAll: %v", err)
	}
	if got := stats.files["go"]; got != 2 {
		t.Errorf("parsed go files = %d, want 2 with the ceiling disabled", got)
	}
}

// Toggling the ceiling changes which files are read, so a cached run must not
// be replayed across the change.
func TestFingerprintTracksMaxFileSize(t *testing.T) {
	dir := writeSizedGoFiles(t)
	a := scanFingerprint(nil, []string{dir}, nil, "auto", "", nil)
	setMaxFileBytesForTest(t, 8<<20)
	b := scanFingerprint(nil, []string{dir}, nil, "auto", "", nil)
	if a == b {
		t.Error("scanFingerprint identical across different -max-file-size ceilings")
	}
}

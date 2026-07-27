package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The size guard exists because nothing capped source size before: the only protection was the
// NAME-based minifiedAsset check, so a generated artifact that does not end in .min.js (a Go
// coverage report, a bundle outside dist/) was parsed in full and exploded into an enormous
// single-file graph.
func writeSized(t *testing.T, dir, name string, size int) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Repeat("x", size)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func withMaxFileBytes(t *testing.T, n int64) {
	t.Helper()
	prev := MaxFileBytes()
	SetMaxFileBytes(n)
	ResetOversizeSkipped()
	t.Cleanup(func() { SetMaxFileBytes(prev); ResetOversizeSkipped() })
}

func TestSizeGuardSkipsOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	writeSized(t, dir, "small.js", 100)
	writeSized(t, dir, "huge.js", 4096)
	withMaxFileBytes(t, 1024)

	got, err := ListFiles(dir, map[string]bool{".js": true})
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(got) != 1 || filepath.Base(got[0]) != "small.js" {
		t.Fatalf("ListFiles = %v, want only small.js", got)
	}
	if n := OversizeSkipped(); n != 1 {
		t.Errorf("OversizeSkipped = %d, want 1", n)
	}

	var bases []string
	for _, e := range ListAllFiles(dir) {
		bases = append(bases, filepath.Base(e.Path))
	}
	if len(bases) != 1 || bases[0] != "small.js" {
		t.Fatalf("ListAllFiles = %v, want only small.js", bases)
	}
}

func TestSizeGuardBoundaryIsInclusive(t *testing.T) {
	dir := t.TempDir()
	writeSized(t, dir, "exact.js", 1024) // exactly at the ceiling must be KEPT
	withMaxFileBytes(t, 1024)

	got, _ := ListFiles(dir, map[string]bool{".js": true})
	if len(got) != 1 {
		t.Fatalf("a file exactly at the ceiling must be kept, got %v", got)
	}
	if n := OversizeSkipped(); n != 0 {
		t.Errorf("OversizeSkipped = %d, want 0", n)
	}
}

func TestSizeGuardDisabled(t *testing.T) {
	dir := t.TempDir()
	writeSized(t, dir, "huge.js", 4096)
	withMaxFileBytes(t, 0) // 0 disables the guard

	got, _ := ListFiles(dir, map[string]bool{".js": true})
	if len(got) != 1 {
		t.Fatalf("guard disabled should keep every file, got %v", got)
	}
	if n := OversizeSkipped(); n != 0 {
		t.Errorf("OversizeSkipped = %d, want 0 when disabled", n)
	}
}

func TestDefaultMaxFileBytesKeepsRealisticSource(t *testing.T) {
	// The default must never drop hand-written code. 2MiB is well above the largest source file
	// in this repo's own tree (~130KB) and well below the generated artifacts it targets.
	if DefaultMaxFileBytes < 1<<20 {
		t.Fatalf("DefaultMaxFileBytes = %d, too small to be safe for hand-written source", DefaultMaxFileBytes)
	}
	dir := t.TempDir()
	writeSized(t, dir, "big-but-real.go", 512<<10) // a 512KB hand-written file still scans
	withMaxFileBytes(t, DefaultMaxFileBytes)
	if got, _ := ListFiles(dir, map[string]bool{".go": true}); len(got) != 1 {
		t.Fatalf("a 512KB source file must not be skipped by the default ceiling, got %v", got)
	}
}

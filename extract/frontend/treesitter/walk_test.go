package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListFilesKeepsBuildPackageUnderSourceRoot(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "src", "main", "java", "com", "example", "build", "dag", "CopyBuildTask.java")
	pkgBuildPath := filepath.Join(dir, "pkg", "build", "types", "types.go")
	outputPath := filepath.Join(dir, "build", "generated", "Generated.java")
	for _, path := range []string{sourcePath, pkgBuildPath, outputPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("class C {}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := ListFiles(dir, map[string]bool{".java": true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPathSuffix(files, "src/main/java/com/example/build/dag/CopyBuildTask.java") {
		t.Fatalf("ListFiles pruned source package directory named build: %v", files)
	}
	goFiles, err := ListFiles(dir, map[string]bool{".go": true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPathSuffix(goFiles, "pkg/build/types/types.go") {
		t.Fatalf("ListFiles pruned Go source package directory named build: %v", goFiles)
	}
	if hasPathSuffix(files, "build/generated/Generated.java") {
		t.Fatalf("ListFiles included top-level build output: %v", files)
	}

	entries := ListAllFiles(dir)
	if !hasEntrySuffix(entries, "src/main/java/com/example/build/dag/CopyBuildTask.java") {
		t.Fatalf("ListAllFiles pruned source package directory named build: %v", entries)
	}
	if !hasEntrySuffix(entries, "pkg/build/types/types.go") {
		t.Fatalf("ListAllFiles pruned Go source package directory named build: %v", entries)
	}
	if hasEntrySuffix(entries, "build/generated/Generated.java") {
		t.Fatalf("ListAllFiles included top-level build output: %v", entries)
	}
}

func hasPathSuffix(paths []string, suffix string) bool {
	for _, path := range paths {
		if strings.HasSuffix(filepath.ToSlash(path), suffix) {
			return true
		}
	}
	return false
}

func hasEntrySuffix(entries []Entry, suffix string) bool {
	for _, entry := range entries {
		if strings.HasSuffix(filepath.ToSlash(entry.Path), suffix) {
			return true
		}
	}
	return false
}

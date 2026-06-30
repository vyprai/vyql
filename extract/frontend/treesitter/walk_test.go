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

func TestListFilesKeepsFirstPartyVendorAssets(t *testing.T) {
	dir := t.TempDir()
	assetPath := filepath.Join(dir, "vendor", "assets", "javascripts", "chartkick.js")
	criPath := filepath.Join(dir, "vendor", "github.com", "containerd", "cri", "pkg", "server", "container_create.go")
	depPath := filepath.Join(dir, "vendor", "bundle", "gems", "dep.js")
	unrelatedGoDepPath := filepath.Join(dir, "vendor", "github.com", "other", "dep", "dep.go")
	for _, path := range []string{assetPath, criPath, depPath, unrelatedGoDepPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("function f() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := ListFiles(dir, map[string]bool{".js": true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPathSuffix(files, "vendor/assets/javascripts/chartkick.js") {
		t.Fatalf("ListFiles pruned first-party vendor asset: %v", files)
	}
	if hasPathSuffix(files, "vendor/bundle/gems/dep.js") {
		t.Fatalf("ListFiles included dependency vendor file: %v", files)
	}
	goFiles, err := ListFiles(dir, map[string]bool{".go": true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasPathSuffix(goFiles, "vendor/github.com/containerd/cri/pkg/server/container_create.go") {
		t.Fatalf("ListFiles pruned vendored containerd CRI source: %v", goFiles)
	}
	if hasPathSuffix(goFiles, "vendor/github.com/other/dep/dep.go") {
		t.Fatalf("ListFiles included unrelated vendored Go source: %v", goFiles)
	}

	entries := ListAllFiles(dir)
	if !hasEntrySuffix(entries, "vendor/assets/javascripts/chartkick.js") {
		t.Fatalf("ListAllFiles pruned first-party vendor asset: %v", entries)
	}
	if hasEntrySuffix(entries, "vendor/bundle/gems/dep.js") {
		t.Fatalf("ListAllFiles included dependency vendor file: %v", entries)
	}
	if !hasEntrySuffix(entries, "vendor/github.com/containerd/cri/pkg/server/container_create.go") {
		t.Fatalf("ListAllFiles pruned vendored containerd CRI source: %v", entries)
	}
	if hasEntrySuffix(entries, "vendor/github.com/other/dep/dep.go") {
		t.Fatalf("ListAllFiles included unrelated vendored Go source: %v", entries)
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

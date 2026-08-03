package treesitter

import (
	"os"
	"path/filepath"
	"strings"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// skipDirs are directories never worth scanning (deps, build output, VCS).
var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true, "dist": true,
	"build": true, "target": true, "__pycache__": true, ".venv": true,
	"venv": true, "testdata": true,
}

var scanHiddenDirs = map[string]bool{
	".github":    true,
	".circleci":  true,
	".buildkite": true,
}

const largeTestResourceMaxBytes = 512 * 1024

// ListFiles walks root and returns files whose extension is in exts (e.g.
// {".py": true}). Dependency/build/VCS directories are skipped.
func ListFiles(root string, exts map[string]bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(root, path, d) {
			return nil
		}
		// match by extension, or by basename for extensionless files (e.g. Dockerfile).
		if exts[strings.ToLower(filepath.Ext(path))] || exts[strings.ToLower(filepath.Base(path))] {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// ListAllFiles walks root ONCE and returns every regular file (dependency/build/VCS dirs
// skipped), each tagged with its lowercased extension and basename. Callers with many language
// filters bucket from this single result instead of walking the tree once per language — on a
// large tree the redundant walks dominated extraction.
type Entry struct {
	Path string
	Ext  string // lowercased extension, e.g. ".py"
	Base string // lowercased basename, e.g. "dockerfile"
}

func ListAllFiles(root string) []Entry {
	var out []Entry
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(root, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(root, path, d) {
			return nil
		}
		out = append(out, Entry{Path: path, Ext: strings.ToLower(filepath.Ext(path)), Base: strings.ToLower(filepath.Base(path))})
		return nil
	})
	return out
}

// FilterEntries returns the paths from entries whose extension or basename is in exts.
func FilterEntries(entries []Entry, exts map[string]bool) []string {
	var out []string
	for _, e := range entries {
		if exts[e.Ext] || exts[e.Base] {
			out = append(out, e.Path)
		}
	}
	return out
}

func shouldSkipDir(root, path, name string) bool {
	if strings.HasPrefix(name, ".") && name != "." {
		return !scanHiddenDirs[name]
	}
	if vendorDirShouldSkip(root, path) {
		return true
	}
	if !skipDirs[name] {
		return false
	}
	if name == "vendor" {
		return false
	}
	if name == "build" {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return true
		}
		return filepath.ToSlash(rel) == "build"
	}
	return true
}

func shouldSkipFile(root, path string, d os.DirEntry) bool {
	info, err := d.Info()
	if err != nil || info.Size() <= largeTestResourceMaxBytes {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return isLargeTestResourcePath(filepath.ToSlash(rel))
}

func isLargeTestResourcePath(rel string) bool {
	parts := strings.Split(rel, "/")
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "__fixtures__", "fixtures":
			return true
		case "test", "tests":
			if i+1 < len(parts) && (parts[i+1] == "resources" || parts[i+1] == "fixtures" || parts[i+1] == "fixtures-js") {
				return true
			}
		}
	}
	return false
}

func vendorDirShouldSkip(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, part := range parts {
		if part != "vendor" {
			continue
		}
		if i == len(parts)-1 {
			return false
		}
		rest := strings.Join(parts[i+1:], "/")
		for _, prefix := range vendoredSourcePrefixes {
			if rest == prefix || strings.HasPrefix(prefix, rest+"/") || strings.HasPrefix(rest, prefix+"/") {
				return false
			}
		}
		return true
	}
	return false
}

var vendoredSourcePrefixes = []string{
	"assets",
	"github.com/containerd/cri",
}

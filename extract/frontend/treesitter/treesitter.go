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
	if !skipDirs[name] {
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

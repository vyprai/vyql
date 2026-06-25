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

// userExcludes are caller-supplied glob patterns (via `vyql scan -exclude`) layered on
// top of skipDirs. Process-global, set once before scanning (the CLI runs one scan per
// invocation; vyqld shells out a fresh process per request, so there's no shared-state
// race). Empty by default — default scanning behavior is unchanged.
var userExcludes []string

// SetExcludes installs the caller's exclude globs. A pattern with no "/" is matched
// (glob) against each path's basename — so `test` prunes every directory named test and
// `*.spec.js` skips those files. A pattern with "/" is matched (glob) against, or treated
// as a substring of, the path relative to the scan root — so `examples/mvc` prunes that
// subtree. Call with nil to clear.
func SetExcludes(patterns []string) {
	out := patterns[:0:0]
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	userExcludes = out
}

// Excludes returns the active user exclude globs (for cache-key fingerprinting, so a
// scan with different -exclude patterns never replays another's cached result).
func Excludes() []string { return userExcludes }

func excluded(base, rel string) bool {
	for _, p := range userExcludes {
		if strings.Contains(p, "/") {
			rel = filepath.ToSlash(strings.TrimPrefix(rel, "/"))
			if ok, _ := filepath.Match(p, rel); ok {
				return true
			}
			if strings.Contains(rel, strings.Trim(p, "/")) {
				return true
			}
			continue
		}
		if p == base {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	return false
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
		rel := strings.TrimPrefix(path, root)
		if d.IsDir() {
			if shouldSkipDir(root, path, d.Name()) || excluded(d.Name(), rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(filepath.Base(path), rel) {
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
		rel := strings.TrimPrefix(path, root)
		if d.IsDir() {
			if shouldSkipDir(root, path, d.Name()) || excluded(d.Name(), rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if excluded(filepath.Base(path), rel) {
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

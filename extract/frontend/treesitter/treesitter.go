package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// skipDirs are directories never worth scanning (deps, build output, VCS).
var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true, "dist": true,
	"build": true, "target": true, "__pycache__": true, ".venv": true,
	"venv": true, "testdata": true,
}

// minifiedAsset matches vendored/minified/bundled web assets (jquery.min.js,
// bootstrap.bundle.min.js, …). These are third-party, single-line, and explode into
// tens of thousands of USG nodes — deep-analyzing them dominates scan time and floods
// findings with false positives, while never containing the target's own vulnerability.
// Skipped by default (no flag): there is no value in analyzing a minified bundle.
func minifiedAsset(base string) bool {
	b := strings.ToLower(base)
	for _, suf := range []string{".min.js", ".min.mjs", ".min.cjs", ".min.css", ".bundle.js", ".bundle.min.js"} {
		if strings.HasSuffix(b, suf) {
			return true
		}
	}
	return false
}

// DefaultMaxFileBytes is the default per-file source size ceiling. Files above it are skipped.
//
// Nothing capped source size before: the only guard was the NAME-based minifiedAsset check, so a
// generated artifact that does not end in .min.js sailed through — a Go coverage report
// (coverage/*.cover.html, which embeds every source file plus a large inline script) or a
// bundled asset in a directory that is not dist/ or node_modules/. Those are machine-generated,
// contain no hand-written vulnerability, and explode into enormous node counts in a SINGLE file,
// which also defeats the per-file bucketing in the adapter flag matcher.
//
// 2 MiB is far above any realistic hand-written source file (the largest in this repo's own tree
// is ~130 KB) and far below the generated artifacts that cause the blowup.
const DefaultMaxFileBytes int64 = 2 << 20

// maxFileBytes is the active ceiling; <= 0 disables the guard.
var maxFileBytes = DefaultMaxFileBytes

// SetMaxFileBytes installs the per-file size ceiling (<= 0 disables it). Process-global and set
// once before scanning, like SetExcludes.
func SetMaxFileBytes(n int64) { maxFileBytes = n }

// MaxFileBytes returns the active ceiling (for cache-key fingerprinting, so a scan with a
// different ceiling never replays another's cached result).
func MaxFileBytes() int64 { return maxFileBytes }

// oversizeSkipped counts files skipped by the size guard during the current scan, so the CLI can
// tell the user what was left out instead of silently dropping it.
var oversizeSkipped atomic.Int64

// OversizeSkipped returns how many files the size guard skipped.
func OversizeSkipped() int64 { return oversizeSkipped.Load() }

// ResetOversizeSkipped zeroes the counter (tests scan repeatedly in one process).
func ResetOversizeSkipped() { oversizeSkipped.Store(0) }

// SkippedFile records one file the walker dropped and why, so `scan -v` can show what was left
// out. Knowing WHICH files were skipped (and which large ones were kept) is how you decide
// whether another guard or ignore is needed.
type SkippedFile struct {
	Path   string
	Reason string // "oversize" | "minified" | "excluded"
	Size   int64
}

// maxRecordedSkips bounds the recorded detail — a tree can skip a very large number of files and
// the list is only ever for human reading. The COUNTS are always exact; only the detail is capped.
const maxRecordedSkips = 500

var (
	skipMu       sync.Mutex
	skippedList  []SkippedFile
	skipCounts   = map[string]int{}
	skipTruncatd int
)

func recordSkip(path, reason string, size int64) {
	skipMu.Lock()
	defer skipMu.Unlock()
	skipCounts[reason]++
	if len(skippedList) < maxRecordedSkips {
		skippedList = append(skippedList, SkippedFile{Path: path, Reason: reason, Size: size})
		return
	}
	skipTruncatd++
}

// SkippedFiles returns the recorded skips, the exact per-reason counts, and how many skips were
// not recorded because the detail list was full.
func SkippedFiles() ([]SkippedFile, map[string]int, int) {
	skipMu.Lock()
	defer skipMu.Unlock()
	out := make([]SkippedFile, len(skippedList))
	copy(out, skippedList)
	counts := make(map[string]int, len(skipCounts))
	for k, v := range skipCounts {
		counts[k] = v
	}
	return out, counts, skipTruncatd
}

// ResetSkipped clears the skip record (tests scan repeatedly in one process).
func ResetSkipped() {
	skipMu.Lock()
	defer skipMu.Unlock()
	skippedList, skipCounts, skipTruncatd = nil, map[string]int{}, 0
	oversizeSkipped.Store(0)
}

// binarySniffBytes is how much of a file's head is inspected for the binary check.
const binarySniffBytes = 512

// binaryFile reports whether a file's head contains a NUL byte, the standard heuristic (git uses
// the same one) for "this is not text".
//
// The generic text-pattern frontend claims essentially every file, so without this a compiled
// binary or a database is parsed as source: one real repo fed in a 141MB Mach-O executable
// (bin/web-cover) and a 6.1MB SQLite db. The size guard happens to catch those two, but only
// because they are large — a small binary would sail through and produce garbage nodes and
// findings. Content, not size, is the right test for "is this source at all".
//
// Unreadable files are treated as text: like the size guard, this only ever skips what it can
// prove should go.
func binaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, binarySniffBytes)
	n, err := f.Read(buf)
	if n <= 0 || (err != nil && n == 0) {
		return false
	}
	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}

// skipReason returns why a walked file should be dropped, or "" to keep it. Checks run
// cheapest-first: name tests, then the stat-based size test, then the content sniff (which costs
// an open+read, so it runs only on files that survived everything else).
func skipReason(path, rel string, d os.DirEntry) string {
	base := filepath.Base(path)
	var size int64
	if info, err := d.Info(); err == nil {
		size = info.Size()
	}
	switch {
	case excluded(base, rel):
		recordSkip(path, "excluded", size)
		return "excluded"
	case minifiedAsset(base):
		recordSkip(path, "minified", size)
		return "minified"
	case maxFileBytes > 0 && size > maxFileBytes:
		oversizeSkipped.Add(1)
		recordSkip(path, "oversize", size)
		return "oversize"
	}
	return ""
}

// keepAsSource applies the content sniff to a file a frontend has CLAIMED by extension. It is
// deliberately not part of skipReason: that runs during the walk on every file in the tree
// (13k+ images and pdfs in one real repo), and paying an open+read there costs ~1.5s to reject
// files no frontend would have looked at anyway. Sniffing at selection time touches only the
// few hundred candidates.
func keepAsSource(path string) bool {
	if !binaryFile(path) {
		return true
	}
	var size int64
	if st, err := os.Stat(path); err == nil {
		size = st.Size()
	}
	recordSkip(path, "binary", size)
	return false
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
		if skipReason(path, rel, d) != "" {
			return nil
		}
		// match by extension, or by basename for extensionless files (e.g. Dockerfile).
		if exts[strings.ToLower(filepath.Ext(path))] || exts[strings.ToLower(filepath.Base(path))] {
			if keepAsSource(path) {
				out = append(out, path)
			}
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
		if skipReason(path, rel, d) != "" {
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
		if (exts[e.Ext] || exts[e.Base]) && keepAsSource(e.Path) {
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

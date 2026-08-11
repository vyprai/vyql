package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/parser"
)

// cachedScan is the gob-serialized whole-scan result stored under a scan fingerprint, so an
// unchanged repo (no source change AND no vyql/ data change) replays instantly instead of
// re-running the pipeline. The fields are spelled out rather than embedding extract.Stats so
// the gob wire format is this file's to change.
type cachedScan struct {
	Findings  []*findings.Finding
	Files     map[string]int
	Languages []string
	// Coverage travels with the findings. A replayed scan that omitted it would
	// drop the "not analysed" warning on exactly the second run of a tree, so
	// the same command would report the same findings with less honesty.
	Excluded  int
	Oversized int
	Unmatched map[string]int
	// ExcludeHits carries the per-pattern counts, keyed by the pattern as written.
	// A replayed scan never walks, so without these the coverage report would
	// mark every pattern as matching nothing -- which is the one thing that
	// report exists to say truthfully.
	ExcludeHits map[string]excludeHit
}

type excludeHit struct {
	Files int
	Dirs  int
}

// scanFingerprint hashes everything a scan's output depends on: the binary (cache salt — a
// rebuild invalidates), the rule source, the active profile, every file under the vyql/ data
// dir (bindings/packs/ontology), and every file under the scan paths. Uses size+mtime (a
// stat, not a read), the conventional incremental-build change signal.
// hashString mixes s into h. hash.Hash documents that Write never returns an
// error, so there is no failure here to handle.
func hashString(h hash.Hash, s string) { _, _ = io.WriteString(h, s) }

func scanFingerprint(salt []byte, paths []string, ruleSources []parser.V2DefinitionSource, profile, overlay string, excludes extract.Excludes) string {
	h := sha256.New()
	h.Write(salt)
	hashString(h, "\x00rules\x00")
	hashString(h, ruleSourcesKey(ruleSources))
	hashString(h, "\x00profile\x00")
	hashString(h, profile)
	hashString(h, "\x00data\x00")
	statWalk(h, datadir.Root())
	if overlay != "" {
		hashString(h, "\x00binding-overlay\x00")
		statWalk(h, overlay)
	}
	// The compiled pattern, not the value as typed: `gen/` and `gen` mean the same
	// thing and must not fingerprint as two different scans.
	for _, ex := range excludes {
		hashString(h, "\x00exclude\x00")
		hashString(h, ex.Pattern)
	}
	// The size ceiling changes which files are read, so it must never replay
	// another ceiling's cached findings.
	hashString(h, "\x00max-file-size\x00")
	hashString(h, strconv.FormatInt(treesitter.MaxFileBytes(), 10))
	for _, p := range paths {
		hashString(h, "\x00src\x00")
		statWalk(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ruleSourcesKey(sources []parser.V2DefinitionSource) string {
	var b strings.Builder
	for _, source := range sources {
		b.WriteString(source.Name)
		b.WriteByte('\x00')
		b.WriteString(source.Source)
		b.WriteByte('\x00')
	}
	return b.String()
}

// statWalk folds each regular file's path, size, and mtime under root into h, in WalkDir's
// deterministic lexical order. VCS/dependency dirs are skipped (they don't affect findings).
//
// The stats run concurrently and the fold stays sequential. This walk is on the warm path --
// it runs before the lookup that is supposed to make a cached scan cheap -- and the data
// directory alone holds thousands of files, most of them the generated package-binding
// corpus. Measured on a warm scan of a small repository, the fingerprint phase was 31.8ms of
// a 90ms run. Every file is still folded, in the same order, so the digest is unchanged; only
// the waiting overlaps.
func statWalk(h hash.Hash, root string) {
	paths := walkFingerprintPaths(root)
	type stamp struct {
		size  int64
		mtime int64
		ok    bool
	}
	stamps := make([]stamp, len(paths))
	workers := min(runtime.GOMAXPROCS(0), len(paths))
	if workers > 1 {
		var wg sync.WaitGroup
		var next atomic.Int64
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1)) - 1
					if i >= len(paths) {
						return
					}
					if info, err := os.Lstat(paths[i]); err == nil {
						stamps[i] = stamp{info.Size(), info.ModTime().UnixNano(), true}
					}
				}
			}()
		}
		wg.Wait()
	} else {
		for i, p := range paths {
			if info, err := os.Lstat(p); err == nil {
				stamps[i] = stamp{info.Size(), info.ModTime().UnixNano(), true}
			}
		}
	}
	// Folded in path order, so the digest does not depend on which worker finished first. A
	// file that could not be stat'd is skipped, exactly as the sequential walk skipped it.
	for i, p := range paths {
		if !stamps[i].ok {
			continue
		}
		hashString(h, p)
		writeStamp(h, stamps[i].size, stamps[i].mtime)
	}
}

// writeStamp folds one file's size and mtime, the conventional incremental-build change
// signal: a stat rather than a read.
func writeStamp(h hash.Hash, size, mtime int64) {
	fmt.Fprintf(h, "|%d|%d\x00", size, mtime)
}

// walkFingerprintPaths lists the files statWalk folds, in WalkDir's lexical order.
func walkFingerprintPaths(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".hg", ".svn":
				return filepath.SkipDir
			case "vendor":
				return nil
			}
			if vendorFingerprintDirShouldSkip(root, p) {
				return filepath.SkipDir
			}
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out
}

func vendorFingerprintDirShouldSkip(root, path string) bool {
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
		for _, prefix := range vendoredFingerprintPrefixes {
			if rest == prefix || strings.HasPrefix(prefix, rest+"/") || strings.HasPrefix(rest, prefix+"/") {
				return false
			}
		}
		return true
	}
	return false
}

var vendoredFingerprintPrefixes = []string{
	"assets",
	"github.com/containerd/cri",
}

// loadCachedScan returns a previously cached scan result for key, if present.
func loadCachedScan(c *parsecache.Cache, key string) (cachedScan, bool) {
	raw, ok := c.GetRaw("scan\x00" + key)
	if !ok {
		return cachedScan{}, false
	}
	var cs cachedScan
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&cs); err != nil {
		return cachedScan{}, false
	}
	return cs, true
}

// storeCachedScan persists a scan result under key.
func storeCachedScan(c *parsecache.Cache, key string, all []*findings.Finding, stats extract.Stats, excludes extract.Excludes) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cachedScanFrom(all, stats, excludes)); err != nil {
		return
	}
	c.PutRaw("scan\x00"+key, buf.Bytes())
}

// cachedScanFrom and statsFromCachedScan are each other's inverse and sit next to each other
// on purpose. They were a literal at the store site and a second literal at the replay site
// in another file, and the two drifted: Oversized was added to one and not the other, so a
// tree's first scan reported files skipped over the size ceiling and every cached scan after
// it reported none.
func cachedScanFrom(all []*findings.Finding, stats extract.Stats, excludes extract.Excludes) cachedScan {
	return cachedScan{
		ExcludeHits: excludeHits(excludes),
		Findings:    all,
		Files:       stats.Files,
		Languages:   stats.Languages,
		Excluded:    stats.Excluded,
		Oversized:   stats.Oversized,
		Unmatched:   stats.Unmatched,
	}
}

// restoreExcludeCounts puts the cached per-pattern counts back on the compiled
// patterns, so a replayed scan reports what it excluded rather than reporting
// that every pattern matched nothing.
func restoreExcludeCounts(cs cachedScan, excludes extract.Excludes) {
	for _, e := range excludes {
		if hit, ok := cs.ExcludeHits[e.Raw]; ok {
			e.Matched, e.PrunedDirs = hit.Files, hit.Dirs
		}
	}
}

func excludeHits(excludes extract.Excludes) map[string]excludeHit {
	if len(excludes) == 0 {
		return nil
	}
	out := make(map[string]excludeHit, len(excludes))
	for _, e := range excludes {
		out[e.Raw] = excludeHit{Files: e.Matched, Dirs: e.PrunedDirs}
	}
	return out
}

func statsFromCachedScan(cs cachedScan) extract.Stats {
	return extract.Stats{
		Files:     cs.Files,
		Languages: cs.Languages,
		Excluded:  cs.Excluded,
		Oversized: cs.Oversized,
		Unmatched: cs.Unmatched,
	}
}

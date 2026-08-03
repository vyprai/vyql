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
	"sort"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/parser"
)

// cachedScan is the gob-serialized whole-scan result stored under a scan fingerprint, so an
// unchanged repo (no source change AND no vyql/ data change) replays instantly instead of
// re-running the pipeline. scanStats' fields are unexported, so its data is carried explicitly.
type cachedScan struct {
	Findings  []*findings.Finding
	Files     map[string]int
	Languages []string
}

// scanFingerprint hashes everything a scan's output depends on: the binary (cache salt — a
// rebuild invalidates), the rule source, the active profile, every file under the vyql/ data
// dir (bindings/packs/ontology), and every file under the scan paths. Uses size+mtime (a
// stat, not a read), the conventional incremental-build change signal.
func scanFingerprint(salt []byte, paths []string, ruleSources []parser.V2DefinitionSource, profile string) string {
	h := sha256.New()
	h.Write(salt)
	io.WriteString(h, "\x00rules\x00")
	io.WriteString(h, ruleSourcesKey(ruleSources))
	io.WriteString(h, "\x00profile\x00")
	io.WriteString(h, profile)
	io.WriteString(h, "\x00data\x00")
	statWalk(h, datadir.Root())
	if overlay := scanBindingOverlay; overlay != "" {
		io.WriteString(h, "\x00binding-overlay\x00")
		statWalk(h, overlay)
	}
	for _, ex := range scanExcludes {
		io.WriteString(h, "\x00exclude\x00")
		io.WriteString(h, ex)
	}
	for _, p := range paths {
		io.WriteString(h, "\x00src\x00")
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
func statWalk(h hash.Hash, root string) {
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
		info, e := d.Info()
		if e != nil {
			return nil
		}
		io.WriteString(h, p)
		fmt.Fprintf(h, "|%d|%d\x00", info.Size(), info.ModTime().UnixNano())
		return nil
	})
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

// statFile folds one file's path+size+mtime into h (skipped silently if it can't be stat'd).
// The building block for fingerprinting a known, bounded file set without walking a tree.
func statFile(h hash.Hash, path string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}
	io.WriteString(h, path)
	fmt.Fprintf(h, "|%d|%d\x00", info.Size(), info.ModTime().UnixNano())
}

// statGlob folds every file matching pattern into h, in sorted order (deterministic).
func statGlob(h hash.Hash, pattern string) {
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	for _, m := range matches {
		statFile(h, m)
	}
}

func statVYQLTreeExcept(h hash.Hash, root string, excludedRelDirs map[string]bool) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(root, p)
			if relErr == nil {
				rel = filepath.ToSlash(rel)
				if excludedRelDirs[rel] {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".vyql") {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		io.WriteString(h, p)
		fmt.Fprintf(h, "|%d|%d\x00", info.Size(), info.ModTime().UnixNano())
		return nil
	})
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
func storeCachedScan(c *parsecache.Cache, key string, all []*findings.Finding, stats scanStats) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cachedScan{Findings: all, Files: stats.files, Languages: stats.languages}); err != nil {
		return
	}
	c.PutRaw("scan\x00"+key, buf.Bytes())
}

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/usg"
)

// manifestParsers maps a dependency-manifest basename to its ecosystem and reader.
var manifestParsers = []struct {
	base  string
	eco   string
	parse func(string) []sca.Dep
}{
	{"requirements.txt", "pypi", sca.ParseRequirements},
	{"setup.py", "pypi", sca.ParseSetupPy},
	{"setup.cfg", "pypi", sca.ParseSetupCfg},
	{"package.json", "npm", sca.ParsePackageJSON},
	{"go.mod", "go", sca.ParseGoMod},
	{"cargo.lock", "git", sca.ParseCargoLockGit},
}

// applySCA discovers dependency manifests under the scanned paths, adds SBOM nodes to the
// graph, then runs the package reputation pipeline per ecosystem and links reachability.
// Manifest/IO errors are non-fatal: package analysis augments a scan, it never gates it.
func applySCA(g usg.Store, paths []string) {
	ecos := map[string]bool{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		root := scanRootFor(p, info)
		entries := entriesForSCAPath(p, info)
		for _, mp := range manifestParsers {
			for _, f := range filesWithBase(entries, mp.base) {
				b, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				deps := mp.parse(string(b))
				if len(deps) == 0 {
					continue
				}
				if sca.BuildSBOM(g, mp.eco, deps, relFrom(p, f)) == nil {
					ecos[mp.eco] = true
				}
			}
		}
		for _, root := range scaRoots(p, info) {
			gm := filepath.Join(root, ".gitmodules")
			b, err := os.ReadFile(gm)
			if err != nil {
				continue
			}
			deps := sca.ParseGitmodules(string(b), gitSubmoduleCommits(root))
			if len(deps) == 0 {
				continue
			}
			if sca.BuildSBOM(g, "git", deps, relFrom(root, gm)) == nil {
				ecos["git"] = true
			}
		}
		for _, f := range vendoredJSFiles(entries) {
			loc := relFrom(root, f)
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			deps := sca.ParseVendoredJS(f, string(b))
			if len(deps) == 0 {
				continue
			}
			if sca.BuildSBOM(g, "npm", deps, loc) == nil {
				ecos["npm"] = true
			}
		}
	}
	if len(ecos) == 0 {
		return
	}
	_ = sca.LinkReachability(g)
	for eco := range ecos {
		_, _, _, _ = sca.Analyze(g, eco)
	}
}

func entriesForSCAPath(p string, info os.FileInfo) []treesitter.Entry {
	if info.IsDir() {
		return treesitter.ListAllFiles(p)
	}
	return []treesitter.Entry{{
		Path: p,
		Ext:  strings.ToLower(filepath.Ext(p)),
		Base: strings.ToLower(filepath.Base(p)),
	}}
}

func filesWithBase(entries []treesitter.Entry, base string) []string {
	base = strings.ToLower(base)
	var out []string
	for _, e := range entries {
		if e.Base == base {
			out = append(out, e.Path)
		}
	}
	return out
}

func scaRoots(p string, info os.FileInfo) []string {
	if info.IsDir() {
		return []string{p}
	}
	if strings.EqualFold(filepath.Base(p), ".gitmodules") {
		return []string{filepath.Dir(p)}
	}
	return nil
}

func vendoredJSFiles(entries []treesitter.Entry) []string {
	const maxVendoredJSSize = 4 << 20
	var out []string
	for _, e := range entries {
		if e.Ext != ".js" {
			continue
		}
		if info, err := os.Stat(e.Path); err == nil && info.Size() <= maxVendoredJSSize {
			out = append(out, e.Path)
		}
	}
	return out
}

func scanRootFor(p string, info os.FileInfo) string {
	if info.IsDir() {
		return p
	}
	return filepath.Dir(p)
}

func gitSubmoduleCommits(root string) map[string]string {
	out := map[string]string{}
	cmd := exec.Command("git", "-C", root, "ls-tree", "-rz", "HEAD")
	b, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, raw := range strings.Split(string(b), "\x00") {
		if raw == "" || !strings.HasPrefix(raw, "160000 ") {
			continue
		}
		meta, path, ok := strings.Cut(raw, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) >= 3 {
			out[path] = fields[2]
		}
	}
	return out
}

// relFrom renders a manifest path relative to the scanned root for tidy finding locations.
func relFrom(root, f string) string {
	if rel, err := filepath.Rel(root, f); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(f)
}

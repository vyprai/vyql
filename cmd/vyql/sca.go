package main

import (
	"os"
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
	{"package.json", "npm", sca.ParsePackageJSON},
}

// applySCA discovers dependency manifests under the scanned paths, adds SBOM nodes to the
// graph, then runs the reputation pipeline (vulnerable / malicious / typosquat /
// unreviewed-version) per ecosystem and links reachability — so SCA rules (SCA-001..004)
// evaluate against the SAME graph as the SAST rules. Manifest/IO errors are non-fatal:
// SCA augments a scan, it never gates it.
func applySCA(g usg.Store, paths []string) {
	ecos := map[string]bool{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		for _, mp := range manifestParsers {
			var files []string
			if info.IsDir() {
				files, _ = treesitter.ListFiles(p, map[string]bool{mp.base: true})
			} else if strings.EqualFold(filepath.Base(p), mp.base) {
				files = []string{p}
			}
			for _, f := range files {
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
	}
	if len(ecos) == 0 {
		return
	}
	_ = sca.LinkReachability(g)
	for eco := range ecos {
		_, _, _, _ = sca.Analyze(g, eco)
	}
}

// relFrom renders a manifest path relative to the scanned root for tidy finding locations.
func relFrom(root, f string) string {
	if rel, err := filepath.Rel(root, f); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(f)
}

// Package sca implements the dependency/SBOM path and the vulnerable-library
// entrypoint projection (docs/20, docs/11), ported from poc/extract/sbom.py
// and advisory.py. Dependency resolution is DECOUPLED from the AST extractor: a
// manifest reader produces sbom.* nodes, an advisory feed marks vulnerable
// versions, and a linker connects code imports to package nodes and flags
// REACHABLE packages. Reachability-gated SCA is then a cross-domain join over
// the SAME graph the SAST extractor populated.
package sca

import (
	"encoding/json"
	"strings"

	"github.com/vyprai/vyql/usg"
)

// Dep is one parsed manifest entry.
type Dep struct {
	Name    string
	Version string
}

// PkgKey identifies a (name, version) pair for advisory lookup.
type PkgKey struct {
	Name    string
	Version string
}

// ParseRequirements is a minimal requirements.txt reader. Lines like
// "name==1.2.3" produce (name, "1.2.3"); other non-comment lines produce
// (name, "*"). Comments (#...) and option lines (-...) are skipped.
func ParseRequirements(content string) []Dep {
	var out []Dep
	for _, raw := range strings.Split(content, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, "=="); i >= 0 {
			out = append(out, Dep{strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+2:])})
		} else {
			out = append(out, Dep{strings.TrimSpace(line), "*"})
		}
	}
	return out
}

// ParsePackageJSON reads an npm package.json's dependencies + devDependencies into
// Deps, normalizing the version range ("^4.17.4" -> "4.17.4") for exact matching.
func ParsePackageJSON(content string) []Dep {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal([]byte(content), &pkg) != nil {
		return nil
	}
	var out []Dep
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, ver := range m {
			out = append(out, Dep{name, normalizeVersion(ver)})
		}
	}
	return out
}

// normalizeVersion strips an npm/semver range prefix (^ ~ >= <= > < =, whitespace) to a
// bare version for exact advisory/malware/trusted matching; "*"/"" /"latest" -> "*".
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=< v")
	if v == "" || v == "*" || strings.EqualFold(v, "latest") || strings.Contains(v, "*") {
		return "*"
	}
	// take the first token of a range like "1.2.0 - 2.0.0" / "1.2 || 1.3".
	if i := strings.IndexAny(v, " |,"); i >= 0 {
		v = v[:i]
	}
	return v
}

// MarkVulnerable labels sbom.PackageVersion nodes that match the explicit advisories map
// ((name,version)->advisory id) as sbom.VulnerableDependency. Used where advisories come
// from an explicit set rather than the loaded JSON feed (the entrypoint projector, tests).
func MarkVulnerable(g usg.Store, advisories map[PkgKey]string) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.Type != "sbom.PackageVersion" {
			continue
		}
		if adv := advisories[PkgKey{n.Prop("name"), n.Prop("version")}]; adv != "" {
			if err := g.AddLabel(n.ID, usg.Label{Concept: "sbom.VulnerableDependency",
				Provenance: usg.Provenance{Adapter: "sbom.osv"}, Detail: map[string]string{"advisory": adv}}); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildSBOM adds one sbom.PackageVersion node per dependency, tagged with its
// ecosystem ("pypi"/"npm"/…). Reputation labeling (vulnerable/malicious/suspicious) is
// done separately by Analyze, which joins these nodes against the loaded reference data.
func BuildSBOM(g usg.Store, eco string, deps []Dep, manifest string) error {
	if manifest == "" {
		manifest = eco + "-manifest"
	}
	for _, d := range deps {
		nid := "pkg:" + eco + "/" + d.Name + "@" + d.Version
		if err := g.AddNode(usg.Node{ID: nid, Type: "sbom.PackageVersion",
			Props: map[string]string{"loc": manifest + ":" + d.Name, "name": d.Name,
				"version": d.Version, "eco": eco}}); err != nil {
			return err
		}
	}
	return nil
}

// LinkReachability marks each package whose symbols are actually called (any
// code node's callee_path rooted at the package name) with sbom.ReachableSymbol.
// It reuses the import-resolved call graph the SAST frontend already produced.
func LinkReachability(g usg.Store) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, n := range nodes {
		path := n.Prop("callee_path")
		if path == "" {
			continue
		}
		root := path
		if i := strings.IndexAny(root, ".["); i >= 0 {
			root = root[:i]
		}
		if root != "" {
			used[root] = true
		}
	}
	for _, n := range nodes {
		if n.Type == "sbom.PackageVersion" && used[n.Prop("name")] {
			if err := g.AddLabel(n.ID, usg.Label{Concept: "sbom.ReachableSymbol",
				Provenance: usg.Provenance{Adapter: "sbom.linker"}}); err != nil {
				return err
			}
		}
	}
	return nil
}

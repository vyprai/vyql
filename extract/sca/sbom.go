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
		if name, ver, ok := splitRequirement(line); ok {
			out = append(out, Dep{NormalizePackageName(name), normalizeVersion(ver)})
		} else {
			out = append(out, Dep{NormalizePackageName(line), "*"})
		}
	}
	return out
}

func splitRequirement(line string) (name, version string, ok bool) {
	for _, op := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "="} {
		if i := strings.Index(line, op); i >= 0 {
			name = strings.TrimSpace(line[:i])
			version = strings.TrimSpace(line[i+len(op):])
			return name, version, true
		}
	}
	return "", "", false
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
			out = append(out, Dep{NormalizePackageName(name), normalizeVersion(ver)})
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
		name := NormalizePackageName(d.Name)
		version := normalizeVersion(d.Version)
		if name == "" {
			continue
		}
		root := PackageRoot(name)
		nid := "pkg:" + eco + "/" + name + "@" + version
		if err := g.AddNode(usg.Node{ID: nid, Type: "sbom.PackageVersion",
			Props: map[string]string{"loc": manifest + ":" + name, "name": name,
				"version": version, "eco": eco, "package": root, "root": root,
				"purl": "pkg:" + eco + "/" + name + "@" + version}}); err != nil {
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
	used := packageUsage(nodes)
	pkgsByID := map[string]usg.Node{}
	for _, n := range nodes {
		if n.Type != "sbom.PackageVersion" {
			continue
		}
		pkgsByID[n.ID] = n
		for _, imp := range used.imports {
			if packageNodeMatches(n, imp) {
				_ = g.AddEdge(usg.Edge{Type: "DEPENDS_ON", Src: imp.id, Dst: n.ID})
				used.reachable[n.ID] = true
			}
		}
		for callRoot := range used.callRoots {
			if PackageMatches(callRoot, n.Prop("name")) || PackageMatches(callRoot, n.Prop("package")) {
				used.reachable[n.ID] = true
			}
		}
	}
	for id := range used.reachable {
		if _, ok := pkgsByID[id]; !ok {
			continue
		}
		if err := g.AddLabel(id, usg.Label{Concept: "sbom.ReachableSymbol",
			Provenance: usg.Provenance{Adapter: "sbom.linker"}}); err != nil {
			return err
		}
	}
	return nil
}

type importUse struct {
	id      string
	module  string
	pkgRoot string
}

type usageEvidence struct {
	imports   []importUse
	callRoots map[string]bool
	reachable map[string]bool
}

func packageUsage(nodes []usg.Node) usageEvidence {
	used := usageEvidence{callRoots: map[string]bool{}, reachable: map[string]bool{}}
	for _, n := range nodes {
		switch n.Type {
		case "code.Import":
			module := n.Prop("module")
			root := n.Prop("package")
			if root == "" {
				root = n.Prop("root")
			}
			if root == "" {
				root = PackageRoot(module)
			}
			used.imports = append(used.imports, importUse{id: n.ID, module: module, pkgRoot: root})
		default:
			if root := CallRoot(n.Prop("callee_path")); root != "" {
				used.callRoots[root] = true
			}
		}
	}
	return used
}

func packageNodeMatches(n usg.Node, imp importUse) bool {
	return PackageMatches(imp.module, n.Prop("name")) ||
		PackageMatches(imp.pkgRoot, n.Prop("name")) ||
		PackageMatches(imp.module, n.Prop("package")) ||
		PackageMatches(imp.pkgRoot, n.Prop("package"))
}

// Package sca implements the dependency/SBOM path and the vulnerable-library
// entrypoint projection (docs/20, docs/11), ported from poc/extract/sbom.py
// and advisory.py. Dependency resolution is DECOUPLED from the AST extractor: a
// manifest reader produces package nodes, package intelligence adds neutral
// analysis tokens, and VyQL adapters map those tokens to concepts/rules.
package sca

import (
	"encoding/json"
	"sort"
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

// ParseSetupPy reads static setuptools install_requires lists from setup.py.
// It intentionally handles literal lists/tuples only; dynamic Python execution is
// outside the manifest reader's trust boundary.
func ParseSetupPy(content string) []Dep {
	var out []Dep
	const key = "install_requires"
	for off := 0; off < len(content); {
		i := strings.Index(content[off:], key)
		if i < 0 {
			break
		}
		i += off
		off = i + len(key)
		if !identifierBoundary(content, i, off) {
			continue
		}
		j := skipSpace(content, off)
		if j >= len(content) || content[j] != '=' {
			continue
		}
		j = skipSpace(content, j+1)
		if j >= len(content) || (content[j] != '[' && content[j] != '(') {
			continue
		}
		body, end, ok := balancedLiteralBody(content, j)
		if !ok {
			continue
		}
		off = end
		for _, lit := range quotedLiterals(body) {
			if name, ver, ok := splitRequirement(lit); ok {
				out = append(out, Dep{NormalizePackageName(name), normalizeVersion(ver)})
			} else if lit = strings.TrimSpace(lit); lit != "" {
				out = append(out, Dep{NormalizePackageName(lit), "*"})
			}
		}
	}
	return out
}

func identifierBoundary(s string, start, end int) bool {
	isIdent := func(b byte) bool {
		return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
	}
	if start > 0 && isIdent(s[start-1]) {
		return false
	}
	return end >= len(s) || !isIdent(s[end])
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

func balancedLiteralBody(s string, start int) (string, int, bool) {
	open := s[start]
	close := byte(']')
	if open == '(' {
		close = ')'
	}
	depth := 0
	inQuote := byte(0)
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			continue
		}
		if ch == open {
			depth++
			continue
		}
		if ch == close {
			depth--
			if depth == 0 {
				return s[start+1 : i], i + 1, true
			}
		}
	}
	return "", start, false
}

func quotedLiterals(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		quote := s[i]
		if quote != '\'' && quote != '"' {
			continue
		}
		var b strings.Builder
		escaped := false
		for j := i + 1; j < len(s); j++ {
			ch := s[j]
			if escaped {
				b.WriteByte(ch)
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				out = append(out, b.String())
				i = j
				break
			}
			b.WriteByte(ch)
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

// ParseGitmodules turns git submodule pins into SBOM dependencies. .gitmodules carries
// identity (path/url); the checked-out git tree carries the immutable gitlink commit.
func ParseGitmodules(content string, commits map[string]string) []Dep {
	var out []Dep
	var path, url string
	flush := func() {
		if path == "" || url == "" {
			return
		}
		commit := commits[path]
		if commit == "" {
			return
		}
		if name := normalizeGitURL(url); name != "" {
			out = append(out, Dep{NormalizePackageName(name), commit})
		}
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			path, url = "", ""
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "path":
			path = strings.TrimSpace(v)
		case "url":
			url = strings.TrimSpace(v)
		}
	}
	flush()
	return out
}

func normalizeGitURL(url string) string {
	url = strings.TrimSpace(strings.TrimSuffix(url, ".git"))
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "ssh://")
	if strings.HasPrefix(url, "git@") {
		url = strings.TrimPrefix(url, "git@")
		url = strings.Replace(url, ":", "/", 1)
	}
	return url
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
	if i := strings.IndexAny(v, " |,;"); i >= 0 {
		v = v[:i]
	}
	return v
}

const scaPackageEvent = "analysis.sca.package"

// MarkVulnerable records a neutral advisory-match token on package nodes that match the
// explicit advisories map. Used where advisories come from an explicit set rather than
// the loaded JSON feed (the entrypoint projector, tests).
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
			if err := addPackageTokens(g, n.ID, "status=vulnerable", "advisory="+adv); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildSBOM adds one package node per dependency, tagged with its
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
				"purl":        "pkg:" + eco + "/" + name + "@" + version,
				"callee_path": scaPackageEvent, "method": "package",
				"str_args": "kind=package"}}); err != nil {
			return err
		}
	}
	return nil
}

// LinkReachability marks each package whose symbols are actually called (any
// code node's callee_path rooted at the package name) with a neutral reachability token.
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
		if err := addPackageTokens(g, id, "reachable=true"); err != nil {
			return err
		}
	}
	return nil
}

func addPackageTokens(g usg.Store, id string, tokens ...string) error {
	n, ok, err := g.GetNode(id)
	if err != nil || !ok {
		return err
	}
	props := map[string]string{}
	for k, v := range n.Props {
		props[k] = v
	}
	props["callee_path"] = scaPackageEvent
	props["method"] = "package"
	seen := map[string]bool{}
	if existing := props["str_args"]; existing != "" {
		for _, tok := range strings.Split(existing, "\x00") {
			if tok != "" {
				seen[tok] = true
			}
		}
	}
	for _, tok := range tokens {
		if tok != "" {
			seen[tok] = true
		}
	}
	var out []string
	for tok := range seen {
		out = append(out, tok)
	}
	sort.Strings(out)
	props["str_args"] = strings.Join(out, "\x00")
	n.Props = props
	return g.AddNode(n)
}

func hasPackageToken(n usg.Node, token string) bool {
	for _, tok := range strings.Split(n.Prop("str_args"), "\x00") {
		if tok == token {
			return true
		}
	}
	return false
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

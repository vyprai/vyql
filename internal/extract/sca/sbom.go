// Package sca implements the dependency/SBOM path and the vulnerable-library
// Entrypoint projection (docs/20, docs/11). Dependency resolution is
// DECOUPLED from the AST extractor: a
// manifest reader produces package nodes, package intelligence adds neutral
// analysis tokens, and VyQL binding applicators map those tokens to concepts/rules.
package sca

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/usg"
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
// "name==1.2.3" produce (name, "==1.2.3"); other non-comment lines produce
// (name, "*"). Comments (#...) and option lines (-...) are skipped. The
// operator is intentionally preserved so advisory matching can distinguish an
// exact pin from an open range that can resolve to a known-bad release.
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
			out = append(out, Dep{NormalizePackageName(name), ver})
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
				out = append(out, Dep{NormalizePackageName(name), ver})
			} else if lit = strings.TrimSpace(lit); lit != "" {
				out = append(out, Dep{NormalizePackageName(lit), "*"})
			}
		}
	}
	return out
}

// ParseSetupCfg reads static setup.cfg install_requires blocks. It handles the
// common setuptools INI form:
//
// [options]
// install_requires =
//
//	package>=1.0
func ParseSetupCfg(content string) []Dep {
	var out []Dep
	inOptions := false
	inRequires := false
	for _, raw := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inOptions = strings.EqualFold(trimmed, "[options]")
			inRequires = false
			continue
		}
		if !inOptions {
			continue
		}
		if key, value, ok := strings.Cut(trimmed, "="); ok && strings.EqualFold(strings.TrimSpace(key), "install_requires") {
			inRequires = true
			if strings.TrimSpace(value) != "" {
				if name, ver, ok := splitRequirement(value); ok {
					out = append(out, Dep{NormalizePackageName(name), ver})
				}
			}
			continue
		}
		if strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t") {
			if inRequires {
				if name, ver, ok := splitRequirement(trimmed); ok {
					out = append(out, Dep{NormalizePackageName(name), ver})
				} else {
					out = append(out, Dep{NormalizePackageName(trimmed), "*"})
				}
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		inRequires = ok && strings.EqualFold(strings.TrimSpace(key), "install_requires")
		if inRequires && strings.TrimSpace(value) != "" {
			if name, ver, ok := splitRequirement(value); ok {
				out = append(out, Dep{NormalizePackageName(name), ver})
			}
		}
	}
	return out
}

// ParseGoMod reads direct and block-form require directives from go.mod.
// It deliberately ignores replace/exclude directives: the required module/version
// is the dependency identity scanned by the SCA advisory feed.
func ParseGoMod(content string) []Dep {
	var out []Dep
	inRequireBlock := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(stripLineComment(raw))
		if line == "" {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			if dep, ok := parseGoRequireLine(line); ok {
				out = append(out, dep)
			}
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			if dep, ok := parseGoRequireLine(rest); ok {
				out = append(out, dep)
			}
		}
	}
	return out
}

func stripLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

func parseGoRequireLine(line string) (Dep, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Dep{}, false
	}
	name := strings.Trim(fields[0], `"`)
	version := strings.Trim(fields[1], `"`)
	if name == "" || version == "" || strings.Contains(name, "=>") || strings.Contains(version, "=>") {
		return Dep{}, false
	}
	return Dep{NormalizePackageName(name), version}, true
}

// ParseCargoLockGit reads git-sourced Cargo.lock packages into the generic git
// ecosystem. Cargo.lock carries the immutable revision after '#', which is the
// advisory identity for git dependencies.
func ParseCargoLockGit(content string) []Dep {
	var out []Dep
	var source string
	flush := func() {
		if source == "" || !strings.HasPrefix(source, "git+") {
			return
		}
		raw := strings.TrimPrefix(source, "git+")
		url, rev, ok := strings.Cut(raw, "#")
		if !ok || strings.TrimSpace(rev) == "" {
			return
		}
		if name := normalizeGitURL(url); name != "" {
			out = append(out, Dep{NormalizePackageName(name), strings.TrimSpace(rev)})
		}
	}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "[[package]]" {
			flush()
			source = ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "source" {
			continue
		}
		source = tomlStringValue(value)
	}
	flush()
	return out
}

func tomlStringValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 {
		return ""
	}
	quote := raw[0]
	if quote != '"' && quote != '\'' {
		return ""
	}
	var b strings.Builder
	escaped := false
	for i := 1; i < len(raw); i++ {
		ch := raw[i]
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
			return b.String()
		}
		b.WriteByte(ch)
	}
	return ""
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
			version = op + strings.TrimSpace(line[i+len(op):])
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

// ParseNpmrc reads project-local npm runtime pins. Legacy Electron applications
// often record the executable runtime in .npmrc rather than package.json; when
// runtime=electron is present, the Brave Electron runtime version is dependency
// evidence for SCA advisories.
func ParseNpmrc(content string) []Dep {
	values := map[string]string{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(stripHashComment(raw))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		values[key] = value
	}
	if !strings.EqualFold(values["runtime"], "electron") {
		return nil
	}
	version := values["brave_electron_version"]
	if version == "" {
		version = values["target"]
	}
	if version == "" {
		return nil
	}
	return []Dep{{Name: "brave/electron", Version: version}}
}

func stripHashComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// ParseComposerLock reads package pins from Composer's lockfile. It uses the
// resolved package versions rather than composer.json constraints so advisory
// matching sees the exact installed PHP package revision.
func ParseComposerLock(content string) []Dep {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if json.Unmarshal([]byte(content), &lock) != nil {
		return nil
	}
	out := make([]Dep, 0, len(lock.Packages)+len(lock.PackagesDev))
	for _, pkg := range append(lock.Packages, lock.PackagesDev...) {
		name := NormalizePackageName(pkg.Name)
		if name == "" {
			continue
		}
		version := strings.TrimSpace(pkg.Version)
		if version == "" {
			version = "*"
		}
		out = append(out, Dep{name, version})
	}
	return out
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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
	type tokenUpdate struct {
		id     string
		tokens []string
	}
	var updates []tokenUpdate
	if err := rangeStoreNodes(g, func(n usg.Node) bool {
		if n.Type != "sbom.PackageVersion" {
			return true
		}
		if adv := advisories[PkgKey{n.Prop("name"), n.Prop("version")}]; adv != "" {
			updates = append(updates, tokenUpdate{n.ID, []string{"status=vulnerable", "advisory=" + adv}})
		}
		return true
	}); err != nil {
		return err
	}
	for _, update := range updates {
		if err := addPackageTokens(g, update.id, update.tokens...); err != nil {
			return err
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
				"specifier":   normalizeSpecifier(d.Version),
				"callee_path": scaPackageEvent, "method": "package",
				"str_args": "kind=package"}}); err != nil {
			return err
		}
	}
	return nil
}

func normalizeSpecifier(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.Join(strings.Fields(v), "")
	if v == "" {
		return "*"
	}
	return v
}

// LinkReachability marks each package whose symbols are actually called (any
// code node's callee_path rooted at the package name) with a neutral reachability token.
// It reuses the import-resolved call graph the SAST frontend already produced.
func LinkReachability(g usg.Store) error {
	used, err := packageUsage(g)
	if err != nil {
		return err
	}
	reachable := map[string]bool{}
	if err := rangeStoreNodes(g, func(n usg.Node) bool {
		if n.Type != "sbom.PackageVersion" {
			return true
		}
		for _, imp := range used.imports {
			if packageNodeMatches(n, imp) {
				_ = g.AddEdge(usg.Edge{Type: "DEPENDS_ON", Src: imp.id, Dst: n.ID})
				reachable[n.ID] = true
			}
		}
		for callRoot := range used.callRoots {
			if PackageMatches(callRoot, n.Prop("name")) || PackageMatches(callRoot, n.Prop("package")) {
				reachable[n.ID] = true
			}
		}
		return true
	}); err != nil {
		return err
	}
	var ids []string
	for id := range reachable {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
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
}

func packageUsage(g usg.Store) (usageEvidence, error) {
	used := usageEvidence{callRoots: map[string]bool{}}
	err := rangeStoreNodes(g, func(n usg.Node) bool {
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
		return true
	})
	return used, err
}

func packageNodeMatches(n usg.Node, imp importUse) bool {
	return PackageMatches(imp.module, n.Prop("name")) ||
		PackageMatches(imp.pkgRoot, n.Prop("name")) ||
		PackageMatches(imp.module, n.Prop("package")) ||
		PackageMatches(imp.pkgRoot, n.Prop("package"))
}

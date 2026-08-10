// The requirement gate: whether a binding applies at all, given the project's dependencies,
// imports, language and file evidence. Includes the version-range comparison.

package bindings

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/extract/sca"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/usg"
)

func packageEvidence(s usg.Store, tech string, crossLang bool) map[string]bool {
	out := map[string]bool{}
	// only import/SBOM nodes carry package evidence — use the type index (O(result)) instead of
	// scanning every node, since this runs once per binding spec.
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		if !crossLang {
			if t := nodeTechFromNode(n); t != "" && t != tech {
				continue
			}
		}
		addPackageEvidenceName(out, n.Prop("module"))
		addPackageEvidenceName(out, n.Prop("symbol"))
		addPackageEvidenceName(out, n.Prop("package"))
		addPackageEvidenceName(out, n.Prop("root"))
	}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		if n, ok, _ := s.GetNode(id); ok {
			addPackageEvidenceName(out, n.Prop("name"))
		}
	}
	return out
}

func importEvidence(s usg.Store, tech string, crossLang bool) map[string]bool {
	out := map[string]bool{}
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		if !crossLang {
			if t := nodeTechFromNode(n); t != "" && t != tech {
				continue
			}
		}
		addPackageEvidenceName(out, n.Prop("module"))
		addPackageEvidenceName(out, n.Prop("symbol"))
		addPackageEvidenceName(out, n.Prop("package"))
		addPackageEvidenceName(out, n.Prop("root"))
	}
	return out
}

func addPackageEvidenceName(out map[string]bool, raw string) {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return
	}
	out[name] = true
	if root := sca.PackageRoot(name); root != "" {
		out[root] = true
	}
	for _, alias := range sca.ImportAliases(name) {
		out[alias] = true
	}
}

func packageAllowed(want []string, have map[string]bool) bool {
	return newPackageGate(have).allowed(want)
}

type packageGate struct {
	have     map[string]bool
	prefixes map[string]bool
	segments map[string]bool
	cache    map[string]bool
}

func (g *packageGate) allowed(want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if g.inEvidence(w) {
			return true
		}
	}
	return false
}

func (g *packageGate) inEvidence(want string) bool {
	want = sca.NormalizePackageName(want)
	if want == "" {
		return true
	}
	if hit, ok := g.cache[want]; ok {
		return hit
	}
	hit := g.matches(want)
	g.cache[want] = hit
	return hit
}

func (g *packageGate) matches(want string) bool {
	if g.have[want] {
		return true
	}
	if root := sca.PackageRoot(want); root != "" && g.have[root] {
		return true
	}
	if g.prefixes[want] {
		return true
	}
	for _, prefix := range packageGatePrefixes(want) {
		if g.have[prefix] {
			return true
		}
	}
	if !strings.ContainsAny(want, "/.") && g.segments[want] {
		return true
	}
	for _, segment := range packageGatePathSegments(want) {
		if g.have[segment] {
			return true
		}
	}
	return false
}

type requirementGate struct {
	packages   *packageGate
	imports    *packageGate
	versions   map[string][]string
	languages  map[string]bool
	project    map[string]bool
	files      map[string]bool
	filesBuilt bool
	store      usg.Store
	tech       string
	crossLang  bool
}

type requirementEffect struct {
	Allowed             bool
	State               string
	ConfidenceDowngrade int
	Detail              map[string]string
}

func (g *requirementGate) importGate() *packageGate {
	if g.imports == nil {
		g.imports = newPackageGate(importEvidence(g.store, g.tech, g.crossLang))
	}
	return g.imports
}

func (g *requirementGate) languageEvidence() map[string]bool {
	if g.languages != nil {
		return g.languages
	}
	langs := map[string]bool{}
	if g.tech != "" {
		langs[g.tech] = true
	}
	impIDs, _ := g.store.NodesOfType("code.Import")
	for _, id := range impIDs {
		if n, ok, _ := g.store.GetNode(id); ok {
			if t := nodeTechFromNode(n); t != "" {
				langs[t] = true
			}
		}
	}
	g.languages = langs
	return langs
}

func (g *requirementGate) versionEvidence() map[string][]string {
	if g.versions == nil {
		g.versions = dependencyVersionEvidence(g.store)
	}
	return g.versions
}

func (g *requirementGate) projectEvidence() map[string]bool {
	if g.project == nil {
		g.project = projectFactEvidence(g.store)
	}
	return g.project
}

func (g *requirementGate) allowed(packages []string, req *parser.BindingRequirement) bool {
	return g.effect(packages, req).Allowed
}

func (g *requirementGate) effect(packages []string, req *parser.BindingRequirement) requirementEffect {
	if req == nil {
		if g.packages.allowed(packages) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
	return g.evalEffect(*req)
}

func (g *requirementGate) evalEffect(req parser.BindingRequirement) requirementEffect {
	switch req.Op {
	case "":
		return requirementEffect{Allowed: true, State: requirementStateSatisfied}
	case "dependency", "framework":
		if req.Range != "" {
			return g.dependencyVersionEffect(req.Value, req.Range)
		}
		if g.packages.inEvidence(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "import":
		if g.importGate().inEvidence(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "content":
		// A code-literal presence gate: the binding only applies when this literal occurs
		// somewhere in the program. Absent ⇒ the binding's match (which requires the literal)
		// is impossible, so it is gated off — letting a CVE pattern binding skip projects it
		// does not target without scanning their nodes. Matched case-insensitively against the
		// whole-program text corpus (a superset of all node text), consistent with how the
		// predicate value itself is matched.
		//
		// This is a pure performance gate (running an un-gated binding just matches nothing), so it
		// is only evaluated above a node-count threshold: building the corpus is not worth it on
		// small/normal repos, where the binding scan is already cheap. Below the threshold the gate
		// is treated as satisfied and the binding runs unchanged.
		if req.Value == "" || storeNodeCount(g.store) < presenceGateMinNodes ||
			sharedContentContains(g.store, lowerString(req.Value)) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "language":
		langs := g.languageEvidence()
		if langs[lowerString(req.Value)] {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateUnknown
		if len(langs) > 0 {
			state = requirementStateConflicting
		}
		return requirementEffect{Allowed: false, State: state}
	case "file":
		g.ensureFiles()
		if g.files[filepath.ToSlash(req.Value)] {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateMissing
		if len(g.files) == 0 {
			state = requirementStateUnknown
		}
		return requirementEffect{Allowed: false, State: state}
	case "schema":
		name, version, _ := strings.Cut(req.Value, "\x00")
		if name == "nir" && (version == "" || version == "2.0") {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := requirementStateMissing
		if name == "nir" {
			state = requirementStateConflicting
		}
		return requirementEffect{Allowed: false, State: state}
	case "project.has":
		if g.hasProjectFact(req.Value) {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	case "all":
		out := requirementEffect{Allowed: true, State: requirementStateSatisfied}
		for _, child := range req.Args {
			eff := g.evalEffect(child)
			if !eff.Allowed {
				return eff
			}
			out = mergeRequirementEffects(out, eff)
		}
		return out
	case "any":
		var best requirementEffect
		found := false
		for _, child := range req.Args {
			if eff := g.evalEffect(child); eff.Allowed {
				if !found || eff.ConfidenceDowngrade < best.ConfidenceDowngrade {
					best = eff
					found = true
				}
			} else if !found {
				best = preferRequirementFailure(best, eff)
			}
		}
		if found {
			return best
		}
		if best.State == "" {
			best.State = requirementStateMissing
		}
		return best
	case "not":
		if len(req.Args) != 1 {
			return requirementEffect{Allowed: false, State: requirementStateConflicting}
		}
		child := g.evalEffect(req.Args[0])
		switch child.State {
		case requirementStateMissing, requirementStateConflicting:
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		case requirementStateUnknown:
			return requirementEffect{Allowed: false, State: requirementStateUnknown}
		default:
			return requirementEffect{Allowed: !child.Allowed, State: requirementStateSatisfied}
		}
	case "soft":
		if len(req.Args) != 1 {
			return requirementEffect{Allowed: false, State: requirementStateConflicting}
		}
		child := g.evalEffect(req.Args[0])
		if child.Allowed {
			return requirementEffect{Allowed: true, State: requirementStateSatisfied}
		}
		state := child.State
		if state == "" {
			state = requirementStateMissing
		}
		return requirementEffect{
			Allowed:             true,
			State:               state,
			ConfidenceDowngrade: 1,
			Detail: map[string]string{
				"requirement_state": state,
				"requirement":       "soft evidence " + state,
			},
		}
	default:
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
}

func mergeRequirementEffects(a, b requirementEffect) requirementEffect {
	out := a
	out.State = mergeRequirementState(out.State, b.State)
	if b.ConfidenceDowngrade > out.ConfidenceDowngrade {
		out.ConfidenceDowngrade = b.ConfidenceDowngrade
	}
	out.Detail = mergeMappingDetail(out.Detail, b.Detail)
	return out
}

func mergeRequirementState(a, b string) string {
	if a == "" || a == requirementStateSatisfied {
		if b == "" {
			return a
		}
		return b
	}
	if b == "" || b == requirementStateSatisfied {
		return a
	}
	if requirementStateRank(b) > requirementStateRank(a) {
		return b
	}
	return a
}

func preferRequirementFailure(a, b requirementEffect) requirementEffect {
	if a.State == "" || requirementStateRank(b.State) > requirementStateRank(a.State) {
		return b
	}
	return a
}

func requirementStateRank(state string) int {
	switch state {
	case requirementStateConflicting:
		return 3
	case requirementStateUnknown:
		return 2
	case requirementStateMissing:
		return 1
	default:
		return 0
	}
}

func (e requirementEffect) apply(conf string, detail map[string]string) (string, map[string]string) {
	if e.ConfidenceDowngrade > 0 {
		conf = downgradeConfidence(conf, e.ConfidenceDowngrade)
	}
	return conf, mergeMappingDetail(detail, e.Detail)
}

func dependencyVersionEvidence(s usg.Store) map[string][]string {
	out := map[string][]string{}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		version := strings.TrimSpace(n.Prop("version"))
		if version == "" {
			continue
		}
		addPackageVersionEvidence(out, n.Prop("name"), version)
	}
	return out
}

func projectFactEvidence(s usg.Store) map[string]bool {
	out := map[string]bool{}
	ids, _ := s.NodesOfType("project.Fact")
	for _, id := range ids {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		addProjectFactEvidence(out, n.Prop("key"))
		addProjectFactEvidence(out, n.Prop("name"))
		addProjectFactEvidence(out, n.Prop("fact"))
		family := strings.TrimSpace(n.Prop("family"))
		name := strings.TrimSpace(n.Prop("value"))
		if name == "" {
			name = strings.TrimSpace(n.Prop("name"))
		}
		if family != "" && name != "" {
			addProjectFactEvidence(out, family+":"+name)
		}
	}
	return out
}

func addProjectFactEvidence(out map[string]bool, raw string) {
	key := normalizeProjectFactKey(raw)
	if key != "" {
		out[key] = true
	}
}

func normalizeProjectFactKey(raw string) string {
	return lowerString(strings.TrimSpace(filepath.ToSlash(raw)))
}

func (g *requirementGate) hasProjectFact(raw string) bool {
	key := normalizeProjectFactKey(raw)
	if key == "" {
		return false
	}
	if g.projectEvidence()[key] {
		return true
	}
	family, value, ok := strings.Cut(key, ":")
	if ok {
		switch family {
		case "dependency", "package", "dep", "npm", "pypi", "go", "maven", "nuget", "gem", "cargo":
			return g.packages.inEvidence(value)
		case "import":
			return g.importGate().inEvidence(value)
		case "framework":
			return g.packages.inEvidence(value)
		case "language", "lang":
			return g.languageEvidence()[value]
		case "file":
			g.ensureFiles()
			return g.files[filepath.ToSlash(value)]
		}
	}
	return false
}

func addPackageVersionEvidence(out map[string][]string, raw, version string) {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return
	}
	add := func(key string) {
		if key != "" {
			out[key] = append(out[key], version)
		}
	}
	add(name)
	add(sca.PackageRoot(name))
	for _, alias := range sca.ImportAliases(name) {
		add(alias)
	}
}

func (g *requirementGate) dependencyVersionEffect(pkg, expr string) requirementEffect {
	hasPackage := g.packages.inEvidence(pkg)
	hasVersion := false
	versions := g.versionEvidence()
	for _, key := range packageEvidenceKeys(pkg) {
		for _, version := range versions[key] {
			hasVersion = true
			if versionSatisfiesRange(version, expr) {
				return requirementEffect{Allowed: true, State: requirementStateSatisfied}
			}
		}
	}
	switch {
	case hasVersion:
		return requirementEffect{Allowed: false, State: requirementStateConflicting}
	case hasPackage:
		return requirementEffect{Allowed: false, State: requirementStateUnknown}
	default:
		return requirementEffect{Allowed: false, State: requirementStateMissing}
	}
}

func packageEvidenceKeys(raw string) []string {
	name := sca.NormalizePackageName(raw)
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(key string) {
		if key != "" && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	add(name)
	add(sca.PackageRoot(name))
	for _, alias := range sca.ImportAliases(name) {
		add(alias)
	}
	return out
}

func versionSatisfiesRange(version, expr string) bool {
	for _, part := range strings.Fields(expr) {
		if !versionSatisfiesComparator(version, part) {
			return false
		}
	}
	return strings.TrimSpace(expr) != ""
}

func versionSatisfiesComparator(version, cmp string) bool {
	op := "="
	value := cmp
	for _, prefix := range []string{">=", "<=", ">", "<", "==", "="} {
		if strings.HasPrefix(cmp, prefix) {
			op = prefix
			value = strings.TrimSpace(strings.TrimPrefix(cmp, prefix))
			break
		}
	}
	order, ok := compareVersions(version, value)
	if !ok {
		return false
	}
	switch op {
	case "=", "==":
		return order == 0
	case ">=":
		return order >= 0
	case "<=":
		return order <= 0
	case ">":
		return order > 0
	case "<":
		return order < 0
	default:
		return false
	}
}

func compareVersions(a, b string) (int, bool) {
	av, okA := parseVersionParts(a)
	bv, okB := parseVersionParts(b)
	if !okA || !okB {
		return 0, false
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(av) {
			ai = av[i]
		}
		if i < len(bv) {
			bi = bv[i]
		}
		if ai < bi {
			return -1, true
		}
		if ai > bi {
			return 1, true
		}
	}
	return 0, true
}

func parseVersionParts(v string) ([]int, bool) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	raw := strings.Split(v, ".")
	out := make([]int, 0, len(raw))
	for _, part := range raw {
		if part == "" {
			return nil, false
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func (g *requirementGate) ensureFiles() {
	if g.filesBuilt {
		return
	}
	g.filesBuilt = true
	g.files = map[string]bool{}
	rangeNodes(g.store, func(n usg.Node) bool {
		if !g.crossLang {
			if t := nodeTechFromNode(n); t != "" && t != g.tech {
				return true
			}
		}
		if file := locFile(n.Prop("loc")); file != "" {
			g.files[filepath.ToSlash(file)] = true
		}
		return true
	})
}

func packageGatePrefixes(name string) []string {
	var out []string
	for _, sep := range []byte{'.', '/'} {
		for i := strings.IndexByte(name, sep); i >= 0; {
			prefix := name[:i]
			if prefix != "" {
				out = append(out, prefix)
			}
			next := strings.IndexByte(name[i+1:], sep)
			if next < 0 {
				break
			}
			i += 1 + next
		}
	}
	return out
}

func packageGatePathSegments(name string) []string {
	if !strings.Contains(name, "/") {
		return nil
	}
	parts := strings.Split(name, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" && !strings.ContainsAny(part, "/.") {
			out = append(out, part)
		}
	}
	return out
}

// presenceApplicator labels nodes with presence/review concepts emitted by v2
// presenceNode bindings.

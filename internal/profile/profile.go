// Package profile implements application-archetype analysis profiles. A profile
// declares which entry-point source families are active for a kind of application,
// plus fingerprints used to auto-detect the archetype from a project. Profiles
// are authored as VyQL data in vyql/profiles/*.vyql.
package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
)

// Profile is one application archetype.
type Profile struct {
	Name        string
	Title       string
	Priority    int          // tie-breaker when profiles have the same detection score
	Detect      []DetectExpr // v2 project-fact predicates; top-level entries are implicit all(...)
	Entrypoints []string     // active source concept names; empty = all
}

type DetectExpr struct {
	Op    string
	Value string
	Args  []DetectExpr
}

// ActiveSources returns the set of active source concepts as "code.X", or nil
// when the profile imposes no narrowing (every wired source stays active).
func (p Profile) ActiveSources() map[string]bool {
	if len(p.Entrypoints) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, e := range p.Entrypoints {
		// Entrypoints are ontology concepts and must be written qualified. This used to guess a
		// namespace for a bare name -- "code." for everything, with a hand-written exception for
		// UserControlledData, which is "core.". That exception is the tell: the guess had already
		// been wrong once, and the next concept authored bare in another namespace would have
		// been misqualified the same silent way, resolving to nothing and switching off a source
		// family without a word. Deciding what namespace a bare concept lives in is the
		// ontology's business, not a profile's.
		//
		// Every one of the 100 entrypoints across the shipped profiles is already qualified, so
		// this rejects nothing that exists today; it stops a future bare name from being guessed
		// at.
		if !strings.Contains(e, ".") {
			fmt.Fprintf(os.Stderr, "vyql: profile %q: entrypoint %q is not a qualified concept (e.g. code.HttpInput); ignoring\n", p.Name, e)
			continue
		}
		out[e] = true
	}
	return out
}

// Load parses every vyql/profiles/*.vyql into Profiles (generic always present).
func Load() ([]Profile, error) {
	files, err := datadir.ReadVYQLDir("profiles")
	if err != nil {
		return genericProfiles(), fmt.Errorf("load profiles: %w", err)
	}
	return loadSources(files)
}

func loadSources(files []datadir.Source) ([]Profile, error) {
	var out []Profile
	decls, err := parser.ParseV2DefinitionSources(v2DefinitionSources(files))
	if err != nil {
		return genericProfiles(), fmt.Errorf("parse profiles: %w", err)
	}
	for _, d := range decls {
		pd, ok := d.(*parser.ProfileDecl)
		if !ok {
			continue
		}
		detect, err := detectExprs(pd.Fields["detect"])
		if err != nil {
			return genericProfiles(), fmt.Errorf("profile %s: %w", pd.Name, err)
		}
		out = append(out, Profile{
			Name:        pd.Name,
			Title:       str(pd.Fields["title"]),
			Priority:    intField(pd.Fields["priority"]),
			Detect:      detect,
			Entrypoints: list(pd.Fields["entrypoints"]),
		})
	}
	if len(out) == 0 {
		return genericProfiles(), nil
	}
	return out, nil
}

func genericProfiles() []Profile {
	return []Profile{{Name: "generic", Title: "Generic application"}}
}

func v2DefinitionSources(files []datadir.Source) []parser.V2DefinitionSource {
	out := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	return out
}

func detectExprs(raw any) ([]DetectExpr, error) {
	if raw == nil {
		return nil, nil
	}
	exprs, ok := raw.([]parser.V2Expr)
	if !ok {
		return nil, fmt.Errorf("detect must use v2 requirement predicate expressions")
	}
	out := make([]DetectExpr, 0, len(exprs))
	for _, expr := range exprs {
		d, err := detectExpr(expr)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func detectExpr(expr parser.V2Expr) (DetectExpr, error) {
	call, ok := expr.(parser.V2CallExpr)
	if !ok {
		return DetectExpr{}, fmt.Errorf("detect entry must be a requirement predicate call")
	}
	if len(call.NamedArgs) != 0 {
		return DetectExpr{}, fmt.Errorf("detect requirement %s does not support named arguments", call.Name)
	}
	switch call.Name {
	case "all", "any":
		if len(call.Args) == 0 {
			return DetectExpr{}, fmt.Errorf("detect requirement %s needs at least one child", call.Name)
		}
		out := DetectExpr{Op: call.Name, Args: make([]DetectExpr, 0, len(call.Args))}
		for _, arg := range call.Args {
			child, err := detectExpr(arg)
			if err != nil {
				return DetectExpr{}, err
			}
			out.Args = append(out.Args, child)
		}
		return out, nil
	case "not":
		if len(call.Args) != 1 {
			return DetectExpr{}, fmt.Errorf("detect requirement not needs exactly one child")
		}
		child, err := detectExpr(call.Args[0])
		if err != nil {
			return DetectExpr{}, err
		}
		return DetectExpr{Op: call.Name, Args: []DetectExpr{child}}, nil
	case "dependency", "file", "framework", "import", "language", "project.has":
		values, err := detectStringArgs(call)
		if err != nil {
			return DetectExpr{}, err
		}
		if len(values) != 1 {
			return DetectExpr{}, fmt.Errorf("detect requirement %s needs exactly one string argument", call.Name)
		}
		return DetectExpr{Op: call.Name, Value: values[0]}, nil
	default:
		return DetectExpr{}, fmt.Errorf("unknown detect requirement %q", call.Name)
	}
}

func detectStringArgs(call parser.V2CallExpr) ([]string, error) {
	out := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		lit, ok := arg.(parser.V2LiteralExpr)
		if !ok {
			return nil, fmt.Errorf("detect requirement %s expects string arguments", call.Name)
		}
		s, ok := lit.Value.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("detect requirement %s expects non-empty string arguments", call.Name)
		}
		out = append(out, s)
	}
	return out, nil
}

// ByName returns the named profile (ok=false if absent).
func ByName(profiles []Profile, name string) (Profile, bool) {
	for _, p := range profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Detect picks the best-matching profile for a project rooted at the given paths,
// by counting satisfied v2 project-fact predicates; ties use the data-defined
// profile priority, then the order profiles are listed.
// Returns the generic profile when nothing matches.
func Detect(paths []string, profiles []Profile) Profile {
	facts, err := defaultProjectFacts()
	if err != nil {
		// Reported, not returned. Without the vocabulary every predicate scores zero and
		// every project reads as generic -- a silent, total loss of archetype detection
		// that looks exactly like a project with no fingerprints.
		reportOnce("vyql: " + err.Error() + "; profile auto-detection is disabled")
	}
	// The roots are resolved once. Each one costs a stat per marker per ancestor
	// directory, and every file() predicate and every fact walk needs the same answer.
	roots := roots(facts, paths)
	ctx := detectContext{
		roots:     roots,
		facts:     facts,
		manifests: readManifests(facts, roots),
		exts:      collectExts(paths),
		has:       map[string]bool{},
	}
	warnUnknownDetectFacts(facts, profiles)
	best := Profile{Name: "generic", Title: "Generic application (no archetype detected)"}
	bestScore := 0
	for _, p := range profiles {
		if p.Name == "generic" {
			continue
		}
		score := 0
		for _, d := range p.Detect {
			part := ctx.score(d)
			if part == 0 {
				score = 0
				break
			}
			score += part
		}
		if score > bestScore || (score == bestScore && score > 0 && p.Priority > best.Priority) {
			best, bestScore = p, score
		}
	}
	return best
}

type detectContext struct {
	roots     []string
	facts     projectFacts
	manifests string
	exts      map[string]bool
	has       map[string]bool // named project.has() fact -> satisfied, answered once
}

func (c detectContext) score(expr DetectExpr) int {
	switch expr.Op {
	case "all":
		score := 0
		for _, child := range expr.Args {
			part := c.score(child)
			if part == 0 {
				return 0
			}
			score += part
		}
		return score
	case "any":
		score := 0
		for _, child := range expr.Args {
			score += c.score(child)
		}
		return score
	case "not":
		if len(expr.Args) != 1 || c.score(expr.Args[0]) != 0 {
			return 0
		}
		return c.facts.weight("not")
	case "dependency", "framework", "import":
		if depMatch(c.manifests, expr.Value) {
			return c.facts.weight(expr.Op)
		}
	case "language":
		if languagePresent(c.facts, c.exts, expr.Value) {
			return c.facts.weight("language")
		}
	case "file":
		if fileExists(c.roots, expr.Value) {
			return c.facts.weight("file")
		}
	case "project.has":
		// An extension is answered from the inventory already collected; every other
		// value names a fact the data declares and a walk decides.
		if ext, ok := strings.CutPrefix(expr.Value, "ext:"); ok {
			if c.exts[strings.ToLower(ext)] {
				return c.facts.weight("ext")
			}
			return 0
		}
		if c.satisfiesFact(expr.Value) {
			return c.facts.weight("fact")
		}
	}
	return 0
}

// satisfiesFact answers a named project.has() fact, memoised: a fact walks the whole
// project, and several profiles ask for the same one.
func (c detectContext) satisfiesFact(name string) bool {
	if got, ok := c.has[name]; ok {
		return got
	}
	nf, ok := c.facts.fact(name)
	got := ok && nf.satisfiedBy(c.roots)
	c.has[name] = got
	return got
}

func depMatch(manifests, dep string) bool {
	// Case-insensitive: PyPI, npm and most package ecosystems treat names that way,
	// and `pip freeze` writes canonical caps -- Flask, Django, SQLAlchemy -- which must
	// still match the lowercase-authored `dep:` fingerprints. Without (?i) a pinned
	// requirements.txt silently fails web-framework detection and the repo is profiled
	// as something else, which changes which rules run at all.
	pat := `(?i)(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(dep) + `($|[^A-Za-z0-9_])`
	return regexp.MustCompile(pat).FindStringIndex(manifests) != nil
}

// readManifests concatenates the text of the declared dependency manifests under the
// scanned roots, so a dependency() fingerprint can substring-match a declared dep.
func readManifests(facts projectFacts, roots []string) string {
	var b strings.Builder
	for _, root := range roots {
		for _, n := range facts.manifests {
			if data, err := os.ReadFile(filepath.Join(root, n)); err == nil {
				b.Write(data)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func collectExts(paths []string) map[string]bool {
	out := map[string]bool{}
	for _, p := range paths {
		_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err == nil {
				out[strings.ToLower(filepath.Ext(path))] = true
			}
			return nil
		})
	}
	return out
}

func languagePresent(facts projectFacts, exts map[string]bool, language string) bool {
	for _, ext := range facts.languageExts[strings.ToLower(language)] {
		if exts[ext] {
			return true
		}
	}
	return false
}

func fileExists(roots []string, rel string) bool {
	for _, root := range roots {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			return true
		}
	}
	return false
}

func roots(facts projectFacts, paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		root := projectRoot(facts, p)
		if seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
	}
	return out
}

func projectRoot(facts projectFacts, p string) string {
	var base string
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		base = p
	} else {
		base = filepath.Dir(p)
	}
	fallback := filepath.Clean(base)
	for {
		if hasProjectMarker(facts, base) {
			return base
		}
		parent := filepath.Dir(base)
		if parent == base {
			return fallback
		}
		base = parent
	}
}

func hasProjectMarker(facts projectFacts, dir string) bool {
	for _, marker := range facts.projectMarkers {
		if strings.ContainsRune(marker, '*') {
			if matches, _ := filepath.Glob(filepath.Join(dir, marker)); len(matches) > 0 {
				return true
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func intField(v any) int {
	if n, ok := v.(int); ok {
		return n
	}
	s := strings.TrimSpace(str(v))
	if s == "" {
		return 0
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func list(v any) []string {
	s, _ := v.([]string)
	return s
}

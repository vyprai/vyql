// Package profile implements application-archetype analysis profiles. A profile
// declares which entry-point source families are active for a kind of application,
// plus fingerprints used to auto-detect the archetype from a project. Profiles
// are authored as VyQL data in vyql/profiles/*.vyql.
package profile

import (
	"encoding/json"
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
		if strings.Contains(e, ".") {
			// already qualified
		} else if e == "UserControlledData" {
			e = "core." + e
		} else {
			e = "code." + e
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
	ctx := detectContext{
		paths:               paths,
		manifests:           readManifests(paths),
		exts:                collectExts(paths),
		npmPublishable:      npmPublishable(paths),
		manifestPublishable: manifestPublishable(paths),
	}
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
	paths               []string
	manifests           string
	exts                map[string]bool
	npmPublishable      bool
	manifestPublishable bool
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
		return 1
	case "dependency", "framework", "import":
		if depMatch(c.manifests, expr.Value) {
			return 1
		}
	case "language":
		if languagePresent(c.exts, expr.Value) {
			return 1
		}
	case "file":
		if fileExists(c.paths, expr.Value) {
			return 1
		}
	case "project.has":
		switch {
		case expr.Value == "npm:publishable":
			if c.npmPublishable {
				return 2
			}
		case expr.Value == "manifest:publishable":
			if c.manifestPublishable {
				return 2
			}
		case strings.HasPrefix(expr.Value, "ext:"):
			ext := strings.TrimPrefix(expr.Value, "ext:")
			if c.exts[strings.ToLower(ext)] {
				return 1
			}
		}
	}
	return 0
}

// manifestPublishable reports whether the project has a publishable package manifest:
// a *.gemspec (Ruby gem), *.podspec (CocoaPods), Cargo.toml with a [lib] target
// (Rust crate lib), or composer.json with "type":"library" (PHP).
func manifestPublishable(paths []string) bool {
	for _, root := range roots(paths) {
		found := false
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || found {
				return nil
			}
			if d.IsDir() {
				if path != root && (d.Name() == "node_modules" || d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			switch {
			case strings.HasSuffix(name, ".gemspec"), strings.HasSuffix(name, ".podspec"), strings.HasSuffix(name, ".nuspec"):
				found = true
			case strings.HasSuffix(name, ".csproj"):
				// a .NET project that declares NuGet PACKAGE metadata is a publishable
				// artifact; ignore Exe output projects.
				if data, err := os.ReadFile(path); err == nil {
					t := string(data)
					if !strings.Contains(t, "<OutputType>Exe</OutputType>") && !strings.Contains(t, "<OutputType>WinExe</OutputType>") &&
						(strings.Contains(t, "<PackageId>") || strings.Contains(t, "<PackageLicenseExpression>") ||
							strings.Contains(t, "<PackageLicenseFile>") || strings.Contains(t, "<GeneratePackageOnBuild>")) {
						found = true
					}
				}
			case name == "pom.xml":
				// A Maven artifact with hpi/maven-plugin packaging is a publishable plugin.
				// Plain-jar poms are too ambiguous to use as a profile fingerprint.
				if data, err := os.ReadFile(path); err == nil {
					t := string(data)
					if strings.Contains(t, "<packaging>hpi</packaging>") || strings.Contains(t, "<packaging>maven-plugin</packaging>") {
						found = true
					}
				}
			case name == "Cargo.toml":
				if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), "[lib]") {
					found = true
				}
			case name == "composer.json":
				if data, err := os.ReadFile(path); err == nil {
					var pkg struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(data, &pkg) == nil && pkg.Type == "library" {
						found = true // explicit only — absent type is ambiguous (PHP apps omit it)
					}
				}
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
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

func npmPublishable(paths []string) bool {
	for _, root := range roots(paths) {
		found := false
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || found {
				return nil
			}
			if d.IsDir() {
				if path != root && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() != "package.json" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			var pkg struct {
				Private bool            `json:"private"`
				Main    string          `json:"main"`
				Module  string          `json:"module"`
				Exports json.RawMessage `json:"exports"`
				Files   json.RawMessage `json:"files"`
				Types   string          `json:"types"`
				Typings string          `json:"typings"`
				Bin     json.RawMessage `json:"bin"`
			}
			if json.Unmarshal(data, &pkg) != nil || pkg.Private {
				return nil
			}
			// A non-private package that declares any publish surface is publishable.
			// `main` is often omitted (defaults to index.js); also accept files/types/bin.
			if pkg.Main != "" || pkg.Module != "" || len(pkg.Exports) > 0 ||
				len(pkg.Files) > 0 || pkg.Types != "" || pkg.Typings != "" || len(pkg.Bin) > 0 {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}

// readManifests concatenates the text of common dependency manifests under the
// scanned roots, so "dep:x" fingerprints can substring-match a declared dep.
func readManifests(paths []string) string {
	names := []string{"package.json", "requirements.txt", "pyproject.toml", "go.mod",
		"Pipfile", "Pipfile.lock", "poetry.lock", "Gemfile", "Gemfile.lock", "pom.xml",
		"build.gradle", "Cargo.toml", "composer.json"}
	var b strings.Builder
	for _, root := range roots(paths) {
		for _, n := range names {
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

func languagePresent(exts map[string]bool, language string) bool {
	for _, ext := range languageExts[strings.ToLower(language)] {
		if exts[ext] {
			return true
		}
	}
	return false
}

var languageExts = map[string][]string{
	"c":           {".c", ".h"},
	"cpp":         {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"},
	"csharp":      {".cs"},
	"dart":        {".dart"},
	"elixir":      {".ex", ".exs"},
	"go":          {".go"},
	"groovy":      {".groovy"},
	"java":        {".java"},
	"javascript":  {".js", ".jsx", ".mjs", ".cjs"},
	"kotlin":      {".kt", ".kts"},
	"objective-c": {".m", ".mm"},
	"php":         {".php"},
	"python":      {".py"},
	"ruby":        {".rb"},
	"rust":        {".rs"},
	"scala":       {".scala"},
	"swift":       {".swift"},
	"typescript":  {".ts", ".tsx", ".mts", ".cts"},
}

func fileExists(paths []string, rel string) bool {
	for _, root := range roots(paths) {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			return true
		}
	}
	return false
}

func roots(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		root := projectRoot(p)
		if seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
	}
	return out
}

func projectRoot(p string) string {
	var base string
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		base = p
	} else {
		base = filepath.Dir(p)
	}
	fallback := filepath.Clean(base)
	for {
		if hasProjectMarker(base) {
			return base
		}
		parent := filepath.Dir(base)
		if parent == base {
			return fallback
		}
		base = parent
	}
}

func hasProjectMarker(dir string) bool {
	markers := []string{
		".git", "package.json", "setup.py", "setup.cfg", "pyproject.toml", "go.mod",
		"Pipfile", "requirements.txt", "Gemfile", "pom.xml", "build.gradle",
		"Cargo.toml", "composer.json", "AndroidManifest.xml", "Info.plist",
		"Package.swift",
	}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.xcodeproj")); len(matches) > 0 {
		return true
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

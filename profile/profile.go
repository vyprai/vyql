// Package profile implements application-archetype threat-modelling profiles
// (design: plan/threat-profiles.md). A profile declares the trust boundary for a
// kind of application — which entry-point source families are attacker-controlled
// — plus fingerprints used to auto-detect the archetype from a project. Profiles
// are authored as VyQL data in vyql/profiles/*.vyql.
package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
)

// Profile is one application archetype.
type Profile struct {
	Name        string
	Title       string
	Detect      []string // fingerprints: "dep:x" | "file:rel" | "ext:.x"
	Entrypoints []string // active source concept short names ("DomInput"); empty = all
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
	dir := filepath.Join(datadir.Root(), "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []Profile{{Name: "generic", Title: "Generic application"}}, nil
	}
	var out []Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".vyql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		decls, err := parser.Parse(string(b))
		if err != nil {
			continue
		}
		for _, d := range decls {
			pd, ok := d.(*parser.ProfileDecl)
			if !ok {
				continue
			}
			out = append(out, Profile{
				Name:        pd.Name,
				Title:       str(pd.Fields["title"]),
				Detect:      list(pd.Fields["detect"]),
				Entrypoints: list(pd.Fields["entrypoints"]),
			})
		}
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
// by counting fingerprint hits; ties break by the order profiles are listed.
// Returns the generic profile when nothing matches.
func Detect(paths []string, profiles []Profile) Profile {
	manifests := readManifests(paths)
	exts := collectExts(paths)
	best := Profile{Name: "generic", Title: "Generic application (no archetype detected)"}
	bestScore := 0
	for _, p := range profiles {
		if p.Name == "generic" {
			continue
		}
		score := 0
		for _, d := range p.Detect {
			kind, val, _ := strings.Cut(d, ":")
			switch kind {
			case "dep":
				if depMatch(manifests, val) {
					score++
				}
			case "file":
				if fileExists(paths, val) {
					score++
				}
			case "npm":
				if val == "library" && npmLibrary(paths) {
					// A publishable package manifest is a stronger archetype signal than
					// incidental docs/demo frontend files inside the same repository.
					score += 2
				}
			case "manifest":
				if val == "library" && manifestLibrary(paths) {
					score += 2 // a non-npm/python ecosystem library manifest (gem/crate/composer/pod)
				}
			case "ext":
				if exts[strings.ToLower(val)] {
					score++
				}
			}
		}
		if score > bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

// manifestLibrary reports whether the project is a library/SDK in a non-npm/python
// ecosystem, by its PUBLISH manifest: a *.gemspec (Ruby gem), *.podspec (CocoaPods),
// Cargo.toml with a [lib] target (Rust crate lib), or composer.json with "type":"library"
// (PHP). These are unambiguous library signals (apps don't ship them), so they won't flip
// applications — and the OWASP ports have none of them.
func manifestLibrary(paths []string) bool {
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
				// library (apps don't); ignore Exe output projects.
				if data, err := os.ReadFile(path); err == nil {
					t := string(data)
					if !strings.Contains(t, "<OutputType>Exe</OutputType>") && !strings.Contains(t, "<OutputType>WinExe</OutputType>") &&
						(strings.Contains(t, "<PackageId>") || strings.Contains(t, "<PackageLicenseExpression>") ||
							strings.Contains(t, "<PackageLicenseFile>") || strings.Contains(t, "<GeneratePackageOnBuild>")) {
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
	pat := `(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(dep) + `($|[^A-Za-z0-9_])`
	return regexp.MustCompile(pat).FindStringIndex(manifests) != nil
}

func npmLibrary(paths []string) bool {
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
			// A non-private package that declares any publish surface is a library/SDK.
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
		"Gemfile", "Gemfile.lock", "pom.xml", "build.gradle", "Cargo.toml", "composer.json"}
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
			if err == nil && !d.IsDir() {
				out[strings.ToLower(filepath.Ext(path))] = true
			}
			return nil
		})
	}
	return out
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
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			out = append(out, p)
		} else {
			out = append(out, filepath.Dir(p))
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func list(v any) []string {
	s, _ := v.([]string)
	return s
}

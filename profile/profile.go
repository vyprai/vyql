// Package profile implements application-archetype threat-modelling profiles
// (design: plan/threat-profiles.md). A profile declares the trust boundary for a
// kind of application — which entry-point source families are attacker-controlled
// — plus fingerprints used to auto-detect the archetype from a project. Profiles
// are authored as VyQL data in vyql/profiles/*.vyql.
package profile

import (
	"os"
	"path/filepath"
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
		if !strings.HasPrefix(e, "code.") {
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
				if strings.Contains(manifests, val) {
					score++
				}
			case "file":
				if fileExists(paths, val) {
					score++
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

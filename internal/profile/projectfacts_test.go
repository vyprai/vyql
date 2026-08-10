package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
)

// The publishable-package rules are the part of the detection vocabulary that real
// repositories exercise least — the local corpus of 85 project trees reaches npm and
// nothing else — so every ecosystem gets an explicit pair here: the shape that publishes
// and the neighbouring shape that does not. A rule that matched everything would look
// exactly as green as a correct one without the negative case.
func TestPublishableManifestPerEcosystem(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	cases := []struct {
		what  string
		want  string // expected profile
		files map[string]string
	}{
		{"ruby gem", "library", map[string]string{"mylib.gemspec": "Gem::Specification.new\n"}},
		{"cocoapod", "library", map[string]string{"MyLib.podspec": "Pod::Spec.new\n"}},
		{"nuget nuspec", "library", map[string]string{"MyLib.nuspec": "<package/>\n"}},

		{"dotnet package project", "library", map[string]string{
			"MyLib.csproj": "<Project><PropertyGroup><PackageId>MyLib</PackageId></PropertyGroup></Project>\n"}},
		{"dotnet console app is not a package", "generic", map[string]string{
			"App.csproj": "<Project><PropertyGroup><OutputType>Exe</OutputType><PackageId>App</PackageId></PropertyGroup></Project>\n"}},
		{"dotnet project with no package metadata", "generic", map[string]string{
			"App.csproj": "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>\n"}},

		{"maven plugin", "library", map[string]string{
			"pom.xml": "<project><packaging>maven-plugin</packaging></project>\n"}},
		{"jenkins plugin", "library", map[string]string{
			"pom.xml": "<project><packaging>hpi</packaging></project>\n"}},
		{"plain jar pom is too ambiguous", "generic", map[string]string{
			"pom.xml": "<project><packaging>jar</packaging></project>\n"}},

		{"rust crate with a lib target", "library", map[string]string{
			"Cargo.toml": "[package]\nname = \"x\"\n\n[lib]\nname = \"x\"\n"}},
		{"rust binary crate", "generic", map[string]string{
			"Cargo.toml": "[package]\nname = \"x\"\n\n[[bin]]\nname = \"x\"\n"}},

		{"php library", "library", map[string]string{"composer.json": `{"name":"v/x","type":"library"}`}},
		{"php application", "generic", map[string]string{"composer.json": `{"name":"v/x","type":"project"}`}},
		{"php package with no declared type", "generic", map[string]string{"composer.json": `{"name":"v/x"}`}},

		{"private npm package is not publishable", "generic", map[string]string{
			"package.json": `{"name":"x","private":true,"main":"index.js"}`}},
		{"npm package publishing only types", "library", map[string]string{
			"package.json": `{"name":"x","types":"index.d.ts"}`}},
		{"npm package with an empty main", "generic", map[string]string{
			"package.json": `{"name":"x","main":""}`}},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			dir := writeTree(t, c.files)
			if got := Detect([]string{dir}, profiles); got.Name != c.want {
				t.Errorf("Detect = %q, want %q", got.Name, c.want)
			}
		})
	}
}

// A dependency's own manifests must not answer the project's fingerprints. The two facts
// skip different directory sets — npm ignores node_modules, the rest also ignores vendor —
// and that asymmetry is now authored per fact, so it is worth pinning.
func TestPublishableFactsIgnoreVendoredManifests(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	dir := writeTree(t, map[string]string{
		"app.py":                             "print('hi')\n",
		"node_modules/left-pad/package.json": `{"name":"left-pad","main":"index.js"}`,
		"vendor/somegem/somegem.gemspec":     "Gem::Specification.new\n",
	})
	if got := Detect([]string{dir}, profiles); got.Name != "generic" {
		t.Errorf("Detect = %q, want generic — a vendored dependency's manifest is not this project's", got.Name)
	}
}

// language() names live in the data as authored strings rather than as identifiers, which
// is the only reason a hyphenated ecosystem name survives the round trip. No shipped
// profile uses the predicate yet, so nothing else would notice it breaking.
func TestLanguagePredicateResolvesHyphenatedNames(t *testing.T) {
	profiles, err := loadSources([]datadir.Source{{Name: "profiles/objc.vyql", Data: []byte(`module profiles;

profile objc_app {
  detect: [language("objective-c")]
  entrypoints: [code.HttpInput]
  priority: 50
  title: "Objective-C app"
}
`)}})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	dir := writeTree(t, map[string]string{"AppDelegate.m": "@implementation AppDelegate\n@end\n"})
	if got := Detect([]string{dir}, profiles); got.Name != "objc_app" {
		t.Errorf("Detect = %q, want objc_app", got.Name)
	}
	other := writeTree(t, map[string]string{"main.go": "package main\n"})
	if got := Detect([]string{other}, profiles); got.Name != "generic" {
		t.Errorf("Detect = %q, want generic", got.Name)
	}
}

// Every knob the loader requires is required for a reason: a vocabulary missing one of
// them answers every predicate of that kind with zero, and a project with no fingerprints
// is indistinguishable from a project whose fingerprints cannot be evaluated.
func TestProjectFactsLoaderRejectsIncompleteVocabulary(t *testing.T) {
	cases := []struct {
		what string
		src  string
	}{
		{"no manifests", `policy projectFacts default { projectMarkers: [".git"], score { file: 1 } }`},
		{"no project markers", `policy projectFacts default { manifests: ["go.mod"], score { file: 1 } }`},
		{"no score", `policy projectFacts default { manifests: ["go.mod"], projectMarkers: [".git"] }`},
		{"misspelled key", `policy projectFacts default { manifest: ["go.mod"], projectMarkers: [".git"], score { file: 1 } }`},
		{"fact with no match rule", `policy projectFacts default { manifests: ["go.mod"], projectMarkers: [".git"], score { file: 1 }
			fact: [ { name: "x:publishable" } ] }`},
		{"match rule naming no file", `policy projectFacts default { manifests: ["go.mod"], projectMarkers: [".git"], score { file: 1 }
			fact: [ { name: "x:publishable", match: [ { contains: ["lib"] } ] } ] }`},
		{"language with no extension", `policy projectFacts default { manifests: ["go.mod"], projectMarkers: [".git"], score { file: 1 }
			language: [ { name: "go" } ] }`},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			decls, err := parser.ParseV2DefinitionSources([]parser.V2DefinitionSource{
				{Name: "profiles/test.vyql", Source: "module profiles;\n\n" + c.src + "\n"},
			})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := projectFactsFromDecls(decls); err == nil {
				t.Error("loaded an incomplete vocabulary without complaining")
			}
		})
	}
}

// A second vocabulary would make which one is in force depend on file order. The parser
// rejects it before the loader sees it, which is the useful place for this to fail — but
// it is the loader that would silently pick one, so the guarantee is worth a test.
func TestASecondProjectFactsPolicyIsRejected(t *testing.T) {
	one := `policy projectFacts default { manifests: ["go.mod"], projectMarkers: [".git"], score { file: 1 } }`
	decls, err := parser.ParseV2DefinitionSources([]parser.V2DefinitionSource{
		{Name: "profiles/test.vyql", Source: "module profiles;\n\n" + one + "\n\n" + one + "\n"},
	})
	if err == nil {
		if _, err := projectFactsFromDecls(decls); err == nil {
			t.Error("two projectFacts policies loaded without complaining")
		}
		return
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("parse error = %v, want a duplicate-declaration complaint", err)
	}
}

// The shipped vocabulary must actually parse and carry every section, or the checks above
// pass against data nothing ships.
func TestShippedProjectFactsAreComplete(t *testing.T) {
	facts, err := defaultProjectFacts()
	if err != nil {
		t.Fatalf("load shipped project facts: %v", err)
	}
	if len(facts.manifests) < 10 {
		t.Errorf("manifests = %d, expected the shipped ecosystem list", len(facts.manifests))
	}
	if len(facts.projectMarkers) < 10 {
		t.Errorf("projectMarkers = %d, expected the shipped marker list", len(facts.projectMarkers))
	}
	if len(facts.languageExts) < 18 {
		t.Errorf("languages = %d, expected the shipped language table", len(facts.languageExts))
	}
	for _, name := range []string{"npm:publishable", "manifest:publishable"} {
		if _, ok := facts.fact(name); !ok {
			t.Errorf("fact %q is not declared", name)
		}
	}
	// Every project.has() in a shipped profile must name a declared fact or an extension.
	// The predicate that names neither scores zero forever and its profile silently stops
	// competing.
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	for _, p := range profiles {
		for _, d := range p.Detect {
			walkDetect(d, func(e DetectExpr) {
				if e.Op != "project.has" || strings.HasPrefix(e.Value, "ext:") {
					return
				}
				if _, ok := facts.fact(e.Value); !ok {
					t.Errorf("profile %s: project.has(%q) names no declared fact", p.Name, e.Value)
				}
			})
		}
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

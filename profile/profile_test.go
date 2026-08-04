package profile

// Profile auto-detection. Each archetype is
// detected from an unambiguous project fingerprint; an empty project → generic.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
)

func TestProfileAutoDetect(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	if len(profiles) < 10 {
		t.Fatalf("expected the 10 shipped profiles, got %d", len(profiles))
	}

	cases := []struct {
		name  string // expected profile
		files map[string]string
	}{
		{"mobile_android", map[string]string{"AndroidManifest.xml": "<manifest/>"}},
		{"mobile_ios", map[string]string{"Info.plist": "<plist/>"}},
		{"electron", map[string]string{"package.json": `{"dependencies":{"electron":"^28"}}`}},
		{"frontend", map[string]string{"package.json": `{"dependencies":{"react":"^18"}}`}},
		{"web", map[string]string{"requirements.txt": "flask==3.0\n"}},
		{"cli", map[string]string{"go.mod": "module x\nrequire github.com/spf13/cobra v1.8.0\n"}},
		{"worker", map[string]string{"requirements.txt": "celery==5.3\n"}},
		{"api", map[string]string{"requirements.txt": "fastapi==0.110\n"}},
		{"web", map[string]string{"requirements.txt": "flask==1.0.2\nclick==6.7\ncelery==4.2.1\n"}},
		{"web", map[string]string{"Pipfile": "[packages]\nflask = \"*\"\n"}},
		{"library", map[string]string{"setup.py": "from setuptools import setup\n"}},
		{"library", map[string]string{"package.json": `{"name":"pkg","main":"index.js"}`}},
		{"library", map[string]string{"package.json": `{"name":"pkg","author":"Matthew <m@example.test>","main":"index.js"}`}},
		{"library", map[string]string{"package.json": `{"name":"pkg","main":"index.js"}`, "website/src/App.tsx": "export default function App() { return null }\n"}},
		{"library", map[string]string{"package.json": `{"private":true,"workspaces":["packages/*"]}`, "packages/lib/package.json": `{"name":"lib","main":"index.js"}`}},
		{"generic", map[string]string{"hello.txt": "no fingerprints here"}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, body := range c.files {
				p := filepath.Join(dir, n)
				_ = os.MkdirAll(filepath.Dir(p), 0o755)
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := Detect([]string{dir}, profiles)
			if got.Name != c.name {
				t.Errorf("Detect = %q, want %q (fingerprint did not select the right archetype)", got.Name, c.name)
			}
		})
	}
}

func TestLoadSourcesReportsInvalidProfileSyntax(t *testing.T) {
	profiles, err := loadSources([]datadir.Source{{
		Name: "profiles/bad.vyql",
		Data: []byte(`profile bad {}`),
	}})
	if err == nil {
		t.Fatal("loadSources succeeded, want parse error")
	}
	if !strings.Contains(err.Error(), "parse profiles") {
		t.Fatalf("error = %v, want parse profiles context", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "generic" {
		t.Fatalf("fallback profiles = %#v, want generic", profiles)
	}
}

func TestLoadSourcesParsesV2Profiles(t *testing.T) {
	profiles, err := loadSources([]datadir.Source{{
		Name: "profiles/sample.vyql",
		Data: []byte(`module profiles;
profile sample {
  title: "Sample"
  priority: 12
  detect: [any(dependency("sample"), file("sample.toml"))]
  entrypoints: [code.HttpInput, core.UserControlledData]
}`),
	}})
	if err != nil {
		t.Fatalf("loadSources: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(profiles))
	}
	got := profiles[0]
	if got.Name != "sample" || got.Title != "Sample" || got.Priority != 12 {
		t.Fatalf("profile header wrong: %#v", got)
	}
	if len(got.Detect) != 1 || got.Detect[0].Op != "any" || len(got.Detect[0].Args) != 2 {
		t.Fatalf("detect = %#v", got.Detect)
	}
	active := got.ActiveSources()
	if !active["code.HttpInput"] || !active["core.UserControlledData"] {
		t.Fatalf("active sources = %#v", active)
	}
}

func TestLoadSourcesRejectsLegacyDetectFingerprints(t *testing.T) {
	_, err := loadSources([]datadir.Source{{
		Name: "profiles/legacy.vyql",
		Data: []byte(`module profiles;
profile legacy {
  detect: ["dep:legacy"]
}`),
	}})
	if err == nil {
		t.Fatal("loadSources succeeded, want legacy detect rejection")
	}
	if !strings.Contains(err.Error(), "detect entries must be requirement predicate calls") {
		t.Fatalf("error = %v", err)
	}
}

func TestLibraryActivatesPublicAPIInputs(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, ok := ByName(profiles, "library")
	if !ok {
		t.Fatal("library profile not loaded")
	}
	if !p.ActiveSources()["core.UserControlledData"] {
		t.Fatalf("library profile should activate core.UserControlledData")
	}
}

func TestElectronActivatesBuildEnvironmentInputs(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, ok := ByName(profiles, "electron")
	if !ok {
		t.Fatal("electron profile not loaded")
	}
	if !p.ActiveSources()["core.UserControlledData"] {
		t.Fatalf("electron profile should activate core.UserControlledData for build/CI config inputs")
	}
}

func TestNpmLibraryDetectsDotRoot(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"pkg","main":"index.js"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatal(err)
		}
	}()
	if got := Detect([]string{"."}, profiles); got.Name != "library" {
		t.Fatalf("Detect('.') = %q, want library", got.Name)
	}
}

func TestLibraryDetectsFromNestedSourceFile(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte("from setuptools import setup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "pkg", "subpkg", "module.py")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("def f(x):\n    return x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Detect([]string{src}, profiles); got.Name != "library" {
		t.Fatalf("Detect(nested source file) = %q, want library", got.Name)
	}
}

// explicit-by-name lookup is also exercised: ByName resolves each shipped profile.
func TestProfileByName(t *testing.T) {
	profiles, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range []string{"generic", "web", "api", "frontend", "cli", "mobile_android", "mobile_ios", "electron", "library", "worker"} {
		found := false
		for _, p := range profiles {
			if p.Name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("shipped profile %q not loaded", name)
		}
	}
}

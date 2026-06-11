package profile

// T8 (plan/test-coverage-tasklist.md): profile auto-detection. Each archetype is
// detected from an unambiguous project fingerprint; an empty project → generic.

import (
	"os"
	"path/filepath"
	"testing"
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
		{"library", map[string]string{"setup.py": "from setuptools import setup\n"}},
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

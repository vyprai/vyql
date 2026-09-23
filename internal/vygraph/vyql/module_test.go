package vyql

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

func TestLoadDirIsDeterministic(t *testing.T) {
	a, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// A copy with different file creation order and mtimes must load identically:
	// the walk sorts, so the KB is a pure function of the tree contents.
	tmp := t.TempDir()
	var names []string
	err = filepath.WalkDir("testdata/toy", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("testdata/toy", path)
		names = append(names, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Copy in reverse order to scramble creation sequence.
	for i := len(names) - 1; i >= 0; i-- {
		data, err := os.ReadFile(filepath.Join("testdata/toy", names[i]))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, names[i]), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("LoadDir(copy): %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("loading the same tree with different file creation order must be identical")
	}

	if a.Manifest == nil || a.Manifest.Module != "toy" || a.Manifest.Version != "0.1.0" ||
		a.Manifest.RequiresOntology != ">=3" || len(a.Manifest.Imports) != 1 {
		t.Fatalf("manifest = %+v", a.Manifest)
	}
	if got := len(a.Rules()); got != 2 {
		t.Fatalf("rules = %d, want 2", got)
	}
	if got := len(a.Adapters()); got != 1 {
		t.Fatalf("adapters = %d", got)
	}
	if _, ok := a.Onto.Get("code.HttpInput"); !ok {
		t.Fatal("ontology missing code.HttpInput")
	}
}

func TestLoadDirStampsProvenance(t *testing.T) {
	kb, err := LoadDir("testdata/toy")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if kb.Manifest.Provenance != "reviewed" || kb.Trust != graph.TrustReviewed {
		t.Fatalf("manifest provenance = %q, trust = %v; want reviewed", kb.Manifest.Provenance, kb.Trust)
	}
}

func TestLoadDirRejectsDuplicateConcepts(t *testing.T) {
	tmp := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", "module toy { provenance trusted }")
	write("a.vyql", "module toy; concept code.A : source { }")
	write("b.vyql", "module toy; concept code.A : source { }")
	_, err := LoadDir(tmp)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("err = %v, want a duplicate-declaration error", err)
	}
}

func TestLoadDirRejectsMissingManifest(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.vyql"), []byte("module toy; concept code.A : source { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(tmp)
	if err == nil || !strings.Contains(err.Error(), "no manifest") {
		t.Fatalf("err = %v, want a missing-manifest error", err)
	}
}

func TestLoadDirRejectsModuleNameMismatch(t *testing.T) {
	tmp := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("module.vyql", "module toy { provenance trusted }")
	write("a.vyql", "module other; concept code.A : source { }")
	_, err := LoadDir(tmp)
	if err == nil || !strings.Contains(err.Error(), "manifest says") {
		t.Fatalf("err = %v, want a module-name mismatch error", err)
	}
}

package frontend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
)

type topPackageSources struct {
	Schema       int                 `json:"schema"`
	ProjectTypes []string            `json:"project_types"`
	Languages    map[string]langSpec `json:"languages"`
}

type langSpec struct {
	Registries   []string `json:"registries"`
	ProjectTypes []string `json:"project_types"`
}

type topPackageSnapshot struct {
	Schema       int                   `json:"schema"`
	ProjectTypes []string              `json:"project_types"`
	Languages    map[string]langTopSet `json:"languages"`
}

type langTopSet struct {
	Registries   []string     `json:"registries"`
	ProjectTypes []string     `json:"project_types"`
	Target       int          `json:"target"`
	Count        int          `json:"count"`
	Complete     bool         `json:"complete"`
	Packages     []topPackage `json:"packages"`
}

type topPackage struct {
	Rank     int    `json:"rank"`
	Name     string `json:"name"`
	Registry string `json:"registry"`
}

func TestTop1000PackageCoverageSnapshot(t *testing.T) {
	var sources topPackageSources
	mustReadJSON(t, "bindings/packages/top1000.sources.json", &sources)
	var snapshot topPackageSnapshot
	mustReadJSON(t, "bindings/packages/top1000.snapshot.json", &snapshot)

	if sources.Schema != 1 || snapshot.Schema != 1 {
		t.Fatalf("unexpected schema: sources=%d snapshot=%d", sources.Schema, snapshot.Schema)
	}
	if len(sources.ProjectTypes) == 0 {
		t.Fatal("source project_types is empty")
	}
	knownProjectTypes := map[string]bool{}
	for _, typ := range sources.ProjectTypes {
		knownProjectTypes[typ] = true
	}

	for _, lang := range supportedPackageCatalogLanguages(t) {
		t.Run(lang, func(t *testing.T) {
			spec, ok := sources.Languages[lang]
			if !ok {
				t.Fatalf("missing source mapping for %s", lang)
			}
			got, ok := snapshot.Languages[lang]
			if !ok {
				t.Fatalf("missing snapshot for %s", lang)
			}
			if len(spec.Registries) == 0 || len(got.Registries) == 0 {
				t.Fatalf("%s has no package registry mapping", lang)
			}
			if got.Target != 1000 || got.Count != 1000 || !got.Complete || len(got.Packages) != 1000 {
				t.Fatalf("%s top package coverage = target %d count %d complete %v rows %d; want 1000 complete rows",
					lang, got.Target, got.Count, got.Complete, len(got.Packages))
			}
			for _, typ := range spec.ProjectTypes {
				if !knownProjectTypes[typ] {
					t.Fatalf("%s uses unknown project type %q", lang, typ)
				}
			}
			if len(spec.ProjectTypes) == 0 || len(got.ProjectTypes) == 0 {
				t.Fatalf("%s must declare project type coverage", lang)
			}

			seen := map[string]bool{}
			for i, pkg := range got.Packages {
				if pkg.Rank != i+1 {
					t.Fatalf("%s package %d rank = %d", lang, i, pkg.Rank)
				}
				if pkg.Name == "" || pkg.Registry == "" {
					t.Fatalf("%s rank %d has incomplete package row: %+v", lang, i+1, pkg)
				}
				if seen[pkg.Name] {
					t.Fatalf("%s duplicate top package %q", lang, pkg.Name)
				}
				seen[pkg.Name] = true
			}
		})
	}
}

func TestGeneratedPackageBindingSourceRejectsLegacySyntax(t *testing.T) {
	source := datadir.Source{
		Name: "bindings/packages/generated/javascript/legacy.vyql",
		Data: []byte(`adapter javascript { source "req.body" -> code.HttpInput }`),
	}

	_, err := parseGeneratedPackageBindingSource(source)
	if err == nil {
		t.Fatal("generated package binding accepted legacy syntax")
	}
	if !strings.Contains(err.Error(), "invalid generated package binding bindings/packages/generated/javascript/legacy.vyql") {
		t.Fatalf("generated binding error = %v, want generated file context", err)
	}

}

func mustReadJSON(t *testing.T, rel string, dst any) {
	t.Helper()
	b, err := datadir.Read(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
}

func supportedPackageCatalogLanguages(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(datadir.Root(), "bindings", "packages")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read package catalog dir: %v", err)
	}
	var out []string
	for _, entry := range entries {
		var lang string
		if entry.IsDir() {
			if entry.Name() == "generated" {
				continue
			}
			lang = entry.Name()
		} else if filepath.Ext(entry.Name()) == ".vyql" {
			lang = entry.Name()[:len(entry.Name())-len(filepath.Ext(entry.Name()))]
		} else {
			continue
		}
		out = append(out, lang)
	}
	if len(out) != 22 {
		t.Fatalf("supported package catalogs = %d (%v), want 22", len(out), out)
	}
	for _, lang := range out {
		if _, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join("bindings", "packages", lang))); err != nil {
			t.Fatalf("missing catalog for %s: %v", lang, err)
		}
	}
	return out
}

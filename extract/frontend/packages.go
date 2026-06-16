package frontend

// Dynamic, dependency-gated package-adapter loading.
//
// The vyrun batch generates one package-aware adapter per (language, top-1000 package)
// under <data root>/adapters/packages/generated/<lang>/<pkg>.vyql — ~9k mapped catalogs.
// Loading all of them on every scan would parse thousands of files and build a spec with
// tens of thousands of mappings for packages a project never touches. Instead this layer
// loads ONLY the per-package adapters whose package is present in the project's dependency
// evidence (imported modules + SBOM/manifest packages). That is the "dynamic import":
// an adapter for `flask` is parsed and activated only when the scanned code actually
// depends on flask. Each loaded mapping still carries its `package "name"` block, so the
// engine's apply-time packageAllowed gate remains the authoritative second check.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

// generatedRoot is the directory holding the generated per-package adapter corpus,
// laid out as <root>/<lang>/<pkg>.vyql. Defaults to the data dir; $VYQL_PACKAGE_ADAPTERS
// overrides it so an uncommitted corpus can be evaluated without staging into vyql/.
func generatedRoot() string {
	if v := os.Getenv("VYQL_PACKAGE_ADAPTERS"); v != "" {
		return v
	}
	return filepath.Join(datadir.Root(), "adapters", "packages", "generated")
}

// DependencyEvidence collects the project's dependency surface from an already-built
// graph: imported modules/symbols (code.Import) and declared packages (sbom.PackageVersion),
// normalized and expanded to package roots. This is the gate set used to decide which
// generated package adapters to load. It mirrors the per-mapping packageEvidence used at
// apply time but spans all languages (crossLang) so a single call covers a polyglot repo.
func DependencyEvidence(s usg.Store) map[string]bool {
	return packageEvidence(s, "", true)
}

// GeneratedPackageAdaptersFor loads the generated per-package adapters for a language,
// restricted to packages present in deps. Missing corpus, unreadable files, or individual
// files that fail to parse are skipped silently — the generated catalog augments a scan,
// it never breaks one. Returns nil when nothing matches.
func GeneratedPackageAdaptersFor(tech string, deps map[string]bool) []adapters.Adapter {
	if len(deps) == 0 {
		return nil
	}
	dir := filepath.Join(generatedRoot(), tech)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	merged := &parser.AdapterDecl{Name: tech, Meta: map[string]any{}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".vyql") {
			continue
		}
		pkg := strings.TrimSuffix(e.Name(), ".vyql")
		if !packageInEvidence(pkg, deps) {
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
			a, ok := d.(*parser.AdapterDecl)
			if !ok || a.Name != tech {
				continue
			}
			merged.Mappings = append(merged.Mappings, a.Mappings...)
		}
	}
	if len(merged.Mappings) == 0 {
		return nil
	}
	return adaptersFromSpec(specFromDecl(merged))
}

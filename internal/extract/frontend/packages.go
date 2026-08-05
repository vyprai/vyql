package frontend

// Dynamic, dependency-gated package-binding loading.
//
// The vyrun batch generates one package-aware binding set per (language, top-1000 package)
// under <data root>/bindings/packages/generated/<lang>/<pkg>/ or
// <data root>/bindings/packages/generated/<lang>/<pkg>.vyql — ~9k mapped
// catalogs. Loading all of them on every scan would parse thousands of files and build a spec with
// tens of thousands of mappings for packages a project never touches. Instead this layer
// loads ONLY the per-package bindings whose package is present in the project's dependency
// evidence (imported modules + SBOM/manifest packages). That is the "dynamic import":
// a binding for `flask` is parsed and activated only when the scanned code actually
// depends on flask. Each loaded mapping still carries its v2 dependency requirement,
// so the engine's apply-time packageAllowed gate remains the authoritative second check.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/sca"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/usg"
)

// generatedRoot is the directory holding the generated per-package binding corpus.
func generatedRoot() string {
	return filepath.Join(datadir.Root(), "bindings", "packages", "generated")
}

// GeneratedRoot exports generatedRoot so the incremental binding-label cache can fingerprint
// the specific generated per-package files a scan loads.
func GeneratedRoot() string { return generatedRoot() }

// DependencyEvidence collects the project's dependency surface from an already-built
// graph: imported modules/symbols (code.Import) and declared packages (sbom.PackageVersion),
// normalized and expanded to package roots. This is the gate set used to decide which
// generated package bindings to load. It mirrors the per-mapping packageEvidence used at
// apply time but spans all languages (crossLang) so a single call covers a polyglot repo.
func DependencyEvidence(s usg.Store) map[string]bool {
	return packageEvidence(s, "", true)
}

var generatedPackageIndex sync.Map // map[tech]map[lowercase stem]actual stem

// GeneratedPackageBindingsFor loads the generated per-package bindings for a language,
// restricted to packages present in deps. The generated directory is indexed once per
// language, then each call reads only files named by project dependency evidence.
// Missing corpus remains non-fatal because the generated catalog augments a scan.
// Present generated files must parse/lower successfully so SCA/CVE verification
// cannot silently lose package coverage. Returns nil when nothing matches.
func GeneratedPackageBindingsFor(tech string, deps map[string]bool) []bindings.Applicator {
	if len(deps) == 0 {
		return nil
	}
	index := generatedPackageFileIndex(tech)
	if len(index) == 0 {
		return nil
	}
	merged := &parser.BindingSet{Name: tech, Meta: map[string]any{}}
	for _, stem := range generatedPackageCandidateStems(deps) {
		actual, ok := index[strings.ToLower(stem)]
		if !ok {
			continue
		}
		sources, err := readGeneratedPackageBindingSources(tech, actual)
		if err != nil {
			panic(fmt.Sprintf("frontend: read generated package binding %s/%s: %v", tech, actual, err))
		}
		for _, source := range sources {
			decls, err := parseGeneratedPackageBindingSource(source)
			if err != nil {
				panic(err.Error())
			}
			for _, d := range decls {
				a, ok := d.(*parser.BindingSet)
				if !ok || a.Name != tech {
					continue
				}
				merged.Mappings = append(merged.Mappings, a.Mappings...)
			}
		}
	}
	if len(merged.Mappings) == 0 {
		return nil
	}
	return bindingApplicatorsFromSpec(filterBindingSpecForActiveConcepts(specFromBindingSet(merged)))
}

func readGeneratedPackageBindingSources(tech, pkg string) ([]datadir.Source, error) {
	dirRel := filepath.ToSlash(filepath.Join("bindings", "packages", "generated", tech, pkg))
	if info, err := os.Stat(filepath.Join(datadir.Root(), dirRel)); err == nil && info.IsDir() {
		return datadir.ReadVYQLDir(dirRel)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return datadir.ReadVYQL(dirRel + ".vyql")
}

func parseGeneratedPackageBindingSource(source datadir.Source) ([]parser.Decl, error) {
	decls, err := parseV2BindingSources([]datadir.Source{source})
	if err != nil {
		return nil, fmt.Errorf("frontend: invalid generated package binding %s: %w", source.Name, err)
	}
	return decls, nil
}

func generatedPackageFileIndex(tech string) map[string]string {
	if cached, ok := generatedPackageIndex.Load(tech); ok {
		return cached.(map[string]string)
	}
	dir := filepath.Join(generatedRoot(), tech)
	entries, err := os.ReadDir(dir)
	if err != nil {
		empty := map[string]string{}
		generatedPackageIndex.Store(tech, empty)
		return empty
	}
	out := map[string]string{}
	for _, e := range entries {
		var stem string
		if e.IsDir() {
			stem = e.Name()
		} else if strings.HasSuffix(e.Name(), ".vyql") {
			stem = strings.TrimSuffix(e.Name(), ".vyql")
		} else {
			continue
		}
		out[strings.ToLower(stem)] = stem
	}
	generatedPackageIndex.Store(tech, out)
	return out
}

func generatedPackageCandidateStems(deps map[string]bool) []string {
	seen := map[string]bool{}
	addName := func(name string) {
		name = sca.NormalizePackageName(name)
		if name == "" {
			return
		}
		addPackagePathPrefixes(seen, name)
		if root := sca.PackageRoot(name); root != "" {
			addPackagePathPrefixes(seen, root)
		}
		for _, alias := range sca.ImportAliases(name) {
			addPackagePathPrefixes(seen, alias)
		}
	}
	for dep := range deps {
		addName(dep)
	}
	var out []string
	for stem := range seen {
		out = append(out, stem)
	}
	sort.Strings(out)
	return out
}

func addPackagePathPrefixes(out map[string]bool, name string) {
	if name == "" {
		return
	}
	addPackageStem(out, name)
	if strings.HasPrefix(name, "@") {
		if parts := strings.Split(name, "/"); len(parts) >= 2 {
			addPackageStem(out, parts[0]+"/"+parts[1])
		}
		return
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 {
		for i := 2; i <= len(parts); i++ {
			addPackageStem(out, strings.Join(parts[:i], "/"))
		}
	}
	dotParts := strings.Split(name, ".")
	if len(dotParts) > 1 {
		for i := 2; i <= len(dotParts); i++ {
			addPackageStem(out, strings.Join(dotParts[:i], "."))
		}
	}
}

func addPackageStem(out map[string]bool, name string) {
	stem := strings.NewReplacer("/", "_", "\\", "_").Replace(name)
	if stem != "" {
		out[strings.ToLower(stem)] = true
	}
}

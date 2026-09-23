package vyql

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/ontology"
)

// KB is a loaded knowledge base: the parsed module files, the manifest, and the
// ontology they declare. Loading is a pure function of the directory contents —
// files are walked in sorted order, so the same tree always yields the same KB.
type KB struct {
	Manifest *Manifest
	Files    []*File
	Schemas  *graph.Schemas
	Onto     *ontology.Ontology
	Threats  map[string]ThreatDecl

	// Trust is the tier every declaration in this module is stamped with,
	// taken from the manifest's provenance field (trusted by default).
	Trust graph.Trust
}

func trustOf(tier string) graph.Trust {
	switch tier {
	case "generated":
		return graph.TrustGenerated
	case "validated":
		return graph.TrustValidated
	case "reviewed":
		return graph.TrustReviewed
	default:
		return graph.TrustTrusted
	}
}

// LoadDir loads a module directory: every *.vyql file, walked in sorted order.
// Exactly one file must carry the manifest block (module.vyql by convention);
// every other file must use the header form and declare the same module name.
// Duplicate declarations across files are an error, not a last-writer-wins.
func LoadDir(dir string) (*KB, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".vyql" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .vyql files under %s", dir)
	}
	sort.Strings(paths)

	kb := &KB{Schemas: graph.NewSchemas(), Threats: map[string]ThreatDecl{}}
	var manifests int
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		f, err := Parse(string(src))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if f.Manifest != nil {
			manifests++
			kb.Manifest = f.Manifest
		}
		kb.Files = append(kb.Files, f)
	}
	if manifests == 0 {
		return nil, fmt.Errorf("module under %s has no manifest (module.vyql with the block form)", dir)
	}
	if manifests > 1 {
		return nil, fmt.Errorf("module under %s has %d manifest blocks; exactly one is allowed", dir, manifests)
	}
	for _, f := range kb.Files {
		if f.Module != kb.Manifest.Module {
			return nil, fmt.Errorf("file declares module %q but the manifest says %q", f.Module, kb.Manifest.Module)
		}
	}

	built, errs := BuildKnowledge(kb.Files, kb.Schemas)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid knowledge under %s: %v", dir, errs)
	}
	kb.Onto = built.Onto
	kb.Threats = built.Threats
	kb.Trust = trustOf(kb.Manifest.Provenance)
	return kb, nil
}

// Rules returns every rule declaration, file order then declaration order —
// deterministic for a given tree.
func (kb *KB) Rules() []RuleDecl {
	var out []RuleDecl
	for _, f := range kb.Files {
		out = append(out, f.Rules...)
	}
	return out
}

// Adapters returns every adapter declaration in deterministic order.
func (kb *KB) Adapters() []AdapterDecl {
	var out []AdapterDecl
	for _, f := range kb.Files {
		out = append(out, f.Adapters...)
	}
	return out
}

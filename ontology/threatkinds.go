package ontology

import (
	"strconv"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/taxonomy"
)

var (
	tkOnce      sync.Once
	threatKinds []ThreatKind
)

// ThreatKind is an analysis-level weakness class (the vocabulary `vulnerable_to`
// / `neutralizes` use). It stays curated and analysis-shaped (docs/06), but
// maps onto the full CWE catalog; CAPEC attack patterns are derived from the
// CWE cross-references in the catalog, so we never hand-enter (and mis-key)
// CAPEC ids.
type ThreatKind struct {
	Name    string   `json:"name"`    // short PascalCase
	Package string   `json:"package"` // family namespace (injection, crypto, …)
	CWE     []string `json:"cwe"`     // primary CWE id(s), e.g. CWE_89
	Desc    string   `json:"desc,omitempty"`
}

// QualifiedName returns the namespaced id `<package>.<Name>` (e.g.
// injection.SqlInjection).
func (t ThreatKind) QualifiedName() string {
	if t.Package == "" {
		return t.Name
	}
	return t.Package + "." + t.Name
}

// CAPEC returns the attack-pattern ids related to this threat kind's CWEs,
// derived from the catalog cross-references.
func (t ThreatKind) CAPEC(cat *taxonomy.Catalog) []string {
	seen := map[int]bool{}
	var out []string
	for _, c := range t.CWE {
		if w, ok := cat.CWE(c); ok {
			for _, p := range w.CAPEC {
				if !seen[p] {
					seen[p] = true
					out = append(out, strconv.Itoa(p))
				}
			}
		}
	}
	return out
}

// ThreatKinds returns the curated threat-kind vocabulary mapped to CWE
// (CAPEC derived), loaded from data/threatkinds.json. Covers the major
// weakness families.
func ThreatKinds() []ThreatKind {
	tkOnce.Do(func() {
		files, err := datadir.ReadVYQLDir("ontology/threatkinds")
		if err != nil {
			panic("ontology: read ontology/threatkinds: " + err.Error())
		}
		decls, err := parser.ParseV2DefinitionSources(v2DefinitionSources(files))
		if err != nil {
			panic("ontology: invalid threat-kind corpus: " + err.Error())
		}
		for _, d := range decls {
			td, ok := d.(*parser.ThreatDecl)
			if !ok {
				continue
			}
			threatKinds = append(threatKinds, ThreatKind{
				Name: td.Name, Package: td.Package,
				CWE:  list(td.Fields, "cwe"),
				Desc: str(td.Fields, "desc"),
			})
		}
	})
	return threatKinds
}

func v2DefinitionSources(files []datadir.Source) []parser.V2DefinitionSource {
	out := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	return out
}

// ThreatKindByName returns a threat kind by its qualified name (e.g.
// injection.SqlInjection).
func ThreatKindByName(name string) (ThreatKind, bool) {
	for _, t := range ThreatKinds() {
		if t.QualifiedName() == name {
			return t, true
		}
	}
	return ThreatKind{}, false
}

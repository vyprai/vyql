// Package definitions inspects the shipped VyQL definition corpus -- concepts,
// bindings, rule packs and reviews -- and reports what it contains.
package definitions

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
)

type InspectOptions struct {
	Kind     string
	Language string
	Query    string
	Max      int
}

type Catalog struct {
	Root     string           `json:"root"`
	Stats    CatalogStats     `json:"stats"`
	Concepts []ConceptSummary `json:"concepts,omitempty"`
	Rules    []RuleSummary    `json:"rules,omitempty"`
	Bindings []MappingSummary `json:"bindings,omitempty"`
	Reviews  []ReviewSummary  `json:"reviews,omitempty"`
	Packs    []PackSummary    `json:"packs,omitempty"`
}

type CatalogStats struct {
	Concepts int `json:"concepts"`
	Rules    int `json:"rules"`
	Bindings int `json:"bindings"`
	Reviews  int `json:"reviews"`
	Packs    int `json:"packs"`
}

type ConceptSummary struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	VulnerableTo []string `json:"vulnerable_to,omitempty"`
	Neutralizes  []string `json:"neutralizes,omitempty"`
	Refines      string   `json:"refines,omitempty"`
	Review       string   `json:"review,omitempty"`
	Source       string   `json:"source"`
}

type RuleSummary struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Severity string   `json:"severity,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
	Concepts []string `json:"concepts,omitempty"`
	Source   string   `json:"source"`
}

type MappingSummary struct {
	Language   string   `json:"language"`
	Kind       string   `json:"kind"`
	Pattern    string   `json:"pattern,omitempty"`
	Concept    string   `json:"concept,omitempty"`
	Packages   []string `json:"packages,omitempty"`
	ArgIndex   int      `json:"arg_index,omitempty"`
	ValMatches []string `json:"val_matches,omitempty"`
	ValAbsents []string `json:"val_absents,omitempty"`
	Exact      bool     `json:"exact,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	NodeKind   string   `json:"node_kind,omitempty"`
	Source     string   `json:"source"`
}

type ReviewSummary struct {
	Concept  string   `json:"concept"`
	Category string   `json:"category,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Expected []string `json:"expected,omitempty"`
	Text     string   `json:"text,omitempty"`
	Source   string   `json:"source"`
}

type PackSummary struct {
	Name     string   `json:"name"`
	Includes []string `json:"includes,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
	Source   string   `json:"source"`
}

func Inspect(opts InspectOptions) (Catalog, error) {
	if opts.Max <= 0 {
		opts.Max = 80
	}
	opts.Kind = strings.ToLower(strings.TrimSpace(opts.Kind))
	if opts.Kind == "" {
		opts.Kind = "all"
	}
	opts.Language = strings.ToLower(strings.TrimSpace(opts.Language))
	opts.Query = strings.ToLower(strings.TrimSpace(opts.Query))

	cat := Catalog{Root: datadir.Root()}
	if wantKind(opts.Kind, "concepts") || wantKind(opts.Kind, "rules") || wantKind(opts.Kind, "reviews") || wantKind(opts.Kind, "packs") {
		if err := inspectDeclDir(&cat, "ontology"); err != nil {
			return cat, err
		}
		if err := inspectDeclDir(&cat, "packs"); err != nil {
			return cat, err
		}
		if err := inspectDeclDir(&cat, "review"); err != nil {
			return cat, err
		}
	}
	if wantKind(opts.Kind, "bindings") {
		if err := inspectDeclDir(&cat, "bindings"); err != nil {
			return cat, err
		}
	}

	sortCatalog(&cat)
	cat.Stats = CatalogStats{
		Concepts: len(cat.Concepts),
		Rules:    len(cat.Rules),
		Bindings: len(cat.Bindings),
		Reviews:  len(cat.Reviews),
		Packs:    len(cat.Packs),
	}
	filterCatalog(&cat, opts)
	return cat, nil
}

func wantKind(got, want string) bool {
	if got == "all" {
		return true
	}
	switch got {
	case "concept":
		got = "concepts"
	case "rule":
		got = "rules"
	case "binding", "mapping", "mappings":
		got = "bindings"
	case "review":
		got = "reviews"
	case "pack":
		got = "packs"
	}
	return got == want
}

func inspectDeclDir(cat *Catalog, rel string) error {
	root := filepath.Join(datadir.Root(), rel)
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	var sources []parser.V2DefinitionSource
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources = append(sources, parser.V2DefinitionSource{Name: relPath(path), Source: string(b)})
		return nil
	})
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, source := range sources {
		selected[source.Name] = true
	}
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesWithCore(sources), func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
	if err != nil {
		return err
	}
	for _, d := range decls {
		addDecl(cat, "", d)
	}
	return nil
}

func v2DefinitionSourcesWithCore(sources []parser.V2DefinitionSource) []parser.V2DefinitionSource {
	hasOntology, hasPolicies := false, false
	for _, source := range sources {
		hasOntology = hasOntology || strings.HasPrefix(source.Name, "ontology/")
		hasPolicies = hasPolicies || strings.HasPrefix(source.Name, "policies/")
	}
	out := make([]parser.V2DefinitionSource, 0, len(sources)+32)
	if !hasOntology {
		if files, err := datadir.ReadVYQLDir("ontology/concepts"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
		if files, err := datadir.ReadVYQLDir("ontology/threatkinds"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
	}
	if !hasPolicies {
		if files, err := datadir.ReadVYQLDir("policies"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
	}
	out = append(out, sources...)
	return out
}

func addDecl(cat *Catalog, source string, d parser.Decl) {
	switch x := d.(type) {
	case *parser.ConceptDecl:
		cat.Concepts = append(cat.Concepts, ConceptSummary{
			Name:         x.QualifiedName(),
			Kind:         x.Kind,
			CWE:          listField(x.Fields, "cwe"),
			VulnerableTo: listField(x.Fields, "vulnerable_to"),
			Neutralizes:  listField(x.Fields, "neutralizes"),
			Refines:      stringField(x.Fields, "refines"),
			Review:       firstNonEmpty(stringField(x.Fields, "review_condition"), stringField(x.Fields, "review_category")),
			Source:       source,
		})
	case *parser.Rule:
		id := stringField(x.Meta, "id")
		if id == "" {
			id = x.QualifiedName()
		}
		cat.Rules = append(cat.Rules, RuleSummary{
			ID:       id,
			Name:     x.QualifiedName(),
			Severity: stringField(x.Meta, "severity"),
			CWE:      listField(x.Meta, "cwe"),
			Concepts: ruleConcepts(x),
			Source:   source,
		})
	case *parser.BindingSet:
		for _, m := range x.Mappings {
			item := MappingSummary{
				Language:   x.Name,
				Kind:       m.Kind,
				Pattern:    m.Pattern,
				Concept:    m.Concept,
				Packages:   append([]string(nil), m.Packages...),
				ArgIndex:   m.ArgIndex,
				ValMatches: append([]string(nil), m.ValMatches...),
				ValAbsents: append([]string(nil), m.ValAbsents...),
				Exact:      m.Exact,
				Source:     source,
			}
			if m.Flag != nil {
				item.Scope = m.Flag.Scope
				item.NodeKind = m.Flag.NodeKind
			}
			cat.Bindings = append(cat.Bindings, item)
		}
	case *parser.ReviewDecl:
		cat.Reviews = append(cat.Reviews, ReviewSummary{
			Concept:  x.Concept,
			Category: stringField(x.Fields, "category"),
			Kind:     stringField(x.Fields, "kind"),
			Expected: listField(x.Fields, "expected"),
			Text:     stringField(x.Fields, "text"),
			Source:   source,
		})
	case *parser.PackDecl:
		cat.Packs = append(cat.Packs, PackSummary{
			Name:     x.Name,
			Includes: listField(x.Fields, "includes"),
			Excludes: listField(x.Fields, "excludes"),
			Source:   source,
		})
	}
}

func relPath(path string) string {
	rel, err := filepath.Rel(datadir.Root(), path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

func stringField(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

func listField(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func ruleConcepts(r *parser.Rule) []string {
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" {
			seen[v] = true
		}
	}
	walkStmt := func(s parser.Stmt) {
		switch x := s.(type) {
		case *parser.FlowStmt:
			add(x.Src.Concept)
			add(x.Dst.Concept)
		case *parser.MatchStmt:
			add(x.Concept)
		case *parser.OrderStmt:
			add(x.First.Concept)
			add(x.Second.Concept)
		}
	}
	walkStmt(r.Body)
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortCatalog(cat *Catalog) {
	sort.Slice(cat.Concepts, func(i, j int) bool { return cat.Concepts[i].Name < cat.Concepts[j].Name })
	sort.Slice(cat.Rules, func(i, j int) bool { return cat.Rules[i].ID < cat.Rules[j].ID })
	sort.Slice(cat.Bindings, func(i, j int) bool {
		a, b := cat.Bindings[i], cat.Bindings[j]
		return a.Language+"\x00"+a.Kind+"\x00"+a.Pattern+"\x00"+a.Concept < b.Language+"\x00"+b.Kind+"\x00"+b.Pattern+"\x00"+b.Concept
	})
	sort.Slice(cat.Reviews, func(i, j int) bool { return cat.Reviews[i].Concept < cat.Reviews[j].Concept })
	sort.Slice(cat.Packs, func(i, j int) bool { return cat.Packs[i].Name < cat.Packs[j].Name })
}

func filterCatalog(cat *Catalog, opts InspectOptions) {
	if opts.Query != "" {
		cat.Concepts = filterSlice(cat.Concepts, opts.Query, conceptHaystack)
		cat.Rules = filterSlice(cat.Rules, opts.Query, ruleHaystack)
		cat.Bindings = filterSlice(cat.Bindings, opts.Query, mappingHaystack)
		cat.Reviews = filterSlice(cat.Reviews, opts.Query, reviewHaystack)
		cat.Packs = filterSlice(cat.Packs, opts.Query, packHaystack)
	}
	if opts.Language != "" {
		cat.Bindings = filterSlice(cat.Bindings, opts.Language, func(v MappingSummary) string {
			return strings.ToLower(v.Language)
		})
	}
	cat.Concepts = limitSlice(cat.Concepts, opts.Max)
	cat.Rules = limitSlice(cat.Rules, opts.Max)
	cat.Bindings = limitSlice(cat.Bindings, opts.Max)
	cat.Reviews = limitSlice(cat.Reviews, opts.Max)
	cat.Packs = limitSlice(cat.Packs, opts.Max)
}

func filterSlice[T any](in []T, q string, hay func(T) string) []T {
	var out []T
	for _, v := range in {
		if strings.Contains(hay(v), q) {
			out = append(out, v)
		}
	}
	return out
}

func limitSlice[T any](in []T, max int) []T {
	if max > 0 && len(in) > max {
		return in[:max]
	}
	return in
}

func conceptHaystack(v ConceptSummary) string {
	return strings.ToLower(strings.Join([]string{
		v.Name, v.Kind, strings.Join(v.CWE, " "), strings.Join(v.VulnerableTo, " "),
		strings.Join(v.Neutralizes, " "), v.Refines, v.Review, v.Source,
	}, " "))
}

func ruleHaystack(v RuleSummary) string {
	return strings.ToLower(strings.Join([]string{
		v.ID, v.Name, v.Severity, strings.Join(v.CWE, " "), strings.Join(v.Concepts, " "), v.Source,
	}, " "))
}

func mappingHaystack(v MappingSummary) string {
	return strings.ToLower(strings.Join([]string{
		v.Language, v.Kind, v.Pattern, v.Concept, strings.Join(v.Packages, " "),
		strings.Join(v.ValMatches, " "), strings.Join(v.ValAbsents, " "), v.Scope, v.NodeKind, v.Source,
	}, " "))
}

func reviewHaystack(v ReviewSummary) string {
	return strings.ToLower(strings.Join([]string{
		v.Concept, v.Category, v.Kind, strings.Join(v.Expected, " "), v.Text, v.Source,
	}, " "))
}

func packHaystack(v PackSummary) string {
	return strings.ToLower(strings.Join([]string{
		v.Name, strings.Join(v.Includes, " "), strings.Join(v.Excludes, " "), v.Source,
	}, " "))
}

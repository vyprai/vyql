package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/parser"
)

// projectFacts is the authored vocabulary behind a profile's `detect:` predicates: which
// manifests answer dependency(), what a language() name is on disk, what makes a directory
// a project root, what each satisfied predicate is worth, and how a named project.has()
// fact is decided. It is `policy projectFacts default` in vyql/profiles/.
type projectFacts struct {
	manifests      []string
	projectMarkers []string
	score          map[string]int
	languageExts   map[string][]string
	facts          []namedFact
}

// namedFact is one project.has() fact, answered by walking the project for a file that
// satisfies any of its match rules.
type namedFact struct {
	name     string
	skipDirs []string
	match    []fileRule
}

// fileRule names a file and, optionally, what its contents must show. A rule with no
// content clause is satisfied by the file existing.
type fileRule struct {
	file       string
	suffix     string
	contains   []string // any one present
	absent     []string // none present
	jsonEquals map[string]string
	jsonFalse  []string
	jsonAnySet []string
}

func (f projectFacts) fact(name string) (namedFact, bool) {
	for _, nf := range f.facts {
		if nf.name == name {
			return nf, true
		}
	}
	return namedFact{}, false
}

// weight is what one satisfied predicate of this kind contributes to a profile's score.
// An undeclared kind is worth nothing, which is the same answer an unknown predicate got
// before the weights were authored.
func (f projectFacts) weight(kind string) int { return f.score[kind] }

var (
	projectFactsOnce  sync.Once
	projectFactsValue projectFacts
	projectFactsErr   error
)

// defaultProjectFacts loads and caches the shipped vocabulary. The error is reported by
// Detect rather than returned: a caller cannot act on it, and the consequence -- every
// predicate scoring zero, so every project reading as generic -- has to reach a human.
func defaultProjectFacts() (projectFacts, error) {
	projectFactsOnce.Do(func() {
		projectFactsValue, projectFactsErr = loadProjectFacts()
	})
	return projectFactsValue, projectFactsErr
}

func loadProjectFacts() (projectFacts, error) {
	files, err := datadir.ReadVYQLDir("profiles")
	if err != nil {
		return projectFacts{}, fmt.Errorf("load project facts: %w", err)
	}
	decls, err := parser.ParseV2DefinitionSources(v2DefinitionSources(files))
	if err != nil {
		return projectFacts{}, fmt.Errorf("parse project facts: %w", err)
	}
	return projectFactsFromDecls(decls)
}

func projectFactsFromDecls(decls []parser.Decl) (projectFacts, error) {
	var decl *parser.V2PolicyDecl
	for _, d := range decls {
		p, ok := d.(*parser.V2PolicyDecl)
		if !ok || p.Kind != "projectFacts" || p.Name != "default" {
			continue
		}
		if decl != nil {
			return projectFacts{}, fmt.Errorf("duplicate policy projectFacts default")
		}
		decl = p
	}
	if decl == nil {
		return projectFacts{}, fmt.Errorf("missing policy projectFacts default")
	}
	return projectFactsFromDecl(decl)
}

func projectFactsFromDecl(p *parser.V2PolicyDecl) (projectFacts, error) {
	out := projectFacts{score: map[string]int{}, languageExts: map[string][]string{}}
	for _, item := range p.Items {
		if len(item.Key) != 1 {
			return projectFacts{}, fmt.Errorf("unexpected item %q", strings.Join(item.Key, " "))
		}
		switch item.Key[0] {
		case "manifests":
			out.manifests = blockStrings(item.Value)
		case "projectMarkers":
			out.projectMarkers = blockStrings(item.Value)
		case "score":
			for _, s := range item.Block {
				if len(s.Key) != 1 {
					continue
				}
				n, ok := blockInt(s.Value)
				if !ok {
					return projectFacts{}, fmt.Errorf("score %s must be an integer", s.Key[0])
				}
				out.score[s.Key[0]] = n
			}
		case "language":
			for _, entry := range blockList(item.Value) {
				name := strings.ToLower(blockString(fieldOf(entry, "name")))
				exts := blockStrings(fieldOf(entry, "exts"))
				if name == "" || len(exts) == 0 {
					return projectFacts{}, fmt.Errorf("language entry needs a name and at least one ext")
				}
				out.languageExts[name] = exts
			}
		case "fact":
			for _, entry := range blockList(item.Value) {
				nf, err := namedFactFromBlock(entry)
				if err != nil {
					return projectFacts{}, err
				}
				out.facts = append(out.facts, nf)
			}
		default:
			// Not skipped. A misspelled key would otherwise leave the vocabulary short by
			// exactly one entry and say nothing, which is how a whole ecosystem stops being
			// detected without anything failing.
			return projectFacts{}, fmt.Errorf("unknown item %q", item.Key[0])
		}
	}
	if len(out.manifests) == 0 {
		return projectFacts{}, fmt.Errorf("manifests must be declared")
	}
	if len(out.projectMarkers) == 0 {
		return projectFacts{}, fmt.Errorf("projectMarkers must be declared")
	}
	if len(out.score) == 0 {
		return projectFacts{}, fmt.Errorf("score must be declared")
	}
	return out, nil
}

func namedFactFromBlock(items []parser.V2BlockItem) (namedFact, error) {
	out := namedFact{
		name:     blockString(fieldOf(items, "name")),
		skipDirs: blockStrings(fieldOf(items, "skipDirs")),
	}
	if out.name == "" {
		return namedFact{}, fmt.Errorf("fact entry needs a name")
	}
	for _, entry := range blockList(fieldOf(items, "match")) {
		r := fileRule{
			file:       blockString(fieldOf(entry, "file")),
			suffix:     blockString(fieldOf(entry, "suffix")),
			contains:   blockStrings(fieldOf(entry, "contains")),
			absent:     blockStrings(fieldOf(entry, "absent")),
			jsonFalse:  blockStrings(fieldOf(entry, "jsonFalse")),
			jsonAnySet: blockStrings(fieldOf(entry, "jsonAnySet")),
		}
		if eq, ok := fieldOf(entry, "jsonEquals").([]parser.V2BlockItem); ok {
			r.jsonEquals = map[string]string{}
			for _, kv := range eq {
				if len(kv.Key) == 1 {
					r.jsonEquals[kv.Key[0]] = blockString(kv.Value)
				}
			}
		}
		if r.file == "" && r.suffix == "" {
			return namedFact{}, fmt.Errorf("fact %s: a match entry needs a file or a suffix", out.name)
		}
		out.match = append(out.match, r)
	}
	if len(out.match) == 0 {
		return namedFact{}, fmt.Errorf("fact %s: needs at least one match entry", out.name)
	}
	return out, nil
}

// fieldOf returns the value of the named single-key item, or nil.
func fieldOf(items []parser.V2BlockItem, key string) any {
	for _, item := range items {
		if len(item.Key) == 1 && item.Key[0] == key {
			if item.Value != nil {
				return item.Value
			}
			return item.Block
		}
	}
	return nil
}

// blockList reads a value written as a list of `{ ... }` blocks.
func blockList(v any) [][]parser.V2BlockItem {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	var out [][]parser.V2BlockItem
	for _, e := range raw {
		if items, ok := e.([]parser.V2BlockItem); ok {
			out = append(out, items)
		}
	}
	return out
}

func blockStrings(v any) []string {
	switch xs := v.(type) {
	case []any:
		out := make([]string, 0, len(xs))
		for _, e := range xs {
			if s := blockString(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return xs
	}
	if s := blockString(v); s != "" {
		return []string{s}
	}
	return nil
}

func blockString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case parser.V2LiteralExpr:
		s, _ := x.Value.(string)
		return s
	}
	return ""
}

func blockInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case parser.V2LiteralExpr:
		n, ok := x.Value.(int)
		return n, ok
	}
	return 0, false
}

// satisfiedBy walks each project root for a file satisfying any match rule, stopping at the
// first hit. Hidden directories are always skipped -- that is a property of walking a
// checkout, not knowledge about an ecosystem -- and the declared skipDirs on top of them.
// The root itself is never skipped: a scan pointed straight at node_modules means it.
func (nf namedFact) satisfiedBy(roots []string) bool {
	for _, root := range roots {
		found := false
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || found {
				return nil
			}
			if d.IsDir() {
				if path != root && (strings.HasPrefix(d.Name(), ".") || nf.skips(d.Name())) {
					return filepath.SkipDir
				}
				return nil
			}
			for _, r := range nf.match {
				if r.matches(path, d.Name()) {
					found = true
					return nil
				}
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}

func (nf namedFact) skips(dir string) bool {
	for _, s := range nf.skipDirs {
		if s == dir {
			return true
		}
	}
	return false
}

// matches reports whether the file at path satisfies this rule. A rule naming a file it
// cannot read is not satisfied.
func (r fileRule) matches(path, base string) bool {
	if r.file != "" && base != r.file {
		return false
	}
	if r.suffix != "" && !strings.HasSuffix(base, r.suffix) {
		return false
	}
	if !r.readsContent() {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(data)
	for _, s := range r.absent {
		if strings.Contains(text, s) {
			return false
		}
	}
	if len(r.contains) > 0 && !containsAny(text, r.contains) {
		return false
	}
	return r.matchesJSON(data)
}

func (r fileRule) readsContent() bool {
	return len(r.contains) > 0 || len(r.absent) > 0 || len(r.jsonEquals) > 0 ||
		len(r.jsonFalse) > 0 || len(r.jsonAnySet) > 0
}

func (r fileRule) matchesJSON(data []byte) bool {
	if len(r.jsonEquals) == 0 && len(r.jsonFalse) == 0 && len(r.jsonAnySet) == 0 {
		return true
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	for field, want := range r.jsonEquals {
		var got string
		if json.Unmarshal(doc[field], &got) != nil || got != want {
			return false
		}
	}
	for _, field := range r.jsonFalse {
		var got bool
		if raw, ok := doc[field]; ok && json.Unmarshal(raw, &got) == nil && got {
			return false
		}
	}
	if len(r.jsonAnySet) > 0 {
		set := false
		for _, field := range r.jsonAnySet {
			// Present and not the empty string. A field carrying null, an empty object or
			// an empty array still declares the surface -- npm reads `"exports": null` as
			// an explicit statement about what is published.
			if raw, ok := doc[field]; ok && string(raw) != `""` {
				set = true
				break
			}
		}
		if !set {
			return false
		}
	}
	return true
}

func containsAny(text string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// warnUnknownDetectFacts reports a project.has() value that names neither an extension nor
// a declared fact. Such a predicate scores zero forever, so the profile that carries it
// quietly stops competing -- the failure looks identical to a project without the
// fingerprint, which is the whole reason it is worth a line on stderr.
func warnUnknownDetectFacts(facts projectFacts, profiles []Profile) {
	for _, p := range profiles {
		for _, d := range p.Detect {
			walkDetect(d, func(e DetectExpr) {
				if e.Op != "project.has" || strings.HasPrefix(e.Value, "ext:") {
					return
				}
				if _, ok := facts.fact(e.Value); !ok {
					reportOnce(fmt.Sprintf("vyql: profile %q: project.has(%q) names no declared fact; it can never match", p.Name, e.Value))
				}
			})
		}
	}
}

func walkDetect(d DetectExpr, visit func(DetectExpr)) {
	visit(d)
	for _, child := range d.Args {
		walkDetect(child, visit)
	}
}

var reported sync.Map

// reportOnce writes a diagnostic to stderr the first time it is produced. Detect runs once
// per scan but many times per test binary, and a data defect repeated eighty times reads
// as noise rather than as the one thing that is wrong.
func reportOnce(msg string) {
	if _, seen := reported.LoadOrStore(msg, true); seen {
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

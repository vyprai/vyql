package main

// Coverage GATES (plan/test-coverage-tasklist.md T0). These meta-tests enforce that
// every rule/concept/threat/adapter stays tested and internally consistent — so a new
// feature cannot ship untested. They read the shipped VyQL data (vyql/) directly.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/parser"
)

// readDataFiles returns {relpath: content} for every *.vyql under vyql/<sub>.
func readDataFiles(t *testing.T, sub, suffix string) map[string]string {
	t.Helper()
	root := filepath.Join(datadir.Root(), sub)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, suffix) {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", sub, err)
	}
	if len(out) == 0 {
		t.Fatalf("no %s files under vyql/%s", suffix, sub)
	}
	return out
}

func parseDataDecls(t *testing.T, sub, suffix string) map[string][]parser.Decl {
	t.Helper()
	out := map[string][]parser.Decl{}
	if strings.HasSuffix(suffix, ".vyql") && !strings.HasPrefix(suffix, ".") {
		sources, err := datadir.ReadVYQL(filepath.ToSlash(filepath.Join(sub, suffix)))
		if err != nil {
			t.Fatalf("read %s/%s: %v", sub, suffix, err)
		}
		if len(sources) == 0 {
			t.Fatalf("no %s sources under vyql/%s", suffix, sub)
		}
		for _, source := range sources {
			decls, err := parseV2DefinitionsForTest(string(source.Data))
			if err != nil {
				t.Fatalf("parse %s: %v", source.Name, err)
			}
			out[source.Name] = decls
		}
		return out
	}
	files := readDataFiles(t, sub, suffix)
	for f, c := range files {
		parse := parseV2DefinitionsForTest
		if sub == "mechanics" {
			parse = parser.ParseV2Definitions
		}
		decls, err := parse(c)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Base(f), err)
		}
		out[f] = decls
	}
	return out
}

func ruleIDs(t *testing.T, files map[string]string) map[string]string { // id -> file
	t.Helper()
	out := map[string]string{}
	for f, c := range files {
		decls, err := parseV2DefinitionsForTest(c)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Base(f), err)
		}
		for _, decl := range decls {
			r, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			if id, _ := r.Meta["id"].(string); id != "" {
				out[id] = f
			}
		}
	}
	return out
}

// T0.1 — every rule has at least one `expect` spec (proves it fires). The allowlist is
// the known-unspecced backlog (T1 burns it down); a NEW rule without a spec fails here.
// As specs are added, allowlisted ids that gain coverage must be REMOVED (asserted below).
func TestRuleFiresCoverageGate(t *testing.T) {
	// Every shipped rule now has an `expect` spec — the burn-down allowlist is empty.
	unspecced := map[string]bool{}

	rules := ruleIDs(t, readDataFiles(t, "packs", ".vyql"))
	// every .test.vyql `expect` (code AND graph specs alike — both live in one format).
	specs := readDataFiles(t, "tests", ".test.vyql")
	expected := map[string]bool{}
	for _, c := range specs {
		for _, ln := range strings.Split(c, "\n") {
			if f := strings.Fields(strings.TrimSpace(ln)); len(f) == 2 && f[0] == "expect" {
				expected[f[1]] = true
			}
		}
	}

	var missing []string
	for id := range rules {
		if expected[id] || unspecced[id] {
			continue
		}
		missing = append(missing, id)
	}
	sort.Strings(missing)
	for _, id := range missing {
		t.Errorf("rule %s (%s) has no `expect` spec and is not in the unspecced allowlist — add a spec", id, filepath.Base(rules[id]))
	}
	// keep the burn-down honest: an allowlisted rule that now has a spec must be removed.
	for id := range unspecced {
		if expected[id] {
			t.Errorf("rule %s is now covered — remove it from the unspecced allowlist", id)
		}
		if rules[id] == "" {
			t.Errorf("allowlisted rule %s no longer exists — remove it from the allowlist", id)
		}
	}
	t.Logf("rule fires-coverage: %d rules, %d covered, %d in burn-down backlog", len(rules), len(expected), len(unspecced))
}

// T0.2 — every code/core concept reference in adapters and packs resolves to a defined
// concept. References come from the parsed VyQL AST, so string-literal sink paths
// (e.g. the Python `code` stdlib module) are not mistaken for concept refs.
func TestConceptRefsResolveGate(t *testing.T) {
	defined := map[string]bool{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts.vyql") {
		for _, decl := range decls {
			if cd, ok := decl.(*parser.ConceptDecl); ok {
				defined[cd.Name] = true
				defined[cd.QualifiedName()] = true
			}
		}
	}
	check := func(sub, suffix string) {
		for f, refs := range conceptRefsByFile(t, sub, suffix) {
			if isGeneratedAdapter(f) {
				continue // generated corpus validated separately below
			}
			for ref := range refs {
				if !defined[ref] && !defined[shortConceptName(ref)] {
					t.Errorf("%s references concept %q which is not defined in concepts.vyql", filepath.Base(f), ref)
				}
			}
		}
	}
	check("adapters", ".vyql")
	check("packs", ".vyql")
	// the dynamically-loaded generated package corpus must also reference only real
	// concepts (a dead label otherwise), but it is excluded from the curated coherence
	// gates below because it legitimately wires broad concepts that have no curated rule.
	for f, refs := range conceptRefsByFile(t, "adapters", ".vyql") {
		if !isGeneratedAdapter(f) {
			continue
		}
		for ref := range refs {
			if !defined[ref] && !defined[shortConceptName(ref)] {
				t.Errorf("generated adapter %s references concept %q not defined in concepts.vyql", f, ref)
			}
		}
	}
	t.Logf("concept refs: %d concepts defined", len(defined))
}

// isGeneratedAdapter reports whether a data-file path is part of the dynamically-loaded
// generated package-adapter corpus (adapters/packages/generated/<lang>/<pkg>.vyql), which
// is auxiliary content gated at scan time and excluded from the curated coherence gates.
func isGeneratedAdapter(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "/adapters/packages/generated/")
}

// conceptRefsIn returns the set of code/core concept names referenced (as targets or
// in rule clauses) across the given vyql/<sub> files.
func conceptRefsIn(t *testing.T, sub string) map[string]bool {
	out := map[string]bool{}
	for f, refs := range conceptRefsByFile(t, sub, ".vyql") {
		if isGeneratedAdapter(f) {
			continue // curated-coherence gates ignore the dynamically-loaded generated corpus
		}
		for ref := range refs {
			out[shortConceptName(ref)] = true
		}
	}
	return out
}

func conceptRefsByFile(t *testing.T, sub, suffix string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for f, decls := range parseDataDecls(t, sub, suffix) {
		refs := map[string]bool{}
		for _, decl := range decls {
			switch d := decl.(type) {
			case *parser.BindingSet:
				for _, m := range d.Mappings {
					if m.Concept != "" && m.Kind != "type" {
						addCoverageConceptRef(refs, m.Concept)
					}
					if m.About != "" && m.About != "*" {
						addCoverageConceptRef(refs, m.About)
					}
				}
			case *parser.Rule:
				collectRuleConceptRefs(d, refs)
			}
		}
		out[f] = refs
	}
	return out
}

func collectRuleConceptRefs(r *parser.Rule, refs map[string]bool) {
	switch body := r.Body.(type) {
	case *parser.FlowStmt:
		addCoverageConceptRef(refs, body.Src.Concept)
		addCoverageConceptRef(refs, body.Dst.Concept)
	case *parser.OrderStmt:
		addCoverageConceptRef(refs, body.First.Concept)
		addCoverageConceptRef(refs, body.Second.Concept)
	case *parser.MatchStmt:
		if body.Concept != "" {
			addCoverageConceptRef(refs, body.Concept)
		}
		if body.RelatedConcept != "" {
			addCoverageConceptRef(refs, body.RelatedConcept)
		}
	}
	for _, cl := range r.Clauses {
		collectExprConceptRefs(cl.Where, refs)
		switch ex := cl.Unless.(type) {
		case parser.PathCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.EndpointCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.DominatesCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.PostDominatesCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.SameReceiverCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.SameScopeCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.GlobalCoveredBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.ExprException:
			collectExprConceptRefs(ex.Expr, refs)
		}
	}
}

func collectExprConceptRefs(expr parser.Expr, refs map[string]bool) {
	switch e := expr.(type) {
	case nil:
		return
	case parser.And:
		for _, part := range e.Parts {
			collectExprConceptRefs(part, refs)
		}
	case parser.Not:
		collectExprConceptRefs(e.Inner, refs)
	case parser.Is:
		addCoverageConceptRef(refs, e.Concept)
	case parser.SolverCall:
		for _, arg := range e.Args {
			if len(arg.Ref.Parts) >= 2 {
				addCoverageConceptRef(refs, arg.Ref.String())
			}
		}
	}
}

func addCoverageConceptRef(refs map[string]bool, ref string) {
	if strings.HasPrefix(ref, "code.") || strings.HasPrefix(ref, "core.") {
		refs[ref] = true
	}
}

func shortConceptName(ref string) string {
	if i := strings.LastIndex(ref, "."); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func fieldStringList(fields map[string]any, key string) []string {
	switch v := fields[key].(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

// T2.5 — concept-coverage gate. Every SINK concept that a rule consumes must be wired
// in at least one adapter (otherwise the rule is latent — it can never fire). This is
// the gate that catches dead sinks (e.g. the reflection/log/header sinks that shipped
// referenced-but-unwired). The allowlist holds sinks for documented-deferred rules.
func TestSinkConceptsWiredGate(t *testing.T) {
	// no deferred sinks — every sink a rule consumes is adapter-wired.
	deferred := map[string]bool{}
	sinks := map[string]bool{}
	for s := range conceptsByKind(t, "sink") {
		sinks[s] = true
	}
	adapterRefs := conceptRefsIn(t, "adapters")
	ruleRefs := conceptRefsIn(t, "packs")
	var latent []string
	for s := range sinks {
		if deferred[s] {
			continue
		}
		if ruleRefs[s] && !adapterRefs[s] {
			latent = append(latent, s)
		}
	}
	sort.Strings(latent)
	for _, s := range latent {
		t.Errorf("sink concept %q is consumed by a rule but wired in NO adapter — latent rule (wire it or document-defer)", s)
	}
	t.Logf("sink concepts: %d defined, %d adapter-wired", len(sinks), countWired(sinks, adapterRefs))
}

func countWired(sinks, wired map[string]bool) int {
	n := 0
	for s := range sinks {
		if wired[s] {
			n++
		}
	}
	return n
}

// conceptsByKind returns the set of concept names of the given kind (sink/source/control).
func conceptsByKind(t *testing.T, kind string) map[string]bool {
	out := map[string]bool{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts.vyql") {
		for _, decl := range decls {
			cd, ok := decl.(*parser.ConceptDecl)
			if ok && cd.Kind == kind {
				out[cd.Name] = true
			}
		}
	}
	return out
}

func conceptsWithBoolField(t *testing.T, kind, field string) map[string]bool {
	out := map[string]bool{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts.vyql") {
		for _, decl := range decls {
			cd, ok := decl.(*parser.ConceptDecl)
			if !ok || cd.Kind != kind {
				continue
			}
			switch v := cd.Fields[field].(type) {
			case bool:
				if v {
					out[cd.Name] = true
				}
			case string:
				if v == "true" {
					out[cd.Name] = true
				}
			}
		}
	}
	return out
}

// T2.1 — every SOURCE concept is wired in an adapter (something produces it) OR is in the
// documented reserved vocabulary set in ontology metadata (defined ahead of wiring; the input
// may currently be subsumed by a broader source, or belong to an archetype not yet wired).
// A NEW source concept must be wired or explicitly marked `coverage_reserved_source: true`.
func TestSourceConceptsWiredGate(t *testing.T) {
	reserved := conceptsWithBoolField(t, "source", "coverage_reserved_source")
	sources := conceptsByKind(t, "source")
	wired := conceptRefsIn(t, "adapters")
	var unwired []string
	for s := range sources {
		if reserved[s] || wired[s] {
			continue
		}
		unwired = append(unwired, s)
	}
	sort.Strings(unwired)
	for _, s := range unwired {
		t.Errorf("source concept %q is wired in NO adapter and not reserved — wire it or add to the reserved set", s)
	}
	t.Logf("source concepts: %d defined, %d reserved-vocabulary", len(sources), len(reserved))
}

// T2.3 — every CONTROL concept WIRED in an adapter must be consumed by some rule's
// coveredBy clause; a wired control no rule reads is INERT (neutralizes
// nothing). This is the gate that catches the OutputEncoding-style mistake. (A control
// defined-but-not-wired is just unused vocabulary and is fine.)
func TestControlsWiredAreConsumedGate(t *testing.T) {
	reserved := conceptsWithBoolField(t, "control", "coverage_reserved_control")
	controls := conceptsByKind(t, "control")
	wired := conceptRefsIn(t, "adapters")
	consumed := map[string]bool{}
	for _, decls := range parseDataDecls(t, "packs", ".vyql") {
		for _, decl := range decls {
			rule, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			for _, clause := range rule.Clauses {
				switch ex := clause.Unless.(type) {
				case parser.PathCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.EndpointCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.DominatesCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.PostDominatesCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.SameReceiverCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.SameScopeCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				case parser.GlobalCoveredBy:
					consumed[shortConceptName(ex.Concept)] = true
				}
			}
		}
	}
	var inert []string
	for ctrl := range controls {
		if reserved[ctrl] {
			continue
		}
		if wired[ctrl] && !consumed[ctrl] {
			inert = append(inert, ctrl)
		}
	}
	sort.Strings(inert)
	for _, ctrl := range inert {
		t.Errorf("control %q is wired in an adapter but consumed by NO rule — inert wiring", ctrl)
	}
	t.Logf("control concepts: %d defined, %d consumed by rules", len(controls), len(consumed))
}

// T0.9 — language-construct gate. Every frontend in the `languages` table must be
// exercised by at least one test: a `.test.vyql` spec that targets it, or a NIR golden
// (testdata/golden/<lang>.golden). A NEW language with neither fails here — forcing a
// construct/behaviour test for every frontend that ships.
func TestEveryLanguageHasATest(t *testing.T) {
	// languages targeted by a code/graph spec (`lang <name>`); graph specs have no lang.
	specLangs := map[string]bool{}
	for _, c := range readDataFiles(t, "tests", ".test.vyql") {
		for _, ln := range strings.Split(c, "\n") {
			if f := strings.Fields(strings.TrimSpace(ln)); len(f) == 2 && f[0] == "lang" {
				specLangs[f[1]] = true
			}
		}
	}
	for _, lg := range languages {
		if specLangs[lg.name] {
			continue
		}
		if _, err := os.Stat(filepath.Join("testdata", "golden", lg.name+".golden")); err == nil {
			continue
		}
		t.Errorf("frontend %q has neither a .test.vyql spec nor a NIR golden — add a construct test", lg.name)
	}
	t.Logf("frontends: %d in table, %d covered by a spec", len(languages), len(specLangs))
}

// T0.3 — every ontology threat reference resolves to a defined threat in the
// correct package.
func TestThreatRefsResolveGate(t *testing.T) {
	defined := map[string]bool{} // "pkg.Threat"
	for _, decls := range parseDataDecls(t, "ontology", "threatkinds.vyql") {
		for _, decl := range decls {
			if td, ok := decl.(*parser.ThreatDecl); ok {
				defined[td.QualifiedName()] = true
			}
		}
	}
	for f, decls := range parseDataDecls(t, "ontology", "concepts.vyql") {
		for _, decl := range decls {
			cd, ok := decl.(*parser.ConceptDecl)
			if !ok {
				continue
			}
			for _, key := range []string{"vulnerable_to", "neutralizes"} {
				for _, ref := range fieldStringList(cd.Fields, key) {
					if !defined[ref] {
						t.Errorf("%s references threat %q which is not defined in threatkinds.vyql", filepath.Base(f), ref)
					}
				}
			}
		}
	}
	t.Logf("threat refs: %d threats defined", len(defined))
}

// T0.4 — no duplicate concept names, rule ids, or (package-qualified) threat names.
func TestNoDuplicateNamesGate(t *testing.T) {
	seen := map[string]int{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts.vyql") {
		for _, decl := range decls {
			if cd, ok := decl.(*parser.ConceptDecl); ok {
				seen[cd.QualifiedName()]++
			}
		}
	}
	for n, k := range seen {
		if k > 1 {
			t.Errorf("duplicate concept %q (%d definitions)", n, k)
		}
	}
	ids := map[string]int{}
	for _, decls := range parseDataDecls(t, "packs", ".vyql") {
		for _, decl := range decls {
			r, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			if id, _ := r.Meta["id"].(string); id != "" {
				ids[id]++
			}
		}
	}
	for n, k := range ids {
		if k > 1 {
			t.Errorf("duplicate rule id %q (%d definitions)", n, k)
		}
	}
	thr := map[string]int{}
	for _, decls := range parseDataDecls(t, "ontology", "threatkinds.vyql") {
		for _, decl := range decls {
			if td, ok := decl.(*parser.ThreatDecl); ok {
				thr[td.QualifiedName()]++
			}
		}
	}
	for n, k := range thr {
		if k > 1 {
			t.Errorf("duplicate threat %q (%d definitions)", n, k)
		}
	}
}

// V2 migration gate — every shipped definition file must be production v2.
// This is intentionally corpus-wide rather than layer-specific: it catches
// legacy v1 files left in less common directories such as profiles, review
// metadata, generated package bindings, or future definition roots.
func TestShippedDefinitionCorpusIsV2Only(t *testing.T) {
	files, err := vyqlFilesUnder(datadir.Root())
	if err != nil {
		t.Fatalf("collect shipped definition files: %v", err)
	}
	checked, err := checkV2DefinitionFiles(files)
	if err != nil {
		t.Fatalf("shipped definition corpus must be v2-only: %v", err)
	}
	if checked < 30000 {
		t.Fatalf("checked only %d v2 definition files; want the full shipped corpus", checked)
	}
	t.Logf("checked %d shipped v2 definition files", checked)
}

func TestShippedDefinitionsDoNotAuthorGoOwnedMechanics(t *testing.T) {
	var hits []string
	root := filepath.Join(datadir.Root(), "mechanics")
	if _, err := os.Stat(root); err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("stat mechanics dir: %v", err)
		}
		root = ""
	}
	if root != "" {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".vyql") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			src := string(data)
			if !strings.Contains(src, "mechanic ruleVerb") && !strings.Contains(src, "mechanic coverage") {
				return nil
			}
			rel, _ := filepath.Rel(datadir.Root(), path)
			hits = append(hits, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("walk mechanics dir: %v", err)
		}
	}
	files, err := vyqlFilesUnder(datadir.Root())
	if err != nil {
		t.Fatalf("collect shipped definition files: %v", err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(data)
		if !strings.Contains(src, "assume") {
			continue
		}
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "assume ") ||
				strings.HasPrefix(trimmed, "where assume(") ||
				strings.Contains(trimmed, " assume(") ||
				strings.Contains(trimmed, " and assume(") ||
				strings.Contains(trimmed, " or assume(") {
				rel, _ := filepath.Rel(datadir.Root(), path)
				hits = append(hits, filepath.ToSlash(rel)+": "+trimmed)
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("Go-owned v2 mechanics must not be authored in shipped definitions:\n%s", strings.Join(hits, "\n"))
	}
}

func TestShippedDefinitionsDoNotUseLegacyV1Syntax(t *testing.T) {
	files, err := vyqlFilesUnder(datadir.Root())
	if err != nil {
		t.Fatalf("collect shipped definition files: %v", err)
	}
	legacyLinePatterns := legacyV1DefinitionLinePatterns()
	var hits []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, pattern := range legacyLinePatterns {
				if pattern.MatchString(line) {
					rel, _ := filepath.Rel(datadir.Root(), path)
					hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), i+1, strings.TrimSpace(line)))
					break
				}
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("shipped non-test definitions must not use legacy v1 syntax:\n%s", strings.Join(hits, "\n"))
	}
}

func TestVyqlTestSpecsDoNotUseLegacyV1DefinitionSyntax(t *testing.T) {
	files := readDataFiles(t, "tests", ".test.vyql")
	legacyLinePatterns := legacyV1DefinitionLinePatterns()
	var hits []string
	for path, src := range files {
		inFence := false
		for i, line := range strings.Split(src, "\n") {
			if strings.TrimSpace(line) == "```" {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			for _, pattern := range legacyLinePatterns {
				if pattern.MatchString(line) {
					rel, _ := filepath.Rel(datadir.Root(), path)
					hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), i+1, strings.TrimSpace(line)))
					break
				}
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("test specs must use the declarative v2 spec format, not legacy v1 definition syntax:\n%s", strings.Join(hits, "\n"))
	}
}

func legacyV1DefinitionLinePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`^\s*adapter\s+[A-Za-z0-9_.-]+\s*\{`),
		regexp.MustCompile(`^\s*source\s+"`),
		regexp.MustCompile(`^\s*sink\s+(?:"|method\s+"|path\s+")`),
		regexp.MustCompile(`^\s*control\s+"`),
		regexp.MustCompile(`^\s*flag\s+[A-Za-z0-9_.]+\s+(?:on|in)\b`),
		regexp.MustCompile(`^\s*mark\s+`),
		regexp.MustCompile(`^\s*match\s+[A-Za-z0-9_.]+\s+as\b`),
		regexp.MustCompile(`^\s*package\s+"`),
		regexp.MustCompile(`^\s*analysis_role\s*:`),
		regexp.MustCompile(`^\s*assume(?:MinLevel|_min_level)\s*:`),
		regexp.MustCompile(`\bunless\s+(?:sanitized_by|guarded_by|closed_by)\b`),
		regexp.MustCompile(`\b(?:has|lacks)\s+"(?:call_path|literal|selector|identifier|function_name|class_name|class_base|class_bases|attr_path|decorator_path|decorator_method|param_name|param_type|param_index|var_name|return):`),
	}
}

// T0.5 — every adapter loads (parses v2 bindings and builds graph-labeling actions)
// without panicking, for every adapter shipped under vyql/adapters/.
func TestAllAdaptersLoadGate(t *testing.T) {
	root := filepath.Join(datadir.Root(), "adapters")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read adapters: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "packages" {
			continue
		}
		tech := entry.Name()
		t.Run(tech, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("adapter %q failed to load: %v", tech, r)
				}
			}()
			if n := len(frontend.AdaptersFor(tech)); n == 0 {
				t.Errorf("adapter %q produced no adapters", tech)
			}
		})
	}
}

func TestEverySourceLanguageHasV2TaintEndpointCoverage(t *testing.T) {
	for _, lang := range sourceLanguagesForCoverage() {
		t.Run(lang, func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(datadir.Root(), "tests", "coverage_"+lang+"_exhaustive.test.vyql")); err != nil {
				t.Fatalf("missing exhaustive language coverage spec: %v", err)
			}
			if _, err := os.Stat(filepath.Join(datadir.Root(), "adapters", "packages", lang)); err != nil {
				t.Fatalf("missing package catalog for %q: %v", lang, err)
			}
			sourceCount, sinkCount := countV2TaintEndpointMappings(t, filepath.Join("adapters", lang), filepath.Join("adapters", "packages", lang))
			if sourceCount == 0 {
				t.Fatalf("%q has no v2 source endpoint definitions", lang)
			}
			if sinkCount == 0 {
				t.Fatalf("%q has no v2 sink endpoint definitions", lang)
			}
			if n := len(frontend.AdaptersFor(lang)); n == 0 {
				t.Fatalf("%q frontend produced no runtime adapters", lang)
			}
		})
	}
}

func TestProductionDefinitionsDoNotUseLegacyV1ParserOrBridge(t *testing.T) {
	root := testRepoRoot(t)
	var hits []string
	legacyParserCalls := []string{
		"parser.Parse(",
		"parser.ParseRuntime",
		"parser.ParseRuntimeSources",
		"parser.ParseV2Runtime",
		"parser.RuntimeSource",
		"parser.RuntimeSourcesFromText",
		"parser.LowerRuntimeSources",
		"parser.LowerV2ToRuntime",
		"parser.AdapterDecl",
		"parser.AdapterMapping",
		"parser.AdapterFlag",
	}
	legacyParserDefinitions := []string{
		"func Parse(",
		"func ParseRuntime",
		"func ParseRuntimeSources",
		"func ParseV2Runtime",
		"type RuntimeSource",
		"func RuntimeSourcesFromText",
		"func LowerRuntimeSources",
		"func LowerV2ToRuntime",
		"type AdapterDecl",
		"type AdapterMapping",
		"type AdapterFlag",
	}
	legacyCoverageClauses := []string{
		"sanitized_by",
		"guarded_by",
		"closed_by",
	}
	legacyMetadataNames := []string{
		"assume_min_level",
		"analysis_role",
		"AssumeMinLevel",
		"assumeMinLevel",
	}
	securityConceptNames := []string{
		"ResourceRelease",
		"LockRelease",
	}
	err := filepath.WalkDir(filepath.Join(root, "go"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		importsVyqlParser := strings.Contains(src, `"github.com/vyprai/vyql/parser"`)
		usesLegacy := false
		for _, snippet := range legacyCoverageClauses {
			if strings.Contains(src, snippet) {
				usesLegacy = true
				break
			}
		}
		for _, snippet := range legacyMetadataNames {
			if strings.Contains(src, snippet) {
				usesLegacy = true
				break
			}
		}
		for _, snippet := range securityConceptNames {
			if strings.Contains(src, snippet) {
				usesLegacy = true
				break
			}
		}
		if importsVyqlParser {
			for _, snippet := range legacyParserCalls {
				if strings.Contains(src, snippet) {
					usesLegacy = true
					break
				}
			}
		}
		if strings.HasPrefix(rel, "go/parser/") {
			for _, snippet := range legacyParserDefinitions {
				if strings.Contains(src, snippet) {
					usesLegacy = true
					break
				}
			}
		}
		if usesLegacy {
			hits = append(hits, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan go sources: %v", err)
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("production code must not define or call the legacy v1 parser or runtime bridge:\n%s", strings.Join(hits, "\n"))
	}
}

func TestDefinitionsDoNotUseLegacyFlagBridge(t *testing.T) {
	var hits []string
	for path, src := range readDataFiles(t, "adapters", ".vyql") {
		lines := strings.Split(src, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "query unstable.legacyFlag") {
				continue
			}
			rel, _ := filepath.Rel(datadir.Root(), path)
			hits = append(hits, filepath.ToSlash(rel)+":"+strconv.Itoa(i+1)+": "+trimmed)
			if len(hits) >= 20 {
				break
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("definitions must use stable `callExpr` or `presenceNode` patterns, not unstable.legacyFlag:\n%s", strings.Join(hits, "\n"))
	}
}

func sourceLanguagesForCoverage() []string {
	out := make([]string, 0, len(languages))
	for _, lg := range languages {
		switch lg.name {
		case "config", "textpattern":
			continue
		default:
			out = append(out, lg.name)
		}
	}
	sort.Strings(out)
	return out
}

func countV2TaintEndpointMappings(t *testing.T, subs ...string) (int, int) {
	t.Helper()
	sourceCount, sinkCount := 0, 0
	for _, sub := range subs {
		for path, src := range readDataFiles(t, sub, ".vyql") {
			decls, err := parseV2DefinitionsForTest(src)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, decl := range decls {
				adapter, ok := decl.(*parser.BindingSet)
				if !ok {
					continue
				}
				for _, mapping := range adapter.Mappings {
					switch {
					case strings.HasPrefix(mapping.Kind, "source"):
						sourceCount++
					case strings.HasPrefix(mapping.Kind, "sink"):
						sinkCount++
					}
				}
			}
		}
	}
	return sourceCount, sinkCount
}

func TestCVE1000LedgerCoverageGate(t *testing.T) {
	repo := testRepoRoot(t)
	poolPath := filepath.Join(repo, "cve-1000", "pool.tsv")
	ledgerPath := filepath.Join(repo, "cve-1000", "ledger.tsv")
	poolRaw, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatalf("read CVE pool: %v", err)
	}
	ledgerRaw, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read CVE ledger: %v", err)
	}

	poolRows := nonemptyTSVRows(string(poolRaw))
	if len(poolRows) != 1000 {
		t.Fatalf("cve-1000 pool rows = %d, want 1000", len(poolRows))
	}
	ledgerRows := nonemptyTSVRows(string(ledgerRaw))
	if len(ledgerRows) != len(poolRows) {
		t.Fatalf("cve-1000 ledger rows = %d, want exactly %d pool rows", len(ledgerRows), len(poolRows))
	}
	covered := make(map[int]bool, len(poolRows))
	ledgerByRank := make(map[int]string, len(poolRows))
	statuses := map[string]int{}
	for i, row := range ledgerRows {
		fields := strings.SplitN(row, "\t", 6)
		if len(fields) != 6 {
			t.Fatalf("ledger row %d has %d fields, want 6: %q", i+1, len(fields), row)
		}
		rank, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("ledger row %d has invalid rank %q", i+1, fields[0])
		}
		if rank < 0 || rank >= len(poolRows) {
			t.Fatalf("ledger row %d rank %d outside pool range 0..%d", i+1, rank, len(poolRows)-1)
		}
		status := fields[4]
		switch status {
		case "CAUGHT", "FIXED", "ATTENTION", "SKIP":
			statuses[status]++
		default:
			t.Fatalf("ledger row %d rank %d has unknown status %q", i+1, rank, status)
		}
		if prev, ok := ledgerByRank[rank]; ok {
			t.Fatalf("cve-1000 ledger rank %d appears more than once:\nfirst: %s\nagain: %s", rank, prev, row)
		}
		ledgerByRank[rank] = row
		covered[rank] = true
	}
	var missing []string
	for rank := range poolRows {
		if !covered[rank] {
			missing = append(missing, strconv.Itoa(rank))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("cve-1000 ledger missing %d pool rank(s): %s", len(missing), strings.Join(missing, ", "))
	}

	cveSpecs := readCVERankSpecFiles(t)
	specRanksByRank := map[int][]string{}
	for _, path := range cveSpecs {
		rank, ok := cveRankFromSpecName(filepath.Base(path))
		if !ok {
			t.Fatalf("CVE spec file has invalid rank name: %s", filepath.Base(path))
		}
		if _, ok := ledgerByRank[rank]; !ok {
			t.Fatalf("CVE spec %s references rank %d which is not present in cve-1000 ledger", filepath.Base(path), rank)
		}
		specRanksByRank[rank] = append(specRanksByRank[rank], filepath.Base(path))
	}
	uniqueSpecRanks := map[int]bool{}
	for rank, names := range specRanksByRank {
		uniqueSpecRanks[rank] = true
		if len(names) > 1 && !cve1000AllowedDuplicateSpecRanks[rank] {
			sort.Strings(names)
			t.Fatalf("CVE rank %d has %d spec files but is not in the duplicate-spec allowlist: %s", rank, len(names), strings.Join(names, ", "))
		}
	}
	for rank := range cve1000AllowedDuplicateSpecRanks {
		if len(specRanksByRank[rank]) < 2 {
			t.Fatalf("CVE duplicate-spec allowlist rank %d is stale; found %d spec file(s)", rank, len(specRanksByRank[rank]))
		}
	}
	if len(cveSpecs) < 787 || len(uniqueSpecRanks) < 781 {
		t.Fatalf("CVE runnable rank specs regressed: files=%d unique_ranks=%d, want at least files=787 unique_ranks=781", len(cveSpecs), len(uniqueSpecRanks))
	}

	var missingRunnable, staleNoSpecExceptions, skipWithSpecs []string
	for rank, row := range ledgerByRank {
		fields := strings.SplitN(row, "\t", 6)
		status := fields[4]
		hasSpec := uniqueSpecRanks[rank]
		switch {
		case status == "SKIP" && hasSpec:
			skipWithSpecs = append(skipWithSpecs, fmt.Sprintf("%d", rank))
		case status != "SKIP" && !hasSpec && !cve1000AcceptedNoSpecRanks[rank]:
			missingRunnable = append(missingRunnable, fmt.Sprintf("%d:%s", rank, status))
		}
	}
	for rank := range cve1000AcceptedNoSpecRanks {
		row, ok := ledgerByRank[rank]
		if !ok {
			staleNoSpecExceptions = append(staleNoSpecExceptions, fmt.Sprintf("%d:missing-ledger", rank))
			continue
		}
		fields := strings.SplitN(row, "\t", 6)
		if fields[4] == "SKIP" {
			staleNoSpecExceptions = append(staleNoSpecExceptions, fmt.Sprintf("%d:skip-status", rank))
			continue
		}
		if uniqueSpecRanks[rank] {
			staleNoSpecExceptions = append(staleNoSpecExceptions, fmt.Sprintf("%d:now-has-spec", rank))
		}
	}
	if len(skipWithSpecs) > 0 {
		sort.Strings(skipWithSpecs)
		t.Fatalf("CVE SKIP ranks must not have runnable specs; remove skip or spec: %s", strings.Join(skipWithSpecs, ", "))
	}
	if len(missingRunnable) > 0 {
		sort.Strings(missingRunnable)
		t.Fatalf("CVE non-SKIP ledger ranks without runnable specs must be listed in cve1000AcceptedNoSpecRanks: %s", strings.Join(missingRunnable, ", "))
	}
	if len(staleNoSpecExceptions) > 0 {
		sort.Strings(staleNoSpecExceptions)
		t.Fatalf("CVE no-spec exception list is stale; remove or fix: %s", strings.Join(staleNoSpecExceptions, ", "))
	}
	t.Logf("cve-1000 ledger: pool=%d ledger_rows=%d unique_ranks=%d statuses=%v cve_specs=%d unique_spec_ranks=%d",
		len(poolRows), len(ledgerRows), len(covered), statuses, len(cveSpecs), len(uniqueSpecRanks))
}

var cve1000AllowedDuplicateSpecRanks = map[int]bool{
	474: true,
	495: true,
	795: true,
	835: true,
	853: true,
	955: true,
}

// cve1000AcceptedNoSpecRanks is the explicit burn-down list for non-SKIP ledger
// rows that are currently verified only by the CVE prep/eval ledger rather than a
// runnable cve_rank*.test.vyql spec. Adding a runnable rank spec must remove the
// rank here; new non-SKIP ledger rows without specs fail the gate.
var cve1000AcceptedNoSpecRanks = map[int]bool{
	0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 8: true, 9: true, 10: true, 11: true, 12: true, 13: true, 14: true, 15: true,
	16: true, 17: true, 18: true, 19: true, 20: true, 21: true, 22: true, 23: true, 24: true, 25: true, 26: true, 27: true, 28: true, 29: true, 30: true, 31: true,
	32: true, 33: true, 34: true, 35: true, 36: true, 37: true, 38: true, 39: true, 40: true, 41: true, 42: true, 43: true, 44: true, 45: true, 46: true, 47: true,
	48: true, 49: true, 50: true, 51: true, 52: true, 53: true, 54: true, 55: true, 56: true, 57: true, 58: true, 59: true, 60: true, 61: true, 62: true, 63: true,
	64: true, 65: true, 66: true, 67: true, 68: true, 69: true, 70: true, 71: true, 72: true, 73: true, 74: true, 75: true, 76: true, 77: true, 78: true, 79: true,
	80: true, 81: true, 82: true, 83: true, 84: true, 85: true, 86: true, 87: true, 88: true, 89: true, 90: true, 91: true, 92: true, 93: true, 94: true, 95: true,
	96: true, 97: true, 98: true, 99: true, 100: true, 101: true, 102: true, 103: true, 104: true, 105: true, 106: true, 107: true, 108: true, 109: true, 110: true, 111: true,
	112: true, 113: true, 114: true, 115: true, 116: true, 117: true, 118: true, 119: true, 120: true, 121: true, 122: true, 123: true, 124: true, 127: true, 128: true, 131: true,
	132: true, 133: true, 134: true, 135: true, 136: true, 137: true, 144: true, 145: true, 160: true, 170: true, 177: true, 183: true, 184: true, 199: true, 208: true, 217: true,
	218: true, 230: true, 231: true, 289: true, 293: true, 302: true, 312: true, 325: true, 329: true, 338: true, 339: true, 342: true, 345: true, 459: true, 461: true, 463: true,
	465: true, 466: true, 489: true, 511: true, 516: true, 522: true, 531: true, 537: true, 538: true, 540: true, 543: true, 544: true, 547: true, 556: true, 561: true, 566: true,
	568: true, 573: true, 574: true, 583: true, 588: true, 591: true, 592: true, 597: true, 609: true, 641: true, 643: true, 710: true, 717: true, 720: true, 721: true, 789: true,
	791: true, 800: true, 819: true, 824: true, 829: true, 996: true,
}

func nonemptyTSVRows(src string) []string {
	lines := strings.Split(src, "\n")
	rows := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, line)
		}
	}
	return rows
}

func readCVERankSpecFiles(t *testing.T) []string {
	t.Helper()
	testsDir := filepath.Join(datadir.Root(), "tests")
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		t.Fatalf("read tests dir: %v", err)
	}
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(name, "cve_rank") && strings.HasSuffix(name, ".test.vyql") {
			out = append(out, filepath.Join(testsDir, name))
		}
	}
	sort.Strings(out)
	return out
}

func cveRankFromSpecName(name string) (int, bool) {
	if !strings.HasPrefix(name, "cve_rank") {
		return 0, false
	}
	rest := strings.TrimPrefix(name, "cve_rank")
	cut := strings.IndexByte(rest, '_')
	if cut < 0 {
		return 0, false
	}
	rank, err := strconv.Atoi(rest[:cut])
	return rank, err == nil
}

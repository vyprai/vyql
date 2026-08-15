package main

// These meta-tests enforce that
// every rule/concept/threat/binding stays tested and internally consistent — so a new
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

	"github.com/vyprai/vyql/internal/bindings"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/parser"
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

// parseDataBindingSets is parseDataDecls' companion: binding sets come from the binding
// compiler, not the declaration stream, so the same files are read through both.
func parseDataBindingSets(t *testing.T, sub, suffix string) map[string][]*bindings.Set {
	t.Helper()
	out := map[string][]*bindings.Set{}
	if !strings.HasPrefix(suffix, ".") {
		sources, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join(sub, strings.TrimSuffix(suffix, ".vyql"))))
		if err != nil {
			t.Fatalf("read %s/%s: %v", sub, suffix, err)
		}
		for _, source := range sources {
			sets, err := compileV2BindingsForTest(string(source.Data))
			if err != nil {
				t.Fatalf("compile %s: %v", source.Name, err)
			}
			out[source.Name] = sets
		}
		return out
	}
	for f, c := range readDataFiles(t, sub, suffix) {
		if sub == "mechanics" {
			continue
		}
		sets, err := compileV2BindingsForTest(c)
		if err != nil {
			t.Fatalf("compile %s: %v", filepath.Base(f), err)
		}
		out[f] = sets
	}
	return out
}

func parseDataDecls(t *testing.T, sub, suffix string) map[string][]parser.Decl {
	t.Helper()
	out := map[string][]parser.Decl{}
	if !strings.HasPrefix(suffix, ".") {
		sources, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join(sub, strings.TrimSuffix(suffix, ".vyql"))))
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

// T0.2 — every code/core concept reference in bindings and packs resolves to a defined
// concept. References come from the parsed VyQL AST, so string-literal sink paths
// (e.g. the Python `code` stdlib module) are not mistaken for concept refs.
func TestConceptRefsResolveGate(t *testing.T) {
	defined := map[string]bool{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts") {
		for _, decl := range decls {
			if cd, ok := decl.(*parser.ConceptDecl); ok {
				defined[cd.Name] = true
				defined[cd.QualifiedName()] = true
			}
		}
	}
	check := func(sub, suffix string) {
		for f, refs := range conceptRefsByFile(t, sub, suffix) {
			if isGeneratedBinding(f) {
				continue // generated corpus validated separately below
			}
			for ref := range refs {
				if !defined[ref] && !defined[shortConceptName(ref)] {
					t.Errorf("%s references concept %q which is not defined in ontology/concepts", filepath.Base(f), ref)
				}
			}
		}
	}
	check("bindings", ".vyql")
	check("packs", ".vyql")
	// the dynamically-loaded generated package corpus must also reference only real
	// concepts (a dead label otherwise), but it is excluded from the curated coherence
	// gates below because it legitimately wires broad concepts that have no curated rule.
	for f, refs := range conceptRefsByFile(t, "bindings", ".vyql") {
		if !isGeneratedBinding(f) {
			continue
		}
		for ref := range refs {
			if !defined[ref] && !defined[shortConceptName(ref)] {
				t.Errorf("generated binding %s references concept %q not defined in ontology/concepts", f, ref)
			}
		}
	}
	t.Logf("concept refs: %d concepts defined", len(defined))
}

// isGeneratedBinding reports whether a data-file path is part of the dynamically-loaded
// generated package-binding corpus (bindings/packages/generated/<lang>/<pkg>.vyql), which
// is auxiliary content gated at scan time and excluded from the curated coherence gates.
func isGeneratedBinding(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "/bindings/packages/generated/")
}

// conceptRefsIn returns the set of code/core concept names referenced (as targets or
// in rule clauses) across the given vyql/<sub> files.
func conceptRefsIn(t *testing.T, sub string) map[string]bool {
	out := map[string]bool{}
	for f, refs := range conceptRefsByFile(t, sub, ".vyql") {
		if isGeneratedBinding(f) {
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
	sets := parseDataBindingSets(t, sub, suffix)
	for f, decls := range parseDataDecls(t, sub, suffix) {
		refs := map[string]bool{}
		for _, decl := range decls {
			if d, ok := decl.(*parser.Rule); ok {
				collectRuleConceptRefs(d, refs)
			}
		}
		for _, set := range sets[f] {
			for _, m := range set.Mappings {
				if m.Concept != "" && m.Kind != "type" {
					addCoverageConceptRef(refs, m.Concept)
				}
				if m.About != "" && m.About != "*" {
					addCoverageConceptRef(refs, m.About)
				}
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
// in at least one binding (otherwise the rule is latent — it can never fire). This is
// the gate that catches dead sinks (e.g. the reflection/log/header sinks that shipped
// referenced-but-unwired). The allowlist holds sinks for documented-deferred rules.
func TestSinkConceptsWiredGate(t *testing.T) {
	// no deferred sinks — every sink a rule consumes is binding-wired.
	deferred := map[string]bool{}
	sinks := map[string]bool{}
	for s := range conceptsByKind(t, "sink") {
		sinks[s] = true
	}
	adapterRefs := conceptRefsIn(t, "bindings")
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
		t.Errorf("sink concept %q is consumed by a rule but wired in NO binding — latent rule (wire it or document-defer)", s)
	}
	t.Logf("sink concepts: %d defined, %d binding-wired", len(sinks), countWired(sinks, adapterRefs))
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
	for _, decls := range parseDataDecls(t, "ontology", "concepts") {
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
	for _, decls := range parseDataDecls(t, "ontology", "concepts") {
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

// T2.1 — every SOURCE concept is wired in a binding (something produces it) OR is in the
// documented reserved vocabulary set in ontology metadata (defined ahead of wiring; the input
// may currently be subsumed by a broader source, or belong to an archetype not yet wired).
// A NEW source concept must be wired or explicitly marked `coverageReservedSource: true`.
func TestSourceConceptsWiredGate(t *testing.T) {
	reserved := conceptsWithBoolField(t, "source", "coverage_reserved_source")
	sources := conceptsByKind(t, "source")
	wired := conceptRefsIn(t, "bindings")
	var unwired []string
	for s := range sources {
		if reserved[s] || wired[s] {
			continue
		}
		unwired = append(unwired, s)
	}
	sort.Strings(unwired)
	for _, s := range unwired {
		t.Errorf("source concept %q is wired in NO binding and not reserved — wire it or add to the reserved set", s)
	}
	t.Logf("source concepts: %d defined, %d reserved-vocabulary", len(sources), len(reserved))
}

// T2.3 — every CONTROL concept WIRED in a binding must be consumed by some rule's
// coveredBy clause; a wired control no rule reads is INERT (neutralizes
// nothing). This is the gate that catches the OutputEncoding-style mistake. (A control
// defined-but-not-wired is just unused vocabulary and is fine.)
func TestControlsWiredAreConsumedGate(t *testing.T) {
	reserved := conceptsWithBoolField(t, "control", "coverage_reserved_control")
	controls := conceptsByKind(t, "control")
	wired := conceptRefsIn(t, "bindings")
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
		t.Errorf("control %q is wired in a binding but consumed by NO rule — inert wiring", ctrl)
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
	for _, lg := range frontend.Languages() {
		if specLangs[lg.Name] {
			continue
		}
		if _, err := os.Stat(filepath.Join("testdata", "golden", lg.Name+".golden")); err == nil {
			continue
		}
		t.Errorf("frontend %q has neither a .test.vyql spec nor a NIR golden — add a construct test", lg.Name)
	}
	t.Logf("frontends: %d in table, %d covered by a spec", len(frontend.Languages()), len(specLangs))
}

// T0.3 — every ontology threat reference resolves to a defined threat in the
// correct package.
func TestThreatRefsResolveGate(t *testing.T) {
	defined := map[string]bool{} // "pkg.Threat"
	for _, decls := range parseDataDecls(t, "ontology", "threatkinds") {
		for _, decl := range decls {
			if td, ok := decl.(*parser.ThreatDecl); ok {
				defined[td.QualifiedName()] = true
			}
		}
	}
	for f, decls := range parseDataDecls(t, "ontology", "concepts") {
		for _, decl := range decls {
			cd, ok := decl.(*parser.ConceptDecl)
			if !ok {
				continue
			}
			for _, key := range []string{"vulnerable_to", "neutralizes"} {
				for _, ref := range fieldStringList(cd.Fields, key) {
					if !defined[ref] {
						t.Errorf("%s references threat %q which is not defined in ontology/threatkinds", filepath.Base(f), ref)
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
	for _, decls := range parseDataDecls(t, "ontology", "concepts") {
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
	for _, decls := range parseDataDecls(t, "ontology", "threatkinds") {
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
	// Every file the walk collected must have been validated. This is the real
	// invariant; a subset silently passing is what the gate exists to stop.
	if checked != len(files) {
		t.Fatalf("validated %d of %d collected definition files", checked, len(files))
	}
	// A presence check, not a coverage metric. It guards the failure where the
	// walk matches nothing and a clean run reports over an empty set. The bound
	// is deliberately far below the real corpus so it does not have to move
	// whenever the data is reshaped -- how the definitions are laid out across
	// files is not what this test is about. The count that does track coverage
	// is the binding floor in data.yml, which is layout-independent.
	if checked < 10000 {
		t.Fatalf("only %d definition files found; the shipped corpus is missing or truncated", checked)
	}
	t.Logf("checked %d shipped v2 definition files", checked)
}

func TestShippedDefinitionsDoNotAuthorLanguageMechanics(t *testing.T) {
	authoredAssumeCall := regexp.MustCompile(`(^|[^A-Za-z0-9_.])assume\s*\(`)
	var hits []string
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
		prog, err := parser.ParseV2(src)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range prog.Decls {
			if mechanic, ok := decl.(*parser.V2MechanicDecl); ok {
				rel, _ := filepath.Rel(datadir.Root(), path)
				hits = append(hits, filepath.ToSlash(rel)+": mechanic "+mechanic.Kind+" "+mechanic.Name)
			}
		}
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "assume ") ||
				strings.HasPrefix(trimmed, "analysisRole:") ||
				authoredAssumeCall.MatchString(trimmed) {
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

func TestShippedProfilesUseV2DetectPredicates(t *testing.T) {
	files := readDataFiles(t, "profiles", ".vyql")
	legacyDetect := regexp.MustCompile(`detect:\s*\[\s*"[^"]+:[^"]*"`)
	quotedPriority := regexp.MustCompile(`priority:\s*"[0-9]+"`)
	var hits []string
	for path, src := range files {
		if legacyDetect.MatchString(src) {
			rel, _ := filepath.Rel(datadir.Root(), path)
			hits = append(hits, filepath.ToSlash(rel)+": legacy detect fingerprints")
		}
		if quotedPriority.MatchString(src) {
			rel, _ := filepath.Rel(datadir.Root(), path)
			hits = append(hits, filepath.ToSlash(rel)+": quoted numeric priority")
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("profiles must use native v2 field syntax:\n%s", strings.Join(hits, "\n"))
	}
}

func TestShippedModelDefinitionsUseV2FieldNames(t *testing.T) {
	snakeField := regexp.MustCompile(`^\s*[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*\s*:`)
	files := map[string]string{}
	for _, sub := range []string{"ontology", "review", "packs"} {
		for path, src := range readDataFiles(t, sub, ".vyql") {
			files[path] = src
		}
	}
	var hits []string
	for path, src := range files {
		for i, line := range strings.Split(src, "\n") {
			if snakeField.MatchString(line) {
				rel, _ := filepath.Rel(datadir.Root(), path)
				hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), i+1, strings.TrimSpace(line)))
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("model, review, and pack definitions must author v2 camelCase field names:\n%s", strings.Join(hits, "\n"))
	}
}

func TestVyqlTestSpecsDoNotUseLegacyV1DefinitionSyntax(t *testing.T) {
	files := readDataFiles(t, "tests", ".test.vyql")
	legacyLinePatterns := legacyV1DefinitionLinePatterns()
	legacySpecPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^\s*adapter\s+\S+\s*$`),
		regexp.MustCompile(`^\s*expect_evidence\s+\S+\s+assumption\s*$`),
		regexp.MustCompile(`^\s*reject_evidence\s+\S+\s+assumption\s*$`),
	}
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
			for _, pattern := range legacySpecPatterns {
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
		regexp.MustCompile(`^\s*adapter\s*:\s*\{`),
		regexp.MustCompile(`^\s*pattern\s+adapterMetadata\s*\{`),
		regexp.MustCompile(`^\s*source\s+"`),
		regexp.MustCompile(`^\s*sink\s+(?:"|method\s+"|path\s+")`),
		regexp.MustCompile(`^\s*control\s+"`),
		regexp.MustCompile(`^\s*flag\s+[A-Za-z0-9_.]+\s+(?:on|in)\b`),
		regexp.MustCompile(`^\s*mark\s+`),
		regexp.MustCompile(`^\s*match\s+[A-Za-z0-9_.]+\s+as\b`),
		regexp.MustCompile(`^\s*package\s+"`),
		regexp.MustCompile(`^\s*module\s+bindings\.[A-Za-z0-9_.-]+\.migration(?:\.|;)`),
		regexp.MustCompile(`^\s*analysis_role\s*:`),
		regexp.MustCompile(`^\s*assume(?:MinLevel|_min_level)\s*:`),
		regexp.MustCompile(`\bunless\s+(?:sanitized_by|guarded_by|closed_by)\b`),
		regexp.MustCompile(`\b(?:has|lacks)\s+"(?:call_path|literal|selector|identifier|function_name|class_name|class_base|class_bases|attr_path|decorator_path|decorator_method|param_name|param_type|param_index|var_name|return):`),
	}
}

// T0.5 — every binding set loads (parses v2 bindings and builds graph-labeling
// applicators) without panicking, for every technology shipped under vyql/bindings/.
func TestAllBindingsLoadGate(t *testing.T) {
	root := filepath.Join(datadir.Root(), "bindings")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read bindings: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "packages" {
			continue
		}
		tech := entry.Name()
		t.Run(tech, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("binding set %q failed to load: %v", tech, r)
				}
			}()
			if n := len(bindings.BindingsFor(tech)); n == 0 {
				t.Errorf("binding set %q produced no graph-labeling applicators", tech)
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
			if _, err := os.Stat(filepath.Join(datadir.Root(), "bindings", "packages", lang)); err != nil {
				t.Fatalf("missing package catalog for %q: %v", lang, err)
			}
			sourceCount, sinkCount, checkCount := countV2TaintEndpointMappings(t, filepath.Join("bindings", lang), filepath.Join("bindings", "packages", lang))
			if sourceCount == 0 {
				t.Fatalf("%q has no v2 source endpoint definitions", lang)
			}
			if sinkCount == 0 {
				t.Fatalf("%q has no v2 sink endpoint definitions", lang)
			}
			if checkCount == 0 {
				t.Fatalf("%q has no v2 check coverage definitions", lang)
			}
			if n := len(bindings.BindingsFor(lang)); n == 0 {
				t.Fatalf("%q frontend produced no binding applicators", lang)
			}
		})
	}
}

func TestEveryExhaustiveLanguageCoverageSpecIsBalanced(t *testing.T) {
	for _, lang := range sourceLanguagesForCoverage() {
		t.Run(lang, func(t *testing.T) {
			path := filepath.Join(datadir.Root(), "tests", "coverage_"+lang+"_exhaustive.test.vyql")
			specs := parseSpecFile(t, path)
			if len(specs) < 4 {
				t.Fatalf("%s has %d exhaustive specs, want at least 4", filepath.Base(path), len(specs))
			}
			codeSpecs, positiveSpecs, cleanSpecs := 0, 0, 0
			totalExpect, totalReject := 0, 0
			var problems []string
			for _, spec := range specs {
				if spec.lang != lang {
					problems = append(problems, fmt.Sprintf("%s:%d %q uses lang %q, want %q", spec.src, spec.line, spec.name, spec.lang, lang))
				}
				if spec.graphSrc != "" {
					problems = append(problems, fmt.Sprintf("%s:%d %q uses graph-only coverage; exhaustive language coverage must run the source frontend", spec.src, spec.line, spec.name))
				}
				if len(spec.files) == 0 {
					problems = append(problems, fmt.Sprintf("%s:%d %q has no code block", spec.src, spec.line, spec.name))
				} else {
					codeSpecs++
				}
				if len(spec.expect) > 0 {
					positiveSpecs++
					totalExpect += len(spec.expect)
				}
				if len(spec.reject) > 0 {
					cleanSpecs++
					totalReject += len(spec.reject)
				}
			}
			if len(problems) > 0 {
				t.Fatalf("invalid exhaustive language coverage spec:\n%s", strings.Join(problems, "\n"))
			}
			if codeSpecs != len(specs) {
				t.Fatalf("%s has %d/%d specs with code blocks; every exhaustive language spec must exercise the frontend", filepath.Base(path), codeSpecs, len(specs))
			}
			if positiveSpecs == 0 || totalExpect == 0 {
				t.Fatalf("%s has no positive expect assertions", filepath.Base(path))
			}
			if cleanSpecs == 0 || totalReject == 0 {
				t.Fatalf("%s has no clean/reject assertions", filepath.Base(path))
			}
		})
	}
}

func TestCompiledV2BindingsDoNotUseLegacyActionFamilies(t *testing.T) {
	var hits []string
	for path, sets := range parseDataBindingSets(t, "bindings", ".vyql") {
		for _, binding := range sets {
			for _, action := range binding.Mappings {
				if strings.HasPrefix(action.Kind, "control") || strings.HasPrefix(action.Kind, "mark") || action.Kind == "flag" {
					hits = append(hits, filepath.ToSlash(path)+": "+binding.Name+" emits legacy compiled action "+action.Kind)
				}
			}
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("compiled v2 bindings must use v2 action families, not legacy v1 control/mark/flag:\n%s", strings.Join(hits, "\n"))
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
		"assume_guard_",
		"assume_sanitizer_",
	}
	legacyAuthoredSyntax := []string{
		"`package \"name\"",
		"`flag <concept> on|in",
	}
	legacyCLISurface := []string{
		"case \"adapters\"",
		"case \"validate-adapter\"",
		"cmdAdapters",
		"cmdValidateAdapter",
		"OverlayAdapters",
		"applyAdaptersIncremental",
		"syntheticIncrementalAdapters",
		"buildGraphWithSyntheticAdapters",
		"GeneratedPackageAdaptersFor",
		"AdaptersFor(",
		"AutoAdapters(",
		"ConfigAdapters(",
		"TextPatternAdapters(",
		"PythonAdapters(",
		"JsAdapters(",
		"RubyAdapters(",
		"GoAdapters(",
		"JavaAdapters(",
		"PHPAdapters(",
		"CSharpAdapters(",
		"CAdapters(",
		"CPPAdapters(",
		"RustAdapters(",
		"BashAdapters(",
		"ScalaAdapters(",
		"LuaAdapters(",
		"KotlinAdapters(",
		"PowerShellAdapters(",
		"SwiftAdapters(",
		"PerlAdapters(",
		"SolidityAdapters(",
		"ObjCAdapters(",
		"adaptersFromSpec",
		"loadAutoBindings",
		"parseGeneratedPackageAdapterSource",
		"adapter-overlay",
		"overlay adapter",
		"generated package adapter",
		"usage: vyql adapters",
		"validate-adapter parse",
		"json:\"adapters",
		"definition kind: all | concepts | rules | adapters",
		"github.com/vyprai/vyql/adapters",
		"adapters.Adapter",
		"adapters.Mapping",
		"adapters.Apply",
	}
	securityConceptNames := []string{
		"ResourceRelease",
		"LockRelease",
	}
	err := filepath.WalkDir(testGoSourceRoot(t), func(path string, d os.DirEntry, err error) error {
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
		importsVyqlParser := strings.Contains(src, `"github.com/vyprai/vyql/internal/parser"`)
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
		for _, snippet := range legacyAuthoredSyntax {
			if strings.Contains(src, snippet) {
				usesLegacy = true
				break
			}
		}
		for _, snippet := range legacyCLISurface {
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

// testGoSourceRoot returns the directory the Go packages live under. This
// repository keeps them in go/; the published tree puts them at the root.
func testGoSourceRoot(t *testing.T) string {
	t.Helper()
	root := testRepoRoot(t)
	if st, err := os.Stat(filepath.Join(root, "go")); err == nil && st.IsDir() {
		return filepath.Join(root, "go")
	}
	return root
}

// checkDocsLackSnippets reports any of `forbidden` appearing in the listed docs.
// A doc absent from this tree is skipped rather than fatal, because the two
// layouts publish different subsets -- but at least one must be found, so a
// wholesale rename cannot quietly turn the gate into a no-op.
func checkDocsLackSnippets(t *testing.T, root string, docs, forbidden []string) {
	t.Helper()
	var hits []string
	checked := 0
	for _, rel := range docs {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		checked++
		src := string(data)
		for _, snippet := range forbidden {
			if strings.Contains(src, snippet) {
				hits = append(hits, rel+": "+snippet)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("none of %v exist under %s -- the gate would pass vacuously", docs, root)
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("documents still use v1 terminology:\n%s", strings.Join(hits, "\n"))
	}
}

func TestPublicDocsUseV2BindingTerminology(t *testing.T) {
	root := testRepoRoot(t)
	docs := []string{"README.md", "go/README.md", "vyql/README.md", "CLAUDE.md", "AGENTS.md"}
	forbidden := []string{
		"concepts, threat-kinds, adapters",
		"pattern  →  concept  →  adapter",
		"per-language **adapters**",
		"framework/config/SCA/secret adapters",
		"adapter DSL reference",
		"adapter-content change",
		"adapter precedence / conflict resolution / provenance",
		"framework/config adapters",
		"adapter files",
		"Concepts, threat kinds, adapters",
		"`mechanic` and `policy` declarations define the security semantics",
		"v2 `mechanic` and `policy` declarations define the security semantics",
	}
	checkDocsLackSnippets(t, root, docs, forbidden)
}

func TestProductionGoUsesV2BindingTerminology(t *testing.T) {
	root := testRepoRoot(t)
	legacyTerms := regexp.MustCompile(`\b[Aa]dapters?\b`)
	var hits []string
	err := filepath.WalkDir(testGoSourceRoot(t), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if legacyTerms.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), i+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("production Go must use v2 binding/applicator terminology, not legacy adapter vocabulary:\n%s", strings.Join(hits, "\n"))
	}
}

func TestCurrentDesignDocsUseV2BindingTerminology(t *testing.T) {
	root := testRepoRoot(t)
	// The series lives at docs/ here and is published as docs/, so check both
	// spellings and let the checker skip whichever this tree does not have.
	//
	// 18 is spelled through a variable deliberately. The projection rewrites the
	// literal "docs/" to "docs/" everywhere, and 18 is not among the published
	// documents -- a rewritten literal would assert a docs/18 that never exists.
	designDir := "design"
	docs := []string{
		"docs/03-architecture-overview.md",
		"docs/07-adapters-and-patterns.md",
		"docs/03-architecture-overview.md",
		"docs/07-adapters-and-patterns.md",
		designDir + "/18-ai-integration.md",
	}
	forbidden := []string{
		"validate-adapter",
		"`adapters`",
		"adapter javascript",
		"adapter_decl",
		"unless sanitized_by",
		"unless guarded_by",
		"adapter application",
		"adapter labels",
		"adapter coverage",
		"AI adapters",
		"│ ADAPTERS",
	}
	checkDocsLackSnippets(t, root, docs, forbidden)

	// The v1 language spec is kept for history and must stay marked as such. It is
	// only present where the design series is.
	legacySpec, err := os.ReadFile(filepath.Join(root, "docs/05-language-specification.md"))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("read legacy language spec: %v", err)
	}
	if !strings.Contains(string(legacySpec), "Status: `SUPERSEDED`") {
		t.Fatalf("docs/05-language-specification.md contains historical v1 syntax and must remain explicitly superseded")
	}
}

func TestBindingDefinitionsUseStableQueryFamilies(t *testing.T) {
	var hits []string
	for path, src := range readDataFiles(t, "bindings", ".vyql") {
		lines := strings.Split(src, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "query unstable.") {
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
		t.Fatalf("binding definitions must use stable `callExpr` or `presenceNode` query families:\n%s", strings.Join(hits, "\n"))
	}
}

// The sink-operation export is data, and the loader treats a missing or unreadable
// file as an empty mapping so a custom VYQL_HOME cannot crash a scan. That silence
// is exactly how the file went missing for a whole engine version without anyone
// noticing, so assert here what the loader will not.
func TestSinkOperationsExportResolves(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(datadir.Root(), "exports", "sink_operations.tsv"))
	if err != nil {
		t.Fatalf("read sink operations export: %v", err)
	}

	defined := map[string]bool{}
	for _, decls := range parseDataDecls(t, "ontology", "concepts") {
		for _, decl := range decls {
			if cd, ok := decl.(*parser.ConceptDecl); ok {
				defined[cd.Name] = true
				defined[shortConceptName(cd.QualifiedName())] = true
			}
		}
	}

	rows := 0
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		concept, op, ok := strings.Cut(line, "\t")
		if !ok {
			t.Errorf("line %d is not <concept>\\t<operation>: %q", i+1, line)
			continue
		}
		concept, op = strings.TrimSpace(concept), strings.TrimSpace(op)
		if op == "" {
			t.Errorf("line %d: %s has no operation", i+1, concept)
		}
		if !defined[concept] && !defined[shortConceptName(concept)] {
			t.Errorf("line %d: %s does not resolve in ontology/concepts", i+1, concept)
		}
		rows++
	}
	if rows == 0 {
		t.Fatal("sink operations export has no rows -- an empty mapping silently disables the graph-json sink vocabulary")
	}
	t.Logf("sink operations export: %d rows, all resolving", rows)
}

func TestMigrationLedgerDoesNotCarryStaleV1BridgeSuggestions(t *testing.T) {
	root := testRepoRoot(t)
	// The ledger records that the v1-to-v2 migration finished and the bridge was
	// not reintroduced. Only a tree that had a v1 can regress that, so the
	// published tree does not carry the file.
	data, err := os.ReadFile(filepath.Join(root, "vyql", "migration-ledger.json"))
	if os.IsNotExist(err) {
		t.Skip("migration ledger is not part of this tree")
	}
	if err != nil {
		t.Fatalf("read migration ledger: %v", err)
	}
	src := string(data)
	forbidden := []string{
		"unstable.legacyFlag",
		"legacyFlagBridgeEntries",
		"adapterMetadataBridgeEntries",
		"unstable adapter metadata",
		"adapter metadata bridge",
		"legacy flag bridge",
		"v1 flag converted",
		"v1 adapter metadata converted",
	}
	var hits []string
	for _, snippet := range forbidden {
		if strings.Contains(src, snippet) {
			hits = append(hits, snippet)
		}
	}
	if len(hits) > 0 {
		sort.Strings(hits)
		t.Fatalf("migration ledger must describe the final v2 state, not stale bridge suggestions: %s", strings.Join(hits, ", "))
	}
	if !strings.Contains(src, `"status": "resolved"`) || !strings.Contains(src, "TestShippedDefinitionCorpusIsV2Only") {
		t.Fatalf("migration ledger must record final resolved status and verification gates")
	}
}

func sourceLanguagesForCoverage() []string {
	out := make([]string, 0, len(frontend.Languages()))
	for _, lg := range frontend.Languages() {
		switch lg.Name {
		case "config", "textpattern":
			continue
		default:
			out = append(out, lg.Name)
		}
	}
	sort.Strings(out)
	return out
}

func countV2TaintEndpointMappings(t *testing.T, subs ...string) (int, int, int) {
	t.Helper()
	sourceCount, sinkCount, checkCount := 0, 0, 0
	for _, sub := range subs {
		for path, src := range readDataFiles(t, sub, ".vyql") {
			sets, err := compileV2BindingsForTest(src)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, binding := range sets {
				for _, mapping := range binding.Mappings {
					switch {
					case strings.HasPrefix(mapping.Kind, "source"):
						sourceCount++
					case strings.HasPrefix(mapping.Kind, "sink"):
						sinkCount++
					case strings.HasPrefix(mapping.Kind, "check") && mapping.Coverage != "":
						checkCount++
					}
				}
			}
		}
	}
	return sourceCount, sinkCount, checkCount
}

// cveDigestRow is one rank of the CVE corpus as the digest records it: the CVE
// that rank was reviewed against, and what the review concluded.
type cveDigestRow struct {
	cve    string
	status string
}

// readCVELedgerDigest loads the in-tree projection of the CVE corpus. The corpus
// itself carries per-rank analysis notes and does not ship here, so the digest is
// what makes the coverage gate below runnable in this tree rather than skipped.
// TestCVECorpusMatchesLedgerDigest keeps the two in agreement wherever both exist.
func readCVELedgerDigest(t *testing.T) map[int]cveDigestRow {
	t.Helper()
	path := filepath.Join("testdata", "cve_ledger_digest.tsv")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CVE ledger digest: %v", err)
	}
	rows := map[int]cveDigestRow{}
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("%s:%d: has %d fields, want 3: %q", path, i+1, len(fields), line)
		}
		rank, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("%s:%d: invalid rank %q", path, i+1, fields[0])
		}
		if prev, ok := rows[rank]; ok {
			t.Fatalf("%s:%d: rank %d appears more than once (first %s)", path, i+1, rank, prev.cve)
		}
		switch fields[2] {
		case "CAUGHT", "FIXED", "ATTENTION", "SKIP", "PENDING":
		default:
			t.Fatalf("%s:%d: rank %d has unknown status %q", path, i+1, rank, fields[2])
		}
		rows[rank] = cveDigestRow{cve: fields[1], status: fields[2]}
	}
	return rows
}

// Every rank the CVE corpus reviewed and did not skip must be pinned here by a
// runnable cve_rank*.test.vyql spec, or be named in the burn-down list with a
// reason. Without this, a rule can be narrowed or a spec deleted and the CVE it
// was written for stops being checked, which is exactly how rank 406 drifted:
// its advisory was withdrawn for good reason, the spec went with it, and nothing
// recorded that the rank now rests on the ledger alone.
func TestCVELedgerCoverageGate(t *testing.T) {
	digest := readCVELedgerDigest(t)
	if len(digest) < 1000 {
		t.Fatalf("CVE ledger digest rows = %d, want at least 1000", len(digest))
	}
	statuses := map[string]int{}
	for _, row := range digest {
		statuses[row.status]++
	}
	// Floors, not exact counts. The pool is extended a block at a time and
	// reviewed a rank at a time, so exact counts cannot hold during a campaign.
	// A floor still catches a status being lost: a review conclusion may only be
	// revised into another conclusion, never deleted.
	minStatuses := map[string]int{"ATTENTION": 110, "CAUGHT": 107, "FIXED": 781, "SKIP": 2}
	for status, min := range minStatuses {
		if statuses[status] < min {
			t.Fatalf("CVE ledger digest %s = %d, want at least %d (statuses = %v)",
				status, statuses[status], min, statuses)
		}
	}

	// Review runs in rank order within a batch, but the batches themselves are
	// work units that different review streams take in any order, so a PENDING
	// rank below the highest reviewed one is no longer proof of a skip. What is
	// proof: a PENDING rank with a reviewed rank above it inside the same
	// 50-rank batch group, because inside a started batch review is strictly in
	// order, so such a rank was passed over rather than not yet reached. A
	// batch group with no reviewed rank at all is unstarted work, wherever it
	// sits relative to other batches.
	const cveBatchSize = 50
	var skipped []string
	for rank, row := range digest {
		if row.status != "PENDING" {
			continue
		}
		for r := rank + 1; r < rank+cveBatchSize && r/cveBatchSize == rank/cveBatchSize; r++ {
			if other, ok := digest[r]; ok && other.status != "PENDING" {
				skipped = append(skipped, strconv.Itoa(rank))
				break
			}
		}
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		t.Fatalf("CVE ranks still PENDING below reviewed ranks in their own batch; review skipped them: %s",
			strings.Join(skipped, ", "))
	}

	cveSpecs := readCVERankSpecFiles(t)
	specNamesByRank := map[int][]string{}
	for _, path := range cveSpecs {
		rank, ok := cveRankFromSpecName(filepath.Base(path))
		if !ok {
			t.Fatalf("CVE spec file has invalid rank name: %s", filepath.Base(path))
		}
		if _, ok := digest[rank]; !ok {
			t.Fatalf("CVE spec %s references rank %d which is not in the ledger digest", filepath.Base(path), rank)
		}
		// Each spec belongs to the thousand-rank directory its rank falls in, so
		// the directory never grows past about a thousand files.
		wantDir := fmt.Sprintf("cve%03d", rank/1000+1)
		if gotDir := filepath.Base(filepath.Dir(path)); gotDir != wantDir {
			t.Fatalf("CVE spec %s for rank %d sits in tests/%s; it belongs in tests/%s",
				filepath.Base(path), rank, gotDir, wantDir)
		}
		specNamesByRank[rank] = append(specNamesByRank[rank], filepath.Base(path))
	}
	uniqueSpecRanks := map[int]bool{}
	for rank, names := range specNamesByRank {
		uniqueSpecRanks[rank] = true
		if len(names) > 1 && !cve1000AllowedDuplicateSpecRanks[rank] {
			sort.Strings(names)
			t.Fatalf("CVE rank %d has %d spec files but is not in the duplicate-spec allowlist: %s", rank, len(names), strings.Join(names, ", "))
		}
	}
	for rank := range cve1000AllowedDuplicateSpecRanks {
		if len(specNamesByRank[rank]) < 2 {
			t.Fatalf("CVE duplicate-spec allowlist rank %d is stale; found %d spec file(s)", rank, len(specNamesByRank[rank]))
		}
	}
	if len(cveSpecs) < 786 || len(uniqueSpecRanks) < 780 {
		t.Fatalf("CVE runnable rank specs regressed: files=%d unique_ranks=%d, want at least files=786 unique_ranks=780", len(cveSpecs), len(uniqueSpecRanks))
	}

	var missingRunnable, staleNoSpecExceptions, skipWithSpecs, pendingWithSpecs []string
	for rank, row := range digest {
		hasSpec := uniqueSpecRanks[rank]
		switch {
		case row.status == "SKIP" && hasSpec:
			skipWithSpecs = append(skipWithSpecs, strconv.Itoa(rank))
		// A spec for a rank with no ledger row means the review happened and its
		// conclusion was never recorded, so the corpus understates the work done.
		case row.status == "PENDING" && hasSpec:
			pendingWithSpecs = append(pendingWithSpecs, strconv.Itoa(rank))
		case row.status != "SKIP" && row.status != "PENDING" && !hasSpec && !cve1000AcceptedNoSpecRanks[rank]:
			missingRunnable = append(missingRunnable, fmt.Sprintf("%d:%s", rank, row.status))
		}
	}
	for rank := range cve1000AcceptedNoSpecRanks {
		row, ok := digest[rank]
		if !ok {
			staleNoSpecExceptions = append(staleNoSpecExceptions, fmt.Sprintf("%d:missing-ledger", rank))
			continue
		}
		if row.status == "SKIP" || row.status == "PENDING" {
			staleNoSpecExceptions = append(staleNoSpecExceptions, fmt.Sprintf("%d:%s-status", rank, strings.ToLower(row.status)))
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
	if len(pendingWithSpecs) > 0 {
		sort.Strings(pendingWithSpecs)
		t.Fatalf("CVE ranks have runnable specs but no ledger row; record the review: %s", strings.Join(pendingWithSpecs, ", "))
	}
	if len(missingRunnable) > 0 {
		sort.Strings(missingRunnable)
		t.Fatalf("CVE non-SKIP ledger ranks without runnable specs must be listed in cve1000AcceptedNoSpecRanks: %s", strings.Join(missingRunnable, ", "))
	}
	if len(staleNoSpecExceptions) > 0 {
		sort.Strings(staleNoSpecExceptions)
		t.Fatalf("CVE no-spec exception list is stale; remove or fix: %s", strings.Join(staleNoSpecExceptions, ", "))
	}
	t.Logf("CVE ledger digest: ranks=%d statuses=%v cve_specs=%d unique_spec_ranks=%d",
		len(digest), statuses, len(cveSpecs), len(uniqueSpecRanks))
}

// In the tree that holds the corpus, the digest must be a faithful projection of
// it and the corpus must be internally consistent. A digest regenerated from an
// edited ledger fails here, which is the only place that can tell -- the tree
// that reads the digest alone has nothing to compare it against.
func TestCVECorpusMatchesLedgerDigest(t *testing.T) {
	repo := testRepoRoot(t)
	corpus := filepath.Join(repo, "cve-1000")
	if _, err := os.Stat(corpus); os.IsNotExist(err) {
		t.Skip("cve-1000 corpus is not part of this tree; the digest gate covers what is here")
	}
	poolRaw, err := os.ReadFile(filepath.Join(corpus, "pool.tsv"))
	if err != nil {
		t.Fatalf("read CVE pool: %v", err)
	}
	ledgerRaw, err := os.ReadFile(filepath.Join(corpus, "ledger.tsv"))
	if err != nil {
		t.Fatalf("read CVE ledger: %v", err)
	}

	poolRows := nonemptyTSVRows(string(poolRaw))
	if len(poolRows) < 1000 {
		t.Fatalf("cve pool rows = %d, want at least 1000", len(poolRows))
	}
	// The pool grows a block at a time and is reviewed a rank at a time, so the
	// ledger trails it for the length of a campaign. It may never lead: a ledger
	// row for a rank the pool does not hold is a review of nothing.
	ledgerRows := nonemptyTSVRows(string(ledgerRaw))
	if len(ledgerRows) > len(poolRows) {
		t.Fatalf("cve ledger rows = %d, more than the %d pool rows", len(ledgerRows), len(poolRows))
	}
	poolFieldsByRank := make([][]string, len(poolRows))
	for rank, row := range poolRows {
		fields := strings.Split(row, "\t")
		if len(fields) < 7 {
			t.Fatalf("pool row %d has %d fields, want at least 7: %q", rank+1, len(fields), row)
		}
		poolFieldsByRank[rank] = fields
	}

	digest := readCVELedgerDigest(t)
	seen := make(map[int]string, len(poolRows))
	usedCVEOverrides := map[int]bool{}
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
		if prev, ok := seen[rank]; ok {
			t.Fatalf("cve-1000 ledger rank %d appears more than once:\nfirst: %s\nagain: %s", rank, prev, row)
		}
		seen[rank] = row

		poolFields := poolFieldsByRank[rank]
		if !cve1000LedgerRepoMatches(fields[1], poolFields) {
			t.Fatalf("ledger row %d rank %d repo = %q, want pool repo %q, owner %q, or owner/repo", i+1, rank, fields[1], poolFields[0], poolFields[1])
		}
		if fields[2] != "" && poolFields[6] != "" && fields[2] != poolFields[6] {
			t.Fatalf("ledger row %d rank %d language = %q, want pool language %q", i+1, rank, fields[2], poolFields[6])
		}
		if fields[3] != poolFields[3] {
			if cve1000AcceptedLedgerCVEMetadataOverrides[rank] != fields[3] {
				t.Fatalf("ledger row %d rank %d CVE = %q, want pool CVE %q", i+1, rank, fields[3], poolFields[3])
			}
			usedCVEOverrides[rank] = true
		}
		switch fields[4] {
		case "CAUGHT", "FIXED", "ATTENTION", "SKIP":
		default:
			t.Fatalf("ledger row %d rank %d has unknown status %q", i+1, rank, fields[4])
		}
		if strings.TrimSpace(fields[5]) == "" {
			t.Fatalf("ledger row %d rank %d status %s is missing verification evidence", i+1, rank, fields[4])
		}

		want, ok := digest[rank]
		if !ok {
			t.Fatalf("ledger rank %d is missing from the digest; regenerate cve_ledger_digest.tsv", rank)
		}
		if want.cve != fields[3] || want.status != fields[4] {
			t.Fatalf("digest rank %d = (%s, %s), ledger has (%s, %s); regenerate cve_ledger_digest.tsv",
				rank, want.cve, want.status, fields[3], fields[4])
		}
	}
	// A pool rank with no ledger row is PENDING, and the digest must say so with
	// the pool's own CVE -- otherwise a spec written for a pending rank could be
	// checked against the wrong advisory.
	var wrongPending []string
	for rank := range poolRows {
		if _, reviewed := seen[rank]; reviewed {
			continue
		}
		row, ok := digest[rank]
		if !ok {
			wrongPending = append(wrongPending, fmt.Sprintf("%d:absent", rank))
			continue
		}
		if row.status != "PENDING" {
			wrongPending = append(wrongPending, fmt.Sprintf("%d:%s", rank, row.status))
			continue
		}
		if row.cve != poolFieldsByRank[rank][3] {
			wrongPending = append(wrongPending, fmt.Sprintf("%d:cve=%s want %s", rank, row.cve, poolFieldsByRank[rank][3]))
		}
	}
	if len(wrongPending) > 0 {
		sort.Strings(wrongPending)
		t.Fatalf("unreviewed pool ranks must be PENDING in the digest with the pool's CVE; regenerate cve_ledger_digest.tsv: %s",
			strings.Join(wrongPending, ", "))
	}
	if len(digest) != len(poolRows) {
		t.Fatalf("digest has %d ranks, pool has %d; regenerate cve_ledger_digest.tsv", len(digest), len(poolRows))
	}
	for rank, cve := range cve1000AcceptedLedgerCVEMetadataOverrides {
		if !usedCVEOverrides[rank] {
			t.Fatalf("CVE ledger metadata override rank %d (%s) is stale; remove it or fix the ledger/pool pair", rank, cve)
		}
	}
	t.Logf("cve corpus: pool=%d ledger_rows=%d digest_ranks=%d", len(poolRows), len(ledgerRows), len(digest))
}

var cve1000AllowedDuplicateSpecRanks = map[int]bool{
	474: true,
	495: true,
	795: true,
	835: true,
	955: true,
}

// cve1000AcceptedLedgerCVEMetadataOverrides is the explicit burn-down list for
// existing ledger rows whose reviewed CVE differs from the selected pool row.
// New CVE mismatches fail the gate; fixing this row must remove the exception.
var cve1000AcceptedLedgerCVEMetadataOverrides = map[int]string{
	15: "CVE-2010-0684",
}

// cve1000AcceptedNoSpecRanks is the explicit burn-down list for non-SKIP ledger
// rows that are currently verified only by the CVE prep/eval ledger rather than a
// runnable cve_rank*.test.vyql spec. Adding a runnable rank spec must remove the
// rank here; new non-SKIP ledger rows without specs fail the gate.
var cve1000AcceptedNoSpecRanks = map[int]bool{
	21: true,
	28: true, 37: true,
	62: true, 69: true, 71: true, 73: true,
	83: true,
	// Rank 406 asked for a requests advisory pinned at 2.31.0, which is HTTPie's
	// decision and fires on every project whose declaration permits a higher
	// release. Scoping it needs a manifest reader that knows the project's own
	// declared name, which none of the five formats extracts. The advisory and
	// its spec are withdrawn, so the ledger row is all that verifies this rank.
	406: true,
	574: true, 588: true,
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

func cve1000LedgerRepoMatches(ledgerRepo string, poolFields []string) bool {
	if len(poolFields) < 2 {
		return false
	}
	project := poolFields[0]
	owner := poolFields[1]
	return ledgerRepo == project || ledgerRepo == owner || ledgerRepo == owner+"/"+project
}

func readCVERankSpecFiles(t *testing.T) []string {
	t.Helper()
	testsDir := filepath.Join(datadir.Root(), "tests")
	// Rank specs live in thousand-rank subdirectories (tests/cve001, tests/cve002,
	// ...), so the whole tree is walked instead of one directory level.
	var out []string
	err := filepath.WalkDir(testsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if !d.IsDir() && strings.HasPrefix(name, "cve_rank") && strings.HasSuffix(name, ".test.vyql") {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests dir: %v", err)
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

// Every sink concept a binding emits must either carry a downstream operation
// or be recorded as deliberately without one. The failure this prevents is
// silent: a new sink concept exports a null operation in graph-json, the
// consuming service sees a finding with no operation, and nothing here noticed.
func TestEverySinkConceptIsMappedOrDocumented(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(datadir.Root(), "exports", "sink_operations.tsv"))
	if err != nil {
		t.Fatalf("read sink_operations.tsv: %v", err)
	}
	mapped, documented := map[string]bool{}, map[string]bool{}
	// "#   ConceptName  --  reason" records a concept left unmapped on purpose.
	unmapped := regexp.MustCompile(`^#\s+([A-Za-z0-9_]+)\s+--`)
	for _, line := range strings.Split(string(raw), "\n") {
		if m := unmapped.FindStringSubmatch(line); m != nil {
			documented[m[1]] = true
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, _, ok := strings.Cut(line, "\t"); ok {
			mapped[strings.TrimSpace(name)] = true
		}
	}

	emitted := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(datadir.Root(), "bindings"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".vyql") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range regexp.MustCompile(`emit sink ([A-Za-z0-9_.]+)`).FindAllStringSubmatch(string(b), -1) {
			parts := strings.Split(m[1], ".")
			emitted[parts[len(parts)-1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk bindings: %v", err)
	}
	if len(emitted) == 0 {
		t.Fatal("no sink concepts found; the walk matched nothing")
	}

	var gap []string
	for c := range emitted {
		if !mapped[c] && !documented[c] {
			gap = append(gap, c)
		}
	}
	sort.Strings(gap)
	if len(gap) > 0 {
		t.Fatalf("%d sink concept(s) neither mapped to an operation nor recorded as unmapped in "+
			"vyql/exports/sink_operations.tsv: %s", len(gap), strings.Join(gap, ", "))
	}
	t.Logf("%d sink concepts: %d mapped, %d documented as unmapped", len(emitted), len(mapped), len(documented))
}

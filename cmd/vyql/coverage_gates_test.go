package main

// Coverage GATES (plan/test-coverage-tasklist.md T0). These meta-tests enforce that
// every rule/concept/threat/adapter stays tested and internally consistent — so a new
// feature cannot ship untested. They read the shipped VyQL data (vyql/) directly.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	files := readDataFiles(t, sub, suffix)
	out := map[string][]parser.Decl{}
	for f, c := range files {
		decls, err := parser.Parse(c)
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
		decls, err := parser.Parse(c)
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
			case *parser.AdapterDecl:
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
	}
	for _, cl := range r.Clauses {
		collectExprConceptRefs(cl.Where, refs)
		switch ex := cl.Unless.(type) {
		case parser.SanitizedBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.GuardedBy:
			addCoverageConceptRef(refs, ex.Concept)
		case parser.ClosedBy:
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
	case parser.Has:
		addCoverageConceptRef(refs, e.Concept)
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
			if v, ok := cd.Fields[field].(string); ok && v == "true" {
				out[cd.Name] = true
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
// `unless sanitized_by`/`guarded_by`; a wired control no rule reads is INERT (neutralizes
// nothing). This is the gate that catches the OutputEncoding-style mistake. (A control
// defined-but-not-wired is just unused vocabulary and is fine.)
func TestControlsWiredAreConsumedGate(t *testing.T) {
	reserved := conceptsWithBoolField(t, "control", "coverage_reserved_control")
	controls := conceptsByKind(t, "control")
	wired := conceptRefsIn(t, "adapters")
	consumed := map[string]bool{}
	re := regexp.MustCompile(`(?:sanitized_by|guarded_by|closed_by)\s+(?:core|code)\.([A-Za-z0-9_]+)`)
	for _, c := range readDataFiles(t, "packs", ".vyql") {
		for _, m := range re.FindAllStringSubmatch(c, -1) {
			consumed[m[1]] = true
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

// T0.5 — every adapter loads (parses + builds its sink/source/control/mark specs) without
// panicking, for every adapter shipped under vyql/adapters/.
func TestAllAdaptersLoadGate(t *testing.T) {
	for f := range readDataFiles(t, "adapters", ".vyql") {
		// Files under adapters/packages/ are dependency catalogs keyed by package name,
		// not standalone tech adapters: the per-language catalog is merged into its tech
		// by AdaptersFor, and the generated/<lang>/<pkg>.vyql corpus loads dynamically via
		// GeneratedPackageAdaptersFor. Their basenames are package names, not techs.
		if strings.Contains(filepath.ToSlash(f), "/adapters/packages/") {
			continue
		}
		tech := strings.TrimSuffix(filepath.Base(f), ".vyql")
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

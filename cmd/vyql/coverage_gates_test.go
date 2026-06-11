package main

// Coverage GATES (plan/test-coverage-tasklist.md T0). These meta-tests enforce that
// every rule/concept/threat/adapter stays tested and internally consistent — so a new
// feature cannot ship untested. They read the shipped VyQL data (vyql/) directly.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/frontend"
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

var (
	ruleIDRe    = regexp.MustCompile(`id:\s*"(VYQL-[A-Z]+-[0-9]+)"`)
	conceptDef  = regexp.MustCompile(`(?m)^concept\s+([A-Za-z0-9_]+)`)
	conceptKind = regexp.MustCompile(`(?m)^concept\s+([A-Za-z0-9_]+)\s*:\s*(sink|source|control)`)
	conceptRef  = regexp.MustCompile(`(?:code|core)\.([A-Z][A-Za-z0-9_]+)`)
	quoted      = regexp.MustCompile(`"[^"]*"`)
	pkgLine     = regexp.MustCompile(`(?m)^package\s+([A-Za-z0-9_.]+)\s*;`)
	threatDef   = regexp.MustCompile(`(?m)^threat\s+([A-Za-z0-9_]+)`)
	threatRef   = regexp.MustCompile(`(?:vulnerable_to|neutralizes):\s*\[([^\]]+)\]`)
)

func ruleIDs(files map[string]string) map[string]string { // id -> file
	out := map[string]string{}
	for f, c := range files {
		for _, m := range ruleIDRe.FindAllStringSubmatch(c, -1) {
			out[m[1]] = f
		}
	}
	return out
}

// T0.1 — every rule has at least one `expect` spec (proves it fires). The allowlist is
// the known-unspecced backlog (T1 burns it down); a NEW rule without a spec fails here.
// As specs are added, allowlisted ids that gain coverage must be REMOVED (asserted below).
func TestRuleFiresCoverageGate(t *testing.T) {
	unspecced := map[string]bool{
		// RF-003 (CSRF): StateChangingOp + CsrfProtection — needs a state-change/CSRF
		// model (identify state-changing handlers + CSRF guards), not adapter-expressible
		// as a plain taint sink. Documented-deferred (engine-gap-closure.md); kept here
		// until that lands. This is the ONLY remaining un-specced rule.
		"VYQL-RF-003": true,
	}

	rules := ruleIDs(readDataFiles(t, "packs", ".vyql"))
	specs := readDataFiles(t, "tests", ".test.vyql")
	expected := map[string]bool{}
	for _, c := range specs {
		for _, ln := range strings.Split(c, "\n") {
			if f := strings.Fields(strings.TrimSpace(ln)); len(f) == 2 && f[0] == "expect" {
				expected[f[1]] = true
			}
		}
	}
	// graph-fixture coverage (vyql/tests/graph/*.graph.json) counts too.
	for _, c := range readDataFiles(t, "tests/graph", ".graph.json") {
		var fixtures []graphFixture
		if json.Unmarshal([]byte(c), &fixtures) == nil {
			for _, fx := range fixtures {
				for _, id := range fx.Expect {
					expected[id] = true
				}
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
// concept. Quoted strings are stripped so string-literal sink paths (e.g. the Python
// `code` stdlib module) are not mistaken for concept refs.
func TestConceptRefsResolveGate(t *testing.T) {
	defined := map[string]bool{}
	for _, c := range readDataFiles(t, "ontology", "concepts.vyql") {
		for _, m := range conceptDef.FindAllStringSubmatch(c, -1) {
			defined[m[1]] = true
		}
	}
	check := func(sub, suffix string) {
		for f, c := range readDataFiles(t, sub, suffix) {
			bare := quoted.ReplaceAllString(c, `""`)
			for _, m := range conceptRef.FindAllStringSubmatch(bare, -1) {
				if !defined[m[1]] {
					t.Errorf("%s references concept %q which is not defined in concepts.vyql", filepath.Base(f), m[1])
				}
			}
		}
	}
	check("adapters", ".vyql")
	check("packs", ".vyql")
	t.Logf("concept refs: %d concepts defined", len(defined))
}

// conceptRefsIn returns the set of code/core concept names referenced (as targets or
// in rule clauses) across the given vyql/<sub> files, quoted strings stripped.
func conceptRefsIn(t *testing.T, sub string) map[string]bool {
	out := map[string]bool{}
	for _, c := range readDataFiles(t, sub, ".vyql") {
		bare := quoted.ReplaceAllString(c, `""`)
		for _, m := range conceptRef.FindAllStringSubmatch(bare, -1) {
			out[m[1]] = true
		}
	}
	return out
}

// T2.5 — concept-coverage gate. Every SINK concept that a rule consumes must be wired
// in at least one adapter (otherwise the rule is latent — it can never fire). This is
// the gate that catches dead sinks (e.g. the reflection/log/header sinks that shipped
// referenced-but-unwired). The allowlist holds sinks for documented-deferred rules.
func TestSinkConceptsWiredGate(t *testing.T) {
	deferred := map[string]bool{
		// RF-003 (CSRF) is documented-deferred — its sink/control are intentionally unwired.
		"StateChangingOp": true, "CsrfProtection": true,
	}
	sinks := map[string]bool{}
	for _, c := range readDataFiles(t, "ontology", "concepts.vyql") {
		for _, m := range conceptKind.FindAllStringSubmatch(c, -1) {
			if m[2] == "sink" {
				sinks[m[1]] = true
			}
		}
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

// T0.3 — every threat reference (vulnerable_to/neutralizes) resolves to a defined threat
// in the correct package.
func TestThreatRefsResolveGate(t *testing.T) {
	defined := map[string]bool{} // "pkg.Threat"
	for _, c := range readDataFiles(t, "ontology", "threatkinds.vyql") {
		pkg := ""
		for _, ln := range strings.Split(c, "\n") {
			if m := pkgLine.FindStringSubmatch(ln); m != nil {
				pkg = m[1]
			}
			if m := threatDef.FindStringSubmatch(ln); m != nil {
				defined[pkg+"."+m[1]] = true
			}
		}
	}
	for f, c := range readDataFiles(t, "ontology", "concepts.vyql") {
		for _, m := range threatRef.FindAllStringSubmatch(c, -1) {
			for _, ref := range strings.Split(m[1], ",") {
				ref = strings.TrimSpace(ref)
				if ref == "" {
					continue
				}
				if !defined[ref] {
					t.Errorf("%s references threat %q which is not defined in threatkinds.vyql", filepath.Base(f), ref)
				}
			}
		}
	}
	t.Logf("threat refs: %d threats defined", len(defined))
}

// T0.4 — no duplicate concept names, rule ids, or (package-qualified) threat names.
func TestNoDuplicateNamesGate(t *testing.T) {
	seen := map[string]int{}
	for _, c := range readDataFiles(t, "ontology", "concepts.vyql") {
		for _, m := range conceptDef.FindAllStringSubmatch(c, -1) {
			seen[m[1]]++
		}
	}
	for n, k := range seen {
		if k > 1 {
			t.Errorf("duplicate concept %q (%d definitions)", n, k)
		}
	}
	ids := map[string]int{}
	for _, c := range readDataFiles(t, "packs", ".vyql") {
		for _, m := range ruleIDRe.FindAllStringSubmatch(c, -1) {
			ids[m[1]]++
		}
	}
	for n, k := range ids {
		if k > 1 {
			t.Errorf("duplicate rule id %q (%d definitions)", n, k)
		}
	}
	thr := map[string]int{}
	for _, c := range readDataFiles(t, "ontology", "threatkinds.vyql") {
		pkg := ""
		for _, ln := range strings.Split(c, "\n") {
			if m := pkgLine.FindStringSubmatch(ln); m != nil {
				pkg = m[1]
			}
			if m := threatDef.FindStringSubmatch(ln); m != nil {
				thr[pkg+"."+m[1]]++
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

package sca

// T10 (plan/test-coverage-tasklist.md): SCA — SBOM parse, advisory match, reachability.
// The extract/sca package had no tests.

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

func TestParseRequirements(t *testing.T) {
	got := ParseRequirements("Flask==2.0.1\n# a comment\nrequests\n-r dev.txt\n\n  django == 4.2  \npyyaml>=6.0\n")
	want := []Dep{{"flask", "2.0.1"}, {"requests", "*"}, {"django", "4.2"}, {"pyyaml", "6.0"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseGitmodules(t *testing.T) {
	got := ParseGitmodules(`[submodule "vendor/llhttp"]
	path = vendor/llhttp
	url = https://github.com/nodejs/llhttp.git
`, map[string]string{"vendor/llhttp": "69d6db2008508489d19267a0dcab30602b16fc5b"})
	want := []Dep{{"github.com/nodejs/llhttp", "69d6db2008508489d19267a0dcab30602b16fc5b"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ParseGitmodules() = %+v, want %+v", got, want)
	}
}

func hasConcept(t *testing.T, g usg.Store, concept string) []string {
	ids, err := g.NodesWithConcept(concept)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestBuildSBOMAdvisoryMatch(t *testing.T) {
	g := usg.NewInMemStore()
	deps := []Dep{{"lodash", "4.17.4"}, {"safe-pkg", "1.0.0"}}
	advisories := map[PkgKey]string{
		{"lodash", "4.17.4"}:  "CVE-2019-10744", // vulnerable
		{"lodash", "4.17.21"}: "",               // patched version not present
	}
	if err := BuildSBOM(g, "npm", deps, ""); err != nil {
		t.Fatal(err)
	}
	if err := MarkVulnerable(g, advisories); err != nil {
		t.Fatal(err)
	}
	vuln := hasConcept(t, g, "sbom.VulnerableDependency")
	if len(vuln) != 1 {
		t.Fatalf("expected exactly 1 VulnerableDependency (lodash@4.17.4), got %d: %v", len(vuln), vuln)
	}
	// the safe package must NOT be flagged.
	for _, id := range vuln {
		if n, _, _ := g.GetNode(id); n.Prop("name") == "safe-pkg" {
			t.Errorf("safe-pkg was flagged vulnerable")
		}
	}
}

func TestBuildSBOMPatchedIsClean(t *testing.T) {
	g := usg.NewInMemStore()
	// same package, PATCHED version → not in the advisory map → no finding.
	deps := []Dep{{"lodash", "4.17.21"}}
	advisories := map[PkgKey]string{{"lodash", "4.17.4"}: "CVE-2019-10744"}
	if err := BuildSBOM(g, "npm", deps, ""); err != nil {
		t.Fatal(err)
	}
	if err := MarkVulnerable(g, advisories); err != nil {
		t.Fatal(err)
	}
	if v := hasConcept(t, g, "sbom.VulnerableDependency"); len(v) != 0 {
		t.Errorf("patched lodash@4.17.21 should be clean, got %d vuln labels", len(v))
	}
}

func TestLinkReachability(t *testing.T) {
	g := usg.NewInMemStore()
	// two packages; only `requests` is actually called.
	_ = BuildSBOM(g, "pypi", []Dep{{"requests", "2.0.0"}, {"unused", "1.0.0"}}, "")
	// a call site rooted at the requests package.
	_ = g.AddNode(usg.Node{ID: "c1", Type: "code.Call", Props: map[string]string{"callee_path": "requests.get", "loc": "a.py:1"}})

	if err := LinkReachability(g); err != nil {
		t.Fatal(err)
	}
	reach := hasConcept(t, g, "sbom.ReachableSymbol")
	if len(reach) != 1 {
		t.Fatalf("expected exactly 1 ReachableSymbol (requests), got %d: %v", len(reach), reach)
	}
	if n, _, _ := g.GetNode(reach[0]); n.Prop("name") != "requests" {
		t.Errorf("reachable package = %q, want requests", n.Prop("name"))
	}
}

func TestLinkReachabilityUsesImportNodesAndEdges(t *testing.T) {
	g := usg.NewInMemStore()
	_ = BuildSBOM(g, "npm", []Dep{{"@scope/pkg", "1.0.0"}, {"unused", "1.0.0"}}, "")
	_ = g.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.js:1", "module": "@scope/pkg/lib", "package": "@scope/pkg",
	}})

	if err := LinkReachability(g); err != nil {
		t.Fatal(err)
	}
	reach := hasConcept(t, g, "sbom.ReachableSymbol")
	if len(reach) != 1 {
		t.Fatalf("expected exactly 1 ReachableSymbol via import, got %d: %v", len(reach), reach)
	}
	n, _, _ := g.GetNode(reach[0])
	if n.Prop("name") != "@scope/pkg" || n.Prop("package") != "@scope/pkg" || n.Prop("purl") != "pkg:npm/@scope/pkg@1.0.0" {
		t.Fatalf("reachable package props wrong: %+v", n.Props)
	}
	edges, _ := g.OutEdges("imp", "DEPENDS_ON")
	if len(edges) != 1 || edges[0].Dst != reach[0] {
		t.Fatalf("import should DEPENDS_ON reachable package, got %+v", edges)
	}
}

package sca

// SCA — SBOM parse, advisory match, reachability.
// The extract/sca package had no tests.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

func TestParseRequirements(t *testing.T) {
	got := ParseRequirements("Flask==2.0.1\n# a comment\nrequests\n-r dev.txt\n\n  django == 4.2  \npyyaml>=6.0\n")
	want := []Dep{{"flask", "==2.0.1"}, {"requests", "*"}, {"django", "==4.2"}, {"pyyaml", ">=6.0"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSetupPyInstallRequires(t *testing.T) {
	got := ParseSetupPy(`from setuptools import setup

setup(
    name="demo",
    install_requires=[
        'AwsCRT==0.11.20',
        "requests>=2.31.0",
    ],
)
`)
	want := []Dep{{"awscrt", "==0.11.20"}, {"requests", ">=2.31.0"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSetupCfgInstallRequires(t *testing.T) {
	got := ParseSetupCfg(`[metadata]
name = httpie

[options]
packages = find:
install_requires =
    requests[socks] >=2.22.0, <=2.31.0
    Pygments>=2.5.2

[options.extras_require]
dev =
    pytest
`)
	want := []Dep{{"requests", ">=2.22.0, <=2.31.0"}, {"pygments", ">=2.5.2"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseGoModRequires(t *testing.T) {
	got := ParseGoMod(`module example.com/app

go 1.21

require github.com/One/Direct v1.2.3

require (
    github.com/ElrondNetwork/elrond-vm-common v1.3.6
    github.com/pkg/errors v0.9.1 // indirect
)

replace github.com/ElrondNetwork/elrond-vm-common v1.3.6 => github.com/example/fork v1.3.7
`)
	want := []Dep{
		{"github.com/one/direct", "v1.2.3"},
		{"github.com/elrondnetwork/elrond-vm-common", "v1.3.6"},
		{"github.com/pkg/errors", "v0.9.1"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseVendoredJSTinyMCEBanner(t *testing.T) {
	got := ParseVendoredJS("tinymce/static/tinymce/plugins/image/plugin.min.js", `/**
 * Version: 5.5.0 (2020-09-29)
 */
!function(){}();
`)
	want := []Dep{{"tinymce", "5.5.0"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ParseVendoredJS() = %+v, want %+v", got, want)
	}
	if got := ParseVendoredJS("static/app.js", `/* Version: 5.5.0 */`); len(got) != 0 {
		t.Fatalf("unrecognized vendored JS path should not emit deps, got %+v", got)
	}
}

func TestParseNpmrcBraveElectronRuntime(t *testing.T) {
	got := ParseNpmrc(`runtime = electron
target = 1.4.0
target_arch = x64
brave_electron_version = 1.4.18
disturl = https://atom.io/download/atom-shell
`)
	want := []Dep{{"brave/electron", "1.4.18"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ParseNpmrc() = %+v, want %+v", got, want)
	}
}

func TestParseNpmrcElectronTargetFallback(t *testing.T) {
	got := ParseNpmrc(`runtime = electron
target = 1.4.20
target_arch = x64
`)
	want := []Dep{{"brave/electron", "1.4.20"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ParseNpmrc() = %+v, want %+v", got, want)
	}
}

func TestParseNpmrcIgnoresNonElectronRuntime(t *testing.T) {
	if got := ParseNpmrc("runtime = node\ntarget = 20.0.0\n"); len(got) != 0 {
		t.Fatalf("non-electron .npmrc should not emit deps, got %+v", got)
	}
}

func TestParseComposerLockPackages(t *testing.T) {
	got := ParseComposerLock(`{
  "packages": [
    {
      "name": "amnah/yii2-user",
      "version": "3.0.0"
    }
  ],
  "packages-dev": [
    {
      "name": "yiisoft/yii2-debug",
      "version": "2.1.0"
    }
  ]
}`)
	want := []Dep{{"amnah/yii2-user", "3.0.0"}, {"yiisoft/yii2-debug", "2.1.0"}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d deps, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMinSafeAdvisoryMatch(t *testing.T) {
	d := &scaData{advisories: map[string]map[string][]advisoryEntry{"npm": {
		"tinymce": {{Version: "*", ID: "CVE-2024-21910", MinSafe: "5.10.0"}},
	}}}
	if adv, ok := matchAdvisory(d, "npm", "tinymce", "5.5.0", "5.5.0"); !ok || adv.ID != "CVE-2024-21910" {
		t.Fatalf("tinymce 5.5.0 should match min_safe advisory, got ok=%v adv=%+v", ok, adv)
	}
	if _, ok := matchAdvisory(d, "npm", "tinymce", "5.10.1", "5.10.1"); ok {
		t.Fatal("tinymce 5.10.1 should be clean for min_safe 5.10.0")
	}
}

func TestMaxSafeAdvisoryMatchPreservesOpenRanges(t *testing.T) {
	d := &scaData{advisories: map[string]map[string][]advisoryEntry{"pypi": {
		"requests": {{Version: "*", ID: "CVE-2023-48052", MaxSafe: "2.31.0"}},
	}}}
	if adv, ok := matchAdvisory(d, "pypi", "requests", "2.22.0", ">=2.22.0"); !ok || adv.ID != "CVE-2023-48052" {
		t.Fatalf("open requests range should match max_safe advisory, got ok=%v adv=%+v", ok, adv)
	}
	if _, ok := matchAdvisory(d, "pypi", "requests", "2.31.0", "==2.31.0"); ok {
		t.Fatal("pinned requests 2.31.0 should be clean for max_safe 2.31.0")
	}
}

func TestExactAdvisoryMatchesSpecifierRanges(t *testing.T) {
	d := &scaData{advisories: map[string]map[string][]advisoryEntry{"pypi": {
		"exotel": {{Version: "0.1.6", ID: "CVE-2022-38792", CWE: []string{"CWE-506"}}},
	}}}
	if adv, ok := matchAdvisory(d, "pypi", "exotel", "0.1.5", ">=0.1.5"); !ok || adv.ID != "CVE-2022-38792" {
		t.Fatalf("exotel>=0.1.5 should allow known-bad 0.1.6, got ok=%v adv=%+v", ok, adv)
	}
	if _, ok := matchAdvisory(d, "pypi", "exotel", "0.1.5", "==0.1.5"); ok {
		t.Fatal("exotel==0.1.5 should not match an advisory for 0.1.6")
	}
	if _, ok := matchAdvisory(d, "pypi", "exotel", "0.1.5", ">=0.1.5,<=0.1.5"); ok {
		t.Fatal("exotel range capped at 0.1.5 should not allow known-bad 0.1.6")
	}
	if adv, ok := matchAdvisory(d, "pypi", "exotel", "*", "*"); !ok || adv.ID != "CVE-2022-38792" {
		t.Fatalf("unpinned exotel should allow known-bad 0.1.6, got ok=%v adv=%+v", ok, adv)
	}
}

func TestPackageMatchesRepositorySlugInImportPath(t *testing.T) {
	cases := []struct {
		observed string
		want     string
		match    bool
	}{
		{"github.com/cloudreve/Cloudreve/v4/pkg/util", "cloudreve", true},
		{"github.com/capnproto/capnproto/c++/src", "capnproto", true},
		{"github.com/cloudreve/Cloudreve/v4/pkg/util", "reve", false},
		{"github.com/example/not-cloudreve/pkg", "cloudreve", false},
	}
	for _, tc := range cases {
		if got := PackageMatches(tc.observed, tc.want); got != tc.match {
			t.Errorf("PackageMatches(%q, %q)=%v want %v", tc.observed, tc.want, got, tc.match)
		}
	}
}

func TestSCARuntimeDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	var forbidden []string
	for _, c := range ontology.Seed().AllConcepts() {
		if ontology.IsInternalConceptRoleConcept(c.QualifiedName()) {
			continue
		}
		forbidden = append(forbidden,
			`"`+c.Name+`"`,
			"`"+c.Name+"`",
			`"`+c.QualifiedName()+`"`,
			"`"+c.QualifiedName()+"`",
		)
		for _, id := range append(append([]string{}, c.CWE...), append(c.CAPEC, c.Attack...)...) {
			forbidden = append(forbidden, `"`+id+`"`, "`"+id+"`")
		}
	}
	for _, tk := range ontology.ThreatKinds() {
		forbidden = append(forbidden,
			`"`+tk.Name+`"`,
			"`"+tk.Name+"`",
			`"`+tk.QualifiedName()+`"`,
			"`"+tk.QualifiedName()+"`",
		)
		for _, id := range tk.CWE {
			forbidden = append(forbidden, `"`+id+`"`, "`"+id+"`")
		}
	}
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range forbidden {
			if strings.Contains(text, needle) {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, rel+": "+needle)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("SCA runtime must not hardcode ontology concepts; move concept mapping to VyQL data: %s", strings.Join(hits, ", "))
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

func TestParseCargoLockGitDependencies(t *testing.T) {
	got := ParseCargoLockGit(`[[package]]
name = "clash_verge_service_ipc"
version = "2.0.26"
source = "git+https://github.com/clash-verge-rev/clash-verge-service-ipc#37b9964a9bce767b5b95ea2be75613b23400c9f0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	want := []Dep{{"github.com/clash-verge-rev/clash-verge-service-ipc", "37b9964a9bce767b5b95ea2be75613b23400c9f0"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("ParseCargoLockGit() = %+v, want %+v", got, want)
	}
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
	vuln := packageIDsWithToken(t, g, "status=vulnerable")
	if len(vuln) != 1 {
		t.Fatalf("expected exactly 1 advisory-matched package (lodash@4.17.4), got %d: %v", len(vuln), vuln)
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
	if v := packageIDsWithToken(t, g, "status=vulnerable"); len(v) != 0 {
		t.Errorf("patched lodash@4.17.21 should be clean, got %d advisory tokens", len(v))
	}
}

func TestGoPseudoVersionMinSafeAdvisoryMatch(t *testing.T) {
	d := &scaData{advisories: map[string]map[string][]advisoryEntry{
		"go": {
			"github.com/consensys/gnark-crypto": {
				{Version: "*", ID: "CVE-2025-58157", MinSafe: "v0.17.1-0.20250502112255-56600883e0e9"},
			},
		},
	}}
	if adv, ok := matchAdvisory(d, "go", "github.com/consensys/gnark-crypto", "v0.17.1-0.20250415081852-c838dcdfa844", "v0.17.1-0.20250415081852-c838dcdfa844"); !ok || adv.ID != "CVE-2025-58157" {
		t.Fatalf("old gnark-crypto pseudo-version should match min_safe advisory, got ok=%v adv=%+v", ok, adv)
	}
	if _, ok := matchAdvisory(d, "go", "github.com/consensys/gnark-crypto", "v0.17.1-0.20250502112255-56600883e0e9", "v0.17.1-0.20250502112255-56600883e0e9"); ok {
		t.Fatal("fixed gnark-crypto pseudo-version should be clean for min_safe advisory")
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
	reach := packageIDsWithToken(t, g, "reachable=true")
	if len(reach) != 1 {
		t.Fatalf("expected exactly 1 reachable package (requests), got %d: %v", len(reach), reach)
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
	reach := packageIDsWithToken(t, g, "reachable=true")
	if len(reach) != 1 {
		t.Fatalf("expected exactly 1 reachable package via import, got %d: %v", len(reach), reach)
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

func packageIDsWithToken(t *testing.T, g usg.Store, token string) []string {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range nodes {
		if n.Type == "sbom.PackageVersion" && hasPackageToken(n, token) {
			out = append(out, n.ID)
		}
	}
	return out
}

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/profile"
)

// setProfile applies a named threat-model profile's trust boundary (active source set), the
// way a real scan does. Changing it changes which source labels adapters emit — so it is a
// global input the incremental adapter-label cache must fingerprint.
func setProfile(t *testing.T, name string) {
	t.Helper()
	profs, _ := profile.Load()
	p, ok := profile.ByName(profs, name)
	if !ok {
		t.Fatalf("profile %q not found", name)
	}
	frontend.SetActiveSources(p.ActiveSources())
}

// fakeDelta is an in-memory lowering.DeltaCache for the findings-equivalence harness.
type fakeDelta map[string][]byte

func (f fakeDelta) GetRaw(k string) ([]byte, bool) { v, ok := f[k]; return v, ok }
func (f fakeDelta) PutRaw(k string, v []byte)      { f[k] = append([]byte(nil), v...) }

// scanFindingKeys runs the full pipeline (buildGraphWith + default packs) against an explicit
// lowering cache and returns a canonical, sorted set of finding identities (rule + sink loc).
// This is the integration-level equivalence signal: incremental and full scans of the same
// source MUST yield the same set.
func scanFindingKeys(t *testing.T, paths []string, cache lowering.DeltaCache) []string {
	t.Helper()
	g, _, err := buildGraphWith(paths, cache)
	if err != nil {
		t.Fatalf("buildGraphWith: %v", err)
	}
	if g == nil {
		return nil
	}
	src, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	onto := ontology.Seed()
	decls, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("rule parse: %v", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		t.Fatalf("rule compile: %v", cerrs)
	}
	eng := engine.New(onto, g)
	var keys []string
	for _, cr := range compiled {
		got, err := eng.Evaluate(cr)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, f := range got {
			keys = append(keys, findingKey(f))
		}
	}
	sort.Strings(keys)
	return keys
}

func findingKey(f *findings.Finding) string {
	sink := ""
	for _, b := range f.Bindings {
		if b.Name == "sink" {
			sink = b.Loc
		}
	}
	return f.RuleID + "@" + sink
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func eqKeys(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestIncrementalFingerprintProfile proves the incremental cache fingerprints the active
// PROFILE (trust boundary), not just source content. The web profile activates HttpInput (so
// the fixture's request→os.system flow is a finding); cli does not (no finding). Populating the
// cache under one profile and rescanning under the other must match a full scan under the new
// profile — i.e. cached labels from profile A must NOT leak into a profile-B scan. (Vacuous
// today since adapters run whole-graph; the gate that keeps incremental adapter-label caching
// honest.)
func TestIncrementalFingerprintProfile(t *testing.T) {
	defer frontend.SetActiveSources(nil)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), "import os\nfrom helper import build_cmd\ndef handler(request):\n    x = request.args.get('name')\n    os.system(build_cmd(x))\n")
	writeFile(t, filepath.Join(dir, "helper.py"), "def build_cmd(v):\n    return 'echo ' + v\n")

	for _, flip := range [][2]string{{"cli", "web"}, {"web", "cli"}} {
		t.Run(flip[0]+"->"+flip[1], func(t *testing.T) {
			cache := fakeDelta{}
			setProfile(t, flip[0])
			_ = scanFindingKeys(t, []string{dir}, cache) // populate under profile A
			setProfile(t, flip[1])
			incr := scanFindingKeys(t, []string{dir}, cache) // reuse cache under profile B
			full := scanFindingKeys(t, []string{dir}, nil)   // full under profile B
			if !eqKeys(incr, full) {
				t.Errorf("profile-fingerprint leak %s->%s\nincr=%v\nfull=%v", flip[0], flip[1], incr, full)
			}
		})
	}
}

// TestIncrementalScanFindings is the integration soundness gate: for each change shape, an
// incremental scan (cache populated from the previous version, then reused) must produce the
// exact same findings as a full scan of the edited tree.
func TestIncrementalScanFindings(t *testing.T) {
	dir := t.TempDir()
	app := filepath.Join(dir, "app.py")
	helper := filepath.Join(dir, "helper.py")

	// app.py: tainted request value flows cross-file through helper.build_cmd into os.system.
	appSrc := "import os\n" +
		"from helper import build_cmd\n" +
		"def handler(request):\n" +
		"    x = request.args.get('name')\n" +
		"    c = build_cmd(x)\n" +
		"    os.system(c)\n"
	helperV1 := "def build_cmd(v):\n    return 'echo ' + v\n"
	writeFile(t, app, appSrc)
	writeFile(t, helper, helperV1)

	// A Go file in the same tree: the native Go frontend yields modules WITHOUT a content hash,
	// so they take the "always relabel, never cache" adapter path. Its weak-hash finding must
	// survive every incremental rescan — guarding the regression where hashless modules were
	// omitted from the relabel set and their adapter labels silently dropped.
	writeFile(t, filepath.Join(dir, "weak.go"), "package main\n\nimport \"crypto/md5\"\n\nfunc weak(b []byte) {\n\th := md5.New()\n\th.Write(b)\n}\n")

	// baseline: a full scan should find the cross-file command injection (sanity that the
	// fixture exercises real taint, so the equivalence check isn't vacuous).
	base := scanFindingKeys(t, []string{dir}, nil)
	if len(base) == 0 {
		t.Fatalf("fixture produced no findings — equivalence check would be vacuous")
	}
	// the Go (hashless module) weak-hash finding must be in the baseline, else the
	// hashless-adapter guard below would pass vacuously.
	hasGo := false
	for _, k := range base {
		if strings.HasPrefix(k, "VYQL-CRY-001@") { // weak-hash from the Go (hashless) module
			hasGo = true
		}
	}
	if !hasGo {
		t.Fatalf("expected the Go weak-hash finding in baseline (hashless-module guard would be vacuous): %v", base)
	}

	edits := []struct {
		name string
		do   func()
	}{
		{"helper body edit", func() { writeFile(t, helper, "def build_cmd(v):\n    y = 1\n    return 'echo ' + v\n") }},
		{"helper signature edit", func() { writeFile(t, helper, "def build_cmd(v, sep):\n    return 'echo' + sep + v\n") }},
		{"app body edit", func() {
			writeFile(t, app, "import os\nfrom helper import build_cmd\ndef handler(request):\n    x = request.args.get('name')\n    log(x)\n    c = build_cmd(x)\n    os.system(c)\n")
		}},
		{"add file", func() { writeFile(t, filepath.Join(dir, "extra.py"), "def noop():\n    return 0\n") }},
	}

	for _, e := range edits {
		t.Run(e.name, func(t *testing.T) {
			// fresh cache, populate from the current tree, then apply the edit and rescan.
			cache := fakeDelta{}
			_ = scanFindingKeys(t, []string{dir}, cache) // populate
			e.do()
			incr := scanFindingKeys(t, []string{dir}, cache) // incremental
			full := scanFindingKeys(t, []string{dir}, nil)   // full reference of edited tree
			if !eqKeys(incr, full) {
				t.Errorf("incremental findings != full after %q\nincr=%v\nfull=%v", e.name, incr, full)
			}
		})
	}
}

// TestIncrementalEditRevertAdd is the finding-identity stability gate (the lifecycle a
// reviewer experiences): edit a file so a finding disappears, revert it and the SAME finding
// reappears with a byte-identical key — VyQL recomputes from content-addressed module state, it
// does not "undo" a cached finding — and adding a file introduces a genuinely new finding.
// Throughout, the incremental scan must equal a full scan of the same tree.
func TestIncrementalEditRevertAdd(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.py")
	// a weak-hash (md5) finding, presence-based — no taint needed, deterministic key.
	weak := "import hashlib\ndef f(data):\n    return hashlib.md5(data).hexdigest()\n"
	safe := "import hashlib\ndef f(data):\n    return hashlib.sha256(data).hexdigest()\n"
	writeFile(t, a, weak)

	cache := fakeDelta{}
	base := scanFindingKeys(t, []string{dir}, cache) // cold populate
	if len(base) != 1 {
		t.Fatalf("expected exactly one baseline finding, got %v", base)
	}

	// change: finding gone (incremental == full).
	writeFile(t, a, safe)
	if got, full := scanFindingKeys(t, []string{dir}, cache), scanFindingKeys(t, []string{dir}, nil); !eqKeys(got, full) || len(got) != 0 {
		t.Fatalf("after change: incr=%v full=%v (want empty, equal)", got, full)
	}

	// revert: the SAME finding with the SAME key reappears via incremental rescan.
	writeFile(t, a, weak)
	rev := scanFindingKeys(t, []string{dir}, cache)
	if !eqKeys(rev, base) {
		t.Fatalf("revert did not reproduce the identical finding key\nbase=%v\nrev =%v", base, rev)
	}

	// add: a second file introduces a new, distinct finding; total grows to two.
	writeFile(t, filepath.Join(dir, "b.py"), "import hashlib\ndef g(x):\n    return hashlib.md5(x).hexdigest()\n")
	add := scanFindingKeys(t, []string{dir}, cache)
	full := scanFindingKeys(t, []string{dir}, nil)
	if !eqKeys(add, full) {
		t.Fatalf("after add: incr=%v != full=%v", add, full)
	}
	if len(add) != 2 {
		t.Fatalf("expected two findings after add, got %v", add)
	}
}

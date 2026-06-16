package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

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

	// baseline: a full scan should find the cross-file command injection (sanity that the
	// fixture exercises real taint, so the equivalence check isn't vacuous).
	base := scanFindingKeys(t, []string{dir}, nil)
	if len(base) == 0 {
		t.Fatalf("fixture produced no findings — equivalence check would be vacuous")
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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

// fakeDelta is an in-memory lowering.DeltaCache for the findings-equivalence harness.
type fakeDelta map[string][]byte

func (f fakeDelta) GetRaw(k string) ([]byte, bool) { v, ok := f[k]; return v, ok }
func (f fakeDelta) PutRaw(k string, v []byte)      { f[k] = append([]byte(nil), v...) }

// scanFindingKeys runs the extract/lower/adapter/evaluate pipeline against an explicit
// lowering cache and returns a canonical, sorted set of finding identities (rule + sink loc).
// This is the integration-level equivalence signal: incremental and full scans of the same
// source MUST yield the same set.
func scanFindingKeys(t *testing.T, paths []string, cache lowering.DeltaCache) []string {
	t.Helper()
	g, err := buildGraphWithSyntheticAdapters(paths, cache)
	if err != nil {
		t.Fatalf("buildGraphWithSyntheticAdapters: %v", err)
	}
	if g == nil {
		return nil
	}
	decls, err := parseV2DefinitionsForTest(syntheticIncrementalRules)
	if err != nil {
		t.Fatalf("rule parse: %v", err)
	}
	compiled, cerrs := engine.CompileRules(decls, syntheticIncrementalOntology())
	if len(cerrs) != 0 {
		t.Fatalf("rule compile: %v", cerrs)
	}
	eng := engine.New(syntheticIncrementalOntology(), g)
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

func buildGraphWithSyntheticAdapters(paths []string, cache lowering.DeltaCache) (usg.Store, error) {
	prog, _, ctorTypes, stats, err := extractAll(paths)
	if err != nil {
		return nil, err
	}
	if len(stats.files) == 0 || len(prog.Modules) == 0 {
		return nil, nil
	}
	var g usg.Store
	if cache != nil {
		var fresh map[string]bool
		g, fresh, err = lowering.LowerIncremental(prog, true, ctorTypes, cache, nil)
		_ = fresh
	} else {
		g, err = lowering.LowerTyped(prog, true, ctorTypes)
	}
	if err != nil {
		return nil, err
	}
	ads := syntheticIncrementalAdapters()
	if cache != nil {
		if _, err := applyAdaptersIncremental(g, ads, moduleHashes(prog), nil, cache); err != nil {
			return nil, err
		}
	} else if _, _, err := adapters.Apply(g, ads, nil); err != nil {
		return nil, err
	}
	return g, nil
}

const syntheticIncrementalRules = `
module test;

rule Flow {
  meta { id: "TEST-FLOW-001", severity: high }
  taint custom.Input -> custom.Target
}

rule Marker {
  meta { id: "TEST-MARKER-001", severity: low }
  issue custom.Marker as sink
}
`

func syntheticIncrementalOntology() *ontology.Ontology {
	onto := ontology.New()
	onto.Add(ontology.Concept{
		Name: "Input", Package: "custom", Kind: "source",
		Taint: []string{"custom.Payload"},
	})
	onto.Add(ontology.Concept{
		Name: "Target", Package: "custom", Kind: "sink",
		EnabledBy: []string{"custom.Payload"}, VulnerableTo: []string{"custom.Condition"},
	})
	onto.Add(ontology.Concept{
		Name: "Marker", Package: "custom", Kind: "sink",
		VulnerableTo: []string{"custom.Condition"},
	})
	return onto
}

func syntheticIncrementalAdapters() []adapters.Adapter {
	return []adapters.Adapter{
		{
			Name: "test.input", Technology: "test", Specificity: 10,
			Fidelity: "resolved", Confidence: "high",
			Apply: func(g usg.Store) []adapters.Mapping {
				if !syntheticSourceActive("custom.Input") {
					return nil
				}
				params, _ := g.NodesOfType("code.Param")
				out := make([]adapters.Mapping, 0, len(params))
				for _, id := range params {
					out = append(out, adapters.Mapping{NodeID: id, Concept: "custom.Input"})
				}
				return out
			},
		},
		{
			Name: "test.target", Technology: "test", Specificity: 10,
			Fidelity: "resolved", Confidence: "high",
			Apply: func(g usg.Store) []adapters.Mapping {
				nodes, _ := g.AllNodes()
				var out []adapters.Mapping
				for _, n := range nodes {
					switch n.Prop("method") {
					case "emit":
						if arg := n.Prop("arg0"); arg != "" {
							out = append(out, adapters.Mapping{NodeID: arg, Concept: "custom.Target"})
						}
					case "marker":
						out = append(out, adapters.Mapping{NodeID: n.ID, Concept: "custom.Marker"})
					}
				}
				return out
			},
		},
	}
}

func syntheticSourceActive(concept string) bool {
	key := frontend.ActiveSourcesKey()
	if key == "*" {
		return true
	}
	for _, part := range strings.Split(key, ",") {
		if part == concept {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
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

func adapterStatKey(root string) string {
	h := sha256.New()
	statStaticAdapterData(h, root)
	return hex.EncodeToString(h.Sum(nil))
}

func TestStaticAdapterFingerprintIncludesSplitLayout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "javascript.vyql"), "module bindings.javascript.flat;\n")
	before := adapterStatKey(root)

	writeFile(t, filepath.Join(root, "javascript", "javascript", "001", "codeHttpInput.vyql"), "module bindings.javascript.split;\n")
	afterSplit := adapterStatKey(root)
	if afterSplit == before {
		t.Fatal("static adapter fingerprint did not include split adapter file")
	}

	writeFile(t, filepath.Join(root, "packages", "generated", "javascript", "express.vyql"), "module bindings.javascript.generated;\n")
	afterGenerated := adapterStatKey(root)
	if afterGenerated != afterSplit {
		t.Fatal("static adapter fingerprint should not include generated package corpus")
	}
}

// TestIncrementalFingerprintActiveSources proves the incremental cache fingerprints the active
// source set, not just source content. Populating the cache under one source policy and rescanning
// under another must match a full scan under the new policy: cached labels from policy A must not
// leak into a policy-B scan.
func TestIncrementalFingerprintActiveSources(t *testing.T) {
	defer frontend.SetActiveSources(nil)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.py"), "def handler(value):\n    emit(value)\n")

	policies := map[string]map[string]bool{
		"off": {},
		"on":  {"custom.Input": true},
	}
	for _, flip := range [][2]string{{"off", "on"}, {"on", "off"}} {
		t.Run(flip[0]+"->"+flip[1], func(t *testing.T) {
			cache := fakeDelta{}
			frontend.SetActiveSources(policies[flip[0]])
			_ = scanFindingKeys(t, []string{dir}, cache) // populate under source policy A
			frontend.SetActiveSources(policies[flip[1]])
			incr := scanFindingKeys(t, []string{dir}, cache) // reuse cache under source policy B
			full := scanFindingKeys(t, []string{dir}, nil)   // full under source policy B
			if !eqKeys(incr, full) {
				t.Errorf("active-source fingerprint leak %s->%s\nincr=%v\nfull=%v", flip[0], flip[1], incr, full)
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

	defer frontend.SetActiveSources(nil)
	frontend.SetActiveSources(map[string]bool{"custom.Input": true})

	appSrc := "from helper import build_value\n" +
		"def handler(value):\n" +
		"    c = build_value(value)\n" +
		"    emit(c)\n"
	helperV1 := "def build_value(v):\n    return 'prefix-' + v\n"
	writeFile(t, app, appSrc)
	writeFile(t, helper, helperV1)

	// A Go file in the same tree: the native Go frontend yields modules WITHOUT a content hash,
	// so they take the "always relabel, never cache" adapter path. Its marker finding must
	// survive every incremental rescan — guarding the regression where hashless modules were
	// omitted from the relabel set and their adapter labels silently dropped.
	writeFile(t, filepath.Join(dir, "native.go"), "package main\n\nfunc keep() {\n\tmarker()\n}\n")

	// baseline: a full scan should find both the flow and the native marker, so the equivalence
	// check is not vacuous.
	base := scanFindingKeys(t, []string{dir}, nil)
	if len(base) == 0 {
		t.Fatalf("fixture produced no findings — equivalence check would be vacuous")
	}
	// the Go (hashless module) marker finding must be in the baseline, else the
	// hashless-adapter guard below would pass vacuously.
	hasGo := false
	for _, k := range base {
		if strings.HasPrefix(k, "TEST-MARKER-001@") {
			hasGo = true
		}
	}
	if !hasGo {
		t.Fatalf("expected the Go marker finding in baseline (hashless-module guard would be vacuous): %v", base)
	}

	edits := []struct {
		name string
		do   func()
	}{
		{"helper body edit", func() { writeFile(t, helper, "def build_value(v):\n    y = 1\n    return 'prefix-' + v\n") }},
		{"helper signature edit", func() { writeFile(t, helper, "def build_value(v, sep='-'):\n    return 'prefix' + sep + v\n") }},
		{"app body edit", func() {
			writeFile(t, app, "from helper import build_value\ndef handler(value):\n    note(value)\n    c = build_value(value)\n    emit(c)\n")
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
	marked := "def f():\n    marker()\n"
	clean := "def f():\n    other()\n"
	writeFile(t, a, marked)

	cache := fakeDelta{}
	base := scanFindingKeys(t, []string{dir}, cache) // cold populate
	if len(base) != 1 {
		t.Fatalf("expected exactly one baseline finding, got %v", base)
	}

	// change: finding gone (incremental == full).
	writeFile(t, a, clean)
	if got, full := scanFindingKeys(t, []string{dir}, cache), scanFindingKeys(t, []string{dir}, nil); !eqKeys(got, full) || len(got) != 0 {
		t.Fatalf("after change: incr=%v full=%v (want empty, equal)", got, full)
	}

	// revert: the SAME finding with the SAME key reappears via incremental rescan.
	writeFile(t, a, marked)
	rev := scanFindingKeys(t, []string{dir}, cache)
	if !eqKeys(rev, base) {
		t.Fatalf("revert did not reproduce the identical finding key\nbase=%v\nrev =%v", base, rev)
	}

	// add: a second file introduces a new, distinct finding; total grows to two.
	writeFile(t, filepath.Join(dir, "b.py"), "def g():\n    marker()\n")
	add := scanFindingKeys(t, []string{dir}, cache)
	full := scanFindingKeys(t, []string{dir}, nil)
	if !eqKeys(add, full) {
		t.Fatalf("after add: incr=%v != full=%v", add, full)
	}
	if len(add) != 2 {
		t.Fatalf("expected two findings after add, got %v", add)
	}
}

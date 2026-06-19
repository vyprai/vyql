package frontend

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestConstraintAllows(t *testing.T) {
	cases := []struct {
		constraint, recvType string
		want                 bool
	}{
		{"alpha.Type", "alpha.Type", true},
		{"Widget", "vendor.pkg.Widget", true},
		{"vendor.pkg.Widget", "Widget", true},
		{"alpha.Type", "beta.Type", false},
		{"alpha.Type,beta.Type,gamma.Type", "gamma.Type", true},
		{"alpha.Type,beta.Type,gamma.Type", "delta.Type", false},
		{"alpha.Type", "", false}, // empty recv handled by the caller, not here
	}
	for _, c := range cases {
		if got := constraintAllows(c.constraint, c.recvType); got != c.want {
			t.Errorf("constraintAllows(%q,%q)=%v want %v", c.constraint, c.recvType, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	// prefix mode: exact, dotted, subscript continuations
	if !matchPath("source.value", []string{"source.value"}, "prefix") {
		t.Error("exact prefix should match")
	}
	if !matchPath("source.value.get", []string{"source.value"}, "prefix") {
		t.Error("dotted continuation should match")
	}
	if !matchPath("Model.query.get", []string{"query.get"}, "prefix") {
		t.Error("dotted suffix should match a path behind a receiver/model segment")
	}
	if matchPath("source.valued", []string{"source.value"}, "prefix") {
		t.Error("a longer word should NOT prefix-match (source.valued != source.value.)")
	}
	// contains mode: substring anywhere (Go varying receivers)
	if !matchPath("obj.Meta.Read.Get", []string{".Meta.Read"}, "contains") {
		t.Error("contains should match a mid-path substring")
	}
	if matchPath("obj.Other", []string{".Meta.Read"}, "contains") {
		t.Error("contains should not falsely match an unrelated path")
	}
}

func TestFrontendDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	concepts := frontendOntologyConceptNeedles(t)
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		if strings.Contains(text, `Concept: "`) || strings.Contains(text, "Concept: `") {
			rel, _ := filepath.Rel(root, path)
			hits = append(hits, rel+": direct concept literal")
		}
		for _, needle := range concepts {
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
		t.Fatalf("frontend extractors must not hardcode ontology concepts; move roles/semantics into VyQL metadata: %s", strings.Join(hits, ", "))
	}
}

func TestFrontendEntryVariableNamesComeFromData(t *testing.T) {
	root := frontendPackageRoot(t)
	forbidden := frontendSourceVarNeedles(t)
	var hits []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
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
		t.Fatalf("frontend entry variable names must be loaded from VyQL data, not hardcoded in Go: %s", strings.Join(hits, ", "))
	}
}

func frontendSourceVarNeedles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(datadir.Root(), "adapters", "*.vyql"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range decls {
			ad, ok := decl.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			for _, key := range []string{"source_var_exact", "source_var_prefix", "source_var_strip_prefix"} {
				for _, value := range metaValues(ad.Meta, key) {
					if len(value) < 3 && !strings.Contains(value, "_") {
						continue
					}
					seen["\""+value+"\""] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

func metaValues(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func frontendPackageRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func frontendOntologyConceptNeedles(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range ontology.Seed().AllConcepts() {
		if c.AnalysisRole != "" {
			continue
		}
		seen["\""+c.Name+"\""] = true
		seen["\""+c.QualifiedName()+"\""] = true
		for _, id := range append(append([]string{}, c.CWE...), append(c.CAPEC, c.Attack...)...) {
			seen["\""+id+"\""] = true
		}
	}
	for _, tk := range ontology.ThreatKinds() {
		seen["\""+tk.Name+"\""] = true
		seen["\""+tk.QualifiedName()+"\""] = true
		for _, id := range tk.CWE {
			seen["\""+id+"\""] = true
		}
	}
	for _, phrase := range []string{"threat-model", "threat model", "trust boundary"} {
		seen[phrase] = true
	}
	addPackRuleIDNeedles(t, seen)
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

func addPackRuleIDNeedles(t *testing.T, seen map[string]bool) {
	t.Helper()
	root := filepath.Join(datadir.Root(), "packs")
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".vyql") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			return err
		}
		for _, decl := range decls {
			rule, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			if id, _ := rule.Meta["id"].(string); id != "" {
				seen["\""+id+"\""] = true
				seen["`"+id+"`"] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read pack rule ids: %v", err)
	}
}

func TestPackageGatedSinkRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:  "custom.Target",
			Pattern:  "samplepkg.handle",
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.sinkAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated sink fired without evidence: %+v", got)
	}

	withImport := usg.NewInMemStore()
	withImport.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withImport.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withImport.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withImport); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "custom.Target" {
		t.Fatalf("package-gated sink did not fire with import evidence: %+v", got)
	}

	withSBOM := usg.NewInMemStore()
	withSBOM.AddNode(usg.Node{ID: "pkg:generic/samplepkg@1.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "samplepkg", "version": "1.0",
	}})
	withSBOM.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "sample.x:3"}})
	withSBOM.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "samplepkg.handle", "method": "handle", "arg0": "arg",
	}})
	if got := adapter.Apply(withSBOM); len(got) != 1 || got[0].NodeID != "arg" {
		t.Fatalf("package-gated sink did not fire with SBOM evidence: %+v", got)
	}
}

func TestValueMatchedSinkUsesFlowingStringTokens(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.Target",
			Pattern:    "open",
			ValMatches: []string{"/tmp/", "w"},
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "tmp", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "path.join", "method": "join", "str_args": "/tmp/fixed",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "arg1", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Const",
	}})
	store.AddNode(usg.Node{ID: "open", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "open", "method": "open", "arg0": "arg0", "arg1": "arg1", "str_args": "w",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tmp", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "open"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg1", Dst: "open"})

	openNode, _, _ := store.GetNode("open")
	var flowIdx flowTokenIndex
	if !valCondsForNode(store, &flowIdx, openNode, []string{"/tmp/", "w"}, nil) {
		t.Fatalf("flowing string tokens did not satisfy value constraints: %q", flowingStringTokens(store, &flowIdx, "open", openNode.Prop("str_args")))
	}

	got := spec.sinkAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg0" || got[0].Concept != "custom.Target" {
		t.Fatalf("value-matched sink did not use flowing string tokens: %+v", got)
	}

	markSpec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Marks: []controlSpec{{
			Concept:    "custom.Mark",
			Pattern:    "open",
			ValMatches: []string{"/tmp/", "w"},
		}},
	}
	got = markSpec.markAdapter().Apply(store)
	if len(got) != 0 {
		t.Fatalf("value-matched mark used flowing string tokens: %+v", got)
	}

	directMarkStore := usg.NewInMemStore()
	directMarkStore.AddNode(usg.Node{ID: "open", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "open", "method": "open", "str_args": "/tmp/fixed\x00w",
	}})
	got = markSpec.markAdapter().Apply(directMarkStore)
	if len(got) != 1 || got[0].NodeID != "open" || got[0].Concept != "custom.Mark" {
		t.Fatalf("value-matched mark did not use direct string tokens: %+v", got)
	}
}

func TestCollectionFirstSinkTargetsIndexedElement(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:         "custom.Command",
			Pattern:         "runtime.execv",
			CollectionFirst: true,
			CollectionIndex: 0,
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "elem0", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "0",
	}})
	store.AddNode(usg.Node{ID: "elem1", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "sample.x:1", "collection_index": "1",
	}})
	store.AddNode(usg.Node{ID: "seq", Type: "code.Seq", Props: map[string]string{
		"loc": "sample.x:1", "callee_path": "__object_literal",
	}})
	store.AddNode(usg.Node{ID: "tmp", Type: "code.Name", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "runtime.execv", "method": "execv", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem0", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem1", Dst: "seq"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "seq", Dst: "tmp"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "tmp", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "call"})

	got := spec.sinkAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "elem0" || got[0].Concept != "custom.Command" {
		t.Fatalf("collection first sink mapping wrong: %+v", got)
	}
}

func TestValueMatchedSourceUsesDirectStringTokensOnly(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:    "custom.Source",
			Paths:      []string{"os.getenv"},
			Match:      "prefix",
			ValMatches: []string{"HTTP_PROXY"},
		}},
	}
	adapter := spec.inputAdapter()

	direct := usg.NewInMemStore()
	direct.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "os.getenv", "method": "getenv", "str_args": "HTTP_PROXY",
	}})
	if got := adapter.Apply(direct); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("value-matched source did not use direct string tokens: %+v", got)
	}

	flowed := usg.NewInMemStore()
	flowed.AddNode(usg.Node{ID: "literal", Type: "code.Const", Props: map[string]string{
		"loc": "sample.x:1", "str_args": "HTTP_PROXY",
	}})
	flowed.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	flowed.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "os.getenv", "method": "getenv", "arg0": "arg0",
	}})
	flowed.AddEdge(usg.Edge{Type: "FLOWS", Src: "literal", Dst: "arg0"})
	flowed.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "src"})
	if got := adapter.Apply(flowed); len(got) != 0 {
		t.Fatalf("value-matched source used flowing string tokens: %+v", got)
	}
}

func TestInputAdapterVisitsCallablePropertyNodeTypes(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept: "custom.Source",
			Paths: []string{
				"call.source",
				"attr.source",
				"name_source",
				"bag.__subscript",
				"__binop.add",
				"__unary.neg",
				"__object_literal",
			},
			Match: "prefix",
		}},
	}
	store := usg.NewInMemStore()
	for _, tc := range []struct {
		id   string
		typ  string
		path string
	}{
		{"call", "code.Call", "call.source"},
		{"attr", "code.Attr", "attr.source"},
		{"name", "code.Name", "name_source"},
		{"subscript", "code.Subscript", "bag.__subscript"},
		{"binop", "code.BinOp", "__binop.add"},
		{"unary", "code.Unary", "__unary.neg"},
		{"seq", "code.Seq", "__object_literal"},
	} {
		store.AddNode(usg.Node{ID: tc.id, Type: tc.typ, Props: map[string]string{
			"loc": "sample.x:1", "callee_path": tc.path, "method": tc.path,
		}})
	}
	got := spec.inputAdapter().Apply(store)
	if len(got) != 7 {
		t.Fatalf("input adapter missed callable node types: %+v", got)
	}
	seen := map[string]bool{}
	for _, m := range got {
		seen[m.NodeID] = true
	}
	for _, id := range []string{"call", "attr", "name", "subscript", "binop", "unary", "seq"} {
		if !seen[id] {
			t.Fatalf("input adapter missed %s in %+v", id, got)
		}
	}
}

func TestPackageGatedSourceRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:  "custom.Source",
			Paths:    []string{"samplepkg.source.value"},
			Match:    "prefix",
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.inputAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("package-gated source did not fire with package evidence: %+v", got)
	}
}

func TestPackageGatedReceiverSourceUsesResolvedType(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Inputs: []inputSpec{{
			Concept:    "custom.Source",
			Methods:    []string{"value"},
			Receiver:   true,
			Constraint: "samplepkg.Request",
			Packages:   []string{"samplepkg"},
		}},
	}
	adapter := spec.inputAdapter()

	withWrongReceiver := usg.NewInMemStore()
	withWrongReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withWrongReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "payload.value", "method": "value",
	}})
	if got := adapter.Apply(withWrongReceiver); len(got) != 0 {
		t.Fatalf("receiver source fired without receiver type: %+v", got)
	}

	withReceiver := usg.NewInMemStore()
	withReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "sample.x:3", "callee_path": "request.value", "method": "value", "recv_type": "samplepkg.Request",
	}})
	if got := adapter.Apply(withReceiver); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("receiver source did not fire with receiver type: %+v", got)
	}
}

func TestPackageGatedControlRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "normalize",
			ByMethod: true,
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.controlAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated control fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("package-gated control did not fire with package evidence: %+v", got)
	}
}

func TestReceiverControlLabelsReceiverNode(t *testing.T) {
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "recv", Type: "code.Name", Props: map[string]string{"loc": "sample.x:1"}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc":    "sample.x:1",
		"method": "checked",
		"recv":   "recv",
	}})

	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Controls: []controlSpec{{
			Concept:  "custom.Control",
			Pattern:  "checked",
			ByMethod: true,
			Receiver: true,
		}},
	}
	got := spec.controlAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "recv" || got[0].Concept != "custom.Control" {
		t.Fatalf("receiver control mapping wrong: %+v", got)
	}
}

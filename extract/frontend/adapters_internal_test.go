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

func TestExplicitPackageBlockSinkRequiresPackageEvidence(t *testing.T) {
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
		t.Fatalf("explicit package-block sink fired without evidence: %+v", got)
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
		t.Fatalf("explicit package-block sink did not fire with import evidence: %+v", got)
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
		t.Fatalf("explicit package-block sink did not fire with SBOM evidence: %+v", got)
	}
}

func TestExplicitPackageBlockParamSourceRequiresPackageEvidence(t *testing.T) {
	defer SetActiveSources(nil)
	SetActiveSources(map[string]bool{"custom.ParamSource": true})

	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		ParamSources: []paramSourceSpec{{
			Concept:  "custom.ParamSource",
			Packages: []string{"samplepkg"},
		}},
	}
	adapter := spec.paramSourceAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "param", Type: "code.Param", Props: map[string]string{
		"loc": "sample.x:2", "exported": "true",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("explicit package-block param source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "param", Type: "code.Param", Props: map[string]string{
		"loc": "sample.x:2", "exported": "true",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "param" || got[0].Concept != "custom.ParamSource" || got[0].Specificity != 3 {
		t.Fatalf("explicit package-block param source did not fire with evidence: %+v", got)
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

func TestValueMatchedSinkUsesUpstreamTokensWhenCallHasNoDirectStrings(t *testing.T) {
	spec := adapterSpec{
		Name:       "neutral",
		Technology: "neutral",
		Sinks: []sinkSpec{{
			Concept:    "custom.Target",
			Pattern:    "queryDB",
			ValMatches: []string{"insert into"},
		}},
	}
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "sql", Type: "code.Format", Props: map[string]string{
		"loc": "sample.x:1", "str_args": "INSERT INTO users VALUES (?)",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "sample.x:2", "vkind": "Name",
	}})
	store.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "queryDB", "method": "queryDB", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "sql", Dst: "arg0"})

	got := spec.sinkAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "arg0" || got[0].Concept != "custom.Target" {
		t.Fatalf("value-matched sink did not use upstream tokens when call had no direct strings: %+v", got)
	}
}

func TestContextFlagSyntaxBuildsScopedFlag(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.SecretComparison in function {
    lang "javascript"
    call path "parseOut"
    selector "data.x-csrf-token"
    token identifier "providedToken"
    not call path "crypto.timingSafeEqual"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context flag: %v", err)
	}
	ad, ok := decls[0].(*parser.AdapterDecl)
	if !ok {
		t.Fatalf("expected adapter decl, got %#v", decls[0])
	}
	spec := specFromDecl(ad)
	if len(spec.Flags) != 1 {
		t.Fatalf("expected one flag spec, got %#v", spec.Flags)
	}
	flag := spec.Flags[0]
	if flag.Scope != "function" || len(flag.Predicates) != 5 ||
		flag.Predicates[0].Values[0] != "lang=javascript" ||
		flag.Predicates[1].Values[0] != "call_path:parseOut" ||
		flag.Predicates[2].Values[0] != "selector:data.x-csrf-token" ||
		flag.Predicates[3].Values[0] != "identifier:providedToken" ||
		!flag.Predicates[4].Negative {
		t.Fatalf("unexpected context flag spec: %#v", flag)
	}

	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.js:1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=javascript\x00selector:data.x-csrf-token\x00identifier:providedToken",
	}})
	store.AddNode(usg.Node{ID: "parse", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.js:5",
		"callee_path": "parseOut",
		"method":      "parseOut",
	}})
	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.SecretComparison" {
		t.Fatalf("context flag did not label matching context node: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:2",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=javascript\x00selector:data.x-csrf-token\x00identifier:providedToken\x00call_path:crypto.timingSafeEqual",
	}})
	store.AddNode(usg.Node{ID: "fixed-parse", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:5",
		"callee_path": "parseOut",
		"method":      "parseOut",
	}})
	store.AddNode(usg.Node{ID: "fixed-safe", Type: "code.Call", Props: map[string]string{
		"loc":         "sample-fixed.js:6",
		"callee_path": "crypto.timingSafeEqual",
		"method":      "timingSafeEqual",
	}})
	got = spec.flagAdapter().Apply(store)
	if len(got) != 1 {
		t.Fatalf("context flag should skip scope with matching excluded call, got %+v", got)
	}
}

func TestContextFlagAstCallPredicatesPreferLexicalScope(t *testing.T) {
	decls, err := parser.Parse(`
adapter java {
  flag custom.WorldAccess in function {
    function "safe"
    call path "world.getBlockAt"
    not call contains_any ["testCoord"]
  }
}
`)
	if err != nil {
		t.Fatalf("parse scoped context flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "World.java:10",
		Scope: "World.java/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "function_name:safe",
		},
	})
	store.AddNode(usg.Node{
		ID:    "other-call",
		Type:  "code.Call",
		Loc:   "World.java:30",
		Scope: "World.java/fn2",
		Props: map[string]string{
			"callee_path": "world.getBlockAt",
			"method":      "getBlockAt",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context flag matched call outside lexical scope: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "local-call",
		Type:  "code.Call",
		Loc:   "World.java:12",
		Scope: "World.java/fn1/if0.t",
		Props: map[string]string{
			"callee_path": "world.getBlockAt",
			"method":      "getBlockAt",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.WorldAccess" {
		t.Fatalf("context flag did not match nested in-scope call: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "guard",
		Type:  "code.Call",
		Loc:   "World.java:11",
		Scope: "World.java/fn1",
		Props: map[string]string{
			"callee_path": "testCoords",
			"method":      "testCoords",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context flag should skip guarded lexical scope, got %+v", got)
	}
}

func TestContextFlagIndexesScopedContextAndMatchesOrderedSelectorScope(t *testing.T) {
	decls, err := parser.Parse(`
adapter go {
  flag custom.ShareInfoLeak in function {
    function "shareInfoHandler"
    call path "store.Share.GetByHash"
    call path "getShareURL"
    selector "shareLink.Token"
  }
}
`)
	if err != nil {
		t.Fatalf("parse scoped selector flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "share.go:610",
		Scope: "share.go/fn77@1361",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "function_name:shareInfoHandler",
		},
	})
	store.AddNode(usg.Node{
		ID:    "lookup",
		Type:  "code.Call",
		Loc:   "share.go:613",
		Scope: "share.go/fn77@1370",
		Props: map[string]string{
			"callee_path": "store.Share.GetByHash",
			"method":      "GetByHash",
		},
	})
	store.AddNode(usg.Node{
		ID:    "token",
		Type:  "code.Attr",
		Loc:   "share.go:618",
		Scope: "share.go/fn77@1384",
		Props: map[string]string{
			"callee_path": "shareLink.Token",
			"method":      "Token",
		},
	})
	store.AddNode(usg.Node{
		ID:    "url",
		Type:  "code.Call",
		Loc:   "share.go:618",
		Scope: "share.go/fn77@1386",
		Props: map[string]string{
			"callee_path": "getShareURL",
			"method":      "getShareURL",
		},
	})

	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.ShareInfoLeak" {
		t.Fatalf("context flag did not match ordered same-function call and selector evidence: %+v", got)
	}
}

func TestAstFlagMatchesUnorderedBinopOperands(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.SecretComparison on binop {
    op any ["==", "==="]
    operand {
      key contains_any ["csrf-token", "x-csrf-token"]
    }
    operand {
      identifier contains_any ["token", "secret", "signature", "key"]
    }
    lacks call contains_any ["scmp", "timingSafeEqual"]
  }
}
`)
	if err != nil {
		t.Fatalf("parse ast flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "cmp", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.js:10", "op": "===", "callee_path": "__binop.eq", "method": "eq", "arg0": "a0", "arg1": "a1",
	}})
	store.AddNode(usg.Node{ID: "a0", Type: "code.Arg"})
	store.AddNode(usg.Node{ID: "a1", Type: "code.Arg"})
	store.AddNode(usg.Node{ID: "header", Type: "code.Subscript", Props: map[string]string{
		"loc": "sample.js:10", "callee_path": "data.__subscript", "method": "[]", "str_args": "x-csrf-token",
	}})
	store.AddNode(usg.Node{ID: "candidate", Type: "code.Param", Props: map[string]string{
		"loc": "sample.js:10", "name": "providedToken",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "header", Dst: "a0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "candidate", Dst: "a1"})
	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "cmp" || got[0].Concept != "custom.SecretComparison" {
		t.Fatalf("AST flag did not label matching binop: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc": "sample.js:20", "callee_path": "crypto.timingSafeEqual", "method": "timingSafeEqual",
	}})
	got = spec.flagAdapter().Apply(store)
	if len(got) != 0 {
		t.Fatalf("AST flag should skip file with constant-time comparison call: %+v", got)
	}
}

func TestContextFlagAstScopedLiteralAndSubscriptPredicates(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.PrototypeMerge in function {
    lang "javascript"
    index "base.__subscript"
    token subscript "obj[key]"
    not literal "__proto__"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context ast flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "merge.js:1",
		Scope: "merge.js/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=javascript",
		},
	})
	store.AddNode(usg.Node{
		ID:    "base-sub",
		Type:  "code.Subscript",
		Loc:   "merge.js:9",
		Scope: "merge.js/fn1/loop",
		Props: map[string]string{"callee_path": "base.__subscript", "method": "[]"},
	})
	store.AddNode(usg.Node{
		ID:    "obj-sub",
		Type:  "code.Subscript",
		Loc:   "merge.js:6",
		Scope: "merge.js/fn1/loop",
		Props: map[string]string{"callee_path": "obj.__subscript", "method": "[]", "str_args": "key"},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST flag did not match scoped subscript nodes: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "proto-literal",
		Type:  "code.Const",
		Loc:   "merge.js:5",
		Scope: "merge.js/fn1",
		Props: map[string]string{"str_args": "__proto__"},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context AST flag should skip scoped prototype literal guard: %+v", got)
	}
}

func TestContextFlagAstScopedSelectorContainsAny(t *testing.T) {
	decls, err := parser.Parse(`
adapter python {
  flag custom.LockOpen in function {
    lang "python"
    selector contains_any ["lock_file", ".lock", "lock"]
  }
}
`)
	if err != nil {
		t.Fatalf("parse context ast selector flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "lock.py:1",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	store.AddNode(usg.Node{
		ID:    "lock-attr",
		Type:  "code.Attr",
		Loc:   "lock.py:9",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "self.lock_file",
			"method":      "lock_file",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST flag did not match selector contains_any text: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "other-ctx",
		Type:  "code.Call",
		Loc:   "other.py:1",
		Scope: "other.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 {
		t.Fatalf("context AST flag should stay file/scope-local, got %+v", got)
	}
}

func TestContextFlagAstSoftLockNoFollowPredicateMix(t *testing.T) {
	decls, err := parser.Parse(`
adapter python {
  flag custom.LockNoFollow in function {
    lang "python"
    call path "os.open"
    selector "os.O_CREAT"
    selector "os.O_EXCL"
    selector contains_any ["lock_file", ".lock", "lock"]
    not literal "O_NOFOLLOW"
  }
}
`)
	if err != nil {
		t.Fatalf("parse soft-lock context flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "lock.py:1",
		Scope: "lock.py/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=python",
		},
	})
	for _, node := range []usg.Node{
		{ID: "open", Type: "code.Call", Loc: "lock.py:9", Scope: "lock.py/fn1/try2", Props: map[string]string{"callee_path": "os.open", "method": "open"}},
		{ID: "create", Type: "code.Attr", Loc: "lock.py:5", Scope: "lock.py/fn1", Props: map[string]string{"callee_path": "os.O_CREAT", "method": "O_CREAT"}},
		{ID: "excl", Type: "code.Attr", Loc: "lock.py:6", Scope: "lock.py/fn1", Props: map[string]string{"callee_path": "os.O_EXCL", "method": "O_EXCL"}},
		{ID: "lock", Type: "code.Attr", Loc: "lock.py:9", Scope: "lock.py/fn1/try2", Props: map[string]string{"callee_path": "self.lock_file", "method": "lock_file"}},
	} {
		store.AddNode(node)
	}
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("soft-lock context flag did not match AST predicate mix: %+v", got)
	}

	store.AddNode(usg.Node{ID: "nofollow", Type: "code.Const", Loc: "lock.py:7", Scope: "lock.py/fn1", Props: map[string]string{"str_args": "O_NOFOLLOW"}})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("soft-lock context flag should skip no-follow hardening: %+v", got)
	}
}

func TestContextFlagAstScopedCallArgPredicates(t *testing.T) {
	decls, err := parser.Parse(`
adapter php {
  flag custom.DirectJsonEncode in function {
    lang "php"
    call arg "json_encode:$data[$field_name]"
    not call arg "json_encode:$value"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "fields.php:1",
		Scope: "fields.php/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=php",
		},
	})
	store.AddNode(usg.Node{
		ID:    "encode",
		Type:  "code.Call",
		Loc:   "fields.php:9",
		Scope: "fields.php/fn1/if2",
		Props: map[string]string{
			"callee_path": "json_encode",
			"method":      "json_encode",
			"str_args":    "$data[$field_name]",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context AST call-arg flag did not match scoped call argument: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:    "fixed",
		Type:  "code.Call",
		Loc:   "fields.php:10",
		Scope: "fields.php/fn1",
		Props: map[string]string{
			"callee_path": "json_encode",
			"method":      "json_encode",
			"str_args":    "$value",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context AST call-arg flag should honor excluded scoped argument: %+v", got)
	}
}

func TestContextFlagAstSubscriptPredicatesHonorKeys(t *testing.T) {
	decls, err := parser.Parse(`
adapter php {
  flag custom.PasswordOnlySessionHash in function {
    lang "php"
    name "authenticate"
    token subscript "$u['password']"
    not token subscript "$u['permissions']"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context subscript flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "auth.php:10",
		Scope: "auth.php/fn1",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=php\x00name=authenticate",
		},
	})
	store.AddNode(usg.Node{
		ID:    "password",
		Type:  "code.Subscript",
		Loc:   "auth.php:12",
		Scope: "auth.php/fn1",
		Props: map[string]string{"callee_path": "$u.__subscript", "str_args": "password"},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context subscript flag should match password without permissions: %+v", got)
	}
	store.AddNode(usg.Node{
		ID:    "permissions",
		Type:  "code.Subscript",
		Loc:   "auth.php:12",
		Scope: "auth.php/fn1",
		Props: map[string]string{"callee_path": "$u.__subscript", "str_args": "permissions"},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context subscript flag should reject matching permissions key: %+v", got)
	}
}

func TestContextFlagIgnoresUnscopedParamsFromOtherFunctions(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.RemoteUrlDebugLog in function {
    lang "javascript"
    name "fetchRepo"
    call path "logger.debug"
    token identifier "url"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context identifier flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{
		ID:    "ctx",
		Type:  "code.Call",
		Loc:   "file.ts:40",
		Scope: "file.ts/fn2",
		Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    "lang=javascript\x00name=fetchRepo",
		},
	})
	store.AddNode(usg.Node{
		ID:    "debug",
		Type:  "code.Call",
		Loc:   "file.ts:45",
		Scope: "file.ts/fn2",
		Props: map[string]string{"callee_path": "logger.debug", "method": "debug"},
	})
	store.AddNode(usg.Node{
		ID:   "other-param",
		Type: "code.Param",
		Loc:  "file.ts:10",
		Props: map[string]string{
			"name": "url",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context identifier flag matched unscoped param from a different function: %+v", got)
	}

	store.AddNode(usg.Node{
		ID:   "local-param",
		Type: "code.Param",
		Loc:  "file.ts:40",
		Props: map[string]string{
			"name": "url",
		},
	})
	if got := spec.flagAdapter().Apply(store); len(got) != 1 || got[0].NodeID != "ctx" {
		t.Fatalf("context identifier flag should match unscoped param on context declaration line: %+v", got)
	}
}

func TestContextFlagCallArgDoesNotUseCompactTokenFallback(t *testing.T) {
	decls, err := parser.Parse(`
adapter php {
  flag custom.DirectJsonEncode in function {
    lang "php"
    call arg "json_encode:$data[$field_name]"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context call-arg flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:1",
		"region":      "fields.php/fn1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php\x00call_arg:json_encode:$data[$field_name]",
	}})
	if got := spec.flagAdapter().Apply(store); len(got) != 0 {
		t.Fatalf("context call-arg flag should require scoped AST call evidence, got %+v", got)
	}
}

func TestContextFlagAstPredicatesUseRegionWhenScopeIsEmpty(t *testing.T) {
	decls, err := parser.Parse(`
adapter php {
  flag custom.ScopedLiteral in function {
    lang "php"
    literal "multiple_dropdown_action"
    call arg "json_encode:$data[$field_name]"
  }
}
`)
	if err != nil {
		t.Fatalf("parse region-scoped context flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "target-ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:10",
		"region":      "fields.php/fn1",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php",
	}})
	store.AddNode(usg.Node{ID: "other-ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:30",
		"region":      "fields.php/fn2",
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    "lang=php",
	}})
	store.AddNode(usg.Node{ID: "lit", Type: "code.Const", Props: map[string]string{
		"loc":      "fields.php:11",
		"region":   "fields.php/fn1",
		"str_args": "multiple_dropdown_action",
	}})
	store.AddNode(usg.Node{ID: "encode", Type: "code.Call", Props: map[string]string{
		"loc":         "fields.php:12",
		"region":      "fields.php/fn1/if1",
		"callee_path": "json_encode",
		"method":      "json_encode",
		"str_args":    "$data[$field_name]",
	}})
	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "target-ctx" {
		t.Fatalf("context AST flag should use region as lexical scope, got %+v", got)
	}
}

func TestContextFlagStructuredTokenContainsSearchesTokenPayload(t *testing.T) {
	decls, err := parser.Parse(`
adapter ruby {
  flag custom.RailsSecretToken in module {
    lang "ruby"
    assign contains_any [".config.secret_token="]
    not expr "Rails.env=='test'"
  }
}
`)
	if err != nil {
		t.Fatalf("parse context structured-token flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "secret_token.rb:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
	}})
	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "ctx" || got[0].Concept != "custom.RailsSecretToken" {
		t.Fatalf("context structured-token flag did not search token payload: %+v", got)
	}

	store.AddNode(usg.Node{ID: "fixed", Type: "code.Call", Props: map[string]string{
		"loc":         "secret_token_fixed.rb:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=ruby\x00expr:Rails.env=='test'\x00assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
	}})
	got = spec.flagAdapter().Apply(store)
	if len(got) != 1 {
		t.Fatalf("context structured-token flag should skip test-only guarded scope, got %+v", got)
	}
}

func TestAstFlagMatchesDownstreamFlowPredicate(t *testing.T) {
	decls, err := parser.Parse(`
adapter cpp {
  flag custom.PointerAddOverflow on binop {
    op "+"
    operand {
      path "alignPointer"
    }
    flows to op ">"
    not flows to op "<"
  }
}
`)
	if err != nil {
		t.Fatalf("parse ast flow flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Props: map[string]string{
		"loc":         "sample.h:1",
		"callee_path": "analysis.module.context",
		"method":      "context",
		"str_args":    "lang=cpp",
	}})
	store.AddNode(usg.Node{ID: "add", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:10", "op": "+", "callee_path": "__binop.add", "arg0": "a0", "arg1": "a1",
	}})
	store.AddNode(usg.Node{ID: "a0", Type: "code.Arg", Props: map[string]string{"loc": "sample.h:10"}})
	store.AddNode(usg.Node{ID: "a1", Type: "code.Arg", Props: map[string]string{"loc": "sample.h:10"}})
	store.AddNode(usg.Node{ID: "align", Type: "code.Call", Props: map[string]string{
		"loc": "sample.h:9", "callee_path": "alignPointer", "method": "alignPointer",
	}})
	store.AddNode(usg.Node{ID: "upper", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:12", "op": ">", "callee_path": "__binop.gt",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "align", Dst: "a0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "a0", Dst: "add"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "a1", Dst: "add"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "add", Dst: "upper"})
	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "add" || got[0].Concept != "custom.PointerAddOverflow" {
		t.Fatalf("AST flow flag did not label vulnerable add: %+v", got)
	}

	store.AddNode(usg.Node{ID: "wrap", Type: "code.BinOp", Props: map[string]string{
		"loc": "sample.h:12", "op": "<", "callee_path": "__binop.lt",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "add", Dst: "wrap"})
	got = spec.flagAdapter().Apply(store)
	if len(got) != 0 {
		t.Fatalf("AST flow flag should skip add with downstream wraparound check: %+v", got)
	}
}

func TestAstFlagCallOperandMatchesTransitiveFlow(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.RemoteUrlDebugLog on call {
    path "logger.debug"
    operand {
      identifier contains_any ["url", "uri"]
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parse param flow flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "url-param", Type: "code.Param", Props: map[string]string{
		"loc": "file.js:10", "name": "url",
	}})
	store.AddNode(usg.Node{ID: "elem", Type: "code.CollectionElement", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "obj", Type: "code.Seq", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "__object_literal",
	}})
	store.AddNode(usg.Node{ID: "arg0", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "debug", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "logger.debug", "method": "debug", "arg0": "arg0",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "url-param", Dst: "elem"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "elem", Dst: "obj"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "obj", Dst: "arg0"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "arg0", Dst: "debug"})

	debug, ok, err := store.GetNode("debug")
	if err != nil || !ok {
		t.Fatalf("missing debug node: ok=%v err=%v", ok, err)
	}
	if !flagNodeKindAllows(spec.Flags[0], debug) {
		t.Fatalf("debug node kind was not allowed by flag: %+v", spec.Flags[0])
	}
	if !flagMatchesNode(store, &flowTokenIndex{}, spec.Flags[0], debug, "javascript", false, nil) {
		t.Fatalf("call operand flag did not match transitive URL flow into debug call")
	}

	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "debug" || got[0].Concept != "custom.RemoteUrlDebugLog" {
		t.Fatalf("call operand flag did not label debug log call: %+v", got)
	}
}

func TestAstFlagCallOperandFallsBackToIncomingArgFlow(t *testing.T) {
	decls, err := parser.Parse(`
adapter javascript {
  flag custom.ZipCompressedSizeRead on call {
    path "tokenizer.readToken"
    operand {
      path "Token.StringType"
      path "zipHeader.compressedSize"
    }
  }
}
`)
	if err != nil {
		t.Fatalf("parse call operand flag: %v", err)
	}
	spec := specFromDecl(decls[0].(*parser.AdapterDecl))
	store := usg.NewInMemStore()
	store.AddNode(usg.Node{ID: "size", Type: "code.Attr", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "zipHeader.compressedSize",
	}})
	store.AddNode(usg.Node{ID: "size-arg", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "string-type", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "Token.StringType", "method": "StringType",
	}})
	store.AddNode(usg.Node{ID: "read-arg", Type: "code.Arg", Props: map[string]string{
		"loc": "file.js:20",
	}})
	store.AddNode(usg.Node{ID: "read-token", Type: "code.Call", Props: map[string]string{
		"loc": "file.js:20", "callee_path": "tokenizer.readToken", "method": "readToken",
	}})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "size", Dst: "size-arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "size-arg", Dst: "string-type"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "string-type", Dst: "read-arg"})
	store.AddEdge(usg.Edge{Type: "FLOWS", Src: "read-arg", Dst: "read-token"})

	got := spec.flagAdapter().Apply(store)
	if len(got) != 1 || got[0].NodeID != "read-token" || got[0].Concept != "custom.ZipCompressedSizeRead" {
		t.Fatalf("call operand flag did not use incoming arg flow fallback: %+v", got)
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

func TestExplicitPackageBlockSourceRequiresPackageEvidence(t *testing.T) {
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
		t.Fatalf("explicit package-block source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.source.value", "method": "value",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "custom.Source" {
		t.Fatalf("explicit package-block source did not fire with package evidence: %+v", got)
	}
}

func TestExplicitPackageBlockReceiverSourceUsesResolvedType(t *testing.T) {
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

func TestExplicitPackageBlockControlRequiresPackageEvidence(t *testing.T) {
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
		t.Fatalf("explicit package-block control fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "sample.x:1", "module": "samplepkg", "package": "samplepkg",
	}})
	withPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "sample.x:2", "callee_path": "samplepkg.normalize", "method": "normalize",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "custom.Control" {
		t.Fatalf("explicit package-block control did not fire with package evidence: %+v", got)
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

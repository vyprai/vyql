package lowering

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

func TestLoweringDoesNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	concepts := loweringForbiddenConceptLiterals(t)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(file), "*.go"))
	if err != nil {
		t.Fatalf("glob lowering files: %v", err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(src), `Concept: "`) {
			t.Fatalf("%s hardcodes a concept label; emit structural facts and map them in VyQL data", filepath.Base(path))
		}
		for _, concept := range concepts {
			if strings.Contains(string(src), concept) {
				t.Fatalf("%s mentions ontology concept %q; emit structural facts and map them in VyQL data", filepath.Base(path), concept)
			}
		}
	}
}

func loweringForbiddenConceptLiterals(t *testing.T) []string {
	t.Helper()
	out := map[string]bool{}
	for _, c := range ontology.Seed().AllConcepts() {
		if c.AnalysisRole != "" {
			continue
		}
		out[`"`+c.Name+`"`] = true
		out["`"+c.Name+"`"] = true
		out[`"`+c.QualifiedName()+`"`] = true
		out["`"+c.QualifiedName()+"`"] = true
		for _, id := range append(append([]string{}, c.CWE...), append(c.CAPEC, c.Attack...)...) {
			out[`"`+id+`"`] = true
			out["`"+id+"`"] = true
		}
	}
	for _, tk := range ontology.ThreatKinds() {
		out[`"`+tk.Name+`"`] = true
		out["`"+tk.Name+"`"] = true
		out[`"`+tk.QualifiedName()+`"`] = true
		out["`"+tk.QualifiedName()+"`"] = true
		for _, id := range tk.CWE {
			out[`"`+id+`"`] = true
			out["`"+id+"`"] = true
		}
	}
	addPackRuleIDNeedles(t, out)
	concepts := make([]string, 0, len(out))
	for concept := range out {
		concepts = append(concepts, concept)
	}
	sort.Strings(concepts)
	return concepts
}

func addPackRuleIDNeedles(t *testing.T, out map[string]bool) {
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
		decls, err := parseV2DefinitionsForTest(string(raw))
		if err != nil {
			return err
		}
		for _, decl := range decls {
			rule, ok := decl.(*parser.Rule)
			if !ok {
				continue
			}
			if id, _ := rule.Meta["id"].(string); id != "" {
				out["\""+id+"\""] = true
				out["`"+id+"`"] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read pack rule ids: %v", err)
	}
}

func TestCollectValTokensDescendsIntoFormat(t *testing.T) {
	var toks []string
	collectValTokens(nir.Format{
		Parts: []nir.Expr{
			nir.Const{Value: "prefix="},
			nir.Const{Value: "sample-value"},
		},
	}, "", &toks)

	for _, tok := range toks {
		if tok == "sample-value" {
			return
		}
	}
	t.Fatalf("expected formatted literal token, got %#v", toks)
}

func TestLoweringCarriesLiteralTokensOnFormatAndSubscript(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.Assign{Targets: []string{"short"}, Value: nir.Index{
				Base: nir.Name{ID: "key_id", Loc: "app.py:1"},
				Key:  nir.Const{Loc: "app.py:1", Value: "-8:"},
				Path: "key_id.upper",
				Loc:  "app.py:1",
			}},
			nir.Assign{Targets: []string{"cmd"}, Value: nir.Format{
				Parts: []nir.Expr{
					nir.Const{Loc: "app.py:2", Value: "\"apt-key adv --recv \""},
					nir.Name{ID: "short", Loc: "app.py:2"},
				},
				Loc: "app.py:2",
			}},
			nir.Assign{Targets: []string{"guard"}, Value: nir.Const{Loc: "app.py:3", Value: "\"__proto__\""}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	var sawSubscript, sawFormat bool
	ids, _ := g.NodesOfType("code.Subscript")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if strings.Contains(n.Prop("str_args"), "-8:") {
			sawSubscript = true
		}
	}
	ids, _ = g.NodesOfType("code.Format")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if strings.Contains(n.Prop("str_args"), "--recv") {
			sawFormat = true
		}
	}
	if !sawSubscript || !sawFormat {
		t.Fatalf("literal tokens missing: subscript=%v format=%v", sawSubscript, sawFormat)
	}
	var sawConst bool
	ids, _ = g.NodesOfType("code.Const")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if strings.Contains(n.Prop("str_args"), "__proto__") {
			sawConst = true
		}
	}
	if !sawConst {
		t.Fatalf("const literal token missing")
	}
}

func TestLoweringMapsJSArgumentsToSyntheticExportParam(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "pkg",
		File: "index.js",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:     "__default_export__",
				Params:   []string{nir.JSArgumentsParam},
				Loc:      "index.js:1",
				Exported: true,
				Body: []nir.Stmt{
					nir.Return{Value: nir.Index{
						Base: nir.Name{ID: "arguments", Loc: "index.js:2"},
						Key:  nir.Const{Value: "0", Loc: "index.js:2"},
						Path: "arguments.__subscript",
						Loc:  "index.js:2",
					}},
				},
			},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	src := findNodeID(t, g, "code.Param", "name", nir.JSArgumentsParam)
	subscriptIDs, err := g.NodesOfType("code.Subscript")
	if err != nil {
		t.Fatal(err)
	}
	if len(subscriptIDs) != 1 {
		t.Fatalf("expected one arguments subscript, got %v", subscriptIDs)
	}
	dst := subscriptIDs[0]
	reachable, err := usg.BFS(g, src, "FLOWS", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[dst] {
		t.Fatalf("synthetic JS arguments param did not flow to arguments subscript")
	}
}

func TestDynamicReadOfCleanTrackedContainerDoesNotInheritSelectorTaint(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app.php",
		File: "app.php",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "view", Loc: "app.php:1", Params: []string{"key", "payload"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "$files", Loc: "app.php:2"}, Attr: "__setitem__", Loc: "app.php:2"},
					Args: []nir.Expr{
						nir.Const{Value: "\"/etc/radiusd.conf\"", Loc: "app.php:2"},
						nir.Const{Value: "\"radiusd\"", Loc: "app.php:2"},
					},
					Path: "$files.__setitem__", Method: "__setitem__", Loc: "app.php:2",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "$files", Loc: "app.php:3"}, Attr: "__setitem__", Loc: "app.php:3"},
					Args: []nir.Expr{
						nir.Name{ID: "payload", Loc: "app.php:3"},
						nir.Const{Value: "\"dynamic\"", Loc: "app.php:3"},
					},
					Path: "$files.__setitem__", Method: "__setitem__", Loc: "app.php:3",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.php:4"},
					Args: []nir.Expr{nir.Index{
						Base: nir.Name{ID: "$files", Loc: "app.php:4"},
						Key:  nir.Name{ID: "key", Loc: "app.php:4"},
						Path: "$files", Loc: "app.php:4",
					}},
					Path: "sink", Method: "sink", Loc: "app.php:4",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	keyParam := findNodeID(t, g, "code.Param", "name", "key")
	payloadParam := findNodeID(t, g, "code.Param", "name", "payload")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.php:4")
	keyReachable, err := usg.BFS(g, keyParam, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if keyReachable[sinkArg] {
		t.Fatalf("dynamic selector taint should not become the selected value of a clean tracked container")
	}
	payloadReachable, err := usg.BFS(g, payloadParam, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !payloadReachable[sinkArg] {
		t.Fatalf("dynamic read of a clean tracked container should still include tainted known slots")
	}
}

func TestExplicitSelfMethodCallDispatchesInheritedOverride(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "app.py",
		File: "app.py",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Base", Loc: "app.py:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "run", Loc: "app.py:2", Params: []string{"self", "value"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"built"}, Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "self", Loc: "app.py:3"}, Attr: "build", Path: "self.build", Loc: "app.py:3"},
						Args:   []nir.Expr{nir.Name{ID: "value", Loc: "app.py:3"}},
						Path:   "self.build", Method: "build", Loc: "app.py:3",
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "app.py:4"},
						Args:   []nir.Expr{nir.Name{ID: "built", Loc: "app.py:4"}},
						Path:   "sink", Method: "sink", Loc: "app.py:4",
					}},
				}},
				nir.FuncDef{Name: "build", Loc: "app.py:5", Params: []string{"self", "value"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Const{Loc: "app.py:6", Value: "base"}},
				}},
			}},
			nir.ClassDef{Name: "Child", Bases: []string{"Base"}, Loc: "app.py:8", Body: []nir.Stmt{
				nir.FuncDef{Name: "build", Loc: "app.py:9", Params: []string{"self", "value"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "value", Loc: "app.py:10"}},
				}},
			}},
			nir.FuncDef{Name: "entry", Loc: "app.py:13", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"child"}, Value: nir.Call{
					Callee: nir.Name{ID: "Child", Loc: "app.py:14"},
					Path:   "Child", Method: "Child", Loc: "app.py:14", IsCtor: true,
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "child", Loc: "app.py:15"}, Attr: "run", Path: "child.run", Loc: "app.py:15"},
					Args:   []nir.Expr{nir.Name{ID: "payload", Loc: "app.py:15"}},
					Path:   "child.run", Method: "run", Loc: "app.py:15",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	overrideParam := findNodeID(t, g, "code.Param", "func", "build", "name", "value", "loc", "app.py:9")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:4")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[overrideParam] {
		t.Fatalf("payload did not reach child override value parameter")
	}
	if !reachable[sinkArg] {
		t.Fatalf("payload did not reach sink arg through inherited override")
	}
}

func TestTargetArgsCallbackDispatchesDynamicCallee(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "app.py",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "runner", Loc: "app.py:1", Params: []string{"callback", "packed"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "callback", Loc: "app.py:2"},
					Args:   []nir.Expr{nir.Name{ID: "packed", Loc: "app.py:2"}},
					Path:   "callback", Method: "callback", Loc: "app.py:2",
				}},
			}},
			nir.FuncDef{Name: "worker", Loc: "app.py:5", Params: []string{"first", "second", "third"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.py:6"},
					Args:   []nir.Expr{nir.Name{ID: "third", Loc: "app.py:6"}},
					Path:   "sink", Method: "sink", Loc: "app.py:6",
				}},
			}},
			nir.FuncDef{Name: "entry", Loc: "app.py:9", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "threading", Loc: "app.py:10"}, Attr: "Thread", Path: "threading.Thread", Loc: "app.py:10"},
					Args: []nir.Expr{
						nir.Pair{Key: "target", Value: nir.Name{ID: "runner", Loc: "app.py:10"}, Loc: "app.py:10"},
						nir.Pair{Key: "args", Value: nir.Seq{Loc: "app.py:10", Parts: []nir.Expr{
							nir.Name{ID: "worker", Loc: "app.py:10"},
							nir.Const{Value: "static", Loc: "app.py:10"},
							nir.Name{ID: "payload", Loc: "app.py:10"},
						}}, Loc: "app.py:10"},
					},
					Path: "threading.Thread", Method: "Thread", Loc: "app.py:10",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	callbackParam := findNodeID(t, g, "code.Param", "func", "worker", "name", "third")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:6")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[callbackParam] {
		t.Fatalf("payload did not reach dynamic callback parameter")
	}
	if !reachable[sinkArg] {
		t.Fatalf("payload did not reach sink arg through dynamic callback")
	}
}

func TestDynamicCallbackFallbackDoesNotCrossLanguageFamilies(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "java",
			File: "Helper.java",
			Body: []nir.Stmt{
				nir.FuncDef{Name: "worker", Params: []string{"x"}, Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "Helper.java:2"},
						Args:   []nir.Expr{nir.Name{ID: "x", Loc: "Helper.java:2"}},
						Path:   "sink", Method: "sink", Loc: "Helper.java:2",
					}},
				}, Loc: "Helper.java:1"},
			},
		},
		{
			Key:  "webapp/js/jquery.min.js",
			File: "webapp/js/jquery.min.js",
			Body: []nir.Stmt{
				nir.FuncDef{Name: "runner", Params: []string{"callback", "payload"}, Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "callback", Loc: "webapp/js/jquery.min.js:2"},
						Args:   []nir.Expr{nir.Name{ID: "payload", Loc: "webapp/js/jquery.min.js:2"}},
						Path:   "callback", Method: "callback", Loc: "webapp/js/jquery.min.js:2",
					}},
				}, Loc: "webapp/js/jquery.min.js:1"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := findNodeID(t, g, "code.Param", "func", "runner", "name", "payload")
	javaSinkArg := findNodeID(t, g, "code.Arg", "loc", "Helper.java:2")
	reachable, err := usg.BFS(g, payload, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[javaSinkArg] {
		t.Fatalf("dynamic callback fallback crossed from javascript into java")
	}
}

func TestAllowlistMembershipIfBoundsTrueBranchValue(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "render", Loc: "app.py:1", Params: []string{"layout"}, Body: []nir.Stmt{
				nir.If{
					Cond: nir.BinOp{
						Left: nir.Name{ID: "layout", Loc: "app.py:2"},
						Op:   "in",
						Right: nir.Seq{Loc: "app.py:2", Parts: []nir.Expr{
							nir.Const{Value: "\"dot\"", Loc: "app.py:2"},
							nir.Const{Value: "\"neato\"", Loc: "app.py:2"},
						}},
						Loc: "app.py:2",
					},
					Then: []nir.Stmt{
						nir.Assign{Loc: "app.py:3", Targets: []string{"args"}, Value: nir.Seq{Loc: "app.py:3", Parts: []nir.Expr{
							nir.Name{ID: "layout", Loc: "app.py:3"},
						}}},
						nir.ExprStmt{Value: nir.Call{
							Callee: nir.Attr{Base: nir.Name{ID: "subprocess", Loc: "app.py:4"}, Attr: "Popen", Path: "subprocess.Popen", Loc: "app.py:4"},
							Args:   []nir.Expr{nir.Name{ID: "args", Loc: "app.py:4"}},
							Path:   "subprocess.Popen", Method: "Popen", Loc: "app.py:4",
						}},
					},
				},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "layout")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:4")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sinkArg] {
		t.Fatalf("allowlisted branch value should not preserve taint into sink arg")
	}
}

func findNodeID(t *testing.T, g usg.Store, typ string, props ...string) string {
	t.Helper()
	if len(props)%2 != 0 {
		t.Fatalf("props must be key/value pairs")
	}
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		match := true
		for i := 0; i < len(props); i += 2 {
			if n.Prop(props[i]) != props[i+1] {
				match = false
				break
			}
		}
		if match {
			return id
		}
	}
	t.Fatalf("node %s with props %v not found", typ, props)
	return ""
}

func TestLowerMaterializesImportNodes(t *testing.T) {
	g, err := Lower(nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Imports: []nir.Import{{
			Local: "samplepkg", Module: "samplepkg", IsModule: true,
		}},
	}}}, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Import")
	if len(ids) != 1 {
		t.Fatalf("import node count = %d, want 1", len(ids))
	}
	n, _, _ := g.GetNode(ids[0])
	if n.Prop("module") != "samplepkg" || n.Prop("local") != "samplepkg" || n.Prop("package") != "samplepkg" {
		t.Fatalf("import props wrong: %+v", n.Props)
	}
}

func TestLowerStampsReceiverTypeFromParamTypes(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.js",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Service", Body: []nir.Stmt{
				nir.FuncDef{Name: "clean", Params: []string{"x"}, Body: []nir.Stmt{nir.Return{Value: nir.Name{ID: "x", Loc: "app.js:1"}}}, Loc: "app.js:1"},
			}, Loc: "app.js:1"},
			nir.FuncDef{Name: "handler", Params: []string{"svc"}, ParamTypes: map[string]string{"svc": "Service"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "svc", Loc: "app.js:3"}, Attr: "clean", Path: "svc.clean", Loc: "app.js:3"},
					Args:   []nir.Expr{nir.Const{Loc: "app.js:3"}},
					Path:   "svc.clean", Method: "clean", Loc: "app.js:3",
				}},
			}, Loc: "app.js:2"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "svc.clean" {
			if got := n.Prop("recv_type"); got != "Service" {
				t.Fatalf("recv_type = %q, want Service", got)
			}
			return
		}
	}
	t.Fatalf("svc.clean call not found")
}

func TestBenchmarkThingIdentityCallDoesNotShareReturnAcrossCallSites(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "helpers",
			File: "ThingInterface.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "ThingInterface", Body: []nir.Stmt{
					nir.FuncDef{Name: "doSomething", Params: []string{"i"}, Body: nil, Loc: "ThingInterface.java:1"},
				}, Loc: "ThingInterface.java:1"},
				nir.ClassDef{Name: "Thing1", Bases: []string{"ThingInterface"}, Body: []nir.Stmt{
					nir.FuncDef{Name: "doSomething", Params: []string{"i"}, Body: []nir.Stmt{
						nir.Return{Value: nir.Name{ID: "i", Loc: "Thing1.java:3"}},
					}, Loc: "Thing1.java:2"},
				}, Loc: "Thing1.java:1"},
			},
		},
		{
			Key:  "app",
			File: "App.java",
			Body: []nir.Stmt{
				nir.FuncDef{Name: "taint", Params: []string{"p"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"thing"}, Value: nir.Const{Loc: "App.java:2"}, Type: "ThingInterface", Loc: "App.java:2"},
					nir.Assign{Targets: []string{"x"}, Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "thing", Loc: "App.java:3"}, Attr: "doSomething", Path: "thing.doSomething", Loc: "App.java:3"},
						Args:   []nir.Expr{nir.Name{ID: "p", Loc: "App.java:3"}},
						Path:   "thing.doSomething", Method: "doSomething", Loc: "App.java:3",
					}},
				}, Loc: "App.java:1"},
				nir.FuncDef{Name: "safe", Body: []nir.Stmt{
					nir.Assign{Targets: []string{"thing"}, Value: nir.Const{Loc: "App.java:6"}, Type: "ThingInterface", Loc: "App.java:6"},
					nir.Assign{Targets: []string{"bar"}, Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "thing", Loc: "App.java:7"}, Attr: "doSomething", Path: "thing.doSomething", Loc: "App.java:7"},
						Args:   []nir.Expr{nir.Const{Value: "safe", Loc: "App.java:7"}},
						Path:   "thing.doSomething", Method: "doSomething", Loc: "App.java:7",
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "File", Loc: "App.java:8"},
						Args:   []nir.Expr{nir.Name{ID: "bar", Loc: "App.java:8"}},
						Path:   "File", Method: "File", Loc: "App.java:8",
					}},
				}, Loc: "App.java:5"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "p")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "App.java:8")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sinkArg] {
		t.Fatalf("benchmark helper identity call shared taint across call sites")
	}
}

func TestLowerPreservesDeclaredReceiverTypeAfterUntypedAssignment(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.java",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"item"}, Type: "ExternalItem", Decl: true},
				nir.Assign{Targets: []string{"item"}, Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "source", Loc: "app.java:3"}, Attr: "next", Path: "source.next", Loc: "app.java:3"},
					Path:   "source.next", Method: "next", Loc: "app.java:3",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "item", Loc: "app.java:4"}, Attr: "name", Path: "item.name", Loc: "app.java:4"},
					Path:   "item.name", Method: "name", Loc: "app.java:4",
				}},
			}, Loc: "app.java:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "item.name" {
			continue
		}
		if got := n.Prop("recv_type"); got != "ExternalItem" {
			t.Fatalf("recv_type = %q, want ExternalItem; props=%+v", got, n.Props)
		}
		return
	}
	t.Fatalf("item.name call not found")
}

func TestLowerCallRecordsReceiverNode(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Body: []nir.Stmt{
				nir.Assign{Targets: []string{"value"}, Value: nir.Const{Loc: "app.py:1", Value: "\"x\""}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "value", Loc: "app.py:2"}, Attr: "checked", Path: "value.checked", Loc: "app.py:2"},
					Path:   "value.checked", Method: "checked", Loc: "app.py:2",
				}},
			}, Loc: "app.py:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "value.checked" {
			continue
		}
		if n.Prop("recv") == "" {
			t.Fatalf("receiver call missing recv prop: %+v", n.Props)
		}
		return
	}
	t.Fatalf("value.checked call not found")
}

func TestLowerFunctionReturnCreatesAnalysisEvent(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Decorators: []string{"decorator_method:get"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Name{ID: "body", Loc: "app.py:2"}},
			}, Loc: "app.py:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.function.return" &&
			n.Prop("arg0") != "" &&
			strings.Contains(n.Prop("str_args"), "decorator_method:get") {
			return
		}
	}
	t.Fatalf("function return analysis event not found")
}

func TestLowerParamEntryCreatesSourceEventFlow(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Params: []string{"value"}, ParamEntries: []nir.ParamEntry{{
				Param:  "value",
				Tokens: []string{"decorator_method:get", "param_name:value"},
			}}, Body: []nir.Stmt{
				nir.Return{Value: nir.Name{ID: "value", Loc: "app.py:2"}},
			}, Loc: "app.py:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	var eventID, paramID string
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.parameter.entry" &&
			strings.Contains(n.Prop("str_args"), "decorator_method:get") {
			eventID = id
			break
		}
	}
	ids, _ = g.NodesOfType("code.Param")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("name") == "value" {
			paramID = id
			break
		}
	}
	if eventID == "" || paramID == "" {
		t.Fatalf("missing event=%q param=%q", eventID, paramID)
	}
	outs, _ := g.OutEdges(eventID, "FLOWS")
	for _, edge := range outs {
		if edge.Dst == paramID {
			return
		}
	}
	t.Fatalf("parameter entry event does not flow to parameter")
}

func TestLowerClassDefCreatesContextEvent(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "C.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Child", Loc: "C.java:3", Bases: []string{"Base", "AutoCloseable"}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.class.context" &&
			strings.Contains(n.Prop("str_args"), "class_name:Child") &&
			strings.Contains(n.Prop("str_args"), "class_base:Base") &&
			strings.Contains(n.Prop("str_args"), "class_base:AutoCloseable") {
			return
		}
	}
	t.Fatalf("class context analysis event not found")
}

func TestLowerClassContextIncludesMemberFunctionTokens(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "C.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Handler", Loc: "C.java:3", Bases: []string{"InvocationHandler"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "invoke", Loc: "C.java:4", ContextTokens: []string{
					"class_name:Handler",
					"class_base:InvocationHandler",
					"function_name:invoke",
					"call:invokeImpl",
				}},
				nir.FuncDef{Name: "invokeImpl", Loc: "C.java:8", ContextTokens: []string{
					"class_name:Handler",
					"class_base:InvocationHandler",
					"function_name:invokeImpl",
					"call:getMethod",
					"call:invokeMethod",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.class.context" {
			continue
		}
		args := n.Prop("str_args")
		if strings.Contains(args, "class_name:Handler") &&
			strings.Contains(args, "class_base:InvocationHandler") &&
			strings.Contains(args, "function_name:invoke") &&
			strings.Contains(args, "call:invokeImpl") &&
			strings.Contains(args, "function_name:invokeImpl") &&
			strings.Contains(args, "call:getMethod") &&
			strings.Contains(args, "call:invokeMethod") {
			return
		}
	}
	t.Fatalf("class context did not include member function tokens")
}

func TestLowerClassContextKeepsNestedClassMemberTokensSeparate(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "C.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Outer", Loc: "C.java:1", Body: []nir.Stmt{
				nir.ClassDef{Name: "Handler", Loc: "C.java:3", Bases: []string{"InvocationHandler"}, Body: []nir.Stmt{
					nir.FuncDef{Name: "invoke", Loc: "C.java:4", ContextTokens: []string{
						"class_name:Handler",
						"class_base:InvocationHandler",
						"function_name:invoke",
						"call:invokeImpl",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	var outer, handler bool
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.class.context" {
			continue
		}
		args := n.Prop("str_args")
		if strings.Contains(args, "class_name:Outer") {
			outer = true
			if strings.Contains(args, "class_base:InvocationHandler") ||
				strings.Contains(args, "function_name:invoke") {
				t.Fatalf("outer class context included nested handler evidence: %q", args)
			}
		}
		if strings.Contains(args, "class_name:Handler") &&
			strings.Contains(args, "class_base:InvocationHandler") &&
			strings.Contains(args, "function_name:invoke") {
			handler = true
		}
	}
	if !outer || !handler {
		t.Fatalf("expected separate outer and handler class context events, got outer=%v handler=%v", outer, handler)
	}
}

func TestLowerResultEntryCreatesControlEventFlow(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "marked", Params: []string{"value"}, ResultEntries: []nir.ResultEntry{{
				Tokens: []string{"marker:review"},
			}}, Body: []nir.Stmt{
				nir.Return{Value: nir.Name{ID: "value", Loc: "app.py:2"}},
			}, Loc: "app.py:1"},
			nir.FuncDef{Name: "handler", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "marked", Loc: "app.py:5"},
					Args:   []nir.Expr{nir.Const{Loc: "app.py:5", Value: "\"x\""}},
					Path:   "marked", Method: "marked", Loc: "app.py:5",
				}},
			}, Loc: "app.py:4"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.function.result" &&
			strings.Contains(n.Prop("str_args"), "marker:review") &&
			n.Prop("arg0") != "" {
			return
		}
	}
	t.Fatalf("result entry event not found")
}

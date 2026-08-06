package lowering

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
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
		if ontology.IsInternalConceptRoleConcept(c.QualifiedName()) {
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

func TestCallEffectIdentityAliasesOutParam(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:   "handler",
				Params: []string{"payload", "stale"},
				Loc:    "app.py:1",
				Body: []nir.Stmt{
					nir.Assign{Targets: []string{"out"}, Value: nir.Name{ID: "stale", Loc: "app.py:2"}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "alias", Loc: "app.py:3"},
						Path:   "alias",
						Method: "alias",
						Loc:    "app.py:3",
						Args: []nir.Expr{
							nir.Name{ID: "payload", Loc: "app.py:3"},
							nir.Name{ID: "out", Loc: "app.py:3"},
						},
						Effects: []nir.CallEffect{{SourceArg: 0, DestArg: 1, Identity: true}},
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "app.py:4"},
						Path:   "sink",
						Method: "sink",
						Loc:    "app.py:4",
						Args:   []nir.Expr{nir.Name{ID: "out", Loc: "app.py:4"}},
					}},
				},
			},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	payload := findNodeID(t, g, "code.Param", "name", "payload")
	stale := findNodeID(t, g, "code.Param", "name", "stale")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:4")
	reachable, err := usg.BFS(g, payload, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("identity call effect did not route payload to out-param sink")
	}
	reachable, err = usg.BFS(g, stale, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sinkArg] {
		t.Fatalf("identity call effect behaved like a join; stale value reached out-param sink")
	}
}

func TestCallEffectReceiverFlowsToResult(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{
				Name:   "handler",
				Params: []string{"builder"},
				Loc:    "app.py:1",
				Body: []nir.Stmt{
					nir.Assign{Targets: []string{"next"}, Value: nir.Call{
						Callee: nir.Attr{
							Base: nir.Name{ID: "builder", Loc: "app.py:2"},
							Attr: "setOption",
							Path: "builder.setOption",
							Loc:  "app.py:2",
						},
						Path:    "builder.setOption",
						Method:  "setOption",
						Loc:     "app.py:2",
						Effects: []nir.CallEffect{{Receiver: true}},
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "app.py:3"},
						Path:   "sink",
						Method: "sink",
						Loc:    "app.py:3",
						Args:   []nir.Expr{nir.Name{ID: "next", Loc: "app.py:3"}},
					}},
				},
			},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	builder := findNodeID(t, g, "code.Param", "name", "builder")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:3")
	reachable, err := usg.BFS(g, builder, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("receiver call effect did not route receiver to fluent result")
	}
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

// A two-part-key container — configparser's `cfg.set(section, key, val)` /
// `cfg.get(section, key)` — must resolve per (section, key) slot: reading a key that was
// never written tainted stays clean, while reading the key that WAS written tainted still
// flows. Before the composite-key model a 3-arg set() marked the container dirty, so every
// later get() read the whole container and any config round-trip produced a false positive.
func TestCompositeKeyContainerReadIsElementSensitive(t *testing.T) {
	call := func(recv, method, path, loc string, args ...nir.Expr) nir.Call {
		return nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: recv, Loc: loc}, Attr: method, Loc: loc},
			Args:   args, Path: path, Method: method, Loc: loc,
		}
	}
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app.py",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Loc: "app.py:1", Params: []string{"payload"}, Body: []nir.Stmt{
				// cfg.set("sec", "keyA", "constant")   → clean slot
				nir.ExprStmt{Value: call("cfg", "set", "cfg.set", "app.py:2",
					nir.Const{Value: "\"sec\"", Loc: "app.py:2"},
					nir.Const{Value: "\"keyA\"", Loc: "app.py:2"},
					nir.Const{Value: "\"constant\"", Loc: "app.py:2"})},
				// cfg.set("sec", "keyB", payload)      → tainted slot
				nir.ExprStmt{Value: call("cfg", "set", "cfg.set", "app.py:3",
					nir.Const{Value: "\"sec\"", Loc: "app.py:3"},
					nir.Const{Value: "\"keyB\"", Loc: "app.py:3"},
					nir.Name{ID: "payload", Loc: "app.py:3"})},
				// safe = cfg.get("sec", "keyA")  → must NOT be tainted
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sinkA", Loc: "app.py:4"},
					Args: []nir.Expr{call("cfg", "get", "cfg.get", "app.py:14",
						nir.Const{Value: "\"sec\"", Loc: "app.py:14"},
						nir.Const{Value: "\"keyA\"", Loc: "app.py:14"})},
					Path: "sinkA", Method: "sinkA", Loc: "app.py:4",
				}},
				// tainted = cfg.get("sec", "keyB") → MUST stay tainted
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sinkB", Loc: "app.py:5"},
					Args: []nir.Expr{call("cfg", "get", "cfg.get", "app.py:15",
						nir.Const{Value: "\"sec\"", Loc: "app.py:15"},
						nir.Const{Value: "\"keyB\"", Loc: "app.py:15"})},
					Path: "sinkB", Method: "sinkB", Loc: "app.py:5",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := findNodeID(t, g, "code.Param", "name", "payload")
	reachable, err := usg.BFS(g, payload, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "app.py:4")] {
		t.Errorf("get(section, keyA) must read the clean slot, not the whole container")
	}
	if !reachable[findNodeID(t, g, "code.Arg", "loc", "app.py:5")] {
		t.Errorf("get(section, keyB) must still carry the taint written to that slot")
	}
}

// A plain dict's `d.get(key, default)` is NOT a two-part key — arg1 is a fallback value.
// Only a 3-arg keyed write marks a container composite, so a dict written through
// __setitem__ must keep flowing the whole container on a 2-arg get (no false negative).
func TestPlainDictGetWithDefaultStillFlowsContainerTaint(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app.py",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Loc: "app.py:1", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "d", Loc: "app.py:2"}, Attr: "__setitem__", Loc: "app.py:2"},
					Args: []nir.Expr{
						nir.Name{ID: "payload", Loc: "app.py:2"},
						nir.Const{Value: "\"k\"", Loc: "app.py:2"},
					},
					Path: "d.__setitem__", Method: "__setitem__", Loc: "app.py:2",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.py:3"},
					Args: []nir.Expr{nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "d", Loc: "app.py:13"}, Attr: "get", Loc: "app.py:13"},
						Args: []nir.Expr{
							nir.Const{Value: "\"k\"", Loc: "app.py:13"},
							nir.Const{Value: "\"fallback\"", Loc: "app.py:13"},
						},
						Path: "d.get", Method: "get", Loc: "app.py:13",
					}},
					Path: "sink", Method: "sink", Loc: "app.py:3",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := findNodeID(t, g, "code.Param", "name", "payload")
	reachable, err := usg.BFS(g, payload, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Arg", "loc", "app.py:3")] {
		t.Errorf("dict.get(key, default) must not be treated as a composite key read")
	}
}

// nodeOrder returns a node's CFG order as the number it is, so comparisons do not
// depend on decimal string ordering.
func nodeOrder(t *testing.T, n usg.Node) int {
	t.Helper()
	v, err := strconv.Atoi(n.Prop("order"))
	if err != nil {
		t.Fatalf("node %s has no numeric order: %q", n.ID, n.Prop("order"))
	}
	return v
}

// callNodeByPath returns the single lowered call node whose callee path is want.
func callNodeByPath(t *testing.T, g usg.Store, want string) usg.Node {
	t.Helper()
	ids, _ := g.NodesOfType("code.Call")
	var found []usg.Node
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == want {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s call, got %d", want, len(found))
	}
	return found[0]
}

// funcProgram wraps body in a single function `f` in a one-module program.
func funcProgram(file string, body ...nir.Stmt) nir.Program {
	return nir.Program{Modules: []nir.Module{{
		Key: "app", File: file,
		Body: []nir.Stmt{nir.FuncDef{Name: "f", Body: body, Loc: file + ":1"}},
	}}}
}

func callStmt(path, loc string) nir.ExprStmt {
	base, method, _ := strings.Cut(path, ".")
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: nir.Name{ID: base, Loc: loc}, Attr: method, Path: path, Loc: loc},
		Path:   path, Method: method, Loc: loc,
	}}
}

func deferStmt(path, loc string) nir.Defer {
	return nir.Defer{Body: []nir.Stmt{callStmt(path, loc)}, Loc: loc}
}

// A deferred call runs when the function returns, so it must be lowered after everything
// the body did — that ordering is what makes a deferred release post-dominate an
// acquisition above it.
func TestLowerDeferPlacesCallAfterTheFunctionBody(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("mu.Lock", "app.go:2"),
		deferStmt("mu.Unlock", "app.go:3"),
		callStmt("w.Work", "app.go:4"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	lock := callNodeByPath(t, g, "mu.Lock")
	unlock := callNodeByPath(t, g, "mu.Unlock")
	work := callNodeByPath(t, g, "w.Work")

	if unlock.Prop("region") != lock.Prop("region") {
		t.Errorf("deferred call region = %q, want the body's %q", unlock.Prop("region"), lock.Prop("region"))
	}
	if nodeOrder(t, unlock) <= nodeOrder(t, work) {
		t.Errorf("deferred call order %d must follow the last body statement's %d",
			nodeOrder(t, unlock), nodeOrder(t, work))
	}
	if !solvers.PostDominates(g, unlock.ID, lock.ID) {
		t.Error("deferred release must post-dominate the acquisition above it")
	}
	// The call keeps the source location it was written at, so findings point at the defer.
	if unlock.Prop("loc") != "app.go:3" {
		t.Errorf("deferred call loc = %q, want app.go:3", unlock.Prop("loc"))
	}
}

// Registering a defer inside a branch only runs it when that branch is taken, so it must
// keep the branch's region and must NOT post-dominate an acquisition outside it.
func TestLowerDeferInBranchDoesNotPostDominateAcquisitionOutsideIt(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("mu.Lock", "app.go:2"),
		nir.If{Then: []nir.Stmt{deferStmt("mu.Unlock", "app.go:4")}, Loc: "app.go:3"},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	lock := callNodeByPath(t, g, "mu.Lock")
	unlock := callNodeByPath(t, g, "mu.Unlock")

	if r := unlock.Prop("region"); !strings.HasPrefix(r, lock.Prop("region")+"/") {
		t.Errorf("conditionally deferred call region = %q, want one nested under %q", r, lock.Prop("region"))
	}
	if solvers.PostDominates(g, unlock.ID, lock.ID) {
		t.Error("a defer registered inside a branch must not post-dominate code outside it")
	}
}

// Deferred calls run last-in-first-out, so their lowered order must be the reverse of
// the order they were registered in.
func TestLowerDeferEmitsRegistrationsInReverseOrder(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		deferStmt("a.First", "app.go:2"),
		deferStmt("b.Second", "app.go:3"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	first := callNodeByPath(t, g, "a.First")
	second := callNodeByPath(t, g, "b.Second")
	if nodeOrder(t, second) >= nodeOrder(t, first) {
		t.Errorf("defers run LIFO: order(second)=%d must precede order(first)=%d",
			nodeOrder(t, second), nodeOrder(t, first))
	}
}

// Each function owns its defers: a nested function's registrations run at ITS return, and
// must not be emitted into the enclosing function's region.
func TestLowerDeferDoesNotEscapeIntoTheEnclosingFunction(t *testing.T) {
	g, err := Lower(nir.Program{Modules: []nir.Module{{
		Key: "app", File: "app.go",
		Body: []nir.Stmt{nir.FuncDef{Name: "outer", Body: []nir.Stmt{
			callStmt("mu.Lock", "app.go:2"),
			nir.FuncDef{Name: "inner", Body: []nir.Stmt{
				deferStmt("mu.Unlock", "app.go:4"),
			}, Loc: "app.go:3"},
		}, Loc: "app.go:1"}},
	}}}, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	lock := callNodeByPath(t, g, "mu.Lock")
	unlock := callNodeByPath(t, g, "mu.Unlock")
	if unlock.Prop("region") == lock.Prop("region") {
		t.Errorf("inner function's defer landed in the outer region %q", lock.Prop("region"))
	}
	if solvers.PostDominates(g, unlock.ID, lock.ID) {
		t.Error("a defer in a nested function must not post-dominate the enclosing function")
	}
}

// A `finally` runs on every path out of the try statement, so its nodes belong to the
// region the statement sits in — not to a nested one, which would read as skippable.
func TestLowerFinallyRunsInTheEnclosingRegion(t *testing.T) {
	g, err := Lower(funcProgram("app.java",
		callStmt("lock.lock", "app.java:2"),
		nir.Try{
			Body:    []nir.Stmt{callStmt("w.work", "app.java:4")},
			Finally: []nir.Stmt{callStmt("lock.unlock", "app.java:6")},
			Loc:     "app.java:3",
		},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "lock.lock")
	release := callNodeByPath(t, g, "lock.unlock")
	body := callNodeByPath(t, g, "w.work")

	if release.Prop("region") != acquire.Prop("region") {
		t.Errorf("finally region = %q, want the enclosing %q", release.Prop("region"), acquire.Prop("region"))
	}
	if body.Prop("region") == acquire.Prop("region") {
		t.Errorf("try body must keep its own region, got the enclosing %q", body.Prop("region"))
	}
	if nodeOrder(t, release) <= nodeOrder(t, body) {
		t.Errorf("finally order %d must follow the try body's %d", nodeOrder(t, release), nodeOrder(t, body))
	}
	if !solvers.PostDominates(g, release.ID, acquire.ID) {
		t.Error("a release in finally must post-dominate an acquisition above the try")
	}
}

// The same holds for an acquisition made INSIDE the try body: the finally still runs.
func TestLowerFinallyPostDominatesTheTryBody(t *testing.T) {
	g, err := Lower(funcProgram("app.java",
		nir.Try{
			Body:    []nir.Stmt{callStmt("lock.lock", "app.java:3")},
			Finally: []nir.Stmt{callStmt("lock.unlock", "app.java:5")},
			Loc:     "app.java:2",
		},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if !solvers.PostDominates(g, callNodeByPath(t, g, "lock.unlock").ID, callNodeByPath(t, g, "lock.lock").ID) {
		t.Error("a release in finally must post-dominate an acquisition in the try body")
	}
}

// A try/finally written inside a branch still only runs when that branch is taken, so it
// must NOT cover an acquisition outside it.
func TestLowerFinallyInBranchDoesNotCoverAcquisitionOutsideIt(t *testing.T) {
	g, err := Lower(funcProgram("app.java",
		callStmt("lock.lock", "app.java:2"),
		nir.If{Then: []nir.Stmt{
			nir.Try{
				Body:    []nir.Stmt{callStmt("w.work", "app.java:5")},
				Finally: []nir.Stmt{callStmt("lock.unlock", "app.java:6")},
				Loc:     "app.java:4",
			},
		}, Loc: "app.java:3"},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if solvers.PostDominates(g, callNodeByPath(t, g, "lock.unlock").ID, callNodeByPath(t, g, "lock.lock").ID) {
		t.Error("a finally inside a branch must not post-dominate code outside that branch")
	}
}

// The journal must restore exactly: sets over existing keys, sets of new keys, and nested
// marks — undoNode(mark) leaves the map byte-equal to its state at the mark.
func TestScopeJournalUndoRestoresExactly(t *testing.T) {
	sc := newScope()
	sc.setNode("kept", "v0") // depth 0: not journaled, permanent
	sc.branchDepth++
	m := sc.markNode()
	sc.setNode("kept", "v1")  // overwrite existing
	sc.setNode("fresh", "f1") // brand-new key
	sc.setNode("fresh", "f2") // overwritten twice — undo must restore absence, not f1
	inner := sc.markNode()
	sc.setNode("kept", "v2")
	sc.undoNode(inner)
	if sc.node["kept"] != "v1" {
		t.Fatalf("inner undo: kept = %q, want v1", sc.node["kept"])
	}
	delta, before := sc.nodeDelta(m)
	if e := delta["kept"]; !e.present || e.val != "v1" {
		t.Fatalf("delta[kept] = %+v, want present v1", e)
	}
	if e := delta["fresh"]; !e.present || e.val != "f2" {
		t.Fatalf("delta[fresh] = %+v, want present f2", e)
	}
	if before["kept"] != "v0" {
		t.Fatalf("before[kept] = %q, want v0", before["kept"])
	}
	if _, ok := before["fresh"]; ok {
		t.Fatal("fresh had no pre-branch value; before must not invent one")
	}
	sc.undoNode(m)
	sc.branchDepth--
	if sc.node["kept"] != "v0" {
		t.Fatalf("outer undo: kept = %q, want v0", sc.node["kept"])
	}
	if _, ok := sc.node["fresh"]; ok {
		t.Fatal("outer undo must remove the branch-created key entirely")
	}
	if len(sc.jn) != 0 {
		t.Fatalf("journal not truncated: %d entries", len(sc.jn))
	}
}

// Writes outside any branch are permanent and unjournaled — straight-line code, the
// overwhelmingly common case, must pay nothing for the journal's existence.
func TestScopeJournalIsFreeOutsideBranches(t *testing.T) {
	sc := newScope()
	for i := range 100 {
		sc.setNode("v", strconv.Itoa(i))
	}
	if len(sc.jn) != 0 {
		t.Fatalf("depth-0 writes were journaled: %d entries", len(sc.jn))
	}
	if sc.node["v"] != "99" {
		t.Fatalf("v = %q, want 99", sc.node["v"])
	}
}

// A clone must not inherit the parent's journal: its writes are nobody else's to undo,
// and undoing the parent must not disturb the clone.
func TestScopeCloneDropsTheJournal(t *testing.T) {
	sc := newScope()
	sc.branchDepth++
	m := sc.markNode()
	sc.setNode("x", "branch")
	inner := sc.clone()
	if inner.branchDepth != 0 || len(inner.jn) != 0 {
		t.Fatalf("clone inherited journal state: depth=%d entries=%d", inner.branchDepth, len(inner.jn))
	}
	inner.setNode("x", "inner") // depth 0 on the clone: permanent there
	sc.undoNode(m)
	if sc.node["x"] != "" {
		t.Fatalf("parent undo: x = %q, want unset", sc.node["x"])
	}
	if inner.node["x"] != "inner" {
		t.Fatalf("clone disturbed by parent undo: x = %q", inner.node["x"])
	}
}

// A function frame restores all four maps, unlike a branch which restores only node: a
// nested function's params, types and constants must not leak into its parent.
func TestScopeFuncFrameRestoresEveryMap(t *testing.T) {
	sc := newScope()
	sc.setNode("v", "outer")
	sc.setCnst("v", "OUTER")
	sc.setTyp("v", [2]string{"m", "Outer"})
	sc.setLex("v", true)
	sc.iter["v"] = []string{"a"}
	outerIter := sc.iter

	fm := sc.markFunc()
	if sc.iter["v"][0] != "a" {
		t.Fatal("frame must start from the enclosing iteration facts")
	}
	sc.setNode("v", "inner")
	sc.setCnst("v", "INNER")
	sc.setTyp("v", [2]string{"m", "Inner"})
	sc.setLex("w", true)
	sc.delCnst("gone")
	sc.iter["v"] = []string{"b"}
	sc.undoFunc(fm)

	if got := sc.node["v"]; got != "outer" {
		t.Errorf("node = %q, want outer", got)
	}
	if got := sc.cnst["v"]; got != "OUTER" {
		t.Errorf("cnst = %q, want OUTER", got)
	}
	if got := sc.typ["v"]; got != [2]string{"m", "Outer"} {
		t.Errorf("typ = %v, want {m Outer}", got)
	}
	if _, ok := sc.lex["w"]; ok {
		t.Error("a lexical flag set inside the frame leaked out")
	}
	if len(sc.iter["v"]) != 1 || sc.iter["v"][0] != "a" {
		t.Errorf("iter = %v, want [a]", sc.iter["v"])
	}
	// Not just equal contents — the SAME map object, so a later write through the
	// enclosing reference is visible on the scope.
	outerIter["probe"] = []string{"seen"}
	if got := sc.iter["probe"]; len(got) != 1 || got[0] != "seen" {
		t.Errorf("frame restored a different map object: probe = %v", got)
	}
	if sc.funcDepth != 0 || len(sc.jc) != 0 || len(sc.jt) != 0 || len(sc.jl) != 0 {
		t.Errorf("journals not unwound: depth=%d c=%d t=%d l=%d",
			sc.funcDepth, len(sc.jc), len(sc.jt), len(sc.jl))
	}
}

// A BRANCH must NOT restore cnst/typ/lex — a constant learned in one arm stays visible to
// the next, which is the behaviour the pre-journal code had and findings depend on.
func TestScopeBranchDoesNotRestoreConstants(t *testing.T) {
	sc := newScope()
	sc.branchDepth++
	m := sc.markNode()
	sc.setNode("v", "branch")
	sc.setCnst("v", "LEARNED")
	sc.undoNode(m)
	sc.branchDepth--

	if _, ok := sc.node["v"]; ok {
		t.Error("branch undo must restore node")
	}
	if got := sc.cnst["v"]; got != "LEARNED" {
		t.Errorf("cnst = %q — a branch must NOT restore constants", got)
	}
}

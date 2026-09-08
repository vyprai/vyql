package lowering

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

func TestLowerCallLowersCallCalleeInnerCall(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.js",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "handler", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					// f(x)(y): the callee is itself a call, the curried and
					// immediate-invocation form. The inner call and its
					// argument must be lowered, not only the outer call.
					Callee: nir.Call{
						Callee: nir.Name{ID: "compile", Loc: "app.js:2"},
						Args:   []nir.Expr{nir.Name{ID: "payload", Loc: "app.js:2"}},
						Path:   "compile", Loc: "app.js:2",
					},
					Path: "compile", Loc: "app.js:2",
				}},
			}, Loc: "app.js:1"},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "compile" {
			continue
		}
		if n.Prop("arg0") == "" {
			t.Fatalf("callee-position call missing its arg slot: %+v", n.Props)
		}
		return
	}
	t.Fatalf("call in callee position not lowered: no code.Call with callee_path compile")
}

// An immediately-invoked function expression is the module wrapper of browser
// JavaScript: `Namespace.module = (function () { ... }())`. The callee slot
// holds the function expression itself -- directly in the `(function () {
// ... }())` spelling and behind a parenthesized-expression chain in
// `(function () { ... })()` -- and the body it names is real program text with
// its own scope. Both spellings must lower that body.
func TestLowerCallLowersImmediatelyInvokedFunctionBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		callee nir.Expr
	}{
		{"direct", nir.Lambda{
			Body:          []nir.Stmt{callStmt("sink.render", "app.js:3")},
			ContextTokens: []string{"lang=javascript\x00name=<lambda>"},
			Loc:           "app.js:2",
		}},
		{"parenthesized", nir.Thru{Inner: nir.Lambda{
			Body:          []nir.Stmt{callStmt("sink.render", "app.js:3")},
			ContextTokens: []string{"lang=javascript\x00name=<lambda>"},
			Loc:           "app.js:2",
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prog := nir.Program{Modules: []nir.Module{{
				Key:  "app",
				File: "app.js",
				Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "Namespace", Loc: "app.js:1"}, Attr: "module", Path: "Namespace.module", Loc: "app.js:1"},
						Args:   []nir.Expr{nir.Call{Callee: tc.callee, Args: []nir.Expr{nir.Name{ID: "jQuery", Loc: "app.js:4"}}, Path: "?", Loc: "app.js:1"}},
						Path:   "Namespace.module", Loc: "app.js:1",
					}},
				},
			}}}
			g, err := Lower(prog, true)
			if err != nil {
				t.Fatalf("lower: %v", err)
			}
			foundCall, foundContext := false, false
			ids, _ := g.NodesOfType("code.Call")
			for _, id := range ids {
				n, _, _ := g.GetNode(id)
				switch n.Prop("callee_path") {
				case "sink.render":
					foundCall = true
				case "analysis.function.context":
					foundContext = true
				}
			}
			if !foundCall {
				t.Fatalf("call inside the invoked function body was not lowered")
			}
			if !foundContext {
				t.Fatalf("invoked function body produced no analysis.function.context")
			}
		})
	}
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
	sc.setIter("v", []string{"b"})
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
	if sc.funcDepth != 0 || len(sc.jc) != 0 || len(sc.jt) != 0 || len(sc.jl) != 0 || len(sc.ji) != 0 {
		t.Errorf("journals not unwound: depth=%d c=%d t=%d l=%d i=%d",
			sc.funcDepth, len(sc.jc), len(sc.jt), len(sc.jl), len(sc.ji))
	}
}

func TestIterationJournalMergesOnlyStableBranchFacts(t *testing.T) {
	sc := newScope()
	sc.iter["kept"] = []string{"same"}
	sc.iter["changed"] = []string{"before"}
	sc.iter["deleted"] = []string{"before"}

	mark := len(sc.ji)
	sc.branchDepth++
	sc.setIter("created", []string{"both"})
	sc.setIter("changed", []string{"then"})
	sc.delIter("deleted")
	thenDelta := sc.iterDelta(mark)
	sc.undoIter(mark)

	sc.setIter("created", []string{"both"})
	sc.setIter("changed", []string{"else"})
	sc.delIter("deleted")
	elseDelta := sc.iterDelta(mark)
	sc.undoIter(mark)
	sc.branchDepth--
	sc.mergeIterationDeltas(thenDelta, elseDelta)

	if got := sc.iter["kept"]; !slices.Equal(got, []string{"same"}) {
		t.Errorf("untouched fact = %v, want [same]", got)
	}
	if got := sc.iter["created"]; !slices.Equal(got, []string{"both"}) {
		t.Errorf("fact created equally in both arms = %v, want [both]", got)
	}
	if _, ok := sc.iter["changed"]; ok {
		t.Error("fact changed differently in the arms survived")
	}
	if _, ok := sc.iter["deleted"]; ok {
		t.Error("fact deleted in both arms survived")
	}
	if len(sc.ji) != 0 {
		t.Fatalf("journal not empty after merge: %d entries", len(sc.ji))
	}
}

func BenchmarkIterationFactBranchJournal(b *testing.B) {
	sc := newScope()
	for i := range 4096 {
		sc.iter[strconv.Itoa(i)] = []string{"value"}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		mark := len(sc.ji)
		sc.branchDepth++
		sc.setIter("changed", []string{"branch"})
		delta := sc.iterDelta(mark)
		sc.undoIter(mark)
		sc.branchDepth--
		sc.mergeIterationDeltas(nil, delta)
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

// A Java inner class's method reads the ENCLOSING instance's field (Druid's
// BasicHTTPAuthenticationFilter reading BasicHTTPAuthenticator.credentialsValidator).
// The field's declared type is what names the callee; without it the call falls back to
// keying on the callee name alone, which goes silent as soon as a second declaration of
// that name exists — here the interface and the sibling implementation.
func TestNestedClassMethodResolvesEnclosingClassFieldReceiver(t *testing.T) {
	validatorMethod := func(cls string, body []nir.Stmt) nir.Stmt {
		return nir.ClassDef{Name: cls, Body: []nir.Stmt{
			nir.FuncDef{Name: "validateCredentials", Params: []string{"username"}, Body: body, Loc: cls + ".java:2"},
		}, Loc: cls + ".java:1"}
	}
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "validator",
			File: "LDAPCredentialsValidator.java",
			Body: []nir.Stmt{
				// the interface and the sibling implementation: three declarations of the
				// name in all, so name-only resolution has nothing unambiguous to pick.
				validatorMethod("CredentialsValidator", nil),
				validatorMethod("MetadataStoreCredentialsValidator", nil),
				validatorMethod("LDAPCredentialsValidator", []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "search", Loc: "LDAPCredentialsValidator.java:3"},
						Args:   []nir.Expr{nir.Name{ID: "username", Loc: "LDAPCredentialsValidator.java:3"}},
						Path:   "search", Method: "search", Loc: "LDAPCredentialsValidator.java:3",
					}},
				}),
			},
		},
		{
			Key:  "auth",
			File: "BasicHTTPAuthenticator.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "BasicHTTPAuthenticator", Body: []nir.Stmt{
					nir.Assign{Targets: []string{"credentialsValidator"}, Value: nir.Const{Loc: "BasicHTTPAuthenticator.java:2"},
						Type: "LDAPCredentialsValidator", Decl: true, Loc: "BasicHTTPAuthenticator.java:2"},
					nir.ClassDef{Name: "BasicHTTPAuthenticationFilter", Body: []nir.Stmt{
						nir.FuncDef{Name: "doFilter", Params: []string{"user"}, Body: []nir.Stmt{
							nir.ExprStmt{Value: nir.Call{
								Callee: nir.Attr{Base: nir.Name{ID: "credentialsValidator", Loc: "BasicHTTPAuthenticator.java:5"},
									Attr: "validateCredentials", Path: "credentialsValidator.validateCredentials", Loc: "BasicHTTPAuthenticator.java:5"},
								Args: []nir.Expr{nir.Name{ID: "user", Loc: "BasicHTTPAuthenticator.java:5"}},
								Path: "credentialsValidator.validateCredentials", Method: "validateCredentials", Loc: "BasicHTTPAuthenticator.java:5",
							}},
						}, Loc: "BasicHTTPAuthenticator.java:4"},
					}, Loc: "BasicHTTPAuthenticator.java:3"},
				}, Loc: "BasicHTTPAuthenticator.java:1"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "user")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "LDAPCredentialsValidator.java:3")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("doFilter's argument did not reach LDAPCredentialsValidator.validateCredentials' body: " +
			"the enclosing class's field receiver was not typed")
	}
}

// The enclosing-class seeding is Java's rule, not every language's: a nested class in
// Python (or JS, or C#) does not see the enclosing class's fields, so the same shape in a
// .py module must leave the receiver untyped rather than borrow the outer class's field.
func TestNestedClassDoesNotBorrowEnclosingFieldReceiverOutsideJava(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "validator",
			File: "validator.py",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "LdapValidator", Body: []nir.Stmt{
					nir.FuncDef{Name: "validate", Params: []string{"username"}, Loc: "validator.py:2"},
				}, Loc: "validator.py:1"},
			},
		},
		{
			Key:  "auth",
			File: "auth.py",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "Authenticator", Body: []nir.Stmt{
					nir.Assign{Targets: []string{"validator"}, Value: nir.Const{Loc: "auth.py:2"},
						Type: "LdapValidator", Decl: true, Loc: "auth.py:2"},
					nir.ClassDef{Name: "Filter", Body: []nir.Stmt{
						nir.FuncDef{Name: "handle", Params: []string{"user"}, Body: []nir.Stmt{
							nir.ExprStmt{Value: nir.Call{
								Callee: nir.Attr{Base: nir.Name{ID: "validator", Loc: "auth.py:5"},
									Attr: "validate", Path: "validator.validate", Loc: "auth.py:5"},
								Args: []nir.Expr{nir.Name{ID: "user", Loc: "auth.py:5"}},
								Path: "validator.validate", Method: "validate", Loc: "auth.py:5",
							}},
						}, Loc: "auth.py:4"},
					}, Loc: "auth.py:3"},
				}, Loc: "auth.py:1"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	call := findNodeID(t, g, "code.Call", "loc", "auth.py:5")
	n, _, err := g.GetNode(call)
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Prop("recv_type"); got != "" {
		t.Fatalf("recv_type = %q, want empty: a Python nested class does not see the enclosing class's fields", got)
	}
}

// A Java class that declares the same method name at two arities (Goobi viewer's
// DataFileTools.getDataFilePath, four parameters beside an unrelated two-parameter
// sibling). The call site names the four-parameter one by passing four arguments, so
// that is the body its arguments have to reach.
func TestOverloadedMethodResolvesByCallSiteArgumentCount(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "tools",
			File: "DataFileTools.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "DataFileTools", Body: []nir.Stmt{
					nir.FuncDef{Name: "getDataFilePath", Params: []string{"pi", "dataFolderName", "altDataFolderName", "fileName"},
						Body: []nir.Stmt{
							nir.ExprStmt{Value: nir.Call{
								Callee: nir.Name{ID: "resolve", Loc: "DataFileTools.java:5"},
								Args:   []nir.Expr{nir.Name{ID: "fileName", Loc: "DataFileTools.java:5"}},
								Path:   "resolve", Method: "resolve", Loc: "DataFileTools.java:5",
							}},
						}, Loc: "DataFileTools.java:4"},
					// the sibling overload, declared last so it is the one a name-keyed
					// table keeps, and never called from this program.
					nir.FuncDef{Name: "getDataFilePath", Params: []string{"pi", "relativeFilePath"},
						Body: []nir.Stmt{
							nir.ExprStmt{Value: nir.Call{
								Callee: nir.Name{ID: "resolve", Loc: "DataFileTools.java:9"},
								Args:   []nir.Expr{nir.Name{ID: "relativeFilePath", Loc: "DataFileTools.java:9"}},
								Path:   "resolve", Method: "resolve", Loc: "DataFileTools.java:9",
							}},
						}, Loc: "DataFileTools.java:8"},
				}, Loc: "DataFileTools.java:1"},
			},
		},
		{
			Key:  "servlet",
			File: "FileServlet.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "FileServlet", Body: []nir.Stmt{
					nir.FuncDef{Name: "getFile", Params: []string{"pi", "fileName"}, Body: []nir.Stmt{
						nir.ExprStmt{Value: nir.Call{
							Callee: nir.Attr{Base: nir.Name{ID: "DataFileTools", Loc: "FileServlet.java:5"},
								Attr: "getDataFilePath", Path: "DataFileTools.getDataFilePath", Loc: "FileServlet.java:5"},
							Args: []nir.Expr{
								nir.Name{ID: "pi", Loc: "FileServlet.java:5"},
								nir.Const{Loc: "FileServlet.java:5"},
								nir.Const{Loc: "FileServlet.java:5"},
								nir.Name{ID: "fileName", Loc: "FileServlet.java:5"},
							},
							Path: "DataFileTools.getDataFilePath", Method: "getDataFilePath", Loc: "FileServlet.java:5",
						}},
					}, Loc: "FileServlet.java:4"},
				}, Loc: "FileServlet.java:1"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "fileName", "func", "getFile")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "DataFileTools.java:5")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("getFile's fourth argument did not reach the four-parameter getDataFilePath body: " +
			"the call resolved to the sibling overload instead of the one its argument count names")
	}
}

// Two declarations at the SAME arity are told apart by parameter types, which call
// resolution does not carry, so the call site's argument count decides nothing between
// them. The call must keep the target it resolved to before rather than pick whichever
// same-arity declaration comes first.
func TestSameArityOverloadsAreNotDisambiguatedByArgumentCount(t *testing.T) {
	method := func(params []string, line string) nir.Stmt {
		return nir.FuncDef{Name: "write", Params: params, Body: []nir.Stmt{
			nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "emit", Loc: "Writer.java:" + line},
				Args:   []nir.Expr{nir.Name{ID: params[len(params)-1], Loc: "Writer.java:" + line}},
				Path:   "emit", Method: "emit", Loc: "Writer.java:" + line,
			}},
		}, Loc: "Writer.java:" + line}
	}
	prog := nir.Program{Modules: []nir.Module{
		{
			Key:  "writer",
			File: "Writer.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "Writer", Body: []nir.Stmt{
					method([]string{"text", "flush"}, "9"),
					method([]string{"bytes", "offset"}, "13"),
					// declared last, so this is the one the name-keyed table holds and the
					// one the two-argument call site does NOT match.
					method([]string{"a", "b", "c"}, "17"),
				}, Loc: "Writer.java:1"},
			},
		},
		{
			Key:  "caller",
			File: "Caller.java",
			Body: []nir.Stmt{
				nir.ClassDef{Name: "Caller", Body: []nir.Stmt{
					nir.FuncDef{Name: "run", Params: []string{"payload"}, Body: []nir.Stmt{
						nir.ExprStmt{Value: nir.Call{
							Callee: nir.Attr{Base: nir.Name{ID: "Writer", Loc: "Caller.java:5"},
								Attr: "write", Path: "Writer.write", Loc: "Caller.java:5"},
							Args: []nir.Expr{nir.Const{Loc: "Caller.java:5"}, nir.Name{ID: "payload", Loc: "Caller.java:5"}},
							Path: "Writer.write", Method: "write", Loc: "Caller.java:5",
						}},
					}, Loc: "Caller.java:4"},
				}, Loc: "Caller.java:1"},
			},
		},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	for _, loc := range []string{"Writer.java:9", "Writer.java:13"} {
		if reachable[findNodeID(t, g, "code.Arg", "loc", loc)] {
			t.Errorf("the argument count picked %s out of two same-arity declarations; it cannot tell them apart", loc)
		}
	}
}

// The Jenkins two-class shape: an extension class whose behaviour lives in its own
// methods, registered under a name by a nested Descriptor carrying @Symbol/@Extension.
// The enclosing class's context must carry the nested class's annotations, or the
// registration and the behaviour it registers sit on two events no binding can join.
// The nested class's MEMBER evidence still stays its own.
func TestLowerClassContextCarriesNestedClassAnnotations(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "VaultBuildWrapper.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "VaultBuildWrapper", Loc: "VaultBuildWrapper.java:1", Bases: []string{"SimpleBuildWrapper"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "provideEnvironmentVariablesFromVault", Loc: "VaultBuildWrapper.java:2", ContextTokens: []string{
					"class_name:VaultBuildWrapper",
					"function_name:provideEnvironmentVariablesFromVault",
					"call_path:valuesToMask.add",
					"call_path:context.env",
				}},
				nir.ClassDef{Name: "DescriptorImpl", Loc: "VaultBuildWrapper.java:9",
					Bases:       []string{"BuildWrapperDescriptor"},
					Annotations: []string{"Extension", "Symbol"},
					Body: []nir.Stmt{
						nir.FuncDef{Name: "isApplicable", Loc: "VaultBuildWrapper.java:11", ContextTokens: []string{
							"class_name:DescriptorImpl",
							"function_name:isApplicable",
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
	var sawOuter bool
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.class.context" {
			continue
		}
		args := n.Prop("str_args")
		if !strings.Contains(args, "class_name:VaultBuildWrapper") {
			continue
		}
		sawOuter = true
		for _, want := range []string{
			"nested_class_annotation:Extension",
			"nested_class_annotation:Symbol",
			"call_path:context.env",
		} {
			if !strings.Contains(args, want) {
				t.Errorf("enclosing class context is missing %q: %q", want, args)
			}
		}
		// the nested class's own members remain its own evidence
		if strings.Contains(args, "function_name:isApplicable") {
			t.Errorf("enclosing class context absorbed the nested class's members: %q", args)
		}
	}
	if !sawOuter {
		t.Fatal("no class-context event for the enclosing class")
	}
}

// Deleting the registration annotation from the nested class is exactly what the
// hashicorp-vault-plugin fix does, so the token must disappear with it.
func TestLowerClassContextNestedAnnotationsAreTheNestedClassesOwn(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "VaultBuildWrapper.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "VaultBuildWrapper", Loc: "VaultBuildWrapper.java:1", Annotations: []string{"Deprecated"}, Body: []nir.Stmt{
				nir.ClassDef{Name: "DescriptorImpl", Loc: "VaultBuildWrapper.java:9", Annotations: []string{"Extension"}},
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
		if strings.Contains(args, "class_name:VaultBuildWrapper") {
			if strings.Contains(args, "nested_class_annotation:Symbol") {
				t.Errorf("annotation the nested class does not carry reached the enclosing class: %q", args)
			}
			// the enclosing class's OWN annotation is not a nested one
			if strings.Contains(args, "nested_class_annotation:Deprecated") {
				t.Errorf("enclosing class reported its own annotation as nested: %q", args)
			}
		}
		if strings.Contains(args, "class_name:DescriptorImpl") && strings.Contains(args, "nested_class_annotation:") {
			t.Errorf("leaf class reported a nested annotation: %q", args)
		}
	}
}

// A method call whose receiver is a call result of UNKNOWN type resolves to nothing: the
// unique-method-name fallback a receiver held in a local reaches is not extended to it. The
// receiver of `ESAPI.encoder().encodeForHTML(x)` is a library value, and routing that call
// into the project's own same-named helper would run a body the program never runs — the
// call stays unresolved and keeps its conservative argument-to-result edge instead.
func TestUntypedCallResultReceiverDoesNotBorrowASameNamedHelper(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "app.py",
		File: "app.py",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "encodeForHTML", Loc: "app.py:1", Params: []string{"value"}, Body: []nir.Stmt{
				nir.Return{Value: nir.Const{Loc: "app.py:2", Value: "safe"}},
			}},
			nir.FuncDef{Name: "entry", Loc: "app.py:5", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"bar"}, Decl: true, Loc: "app.py:6", Value: nir.Call{
					Callee: nir.Attr{Base: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "ESAPI", Loc: "app.py:6"}, Attr: "encoder", Path: "ESAPI.encoder", Loc: "app.py:6"},
						Path:   "ESAPI.encoder", Method: "encoder", Loc: "app.py:6",
					}, Attr: "encodeForHTML", Path: "ESAPI.encoder.encodeForHTML", Loc: "app.py:6"},
					Args: []nir.Expr{nir.Name{ID: "payload", Loc: "app.py:6"}},
					Path: "ESAPI.encoder.encodeForHTML", Method: "encodeForHTML", Loc: "app.py:6",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.py:7"},
					Args:   []nir.Expr{nir.Name{ID: "bar", Loc: "app.py:7"}},
					Path:   "sink", Method: "sink", Loc: "app.py:7",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	helperParam := findNodeID(t, g, "code.Param", "func", "encodeForHTML", "name", "value")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.py:7")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[helperParam] {
		t.Fatalf("an untyped call-result receiver resolved to a same-named project helper")
	}
	if !reachable[sinkArg] {
		t.Fatalf("the unresolved call lost its conservative argument-to-result edge")
	}
}

// The service-registry indirection, with every name it dispatches on ambiguous: the entry
// point carries the same short name as the method it calls, so the unique-method-name
// fallback is starved and only the receiver TYPES can carry the dispatch — the interface a
// call's declared result type names, and the implementation registered under the receiver
// type its declaration names.
func TestCallResultReceiverDispatchesOnDeclaredResultType(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.go",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Runner", Loc: "app.go:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "Run", Loc: "app.go:2", Params: []string{"value"}},
			}},
			nir.ClassDef{Name: "runnerImpl", Loc: "app.go:4", Bases: []string{"Runner"}},
			nir.FuncDef{Name: "Run", Recv: "runnerImpl", Loc: "app.go:6", Params: []string{"value"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.go:7"},
					Args:   []nir.Expr{nir.Name{ID: "value", Loc: "app.go:7"}},
					Path:   "sink", Method: "sink", Loc: "app.go:7",
				}},
			}},
			nir.ClassDef{Name: "Registry", Loc: "app.go:10", Body: []nir.Stmt{
				nir.FuncDef{Name: "Runner", Loc: "app.go:11", Returns: "Runner"},
			}},
			nir.ClassDef{Name: "store", Loc: "app.go:13", Bases: []string{"Registry"}},
			nir.FuncDef{Name: "Runner", Recv: "store", Returns: "Runner", Loc: "app.go:15", Body: []nir.Stmt{
				nir.Return{Value: nir.Const{Loc: "app.go:15", Value: "impl"}},
			}},
			nir.Assign{Targets: []string{"MyRegistry"}, Type: "Registry", Decl: true,
				Value: nir.Const{Loc: "app.go:18"}, Loc: "app.go:18"},
			nir.FuncDef{Name: "Run", Loc: "app.go:20", Params: []string{"payload"}, Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "MyRegistry", Loc: "app.go:21"}, Attr: "Runner", Path: "MyRegistry.Runner", Loc: "app.go:21"},
						Path:   "MyRegistry.Runner", Method: "Runner", Loc: "app.go:21",
					}, Attr: "Run", Path: "MyRegistry.Runner.Run", Loc: "app.go:21"},
					Args: []nir.Expr{nir.Name{ID: "payload", Loc: "app.go:21"}},
					Path: "MyRegistry.Runner.Run", Method: "Run", Loc: "app.go:21",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "name", "payload")
	implParam := findNodeID(t, g, "code.Param", "func", "Run", "name", "value", "loc", "app.go:6")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "app.go:7")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[implParam] {
		t.Fatalf("payload did not reach the implementation method the call result's declared type dispatches to")
	}
	if !reachable[sinkArg] {
		t.Fatalf("payload did not reach the sink arg inside the implementation body")
	}
}

// exitNodes returns the conditional-exit markers in a lowered graph.
func exitNodes(t *testing.T, g usg.Store) []usg.Node {
	t.Helper()
	ids, _ := g.NodesOfType(usg.ExitNodeType)
	var out []usg.Node
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		out = append(out, n)
	}
	return out
}

// A `return` inside a branch ends the function without reaching what follows the branch.
// The lowering marks it, because region and order alone cannot say so — and a release
// written after the branch was read as covering the path the return takes.
func TestLowerEarlyReturnLeavesTrailingReleaseUncovered(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.If{Then: []nir.Stmt{nir.Return{}}, Loc: "app.go:3"},
		callStmt("res.Release", "app.go:5"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "res.Acquire")
	release := callNodeByPath(t, g, "res.Release")

	exits := exitNodes(t, g)
	if len(exits) != 1 {
		t.Fatalf("want one exit marker for the return inside the branch, got %d", len(exits))
	}
	if r := exits[0].Prop("region"); !strings.HasPrefix(r, acquire.Prop("region")+"/") {
		t.Errorf("exit marker region = %q, want one nested under the body's %q", r, acquire.Prop("region"))
	}
	if o := nodeOrder(t, exits[0]); o <= nodeOrder(t, acquire) || o >= nodeOrder(t, release) {
		t.Errorf("exit marker order %d must fall between the acquisition and the release", o)
	}

	if !solvers.PostDominates(g, release.ID, acquire.ID) {
		t.Fatal("the structural relation still holds: the release follows in the enclosing region")
	}
	if solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{release.ID}, acquire.ID) {
		t.Error("the branch returns before the release, so it does not run on every path")
	}
}

// A release inside the branch that returns covers the path that branch takes, and the
// trailing one covers the path that falls through it.
func TestLowerEarlyReturnCoveredByReleaseInTheBranch(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.If{Then: []nir.Stmt{
			callStmt("res.ReleaseEarly", "app.go:4"),
			nir.Return{},
		}, Loc: "app.go:3"},
		callStmt("res.Release", "app.go:6"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "res.Acquire")
	releases := []string{
		callNodeByPath(t, g, "res.Release").ID,
		callNodeByPath(t, g, "res.ReleaseEarly").ID,
	}
	if !solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), releases, acquire.ID) {
		t.Error("every path out of the function runs a release")
	}
}

// A `return` written at the top level of the body ends the function where nothing
// follows it anyway, so it needs no marker.
func TestLowerTopLevelReturnNeedsNoExitMarker(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.Return{},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if n := len(exitNodes(t, g)); n != 0 {
		t.Errorf("want no exit marker for a top-level return, got %d", n)
	}
}

// A `return` inside a callback leaves the callback, not the function that passes it, so
// it must not be read as an exit of the enclosing function.
func TestLowerReturnInsideCallbackDoesNotSkipTheEnclosingRelease(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "list", Loc: "app.go:3"}, Attr: "each", Path: "list.each", Loc: "app.go:3"},
			Path:   "list.each", Method: "each", Loc: "app.go:3",
			Args: []nir.Expr{nir.Lambda{Body: []nir.Stmt{
				nir.If{Then: []nir.Stmt{nir.Return{}}, Loc: "app.go:4"},
			}, Loc: "app.go:3"}},
		}},
		callStmt("res.Release", "app.go:6"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "res.Acquire")
	release := callNodeByPath(t, g, "res.Release")
	if !solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{release.ID}, acquire.ID) {
		t.Error("a return inside a callback does not leave the enclosing function")
	}
}

// A callback opened inside a branch carries that branch in its region path, so the region
// of a `return` written in the callback does start with the enclosing function body's own
// region followed by "/". The callback marker "#" is what separates the callback's exits
// from the function's: read without it, the return leaves the enclosing function and the
// release written after the branch is reported as a resource the function abandons.
func TestLowerReturnInsideCallbackOpenedInABranchDoesNotSkipTheEnclosingRelease(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.If{Cond: nir.Name{ID: "ok", Loc: "app.go:3"}, Then: []nir.Stmt{
			nir.ExprStmt{Value: nir.Call{
				Callee: nir.Attr{Base: nir.Name{ID: "list", Loc: "app.go:4"}, Attr: "each", Path: "list.each", Loc: "app.go:4"},
				Path:   "list.each", Method: "each", Loc: "app.go:4",
				Args: []nir.Expr{nir.Lambda{Body: []nir.Stmt{
					nir.If{Cond: nir.Name{ID: "skip", Loc: "app.go:5"}, Then: []nir.Stmt{nir.Return{}}, Loc: "app.go:5"},
				}, Loc: "app.go:4"}},
			}},
		}, Loc: "app.go:3"},
		callStmt("res.Release", "app.go:8"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "res.Acquire")
	release := callNodeByPath(t, g, "res.Release")

	exits := exitNodes(t, g)
	if len(exits) != 1 {
		t.Fatalf("want one exit marker for the return inside the callback, got %d", len(exits))
	}
	// Both halves of the shape this test exists for: the region passes the plain prefix
	// test against the function body, and only the callback marker tells them apart.
	region, body := exits[0].Prop("region"), acquire.Prop("region")
	if !strings.HasPrefix(region, body+"/") {
		t.Fatalf("exit marker region = %q, want a callback opened inside a branch of the body's %q", region, body)
	}
	if !strings.Contains(region[len(body):], "#") {
		t.Fatalf("exit marker region = %q, want the callback marker under the body's %q", region, body)
	}

	if !solvers.PostDominates(g, release.ID, acquire.ID) {
		t.Fatal("the structural relation still holds: the release follows in the enclosing region")
	}
	if !solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{release.ID}, acquire.ID) {
		t.Error("a return inside a callback leaves the callback, so the release after the branch still runs")
	}
}

// A deferred release runs on every path out of the function, early returns included, so
// the lowering marks it as unwind cleanup and the exit markers do not unseat it.
func TestLowerDeferredReleaseCoversAnEarlyReturn(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("mu.Lock", "app.go:2"),
		deferStmt("mu.Unlock", "app.go:3"),
		nir.If{Then: []nir.Stmt{nir.Return{}}, Loc: "app.go:4"},
		callStmt("w.Work", "app.go:6"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	lock := callNodeByPath(t, g, "mu.Lock")
	unlock := callNodeByPath(t, g, "mu.Unlock")
	if unlock.Prop(usg.UnwindProp) == "" {
		t.Errorf("deferred call must carry %s", usg.UnwindProp)
	}
	if !solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{unlock.ID}, lock.ID) {
		t.Error("a deferred release runs on the early-return path too")
	}
}

// The same for a `finally`: it runs however the try statement is left.
func TestLowerFinallyReleaseCoversAnEarlyReturn(t *testing.T) {
	g, err := Lower(funcProgram("app.java",
		callStmt("lock.lock", "app.java:2"),
		nir.Try{
			Body:    []nir.Stmt{nir.If{Then: []nir.Stmt{nir.Return{}}, Loc: "app.java:4"}},
			Finally: []nir.Stmt{callStmt("lock.unlock", "app.java:7")},
			Loc:     "app.java:3",
		},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "lock.lock")
	release := callNodeByPath(t, g, "lock.unlock")
	if release.Prop(usg.UnwindProp) == "" {
		t.Errorf("a call in a finally body must carry %s", usg.UnwindProp)
	}
	if !solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{release.ID}, acquire.ID) {
		t.Error("a finally release runs on the path a return inside the try takes")
	}
}

// The shape the gap is about, lowered end to end: a handle is acquired, used, and released
// at the bottom of the function, and a branch in between returns without releasing it. The
// trailing release covers the path that falls through the branch and nothing covers the
// path the branch takes.
func TestLowerReturnAfterTheHandleIsUsedLeavesTheReleaseUncovered(t *testing.T) {
	use := func(path, loc string) nir.ExprStmt {
		base, method, _ := strings.Cut(path, ".")
		return nir.ExprStmt{Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: base, Loc: loc}, Attr: method, Path: path, Loc: loc},
			Args:   []nir.Expr{nir.Name{ID: "h", Loc: loc}},
			Path:   path, Method: method, Loc: loc,
		}}
	}
	g, err := Lower(funcProgram("app.c",
		nir.Assign{Targets: []string{"h"}, Decl: true, Loc: "app.c:2", Value: nir.Call{
			Callee: nir.Attr{Base: nir.Name{ID: "res", Loc: "app.c:2"}, Attr: "Acquire", Path: "res.Acquire", Loc: "app.c:2"},
			Path:   "res.Acquire", Method: "Acquire", Loc: "app.c:2",
		}},
		use("res.Work", "app.c:3"),
		nir.If{Then: []nir.Stmt{nir.Return{}}, Loc: "app.c:4"},
		use("res.Release", "app.c:6"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	acquire := callNodeByPath(t, g, "res.Acquire")
	release := callNodeByPath(t, g, "res.Release")

	if !solvers.PostDominates(g, release.ID, acquire.ID) {
		t.Fatal("the structural relation still holds: the release follows in the enclosing region")
	}
	if solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{release.ID}, acquire.ID) {
		t.Error("the branch returns with the handle in use and releases nothing")
	}
}

// A defer registered inside a NESTED function runs when that function returns, so the
// region it covers is the nested one — it must not cover the enclosing function.
func TestLowerDeferredReleaseInNestedFunctionCoversOnlyIt(t *testing.T) {
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
	if solvers.PostDominatesCovered(g, solvers.NewExitIndex(g), []string{unlock.ID}, lock.ID) {
		t.Error("a defer in a nested function must not cover the enclosing function")
	}
}

// A `raise` inside a try body resumes in the handler rather than leaving the function, so
// it must not be recorded as an exit — the release written after the try still runs.
func TestLowerThrowInsideTryIsNotAnExit(t *testing.T) {
	caught, err := Lower(funcProgram("app.py",
		callStmt("res.Acquire", "app.py:2"),
		nir.Try{
			Body:     []nir.Stmt{nir.Terminate{Kind: "raise", Loc: "app.py:4"}},
			Handlers: [][]nir.Stmt{{callStmt("log.Warn", "app.py:6")}},
			Loc:      "app.py:3",
		},
		callStmt("res.Release", "app.py:7"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if n := len(exitNodes(t, caught)); n != 0 {
		t.Errorf("a raise inside a try body is not a function exit, got %d marker(s)", n)
	}
	acquire := callNodeByPath(t, caught, "res.Acquire")
	release := callNodeByPath(t, caught, "res.Release")
	if !solvers.PostDominatesCovered(caught, solvers.NewExitIndex(caught), []string{release.ID}, acquire.ID) {
		t.Error("the release after the try still runs on every path")
	}

	// The same raise written in a branch, with nothing to catch it, does leave.
	uncaught, err := Lower(funcProgram("app.py",
		callStmt("res.Acquire", "app.py:2"),
		nir.If{Then: []nir.Stmt{nir.Terminate{Kind: "raise", Loc: "app.py:4"}}, Loc: "app.py:3"},
		callStmt("res.Release", "app.py:6"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if n := len(exitNodes(t, uncaught)); n != 1 {
		t.Fatalf("want one exit marker for the uncaught raise, got %d", n)
	}
	if solvers.PostDominatesCovered(uncaught, solvers.NewExitIndex(uncaught),
		[]string{callNodeByPath(t, uncaught, "res.Release").ID}, callNodeByPath(t, uncaught, "res.Acquire").ID) {
		t.Error("the branch raises before the release, so it does not run on every path")
	}
}

// An exit marker records the condition of the branch it sits in, because that is what says
// WHY the function leaves there: a branch on what an acquisition returned is the guard that
// checks whether the acquisition succeeded. The condition of an ENCLOSING branch is not
// that, so a region opened inside one carries no guard of its own.
func TestLowerExitMarkerCarriesTheConditionOfItsOwnBranch(t *testing.T) {
	cond := nir.Name{ID: "status", Loc: "app.go:3"}
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.If{Cond: cond, Then: []nir.Stmt{
			nir.If{Then: []nir.Stmt{callStmt("l.Log", "app.go:5")}, Loc: "app.go:4"},
			nir.Return{},
		}, Loc: "app.go:3"},
		nir.Loop{Body: []nir.Stmt{nir.Return{}}, Loc: "app.go:8"},
		callStmt("res.Release", "app.go:9"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	exits := exitNodes(t, g)
	if len(exits) != 2 {
		t.Fatalf("want two exit markers, got %d", len(exits))
	}
	sort.Slice(exits, func(i, j int) bool { return nodeOrder(t, exits[i]) < nodeOrder(t, exits[j]) })

	guard := exits[0].Prop(usg.ExitGuardProp)
	if guard == "" {
		t.Fatal("the return inside the branch carries no condition")
	}
	n, ok, _ := g.GetNode(guard)
	if !ok || n.Type != "code.Name" || n.Prop("callee_path") != "status" {
		t.Errorf("exit guard = %s (%s), want the node the branch condition evaluated to", guard, n.Type)
	}
	if got := exits[1].Prop(usg.ExitGuardProp); got != "" {
		t.Errorf("a return inside a loop body is not taken on any branch condition, got guard %q", got)
	}
}

// Every control region opened inside a branch starts a scope of its own, so it carries no
// condition from the branch that encloses it. A `return` written in a loop that sits inside
// an `if` arm is reached by iterating the loop, not because the `if` condition held, and its
// exit marker records no guard at all. The guard is what marks an exit as the acquisition's
// own failure check, and an exit wrongly marked that way hides a resource the function
// really does abandon.
func TestLowerExitMarkerInALoopInsideABranchCarriesNoCondition(t *testing.T) {
	g, err := Lower(funcProgram("app.go",
		callStmt("res.Acquire", "app.go:2"),
		nir.If{Cond: nir.Name{ID: "status", Loc: "app.go:3"}, Then: []nir.Stmt{
			nir.Loop{Body: []nir.Stmt{nir.Return{}}, Loc: "app.go:4"},
		}, Loc: "app.go:3"},
		callStmt("res.Release", "app.go:7"),
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	exits := exitNodes(t, g)
	if len(exits) != 1 {
		t.Fatalf("want one exit marker for the return inside the loop, got %d", len(exits))
	}
	// The shape this test exists for: the loop region is opened inside the branch arm, so
	// the enclosing condition is live at the point the loop body is lowered.
	if region := exits[0].Prop("region"); !strings.Contains(region, ".t/loop") {
		t.Fatalf("exit marker region = %q, want a loop opened inside an if arm", region)
	}
	if got := exits[0].Prop(usg.ExitGuardProp); got != "" {
		t.Errorf("exit marker guard = %q, want none: the loop body is not entered on the enclosing branch's condition", got)
	}
}

// The end-to-end shape: two sequential single-armed if-blocks, each releasing the
// same pointer. The lowering gives each its own control region, and those regions
// are siblings — but they are separate constructs, not the arms of one, so the
// first release reaches the second and the double-free pair exists to report.
func TestLowerSequentialGuardedBlocksReachEachOther(t *testing.T) {
	g, err := Lower(funcProgram("app.c",
		callStmt("p.alloc", "app.c:2"),
		nir.If{Then: []nir.Stmt{callStmt("p.free", "app.c:4")}, Loc: "app.c:3"},
		nir.If{Then: []nir.Stmt{callStmt("p.freeAgain", "app.c:7")}, Loc: "app.c:6"},
		nir.If{Then: []nir.Stmt{callStmt("p.use", "app.c:10")},
			Else: []nir.Stmt{callStmt("p.otherArm", "app.c:12")}, Loc: "app.c:9"},
	), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	first := callNodeByPath(t, g, "p.free")
	second := callNodeByPath(t, g, "p.freeAgain")
	use := callNodeByPath(t, g, "p.use")
	otherArm := callNodeByPath(t, g, "p.otherArm")

	if first.Prop("region") == second.Prop("region") {
		t.Fatalf("the two guarded blocks must lower to distinct regions, both are %q", first.Prop("region"))
	}
	if !solvers.Reaches(g, first.ID, second.ID) {
		t.Errorf("release in %q must reach the release in %q", first.Prop("region"), second.Prop("region"))
	}
	if !solvers.Reaches(g, first.ID, use.ID) {
		t.Errorf("release in %q must reach the use in %q", first.Prop("region"), use.Prop("region"))
	}
	if solvers.Reaches(g, use.ID, otherArm.ID) {
		t.Error("the then arm of one if must not reach its own else arm")
	}
	// The widening must not reach into dominance: a release inside a guarded block
	// still does not always run.
	if solvers.PostDominates(g, first.ID, callNodeByPath(t, g, "p.alloc").ID) {
		t.Error("a release inside a guarded block must not post-dominate the allocation")
	}
}

// A class static property is one location for the whole program, not one per file. The write
// and the read below are in different modules, so the slot only joins them if it is keyed on
// the property rather than on anything module-local.
func TestClassStaticPropertySlotIsSharedAcrossModules(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{
		{Key: "", File: "Model.php", Body: []nir.Stmt{
			nir.ClassDef{Name: "Model", Loc: "Model.php:2", Members: []string{"$held"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "keep", Loc: "Model.php:3", Params: []string{"v"}, Body: []nir.Stmt{
					nir.Assign{Targets: []string{"Model::$held"}, Value: nir.Name{ID: "v", Loc: "Model.php:4"}},
				}},
			}},
		}},
		{Key: "", File: "Engine.php", Body: []nir.Stmt{
			nir.ClassDef{Name: "Engine", Loc: "Engine.php:2", Body: []nir.Stmt{
				nir.FuncDef{Name: "emit", Loc: "Engine.php:3", Body: []nir.Stmt{
					// `self::$held` inside Engine: the property is declared on Model, and that is
					// the class whose slot both accesses have to land on.
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "Engine.php:4"},
						Args:   []nir.Expr{nir.Name{ID: "Engine::$held", Loc: "Engine.php:4"}},
						Path:   "sink", Method: "sink", Loc: "Engine.php:4",
					}},
				}},
			}},
		}},
	}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	param := findNodeID(t, g, "code.Param", "name", "v")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "Engine.php:4")
	reachable, err := usg.BFS(g, param, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sinkArg] {
		t.Fatalf("the static property write in Model.php does not reach the read in Engine.php")
	}
}

// fieldWriteStmt spells the member write `base.attr = v` the way the C#/JS/Kotlin/Java
// frontends do: a path call with no method, whose single argument is the assigned value.
func fieldWriteStmt(base nir.Expr, attr string, val nir.Expr, loc string) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: base, Attr: attr, Path: "this." + attr, Loc: loc},
		Args:   []nir.Expr{val},
		Path:   "this." + attr,
		Method: "",
		Loc:    loc,
	}}
}

// A setter parks a value on a field and a getter hands it back: the write and the read sit in
// two different method bodies, and only the receiver at the two call sites ties them together.
// The getter's body is lowered before either call site here (source order), so at the moment
// `this.v` is read no slot for `v` exists on the getter's `this` — the read has to be RECORDED,
// not merely looked up, or aliasing the receiver later has nothing to connect it to.
func TestStoredFieldReachesGetterAcrossCallBoundary(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "app.cs",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Holder", Members: []string{"v", "safe"}, Loc: "app.cs:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "getV", Loc: "app.cs:2", Body: []nir.Stmt{
					nir.Return{Value: nir.Attr{Base: nir.Name{ID: "this", Loc: "app.cs:2"}, Attr: "v", Path: "this.v", Loc: "app.cs:2"}},
				}},
				nir.FuncDef{Name: "getSafe", Loc: "app.cs:3", Body: []nir.Stmt{
					nir.Return{Value: nir.Attr{Base: nir.Name{ID: "this", Loc: "app.cs:3"}, Attr: "safe", Path: "this.safe", Loc: "app.cs:3"}},
				}},
				nir.FuncDef{Name: "setV", Params: []string{"x"}, Loc: "app.cs:4", Body: []nir.Stmt{
					fieldWriteStmt(nir.Name{ID: "this", Loc: "app.cs:4"}, "v", nir.Name{ID: "x", Loc: "app.cs:4"}, "app.cs:4"),
				}},
			}},
			nir.FuncDef{Name: "handler", Params: []string{"taint", "h"}, ParamTypes: map[string]string{"h": "Holder"}, Loc: "app.cs:5", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "app.cs:6"}, Attr: "setV", Path: "h.setV", Loc: "app.cs:6"},
					Args:   []nir.Expr{nir.Name{ID: "taint", Loc: "app.cs:6"}},
					Path:   "h.setV", Method: "setV", Loc: "app.cs:6",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "sink", Loc: "app.cs:7"}, Path: "sink", Method: "sink", Loc: "app.cs:7",
					Args: []nir.Expr{nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "app.cs:7"}, Attr: "getV", Path: "h.getV", Loc: "app.cs:7"},
						Path:   "h.getV", Method: "getV", Loc: "app.cs:7",
					}},
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "other", Loc: "app.cs:8"}, Path: "other", Method: "other", Loc: "app.cs:8",
					Args: []nir.Expr{nir.Call{
						Callee: nir.Attr{Base: nir.Name{ID: "h", Loc: "app.cs:8"}, Attr: "getSafe", Path: "h.getSafe", Loc: "app.cs:8"},
						Path:   "h.getSafe", Method: "getSafe", Loc: "app.cs:8",
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	source := findNodeID(t, g, "code.Param", "name", "taint")
	stored := findNodeID(t, g, "code.Arg", "loc", "app.cs:7")
	sibling := findNodeID(t, g, "code.Arg", "loc", "app.cs:8")
	reachable, err := usg.BFS(g, source, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[stored] {
		t.Fatalf("the value setV stored on the field did not reach the getV that reads it back")
	}
	if reachable[sibling] {
		t.Fatalf("taint on field v leaked into the sibling field safe")
	}
}

// The stable per-method `this` node used to be synthesized only for classes whose frontend
// declared their members — which only C# does — so in every other language each `this` spelling
// became a fresh node and a field written through one `this` was a different slot from the field
// read through the next. An explicitly spelled `this` needs no member list.
func TestThisQualifiedFieldConnectsWithoutDeclaredMembers(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "App.java",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Holder", Loc: "App.java:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "handle", Params: []string{"taint"}, Loc: "App.java:2", Body: []nir.Stmt{
					fieldWriteStmt(nir.Name{ID: "this", Loc: "App.java:3"}, "v", nir.Name{ID: "taint", Loc: "App.java:3"}, "App.java:3"),
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "sink", Loc: "App.java:4"}, Path: "sink", Method: "sink", Loc: "App.java:4",
						Args: []nir.Expr{nir.Attr{Base: nir.Name{ID: "this", Loc: "App.java:4"}, Attr: "v", Path: "this.v", Loc: "App.java:4"}},
					}},
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "other", Loc: "App.java:5"}, Path: "other", Method: "other", Loc: "App.java:5",
						Args: []nir.Expr{nir.Attr{Base: nir.Name{ID: "this", Loc: "App.java:5"}, Attr: "safe", Path: "this.safe", Loc: "App.java:5"}},
					}},
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	source := findNodeID(t, g, "code.Param", "name", "taint")
	stored := findNodeID(t, g, "code.Arg", "loc", "App.java:4")
	sibling := findNodeID(t, g, "code.Arg", "loc", "App.java:5")
	reachable, err := usg.BFS(g, source, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[stored] {
		t.Fatalf("a this-qualified field written and read in one method did not connect")
	}
	if reachable[sibling] {
		t.Fatalf("taint on this.v leaked into the sibling field this.safe")
	}
}

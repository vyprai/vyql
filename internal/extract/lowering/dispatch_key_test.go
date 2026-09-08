package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// presetDispatchProgram is the two-package shape a plugin framework has. One module registers a
// hook by exporting a function under the agreed name; another, which imports nothing from it,
// asks the registry for that name and hands the answer to a sink:
//
//	// common-preset.ts
//	export const env = async () => { const { raw } = getEnvironment(); return raw; };
//
//	// iframe-webpack.config.ts
//	function build(presets) {
//	  const envs = presets.apply('env');
//	  definePlugin(stringifyProcessEnvs(envs));
//	}
//
// method and hook name what the consumer calls on the registry and which key it asks for, so a
// test can vary either without restating the program.
func presetDispatchProgram(method, hook string) nir.Program {
	preset := nir.Module{
		Key:  "common-preset.ts",
		File: "common-preset.ts",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "env", Loc: "common-preset.ts:1", Exported: true, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"raw"}, Decl: true, Loc: "common-preset.ts:2", Value: nir.Call{
					Callee: nir.Name{ID: "getEnvironment", Loc: "common-preset.ts:2"},
					Path:   "lazy-universal-dotenv.getEnvironment", Method: "getEnvironment", Loc: "common-preset.ts:2",
				}},
				nir.Return{Value: nir.Name{ID: "raw", Loc: "common-preset.ts:3"}},
			}},
		},
	}
	consumer := nir.Module{
		Key:  "iframe-webpack.config.ts",
		File: "iframe-webpack.config.ts",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "build", Loc: "iframe-webpack.config.ts:1", Params: []string{"presets"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"envs"}, Decl: true, Loc: "iframe-webpack.config.ts:2", Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "presets", Loc: "iframe-webpack.config.ts:2"}, Attr: method,
						Path: "presets." + method, Loc: "iframe-webpack.config.ts:2"},
					Args: []nir.Expr{nir.Const{Value: "'" + hook + "'", Loc: "iframe-webpack.config.ts:2"}},
					Path: "presets." + method, Method: method, Loc: "iframe-webpack.config.ts:2",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "definePlugin", Loc: "iframe-webpack.config.ts:3"},
					Args: []nir.Expr{nir.Call{
						Callee: nir.Name{ID: "stringifyProcessEnvs", Loc: "iframe-webpack.config.ts:3"},
						Args:   []nir.Expr{nir.Name{ID: "envs", Loc: "iframe-webpack.config.ts:3"}},
						Path:   "stringifyProcessEnvs", Method: "stringifyProcessEnvs", Loc: "iframe-webpack.config.ts:3",
					}},
					Path: "definePlugin", Method: "definePlugin", Loc: "iframe-webpack.config.ts:3",
				}},
			}},
		},
	}
	return nir.Program{Modules: []nir.Module{preset, consumer}}
}

// dispatchReaches reports whether the value the registered hook produced reaches the consumer's
// sink argument.
func dispatchReaches(t *testing.T, prog nir.Program) bool {
	t.Helper()
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := callNodeByPath(t, g, "lazy-universal-dotenv.getEnvironment")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "iframe-webpack.config.ts:3")
	reachable, err := usg.BFS(g, src.ID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reachable[sinkArg]
}

// The value a plugin produced reaches a consumer that receives it only through the framework's
// string-keyed dispatch. Nothing in the consumer names the plugin -- no import, no callee -- so
// before this the two modules sat on separate flows and the path a run would take had no route
// in the graph.
func TestStringKeyDispatchCarriesTheHookResultToItsConsumer(t *testing.T) {
	if !dispatchReaches(t, presetDispatchProgram("apply", "env")) {
		t.Error("presets.apply('env') did not carry the registered hook's return to the consumer")
	}
}

// A key that names no declaration dispatches to nothing: `presets.apply('core')` in a program
// with no `core` leaves the call exactly as unresolved as it was.
func TestStringKeyDispatchNeedsTheKeyToNameADeclaration(t *testing.T) {
	if dispatchReaches(t, presetDispatchProgram("apply", "core")) {
		t.Error("a key naming no declaration still routed a body into the call")
	}
}

// A key that collides with two declarations does not name either of them, so the dispatch stays
// unresolved rather than betting the flow on one of them.
func TestStringKeyDispatchNeedsTheDeclarationToBeUnique(t *testing.T) {
	prog := presetDispatchProgram("apply", "env")
	prog.Modules = append(prog.Modules, nir.Module{
		Key: "vite-preset.ts", File: "vite-preset.ts",
		Body: []nir.Stmt{nir.FuncDef{Name: "env", Loc: "vite-preset.ts:1", Exported: true, Body: []nir.Stmt{
			nir.Return{Value: nir.Const{Value: "''", Loc: "vite-preset.ts:2"}},
		}}},
	})
	if dispatchReaches(t, prog) {
		t.Error("an ambiguous key still routed a body into the call")
	}
}

// The method has to be one dispatch is spelled with: an ordinary reader on some object that
// happens to take a string is not a plugin lookup.
func TestStringKeyDispatchNeedsADispatchMethod(t *testing.T) {
	if dispatchReaches(t, presetDispatchProgram("getOption", "env")) {
		t.Error("an ordinary string-taking method was read as a plugin dispatch")
	}
}

// What the dispatch is invoked WITH reaches the hook's parameters: the key is the lookup, the
// arguments after it are the call. `presets.apply('previewHead', config)` hands config to the
// registered previewHead(previous).
func TestStringKeyDispatchCarriesItsArgumentsIntoTheHook(t *testing.T) {
	prog := presetDispatchProgram("apply", "env")
	preset := prog.Modules[0].Body[0].(nir.FuncDef)
	preset.Params = []string{"previous"}
	prog.Modules[0].Body[0] = preset
	consumer := prog.Modules[1].Body[0].(nir.FuncDef)
	consumer.Params = []string{"presets", "config"}
	assign := consumer.Body[0].(nir.Assign)
	call := assign.Value.(nir.Call)
	call.Args = append(call.Args, nir.Name{ID: "config", Loc: "iframe-webpack.config.ts:2"})
	assign.Value = call
	consumer.Body[0] = assign
	prog.Modules[1].Body[0] = consumer

	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := findNodeID(t, g, "code.Param", "func", "build", "name", "config")
	hookParam := findNodeID(t, g, "code.Param", "func", "env", "name", "previous")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[hookParam] {
		t.Error("the argument after the key did not reach the registered hook's parameter")
	}
}

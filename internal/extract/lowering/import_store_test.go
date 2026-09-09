package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// contextStoreProgram is the two-function shape a request-scoped context store has. One function
// receives the context object from the framework and parks a parsed request value on it; another,
// which shares no call and no object with the first, reads that key back and hands it to a sink:
//
//	// middlewares/extract_query_params.ts
//	import { Context } from "hono";
//	export const handle = (c: Context) => { c.set("input", parse(query)); };
//
//	// routes/index.ts
//	import { Context } from "hono";
//	export const index = (c: Context) => { render(c.get("input")); };
//
// storeKey and readKey name which key each side touches, so one program can ask about a matching
// pair or a mismatched one. declaredType names the type both parameters are annotated with.
func contextStoreProgram(storeKey, readKey, declaredType string) nir.Program {
	honoImport := func() []nir.Import {
		if declaredType == "" {
			return nil
		}
		return []nir.Import{{Local: declaredType, Module: "hono", Symbol: declaredType}}
	}
	middleware := nir.Module{
		Key: "extract_query_params.ts", File: "extract_query_params.ts", Imports: honoImport(),
		Body: []nir.Stmt{nir.FuncDef{Name: "handle", Loc: "extract_query_params.ts:2", Exported: true,
			Params: []string{"c", "query"}, ParamTypes: map[string]string{"c": declaredType},
			Body: []nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Attr{Base: nir.Name{ID: "c", Loc: "extract_query_params.ts:3"}, Attr: "set",
					Path: "c.set", Loc: "extract_query_params.ts:3"},
				Args: []nir.Expr{
					nir.Const{Value: "\"" + storeKey + "\"", Loc: "extract_query_params.ts:3"},
					nir.Name{ID: "query", Loc: "extract_query_params.ts:3"},
				},
				Path: "c.set", Method: "set", Loc: "extract_query_params.ts:3",
			}}}}},
	}
	route := nir.Module{
		Key: "index.ts", File: "index.ts", Imports: honoImport(),
		Body: []nir.Stmt{nir.FuncDef{Name: "index", Loc: "index.ts:2", Exported: true,
			Params: []string{"c"}, ParamTypes: map[string]string{"c": declaredType},
			Body: []nir.Stmt{
				nir.Assign{Targets: []string{"input"}, Decl: true, Loc: "index.ts:3", Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "c", Loc: "index.ts:3"}, Attr: "get",
						Path: "c.get", Loc: "index.ts:3"},
					Args: []nir.Expr{nir.Const{Value: "\"" + readKey + "\"", Loc: "index.ts:3"}},
					Path: "c.get", Method: "get", Loc: "index.ts:3",
				}},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "render", Loc: "index.ts:4"},
					Args:   []nir.Expr{nir.Name{ID: "input", Loc: "index.ts:4"}},
					Path:   "render", Method: "render", Loc: "index.ts:4",
				}},
			}}},
	}
	return nir.Program{Modules: []nir.Module{middleware, route}}
}

// contextStoreReaches reports whether the value the middleware stored reaches the route's sink
// argument. The parameter is the source side: what the framework handed the middleware is the
// request, and everything downstream of the store flows from it.
func contextStoreReaches(t *testing.T, prog nir.Program) bool {
	t.Helper()
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	stored := findNodeID(t, g, "code.Param", "name", "query")
	sinkArg := findNodeID(t, g, "code.Arg", "loc", "index.ts:4")
	reachable, err := usg.BFS(g, stored, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reachable[sinkArg]
}

// A value one function stores on a request-scoped context object with a library setter reaches
// the sink another function feeds from the matching getter. The two share no call site and no
// object -- the framework, not the program, hands the same context to both -- so before this the
// value dead-ended at the setter and the read lowered against an unrelated parameter node.
func TestAContextStoreCarriesTaintBetweenFunctionsThatShareNoObject(t *testing.T) {
	if !contextStoreReaches(t, contextStoreProgram("input", "input", "Context")) {
		t.Error("c.set(\"input\", v) did not reach the c.get(\"input\") that reads it back")
	}
}

// The join is element-sensitive: only the key that was stored under is read back tainted, so a
// getter for a key this code never wrote stays clean. That is the property the whole program's
// stores share one namespace depends on -- a coarser join would light up every key.
func TestAContextStoreReadsOnlyTheKeyThatWasStored(t *testing.T) {
	if contextStoreReaches(t, contextStoreProgram("input", "imageId", "Context")) {
		t.Error("c.get(\"imageId\") read the taint stored under \"input\"")
	}
}

// The join keys on the type the two parameters are declared with, so a receiver with no
// declaration is not joined to anything: nothing names the library, and an untyped parameter is
// as likely to be a map the program built as a context the framework handed it.
func TestAContextStoreNeedsTheReceiverToBeDeclaredWithTheImportedType(t *testing.T) {
	if contextStoreReaches(t, contextStoreProgram("input", "input", "")) {
		t.Error("an undeclared receiver picked up the import-keyed store join")
	}
}

// A type the scan itself declares resolves to its own methods, which is the case the
// object-sensitive slots were built for; the import-keyed join is only for the library object
// whose body the scan cannot see. Keeping the two apart means a project class gains nothing here
// and loses nothing either.
func TestAContextStoreDoesNotJoinATypeTheProgramDeclares(t *testing.T) {
	prog := contextStoreProgram("input", "input", "Context")
	for i := range prog.Modules {
		prog.Modules[i].Imports = []nir.Import{{Local: "Context", Module: "app/context.ts", Symbol: "Context"}}
		prog.Modules[i].Body = append(prog.Modules[i].Body, nir.ClassDef{Name: "Context", Loc: prog.Modules[i].File + ":9"})
	}
	if contextStoreReaches(t, prog) {
		t.Error("a type declared by the program picked up the import-keyed store join")
	}
}

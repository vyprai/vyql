package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// A handler object wrapped in a TypeScript assertion — `export default {…} as T`,
// `export default ({…}) as T`, `const h = {…} satisfies T` — parses to an
// as_expression/satisfies_expression child, not an object child. The export and
// declarator paths used to test the child's kind against `object` without
// unwrapping the assertion first, so the handler's methods contributed no
// function, no call nodes and no flow, and no binding could reach what a handler
// reads.
func TestTypeScriptAssertedObjectMethodsAreLowered(t *testing.T) {
	cases := []struct {
		name   string
		ext    string
		method string
		call   string
		src    string
	}{
		{"export_default_as", "ts", "GET", "query", `
export default {
  GET(req) {
    db.query(req.url);
  },
  POST: async (req) => {
    exec(req.body);
  },
} as RouteHandlers;
`},
		{"export_default_parenthesized_as", "ts", "GET", "query", `
export default ({
  GET(req) {
    db.query(req.url);
  },
}) as RouteHandlers;
`},
		{"declarator_satisfies", "ts", "run", "exec", `
const handlers = {
  run(cmd) {
    exec(cmd);
  },
} satisfies HandlerMap;
`},
		{"export_default_as_tsx", "tsx", "GET", "query", `
export default {
  GET(req) {
    db.query(req.url);
  },
} as RouteHandlers;
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "route."+tc.ext)
			if err := os.WriteFile(path, []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}

			prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fn, ok := findFuncDef(prog, tc.method)
			if !ok {
				t.Fatalf("asserted object method %s was not extracted; program=%#v", tc.method, prog)
			}
			if !funcBodyHasCall(fn.Body, tc.call) {
				t.Fatalf("asserted object method %s body was not lowered; body=%#v", tc.method, fn.Body)
			}

			graph, err := lowering.Lower(prog, true)
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := graph.AllNodes()
			if err != nil {
				t.Fatal(err)
			}
			seen := false
			for _, n := range nodes {
				if n.Type == "code.Call" && strings.Contains(n.Prop("callee_path"), tc.call) {
					seen = true
				}
			}
			if !seen {
				t.Fatalf("call inside an asserted object method never reached the graph; nodes=%#v", nodes)
			}
		})
	}
}

// The pair-spelled arrow method of a default-exported asserted object is a
// function of its own, and a default export marks the object's methods exported.
func TestTypeScriptAssertedObjectPairMethodAndExportFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route.ts")
	src := []byte(`
export default {
  POST: async (req) => {
    exec(req.body);
  },
} as RouteHandlers;
`)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "POST")
	if !ok {
		t.Fatalf("asserted object pair method POST was not extracted; program=%#v", prog)
	}
	if !funcBodyHasCall(fn.Body, "exec") {
		t.Fatalf("asserted object pair method body was not lowered; body=%#v", fn.Body)
	}
	if !fn.Exported {
		t.Fatalf("default-exported asserted object method should be exported")
	}
}

// The `const h = {…} satisfies T` declarator still lowers the variable's
// assignment alongside the methods the unwrap now adds.
func TestTypeScriptAssertedDeclaratorKeepsAssignment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "handlers.ts")
	src := []byte(`
const handlers = {
  run(cmd) {
    exec(cmd);
  },
} satisfies HandlerMap;
`)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	assigned := false
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			if a, ok := st.(nir.Assign); ok && len(a.Targets) > 0 && a.Targets[0] == "handlers" {
				assigned = true
			}
		}
	}
	if !assigned {
		t.Fatalf("handlers assignment was not lowered; program=%#v", prog)
	}
	if _, ok := findFuncDef(prog, "run"); !ok {
		t.Fatalf("asserted declarator object method run was not extracted; program=%#v", prog)
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A module wires its loader through a setter, so the function reaches its name by an
// assignment statement rather than by the name's own declaring initialiser:
//
//	let loaderOptions
//	let requireModule
//	export function setRequireModule(options) {
//	  loaderOptions = options
//	  requireModule = (id) => { return loaderOptions.load(id) }
//	}
//	export async function loadServerAction(id) {
//	  const [file, name] = id.split('#')
//	  const mod = await requireModule(file)
//	  return mod[name]
//	}
//
// Written with `const requireModule = (id) => …` the arrow is a declaring initialiser,
// lowers to a function definition, and the call at the bottom resolves to its body.
// Written this way it has to resolve to the same body: the two are the same call, and
// anything else leaves the call carrying only the local name with no callee body for
// its arguments to reach.
const assignmentBoundCalleeSrc = `
let loaderOptions
let requireModule

export function setRequireModule(options) {
  loaderOptions = options
  requireModule = (id) => {
    return loaderOptions.load(id)
  }
}

export async function loadServerAction(id) {
  const [file, name] = id.split('#')
  const mod = await requireModule(file)
  return mod[name]
}
`

// The same module with the loader bound by its own declaring initialiser. Every
// signature, every name and every intermediate step is the same; only the binding
// differs. This is what the assignment spelling has to behave like.
const declaringInitialiserCalleeSrc = `
let loaderOptions

const requireModule = (id) => {
  return loaderOptions.load(id)
}

export function setRequireModule(options) {
  loaderOptions = options
}

export async function loadServerAction(id) {
  const [file, name] = id.split('#')
  const mod = await requireModule(file)
  return mod[name]
}
`

// lowerJSFile extracts and lowers one JavaScript module, so a test can ask what a
// value in it can reach.
func lowerJSFile(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "core.js")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// paramOf returns a named function's parameter node, or "" when the function never
// became one -- which is the symptom this change is about, so callers may want the
// quiet form rather than a failure.
func paramOf(g usg.Store, fn, name string) string {
	ids, err := g.NodesOfType("code.Param")
	if err != nil {
		return ""
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok || n.Prop("name") != name || n.Prop("func") != fn {
			continue
		}
		return id
	}
	return ""
}

// callArgOf returns a call's argument slot by callee path, or "" when no such call
// lowered.
func callArgOf(g usg.Store, calleePath string, i int) string {
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		return ""
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok || n.Prop("callee_path") != calleePath {
			continue
		}
		return n.Prop(usg.ArgPropKey(i))
	}
	return ""
}

// reaches reports whether BFS over FLOWS carries src to dst.
func reaches(t *testing.T, g usg.Store, src, dst string) bool {
	t.Helper()
	if src == "" || dst == "" {
		return false
	}
	r, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return r[dst]
}

// The call through the assignment-bound name reaches the assigned body's parameter,
// and through it the call that body makes -- the same edges the declaring
// initialiser spelling produces.
func TestCallThroughAssignmentBoundCalleeReachesAssignedBody(t *testing.T) {
	g := lowerJSFile(t, assignmentBoundCalleeSrc)
	src := paramOf(g, "loadServerAction", "id")
	if src == "" {
		t.Fatal("loadServerAction's parameter never lowered")
	}
	if p := paramOf(g, "requireModule", "id"); p == "" {
		t.Fatal("a name bound to a function by an assignment statement did not become a function definition, so the call through it has no callee body")
	} else if !reaches(t, g, src, p) {
		t.Fatal("the argument of a call through an assignment-bound callee did not reach the assigned body's parameter")
	}
	if s := callArgOf(g, "loaderOptions.load", 0); s != "" && !reaches(t, g, src, s) {
		t.Fatal("the argument of a call through an assignment-bound callee did not reach the assigned body's own call")
	}
}

// The declaring-initialiser spelling keeps resolving; the two spellings of one
// binding must not drift apart again.
func TestCallThroughDeclaringInitialiserCalleeStillReaches(t *testing.T) {
	g := lowerJSFile(t, declaringInitialiserCalleeSrc)
	src := paramOf(g, "loadServerAction", "id")
	if src == "" {
		t.Fatal("loadServerAction's parameter never lowered")
	}
	if p := paramOf(g, "requireModule", "id"); p == "" {
		t.Fatal("the declaring-initialiser spelling stopped lowering to a function definition")
	} else if !reaches(t, g, src, p) {
		t.Fatal("the argument of a call through a declaration-bound callee no longer reaches its parameter")
	}
}

// Only a plain identifier target is a name being bound to a function. A member or a
// subscript target stores a function value somewhere, and those keep the lowering
// they have always had.
func TestAssignmentBoundCalleeLeavesNonNameTargetsAlone(t *testing.T) {
	g := lowerJSFile(t, `
let registry = {}

export function wire() {
  registry.handler = (v) => { return db.query(v) }
  registry.slots[0] = (v) => { return db.query(v) }
}
`)
	if _, ok := funcDefNames(g)["handler"]; ok {
		t.Fatal("a member-target assignment became a function definition; it stores a value, it does not bind a name")
	}
	if _, ok := funcDefNames(g)["slots"]; ok {
		t.Fatal("a subscript-target assignment became a function definition; it stores a value, it does not bind a name")
	}
}

// funcDefNames lists the function definitions a program's graph carries, by the
// parameter nodes their signatures mint.
func funcDefNames(g usg.Store) map[string]bool {
	out := map[string]bool{}
	ids, err := g.NodesOfType("code.Param")
	if err != nil {
		return out
	}
	for _, id := range ids {
		if n, ok, err := g.GetNode(id); err == nil && ok {
			out[n.Prop("func")] = true
		}
	}
	return out
}

package treesitter

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// `render_details render;` is how C introduces an aggregate before filling it in. A bare
// local gets the declaration Java gives `Foo f;`: an empty constant, which names the
// storage without claiming a value for it, so a member store and a later member read name
// the same object.
func TestCBareLocalDeclarationBindsTheName(t *testing.T) {
	prog := extractCSource(t, "bare.c", `
static void run(void)
{
    render_details render;
    char *buf;
    int counts[4];
}
`)
	for _, name := range []string{"render", "buf", "counts"} {
		a, ok := cAssign(prog, name)
		if !ok {
			t.Errorf("no declaration statement for %q: %#v", name, prog.Modules[0].Body)
			continue
		}
		if !a.Decl {
			t.Errorf("%q: Decl = false, want true (a local, not a write to an outer name)", name)
		}
		if _, isConst := a.Value.(nir.Const); !isConst {
			t.Errorf("%q: value = %#v, want an empty Const", name, a.Value)
		}
	}
}

// A prototype declared inside a body declares a function, not storage: binding its name
// would shadow the callee at every later call of it.
func TestCNestedPrototypeDoesNotBindAName(t *testing.T) {
	prog := extractCSource(t, "proto.c", `
static void run(void)
{
    char *helper(int n);
    sink(helper(1));
}
`)
	if a, ok := cAssign(prog, "helper"); ok {
		t.Errorf("a nested prototype bound its own name: %#v", a)
	}
}

// A file-scope declaration binds too, and its binding is the one node every other
// function's mention of the global resolves to — so it carries the name, rather than the
// anonymous placeholder a local gets, and it claims no value for the storage.
func TestCFileScopeDeclarationBindsTheGlobalToItsOwnName(t *testing.T) {
	prog := extractCSource(t, "global.c", `
static render_details shared;

static void run(void)
{
    use(shared);
}
`)
	a, ok := cAssign(prog, "shared")
	if !ok {
		t.Fatalf("no declaration statement for the file-scope global: %#v", prog.Modules[0].Body)
	}
	if !a.Decl {
		t.Errorf("shared: Decl = false, want true (a declaration, not a write)")
	}
	nm, isName := a.Value.(nir.Name)
	if !isName {
		t.Fatalf("shared: value = %#v, want a Name carrying the global's own name", a.Value)
	}
	if nm.ID != "shared" {
		t.Errorf("shared: value names %q, want \"shared\"", nm.ID)
	}
}

// `a[i] = v` is the other spelling of an aggregate member store. It emits the synthetic
// __setitem__ call the Python and PHP frontends emit, carrying the value and the key,
// rather than falling through to the two-bare-statements fallback that drops the store.
func TestCSubscriptStoreIsASetitemCall(t *testing.T) {
	prog := extractCSource(t, "elem.c", `
static void run(int *a, int i, int v)
{
    a[i] = v;
}
`)
	store, ok := cFieldStoreCall(prog, "a.__setitem__")
	if !ok {
		t.Fatalf("no element-write call for a[i]: %#v", prog.Modules[0].Body)
	}
	if store.Method != "__setitem__" {
		t.Errorf("element write method = %q, want __setitem__", store.Method)
	}
	if len(store.Args) != 2 {
		t.Fatalf("element write args = %d, want the value and the key", len(store.Args))
	}
	if v, ok := store.Args[0].(nir.Name); !ok || v.ID != "v" {
		t.Errorf("element write value = %#v, want the local `v`", store.Args[0])
	}
	if k, ok := store.Args[1].(nir.Name); !ok || k.ID != "i" {
		t.Errorf("element write key = %#v, want the index `i`", store.Args[1])
	}
}

// cAssign finds the Assign whose sole target is name, anywhere in the program.
func cAssign(prog nir.Program, name string) (nir.Assign, bool) {
	var found nir.Assign
	ok := false
	var walk func([]nir.Stmt)
	walk = func(stmts []nir.Stmt) {
		for _, s := range stmts {
			switch st := s.(type) {
			case nir.Assign:
				if len(st.Targets) == 1 && st.Targets[0] == name {
					found, ok = st, true
				}
			case nir.FuncDef:
				walk(st.Body)
			case nir.Block:
				walk(st.Stmts)
			case nir.If:
				walk(st.Then)
				walk(st.Else)
			case nir.Loop:
				walk(st.Body)
			}
		}
	}
	for _, m := range prog.Modules {
		walk(m.Body)
	}
	return found, ok
}

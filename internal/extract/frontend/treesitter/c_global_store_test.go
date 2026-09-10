package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// cLower lowers one C file into a graph.
func cLower(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "app.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// cParamReachesSink reports whether the parameter named from reaches the single
// argument of the call whose callee path is sink. An argument node carries the loc of
// the expression it is, which in these programs is the line its call is on.
func cParamReachesSink(t *testing.T, g usg.Store, from, sink string) bool {
	t.Helper()
	call := cOneNode(t, g, "code.Call", "callee_path", sink)
	n, ok, err := g.GetNode(call)
	if err != nil || !ok {
		t.Fatalf("call %s disappeared from the graph", sink)
	}
	arg := cOneNode(t, g, "code.Arg", "loc", n.Loc)
	reach, err := usg.BFS(g, cOneNode(t, g, "code.Param", "name", from), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reach[arg]
}

// cOneNode returns the id of the one node of typ carrying key=val, failing when there
// are none or several — several would make the question ambiguous.
func cOneNode(t *testing.T, g usg.Store, typ, key, val string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Prop(key) == val {
			if found != "" {
				t.Fatalf("more than one %s carries %s=%s", typ, key, val)
			}
			found = id
		}
	}
	if found == "" {
		t.Fatalf("no %s with %s=%s in the lowered graph", typ, key, val)
	}
	return found
}

// A file-scope struct is one object for the whole translation unit, so a function that
// stores into its field and another that reads the field back are talking about the same
// storage: what the first put there is what the second reads. Nothing joins the two
// functions, so the identity has to come from the declaration.
func TestCTaintCrossesAFileScopeStructFieldStore(t *testing.T) {
	g := cLower(t, `
typedef struct { char *name; } session;

static session g_session;

void load(char *input)
{
    g_session.name = input;
}

void use(void)
{
    log_name(g_session.name);
}
`)
	if !cParamReachesSink(t, g, "input", "log_name") {
		t.Error("the value stored into a file-scope struct's field did not reach the function that reads it back")
	}
}

// Field sensitivity is per field and not per struct: a value stored into one field of
// the global must not surface on a read of a sibling field.
func TestCTaintIntoOneFieldOfAFileScopeStructStaysOutOfItsSiblings(t *testing.T) {
	g := cLower(t, `
typedef struct { char *name; char *label; } session;

static session g_session;

void load(char *input)
{
    g_session.label = input;
}

void use(void)
{
    log_name(g_session.name);
}
`)
	if cParamReachesSink(t, g, "input", "log_name") {
		t.Error("a value stored into one field of a file-scope struct reached a sibling field")
	}
}

// A body-local of the same name as a file-scope variable is a different object: the
// declaration shadows the global, so a store into the local must not reach a reader of
// the global.
func TestCAFileScopeVariableIsNotTaintedByALocalOfTheSameName(t *testing.T) {
	g := cLower(t, `
static char *g_name;

void load(char *input)
{
    char *g_name = input;
    log_local(g_name);
}

void use(void)
{
    log_name(g_name);
}
`)
	if cParamReachesSink(t, g, "input", "log_name") {
		t.Error("a value stored into a local that shadows a file-scope variable reached the global")
	}
}

// A global held through a pointer spells the store with `->` instead of `.`, and is the
// shape most C state actually takes. The same declaration has to carry it.
func TestCTaintCrossesAFileScopePointerStructFieldStore(t *testing.T) {
	g := cLower(t, `
typedef struct { char *name; } session;

static session *g_session;

void load(char *input)
{
    g_session->name = input;
}

void use(void)
{
    log_name(g_session->name);
}
`)
	if !cParamReachesSink(t, g, "input", "log_name") {
		t.Error("the value stored through a file-scope pointer's field did not reach the function that reads it back")
	}
}

// Two globals of one type are two objects, even though neither is a parameter and
// nothing aliases them: the slot is per global, not per type or per field name.
func TestCTwoFileScopeStructsDoNotShareAField(t *testing.T) {
	g := cLower(t, `
typedef struct { char *name; } session;

static session g_a;
static session g_b;

void store(char *input)
{
    g_a.name = input;
}

void use(void)
{
    log_name(g_b.name);
}
`)
	if cParamReachesSink(t, g, "input", "log_name") {
		t.Error("a value stored into one global reached a same-named field of another global")
	}
}

// The within-one-function route through a global field is the control: both halves
// already run through one object, so the declaration must not take that path away.
func TestCTaintThroughAFileScopeStructFieldInsideOneFunction(t *testing.T) {
	g := cLower(t, `
typedef struct { char *name; } session;

static session g_session;

void handle(char *input)
{
    g_session.name = input;
    log_name(g_session.name);
}
`)
	if !cParamReachesSink(t, g, "input", "log_name") {
		t.Error("a store into a global field and the read of it in the same body no longer meet")
	}
}

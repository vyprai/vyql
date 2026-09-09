package extract_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// C introduces an aggregate with a bare declaration and fills it in afterwards, so the
// declaration is where the object gets its identity: a bare local gets the declaration
// Java gives `Foo f;`, which names the storage without claiming a value for it, so a
// store into one of its members and a read of that member name the same object and a
// value crosses between them. These are the four shapes CVE-2021-4216 is built out of.

// The muraster shape end to end: a local aggregate declared bare, filled through a pointer
// parameter by one function, and read back a member at a time by another.
func TestCTaintCrossesALocalAggregateFilledThroughAPointerParameter(t *testing.T) {
	g := lowerC(t, "muraster.c", `
static void get_page_render_details(fz_context *ctx, fz_page *page, render_details *render)
{
    render->bounds = fz_bound_page(ctx, page);
    render->ibounds = fz_round_rect(render->bounds);
}

static void initialise_banding(fz_context *ctx, render_details *render)
{
    int w = render->ibounds.x1 - render->ibounds.x0;
    size_t min_band_mem = (size_t)bpp * w * min_band_height;
    int reps = (int)(max_band_memory / min_band_mem);
}

static void run(fz_context *ctx, fz_page *page)
{
    render_details render;

    get_page_render_details(ctx, page, &render);
    initialise_banding(ctx, &render);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "muraster.c:4"), "code.Attr", "muraster.c:10") {
		t.Error("the page bounds stored on a member never reached the nested member read that divides by it")
	}
}

// The same identity question with both halves in one function: a member store followed by a
// read of that member.
func TestCTaintCrossesAMemberStoreOnALocalStruct(t *testing.T) {
	g := lowerC(t, "member.c", `
static void run(void)
{
    struct box b;

    b.width = fread_all();
    sink(b.width);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "member.c:6"), "code.Attr", "member.c:7") {
		t.Error("a value stored into a member of a bare-declared local did not reach the read of that member")
	}
}

// The precision half: sharing one node for the object must not make every member of it one
// slot. Same program, reading a DIFFERENT member.
func TestCASiblingMemberOfTheSameLocalStaysClean(t *testing.T) {
	g := lowerC(t, "sibling.c", `
static void run(void)
{
    struct box b;

    b.width = fread_all();
    sink(b.height);
}
`)
	if reachesNodeAt(t, g, callAt(t, g, "sibling.c:6"), "code.Attr", "sibling.c:7") {
		t.Error("a read of a different member saw the written member's slot")
	}
}

// The other spelling of an aggregate member: `a[i] = v` lowers to the synthetic
// __setitem__ store, so a later `a[i]` read carries the value.
func TestCTaintCrossesAnArrayElementStore(t *testing.T) {
	g := lowerC(t, "element.c", `
static void run(void)
{
    int a[4];

    a[0] = fread_all();
    sink(a[0]);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "element.c:6"), "code.Subscript", "element.c:7") {
		t.Error("a value stored into an array element did not reach the read of that element")
	}
}

// callAt returns the id of the call node at loc.
func callAt(t *testing.T, g usg.Store, loc string) string {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Loc == loc {
			return n.ID
		}
	}
	t.Fatalf("no call node at %s", loc)
	return ""
}

// reachesNodeAt reports whether taint flows from `from` to a node of type `typ` at `loc`.
func reachesNodeAt(t *testing.T, g usg.Store, from, typ, loc string) bool {
	t.Helper()
	reachable, err := usg.BFS(g, from, "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
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
		if ok && n.Loc == loc && reachable[id] {
			return true
		}
	}
	return false
}

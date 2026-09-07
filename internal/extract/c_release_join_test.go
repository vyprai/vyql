package extract_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// The end-to-end shape of CVE-2018-9336, from C source to the join: a producer publishes
// its allocation into a caller-visible field and still releases its own alias at the
// shared cleanup label; a destructor releases the field; the caller hands the same struct
// to both. The two releases are in two functions, so no region order puts them on a path,
// and before the field store had a node nothing said the local and the field named one
// buffer either.
func TestCReleasesInTwoFunctionsJoinOnThePublishedAllocation(t *testing.T) {
	g := lowerC(t, "interactive.c", `
static BOOL GetStartupData(HANDLE pipe, STARTUP_DATA *sud)
{
    WCHAR *data = NULL;
    BOOL ret = FALSE;

    data = malloc(bytes);
    if (data == NULL)
    {
        goto out;
    }

    sud->directory = data;
    if (size <= 0)
    {
        goto out;
    }

    data = NULL;
    ret = TRUE;

out:
    free(data);
    return ret;
}

static VOID FreeStartupData(STARTUP_DATA *sud)
{
    free(sud->directory);
}

static DWORD RunOpenvpn(LPVOID p)
{
    STARTUP_DATA sud = { 0, 0, 0 };

    GetStartupData(p, &sud);
    FreeStartupData(&sud);
    return 0;
}
`)
	rel := releases(t, g)
	local, field := rel[0], rel[1] // free(data) in GetStartupData, free(sud->directory) in FreeStartupData
	if solvers.Reaches(g, local, field) {
		t.Fatal("two releases in two functions must not be sequenced by region order")
	}
	if !solvers.NewStorageJoin(g).Joins(local, field) {
		t.Error("the release of the published buffer and the release of the field did not join")
	}
}

// The same two functions with nothing published between them: the producer releases a
// field it never wrote, so there is no store to establish the identity and the pair stays
// unselectable. This is the shape a producer/destructor pair has when it is correct.
func TestCReleasesInTwoFunctionsDoNotJoinWithoutAPublishedAllocation(t *testing.T) {
	g := lowerC(t, "box.c", `
static int publish(struct box *b, const char *value)
{
    if (!parse(value, &b->field))
    {
        free(b->field);
        return 0;
    }
    return 1;
}

static void destroy(struct box *b)
{
    free(b->field);
}

static void run(const char *value)
{
    struct box b = { 0 };

    publish(&b, value);
    destroy(&b);
}
`)
	rel := releases(t, g)
	first, second := rel[0], rel[1] // free(b->field) in publish, then in destroy
	if solvers.NewStorageJoin(g).Joins(first, second) {
		t.Error("two releases of a field nobody published joined")
	}
}

func lowerC(t *testing.T, name, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// releases returns the free() call nodes in source order.
func releases(t *testing.T, g usg.Store) []string {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var out []usg.Node
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "free" {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	if len(out) != 2 {
		t.Fatalf("free() calls = %d, want 2", len(out))
	}
	return []string{out[0].ID, out[1].ID}
}

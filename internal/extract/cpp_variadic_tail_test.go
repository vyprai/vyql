package extract_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// C++ shares the ccConv walker with C, but its grammar spells the `...` as an
// anonymous token where C spells it a named variadic_parameter node, so the
// walker's parameter-list check does not recognize a .cpp tail and the
// synthetic __varargs__ parameter is never appended: a .cpp wrapper's body
// stays unreachable from its callers' tail arguments. That darkness is
// specified, not an oversight — the corpus's rank-1082 varargs pair
// (cve_rank1082_domoticz_floorplan_sql_format) rejects VYQL-INJ-001 for
// exactly this wrapper shape, and its expectation is marked
// attention-engine-gap on the definitions side, so moving it is theirs, not
// the engine's. These pins hold the C++ boundary dark until then; lighting it
// is a one-check change in ccWithVariadicTailParam to make together with that
// expectation, never ahead of it.

// The printf-wrapper shape parsed by the C++ grammar: the tail argument stops
// at the call boundary, and the vfprintf inside the wrapper stays unreachable
// from it.
func TestCPPVariadicTailStopsAtTheCallBoundary(t *testing.T) {
	g := lowerCPP(t, "wrapper.cpp", `
static void log_msg(int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    std::vfprintf(stderr, format, ap);
    va_end(ap);
}

static void report(char *name)
{
    log_msg(LOG_INFO, "scanned %s", name);
}
`)
	if reachesCallArg(t, g, callArgAt(t, g, "wrapper.cpp:12", 2), "wrapper.cpp:6", 2) {
		t.Error("a C++ tail argument crossed the wrapper's call boundary into the vfprintf that prints it, past the corpus expectation that rejects this route")
	}
	if reachesCallArg(t, g, callArgAt(t, g, "wrapper.cpp:12", 2), "wrapper.cpp:6", 1) {
		t.Error("a C++ tail argument reached the vfprintf's format slot")
	}
}

// A C++ wrapper that never opens a va_list reads nothing from its tail, so its
// call keeps the conservative argument-to-result edge exactly as the C side
// does: the tail is unread, not newly dropped.
func TestCPPUnreadVariadicTailKeepsTheResultEdge(t *testing.T) {
	g := lowerCPP(t, "unread.cpp", `
static int sum(int first, ...)
{
    return first;
}

static void use(char *secret)
{
    int total = sum(1, secret);
    sink(total);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "unread.cpp:9", 1), "unread.cpp:10", 0) {
		t.Error("an unread C++ variadic tail lost the argument-to-result edge it used to keep")
	}
}

func lowerCPP(t *testing.T, name, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCPP([]string{path}, dir)
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

package extract_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// The variadic tail's route into a printf-style wrapper's body is pinned for C
// in c_variadic_tail_test.go. C++ shares the ccConv walker, but its grammar
// spells the `...` as an anonymous token where C spells it a named
// variadic_parameter node — and no test in the package ran ExtractCPP to
// notice the difference, so the tail route stayed dark for every .cpp wrapper
// until the parameter-list check learned both spellings. These tests keep it
// lit: the wrapper below spells its output call through the std namespace, the
// way C++ code does, and asserts the same separations the C tests do.

// The printf-wrapper shape end to end, parsed by the C++ grammar: one tainted
// tail argument crosses the wrapper's call boundary and reaches the
// vfprintf that prints it, without taking the format slot.
func TestCPPVariadicTailReachesTheWrapperBody(t *testing.T) {
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
	if !reachesCallArg(t, g, callArgAt(t, g, "wrapper.cpp:12", 2), "wrapper.cpp:6", 2) {
		t.Error("the tail argument handed the C++ logging wrapper never reached the vfprintf that prints it")
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

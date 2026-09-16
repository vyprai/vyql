package extract_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A C logging wrapper is variadic: it declares `...`, opens the tail into a
// va_list with va_start, and hands the list to a v-formatted call. The tail
// arguments a caller passes have no parameter to bind to, so before the
// variadic tail was traced they stopped at the call boundary — the wrapper's
// own body, where every printf-style sink lives, was unreachable from the
// data. These tests pin the route CVE-2025-54389 needs: the filename a caller
// hands the wrapper reaches the wrapper's own output call.

// The printf-wrapper shape end to end: one tainted tail argument crosses the
// wrapper's call boundary and reaches the vfprintf that prints it.
func TestCVariadicTailReachesTheWrapperBody(t *testing.T) {
	g := lowerC(t, "wrapper.c", `
static void log_msg(int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void report(char *name)
{
    log_msg(LOG_INFO, "scanned %s", name);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "wrapper.c:12", 2), "wrapper.c:6", 2) {
		t.Error("the tail argument handed to the logging wrapper never reached the vfprintf that prints it")
	}
}

// A caller passing several tail arguments: the second and later ones are past
// the parameter list entirely, and each still reaches the wrapper's list.
func TestCVariadicTailCarriesEveryTailArgument(t *testing.T) {
	g := lowerC(t, "twotail.c", `
static void logf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsyslog(LOG_INFO, format, ap);
    va_end(ap);
}

static void emit(char *path, char *detail)
{
    logf("%s: %s", path, detail);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "twotail.c:12", 1), "twotail.c:6", 2) {
		t.Error("the first tail argument never reached the vsyslog list it was opened into")
	}
	if !reachesCallArg(t, g, callArgAt(t, g, "twotail.c:12", 2), "twotail.c:6", 2) {
		t.Error("a tail argument past the first never reached the vsyslog list it was opened into")
	}
}

// The tail must not bleed onto the wrapper's format slot: the named format
// parameter reaches the v-call's format argument, the tail reaches the list,
// and neither takes the other's place.
func TestCVariadicTailStaysOffTheFormatSlot(t *testing.T) {
	g := lowerC(t, "slots.c", `
static void log_msg(int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void report(char *name, char *controlled)
{
    log_msg(LOG_INFO, controlled, name);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "slots.c:12", 1), "slots.c:6", 1) {
		t.Error("the format argument stopped reaching the vfprintf's format slot")
	}
	if reachesCallArg(t, g, callArgAt(t, g, "slots.c:12", 1), "slots.c:6", 2) {
		t.Error("the format argument reached the vfprintf's list slot")
	}
	if reachesCallArg(t, g, callArgAt(t, g, "slots.c:12", 2), "slots.c:6", 1) {
		t.Error("a tail argument reached the vfprintf's format slot")
	}
}

// A va_copy re-opens one list onto another, and the copy the wrapper hands the
// v-call carries the tail the original was opened from.
func TestCVariadicTailSurvivesAVaCopy(t *testing.T) {
	g := lowerC(t, "vacopy.c", `
static void log_both(const char *format, ...)
{
    va_list ap, copy;
    va_start(ap, format);
    va_copy(copy, ap);
    vfprintf(stderr, format, copy);
    va_end(copy);
    va_end(ap);
}

static void run(char *user)
{
    log_both("%s", user);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "vacopy.c:14", 1), "vacopy.c:7", 2) {
		t.Error("the tail argument never reached the va_copy the vfprintf prints from")
	}
}

// A wrapper that reads the list element by element with va_arg, rather than
// handing it to a v-formatted call: the read is a read of the list, so the
// tail reaches whatever the wrapper does with the element.
func TestCVariadicTailReachesAVaArgRead(t *testing.T) {
	g := lowerC(t, "vaarg.c", `
static void emit(const char *s);

static void append_all(const char *first, ...)
{
    va_list ap;
    va_start(ap, first);
    const char *s = va_arg(ap, const char *);
    emit(s);
    va_end(ap);
}

static void run(char *user)
{
    append_all("start", user, NULL);
}
`)
	if !reachesCallArg(t, g, callArgAt(t, g, "vaarg.c:15", 1), "vaarg.c:9", 0) {
		t.Error("the tail argument never reached the va_arg read's consumer")
	}
}

// A variadic function that never opens a va_list reads nothing from its tail,
// so its call keeps the conservative argument-to-result edge exactly as
// before: the tail is unread, not newly dropped.
func TestCUnreadVariadicTailKeepsTheResultEdge(t *testing.T) {
	g := lowerC(t, "unread.c", `
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
	if !reachesCallArg(t, g, callArgAt(t, g, "unread.c:9", 1), "unread.c:10", 0) {
		t.Error("an unread variadic tail lost the argument-to-result edge it used to keep")
	}
}

// callArgAt returns the id of the argument-slot node at index i of the call at loc.
func callArgAt(t *testing.T, g usg.Store, loc string, i int) string {
	t.Helper()
	a := callNodeAt(t, g, loc).Prop(usg.ArgPropKey(i))
	if a == "" {
		t.Fatalf("no argument %d on the call at %s", i, loc)
	}
	return a
}

// reachesCallArg reports whether taint flows from `from` into argument i of the
// call at loc.
func reachesCallArg(t *testing.T, g usg.Store, from, loc string, i int) bool {
	t.Helper()
	reachable, err := usg.BFS(g, from, "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	a := callNodeAt(t, g, loc).Prop(usg.ArgPropKey(i))
	return a != "" && reachable[a]
}

// callNodeAt returns the call node at loc.
func callNodeAt(t *testing.T, g usg.Store, loc string) usg.Node {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Loc == loc {
			return n
		}
	}
	t.Fatalf("no call node at %s", loc)
	return usg.Node{}
}

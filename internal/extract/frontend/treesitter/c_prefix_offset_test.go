package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccPrefixOffsetObs runs the prefix-offset observation over one C source and
// returns the emitted facts as "pointer=..;prefix=..;offset=.." text.
func ccPrefixOffsetObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "command.c")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok {
			continue
		}
		for _, s := range fn.Body {
			es, ok := s.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.Value.(nir.Call)
			if !ok || call.Path != "analysis.prefix_length.offset_past_verified" {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.Join(parts, ";"))
		}
	}
	return out
}

// ccPrefixOffsetCase asserts one fire/clear pair: the live source establishes
// the bound and reads past it, the suppressed source differs only in the
// construct under test and must report nothing.
func ccPrefixOffsetCase(t *testing.T, name, live, suppressed string) {
	t.Helper()
	if got := ccPrefixOffsetObs(t, live); len(got) != 1 {
		t.Fatalf("%s: live variant: got %q want exactly one fact", name, got)
	}
	if got := ccPrefixOffsetObs(t, suppressed); len(got) != 0 {
		t.Fatalf("%s: suppressed variant: got %q want none", name, got)
	}
}

func TestCPrefixOffsetObservations(t *testing.T) {
	// The bare libc spellings, both argument orders: the guard matches a
	// two-byte prefix and the branch it admits prints from three bytes in,
	// past the terminator the shortest admitted response ends on. The
	// correctly-paired length-3 branch above must not fire, because its
	// advance stops on the byte the comparison proved present.
	ccPrefixOffsetCase(t, "bare strncasecmp, literal first",
		`#include <string.h>
static int cmd_handle_untagged(struct ImapData *idata)
{
  char *s = imap_next_word(idata->buf);
  if (strncasecmp("NO", s, 2) == 0)
    mutt_error("%s", s + 3);
  return 0;
}
`,
		`#include <string.h>
static int cmd_handle_untagged(struct ImapData *idata)
{
  char *s = imap_next_word(idata->buf);
  if (strncasecmp("NO", s, 2) == 0)
    mutt_error("%s", s + 2);
  return 0;
}
`)

	// The same pair with the bare pointer-first spelling, and the wrapper
	// spelling the target itself uses: every naming form establishes the
	// same bound.
	ccPrefixOffsetCase(t, "bare strncmp, pointer first",
		`#include <string.h>
static void parse(const char *line)
{
  if (strncmp(line, "OK", 2) == 0) {
    error("%s", line + 4);
  }
}
`,
		`#include <string.h>
static void parse(const char *line)
{
  if (strncmp(line, "OK", 2) == 0) {
    error("%s", line + 2);
  }
}
`)
	ccPrefixOffsetCase(t, "library wrapper name",
		`#include <string.h>
static int cmd_handle_untagged(struct ImapData *idata)
{
  char *s = imap_next_word(idata->buf);
  if (mutt_str_strncasecmp("NO", s, 2) == 0)
    mutt_error("%s", s + 3);
  return 0;
}
`,
		`#include <string.h>
static int cmd_handle_untagged(struct ImapData *idata)
{
  char *s = imap_next_word(idata->buf);
  if (mutt_str_strncasecmp("NO", s, 2) == 0)
    mutt_error("%s", s + 2);
  return 0;
}
`)

	// The full dispatch chain: the correctly-paired length-3 branch sits
	// in the same function as the mismatched length-2 one, so only the
	// branch-local pairing separates them.
	if got := ccPrefixOffsetObs(t, `
#include <string.h>
static int cmd_handle_untagged(struct ImapData *idata)
{
  char *s = imap_next_word(idata->buf);
  if (mutt_str_strncasecmp("BYE", s, 3) == 0)
  {
    s += 3;
    mutt_error("%s", s);
  }
  else if (ImapServernoise && (mutt_str_strncasecmp("NO", s, 2) == 0))
  {
    mutt_error("%s", s + 3);
  }
  return 0;
}
`); strings.Join(got, "|") != "pointer=s;prefix=2;offset=3" {
		t.Fatalf("dispatch chain: got %q want the NO branch's s+3 alone", got)
	}

	// A disjunction compares two prefixes on the pointer and only promises
	// that one arm matched, so the fact fires only when the offset exceeds
	// every arm's verified length.
	ccPrefixOffsetCase(t, "disjunction takes the longest arm",
		`#include <string.h>
static char *dbd_map(const char *a2)
{
  if ((strncmp(a2, "dbd:", 4) == 0) || (strncmp(a2, "fastdbd:", 8) == 0))
    return a2 + 9;
  return 0;
}
`,
		`#include <string.h>
static char *dbd_map(const char *a2)
{
  if ((strncmp(a2, "dbd:", 4) == 0) || (strncmp(a2, "fastdbd:", 8) == 0))
    return a2 + 8;
  return 0;
}
`)

	// A guard that subscripts the compared pointer at or past the compared
	// length consults that byte itself, so the advance is not the first
	// unverified read.
	ccPrefixOffsetCase(t, "subscript consults the byte",
		`#include <string.h>
static const char *lookup_variable(char *var)
{
  if (!strncasecmp(var, "ENV", 3)) {
    var += 4;
    return getenv(var);
  }
  return 0;
}
`,
		`#include <string.h>
static const char *lookup_variable(char *var)
{
  if (var[4] && !strncasecmp(var, "ENV", 3)) {
    var += 4;
    return getenv(var);
  }
  return 0;
}
`)

	// A comparison tested for failure proves nothing about the bytes that
	// follow, so it establishes no bound at all.
	ccPrefixOffsetCase(t, "failure test establishes nothing",
		`#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) == 0) {
    error("%s", s + 4);
  }
}
`,
		`#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) != 0) {
    error("%s", s + 4);
  }
}
`)

	// The bound lives in the branch the comparison admits: an advance in a
	// sibling arm is not vouched for, and an advance on a different word is
	// not the compared pointer at all.
	ccPrefixOffsetCase(t, "bound is branch-local and pointer-local",
		`#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) == 0) {
    error("%s", s + 4);
  }
}
`,
		`#include <string.h>
static void dispatch(const char *s, char *w)
{
  if (strncmp(s, "OK", 2) == 0) {
    ok();
  } else {
    error("%s", s + 4);
  }
  if (strncmp(s, "LIST", 4) == 0) {
    error("%s", w + 9);
  }
}
`)

	// A nested if that compares the same pointer again tightens the bound
	// inside its own consequence: both guards hold there, so the advance is
	// covered by the longer prefix.
	ccPrefixOffsetCase(t, "nested comparison tightens the bound",
		`#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) == 0) {
    if (flag) {
      error("%s", s + 3);
    }
  }
}
`,
		`#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) == 0) {
    if (strncmp(s, "OK [", 4) == 0) {
      error("%s", s + 3);
    }
  }
}
`)

	// A nested while's condition is checked before every iteration, so it
	// tightens the bound inside its own body the way a nested if does --
	// the parent-then-sibling walk over ".." and "/.." is the shape this
	// keeps clear.
	ccPrefixOffsetCase(t, "nested loop condition tightens the bound",
		`#include <string.h>
static int parse_path_arg(const char *id)
{
  int parsed = 0;
  if (!strncmp(id, "..", 2)) {
    parsed += 2;
    id += 2;
    while (more(id)) {
      parsed += 3;
      id += 3;
    }
  }
  return parsed;
}
`,
		`#include <string.h>
static int parse_path_arg(const char *id)
{
  int parsed = 0;
  if (!strncmp(id, "..", 2)) {
    parsed += 2;
    id += 2;
    while (!strncmp(id, "/..", 3)) {
      parsed += 3;
      id += 3;
    }
  }
  return parsed;
}
`)

	// A loop whose condition compares a prefix and whose body advances the
	// pointer is a documented residual and must stay unreported.
	if got := ccPrefixOffsetObs(t, `
#include <string.h>
static void walk(const char *s)
{
  while (strncmp(s, "OK", 2) == 0) {
    error("%s", s + 3);
    s += 2;
  }
}
`); len(got) != 0 {
		t.Fatalf("loop form is a residual: got %q want none", got)
	}

	// The pairing is by spelling, a documented false-positive residual: a
	// branch that reassigns the compared pointer and then advances the
	// name still reports, although the name no longer names the compared
	// bytes.
	if got := ccPrefixOffsetObs(t, `
#include <string.h>
static void dispatch(const char *s)
{
  if (strncmp(s, "OK", 2) == 0) {
    s = fresh_word();
    error("%s", s + 3);
  }
}
`); len(got) != 1 {
		t.Fatalf("reassignment residual: got %q want the documented firing", got)
	}
}

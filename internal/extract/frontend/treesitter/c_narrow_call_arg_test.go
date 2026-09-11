package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// cFuncHasAnalysisPath reports whether a function's body carries an
// observation call of one path at all, so a test can assert a function
// reports nothing.
func cFuncHasAnalysisPath(stmts []nir.Stmt, funcName, path string) bool {
	for _, st := range stmts {
		switch x := st.(type) {
		case nir.FuncDef:
			if x.Name != funcName {
				continue
			}
			for _, bodyStmt := range x.Body {
				exprStmt, ok := bodyStmt.(nir.ExprStmt)
				if !ok {
					continue
				}
				if call, ok := exprStmt.Value.(nir.Call); ok && call.Path == path {
					return true
				}
			}
		case nir.ClassDef:
			if cFuncHasAnalysisPath(x.Body, funcName, path) {
				return true
			}
		}
	}
	return false
}

// TestCNarrowCallArgObservation pins the implicit wide-to-narrow conversion at
// a call argument: a value the file declares at a pointer width, or the
// difference of two pointers, reaching a parameter the file declares narrower,
// with no cast naming the conversion. Each quiet case is a conversion this
// observation must leave to another one -- an explicit cast to the narrow
// type, a parameter as wide as the argument, a width the file does not state
// -- or a callee the file does not type.
func TestCNarrowCallArgObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "narrow_arg.c")
	src := []byte(`
#include <stdint.h>

struct buf { char *data; int len; };

int narrow_sink(struct buf *b, const char *s, int size);
void wide_sink(struct buf *b, size_t size);
size_t wide_len(const char *s);

int narrow_total(int total)
{
  return total;
}

int vulnerable_wide_local(size_t n)
{
  struct buf b;
  narrow_sink(&b, "x", n);
  return 0;
}

int vulnerable_wide_arithmetic(size_t n)
{
  struct buf b;
  narrow_sink(&b, "x", n + 1);
  return 0;
}

int vulnerable_wide_result(const char *s)
{
  struct buf b;
  narrow_sink(&b, s, wide_len(s));
  return 0;
}

int vulnerable_widened_cast(size_t n)
{
  struct buf b;
  narrow_sink(&b, "x", (uint64_t) n);
  return 0;
}

int vulnerable_pointer_difference(const char *start, const char *base)
{
  struct buf b;
  narrow_sink(&b, base, start - base);
  return 0;
}

int vulnerable_pointer_difference_cast(char *start, char *base)
{
  struct buf b;
  narrow_sink(&b, base, (char *) start - (char *) base);
  return 0;
}

int vulnerable_wide_to_defined_callee(size_t n)
{
  return narrow_total(n);
}

int fixed_explicit_cast(size_t n)
{
  struct buf b;
  narrow_sink(&b, "x", (int) n);
  return 0;
}

int fixed_wide_parameter(size_t n)
{
  struct buf b;
  wide_sink(&b, n);
  return 0;
}

int fixed_narrow_local(void)
{
  struct buf b;
  int n = 4;
  narrow_sink(&b, "x", n);
  return 0;
}

int fixed_member_width_unknown(struct buf *b, size_t n)
{
  narrow_sink(b, b->data, b->len);
  return 0;
}

int fixed_pointer_minus_integer(const char *start, int k)
{
  struct buf b;
  narrow_sink(&b, start, start - k);
  return 0;
}

int fixed_callee_this_file_does_not_type(size_t n)
{
  struct buf b;
  memcpy(b.data, "x", n);
  return 0;
}

/* the library's own spelling of an internal append: the parameter the body
   hands to narrow_sink is the one the caller's third argument fills */
#define append_fast(p, ptr, n)                     \
  do {                                             \
    if ((p)->cap > (n)) {                          \
      narrow_sink((p), (ptr), (n));                \
    } else { wide_sink((p), (n)); }                \
  } while (0)

/* the same forwarding, with the parameter that reaches the int position
   written first */
#define forward_swapped(first, second) narrow_sink(&g_buf, (second), (first))

/* the conversion written inside the macro is explicit, and this observation is
   not the one that reads it */
#define append_cast(p, ptr, n) narrow_sink((p), (ptr), (int) (n))

/* a call a comment mentions forwards nothing */
#define append_quiet(p, ptr, n)          \
  do {                                   \
    /* narrow_sink((p), (ptr), (n)); */  \
    bump((n));                           \
  } while (0)

#define bump(v) ((v) + 1)

struct buf g_buf;

int vulnerable_macro_forwarded(size_t n)
{
  struct buf b;
  append_fast(&b, "x", n);
  return 0;
}

int vulnerable_macro_pointer_difference(const char *start, const char *base)
{
  struct buf b;
  append_fast(&b, base, start - base);
  return 0;
}

int vulnerable_macro_computed_argument(size_t n)
{
  struct buf b;
  append_fast(&b, "x", n + 1);
  return 0;
}

int vulnerable_macro_position_remapped(size_t n)
{
  forward_swapped(n, "x");
  return 0;
}

int fixed_macro_explicit_cast(size_t n)
{
  struct buf b;
  append_cast(&b, "x", n);
  return 0;
}

int fixed_macro_comment_only(size_t n)
{
  struct buf b;
  append_quiet(&b, "x", n);
  return 0;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := "analysis.narrow_call_arg.wide_to_narrow"
	for _, fire := range []struct {
		fn     string
		tokens []string
	}{
		{"vulnerable_wide_local", []string{
			"callee=narrow_sink", "position=2", "target=int",
			"source=wide_declared", "origin=n", "operand=n",
		}},
		{"vulnerable_wide_arithmetic", []string{
			"source=wide_declared", "origin=n", "operand=n+1",
		}},
		{"vulnerable_wide_result", []string{
			"source=wide_result", "origin=wide_len",
		}},
		{"vulnerable_widened_cast", []string{
			"source=wide_cast", "origin=uint64_t",
		}},
		{"vulnerable_pointer_difference", []string{
			"source=pointer_difference", "origin=ptrdiff_t", "operand=start-base",
		}},
		{"vulnerable_pointer_difference_cast", []string{
			"source=pointer_difference", "origin=ptrdiff_t",
		}},
		{"vulnerable_wide_to_defined_callee", []string{
			"callee=narrow_total", "position=0", "target=int", "source=wide_declared",
		}},
		{"vulnerable_macro_forwarded", []string{
			"callee=append_fast", "position=2", "target=int", "source=wide_declared", "origin=n",
		}},
		{"vulnerable_macro_pointer_difference", []string{
			"callee=append_fast", "position=2", "target=int",
			"source=pointer_difference", "origin=ptrdiff_t", "operand=start-base",
		}},
		{"vulnerable_macro_computed_argument", []string{
			"callee=append_fast", "position=2", "target=int", "source=wide_declared", "operand=n+1",
		}},
		{"vulnerable_macro_position_remapped", []string{
			"callee=forward_swapped", "position=0", "target=int", "source=wide_declared",
		}},
	} {
		for _, token := range fire.tokens {
			if !cFuncHasAnalysisToken(prog.Modules[0].Body, fire.fn, path, token) {
				t.Fatalf("%s missing narrow call argument token %q: %#v", fire.fn, token, prog.Modules[0].Body)
			}
		}
	}
	for _, quiet := range []string{
		"fixed_explicit_cast",
		"fixed_wide_parameter",
		"fixed_narrow_local",
		"fixed_member_width_unknown",
		"fixed_pointer_minus_integer",
		"fixed_callee_this_file_does_not_type",
		"fixed_macro_explicit_cast",
		"fixed_macro_comment_only",
	} {
		if cFuncHasAnalysisPath(prog.Modules[0].Body, quiet, path) {
			t.Fatalf("%s should not emit a narrow call argument observation: %#v", quiet, prog.Modules[0].Body)
		}
	}
}

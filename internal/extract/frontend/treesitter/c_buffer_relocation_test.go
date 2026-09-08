package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccBufferRelocationObs runs the buffer-relocation observation over one
// translation unit and returns the emitted facts as
// "copy=..;destination=..;origin=..;displacement=..;applied=.." text. The file
// name picks the grammar, so a .cpp case reads the C++ spellings.
func ccBufferRelocationObs(t *testing.T, file, src string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(file, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func([]nir.Stmt)
	walk = func(body []nir.Stmt) {
		for _, st := range body {
			switch s := st.(type) {
			case nir.ClassDef:
				walk(s.Body)
			case nir.FuncDef:
				walk(s.Body)
			case nir.ExprStmt:
				call, ok := s.Value.(nir.Call)
				if !ok || call.Path != "analysis.buffer_relocation.displacement_not_copy_origin" {
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
	}
	walk(prog.Modules[0].Body)
	return out
}

// scannerFill is re2c's refill routine reduced to the shape the CVE turns on:
// the grown-buffer branch copies the live lexeme to a fresh block and rebases
// every saved position by one displacement. %s is the pointer that
// displacement subtracts.
const scannerFill = `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define YYMAXFILL 16

struct Scanner {
  size_t BSIZE;
  char *bot, *lim, *cur, *tok;

  bool fill(size_t need);
  void shift_ptrs_and_fpos(ptrdiff_t offs);
  bool read(size_t want);
};

bool Scanner::fill(size_t need) {
  size_t free = (size_t)(tok - bot);
  size_t copy = (size_t)(lim - tok);

  if (free >= need) {
    memmove(bot, tok, copy);
    shift_ptrs_and_fpos(-(ptrdiff_t)free);
  } else {
    BSIZE += need;
    char *buf = new char[BSIZE + YYMAXFILL];
    memmove(buf, tok, copy);
    shift_ptrs_and_fpos(buf - %s);
    delete[] bot;
    bot = buf;
    free = BSIZE - copy;
  }
  return read(free);
}
`

func TestCBufferRelocationOriginObservations(t *testing.T) {
	// The shipped re2c refill: the copy carried the bytes from tok, and the
	// displacement handed to shift_ptrs_and_fpos subtracts bot, the base of
	// the buffer the copy did not start from.
	got := ccBufferRelocationObs(t, "scanner.cpp", strings.Replace(scannerFill, "%s", "bot", 1))
	want := "copy=memmove;destination=buf;origin=tok;displacement=buf-bot;applied=shift_ptrs_and_fpos"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("vulnerable refill: got %q want [%q]", got, want)
	}

	// The fix changes that one operand and nothing else. The displacement is
	// then the copy's own destination - source, and the fact clears.
	if got := ccBufferRelocationObs(t, "scanner.cpp", strings.Replace(scannerFill, "%s", "tok", 1)); len(got) != 0 {
		t.Fatalf("patched refill: got %q want none", got)
	}
}

// TestCBufferRelocationOriginNames is the same relocation under names nothing
// in the engine knows, through struct members rather than locals, and with the
// displacement bound to a variable before it is passed: the fact has to hold
// on the shape, not on re2c's identifiers.
func TestCBufferRelocationOriginNames(t *testing.T) {
	const src = `#include <stdlib.h>
#include <string.h>

struct reader {
  size_t cap;
  char *base, *fill_at, *token_at;
};

static void reposition(struct reader *r, long delta) {
  r->fill_at += delta;
  r->token_at += delta;
}

static int top_up(struct reader *r, size_t least) {
  size_t held = (size_t)(r->fill_at - r->token_at);
  char *grown = malloc(r->cap + least);
  if (!grown) return 0;

  memmove(grown, r->token_at, held);
  %s
  free(r->base);
  r->base = grown;
  return 1;
}
`
	direct := ccBufferRelocationObs(t, "buffer.c", strings.Replace(src, "%s", "reposition(r, grown - r->base);", 1))
	want := "copy=memmove;destination=grown;origin=r.token_at;displacement=grown-r->base;applied=reposition"
	if len(direct) != 1 || direct[0] != want {
		t.Fatalf("member-named relocation: got %q want [%q]", direct, want)
	}

	bound := ccBufferRelocationObs(t, "buffer.c", strings.Replace(src, "%s", "long delta = grown - r->base;\n  reposition(r, delta);", 1))
	wantBound := "copy=memmove;destination=grown;origin=r.token_at;displacement=grown-r->base;applied=reposition"
	if len(bound) != 1 || bound[0] != wantBound {
		t.Fatalf("relocation through a bound displacement: got %q want [%q]", bound, wantBound)
	}

	fixed := ccBufferRelocationObs(t, "buffer.c", strings.Replace(src, "%s", "reposition(r, grown - r->token_at);", 1))
	if len(fixed) != 0 {
		t.Fatalf("relocation from the copy's own origin: got %q want none", fixed)
	}
}

// TestCBufferRelocationOriginQuiet holds the boundaries: a difference that
// never reaches a call, one whose minuend is not a copy destination, a copy's
// own size argument, and a second copy into the same destination that did read
// from the subtracted pointer are all silent.
func TestCBufferRelocationOriginQuiet(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"difference never handed anywhere", `
  memmove(buf, tok, n);
  ptrdiff_t offs = buf - bot;
  (void) offs;`},
		{"minuend is not a copy destination", `
  memmove(buf, tok, n);
  shift(lim - bot);`},
		{"the copy's own size argument", `
  memmove(buf, tok, lim - bot);`},
		{"another copy did start from it", `
  memmove(buf, tok, n);
  memmove(buf, bot, n);
  shift(buf - bot);`},
		{"no raw copy at all", `
  shift(buf - bot);`},
		{"the difference is read before the copy", `
  shift(buf - bot);
  memmove(buf, tok, n);`},
		{"the subtracted operand is a declared count", `
  size_t written = 4;
  memmove(buf, tok, n);
  shift(buf - written);`},
		{"the destination was written from the subtracted pointer", `
  char *cursor = bot;
  memmove(cursor, tok, n);
  shift(cursor - bot);`},
		{"one write put the same pointer in both names", `
  char *cursor;
  cursor = bot = tok;
  memmove(cursor, lim, n);
  shift(cursor - bot);`},
	} {
		src := `#include <string.h>
#include <stddef.h>
extern void shift(ptrdiff_t offs);
void relocate(char *buf, char *bot, char *tok, char *lim, size_t n) {` + tc.body + `
}
`
		if got := ccBufferRelocationObs(t, "quiet.c", src); len(got) != 0 {
			t.Fatalf("%s: got %q want none", tc.name, got)
		}
	}
}

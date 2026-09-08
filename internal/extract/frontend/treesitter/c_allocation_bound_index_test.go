package treesitter

import (
	"strings"
	"testing"
)

// TestIndexWithinAllocationIsInBounds covers the terminator idiom: the array is
// allocated with one element more than the index names, so the write lands on
// the last allocated slot and no comparison is needed to place it in bounds.
func TestIndexWithinAllocationIsInBounds(t *testing.T) {
	inBounds := map[string]string{
		"malloc sized by the index plus one, times the element size": `
#include <stdlib.h>
struct holder { char **items; unsigned count; };
void fill(struct holder *h) {
  h->items = malloc((h->count + 1) * sizeof(char *));
  h->items[h->count] = 0;
}
`,
		"calloc counting the index plus one elements": `
#include <stdlib.h>
struct holder { char **items; unsigned count; };
void fill(struct holder *h) {
  h->items = calloc(h->count + 1, sizeof(char *));
  h->items[h->count] = 0;
}
`,
		"malloc counting bytes for a byte buffer": `
#include <stdlib.h>
struct buf { char *p; unsigned len; };
void terminate(struct buf *b) {
  b->p = malloc(b->len + 1);
  b->p[b->len] = 0;
}
`,
		"the allocation stands after the write": `
#include <stdlib.h>
struct holder { char **items; unsigned count; };
void fill(struct holder *h) {
  h->items[h->count] = 0;
  h->items = malloc((h->count + 1) * sizeof(char *));
}
`,
	}
	for name, src := range inBounds {
		for _, file := range []string{"term.c", "term.cpp"} {
			if got := ccFieldDerivedIndexFacts(t, file, src); len(got) != 0 {
				t.Fatalf("%s (%s): got %q want no fact", name, file, got)
			}
		}
	}

	// The C++ spelling of the same idiom, with the cast the C compiler does not
	// need and the length read through a method.
	const cppTerminator = `
#include <cstdlib>
#include <vector>
struct item { int v; };
struct holder { item **items; };
void fill(struct holder *h, std::vector<item> &src) {
  h->items = static_cast<item **>(malloc((src.size() + 1) * sizeof(item *)));
  h->items[src.size()] = nullptr;
}
`
	if got := ccFieldDerivedIndexFacts(t, "term.cpp", cppTerminator); len(got) != 0 {
		t.Fatalf("cpp terminator: got %q want no fact", got)
	}

	// new[] states its element count the same way.
	const cppNew = `
struct buf { char *p; unsigned len; };
void terminate(struct buf *b) {
  b->p = new char[b->len + 1];
  b->p[b->len] = 0;
}
`
	if got := ccFieldDerivedIndexFacts(t, "term.cpp", cppNew); len(got) != 0 {
		t.Fatalf("cpp new[]: got %q want no fact", got)
	}
}

// TestIndexOutsideAllocationStillReports pins the other direction: an index the
// allocation does not reserve a slot for stays reported, so the allocation
// reading does not swallow the unchecked field-derived index the rule exists
// for.
func TestIndexOutsideAllocationStillReports(t *testing.T) {
	reported := map[string]string{
		"index one past the last allocated element": `
#include <stdlib.h>
struct holder { char **items; unsigned count; };
void fill(struct holder *h) {
  h->items = malloc((h->count + 1) * sizeof(char *));
  h->items[h->count + 1] = 0;
}
`,
		"index equal to the allocated element count": `
#include <stdlib.h>
struct holder { char **items; unsigned count; };
void fill(struct holder *h) {
  h->items = malloc(h->count * sizeof(char *));
  h->items[h->count] = 0;
}
`,
		"the allocation sizes a different array": `
#include <stdlib.h>
struct holder { char **items; char **other; unsigned count; };
void fill(struct holder *h) {
  h->other = malloc((h->count + 1) * sizeof(char *));
  h->items[h->count] = 0;
}
`,
		"a field index with no allocation to relate it to": `
struct sec { unsigned char *content; unsigned long offset; };
unsigned char read_at(struct sec *s) {
  return s->content[s->offset];
}
`,
		"the allocation is sized by an unrelated field": `
#include <stdlib.h>
struct holder { char **items; unsigned count; unsigned cap; };
void fill(struct holder *h) {
  h->items = malloc((h->cap + 1) * sizeof(char *));
  h->items[h->count] = 0;
}
`,
	}
	for name, src := range reported {
		for _, file := range []string{"term.c", "term.cpp"} {
			got := ccFieldDerivedIndexFacts(t, file, src)
			if len(got) != 1 {
				t.Fatalf("%s (%s): got %q want exactly one field-derived fact", name, file, got)
			}
			if !strings.Contains(got[0], "guard=missing_upper_bound") {
				t.Fatalf("%s (%s): fact %q is not the unguarded one", name, file, got[0])
			}
		}
	}
}

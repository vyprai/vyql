package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccFieldAliasObs runs the field-alias invalidation observation over one
// translation unit and returns the emitted facts as
// "alias=..;field=..;capture=..;reallocated=..;allocator=..;use=.." text.
func ccFieldAliasObs(t *testing.T, file, src string) []string {
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
				if !ok || call.Path != "analysis.lifetime.field_alias_stale_after_realloc" {
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

// arraySubscr is micropython's slice-assignment path (py/objarray.c) reduced to
// the shape CVE-2024-8947 turns on: the routine reads the source array's items
// pointer, then grows its own items with m_renew -- which may hand back a
// different block and release the old one -- and copies out of the pointer it
// read before the move. `bytearray[a:b] = bytearray` makes the two arrays one
// object, so the pointer the copy reads from is the block m_renew released.
//
// dest_items is the control inside the same routine: it is read out of the same
// member, and the routine takes it from the member again after the m_renew.
const arraySubscr = `
static mp_obj_t array_subscr(mp_obj_t self_in, mp_obj_t index_in, mp_obj_t value) {
    mp_obj_array_t *o = MP_OBJ_TO_PTR(self_in);
    mp_bound_slice_t slice;
    size_t src_len;
    void *src_items;
    size_t item_sz = mp_binary_get_size('@', o->typecode & TYPECODE_MASK, NULL);

    if (mp_obj_is_obj(value)) {
        mp_obj_array_t *src_slice = MP_OBJ_TO_PTR(value);
        src_len = src_slice->len;
        src_items = src_slice->items;
    } else {
        mp_buffer_info_t bufinfo;
        mp_get_buffer_raise(value, &bufinfo, MP_BUFFER_READ);
        src_len = bufinfo.len;
        src_items = bufinfo.buf;
    }

    mp_int_t len_adj = src_len - (slice.stop - slice.start);
    uint8_t *dest_items = o->items;
    if (len_adj > 0) {
        if ((size_t)len_adj > o->free) {
            o->items = m_renew(byte, o->items, (o->len + o->free) * item_sz, (o->len + len_adj) * item_sz);
            o->free = len_adj;
%s
            dest_items = o->items;
        }
        mp_seq_replace_slice_grow_inplace(dest_items, o->len,
            slice.start, slice.stop, src_items, src_len, len_adj, item_sz);
    }
    return mp_const_none;
}
`

func TestCFieldAliasStaleAfterRealloc(t *testing.T) {
	// The shipped routine: src_items was read out of ->items before m_renew
	// moved ->items, and mp_seq_replace_slice_grow_inplace reads it after.
	got := ccFieldAliasObs(t, "objarray.c", strings.Replace(arraySubscr, "%s", "", 1))
	want := "alias=src_items;field=items;capture=src_slice.items;reallocated=o.items;allocator=m_renew;use=mp_seq_replace_slice_grow_inplace"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("shipped slice assign: got %q want [%q]", got, want)
	}

	// The fix takes src_items from the member again after the move, exactly as
	// the routine already did for dest_items, and the fact clears.
	refreshed := strings.Replace(arraySubscr, "%s", `
            if (src_items == dest_items) {
                src_items = o->items;
            }`, 1)
	if got := ccFieldAliasObs(t, "objarray.c", refreshed); len(got) != 0 {
		t.Fatalf("patched slice assign: got %q want none", got)
	}
}

// TestCFieldAliasStaleAfterReallocNames is the same relation under names
// nothing in the engine knows, with the standard allocator and a dereference
// rather than a call for the stale read: the fact has to hold on the ordering,
// not on micropython's identifiers.
func TestCFieldAliasStaleAfterReallocNames(t *testing.T) {
	const src = `#include <stdlib.h>
#include <string.h>

struct vec {
  char *data;
  size_t len, cap;
};

int vec_push(struct vec *v, struct vec *other, size_t n) {
  char *tail = other->data;
  if (v->cap < v->len + n) {
    v->data = realloc(v->data, v->len + n);
    if (v->data == NULL) return 0;
    v->cap = v->len + n;
  }
  %s
  return 1;
}
`
	stale := ccFieldAliasObs(t, "vec.c", strings.Replace(src, "%s", "memcpy(v->data + v->len, tail, n);", 1))
	want := "alias=tail;field=data;capture=other.data;reallocated=v.data;allocator=realloc;use=memcpy"
	if len(stale) != 1 || stale[0] != want {
		t.Fatalf("member-named relocation: got %q want [%q]", stale, want)
	}

	// the same routine through the C++ grammar: the shape is the frontend's,
	// not one grammar's.
	cpp := ccFieldAliasObs(t, "vec.cpp", strings.Replace(src, "%s", "memcpy(v->data + v->len, tail, n);", 1))
	if len(cpp) != 1 || cpp[0] != want {
		t.Fatalf("C++ spelling: got %q want [%q]", cpp, want)
	}

	deref := ccFieldAliasObs(t, "vec.c", strings.Replace(src, "%s", "v->data[0] = *tail;", 1))
	wantDeref := "alias=tail;field=data;capture=other.data;reallocated=v.data;allocator=realloc;use=dereference"
	if len(deref) != 1 || deref[0] != wantDeref {
		t.Fatalf("stale dereference: got %q want [%q]", deref, wantDeref)
	}

	fixed := ccFieldAliasObs(t, "vec.c", strings.Replace(src, "%s", "tail = other->data;\n  memcpy(v->data + v->len, tail, n);", 1))
	if len(fixed) != 0 {
		t.Fatalf("re-read member: got %q want none", fixed)
	}
}

// TestCFieldAliasStaleAfterReallocQuiet holds the boundaries: an ordering that
// runs the other way, a member that was never reallocated, an allocation that
// did not read the block it replaces, a local rebound on the way to the
// allocator, and a captured count rather than a pointer are all silent.
func TestCFieldAliasStaleAfterReallocQuiet(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"the read comes before the reallocation", `
  char *tail = v->data;
  memcpy(dst, tail, n);
  v->data = realloc(v->data, n);`},
		{"the local is captured after the move", `
  v->data = realloc(v->data, n);
  char *tail = v->data;
  memcpy(dst, tail, n);`},
		{"another member was reallocated", `
  char *tail = v->data;
  v->scratch = realloc(v->scratch, n);
  memcpy(dst, tail, n);`},
		{"the allocation did not read the old block", `
  char *tail = v->data;
  v->data = malloc(n);
  memcpy(dst, tail, n);`},
		{"a fresh block is stored beside the member", `
  char *tail = v->data;
  char *grown = realloc(v->data, n);
  memcpy(dst, tail, n);`},
		{"the local is rebound before the allocator", `
  char *tail = v->data;
  tail = dst;
  v->data = realloc(v->data, n);
  memcpy(dst, tail, n);`},
		{"the local is put back before it is read", `
  char *tail = v->data;
  v->data = realloc(v->data, n);
  tail = v->data;
  memcpy(dst, tail, n);`},
		{"the capture is a count, not a pointer", `
  size_t held = v->len;
  v->len = realloc(v->len, n);
  memcpy(dst, held, n);`},
		{"nothing is read after the move", `
  char *tail = v->data;
  v->data = realloc(v->data, n);
  v->cap = n;`},
		{"only the member itself is read after the move", `
  char *tail = v->data;
  v->data = realloc(v->data, n);
  memcpy(dst, v->data, n);
  (void) tail;`},
	} {
		src := `#include <stdlib.h>
#include <string.h>
struct vec { char *data, *scratch; size_t len, cap; };
void grow(struct vec *v, char *dst, size_t n) {` + tc.body + `
}
`
		if got := ccFieldAliasObs(t, "quiet.c", src); len(got) != 0 {
			t.Fatalf("%s: got %q want none", tc.name, got)
		}
	}
}

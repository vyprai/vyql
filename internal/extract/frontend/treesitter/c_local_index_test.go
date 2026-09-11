package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccIndexAccessFacts runs the index-access observation over one C or C++
// source and returns every field-derived fact as
// `<variant>;<token>;<token>...`, whatever bound state the access ended in: an
// access with no bound lands on analysis.index.field_derived_missing_upper_bound
// and one with a bound on analysis.index.access, and the index has to be
// readable in both.
func ccIndexAccessFacts(t *testing.T, name, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(name, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{file}, dir)
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
			if !ok || !strings.HasPrefix(call.Path, "analysis.index.") {
				continue
			}
			parts := []string{strings.TrimPrefix(call.Path, "analysis.index.")}
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

// The observation this file pins is the one dragonfly's Traverse turns on: the
// subscripted index is a local (`sid`) holding what a field read produced, and
// the only sanity check in sight is on a different field of the same cursor.

// TestLocalFieldDerivedIndexIsObserved covers the local half: an index computed
// into a local variable off a field read is the field-derived index it was
// computed from, and is observed like the direct `s->idx` subscript is -- with
// a bound when one bounds the local and without one when it does not.
func TestLocalFieldDerivedIndexIsObserved(t *testing.T) {
	const unbounded = `
struct cursor { unsigned segment_id; unsigned bucket_id; };
struct table { char *segments[8]; unsigned bucket_count; unsigned segment_count; };

void traverse(struct cursor *c, struct table *t) {
  if (c->bucket_id >= t->bucket_count) return;
  unsigned sid = c->segment_id;
  t->segments[sid] = 0;
}
`
	for _, file := range []string{"dash.c", "dash.cpp"} {
		got := ccIndexAccessFacts(t, file, unbounded)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{
			"field_derived_missing_upper_bound", "index_kind=field_derived",
			"guard=missing_upper_bound", "index=sid", "origin=c->segment_id",
		} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}

	const bounded = `
struct cursor { unsigned segment_id; };
struct table { char *segments[8]; unsigned segment_count; };

void traverse(struct cursor *c, struct table *t) {
  unsigned sid = c->segment_id;
  if (sid >= t->segment_count) return;
  t->segments[sid] = 0;
}
`
	for _, file := range []string{"dash.c", "dash.cpp"} {
		got := ccIndexAccessFacts(t, file, bounded)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{
			"index_kind=field_derived", "guard=upper_bound", "index=sid",
			"origin=c->segment_id", "bound=t->segment_count", "bound_side=before",
		} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}
}

// TestLocalFieldDerivedIndexBoundSide pins the side the bound stands on: the
// same comparison credited as a bound reads differently before the access,
// where it protects it, and after it, where it is too late.
func TestLocalFieldDerivedIndexBoundSide(t *testing.T) {
	const late = `
struct cursor { unsigned segment_id; };
struct table { char *segments[8]; unsigned segment_count; };

void traverse(struct cursor *c, struct table *t) {
  unsigned sid = c->segment_id;
  t->segments[sid] = 0;
  if (sid < t->segment_count) sid++;
}
`
	for _, file := range []string{"dash.c", "dash.cpp"} {
		got := ccIndexAccessFacts(t, file, late)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{
			"guard=upper_bound", "bound=t->segment_count", "bound_side=after",
		} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}
}

// TestLocalFieldDerivedIndexScope keeps the widening on the field-derived side
// of the line the direct path has always held: a local read off a parameter or
// a constant is not field-derived, and a store only reaches the accesses that
// follow it.
func TestLocalFieldDerivedIndexScope(t *testing.T) {
	unrelated := map[string]string{
		"read off a parameter": `
struct table { char *segments[8]; };
void traverse(struct table *t, unsigned n) {
  unsigned sid = n;
  t->segments[sid] = 0;
}
`,
		"read off a constant": `
struct table { char *segments[8]; };
void traverse(struct table *t) {
  unsigned sid = 0;
  t->segments[sid] = 0;
}
`,
		"held by a parameter, never stored": `
struct table { char *segments[8]; };
void traverse(struct table *t, unsigned sid) {
  t->segments[sid] = 0;
}
`,
		"clamped off a field": `
#define MIN(a, b) ((a) < (b) ? (a) : (b))
struct gg { unsigned len; };
struct table { char buf[70]; };
void dissect(struct gg *gg, struct table *t, size_t offset) {
  size_t copy_len = MIN(gg->len - offset, 70);
  t->buf[copy_len] = 0;
}
`,
		"shifted off a field": `
struct gg { unsigned len; };
struct table { char buf[70]; };
void dissect(struct gg *gg, struct table *t) {
  size_t at = gg->len - 22;
  t->buf[at] = 0;
}
`,
		"field-derived store overwritten by a later one": `
struct cursor { unsigned segment_id; };
struct table { char *segments[8]; };
void traverse(struct cursor *c, struct table *t) {
  unsigned sid = c->segment_id;
  sid = 3;
  t->segments[sid] = 0;
}
`,
		"bound names a longer identifier": `
struct table { char *segments[8]; unsigned limit; };
void traverse(struct table *t, unsigned sid) {
  unsigned maxsid = t->limit;
  if (maxsid < 8) return;
  t->segments[sid] = 0;
}
`,
	}
	for name, src := range unrelated {
		for _, file := range []string{"dash.c", "dash.cpp"} {
			if got := ccIndexAccessFacts(t, file, src); len(got) != 0 {
				t.Fatalf("%s (%s): got %q want no fact", name, file, got)
			}
		}
	}

	const oneOfTwo = `
struct cursor { unsigned segment_id; };
struct table { char *segments[8]; };

void traverse(struct cursor *c, struct table *t) {
  unsigned sid = 0;
  t->segments[sid] = 0;
  sid = c->segment_id;
  t->segments[sid] = 0;
}
`
	for _, file := range []string{"dash.c", "dash.cpp"} {
		got := ccIndexAccessFacts(t, file, oneOfTwo)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want the one access the field-derived store reaches", file, got)
		}
		if !strings.Contains(got[0], "origin=c->segment_id") {
			t.Fatalf("%s: fact %q does not carry the store it was read from", file, got[0])
		}
	}
}

// TestLocalFieldDerivedIndexTemplateClose pins the C++ spelling a guard search
// for a bare name has to survive: a closed template reads in the compacted body
// as `unsigned>sid_map`, which is not `unsigned > sid`.
func TestLocalFieldDerivedIndexTemplateClose(t *testing.T) {
	const src = `
struct cursor { unsigned segment_id; };
struct table { char *segments[8]; };

void traverse(struct cursor *c, struct table *t) {
  std::map<const cursor*, unsigned> sid_map;
  unsigned sid = c->segment_id;
  t->segments[sid] = 0;
}
`
	got := ccIndexAccessFacts(t, "dash.cpp", src)
	if len(got) != 1 {
		t.Fatalf("got %q want exactly one field-derived fact", got)
	}
	if !strings.Contains(got[0], "guard=missing_upper_bound") {
		t.Fatalf("fact %q took the declared name for a bound", got[0])
	}
	if !strings.Contains(got[0], "origin=c->segment_id") {
		t.Fatalf("fact %q missing %q", got[0], "origin=c->segment_id")
	}
}

// TestDirectFieldDerivedIndexReportsItsBound pins the half the local path
// shares with the direct one: wherever the guard came from, the observation
// records the comparison it was credited from and which side of the access
// that comparison stands on.
func TestDirectFieldDerivedIndexReportsItsBound(t *testing.T) {
	const src = `
struct table { char *segments[8]; unsigned segment_count; unsigned cursor; };

void traverse(struct table *t) {
  if (t->cursor >= t->segment_count) return;
  t->segments[t->cursor] = 0;
}
`
	for _, file := range []string{"dash.c", "dash.cpp"} {
		got := ccIndexAccessFacts(t, file, src)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{
			"index_kind=field_derived", "guard=upper_bound",
			"index=t->cursor", "bound=t->segment_count", "bound_side=before",
		} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}
}

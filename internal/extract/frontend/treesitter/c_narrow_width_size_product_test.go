package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// The pair the observation exists to separate: the same allocation, the same
// product, spelled over fields the file declares at a 32-bit width and over
// fields it declares at size_t. Only the first reports.
func TestCNarrowWidthSizeProductObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "size_product.c")
	src := []byte(`
#include <stddef.h>

struct image
{
  char *pixels;
  unsigned int w, h;
};

struct image_fixed
{
  char *pixels;
  size_t w, h;
};

struct dims
{
  unsigned int w, h;
};

typedef struct
{
  unsigned int w, h;
} dims_t;

struct narrow16
{
  unsigned short w, h;
};

size_t total_pixels(void);

char *vulnerable_struct_fields(void)
{
  struct image *im = malloc(sizeof(struct image));
  unsigned int depth, bpp;
  depth = 4;
  im->w = 0x10000;
  im->h = 0x10000;
  bpp = 32;
  im->pixels = malloc(im->w * im->h * depth);
  return im->pixels;
}

char *fixed_size_t_fields(void)
{
  struct image_fixed *im = malloc(sizeof(struct image_fixed));
  size_t depth = 4;
  im->pixels = malloc(im->w * im->h * depth);
  return im->pixels;
}

char *fixed_widening_cast(struct image *im)
{
  unsigned int depth = 4;
  return malloc((size_t)im->w * im->h * depth);
}

char *fixed_widening_cast_at_declaration(struct image_fixed *im)
{
  return malloc(im->w * im->h);
}

char *vulnerable_value_members(void)
{
  struct dims d;
  d.w = d.h = 0x10000;
  return malloc(d.w * d.h);
}

char *vulnerable_typedef_members(void)
{
  dims_t d;
  d.w = d.h = 0x10000;
  return malloc(d.w * d.h);
}

char *vulnerable_literal_factor(struct image *im)
{
  return malloc(im->w * im->h * 4);
}

char *vulnerable_realloc_size(struct image *im, char *old)
{
  return realloc(old, im->w * im->h * 4);
}

char *quiet_sizeof_factor(struct image *im)
{
  return malloc(im->w * im->h * sizeof(unsigned int));
}

char *vulnerable_narrow_cast_factor(struct image *im)
{
  return malloc((uint32_t)im->w * im->h);
}

char *quiet_wide_result_factor(struct image *im)
{
  return malloc(total_pixels() * im->w * im->h);
}

char *quiet_undeclared_struct(struct header *h)
{
  return malloc(h->w * h->h);
}

char *quiet_single_narrow_field(struct image *im, unsigned long stride)
{
  return malloc(im->w * stride);
}

char *quiet_local_product(void)
{
  unsigned int a, b;
  a = b = 0x10000;
  return malloc(a * b);
}

char *quiet_counting_allocator(struct image *im)
{
  return calloc(im->w, im->h);
}

char *quiet_non_product_size(struct image *im)
{
  return malloc(im->w);
}

char *quiet_sum_around_product(struct image *im)
{
  return malloc(im->w * im->h + 1);
}

char *quiet_promoted_fields(struct narrow16 *im)
{
  return malloc(im->w * im->h);
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := "analysis.narrow_width.size_product"
	for _, fire := range []string{
		"vulnerable_struct_fields",
		"vulnerable_value_members",
		"vulnerable_typedef_members",
		"vulnerable_literal_factor",
		"vulnerable_realloc_size",
		"vulnerable_narrow_cast_factor",
	} {
		if !cFuncHasAnalysisToken(prog.Modules[0].Body, fire, path, "width=32bit_declared") {
			t.Fatalf("%s missing narrow-width size product observation: %#v", fire, prog.Modules[0].Body)
		}
	}
	for _, token := range []string{"alloc=malloc", "fields=im->w,im->h", "size=im->w*im->h*depth"} {
		if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable_struct_fields", path, token) {
			t.Fatalf("vulnerable_struct_fields missing size product token %q", token)
		}
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable_value_members", path, "fields=d.w,d.h") ||
		!cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable_typedef_members", path, "fields=d.w,d.h") {
		t.Fatalf("value and typedef member selections do not name their fields: %#v", prog.Modules[0].Body)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable_literal_factor", path, "size=im->w*im->h*4") {
		t.Fatalf("vulnerable_literal_factor does not name its size expression")
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable_realloc_size", path, "alloc=realloc") {
		t.Fatalf("vulnerable_realloc_size does not name the allocator that takes the size")
	}
	for _, quiet := range []string{
		"fixed_size_t_fields",
		"fixed_widening_cast",
		"fixed_widening_cast_at_declaration",
		"quiet_sizeof_factor",
		"quiet_wide_result_factor",
		"quiet_undeclared_struct",
		"quiet_single_narrow_field",
		"quiet_local_product",
		"quiet_counting_allocator",
		"quiet_non_product_size",
		"quiet_sum_around_product",
		"quiet_promoted_fields",
	} {
		if cFuncHasAnalysisToken(prog.Modules[0].Body, quiet, path, "width=32bit_declared") {
			t.Fatalf("%s should not emit a narrow-width size product observation: %#v", quiet, prog.Modules[0].Body)
		}
	}
}

// The fact is a frontend observation, not a rule: it says the product is
// computed at a declared width, and says nothing about who chooses the
// operands. A guard above the allocation does not discharge it -- that
// judgement is the rule's.
func TestCNarrowWidthSizeProductIgnoresGuardAndReadsEverySite(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "guarded.c")
	src := []byte(`
struct image
{
  char *pixels;
  unsigned int w, h;
};

char *guarded_alloc(struct image *im)
{
  if (im->w > 0x10000 || im->h > 0x10000)
    return 0;
  return malloc(im->w * im->h * 4);
}

char *two_sites(struct image *im)
{
  char *a = malloc(im->w * im->h * 4);
  char *b = malloc(im->w * im->h);
  return a ? b : a;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := "analysis.narrow_width.size_product"
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "guarded_alloc", path, "width=32bit_declared") {
		t.Fatalf("guarded_alloc missing narrow-width size product observation: %#v", prog.Modules[0].Body)
	}
	sites := 0
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != "two_sites" {
			continue
		}
		for _, bodyStmt := range fn.Body {
			exprStmt, ok := bodyStmt.(nir.ExprStmt)
			if !ok {
				continue
			}
			if call, ok := exprStmt.Value.(nir.Call); ok && call.Path == path {
				sites++
			}
		}
	}
	if sites != 2 {
		t.Fatalf("two_sites emitted %d size product observations, want one per allocation site", sites)
	}
}

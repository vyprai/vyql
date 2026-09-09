package treesitter

import (
	"strings"
	"testing"
)

// A cast is what tells a reader that the pointer handed to a call is not the
// thing it was declared as. ccExprShape keeps a cast's target type, so
// `sscanf(line, "%31s", (char *)&cfg)` and `sscanf(line, "%31s", dst)` produce
// different call_arg_shape tokens and a binding can tell the converted pointer
// from the plain one, and read what width the code claims the destination has.
func TestCCastShapeKeepsTheTargetType(t *testing.T) {
	prog := extractCSource(t, "cfg.c", `
struct cfg { char name[8]; int flags; };

int load_cast(const char *line, struct cfg *out) {
  sscanf(line, "%31s", (char *)out);
  memcpy((unsigned char *)out, line, 32);
  return 0;
}

int load_plain(const char *line, char *dst) {
  sscanf(line, "%31s", dst);
  memcpy(dst, line, 32);
  return 0;
}
`)
	cast := cFuncContextTokens(prog.Modules[0].Body, "load_cast")
	for _, want := range []string{
		"call_arg_shape_at:sscanf:2:CAST(char*,ID)",
		"call_arg_shape:sscanf:CAST(char*,ID)",
		"call_arg_shape_at:memcpy:0:CAST(unsigned char*,ID)",
		"cast_shape:CAST(char*,ID)",
		"cast_shape:CAST(unsigned char*,ID)",
	} {
		if !strings.Contains(cast, want) {
			t.Fatalf("load_cast context missing %q; context=%q", want, cast)
		}
	}

	// The uncast call keeps the shape it always had, and carries no cast at
	// all: the two spellings are distinguishable, which is the whole point.
	plain := cFuncContextTokens(prog.Modules[0].Body, "load_plain")
	if !strings.Contains(plain, "call_arg_shape_at:sscanf:2:ID") {
		t.Fatalf("load_plain context missing the uncast argument shape; context=%q", plain)
	}
	if strings.Contains(plain, "CAST(") {
		t.Fatalf("load_plain context claims a cast; context=%q", plain)
	}
}

// A binding written before casts were spelled matched the operand's shape, so
// the cast-free spelling is emitted beside the cast one at every shape token
// rather than replaced by it.
func TestCCastShapeKeepsTheCastFreeSpellingBesideIt(t *testing.T) {
	prog := extractCSource(t, "compat.c", `
int copy(void *dst, const struct entry *ent, int n) {
  unsigned char *p = (unsigned char *)dst;
  memcpy((void *)p, ent->data, (size_t)n);
  p[(int)n] = 0;
  n = (int)ent->len;
  return ((int)n > 0);
}
`)
	tokens := cFuncContextTokens(prog.Modules[0].Body, "copy")
	for _, want := range []string{
		"call_arg_shape_at:memcpy:0:CAST(void*,ID)",
		"call_arg_shape_at:memcpy:0:ID",
		"call_arg_shape_at:memcpy:2:CAST(size_t,ID)",
		"call_arg_shape_at:memcpy:2:ID",
		"assign_shape:ID=CAST(unsigned char*,ID)",
		"assign_shape:ID=ID",
		"index_shape:ID[CAST(int,ID)]",
		"index_shape:ID[ID]",
		"assign_shape:ID=CAST(int,ID.FIELD)",
		"binary_shape:CAST(int,ID)>0",
		"binary_shape:ID>0",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("copy context missing %q; context=%q", want, tokens)
		}
	}
}

// A C++ named cast still parses as a call, but the C-style cast a C++ file
// writes over a pointer-to-pointer has to keep its depth: a cast to `void **`
// addresses something a cast to `void *` does not.
func TestCPPCastShapeKeepsPointerDepth(t *testing.T) {
	prog := extractCSource(t, "sock.cpp", `
int bind_any(int fd, struct sockaddr_in *addr, void *slot) {
  bind(fd, (struct sockaddr *)addr, sizeof(*addr));
  release((void **)&slot);
  return 0;
}
`)
	tokens := cFuncContextTokens(prog.Modules[0].Body, "bind_any")
	for _, want := range []string{
		"call_arg_shape_at:bind:1:CAST(struct sockaddr*,ID)",
		"call_arg_shape_at:release:0:CAST(void**,&ID)",
		"call_arg_shape_at:release:0:&ID",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("bind_any context missing %q; context=%q", want, tokens)
		}
	}
}

func TestCCastTypeShapeNormalizes(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"char *", "char*"},
		{"unsigned  char\n*", "unsigned char*"},
		{"const char *", "char*"},
		{"volatile unsigned long", "unsigned long"},
		{"void **", "void**"},
		{"struct sockaddr *", "struct sockaddr*"},
		{"uint8_t", "uint8_t"},
		{"char (*)[4]", "char(*)[4]"},
		{"", ""},
	} {
		if got := ccCastTypeShape(tc.raw); got != tc.want {
			t.Errorf("ccCastTypeShape(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

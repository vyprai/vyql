package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccOutParamStatusObs runs the out-parameter status observation over one C
// source and returns the emitted facts as "call=..;status=..;out=.." text.
func ccOutParamStatusObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "decode.c")
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
			if !ok || call.Path != "analysis.out_param.status_unchecked" {
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

// ccOutParamStatusCase asserts one fire/clear pair: the live source reads the
// call's output without ever consulting the status it returned, the cleared
// source differs only in consulting that status and must report nothing.
func ccOutParamStatusCase(t *testing.T, name, live, cleared string) {
	t.Helper()
	if got := ccOutParamStatusObs(t, live); len(got) != 1 {
		t.Fatalf("%s: live variant: got %q want exactly one fact", name, got)
	}
	if got := ccOutParamStatusObs(t, cleared); len(got) != 0 {
		t.Fatalf("%s: cleared variant: got %q want none", name, got)
	}
}

func TestCOutParamStatusObservations(t *testing.T) {
	// The idiom's own spelling: the status is captured, the output is read
	// through a member access inside the branch that tests only the
	// pointers' non-nullness, and the status is never named again before
	// the read. Consulting it in the same guard is the remediation.
	ccOutParamStatusCase(t, "bare null guard",
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (out && *out) {
    (*out)->cs = 18;
  }
  return ret;
}
`,
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (ret && out && *out) {
    (*out)->cs = 18;
  }
  return ret;
}
`)

	// The explicit spelling carries the same pairing, and the declaration
	// form captures the status too: whitespace must not fuse the declared
	// type into the variable's name, or the consult test would look for a
	// name nothing consults.
	ccOutParamStatusCase(t, "explicit null guard, inline declaration",
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ok = decode(c, out);
  if (out != NULL && *out != NULL) {
    (*out)->cs = 18;
  }
  return ok;
}
`,
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ok = decode(c, out);
  if (ok != 0 && out != NULL && *out != NULL) {
    (*out)->cs = 18;
  }
  return ok;
}
`)

	// A branch without braces still guards its single statement, so the
	// read inside it pairs with the guard the same way.
	ccOutParamStatusCase(t, "single-statement branch",
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (out && *out)
    (*out)->cs = 18;
  return ret;
}
`,
		`typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (ret && out && *out)
    (*out)->cs = 18;
  return ret;
}
`)
}

func TestCOutParamStatusObservationsCleared(t *testing.T) {
	// Consulting the status anywhere between the call and the read clears
	// the fact: a dominating branch that returns on failure carries the
	// same guarantee the guard's own conjunct would.
	for name, src := range map[string]string{
		"dominating early return": `typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (ret == 0) {
    return ret;
  }
  if (out && *out) {
    (*out)->cs = 18;
  }
  return ret;
}
`,
		"wrapper macro test": `typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (FAILED(ret)) {
    return ret;
  }
  if (out && *out) {
    (*out)->cs = 18;
  }
  return ret;
}
`,
	} {
		if got := ccOutParamStatusObs(t, src); len(got) != 0 {
			t.Fatalf("%s: got %q want none", name, got)
		}
	}

	// A cleanup that releases the handle instead of reading it does not
	// name a member, so the pairing the fact reports is absent: the branch
	// disposes of the output rather than trusting it.
	for name, src := range map[string]string{
		"release instead of read": `typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);
void img_release(img_t *image);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  if (out && *out) {
    img_release(*out);
    *out = 0;
  }
  return ret;
}
`,
		"no guard at all": `typedef int BOOL;
typedef struct { int cs; } img_t;
BOOL decode(void *c, img_t **out);

static int read_header(void *c, img_t **out)
{
  BOOL ret;
  ret = decode(c, out);
  return ret;
}
`,
	} {
		if got := ccOutParamStatusObs(t, src); len(got) != 0 {
			t.Fatalf("%s: got %q want none", name, got)
		}
	}
}

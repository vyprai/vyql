package treesitter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccInPlaceEffects extracts one C source and reports, per statement-position
// call, the argument positions the frontend marked as mutated in place, as
// "callee#index" text.
func ccInPlaceEffects(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "handler.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(stmts []nir.Stmt)
	walk = func(stmts []nir.Stmt) {
		for _, s := range stmts {
			switch st := s.(type) {
			case nir.FuncDef:
				walk(st.Body)
			case nir.Block:
				walk(st.Stmts)
			case nir.ExprStmt:
				call, ok := st.Value.(nir.Call)
				if !ok {
					continue
				}
				for _, eff := range call.Effects {
					if eff.InPlace {
						out = append(out, fmt.Sprintf("%s#%d", call.Path, eff.DestArg))
					}
				}
			}
		}
	}
	walk(prog.Modules[0].Body)
	sort.Strings(out)
	return out
}

// The shape the gap was found in (netdata's CVE-2018-18836 fix): a void
// function handed the buffer it rewrites. The call's result is discarded, so
// what the call is there for is what it wrote through that pointer, and the
// frontend has to say so — a later read of the variable reads the call's
// output, not the value the call was passed.
func TestCVoidPointerCallMarksItsArgumentMutatedInPlace(t *testing.T) {
	const src = `
void fix_google_param(char *s);

void handler(char *url) {
    char *responseHandler = url_param(url, "callback");
    fix_google_param(responseHandler);
    emit("%s(", responseHandler);
}
`
	got := ccInPlaceEffects(t, src)
	want := []string{"fix_google_param#0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The definition in the same translation unit types the callee just as well as
// a prototype does — netdata's own fix_google_param is `void` with no separate
// declaration — and every mutable pointer parameter is mutated, not only arg0.
func TestCVoidPointerCallTypedFromItsDefinition(t *testing.T) {
	const src = `
void scrub_pair(char *name, int flags, char *value) {
    name[0] = '_';
    value[0] = '_';
}

void handler(char *url) {
    char *name = url_param(url, "name");
    char *value = url_param(url, "value");
    scrub_pair(name, 0, value);
    emit("%s=%s", name, value);
}
`
	got := ccInPlaceEffects(t, src)
	want := []string{"scrub_pair#0", "scrub_pair#2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// The declaration is read straight out of the file text, so the layout it is
// written in must not change what it says. A name split from `void` or from its
// parameter list by tabs or newlines is the same declaration.
func TestCVoidPointerCallTypedAcrossLineBreaks(t *testing.T) {
	const src = "\nvoid\n\tfix_google_param\t(char *s);\n\nvoid handler(char *url) {\n" +
		"    char *p = url_param(url, \"callback\");\n" +
		"    fix_google_param(p);\n" +
		"    emit(\"%s(\", p);\n}\n"
	got := ccInPlaceEffects(t, src)
	want := []string{"fix_google_param#0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Each rejection is a declaration saying the call does not write there, or a
// call site naming storage no variable stands for. Typing this wrong is how a
// check gets credited with covering a read it never touched, so nothing that
// is not spelled out in the translation unit is assumed.
func TestCInPlaceMutationRejectsWhatTheDeclarationDoesNotSay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     string
		because string
	}{
		{
			name: "the callee has a result to read",
			src: `
int fix_google_param(char *s);
void handler(char *p) { fix_google_param(p); emit("%s", p); }
`,
			because: "a function with a result is not called only for what it wrote",
		},
		{
			name: "the parameter is const",
			src: `
void log_param(const char *s);
void handler(char *p) { log_param(p); emit("%s", p); }
`,
			because: "const is the declaration promising the callee does not write through it",
		},
		{
			name: "the parameter is passed by value",
			src: `
void note_count(int n);
void handler(int n) { note_count(n); emit("%d", n); }
`,
			because: "C cannot mutate a by-value argument",
		},
		{
			name: "the name runs on from another word",
			src: `
void avoid_google_param(char *s);
void handler(char *p) { google_param(p); emit("%s", p); }
`,
			because: "`avoid_google_param` declares avoid_google_param, not google_param",
		},
		{
			name: "the declaration is a function pointer",
			src: `
void (*fix_google_param)(char *s);
void handler(char *p) { fix_google_param(p); emit("%s", p); }
`,
			because: "a pointer variable is not a callee this file gives a shape",
		},
		{
			name: "the callee returns a pointer",
			src: `
void *fix_google_param(char *s);
void handler(char *p) { fix_google_param(p); emit("%s", p); }
`,
			because: "`void *f(` is a pointer-returning function, not a void one",
		},
		{
			name: "the callee is only declared in a header",
			src: `
void handler(char *p) { fix_google_param(p); emit("%s", p); }
`,
			because: "an untyped callee could be anything; this translation unit does not know",
		},
		{
			name: "the argument is not a bare identifier",
			src: `
void fix_google_param(char *s);
void handler(struct req *r) { fix_google_param(r->callback); emit("%s", r->callback); }
`,
			because: "no variable stands for that storage, so there is nothing to re-bind",
		},
		{
			name: "the result is used",
			src: `
void fix_google_param(char *s);
void handler(char *p) { char *q = fix_google_param(p); emit("%s", p); }
`,
			because: "a call whose value is read is not in statement position",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ccInPlaceEffects(t, tc.src); len(got) != 0 {
				t.Fatalf("got %v, want none: %s", got, tc.because)
			}
		})
	}
}

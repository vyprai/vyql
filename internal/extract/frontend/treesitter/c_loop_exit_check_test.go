package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccCursorLoopFacts runs the index-access observation over one C or C++
// source and returns the emitted facts whose callee path is path, one string
// of semicolon-joined constant arguments per fact.
func ccCursorLoopFacts(t *testing.T, name, src, path string) []string {
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
			if !ok || call.Path != path {
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

const ccCursorLoopExitPath = "analysis.cursor_loop.missing_exit_check"

// The gap's shape, reduced: a walk bounded in its own condition that also
// breaks out of its own body, then a cleanup that steps the cursor and stores
// through it as if the break were what ended the walk. On the exit that
// exhausted the bound the cursor already sits past the last element the range
// allows, so the step and the store both land outside it.
func TestCursorLoopMissingExitCheckFact(t *testing.T) {
	for name, src := range map[string]string{
		"cleanup steps the cursor": `
struct opt { unsigned char type; unsigned char len; };
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (p->type == 0) break;
		p += p->len;
	}
	p++;
	*p = 0;
}
`,
		"cleanup stores through the cursor": `
struct opt { unsigned char type; unsigned char len; };
void mark(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (p[0] == 1) break;
		p++;
	}
	p[0] = 2;
}
`,
		"cleanup steps and stores in one statement": `
struct opt { unsigned char type; };
void mark(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (p->type == 1) break;
		p++;
	}
	*p++ = 2;
}
`,
	} {
		for _, file := range []string{"opts.c", "opts.cpp"} {
			got := ccCursorLoopFacts(t, file, src, ccCursorLoopExitPath)
			if len(got) != 1 {
				t.Fatalf("%s (%s): got %q want exactly one fact", name, file, got)
			}
			for _, want := range []string{"cursor=p", "guard=missing_exit_test"} {
				if !strings.Contains(got[0], want) {
					t.Fatalf("%s (%s): fact %q missing %q", name, file, got[0], want)
				}
			}
		}
	}

	// The cleanup's own spelling rides in the fact, so a binding can name the
	// step apart from the store.
	advance := ccCursorLoopFacts(t, "step.c", `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	p++;
}
`, ccCursorLoopExitPath)
	if len(advance) != 1 || !strings.Contains(advance[0], "cleanup=advance") {
		t.Fatalf("step-only cleanup: got %q want cleanup=advance", advance)
	}
	write := ccCursorLoopFacts(t, "store.c", `
void mark(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	*p = 2;
}
`, ccCursorLoopExitPath)
	if len(write) != 1 || !strings.Contains(write[0], "cleanup=write_through") {
		t.Fatalf("store-only cleanup: got %q want cleanup=write_through", write)
	}
	both := ccCursorLoopFacts(t, "both.c", `
void mark(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	*p++ = 2;
}
`, ccCursorLoopExitPath)
	if len(both) != 1 || !strings.Contains(both[0], "cleanup=advance_and_write_through") {
		t.Fatalf("combined cleanup: got %q want cleanup=advance_and_write_through", both)
	}

	// The bound the loop states rides in the fact beside the cursor it bounds.
	bound := ccCursorLoopFacts(t, "bound.c", `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	p++;
}
`, ccCursorLoopExitPath)
	if len(bound) != 1 || !strings.Contains(bound[0], "bound=p<end") {
		t.Fatalf("fact %q does not carry the loop's bound", bound)
	}
}

// Every one of these is the same walk with the exit told apart, the cursor
// re-established, or one of the two exits absent -- the cases where where the
// loop left the cursor is not in question.
func TestCursorLoopMissingExitCheckSuppressed(t *testing.T) {
	suppressed := map[string]string{
		"exit tested against the bound": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	if (p == end) return;
	p++;
	*p = 0;
}
`,
		"exit tested by the match condition": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	if (*p != 0) return;
	p++;
	*p = 0;
}
`,
		"cursor asked where it is before it is touched": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	int done = (p == end);
	p++;
	*p = 0;
}
`,
		"cursor reset to a fresh base": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	p = buf;
	*p = 0;
}
`,
		"loop has no break of its own": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		p++;
	}
	p++;
	*p = 0;
}
`,
		"loop bounds its cursor nowhere in its condition": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (1) {
		if (*p == 0) break;
		p++;
	}
	p++;
	*p = 0;
}
`,
		"cleanup sits behind another branch": `
void terminate(unsigned char *buf, unsigned char *end, int flags) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	if (flags & 1) {
		p++;
		*p = 0;
	}
}
`,
		"first touch of the cursor is a read": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 0) break;
		p++;
	}
	unsigned char t = *p;
	*p = 0;
}
`,
	}
	for name, src := range suppressed {
		for _, file := range []string{"opts.c", "opts.cpp"} {
			if got := ccCursorLoopFacts(t, file, src, ccCursorLoopExitPath); len(got) != 0 {
				t.Fatalf("%s (%s): got %q want no fact", name, file, got)
			}
		}
	}
}

// A break that belongs to a switch or to a loop nested inside the walk does
// not give the walk a second exit of its own.
func TestCursorLoopMissingExitCheckIgnoresBorrowedBreaks(t *testing.T) {
	for name, src := range map[string]string{
		"break belongs to the switch": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		switch (*p) {
		case 0: break;
		default: p++;
		}
	}
	p++;
	*p = 0;
}
`,
		"break belongs to a nested loop": `
void terminate(unsigned char *buf, unsigned char *end) {
	unsigned char *p = buf;
	while (p < end) {
		if (*p == 1) {
			for (int i = 0; i < 4; i++) {
				if (p[i] == 0) break;
			}
		}
		p++;
	}
	p++;
	*p = 0;
}
`,
	} {
		for _, file := range []string{"opts.c", "opts.cpp"} {
			if got := ccCursorLoopFacts(t, file, src, ccCursorLoopExitPath); len(got) != 0 {
				t.Fatalf("%s (%s): got %q want no fact", name, file, got)
			}
		}
	}
}

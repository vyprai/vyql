package engine

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

const inPlaceCoverageRule = `
module test;
rule EscapedFlow {
  meta { id: "TEST-INPLACE", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.path coveredBy custom.Transform
}
`

func lowerCForEngineTest(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "web_api_v1.c")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// labelCCall labels every call node with this callee path.
func labelCCall(t *testing.T, g usg.Store, path string, l usg.Label) {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range all {
		if n.Prop("callee_path") != path {
			continue
		}
		if err := g.AddLabel(n.ID, l); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no node with callee path %q to label", path)
	}
}

// labelCCallArg labels the argument SLOT at index of every call with this callee
// path — where a check binding's `at args[i]` lands.
func labelCCallArg(t *testing.T, g usg.Store, path string, index int, l usg.Label) {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range all {
		if n.Prop("callee_path") != path {
			continue
		}
		in, err := g.InEdges(n.ID, "FLOWS")
		if err != nil {
			t.Fatal(err)
		}
		var args []usg.Node
		for _, e := range in {
			an, ok, err := g.GetNode(e.Src)
			if err != nil {
				t.Fatal(err)
			}
			if ok && an.Type == "code.Arg" {
				args = append(args, an)
			}
		}
		sort.Slice(args, func(i, j int) bool { return args[i].Order < args[j].Order })
		if index >= len(args) {
			continue
		}
		if err := g.AddLabel(args[index].ID, l); err != nil {
			t.Fatal(err)
		}
		found = true
	}
	if !found {
		t.Fatalf("no argument %d of a call to %q to label", index, path)
	}
}

// The gap end to end, on the shape it was found in (CVE-2018-18836, netdata's
// JSONP callback parameter): the fix adds fix_google_param, a void function
// that rewrites the bytes its argument points at. It returns nothing, so it
// never produced a new definition of the variable — the check landed on its own
// argument and the sink read the same pointer off the definition they shared,
// a sibling of the check rather than a successor of it. Both revisions reported
// identically and the fix had nothing to prove.
//
// The last case is the control: change the fix's declaration so this
// translation unit no longer says the call writes through that pointer, and the
// check covers nothing again. What discharges the read is the callee's declared
// shape, not the call being present.
func TestCInPlaceMutationLetsACheckCoverALaterRead(t *testing.T) {
	handler := func(decl, fix string) string {
		return `
typedef struct web_buffer BUFFER;
extern void buffer_sprintf(BUFFER *wb, const char *fmt, ...);
extern char *url_param(char *url, char *name);
` + decl + `

int web_client_api_request_v1_data(struct web_client *w, char *url) {
    char *responseHandler = url_param(url, "callback");
` + fix + `
    buffer_sprintf(w->response.data, "%s({status:'ok',table:", responseHandler);
    return 200;
}
`
	}
	const voidDecl = "void fix_google_param(char *s);"
	const intDecl = "int fix_google_param(char *s);"
	const fixCall = "    fix_google_param(responseHandler);"

	for _, tc := range []struct {
		name    string
		src     string
		fixed   bool
		want    int
		because string
	}{
		{
			name:    "the vulnerable revision",
			src:     handler(voidDecl, ""),
			want:    1,
			because: "nothing screens the callback before it is written into the response",
		},
		{
			name:    "the fixed revision",
			src:     handler(voidDecl, fixCall),
			fixed:   true,
			want:    0,
			because: "the read at the sink is what fix_google_param left in that buffer",
		},
		{
			name:    "a fix whose callee has a result to read",
			src:     handler(intDecl, fixCall),
			fixed:   true,
			want:    1,
			because: "a callee that returns a value is not typed as writing through its argument",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := lowerCForEngineTest(t, tc.src)
			labelCCall(t, g, "url_param", usg.Label{Concept: "custom.Input"})
			labelCCall(t, g, "buffer_sprintf", usg.Label{Concept: "custom.Target"})
			if tc.fixed {
				labelCCallArg(t, g, "fix_google_param", 0, usg.Label{Concept: "custom.Transform"})
			}
			if got := runRuleOnStore(t, inPlaceCoverageRule, g); got != tc.want {
				t.Fatalf("got %d findings, want %d: %s", got, tc.want, tc.because)
			}
		})
	}
}

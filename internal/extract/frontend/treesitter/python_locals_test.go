package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// pyLocalsLower extracts and lowers one Python file written at rel inside a temp target.
func pyLocalsLower(t *testing.T, rel, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// pyParamReachesCallArg reports whether the parameter named from reaches the argument of the
// call whose callee path is callee. The argument is the Arg node that flows into that call,
// which identifies it without relying on a loc the semantic-review nodes also carry.
func pyParamReachesCallArg(t *testing.T, g usg.Store, from, callee, loc string) bool {
	t.Helper()
	call := pyOneNode(t, g, "code.Call", "callee_path", callee)
	n, ok, err := g.GetNode(call)
	if err != nil || !ok {
		t.Fatalf("call %s disappeared from the graph", callee)
	}
	if n.Loc != loc {
		t.Fatalf("call %s is at %s, want %s", callee, n.Loc, loc)
	}
	ins, err := g.InEdges(call, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	var arg string
	for _, ed := range ins {
		src, ok, err := g.GetNode(ed.Src)
		if err != nil || !ok {
			t.Fatalf("call %s has an edge from a missing node", callee)
		}
		if src.Type == "code.Arg" {
			if arg != "" {
				t.Fatalf("call %s has several argument slots", callee)
			}
			arg = src.ID
		}
	}
	if arg == "" {
		t.Fatalf("call %s has no argument slot", callee)
	}
	reach, err := usg.BFS(g, pyOneNode(t, g, "code.Param", "name", from), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reach[arg]
}

// pyOneNode returns the id of the one node of typ carrying key=val, failing when there is
// none or several — several would make the question ambiguous.
func pyOneNode(t *testing.T, g usg.Store, typ, key, val string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Prop(key) == val {
			if found != "" {
				t.Fatalf("expected one %s with %s=%q, found several", typ, key, val)
			}
			found = id
		}
	}
	if found == "" {
		t.Fatalf("expected one %s with %s=%q, found none", typ, key, val)
	}
	return found
}

// The shape the gap names: a value that reaches the response writer only by being read back
// out of the local scope snapshot. MoinMoin's fckdialog.py formats its whole dialog page from
// `locals()`, so the pagename parameter reaches the HTML attribute slot through the mapping
// operand and through nothing else.
func TestPythonLocalsFormatOperandCarriesScopeTaint(t *testing.T) {
	src := `def link_dialog(request):
    name = request.values.get("pagename", "")
    request.write(u'''<input name="pagename" value="%(name)s">''' % locals())
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if !pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:3") {
		t.Fatalf("taint did not follow the %% locals() format operand to the response writer")
	}
}

// The subscript spelling of the same read: locals()[key] re-reads one binding out of the
// snapshot, and that read carries what the binding carried.
func TestPythonLocalsSubscriptCarriesScopeTaint(t *testing.T) {
	src := `def link_dialog(request):
    name = request.values.get("pagename", "")
    request.write(locals()["name"])
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if !pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:3") {
		t.Fatalf("taint did not follow the locals() subscript read to the response writer")
	}
}

// Precision: the snapshot is read by the keys the template names, not as the whole scope. A
// page that formats only a constant slot does not import the tainted binding sitting beside
// it — which is what keeps an escaped revision of the same page quiet.
func TestPythonLocalsFormatReadsOnlyTheSlotsTheTemplateNames(t *testing.T) {
	src := `def link_dialog(request):
    name = request.values.get("pagename", "")
    action = "fckdialog"
    request.write(u'''<form action=%(action)s method="GET">''' % locals())
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:4") {
		t.Fatalf("a template naming a constant slot read the tainted binding beside it")
	}
}

// The snapshot is taken at the call: a binding made after it is not in it, so re-assigning
// the name does not retroactively taint the page formatted earlier.
func TestPythonLocalsSnapshotExcludesLaterBindings(t *testing.T) {
	src := `def link_dialog(request):
    name = "safe"
    page = u'''<input value="%(name)s">''' % locals()
    name = request.values.get("pagename", "")
    request.write(page)
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:5") {
		t.Fatalf("a binding made after the snapshot reached a page formatted before it")
	}
}

// A positional conversion formats the snapshot itself rather than reading named slots, so the
// whole scope reaches the result — the sound fallback.
func TestPythonLocalsPositionalFormatCarriesTheWholeScope(t *testing.T) {
	src := `def link_dialog(request):
    name = request.values.get("pagename", "")
    request.write(u"<input>%s</input>" % locals())
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if !pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:3") {
		t.Fatalf("a positional format over the snapshot lost the scope's taint")
	}
}

// A `locals` the program declares is that function and not the builtin: it keeps its own
// dataflow and the scope is not tied to its result.
func TestPythonProgramDefinedLocalsIsNotTheSnapshot(t *testing.T) {
	src := `def locals():
    return {"name": "safe"}

def link_dialog(request):
    name = request.values.get("pagename", "")
    request.write(u'''<input value="%(name)s">''' % locals())
`
	g := pyLocalsLower(t, "fckdialog.py", src)
	if pyParamReachesCallArg(t, g, "request", "request.write", "fckdialog.py:6") {
		t.Fatalf("a program-defined locals() was read as the builtin snapshot")
	}
}

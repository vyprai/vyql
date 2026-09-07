package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A function-scope check — a control anchored on the synthetic
// analysis.function.context node — summarises a whole function, so it covers every sink
// in it without dominating anything. The summary is collected over the function's whole
// subtree, nested definitions included, so a call written inside a closure is credited to
// the function that encloses it. These tests pin the line between the two: a function
// with no function inside it keeps presence semantics, and a function that has one has to
// show the control touched the value that reaches the sink.

const scopeCoverageRule = `
module test;
rule ScopeCovered {
  meta { id: "TEST-SCOPE", severity: high }
  taint custom.Input -> custom.Target as sink
  unless sink.endpoint coveredBy custom.Transform
}
`

// lowerPython runs the real Python frontend and lowerer over one source file, which is
// what puts the analysis.function.context node and the "#fn" nested-function regions in
// the graph. Building either by hand would be building the thing under test.
func lowerPython(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.py")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	return g
}

// nodeWithCalleePath returns the id of the single node calling `path`. Failing when there
// is not exactly one keeps a fixture edit from silently labelling the wrong call.
func nodeWithCalleePath(t *testing.T, s usg.Store, path string) string {
	t.Helper()
	var hits []string
	nodes, err := s.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Prop("callee_path") == path {
			hits = append(hits, n.ID)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("callee_path %q: want 1 node, got %d", path, len(hits))
	}
	return hits[0]
}

func paramNode(t *testing.T, s usg.Store, fn, param string) string {
	t.Helper()
	want := fn + "#param#" + param
	nodes, err := s.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if strings.HasSuffix(n.ID, want) {
			return n.ID
		}
	}
	t.Fatalf("parameter node %q not found", want)
	return ""
}

// functionContextNode returns the analysis.function.context node whose summary names fn.
func functionContextNode(t *testing.T, s usg.Store, fn string) string {
	t.Helper()
	nodes, err := s.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		if strings.Contains(n.Prop("str_args"), "name="+fn+"\x00") {
			return n.ID
		}
	}
	t.Fatalf("analysis.function.context node for %q not found", fn)
	return ""
}

// The gap: `copy_component` contains a nested helper, and the only thing carrying the
// control is a call inside that helper, on that helper's own parameter. The value that
// reaches write_out never went near it, so the function-scope check must not cover the
// sink.
func TestFunctionScopeCheckDoesNotCoverAValueItNeverSaw(t *testing.T) {
	s := lowerPython(t, `
def copy_component(root, name):
    def render(child, base):
        return child.confine(base)

    target = root / name
    if target.is_file():
        write_out(target)
`)
	s.AddLabel(paramNode(t, s, "copy_component", "root"), usg.Label{Concept: "custom.Input"})
	s.AddLabel(nodeWithCalleePath(t, s, "write_out"), usg.Label{Concept: "custom.Target"})
	s.AddLabel(functionContextNode(t, s, "copy_component"), coverageLabel("custom.Transform", "endpoint"))
	s.AddLabel(nodeWithCalleePath(t, s, "child.confine"), coverageLabel("custom.Transform", "endpoint"))

	if c := compileEvalV2(t, scopeCoverageRule, s); c[0] != 1 {
		t.Fatalf("a control applied inside a nested helper, on that helper's own value, must not "+
			"cover a sink in the enclosing function: want 1 finding, got %d", c[0])
	}
}

// Nothing but the function-scope label — no concrete node carries the control anywhere.
// The nested helper means the summary may be describing the helper, so it cannot be taken
// as covering the sink. This is the shipped shape the gap was filed on: a function whose
// context facts pick up a nested closure's call.
func TestFunctionScopeCheckAloneDoesNotCoverAcrossANestedHelper(t *testing.T) {
	s := lowerPython(t, `
def copy_component(root, name):
    def render(child, base):
        return child.confine(base)

    target = root / name
    if target.is_file():
        write_out(target)
`)
	s.AddLabel(paramNode(t, s, "copy_component", "root"), usg.Label{Concept: "custom.Input"})
	s.AddLabel(nodeWithCalleePath(t, s, "write_out"), usg.Label{Concept: "custom.Target"})
	s.AddLabel(functionContextNode(t, s, "copy_component"), coverageLabel("custom.Transform", "endpoint"))

	if c := compileEvalV2(t, scopeCoverageRule, s); c[0] != 1 {
		t.Fatalf("a function-scope check over a function with a nested helper must not cover on its "+
			"own: want 1 finding, got %d", c[0])
	}
}

// The same function, with the control applied to the value that reaches the sink. The
// call sits inside a branch, so it dominates nothing and the dominance arm cannot be what
// suppresses; the function-scope check is, now that the control has touched the value.
func TestFunctionScopeCheckCoversTheValueItTouched(t *testing.T) {
	s := lowerPython(t, `
def copy_component(root, name, strict):
    def render(child, base):
        return child.name

    target = root / name
    if strict:
        confine(target, root)
    if target.is_file():
        write_out(target)
`)
	confine := nodeWithCalleePath(t, s, "confine")
	s.AddLabel(paramNode(t, s, "copy_component", "root"), usg.Label{Concept: "custom.Input"})
	s.AddLabel(nodeWithCalleePath(t, s, "write_out"), usg.Label{Concept: "custom.Target"})
	s.AddLabel(functionContextNode(t, s, "copy_component"), coverageLabel("custom.Transform", "endpoint"))
	s.AddLabel(confine, coverageLabel("custom.Transform", "endpoint"))

	if c := compileEvalV2(t, scopeCoverageRule, s); c[0] != 0 {
		t.Fatalf("a control applied to the value that reaches the sink must let the function-scope "+
			"check cover it: want 0 findings, got %d", c[0])
	}

	// Without the function-scope label the branch-local control covers nothing on its own,
	// which is what makes the assertion above about the scope check rather than about
	// dominance or flow coverage.
	bare := lowerPython(t, `
def copy_component(root, name, strict):
    def render(child, base):
        return child.name

    target = root / name
    if strict:
        confine(target, root)
    if target.is_file():
        write_out(target)
`)
	bare.AddLabel(paramNode(t, bare, "copy_component", "root"), usg.Label{Concept: "custom.Input"})
	bare.AddLabel(nodeWithCalleePath(t, bare, "write_out"), usg.Label{Concept: "custom.Target"})
	bare.AddLabel(nodeWithCalleePath(t, bare, "confine"), coverageLabel("custom.Transform", "endpoint"))
	if c := compileEvalV2(t, scopeCoverageRule, bare); c[0] != 1 {
		t.Fatalf("a control in one branch covers nothing by itself: want 1 finding, got %d", c[0])
	}
}

// A function with no function inside it: its summary is about its own body, so it keeps
// presence semantics with no concrete control node anywhere. This is the shape the
// function-scope check exists for — a containment comparison written as a bare statement
// inside a try block, which no call-anchored control can dominate.
func TestFunctionScopeCheckStillCoversAFunctionWithNoNestedHelper(t *testing.T) {
	s := lowerPython(t, `
def copy_component(root, name):
    target = root / name
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        raise Rejected()
    if target.is_file():
        write_out(target)
`)
	s.AddLabel(paramNode(t, s, "copy_component", "root"), usg.Label{Concept: "custom.Input"})
	s.AddLabel(nodeWithCalleePath(t, s, "write_out"), usg.Label{Concept: "custom.Target"})
	s.AddLabel(functionContextNode(t, s, "copy_component"), coverageLabel("custom.Transform", "endpoint"))

	if c := compileEvalV2(t, scopeCoverageRule, s); c[0] != 0 {
		t.Fatalf("a function-scope check over a function with no nested helper must keep covering "+
			"it: want 0 findings, got %d", c[0])
	}
}

func TestFunctionScopeChainReadsNestedFunctionRegions(t *testing.T) {
	for _, tc := range []struct {
		region string
		want   []string
	}{
		// a function at module level, and a branch inside it
		{"sample.py/fn2", []string{"sample.py/fn2"}},
		{"sample.py/fn2/if19.e/if20.t", []string{"sample.py/fn2"}},
		// a function defined at the top of another function's body: the lowerer joins the
		// two with "#fn", so the marker lands in the function's own segment
		{"sample.py/fn2#fn4", []string{"sample.py/fn2", "sample.py/fn2#fn4"}},
		{"sample.py/fn2#fn4/if5.t", []string{"sample.py/fn2", "sample.py/fn2#fn4"}},
		// a function defined inside a branch of another function
		{"sample.py/fn2/if9.t#fn11/if12.t", []string{"sample.py/fn2", "sample.py/fn2/if9.t#fn11"}},
		// three deep
		{"sample.py/fn2#fn4#fn7/if8.t", []string{"sample.py/fn2", "sample.py/fn2#fn4", "sample.py/fn2#fn4#fn7"}},
		// no function at all
		{"sample.py", nil},
		{"", nil},
	} {
		got := functionScopeChain(tc.region)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("functionScopeChain(%q) = %q, want %q", tc.region, got, tc.want)
		}
	}
}

// A check anchored on a function that is ITSELF nested keeps presence semantics when
// nothing is nested inside it: the gate is about the check's own function, not about
// every function in the file.
func TestFunctionScopeCheckInsideANestedHelperIsNotGated(t *testing.T) {
	s := lowerPython(t, `
def outer(root, name):
    def resolve_source(base, part):
        target = base / part
        if target.is_file():
            write_out(target)
        return target

    return resolve_source(root, name)
`)
	s.AddLabel(paramNode(t, s, "outer", "root"), usg.Label{Concept: "custom.Input"})
	s.AddLabel(nodeWithCalleePath(t, s, "write_out"), usg.Label{Concept: "custom.Target"})
	s.AddLabel(functionContextNode(t, s, "resolve_source"), coverageLabel("custom.Transform", "endpoint"))

	if c := compileEvalV2(t, scopeCoverageRule, s); c[0] != 0 {
		t.Fatalf("a function-scope check on a helper with nothing nested inside it must keep "+
			"covering its own sinks: want 0 findings, got %d", c[0])
	}
}

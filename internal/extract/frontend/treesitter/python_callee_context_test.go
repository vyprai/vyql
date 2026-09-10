package treesitter_test

import (
	"slices"
	"testing"
)

// A check a Python function delegates to a sibling helper has to be visible from
// the caller: deepdiff's fix screens delta path elements in a module-level
// `check_elem` called from every traversal point, so a function-scoped binding
// that reports the dunder walk must be able to require that the walk is the one
// whose elements are screened. Without the caller carrying what its callees do,
// the guarded and the unguarded traversal read identically.
func TestPythonDelegatedCheckReachesTheCallersContext(t *testing.T) {
	guarded := `
def check_elem(elem):
    if elem.startswith("__") and elem.endswith("__"):
        raise ValueError("Invalid path element: " + elem)


def get_nested_obj(obj, elems):
    for elem, act in elems:
        check_elem(elem)
        obj = getattr(obj, elem)
    return obj
`
	unguarded := `
def get_nested_obj(obj, elems):
    for elem, act in elems:
        obj = getattr(obj, elem)
    return obj
`
	tokens := pythonFunctionContextTokens(t, guarded, "get_nested_obj", "analysis.function.context")
	for _, want := range []string{
		"callee:call=startswith",
		"callee:call_path=elem.startswith",
		"callee:literal=__",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("delegated fact %q missing from get_nested_obj context; tokens=%q", want, tokens)
		}
	}
	// The screen's own name is already the caller's own call fact; what crosses
	// the hop is what the screen does. A builtin resolves to no helper body, so
	// it is attributed nothing.
	if slices.Contains(tokens, "callee:call=getattr") {
		t.Fatalf("a builtin callee was attributed delegated facts; tokens=%q", tokens)
	}

	tokens = pythonFunctionContextTokens(t, unguarded, "get_nested_obj", "analysis.function.context")
	for _, tok := range tokens {
		if len(tok) > 7 && tok[:7] == "callee:" {
			t.Fatalf("the traversal without the screen carried a delegated fact %q; tokens=%q", tok, tokens)
		}
	}
}

// Attribution is one hop: a helper's own helpers do not reach the caller, and a
// function's delegated facts stay keyed under `callee:` rather than merging into
// what the function itself does.
func TestPythonDelegatedAttributionIsOneHopAndKeyedApart(t *testing.T) {
	src := `
def deepest(v):
    return v.normalize('NFKC')


def middle(v):
    return deepest(v)


def outer(v):
    return middle(v)
`
	tokens := pythonFunctionContextTokens(t, src, "outer", "analysis.function.context")
	if !slices.Contains(tokens, "callee:call=deepest") {
		t.Fatalf("the one call the helper makes was not attributed; tokens=%q", tokens)
	}
	if slices.Contains(tokens, "callee:call=normalize") {
		t.Fatalf("attribution crossed a second hop; tokens=%q", tokens)
	}
	if slices.Contains(tokens, "call:deepest") {
		t.Fatalf("delegated facts were merged into the caller's own call facts; tokens=%q", tokens)
	}
}

// Names that resolve to nothing -- builtins, parameters, callees defined
// elsewhere -- must not spend the attribution budget, or a check delegated late
// in a long function is priced out by the calls before it.
func TestPythonDelegatedAttributionBudgetCountsResolvedHelpersOnly(t *testing.T) {
	src := `
def is_unsafe(elem):
    return elem.startswith("__")


def walk(node, a, b, c, d, e, f, g, h, i, j):
    a(node); b(node); c(node); d(node); e(node)
    f(node); g(node); h(node); i(node); j(node)
    if is_unsafe(node):
        return None
    return node.value
`
	tokens := pythonFunctionContextTokens(t, src, "walk", "analysis.function.context")
	if !slices.Contains(tokens, "callee:call=startswith") {
		t.Fatalf("the delegated check was priced out by unresolved callees; tokens=%q", tokens)
	}
}

// A callee the function received as a parameter is not the module-level helper
// that happens to carry the same name, and a method definition is not the
// module-scope name a bare call resolves to.
func TestPythonDelegatedAttributionSkipsShadowedCallees(t *testing.T) {
	src := `
def replace(v):
    return v.strip()


def run(replace):
    return replace('x')
`
	tokens := pythonFunctionContextTokens(t, src, "run", "analysis.function.context")
	for _, tok := range tokens {
		if tok == "callee:call=strip" {
			t.Fatalf("a parameter-shadowed callee was attributed the module helper's facts; tokens=%q", tokens)
		}
	}
}

// A name defined twice at module scope resolves to no body, and a function is
// never attributed its own facts through a recursive call.
func TestPythonDelegatedAttributionSkipsAmbiguousAndSelfCalls(t *testing.T) {
	src := `
def helper(v):
    return v.replace('a', 'b')


def helper(v):
    return v.strip()


def caller(v):
    return caller(helper(v))
`
	tokens := pythonFunctionContextTokens(t, src, "caller", "analysis.function.context")
	for _, tok := range tokens {
		if len(tok) > 7 && tok[:7] == "callee:" {
			t.Fatalf("an ambiguous helper name was attributed; tokens=%q", tokens)
		}
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// functionContextTokens returns the str_args of the analysis.function.context
// event lowered for the named function.
func functionContextTokens(t *testing.T, name, file, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "name="+name) {
			return tokens
		}
	}
	t.Fatalf("no analysis.function.context event for %s; nodes=%#v", name, nodes)
	return ""
}

// A check the renderer delegates to a sibling helper has to be visible from the
// renderer: the caller of a helper that tests the attribute name must not read
// like the caller of a helper that does not (CVE-2023-0410's shape).
func TestJavaScriptDelegatedCheckReachesTheCallersContext(t *testing.T) {
	const guarded = `
const unsafeAttrCharRE = /[>/="'\t\n\f ]/;
export const isSSRUnsafeAttr = (name) => {
  return unsafeAttrCharRE.test(name);
};

const escapeAttr = (s) => {
  return s.replace(/[&"]/g, (c) => (c === '&' ? '&amp;' : '&quot;'));
};

const renderNode = (node, stream) => {
  let openingElement = '<' + node.type;
  for (const prop of Object.keys(node.props)) {
    const attrName = prop;
    if (isSSRUnsafeAttr(attrName)) {
      continue;
    }
    openingElement += ' ' + attrName + '="' + escapeAttr(node.props[prop]) + '"';
  }
  stream.write(openingElement + '>');
};
`
	const unguarded = `
const escapeAttr = (s) => {
  return s.replace(/[&"]/g, (c) => (c === '&' ? '&amp;' : '&quot;'));
};

const renderNode = (node, stream) => {
  let openingElement = '<' + node.type;
  for (const prop of Object.keys(node.props)) {
    const attrName = prop;
    openingElement += ' ' + attrName + '="' + escapeAttr(node.props[prop]) + '"';
  }
  stream.write(openingElement + '>');
};
`
	got := functionContextTokens(t, "renderNode", "render-ssr.ts", guarded)
	for _, want := range []string{
		"callee:call=test",
		"callee:call_path=unsafeAttrCharRE.test",
		"callee:call=replace",
		"callee:literal=&amp;",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("delegated fact %q missing from renderNode context; tokens=%q", want, got)
		}
	}

	got = functionContextTokens(t, "renderNode", "render-ssr.ts", unguarded)
	if strings.Contains(got, "callee:call=test") {
		t.Fatalf("renderNode without the name check carried the delegated test fact; tokens=%q", got)
	}
	if !strings.Contains(got, "callee:call=replace") {
		t.Fatalf("the escape helper it does call was not attributed; tokens=%q", got)
	}
}

// Attribution is one hop: a helper's own helpers do not reach the caller, and a
// function's delegated facts stay keyed as delegated rather than merging into
// what the function itself does.
func TestJavaScriptDelegatedAttributionIsOneHopAndKeyedApart(t *testing.T) {
	got := functionContextTokens(t, "outer", "chain.js", `
function deepest(v) {
  return v.normalize('NFKC');
}

function middle(v) {
  return deepest(v);
}

function outer(v) {
  return middle(v);
}
`)
	if !strings.Contains(got, "callee:call=deepest") {
		t.Fatalf("the one call the helper makes was not attributed; tokens=%q", got)
	}
	if strings.Contains(got, "callee:call=normalize") {
		t.Fatalf("attribution crossed a second hop; tokens=%q", got)
	}
	if strings.Contains(got, "\x00call:normalize") || strings.Contains(got, "\x00call_path:deepest") {
		t.Fatalf("delegated facts were merged into the caller's own call facts; tokens=%q", got)
	}
}

// Names that resolve to nothing -- imports, parameters, callees defined
// elsewhere -- must not spend the attribution budget, or a check delegated
// late in a long function is priced out by the calls before it.
func TestJavaScriptDelegatedAttributionBudgetCountsResolvedHelpersOnly(t *testing.T) {
	got := functionContextTokens(t, "renderNode", "budget.ts", `
import { a, b, c, d, e, f, g, h, i, j } from './imported';

const isUnsafeAttr = (name) => {
  return unsafeAttrCharRE.test(name);
};

const renderNode = (node, stream) => {
  a(node); b(node); c(node); d(node); e(node);
  f(node); g(node); h(node); i(node); j(node);
  if (isUnsafeAttr(node.attr)) {
    return;
  }
  stream.write(node.attr);
};
`)
	if !strings.Contains(got, "callee:call=test") {
		t.Fatalf("the delegated check was priced out by unresolved callees; tokens=%q", got)
	}
}

// A callee the function received as a parameter is not the file-scope helper
// that happens to carry the same name.
func TestJavaScriptDelegatedAttributionSkipsParameterShadowedCallees(t *testing.T) {
	got := functionContextTokens(t, "run", "shadow.js", `
const cb = (v) => {
  return v.replace('a', 'b');
};

function run(cb) {
  return cb('x');
}
`)
	if strings.Contains(got, "callee:call=replace") {
		t.Fatalf("a parameter-shadowed callee was attributed the file-scope helper's facts; tokens=%q", got)
	}
}

// A name defined twice in the file resolves to no body, and a function is never
// attributed its own facts through a recursive call.
func TestJavaScriptDelegatedAttributionSkipsAmbiguousAndSelfCalls(t *testing.T) {
	got := functionContextTokens(t, "caller", "ambiguous.js", `
function helper(v) {
  return v.replace('a', 'b');
}

function helper(v) {
  return v.trim();
}

function caller(v) {
  return caller(helper(v));
}
`)
	if strings.Contains(got, "callee:") {
		t.Fatalf("an ambiguous helper name was attributed; tokens=%q", got)
	}
}

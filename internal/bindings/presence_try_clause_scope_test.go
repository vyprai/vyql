package bindings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A try's catch clause is its own control region but stays WRITTEN in the try: the
// lexical scope a node.scopeCall predicate reads from a clause node is the try's, so
// the try body's calls are in the handler's scope. This is the fact an auth-check
// fail-open rule pairs on — a handler that denies on the error path is credited only
// where its scope also holds the validation fetch the gate made — and it is exactly
// what splitting the regions would silently drop: with the handler's lexical scope
// read as its own region, the body's fetch falls out of it and the rule stops seeing
// the check its handler is supposed to answer for.
func TestPresenceScopeCallSeesTryBodyFromHandler(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.test;

binding handlerSeesBodyFetch {
  query pattern presenceNode where node.kind == "call"
    and node.path ~= "analysis.function.return"
    and node.prop.region contains "try"
    and not (node.prop.region contains ".t")
    and node.scopeCall.path ~= "fetch"
  emit issue custom.HandlerSeesFetch at node
}
`)
	if err != nil {
		t.Fatalf("compile handler-scope flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))

	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.ts")
	src := []byte(`
export async function proxy(req: Request): Promise<Response> {
  try {
    const res = await fetch("https://internal.example/check-session", {
      headers: { Cookie: req.headers.get("cookie") },
    });
    return rewrite(res);
  } catch (err) {
    return Response.redirect("/login");
  }
}

export async function noFetchHere(req: Request): Promise<Response> {
  try {
    return passthrough(req);
  } catch (err) {
    return Response.redirect("/login");
  }
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := store.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]usg.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	// Exactly the two proxy returns match: the body's (region `try<N>`) and the
	// handler's (region `try<N>.h0`), both holding the body's fetch in scope. The
	// second function's try makes no fetch, so neither of its returns can match —
	// scope does not leak across functions either.
	var regions []string
	handlerReturnMatched := false
	for _, m := range spec.presenceApplicator().Apply(store) {
		region := byID[m.NodeID].Prop("region")
		regions = append(regions, region)
		if strings.HasSuffix(region, ".h0") {
			handlerReturnMatched = true
		}
	}
	if len(regions) != 2 {
		t.Fatalf("want the two returns of the fetch-bearing try matched, got %v", regions)
	}
	if !handlerReturnMatched {
		t.Fatalf("handler return was not matched with the try body's fetch in scope: %v", regions)
	}
}

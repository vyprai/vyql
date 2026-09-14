package treesitter_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// rustFunctionContextTokens returns the str_args of the analysis.function.context
// event lowered for the named function.
func rustFunctionContextTokens(t *testing.T, src, functionName string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tower.rs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRust([]string{path}, dir)
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
		tokens := strings.Split(n.Prop("str_args"), "\x00")
		if slices.Contains(tokens, "name="+functionName) {
			return tokens
		}
	}
	t.Fatalf("no analysis.function.context event for %s", functionName)
	return nil
}

// A check a Rust function delegates to a sibling free function has to be
// visible from the caller: the streamable HTTP transport's fix screens the Host
// header in a private `validate_dns_rebinding_headers` called from
// `StreamableHttpService::handle`, so a binding anchored on the accepting
// function must be able to require that the check is the one whose body reads
// the documented `config.allowed_hosts` spelling. Without the caller carrying
// what its callees do, the guarded and the unguarded handler read identically.
func TestRustDelegatedCheckReachesTheCallersContext(t *testing.T) {
	guarded := `
pub struct StreamableHttpServerConfig {
    pub allowed_hosts: Vec<String>,
}

pub struct StreamableHttpService {
    pub config: StreamableHttpServerConfig,
}

fn host_is_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    allowed_hosts.iter().any(|allowed| allowed.trim() == host)
}

fn validate_dns_rebinding_headers(config: &StreamableHttpServerConfig) -> Result<(), ()> {
    if !host_is_allowed("host", &config.allowed_hosts) {
        return Err(());
    }
    Ok(())
}

impl StreamableHttpService {
    fn handle(&self, request: Request) -> Response {
        if let Err(response) = validate_dns_rebinding_headers(&self.config) {
            return response;
        }
        request.dispatch()
    }
}
`
	unguarded := `
pub struct StreamableHttpService;

impl StreamableHttpService {
    fn handle(&self, request: Request) -> Response {
        request.dispatch()
    }
}
`
	tokens := rustFunctionContextTokens(t, guarded, "handle")
	for _, want := range []string{
		"callee:selector=config.allowed_hosts",
		"callee:call=host_is_allowed",
		"callee:call_path=host_is_allowed",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("delegated fact %q missing from handle context; tokens=%q", want, tokens)
		}
	}
	// What crosses is what the helper does, not what it is called: the
	// handler's own `call:` family gains nothing from the helper's body beyond
	// the call it itself makes.
	if slices.Contains(tokens, "call:allowed_hosts") || slices.Contains(tokens, "call:is_empty") {
		t.Fatalf("the helper's own calls merged into the caller's own call facts; tokens=%q", tokens)
	}

	tokens = rustFunctionContextTokens(t, unguarded, "handle")
	for _, tok := range tokens {
		if len(tok) > 7 && tok[:7] == "callee:" {
			t.Fatalf("the handler without the screen carried a delegated fact %q; tokens=%q", tok, tokens)
		}
	}
}

// Attribution is one hop: a helper's own helpers do not reach the caller, and a
// function's delegated facts stay keyed under `callee:` rather than merging into
// what the function itself does.
func TestRustDelegatedAttributionIsOneHopAndKeyedApart(t *testing.T) {
	src := `
fn deepest(v: &str) -> String {
    v.normalize("NFKC")
}

fn middle(v: &str) -> String {
    deepest(v)
}

fn outer(v: &str) -> String {
    middle(v)
}
`
	tokens := rustFunctionContextTokens(t, src, "outer")
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

// Names that resolve to nothing -- parameters, callees defined elsewhere -- must
// not spend the attribution budget, or a check delegated late in a long function
// is priced out by the calls before it.
func TestRustDelegatedAttributionBudgetCountsResolvedHelpersOnly(t *testing.T) {
	src := `
fn is_unsafe_elem(elem: &str) -> bool {
    elem.starts_with("__")
}

fn walk(node: &Node, a: A, b: B, c: C, d: D, e: E, f: F, g: G, h: H, i: I, j: J) -> bool {
    a(node); b(node); c(node); d(node); e(node);
    f(node); g(node); h(node); i(node); j(node);
    if is_unsafe_elem(node.name()) {
        return true;
    }
    false
}
`
	tokens := rustFunctionContextTokens(t, src, "walk")
	if !slices.Contains(tokens, "callee:call=starts_with") {
		t.Fatalf("the delegated check was priced out by unresolved callees; tokens=%q", tokens)
	}
}

// A callee the function received as a parameter is not the free function that
// happens to carry the same name, and an associated function of an impl is
// reachable only through its receiver or type path, never by a bare name.
func TestRustDelegatedAttributionSkipsShadowedAndAssociatedCallees(t *testing.T) {
	src := `
fn replace(v: &str) -> String {
    v.trim().to_string()
}

struct Cleaner;

impl Cleaner {
    fn scrub(v: &str) -> String {
        v.trim_end().to_string()
    }
}

fn run(replace: fn(&str) -> String) -> String {
    replace("x")
}

fn wash(v: &str) -> String {
    Cleaner::scrub(v)
}
`
	tokens := rustFunctionContextTokens(t, src, "run")
	for _, tok := range tokens {
		if tok == "callee:call=trim" {
			t.Fatalf("a parameter-shadowed callee was attributed the free function's facts; tokens=%q", tokens)
		}
	}
	// Cleaner::scrub is a scoped call, so nothing crosses the hop either way;
	// the associated function must not be reachable from a bare name either.
	tokens = rustFunctionContextTokens(t, src, "wash")
	for _, tok := range tokens {
		if tok == "callee:call=trim_end" {
			t.Fatalf("an associated function was attributed through a bare-name resolution; tokens=%q", tokens)
		}
	}
}

// A name defined twice at file scope resolves to no body, and a function is
// never attributed its own facts through a recursive call.
func TestRustDelegatedAttributionSkipsAmbiguousAndSelfCalls(t *testing.T) {
	src := `
fn helper(v: &str) -> String {
    v.replace("a", "b")
}

fn helper(v: &str) -> String {
    v.trim().to_string()
}

fn caller(v: &str) -> String {
    caller(helper(v))
}
`
	tokens := rustFunctionContextTokens(t, src, "caller")
	for _, tok := range tokens {
		if len(tok) > 7 && tok[:7] == "callee:" {
			t.Fatalf("an ambiguous helper name was attributed; tokens=%q", tokens)
		}
	}
}

// A helper declared inside a nested module is in scope for a bare call once the
// file imports it, so it stays resolvable: the test-module shape -- a `mod
// tests` block holding the helpers its own test functions call -- is where a
// real crate puts them.
func TestRustDelegatedAttributionReachesHelpersInsideAModule(t *testing.T) {
	src := `
mod checks {
    pub fn is_unsafe_elem(elem: &str) -> bool {
        elem.starts_with("__")
    }
}

use checks::is_unsafe_elem;

fn walk(elem: &str) -> bool {
    if is_unsafe_elem(elem) {
        return true;
    }
    false
}
`
	tokens := rustFunctionContextTokens(t, src, "walk")
	if !slices.Contains(tokens, "callee:call=starts_with") {
		t.Fatalf("the helper inside the module block was not attributed; tokens=%q", tokens)
	}
}

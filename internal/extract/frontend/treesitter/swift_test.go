package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestSwiftModuleContextIncludesRawAndCompactText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.swift")
	src := `server.applyPolicyToFilter()
server.applyAllowlistToFilter()
server.applyJailRulesToFilter()
let initialRules = server.mergedRules()
adapter.start(initialRules: initialRules, onXProtectChanged: { server.handleXProtectChange() })

func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
    guard let urlString = webView.url?.absoluteString,
          URIFixup.getURL(entry: urlString) != nil else {
        stop()
        return
    }
}
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractSwift([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(prog.Modules))
	}

	var tokens []string
	for _, st := range prog.Modules[0].Body {
		es, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.Value.(nir.Call)
		if !ok || call.Path != "analysis.module.context" {
			continue
		}
		for _, arg := range call.Args {
			if c, ok := arg.(nir.Const); ok {
				tokens = append(tokens, c.Value)
			}
		}
	}
	joined := strings.Join(tokens, "\x00")
	for _, want := range []string{
		"lang=swift",
		"server.applyPolicyToFilter()",
		"adapter.start(initialRules:initialRules,onXProtectChanged:{server.handleXProtectChange()})",
		"function_name:webView",
		"param_label:didReceiveServerRedirectForProvisionalNavigation",
		"call_path:URIFixup.getURL",
		"call_path:stop",
		"selector:webView.url",
		"startup_order:clearance_policy_before_adapter_start",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("module context missing %q in %q", want, joined)
		}
	}
}

func TestSwiftModuleContextDoesNotMarkPolicyAfterAdapterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.swift")
	src := `let initialRules = coordinator.mergedRules()
endpointClient.start(initialRules: initialRules, onXProtectChanged: { coordinator.handleXProtectChange() })
coordinator.applyPolicyToFilter()
coordinator.applyAllowlistToFilter()
coordinator.applyJailRulesToFilter()
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractSwift([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range prog.Modules[0].Body {
		es, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.Value.(nir.Call)
		if !ok || call.Path != "analysis.module.context" {
			continue
		}
		for _, arg := range call.Args {
			if c, ok := arg.(nir.Const); ok && c.Value == "startup_order:clearance_policy_before_adapter_start" {
				t.Fatalf("policy-after-start module should not emit startup-order token: %#v", call.Args)
			}
		}
	}
}

func TestSwiftModuleContextMarksPolicyBeforeAdapterStartDespiteEarlierStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.swift")
	src := `pipeline.start()

let adapter = ESInboundAdapter(interactor: interactor, esAdapterQueue: esAdapterQueue)
let jailAdapter = ESJailAdapter(interactor: interactor)
let server = XPCServer(interactor: interactor, adapter: adapter, jailAdapter: jailAdapter)

server.applyPolicyToFilter()
server.applyAllowlistToFilter()
server.applyJailRulesToFilter()

server.start()

let initialRules = server.mergedRules()
server.startJailAdapterIfEnabled()
jailAdapter.startSweepTimer()
adapter.start(initialRules: initialRules, onXProtectChanged: { server.handleXProtectChange() })
adapter.clearCache()
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractSwift([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range prog.Modules[0].Body {
		es, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		call, ok := es.Value.(nir.Call)
		if !ok || call.Path != "analysis.module.context" {
			continue
		}
		for _, arg := range call.Args {
			if c, ok := arg.(nir.Const); ok && c.Value == "startup_order:clearance_policy_before_adapter_start" {
				return
			}
		}
	}
	t.Fatalf("module context missing startup-order token")
}

// Swift's grammar has no defer_statement — `defer { … }` parses as a call to an
// identifier of that name with a trailing closure. The frontend must recognise that shape
// and emit nir.Defer, so the lowerer places the block at the function's exit instead of
// inlining it where the `defer` was written.
func TestSwiftDeferBecomesNIRDefer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock.swift")
	src := []byte(`import Foundation

func f(_ mu: NSLock) {
	mu.lock()
	defer { mu.unlock() }
	work()
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractSwift([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}

	var fn nir.FuncDef
	for _, st := range prog.Modules[0].Body {
		if d, ok := st.(nir.FuncDef); ok && d.Name == "f" {
			fn = d
		}
	}
	if fn.Name == "" {
		t.Fatal("func f not found")
	}

	var defers []nir.Defer
	for _, st := range fn.Body {
		if d, ok := st.(nir.Defer); ok {
			defers = append(defers, d)
		}
	}
	if len(defers) != 1 {
		t.Fatalf("want one nir.Defer in the body, got %d (body %T)", len(defers), fn.Body)
	}
	if len(defers[0].Body) != 1 {
		t.Fatalf("deferred block = %d statements, want 1", len(defers[0].Body))
	}
	stmt, ok := defers[0].Body[0].(nir.ExprStmt)
	if !ok {
		t.Fatalf("deferred statement = %T, want nir.ExprStmt", defers[0].Body[0])
	}
	call, ok := stmt.Value.(nir.Call)
	if !ok || call.Path != "mu.unlock" {
		t.Errorf("deferred call = %#v, want a call to mu.unlock", stmt.Value)
	}

	// The block must NOT also be inlined at the `defer` — that would lower it twice.
	for _, st := range fn.Body {
		es, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		if c, ok := es.Value.(nir.Call); ok && c.Path == "mu.unlock" {
			t.Error("deferred call was also lowered inline at the defer statement")
		}
	}
}

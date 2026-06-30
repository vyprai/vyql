package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
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

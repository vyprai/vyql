package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestPythonFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sso.py")
	src := []byte(`class SSOBase:
    async def verify_and_process(self, request):
        self._state = request.query_params.get("state")
        sso_state = request.cookies.get("sso_state")
        if sso_state != self._state:
            raise SSOLoginError(401, "Invalid state")
        return await self.process_login("code", request)
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		args := n.Prop("str_args")
		if !strings.Contains(args, "name=verify_and_process") {
			continue
		}
		for _, want := range []string{
			"lang=python",
			"function_name:verify_and_process",
			"param_name:request",
			"assign:self._state=request.query_params.get(\"state\")",
			"assign_call:self._state:request.query_params.get",
			"call_path:request.cookies.get",
			"identifier:sso_state",
			"identifier:request",
			"literal:sso_state",
			"selector:self._state",
			"expr:sso_state!=self._state",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("python function context missing %q in %q", want, args)
			}
		}
		return
	}
	t.Fatalf("python function context for verify_and_process not found; nodes=%#v", nodes)
}

func TestPythonFunctionContextIncludesRouteFilenameLimitTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "media.py")
	src := []byte(`from flask import jsonify, make_response
from werkzeug.utils import secure_filename

@MediaBp.route("/<camera_name>/start/<int:start_ts>/end/<int:end_ts>/clip.mp4")
def recording_clip(camera_name, start_ts, end_ts):
    file_name = f"clip_{camera_name}_{start_ts}-{end_ts}.mp4"

    if len(file_name) > 1000:
        return make_response(jsonify({"success": False}), 403)

    file_name = secure_filename(file_name)
    path = os.path.join(CACHE_DIR, file_name)
    return path
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		args := n.Prop("str_args")
		if !strings.Contains(args, "name=recording_clip") {
			continue
		}
		for _, want := range []string{
			"decorator_method:route",
			"param_name:camera_name",
			"assign:file_name=f\"clip_{camera_name}_{start_ts}-{end_ts}.mp4\"",
			"call_path:len",
			"expr:len(file_name)>1000",
			"call_path:secure_filename",
			"call_path:os.path.join",
			"identifier:CACHE_DIR",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("python route filename context missing %q in %q", want, args)
			}
		}
		return
	}
	t.Fatalf("python function context for recording_clip not found; nodes=%#v", nodes)
}

func TestPythonModuleContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.py")
	src := []byte(`import yaml

with open("/var/feast/feature_store.yaml") as f:
    feast_config = yaml.load(f, Loader=yaml.Loader)

viewer_scopes = [
    CLIENT_READ,
    CONFIG_READ,
]
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"lang=python",
			"function_name:module",
			"assign:feast_config=yaml.load(f,Loader=yaml.Loader)",
			"assign_call:feast_config:yaml.load",
			"assign_item:viewer_scopes:CLIENT_READ",
			"assign_item:viewer_scopes:CONFIG_READ",
			"call_path:yaml.load",
			"selector:yaml.Loader",
			"literal:/var/feast/feature_store.yaml",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("python module context missing %q in %q", want, args)
			}
		}
		return
	}
	t.Fatalf("python module context not found; nodes=%#v", nodes)
}

func TestPythonFunctionEndContextIncludesPrefixedModuleFacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.py")
	src := []byte(`import base64

def issue_token(identity):
    return base64.b64encode(identity.encode()).decode()

def authenticate(password, digest):
    if not verify_password(password, digest):
        return None
    return {"ok": True}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context.end" {
			continue
		}
		args := n.Prop("str_args")
		tokens := make(map[string]bool)
		for _, token := range strings.Split(args, "\x00") {
			tokens[token] = true
		}
		if !tokens["name=authenticate"] {
			continue
		}
		if got := n.Prop("loc"); got != "auth.py:9" {
			t.Fatalf("function-end loc = %q, want auth.py:9", got)
		}
		for _, want := range []string{"call_path:verify_password", "module_call_path:base64.b64encode", "module_function_name:module"} {
			if !tokens[want] {
				t.Fatalf("function-end context missing %q in %q", want, args)
			}
		}
		if tokens["call_path:base64.b64encode"] {
			t.Fatalf("function-end context unexpectedly includes prior function's unprefixed call fact in %q", args)
		}
		return
	}
	t.Fatal("authenticate function-end context not found")
}

func TestPythonFunctionLocalEndContextExcludesModuleFacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.py")
	src := []byte(`import base64

def issue_token(identity):
    return base64.b64encode(identity.encode()).decode()

def authenticate(password, digest):
    if not verify_password(password, digest):
        return None
    return {"ok": True}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.local.end" {
			continue
		}
		args := n.Prop("str_args")
		tokens := make(map[string]bool)
		for _, token := range strings.Split(args, "\x00") {
			tokens[token] = true
			if strings.HasPrefix(token, "module_") {
				t.Fatalf("function-local end context unexpectedly includes module token %q in %q", token, args)
			}
		}
		if !tokens["name=authenticate"] {
			continue
		}
		if got := n.Prop("loc"); got != "auth.py:9" {
			t.Fatalf("function-local end loc = %q, want auth.py:9", got)
		}
		if !tokens["call_path:verify_password"] {
			t.Fatalf("function-local end context missing %q in %q", "call_path:verify_password", args)
		}
		if tokens["call_path:base64.b64encode"] {
			t.Fatalf("function-local end context unexpectedly includes prior function call fact in %q", args)
		}
		return
	}
	t.Fatal("authenticate function-local end context not found")
}

func pythonFunctionLocalEndTokens(t *testing.T, src, functionName string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.py")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
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
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.local.end" {
			continue
		}
		tokens := strings.Split(n.Prop("str_args"), "\x00")
		for _, token := range tokens {
			if token == "name="+functionName {
				return tokens
			}
		}
	}
	t.Fatalf("function-local end context for %s not found", functionName)
	return nil
}

func tokenWithPrefix(tokens []string, prefix string) string {
	for _, token := range tokens {
		if strings.HasPrefix(token, prefix) {
			return token
		}
	}
	return ""
}

func TestPythonFunctionLocalEndContextExcludesModuleLiterals(t *testing.T) {
	tokens := pythonFunctionLocalEndTokens(t, `HELP_TEXT = "call db.session.commit() or abort(403)"

def helper():
    return "abort("

def load_document(document_id):
    document = Document.query.get(document_id)
    return document
`, "load_document")
	for _, token := range tokens {
		if strings.Contains(token, ".commit()") || strings.Contains(token, "abort(") {
			t.Fatalf("function-local end leaked module or other-function literal %q", token)
		}
	}
}

func TestPythonFunctionLocalEndIncludesTerminalGuardBeforeUseFacts(t *testing.T) {
	src := `def guarded_document(document_id, principal):
    document = Document.query.get(document_id)
    if document.owner_id != principal:
        abort(403)
    return render_template("document.html", document=document)

def reversed_guard(document_id, principal):
    document = Document.query.get(document_id)
    if principal != document.owner_id:
        abort(403)
    return document

def guarded_order(order_id, user_id):
    if user_id != None or order_id is not None:
        return ""
    order = Order.query.get(order_id)
    return order

def guarded_invoice(invoice_id):
    if invoice_id != None:
        return ""
    invoice = Invoice.query.get(invoice_id)
    return invoice
`
	guarded := pythonFunctionLocalEndTokens(t, src, "guarded_document")
	token := tokenWithPrefix(guarded, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;")
	if token == "" || !strings.Contains(token, "condition=document.owner_id!=principal") || !strings.Contains(token, "terminal=call:abort(403)") || !strings.Contains(token, "later_op=return:render_template(\"document.html\",document=document)") {
		t.Fatalf("target-correlated mismatch guard fact missing or incomplete: %q", token)
	}
	reversed := pythonFunctionLocalEndTokens(t, src, "reversed_guard")
	if tokenWithPrefix(reversed, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;") == "" {
		t.Fatalf("reversed mismatch guard did not preserve the protected operand: %q", strings.Join(reversed, " | "))
	}
	order := pythonFunctionLocalEndTokens(t, src, "guarded_order")
	if tokenWithPrefix(order, "terminal_guard_before:later_use=order_id;guard_non_null=order_id;") == "" {
		t.Fatalf("is-not-None guard fact missing: %q", strings.Join(order, " | "))
	}
	invoice := pythonFunctionLocalEndTokens(t, src, "guarded_invoice")
	if tokenWithPrefix(invoice, "terminal_guard_before:later_use=invoice_id;guard_non_null=invoice_id;") == "" {
		t.Fatalf("not-equal-None guard fact missing: %q", strings.Join(invoice, " | "))
	}
}

func TestPythonFunctionLocalEndTerminalGuardFactsRespectOrderAndPolarity(t *testing.T) {
	src := `def inverted_guard(document_id, principal):
    document = Document.query.get(document_id)
    if document.owner_id == principal:
        abort(403)
    return document

def guard_after_use(document_id, principal):
    document = Document.query.get(document_id)
    return document
    if document.owner_id != principal:
        abort(403)

def guard_before_unrelated_use(document_id, principal, profile):
    document = Document.query.get(document_id)
    if document.owner_id != principal:
        abort(403)
    return profile
`
	inverted := pythonFunctionLocalEndTokens(t, src, "inverted_guard")
	if tokenWithPrefix(inverted, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;") != "" {
		t.Fatalf("equality guard was misclassified as a safe mismatch: %q", strings.Join(inverted, " | "))
	}
	after := pythonFunctionLocalEndTokens(t, src, "guard_after_use")
	if tokenWithPrefix(after, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;") != "" {
		t.Fatalf("guard after protected use was classified as dominating: %q", strings.Join(after, " | "))
	}
	unrelated := pythonFunctionLocalEndTokens(t, src, "guard_before_unrelated_use")
	if tokenWithPrefix(unrelated, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;") != "" {
		t.Fatalf("guard before only an unrelated later use was target-correlated: %q", strings.Join(unrelated, " | "))
	}
}

func TestPythonFunctionLocalEndMarksOnlyProvablyUnreachableCalls(t *testing.T) {
	src := `def length_guard(user_id):
    if len(user_id) >= 0:
        return ""
    db.session.commit()

def numeric_guard(retry_count):
    if retry_count >= 0:
        return ""
    db.session.commit()

def late_length_guard(user_id):
    db.session.commit()
    if len(user_id) >= 0:
        return ""
`
	lengthGuard := pythonFunctionLocalEndTokens(t, src, "length_guard")
	if tokenWithPrefix(lengthGuard, "unreachable_call:db.session.commit()") == "" {
		t.Fatalf("provably unreachable call fact missing: %q", strings.Join(lengthGuard, " | "))
	}
	numericGuard := pythonFunctionLocalEndTokens(t, src, "numeric_guard")
	if tokenWithPrefix(numericGuard, "unreachable_call:db.session.commit()") != "" {
		t.Fatalf("arbitrary numeric guard was treated as always true: %q", strings.Join(numericGuard, " | "))
	}
	lateGuard := pythonFunctionLocalEndTokens(t, src, "late_length_guard")
	if tokenWithPrefix(lateGuard, "unreachable_call:db.session.commit()") != "" {
		t.Fatalf("later terminal guard marked an earlier call unreachable: %q", strings.Join(lateGuard, " | "))
	}
}

func TestPythonFunctionLocalEndTerminalGuardFactsAreSizeBounded(t *testing.T) {
	principal := strings.Repeat("principal_", 600)
	tokens := pythonFunctionLocalEndTokens(t, "def guarded_document(document_id, "+principal+"):\n"+
		"    document = Document.query.get(document_id)\n"+
		"    if document.owner_id != "+principal+":\n"+
		"        abort(403)\n"+
		"    return document\n", "guarded_document")
	found := false
	for _, token := range tokens {
		if !strings.HasPrefix(token, "terminal_guard_before:") {
			continue
		}
		found = true
		if len(token) > 1024 {
			t.Fatalf("terminal-guard fact has unbounded size %d: %q", len(token), token)
		}
	}
	if !found {
		t.Fatal("bounded terminal-guard evidence was dropped")
	}
}

func TestPythonFunctionLocalEndDoesNotTreatLambdaCaptureAsSameScopeUse(t *testing.T) {
	tokens := pythonFunctionLocalEndTokens(t, `def guarded_document(document_id, principal):
    document = Document.query.get(document_id)
    if document.owner_id != principal:
        abort(403)
    register(lambda: document)
    return "public"
`, "guarded_document")
	if tokenWithPrefix(tokens, "terminal_guard_before:later_use=document;guard_mismatch=document.owner_id;") != "" {
		t.Fatalf("lambda capture was classified as a same-scope later use: %q", strings.Join(tokens, " | "))
	}
}

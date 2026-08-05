package treesitter_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
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
			"python_review:overbroad_role_permission_grant",
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

func pythonFunctionContextTokens(t *testing.T, src, functionName, calleePath string) []string {
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
		if n.Type != "code.Call" || n.Prop("callee_path") != calleePath {
			continue
		}
		tokens := strings.Split(n.Prop("str_args"), "\x00")
		for _, token := range tokens {
			if token == "name="+functionName {
				return tokens
			}
		}
	}
	t.Fatalf("%s context for %s not found", calleePath, functionName)
	return nil
}

func pythonFunctionLocalEndTokens(t *testing.T, src, functionName string) []string {
	t.Helper()
	return pythonFunctionContextTokens(t, src, functionName, "analysis.function.local.end")
}

func tokenWithPrefix(tokens []string, prefix string) string {
	for _, token := range tokens {
		if strings.HasPrefix(token, prefix) {
			return token
		}
	}
	return ""
}

func uniqueTokens(tokens []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, token := range tokens {
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	return out
}

func countTokensWithPrefix(tokens []string, prefix string) int {
	count := 0
	for _, token := range uniqueTokens(tokens) {
		if strings.HasPrefix(token, prefix) {
			count++
		}
	}
	return count
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

func TestPythonFunctionLocalEndExcludesEnclosingClassBodiesButCombinedContextKeepsThem(t *testing.T) {
	src := `class DocumentRoutes(BaseRoutes):
    @app.get("/documents/<int:document_id>")
    def view_document(self, document_id):
        principal_id = session.get("user_id")
        document = Document.query.get(document_id)
        return document

    def sibling_writer(self, sibling_id):
        sibling = Sibling.query.get(sibling_id)
        database.session.commit()
        return sibling
`
	local := pythonFunctionLocalEndTokens(t, src, "view_document")
	for _, token := range local {
		if strings.Contains(token, "Sibling.query.get") || strings.Contains(token, "database.session.commit") {
			t.Fatalf("function-local end leaked enclosing class body token %q", token)
		}
	}
	for _, want := range []string{"class_name=DocumentRoutes", "class_bases=BaseRoutes", "class_base:BaseRoutes"} {
		if tokenWithPrefix(local, want) == "" {
			t.Fatalf("function-local end lost class metadata %q: %q", want, strings.Join(local, " | "))
		}
	}
	combined := pythonFunctionContextTokens(t, src, "view_document", "analysis.function.context.end")
	joined := strings.Join(combined, "\x00")
	for _, want := range []string{"Sibling.query.get(sibling_id)", "database.session.commit()"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("combined context lost established class body %q: %q", want, joined)
		}
	}
}

func TestPythonFunctionLocalEndExcludesNestedScopesButCombinedContextKeepsThem(t *testing.T) {
	src := `@app.get("/documents/<int:document_id>")
def view_document(document_id):
    principal_id = session.get("user_id")
    document = Document.query.get(document_id)

    def unused_nested():
        nested_id = session.get("nested-user")
        Nested.query.get(nested_id)
        db.commit()

    class UnusedNested:
        def save(self):
            database.session.commit()

    callback = lambda: session.get("lambda-user")
    return document
`
	local := pythonFunctionLocalEndTokens(t, src, "view_document")
	for _, token := range local {
		for _, forbidden := range []string{"nested-user", "Nested.query.get", "db.commit", "database.session.commit", "lambda-user", "lambda:"} {
			if strings.Contains(token, forbidden) {
				t.Fatalf("function-local end leaked nested scope %q in token %q", forbidden, token)
			}
		}
	}
	combined := pythonFunctionContextTokens(t, src, "view_document", "analysis.function.context.end")
	joined := strings.Join(combined, "\x00")
	for _, want := range []string{"nested-user", "Nested.query.get", "db.commit()", "database.session.commit()", "lambda-user"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("combined context lost established nested evidence %q: %q", want, joined)
		}
	}
}

func TestPythonFunctionLocalEndEmitsSessionProvenTerminalGuardCorrelations(t *testing.T) {
	src := `def guarded_document(document_id):
    principal_id = session.get("user_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return render_template("document.html", document=document)

def reversed_guard(document_id):
    principal_id = session["user_id"]
    document = Document.query.get(document_id)
    if principal_id != document.owner_id:
        abort(403)
    return document

def guarded_principal_object(document_id):
    principal = Account.query.get(session.get("user_id"))
    document = Document.query.get(document_id)
    if document.owner != principal:
        raise Forbidden()
    return document

def guarded_alias(document_id):
    session_principal = session.get("user_id")
    principal_alias = session_principal
    document = Document.query.get(document_id)
    if principal_alias != document.user_id:
        return None
    return document

def guarded_user(user_id):
    principal_id = session.get("user_id")
    if user_id != principal_id:
        abort(403)
    user = User.query.get(user_id)
    return user

def guarded_order(order_id):
    if order_id is not None:
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
	wantDocument := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort"
	if tokenWithPrefix(guarded, wantDocument) == "" {
		t.Fatalf("session-proven object guard correlation missing: %q", strings.Join(guarded, " | "))
	}
	reversed := pythonFunctionLocalEndTokens(t, src, "reversed_guard")
	if tokenWithPrefix(reversed, wantDocument) == "" {
		t.Fatalf("reversed mismatch did not normalize target and counterpart: %q", strings.Join(reversed, " | "))
	}
	principalObject := pythonFunctionLocalEndTokens(t, src, "guarded_principal_object")
	if tokenWithPrefix(principalObject, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner;counterpart_source=session;guard_counterpart=principal;terminal=raise") == "" {
		t.Fatalf("principal-object session provenance missing: %q", strings.Join(principalObject, " | "))
	}
	alias := pythonFunctionLocalEndTokens(t, src, "guarded_alias")
	if tokenWithPrefix(alias, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.user_id;counterpart_source=session;guard_counterpart=principal_alias;terminal=return") == "" {
		t.Fatalf("unconditional session alias provenance missing: %q", strings.Join(alias, " | "))
	}
	user := pythonFunctionLocalEndTokens(t, src, "guarded_user")
	if tokenWithPrefix(user, "terminal_guard_blocks_call:operation=query.get;args=user_id;guard_kind=mismatch;guard_target=user_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort;callee=User.query.get") == "" {
		t.Fatalf("target-ID guard was not tied to its later ORM call: %q", strings.Join(user, " | "))
	}
	if tokenWithPrefix(user, "terminal_guard_blocks_return:use=user;guard_kind=mismatch;guard_target=user_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
		t.Fatalf("target-ID guard was not paired with its later target-bearing return: %q", strings.Join(user, " | "))
	}
	order := pythonFunctionLocalEndTokens(t, src, "guarded_order")
	if tokenWithPrefix(order, "terminal_guard_blocks_call:operation=query.get;args=order_id;guard_kind=non_null;guard_target=order_id;counterpart_source=literal;guard_counterpart=None;terminal=return;callee=Order.query.get") == "" {
		t.Fatalf("same-target non-null guard was not tied to its later ORM call: %q", strings.Join(order, " | "))
	}
	if tokenWithPrefix(order, "terminal_guard_blocks_return:use=order;guard_kind=non_null;guard_target=order_id;counterpart_source=literal;guard_counterpart=None;terminal=return") == "" {
		t.Fatalf("same-target non-null guard was not paired with its later target-bearing return: %q", strings.Join(order, " | "))
	}
	invoice := pythonFunctionLocalEndTokens(t, src, "guarded_invoice")
	if tokenWithPrefix(invoice, "terminal_guard_blocks_call:operation=query.get;args=invoice_id;guard_kind=non_null;guard_target=invoice_id;counterpart_source=literal;guard_counterpart=None;terminal=return;callee=Invoice.query.get") == "" {
		t.Fatalf("not-equal-None guard was not tied to its later ORM call: %q", strings.Join(invoice, " | "))
	}
}

func TestPythonFunctionLocalEndGuardProvenanceIsPathLocalAndPrior(t *testing.T) {
	src := `def request_claim(document_id):
    claimed_owner_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != claimed_owner_id:
        abort(403)
    return document

def assigned_after_guard(document_id):
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    principal_id = session.get("user_id")
    return document

def branch_only(document_id, load_principal):
    if load_principal:
        principal_id = session.get("user_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def overwritten(document_id):
    principal_id = session.get("user_id")
    principal_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def branch_local(document_id, enabled):
    if enabled:
        principal_id = session.get("user_id")
        document = Document.query.get(document_id)
        if document.owner_id != principal_id:
            abort(403)
        return document
    return None
`
	for _, name := range []string{"request_claim", "assigned_after_guard", "branch_only", "overwritten"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		unknownPrefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;"
		token := tokenWithPrefix(tokens, unknownPrefix)
		if token == "" || !strings.Contains(token, "counterpart_source=unknown") {
			t.Fatalf("%s did not retain unknown counterpart provenance: %q", name, strings.Join(tokens, " | "))
		}
		if strings.Contains(token, "counterpart_source=session") {
			t.Fatalf("%s used non-prior or non-path session provenance: %q", name, token)
		}
	}
	branchLocal := pythonFunctionLocalEndTokens(t, src, "branch_local")
	if tokenWithPrefix(branchLocal, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
		t.Fatalf("same-path branch assignment did not prove its later guard: %q", strings.Join(branchLocal, " | "))
	}
}

func TestPythonFunctionLocalEndCompoundAssignmentsInvalidateOuterProvenance(t *testing.T) {
	src := `def if_reassigned(document_id, use_claimed):
    principal_id = session.get("user_id")
    if use_claimed:
        principal_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def elif_reassigned(document_id, first, use_claimed):
    principal_id = session.get("user_id")
    if first:
        audit()
    elif use_claimed:
        principal_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def else_reassigned(document_id, preserve):
    principal_id = session.get("user_id")
    if preserve:
        audit()
    else:
        principal_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def loop_reassigned(document_id, claimed_ids):
    principal_id = session.get("user_id")
    for claimed_id in claimed_ids:
        principal_id = claimed_id
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def try_reassigned(document_id):
    principal_id = session.get("user_id")
    try:
        principal_id = request.args.get("owner_id")
    except LookupError:
        audit()
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def with_reassigned(document_id):
    principal_id = session.get("user_id")
    with authorization_context():
        principal_id = request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def augmented_in_branch(document_id, mutate):
    principal_id = session.get("user_id")
    if mutate:
        principal_id += request.args.get("suffix")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def nested_scope_does_not_reassign(document_id):
    principal_id = session.get("user_id")
    def unused():
        principal_id = request.args.get("owner_id")
        return principal_id
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document
`
	unknownPrefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;"
	for _, name := range []string{
		"if_reassigned",
		"elif_reassigned",
		"else_reassigned",
		"loop_reassigned",
		"try_reassigned",
		"with_reassigned",
		"augmented_in_branch",
	} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		token := tokenWithPrefix(tokens, unknownPrefix)
		if token == "" || !strings.Contains(token, "counterpart_source=unknown") {
			t.Fatalf("%s retained provenance assigned in a potentially reachable compound block: %q", name, strings.Join(tokens, " | "))
		}
	}
	nestedScope := pythonFunctionLocalEndTokens(t, src, "nested_scope_does_not_reassign")
	if tokenWithPrefix(nestedScope, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
		t.Fatalf("nested function assignment invalidated the enclosing provenance: %q", strings.Join(nestedScope, " | "))
	}
}

func TestPythonFunctionLocalEndCompoundHeaderBindingsInvalidateOuterProvenance(t *testing.T) {
	src := `def for_target_reassigned(document_id):
    principal_id = session.get("user_id")
    for principal_id in request.args.getlist("owner_id"):
        audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def tuple_for_target_reassigned(document_id, claims):
    principal_id = session.get("user_id")
    for ignored, principal_id in claims:
        audit(ignored)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def walrus_reassigned(document_id):
    principal_id = session.get("user_id")
    if (principal_id := request.args.get("owner_id")):
        audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def with_alias_reassigned(document_id):
    principal_id = session.get("user_id")
    with authorization_context() as principal_id:
        audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def except_alias_reassigned(document_id):
    principal_id = session.get("user_id")
    try:
        authorize()
    except AuthorizationError as principal_id:
        audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def match_capture_reassigned(document_id, claim):
    principal_id = session.get("user_id")
    match claim:
        case {"owner_id": principal_id}:
            audit(principal_id)
        case _:
            audit()
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def use_only_condition(document_id):
    principal_id = session.get("user_id")
    if principal_id:
        audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document
`
	unknownPrefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;"
	for _, name := range []string{
		"for_target_reassigned",
		"tuple_for_target_reassigned",
		"walrus_reassigned",
		"with_alias_reassigned",
		"except_alias_reassigned",
		"match_capture_reassigned",
	} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		token := tokenWithPrefix(tokens, unknownPrefix)
		if token == "" || !strings.Contains(token, "counterpart_source=unknown;guard_counterpart=principal_id") {
			t.Fatalf("%s retained provenance rebound by a compound header: %q", name, strings.Join(tokens, " | "))
		}
	}
	useOnly := pythonFunctionLocalEndTokens(t, src, "use_only_condition")
	if tokenWithPrefix(useOnly, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
		t.Fatalf("ordinary condition use cleared trusted provenance: %q", strings.Join(useOnly, " | "))
	}
}

func TestPythonFunctionLocalEndEmbeddedWalrusInvalidatesWithoutClearingDirectAssignmentsOrReads(t *testing.T) {
	src := `def embedded_walrus(document_id):
    principal_id = session.get("user_id")
    audit(principal_id := request.args.get("owner_id"))
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def direct_assignment(document_id):
    principal_id = session.get("user_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def ordinary_read(document_id):
    principal_id = session.get("user_id")
    audit(principal_id)
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document
`
	embedded := pythonFunctionLocalEndTokens(t, src, "embedded_walrus")
	embeddedPrefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;"
	embeddedToken := tokenWithPrefix(embedded, embeddedPrefix)
	if embeddedToken == "" || !strings.Contains(embeddedToken, "counterpart_source=unknown;guard_counterpart=principal_id") {
		t.Fatalf("embedded walrus retained earlier session provenance: %q", strings.Join(embedded, " | "))
	}
	sessionPrefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort"
	for _, name := range []string{"direct_assignment", "ordinary_read"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, sessionPrefix) == "" {
			t.Fatalf("%s cleared direct assignment provenance without a rebind: %q", name, strings.Join(tokens, " | "))
		}
	}
}

func TestPythonFunctionLocalEndSessionProvenanceRequiresEveryIdentityAlternative(t *testing.T) {
	src := `def all_session_boolean(document_id):
    principal_id = session.get("primary_id") or session["backup_id"]
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def all_session_conditional(document_id, use_primary):
    principal_id = session.get("primary_id") if use_primary else session["backup_id"]
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def wrapped_with_literal_ancillary(document_id):
    principal = Account.query.get(session.get("user_id"), cache=True)
    document = Document.query.get(document_id)
    if document.owner != principal:
        abort(403)
    return document

def request_or_session(document_id):
    principal_id = request.args.get("owner_id") or session.get("user_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def session_and_request(document_id):
    principal_id = session.get("user_id") and request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def mixed_conditional(document_id, use_claimed):
    principal_id = session.get("user_id") if not use_claimed else request.args.get("owner_id")
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def dynamic_session_key(document_id):
    principal_id = session.get(request.args.get("session_key"))
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def dynamic_session_subscript(document_id, session_key):
    principal_id = session[session_key]
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def mixed_container(document_id):
    principal_id = [session.get("user_id"), request.args.get("owner_id")]
    document = Document.query.get(document_id)
    if document.owner_id != principal_id:
        abort(403)
    return document

def mixed_wrapper(document_id):
    principal = Account.query.get(session.get("user_id"), request.args.get("tenant_id"))
    document = Document.query.get(document_id)
    if document.owner != principal:
        abort(403)
    return document
`
	for _, name := range []string{"all_session_boolean", "all_session_conditional"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
			t.Fatalf("%s lost all-session alternative provenance: %q", name, strings.Join(tokens, " | "))
		}
	}
	wrapped := pythonFunctionLocalEndTokens(t, src, "wrapped_with_literal_ancillary")
	if tokenWithPrefix(wrapped, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=document.owner;counterpart_source=session;guard_counterpart=principal;terminal=abort") == "" {
		t.Fatalf("literal-only wrapper ancillary argument lost session provenance: %q", strings.Join(wrapped, " | "))
	}
	for _, testCase := range []struct {
		name   string
		target string
		other  string
	}{
		{name: "request_or_session", target: "document.owner_id", other: "principal_id"},
		{name: "session_and_request", target: "document.owner_id", other: "principal_id"},
		{name: "mixed_conditional", target: "document.owner_id", other: "principal_id"},
		{name: "dynamic_session_key", target: "document.owner_id", other: "principal_id"},
		{name: "dynamic_session_subscript", target: "document.owner_id", other: "principal_id"},
		{name: "mixed_container", target: "document.owner_id", other: "principal_id"},
		{name: "mixed_wrapper", target: "document.owner", other: "principal"},
	} {
		tokens := pythonFunctionLocalEndTokens(t, src, testCase.name)
		prefix := "terminal_guard_blocks_return:use=document;guard_kind=mismatch;guard_target=" + testCase.target + ";"
		token := tokenWithPrefix(tokens, prefix)
		if token == "" || !strings.Contains(token, "counterpart_source=unknown;guard_counterpart="+testCase.other) {
			t.Fatalf("%s trusted a mixed or dynamic identity expression: %q", testCase.name, strings.Join(tokens, " | "))
		}
	}
}

func TestPythonFunctionLocalEndOperationCorrelationsRespectOrderAndPolarity(t *testing.T) {
	src := `def inverted_guard(document_id):
    principal_id = session.get("user_id")
    document = Document.query.get(document_id)
    if document.owner_id == principal_id:
        abort(403)
    return document

def guard_after_query_get(document_id):
    principal_id = session.get("user_id")
    document = Document.query.get(document_id)
    if document_id != principal_id:
        abort(403)
    audit(document_id)
    return "public"

def non_null_after_query_get(document_id):
    document = Document.query.get(document_id)
    if document_id != None:
        return ""
    audit(document_id)
    return "public"
`
	inverted := pythonFunctionLocalEndTokens(t, src, "inverted_guard")
	if tokenWithPrefix(inverted, "terminal_guard_blocks_return:use=document;guard_kind=equal;guard_target=document.owner_id;counterpart_source=session;guard_counterpart=principal_id;terminal=abort") == "" {
		t.Fatalf("equality polarity was not preserved: %q", strings.Join(inverted, " | "))
	}
	if tokenWithPrefix(inverted, "terminal_guard_blocks_return:use=document;guard_kind=mismatch;") != "" {
		t.Fatalf("equality guard was misclassified as mismatch: %q", strings.Join(inverted, " | "))
	}
	for _, name := range []string{"guard_after_query_get", "non_null_after_query_get"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, "terminal_guard_blocks_call:operation=query.get;args=document_id;") != "" {
			t.Fatalf("%s let an unrelated later target use cover an earlier ORM call: %q", name, strings.Join(tokens, " | "))
		}
	}
}

func TestPythonFunctionLocalEndReachabilityUsesOnlyProvablyTrueGuards(t *testing.T) {
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
	if tokenWithPrefix(lengthGuard, "reachable_call_method:commit") != "" {
		t.Fatalf("provably unreachable call was marked reachable: %q", strings.Join(lengthGuard, " | "))
	}
	numericGuard := pythonFunctionLocalEndTokens(t, src, "numeric_guard")
	if tokenWithPrefix(numericGuard, "reachable_call_method:commit") == "" {
		t.Fatalf("arbitrary numeric guard was treated as always true: %q", strings.Join(numericGuard, " | "))
	}
	lateGuard := pythonFunctionLocalEndTokens(t, src, "late_length_guard")
	if tokenWithPrefix(lateGuard, "reachable_call_method:commit") == "" {
		t.Fatalf("later terminal guard hid an earlier reachable call: %q", strings.Join(lateGuard, " | "))
	}
}

func TestPythonFunctionLocalEndEmitsPositiveReachableCallMethods(t *testing.T) {
	src := `def direct_db():
    db.commit()

def direct_database():
    database.session.commit()

def retry_guard(retry_count):
    if retry_count >= 0:
        return ""
    db.commit()

def length_guard(user_id):
    if len(user_id) >= 0:
        return ""
    db.commit()

def before_length_guard(user_id):
    db.commit()
    if len(user_id) >= 0:
        return ""
    database.session.commit()

def branch_commit(enabled):
    if enabled:
        db.commit()
    return ""

def after_return():
    return ""
    db.commit()

def after_raise():
    raise RuntimeError()
    db.commit()

def after_abort():
    abort(403)
    db.commit()

def nested_only():
    def unused():
        db.commit()
    callback = lambda: database.session.commit()
    return ""

def mixed_nested(user_id, enabled):
    if enabled:
        db.commit()
    if len(user_id) >= 0:
        return ""
        database.session.commit()
`
	for _, name := range []string{"direct_db", "direct_database", "retry_guard", "before_length_guard", "branch_commit", "mixed_nested"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, "reachable_call_method:commit") == "" {
			t.Fatalf("%s lost a reachable commit: %q", name, strings.Join(tokens, " | "))
		}
	}
	for _, name := range []string{"length_guard", "after_return", "after_raise", "after_abort", "nested_only"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, "reachable_call_method:commit") != "" {
			t.Fatalf("%s marked an unreachable or nested commit reachable: %q", name, strings.Join(tokens, " | "))
		}
	}
}

func TestPythonFunctionLocalEndReachableCommitSurvivesSeparateUnreachableCommit(t *testing.T) {
	tokens := pythonFunctionLocalEndTokens(t, `def mixed_commits(user_id, enabled):
    if enabled:
        db.commit()
    if len(user_id) >= 0:
        return ""
    database.session.commit()
`, "mixed_commits")
	if tokenWithPrefix(tokens, "reachable_call_method:commit") == "" {
		t.Fatalf("unreachable commit hid a separate reachable commit: %q", strings.Join(tokens, " | "))
	}
}

func TestPythonFunctionLocalEndCorrelatesRequestIdentityFlows(t *testing.T) {
	src := `def header_replacement():
    principal_id = session.get("user_id")
    requested_id = request.headers.get("X-User-Id")
    if requested_id:
        principal_id = requested_id
    principal = User.query.get(principal_id)
    return principal

def unreachable_header_replacement():
    principal_id = session.get("user_id")
    requested_id = request.headers.get("X-User-Id")
    if requested_id:
        if User.query.get(requested_id):
            principal_id = requested_id
        else:
            return ""
        if principal_id:
            return ""
    if len(principal_id) or len(requested_id):
        return ""
    principal = User.query.get(principal_id)
    return principal

def header_validation_only():
    principal_id = session.get("user_id")
    requested_id = request.headers.get("X-User-Id")
    if requested_id != principal_id:
        abort(403)
    principal = User.query.get(principal_id)
    return principal

def subscript_header_replacement():
    account_id = session["account_id"]
    requested_id = request.headers.get("X-Account-Id")
    if requested_id:
        account_id = requested_id
    account = Account.query.get(account_id)
    return account

def request_selected_session(username):
    password = request.form["password"]
    account = Account.query.filter_by(username=username, password=password).first()
    if account:
        if Account.query.get(request.form["account_id"]):
            session["account_id"] = request.form["account_id"]

def authenticated_record_session(username):
    password = request.form["password"]
    account = Account.query.filter_by(username=username, password=password).first()
    if account:
        session["account_id"] = account.id
`

	header := pythonFunctionLocalEndTokens(t, src, "header_replacement")
	if tokenWithPrefix(header, "assignment_flow_reaches_operation:source_category=request;source=request.headers.get;previous_source=session;operation_category=query;operation=query.get;target=principal_id;args=principal_id;callee=User.query.get") == "" {
		t.Fatalf("reachable header-selected principal lookup was not correlated: %q", strings.Join(header, " | "))
	}
	subscriptHeader := pythonFunctionLocalEndTokens(t, src, "subscript_header_replacement")
	if tokenWithPrefix(subscriptHeader, "assignment_flow_reaches_operation:source_category=request;source=request.headers.get;previous_source=session;operation_category=query;operation=query.get;target=account_id;args=account_id;callee=Account.query.get") == "" {
		t.Fatalf("subscript-loaded server value replacement was not correlated: %q", strings.Join(subscriptHeader, " | "))
	}

	for _, name := range []string{"unreachable_header_replacement", "header_validation_only"} {
		tokens := pythonFunctionLocalEndTokens(t, src, name)
		if tokenWithPrefix(tokens, "assignment_flow_reaches_operation:") != "" {
			t.Fatalf("%s emitted a request-principal replacement flow: %q", name, strings.Join(tokens, " | "))
		}
	}

	requestSession := pythonFunctionLocalEndTokens(t, src, "request_selected_session")
	if tokenWithPrefix(requestSession, "assignment_flow_reaches_store:source_category=request;store=session;source=request.form;key=account_id;value=request.form[\"account_id\"]") == "" {
		t.Fatalf("request-selected session identity was not correlated: %q", strings.Join(requestSession, " | "))
	}
	authenticatedSession := pythonFunctionLocalEndTokens(t, src, "authenticated_record_session")
	if tokenWithPrefix(authenticatedSession, "assignment_flow_reaches_store:") != "" {
		t.Fatalf("authenticated record identity was classified as request-selected: %q", strings.Join(authenticatedSession, " | "))
	}
}

func TestPythonFunctionLocalEndControlEvidenceHasReservedBudgets(t *testing.T) {
	var saturated strings.Builder
	saturated.WriteString("def saturated_handler(document_id):\n")
	saturated.WriteString("    principal_id = session.get(\"user_id\")\n")
	for i := 0; i < 700; i++ {
		saturated.WriteString("    value_")
		saturated.WriteString(strconv.Itoa(i))
		saturated.WriteString(" = ")
		saturated.WriteString(strconv.Itoa(i))
		saturated.WriteString("\n")
	}
	saturated.WriteString("    if document.owner_id != principal_id:\n")
	saturated.WriteString("        abort(403)\n")
	saturated.WriteString("    db.commit()\n")
	saturated.WriteString("    return document\n")
	tokens := uniqueTokens(pythonFunctionLocalEndTokens(t, saturated.String(), "saturated_handler"))
	basePrefixes := []string{"function_name:", "param_name:", "param_index:", "assign:", "assign_item:", "assign_call:", "call_path:", "call:", "selector:", "identifier:", "subscript:", "index_base:", "index_key:", "expr:", "literal:", "python_review:"}
	baseCount := 0
	for _, token := range tokens {
		for _, prefix := range basePrefixes {
			if strings.HasPrefix(token, prefix) {
				baseCount++
				break
			}
		}
	}
	if baseCount != 512 {
		t.Fatalf("base token budget = %d, want saturated budget 512", baseCount)
	}
	terminalCount := countTokensWithPrefix(tokens, "terminal_guard_blocks_")
	if terminalCount == 0 || terminalCount > 128 {
		t.Fatalf("terminal evidence count = %d, want 1..128", terminalCount)
	}
	reachableCount := countTokensWithPrefix(tokens, "reachable_call_method:")
	if reachableCount == 0 || reachableCount > 32 {
		t.Fatalf("reachable-method evidence count = %d, want 1..32", reachableCount)
	}
	if baseCount+terminalCount+reachableCount > 672 {
		t.Fatalf("structured evidence exceeded total reserved budgets: base=%d terminal=%d reachable=%d", baseCount, terminalCount, reachableCount)
	}

	var operations strings.Builder
	operations.WriteString("def bounded_operations(document_id):\n")
	operations.WriteString("    principal_id = session.get(\"user_id\")\n")
	operations.WriteString("    if document.owner_id != principal_id:\n")
	operations.WriteString("        abort(403)\n")
	for i := 0; i < 80; i++ {
		operations.WriteString("    audit_")
		operations.WriteString(strconv.Itoa(i))
		operations.WriteString("(document)\n")
	}
	operationTokens := pythonFunctionLocalEndTokens(t, operations.String(), "bounded_operations")
	if got := countTokensWithPrefix(operationTokens, "terminal_guard_blocks_call:"); got > 64 {
		t.Fatalf("per-guard operation/orientation cap exceeded: got %d, want <= 64", got)
	}

	var uses strings.Builder
	uses.WriteString("def bounded_uses(left, right):\n")
	uses.WriteString("    if left != right:\n")
	uses.WriteString("        abort(403)\n")
	uses.WriteString("    return (")
	for i := 0; i < 80; i++ {
		if i > 0 {
			uses.WriteString(", ")
		}
		uses.WriteString("value_")
		uses.WriteString(strconv.Itoa(i))
	}
	uses.WriteString(")\n")
	useTokens := pythonFunctionLocalEndTokens(t, uses.String(), "bounded_uses")
	if got := countTokensWithPrefix(useTokens, "terminal_guard_blocks_return:"); got > 32 {
		t.Fatalf("per-guard use/orientation cap exceeded: got %d, want <= 32", got)
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
		if !strings.HasPrefix(token, "terminal_guard_blocks_") {
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
	if tokenWithPrefix(tokens, "terminal_guard_blocks_call:operation=register;") != "" {
		t.Fatalf("lambda capture was classified as a same-scope later use: %q", strings.Join(tokens, " | "))
	}
}

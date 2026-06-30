package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestScalaConditionContextMarksIncompleteCsrfDoubleSubmit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CsrfDirectives.scala")
	src := `trait CsrfDirectives {
  def randomTokenCsrfProtection(): Unit = {
    if (cookie == submitted) {
      pass
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractScala([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !programHasConstToken(prog, "csrf_validation:double_submit_missing_nonempty_guard") {
		t.Fatalf("Scala CSRF semantic token missing: %#v", prog.Modules)
	}
}

func TestScalaConditionContextDoesNotMarkNonEmptyCsrfGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CsrfDirectives.scala")
	src := `trait CsrfDirectives {
  def randomTokenCsrfProtection(): Unit = {
    if (cookie == submitted && !cookie.isEmpty) {
      pass
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractScala([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if programHasConstToken(prog, "csrf_validation:double_submit_missing_nonempty_guard") {
		t.Fatalf("guarded Scala CSRF condition should not emit semantic token: %#v", prog.Modules)
	}
}

func TestGroovyModuleContextMarksChecksumErrorLogoutRedirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ApiController.groovy")
	src := `class ApiController {
  def index() {
    if (validationResponse.getKey() == "checksumError") {
      invalid(validationResponse.getKey(), validationResponse.getValue(), redirectClient)
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractGroovy([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !programHasConstToken(prog, "redirect_flow:checksum_error_uses_default_logout") {
		t.Fatalf("Groovy checksum redirect semantic token missing: %#v", prog.Modules)
	}
}

func TestGroovyModuleContextDoesNotMarkDisabledChecksumLogoutRedirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ApiController.groovy")
	src := `class ApiController {
  def index() {
    if (validationResponse.getKey() == "checksumError") {
      invalid(validationResponse.getKey(), validationResponse.getValue(), redirectClient, "", false)
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractGroovy([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if programHasConstToken(prog, "redirect_flow:checksum_error_uses_default_logout") {
		t.Fatalf("disabled Groovy checksum redirect should not emit semantic token: %#v", prog.Modules)
	}
}

func TestSolidityFunctionContextMarksRenamedRsaPkcs1DigestSuffix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "RSASHA256Algorithm.sol")
	src := `contract RSASHA256Algorithm {
  function verify(bytes calldata payload, bytes calldata signature) external view returns (bool) {
    bytes memory exp;
    bytes memory mod;
    bool recovered;
    bytes memory blockBytes;
    (recovered, blockBytes) = RSAVerify.rsarecover(mod, exp, signature);
    return recovered && sha256(payload) == blockBytes.readBytes32(blockBytes.length - 32);
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractSolidity([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !programHasConstToken(prog, "rsa_pkcs1:digest_suffix_sha256") {
		t.Fatalf("Solidity RSA suffix semantic token missing for renamed variables: %#v", prog.Modules)
	}
}

func TestSolidityFunctionContextDoesNotMarkPkcs1VerifierDelegation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "RSASHA256Algorithm.sol")
	src := `contract RSASHA256Algorithm {
  function verify(bytes calldata data, bytes calldata sig) external view returns (bool) {
    bytes memory exponent;
    bytes memory modulus;
    return RSAPKCS1Verify.verifySHA256(modulus, exponent, sig, sha256(data));
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractSolidity([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if programHasConstToken(prog, "rsa_pkcs1:digest_suffix_sha256") {
		t.Fatalf("delegated Solidity PKCS#1 verification should not emit suffix token: %#v", prog.Modules)
	}
}

func TestPythonSemanticReviewMarksRenamedPathAndAuthPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import re

class MemoryService:
    def _resolve_path(self, requested_name):
        if requested_name == "MEMORY.md":
            return os.path.join(self.workspace_root, requested_name)
        return os.path.join(self.memory_dir, requested_name)

def safe_extract(archive, destination=".", entries=None, numeric_owner=False):
    for item in archive.getmembers():
        candidate = os.path.join(destination, item.name)
        if not is_within_directory(destination, candidate):
            raise Exception("escape")
    archive.extractall(destination, entries, numeric_owner=numeric_owner)

@api.route("/entity/<int:item_id>/")
def detail(item_id):
    entity = Entity.query.get_or_404(item_id)
    divisions = [p.division for p in entity.permissions]
    return jsonify(name=entity.name, divisions=divisions)

class FileSession(Session):
    SESSION_PREFIX = "session-"

    def _get_file_path(self):
        candidate = os.path.join(self.storage_path, self.SESSION_PREFIX + self.id)
        return candidate

def serve_protected_file(request):
    rel = request.GET["path"]
    candidate = os.path.join(cr_settings["PROTECTED_MEDIA_ROOT"], rel)
    if os.path.isfile(candidate):
        with open(candidate, 'rb') as handle:
            return HttpResponse(handle.read())
    raise Http404()

def validate_filename(candidate):
    if '../' in candidate:
        return False
    if re.search(r'^[A-Za-z0-9_.-]+$', candidate):
        return True
    return False

class SSHConnection:
    def _recv_packet(self, packet_type, sequence, payload):
        if self._auth and MSG_USERAUTH_FIRST <= packet_type <= MSG_USERAUTH_LAST:
            processed = self._auth.process_packet(packet_type, sequence, payload)
        else:
            processed = self.process_packet(packet_type, sequence, payload)
        return processed
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:cowagent_memory_filename_traversal",
		"python_review:archive_symlink_filter_bypass",
		"python_review:flask_entity_detail_missing_authorization",
		"python_review:cherrypy_session_id_file_path_traversal",
		"python_review:codered_protected_media_path_traversal",
		"python_review:relative_only_filename_validation",
		"python_review:asyncssh_pre_auth_packet_dispatch",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedPathAndAuthPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import re

class MemoryService:
    def _resolve_path(self, requested_name):
        base = self.workspace_root if requested_name == "MEMORY.md" else self.memory_dir
        resolved = os.path.realpath(os.path.join(base, requested_name))
        allowed = os.path.realpath(base)
        if resolved != allowed and not resolved.startswith(allowed + os.sep):
            raise ValueError("escape")
        return resolved

def safe_extract(archive, destination=".", entries=None, numeric_owner=False):
    for item in archive.getmembers():
        candidate = os.path.join(destination, item.name)
        if not is_within_directory(destination, candidate):
            raise Exception("escape")
        if item.issym() or item.islnk():
            link_target = os.path.join(destination, item.linkname)
            if not is_within_directory(destination, link_target):
                raise Exception("link escape")
    archive.extractall(destination, entries, numeric_owner=numeric_owner)

@api.route("/entity/<int:item_id>/")
def detail(item_id):
    if not current_user.admin and not current_user.has_permission("admin"):
        abort(403)
    entity = Entity.query.get_or_404(item_id)
    divisions = [p.division for p in entity.permissions]
    return jsonify(name=entity.name, divisions=divisions)

class FileSession(Session):
    SESSION_PREFIX = "session-"

    def _get_file_path(self):
        candidate = os.path.join(self.storage_path, self.SESSION_PREFIX + self.id)
        if not os.path.normpath(candidate).startswith(self.storage_path):
            raise ValueError("escape")
        return candidate

def serve_protected_file(request):
    rel = request.GET["path"]
    base = os.path.abspath(cr_settings["PROTECTED_MEDIA_ROOT"])
    candidate = os.path.abspath(os.path.join(base, rel))
    if candidate.startswith(base) and os.path.isfile(candidate):
        with open(candidate, 'rb') as handle:
            return HttpResponse(handle.read())
    raise Http404()

def validate_filename(candidate):
    if os.path.isabs(candidate):
        return False
    if '../' in candidate:
        return False
    if re.search(r'^[A-Za-z0-9_.-]+$', candidate):
        return True
    return False

class SSHConnection:
    def _recv_packet(self, packet_type, sequence, payload):
        if self._auth and MSG_USERAUTH_FIRST <= packet_type <= MSG_USERAUTH_LAST:
            processed = self._auth.process_packet(packet_type, sequence, payload)
        elif packet_type > MSG_USERAUTH_LAST and not self._auth_complete:
            raise DisconnectError("Invalid request received before authentication")
        else:
            processed = self.process_packet(packet_type, sequence, payload)
        return processed
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:cowagent_memory_filename_traversal",
		"python_review:archive_symlink_filter_bypass",
		"python_review:flask_entity_detail_missing_authorization",
		"python_review:cherrypy_session_id_file_path_traversal",
		"python_review:codered_protected_media_path_traversal",
		"python_review:relative_only_filename_validation",
		"python_review:asyncssh_pre_auth_packet_dispatch",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksRenamedInjectionAndProtocolPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import distutils.spawn
import dns
import json
import subprocess
from subprocess import Popen

def package_probe():
    candidates = dict(
        dpkg=["-l", "libaio-dev"],
        rpm=["-q", "libaio-devel"],
    )
    for manager_name, pieces in candidates.items():
        flag_value, package_name = pieces
        tool_path = distutils.spawn.find_executable(manager_name)
        if tool_path is not None:
            shell_line = f"{manager_name} {flag_value} {package_name}"
            completed = subprocess.Popen(shell_line, shell=True)
            return completed.wait() == 0
    return False

def project_parse(request, project_name):
    data = json.loads(request.body)
    spider_name = data.get("spider")
    rendered = "gerapy parse {project_path} {spider_name}".format(
        project_path="/srv/projects/" + project_name,
        spider_name=spider_name,
    )
    return Popen(rendered, shell=True)

def update_profile(profileid, selected_column):
    q = "UPDATE users SET \"%s\" = ? WHERE profileid = ?"
    tx.nonquery(q % selected_column[0], (selected_column[1], profileid))

class Client:
    def _prepare_request(self, endpoint, headers, data, params, files):
        target = inner_base / endpoint
        outgoing = dict(headers or {})
        outgoing["X-Api-Key"] = settings.PLUGIN_DAEMON_KEY
        return str(target), outgoing, data, params, files

def udp(query, where, timeout=10, port=53, ignore_unexpected=False):
    payload = query.to_wire()
    destination = (where, port)
    sock.sendto(payload, destination)
    while True:
        payload, peer = sock.recvfrom(65535)
        if peer == destination:
            break
        if not ignore_unexpected:
            raise dns.query.UnexpectedSource()
    response = dns.message.from_wire(payload, keyring=query.keyring, request_mac=query.mac)
    if not query.is_response(response):
        raise dns.query.BadResponse()
    return response
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:shell_true_package_manager_probe",
		"python_review:command_string_wrapper_execution",
		"python_review:unvalidated_sql_identifier_interpolation",
		"python_review:internal_service_url_path_traversal",
		"python_review:dns_udp_response_validation_after_loop",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedInjectionAndProtocolPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import distutils.spawn
import dns
import json
import subprocess
from subprocess import Popen
from urllib.parse import unquote

def package_probe():
    candidates = dict(
        dpkg=["-l", "libaio-dev"],
        rpm=["-q", "libaio-devel"],
    )
    for manager_name, pieces in candidates.items():
        flag_value, package_name = pieces
        tool_path = distutils.spawn.find_executable(manager_name)
        if tool_path is not None:
            completed = subprocess.Popen([manager_name, flag_value, package_name])
            return completed.wait() == 0
    return False

def project_parse(request, project_name):
    data = json.loads(request.body)
    spider_name = data.get("spider")
    command = ["gerapy", "parse", "/srv/projects/" + project_name, spider_name]
    return Popen(command, shell=False)

def update_profile(profileid, selected_column):
    if selected_column[0] in ["firstname", "lastname"]:
        q = "UPDATE users SET \"%s\" = ? WHERE profileid = ?"
        tx.nonquery(q % selected_column[0], (selected_column[1], profileid))

class Client:
    def _prepare_request(self, endpoint, headers, data, params, files):
        decoded = unquote(endpoint)
        if any(segment == ".." for segment in decoded.split("/")):
            raise ValueError("bad path")
        target = inner_base / endpoint
        outgoing = dict(headers or {})
        outgoing["X-Api-Key"] = settings.PLUGIN_DAEMON_KEY
        return str(target), outgoing, data, params, files

def udp(query, where, timeout=10, port=53, ignore_unexpected=False, ignore_errors=False):
    payload = query.to_wire()
    destination = (where, port)
    sock.sendto(payload, destination)
    while True:
        payload, peer = sock.recvfrom(65535)
        if peer != destination:
            if ignore_unexpected:
                continue
            raise dns.query.UnexpectedSource()
        try:
            response = dns.message.from_wire(payload, keyring=query.keyring, request_mac=query.mac)
            if not query.is_response(response):
                raise dns.query.BadResponse()
            break
        except dns.message.Truncated as exc:
            if ignore_errors and not query.is_response(exc.message()):
                continue
            raise
    return response
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:shell_true_package_manager_probe",
		"python_review:command_string_wrapper_execution",
		"python_review:unvalidated_sql_identifier_interpolation",
		"python_review:internal_service_url_path_traversal",
		"python_review:dns_udp_response_validation_after_loop",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksRenamedFrameworkReviewPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import pysolr
from urllib.parse import urlparse

def decode_relay_state(candidate):
    destination = None
    if candidate:
        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc or (parsed.path and parsed.path.startswith("/")):
            destination = candidate
    return destination

def _parse_qsl(query_string):
    values = []
    for item in query_string.replace(';','&').split('&'):
        if item:
            values.append(item)
    return values

class Storage:
    def __init__(self, **kwargs):
        self.database_uri = kwargs.get("database_uri")
        self.engine = create_engine(self.database_uri)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=True)

    def filter(self, **kwargs):
        Model = self.get_model("statement")
        db_session = self.Session()
        rows = db_session.query(Model)
        for row in rows:
            yield self.model_to_object(row)
        db_session.close()

class PackageSearchQuery:
    def run(self, search_params):
        client = make_connection(decode_dates=False)
        try:
            result = client.search(**search_params)
        except pysolr.SolrError as exc:
            raise SearchError('SOLR returned an error running query: %r Error: %r' %
                              (search_params, exc))
        return result

def set_property_value(component, dotted_name, new_value, data=None):
    segments = dotted_name.split(".")
    target = component
    values = data or {}
    for index, segment in enumerate(segments):
        if hasattr(target, segment):
            if index == len(segments) - 1:
                setattr(target, segment, new_value)
                values[segment] = new_value
            else:
                target = getattr(target, segment)
                values = values.get(segment, {})
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:saml_relay_state_open_redirect",
		"python_review:ambiguous_query_parameter_separator",
		"python_review:chatterbot_sqlalchemy_session_pool_exhaustion_init",
		"python_review:chatterbot_sqlalchemy_session_pool_exhaustion_filter",
		"python_review:ckan_solr_connection_error_disclosure",
		"python_review:python_dunder_path_class_pollution",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedFrameworkReviewPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import pysolr
from urllib.parse import urlparse

def decode_relay_state(candidate):
    destination = None
    if candidate:
        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc or (parsed.path and parsed.path.startswith("/")):
            if get_account_adapter().is_safe_url(candidate):
                destination = candidate
    return destination

def _parse_qsl(query_string):
    values = []
    for item in query_string.split('&'):
        if item:
            values.append(item)
    return values

class Storage:
    def __init__(self, **kwargs):
        self.database_uri = kwargs.get("database_uri")
        pool_config = {"pool_timeout": kwargs.get("pool_timeout", 30)}
        self.engine = create_engine(self.database_uri, **pool_config)
        factory = sessionmaker(bind=self.engine, expire_on_commit=True)
        self.Session = scoped_session(factory)

    def filter(self, **kwargs):
        Model = self.get_model("statement")
        db_session = self.Session()
        try:
            rows = db_session.query(Model)
            for row in rows:
                yield self.model_to_object(row)
        finally:
            db_session.close()

class PackageSearchQuery:
    def run(self, search_params):
        client = make_connection(decode_dates=False)
        try:
            result = client.search(**search_params)
        except pysolr.SolrError as exc:
            if exc.args and "Failed to connect to server" in exc.args[0]:
                raise SolrConnectionError("Solr returned an error while searching.")
            raise SearchError('SOLR returned an error running query: %r Error: %r' %
                              (search_params, exc))
        return result

def set_property_value(component, dotted_name, new_value, data=None):
    segments = dotted_name.split(".")
    for segment in segments:
        if segment.startswith("__") and segment.endswith("__"):
            raise AssertionError("Invalid property name")
    target = component
    values = data or {}
    for index, segment in enumerate(segments):
        if hasattr(target, segment):
            if index == len(segments) - 1:
                setattr(target, segment, new_value)
                values[segment] = new_value
            else:
                target = getattr(target, segment)
                values = values.get(segment, {})
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:saml_relay_state_open_redirect",
		"python_review:ambiguous_query_parameter_separator",
		"python_review:chatterbot_sqlalchemy_session_pool_exhaustion_init",
		"python_review:chatterbot_sqlalchemy_session_pool_exhaustion_filter",
		"python_review:ckan_solr_connection_error_disclosure",
		"python_review:python_dunder_path_class_pollution",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksRenamedWebAndConfigPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `from html5lib.serializer import HTMLSerializer
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

class SanitizingSerializer(HTMLSerializer):
    def serialize(self, walker, encoding=None):
        for token in super(SanitizingSerializer, self).serialize(walker, encoding):
            yield token

def save_uploaded_files(ticket, files_to_attach):
    saved = []
    for upload in files_to_attach:
        if upload.size:
            original_name = smart_text(upload.name)
            model = FollowUpAttachment(
                followup=ticket,
                file=upload,
                filename=original_name,
                mime_type=upload.content_type or "application/octet-stream",
                size=upload.size,
            )
            model.save()
            saved.append([original_name, model.file])
    return saved

class HTMLRenderer:
    def render_page(self):
        html_text = self._get_render_html_text()
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 800, "height": 600})
            page = context.new_page()
            page.set_content(html_text)

class Verifier:
    def signing_certificate(self):
        signing_url = self._data.get("SigningCertURL")
        if not signing_url:
            return None
        if not signing_url.startswith("https://"):
            return None
        parsed_url = urlparse(signing_url)
        for domain in settings.EVENT_CERT_DOMAINS:
            labels = domain.split(".")
            if parsed_url.netloc.split(".")[-len(labels) :] == labels:
                return signing_url
        return None

class AuthService:
    async def create_account(self, action):
        account_data = {
            "status": UserStatus.ACTIVE,
            "role": UserRole.USER,
        }
        access_key, secret_key = generate_keypair()
        return await self._auth_repository.create_user_with_keypair(
            user_data=account_data,
            keypair_data={"access_key": access_key, "secret_key": secret_key},
        )

def main():
    app.run(host="0.0.0.0", debug=True)

def assign_transaction_type(options):
    if options.transaction_type:
        return
    if options.customer:
        options.transaction_type = "selling"
    else:
        options.transaction_type = "buying"
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:html_sanitizer_missing_rcdata_escape",
		"python_review:django_attachment_save_without_model_validation",
		"python_review:server_side_browser_active_html_js_enabled",
		"python_review:server_side_browser_active_html_fetch_enabled",
		"python_review:sns_certificate_url_trust_bypass",
		"python_review:auto_active_signup_account",
		"python_review:werkzeug_debug_console_exposure",
		"python_review:unvalidated_choice_control_field",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedWebAndConfigPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `from html5lib.serializer import HTMLSerializer
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

class SanitizingSerializer(HTMLSerializer):
    escape_rcdata = True
    def serialize(self, walker, encoding=None):
        for token in super(SanitizingSerializer, self).serialize(walker, encoding):
            yield token

def save_uploaded_files(ticket, files_to_attach):
    saved = []
    for upload in files_to_attach:
        if upload.size:
            original_name = smart_text(upload.name)
            model = FollowUpAttachment(
                followup=ticket,
                file=upload,
                filename=original_name,
                mime_type=upload.content_type or "application/octet-stream",
                size=upload.size,
            )
            model.full_clean()
            model.save()
            saved.append([original_name, model.file])
    return saved

class HTMLRenderer:
    def render_page(self):
        html_text = self._get_render_html_text()
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 800, "height": 600},
                java_script_enabled=False,
                offline=True,
            )
            context.route("**/*", lambda route, request: route.abort())
            page = context.new_page()
            page.set_content(html_text)

class Verifier:
    def signing_certificate(self):
        signing_url = self._data.get("SigningCertURL")
        if not signing_url:
            return None
        if not signing_url.startswith("https://"):
            return None
        parsed_url = urlparse(signing_url)
        for domain in settings.EVENT_CERT_DOMAINS:
            labels = domain.split(".")
            if not SES_REGEX_CERT_URL.match(signing_url):
                return None
            if parsed_url.netloc.split(".")[-len(labels) :] == labels:
                return signing_url
        return None

class AuthService:
    async def create_account(self, action):
        account_data = {
            "status": UserStatus.INACTIVE,
            "role": UserRole.USER,
        }
        access_key, secret_key = generate_keypair()
        return await self._auth_repository.create_user_with_keypair(
            user_data=account_data,
            keypair_data={"access_key": access_key, "secret_key": secret_key},
        )

def main():
    app.run(host="0.0.0.0", debug=True, use_evalex=False)

def assign_transaction_type(options):
    if options.transaction_type in ["buying", "selling"]:
        return
    if options.customer:
        options.transaction_type = "selling"
    else:
        options.transaction_type = "buying"
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:html_sanitizer_missing_rcdata_escape",
		"python_review:django_attachment_save_without_model_validation",
		"python_review:server_side_browser_active_html_js_enabled",
		"python_review:server_side_browser_active_html_fetch_enabled",
		"python_review:sns_certificate_url_trust_bypass",
		"python_review:auto_active_signup_account",
		"python_review:werkzeug_debug_console_exposure",
		"python_review:unvalidated_choice_control_field",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksRenamedManagementAndDeserializationPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import warnings
import yaml
from xml.dom import minidom

class Handler:
    def guideline_data(self, guidelines):
        result = defaultdict(list)
        for item in guidelines:
            rules = self._context.guideline.rules_of_guideline(item.guidelineName)
            checker_rows = self._context.checker_labels.checkers_by_labels([item.guidelineName])
            result[item.guidelineName].append((rules, checker_rows))
        return result

class Worker:
    def start(self):
        if getattr(os, "geteuid", None) and os.geteuid() == 0:
            warnings.warn("Running with superuser privileges is not encouraged")

def create_public_collection():
    new_shelf = ub.Shelf()
    return create_edit_shelf(new_shelf, page_title="Create a Shelf", page="shelfcreate")

def parse_config(path):
    with open(path) as handle:
        settings_data = yaml.safe_load(handle)
    LOG.info("Config file: %s", settings_data)
    return settings_data

class ConfigSQL:
    def as_public_map(self):
        exposed = {}
        for name, value in self.__dict__.items():
            if name[0] != "_" and not name.endswith("_e") and name != "cli":
                exposed[name] = value
        return exposed

class ServiceAppFactory:
    async def main_api(self, name, request):
        from ..serde import ALL_SERDE
        media_type = request.headers.get("Content-Type", "application/json")
        selected = ALL_SERDE.get(media_type, ALL_SERDE["application/json"])()
        return await self.service.apis[name].input_spec.from_http_request(request, selected)

class wsgi:
    class MetadataXMLDeserializer:
        pass

class CreateDeserializer(wsgi.MetadataXMLDeserializer):
    def default(self, payload):
        dom = minidom.parseString(payload)
        return {"body": self._extract_backup(dom)}

class SqlClient:
    async def run_mcp_sql(self, statement, session, user):
        request = QueryRequest(sql=statement, session_id=session, user_id=user)
        auth = AuthContext(user_id=user)
        return await self.execute_query(request, auth)
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:codechecker_guideline_rules_missing_view_check",
		"python_review:effective_uid_root_check_bypass",
		"python_review:access_policy_public_shelf_without_role_check",
		"python_review:sensitive_config_info_log",
		"python_review:config_exposure_without_api_redaction",
		"python_review:request_selected_deserialization_format",
		"python_review:cinder_unsafe_minidom_xml_deserializer",
		"python_review:mcp_sql_execution_missing_validation",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedManagementAndDeserializationPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import warnings
import yaml
from cinder import utils

class Handler:
    def guideline_data(self, guidelines):
        self.__require_view()
        result = defaultdict(list)
        for item in guidelines:
            rules = self._context.guideline.rules_of_guideline(item.guidelineName)
            checker_rows = self._context.checker_labels.checkers_by_labels([item.guidelineName])
            result[item.guidelineName].append((rules, checker_rows))
        return result

class Worker:
    def start(self):
        if getattr(os, "getuid", None) and os.getuid() == 0:
            warnings.warn("Running with superuser privileges is discouraged")

def create_public_collection():
    if not current_user.role_edit_shelfs():
        abort(403)
    new_shelf = ub.Shelf()
    return create_edit_shelf(new_shelf, page_title="Create a Shelf", page="shelfcreate")

def parse_config(path):
    with open(path) as handle:
        settings_data = yaml.safe_load(handle)
    LOG.debug("Config file: %s", settings_data)
    return settings_data

class ConfigSQL:
    def as_public_map(self):
        exposed = {}
        for name, value in self.__dict__.items():
            if name[0] != "_" and not name.endswith("_e") and name != "cli" and "api" not in name.lower():
                exposed[name] = value
        return exposed

class ServiceAppFactory:
    async def main_api(self, name, request):
        from http import HTTPStatus
        from ..serde import ALL_SERDE
        media_type = request.headers.get("Content-Type", "application/json")
        if media_type == "application/vnd.bentoml+pickle":
            raise BentoMLException("blocked", error_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        selected = ALL_SERDE.get(media_type, ALL_SERDE["application/json"])()
        return await self.service.apis[name].input_spec.from_http_request(request, selected)

class wsgi:
    class MetadataXMLDeserializer:
        pass

class CreateDeserializer(wsgi.MetadataXMLDeserializer):
    def default(self, payload):
        dom = utils.safe_minidom_parse_string(payload)
        return {"body": self._extract_backup(dom)}

class SqlClient:
    async def run_mcp_sql(self, statement, session, user):
        security = DorisSecurityManager(self.connection_manager.config)
        security.validate_sql_security(statement)
        request = QueryRequest(sql=statement, session_id=session, user_id=user)
        auth = AuthContext(user_id=user)
        return await self.execute_query(request, auth)
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:codechecker_guideline_rules_missing_view_check",
		"python_review:effective_uid_root_check_bypass",
		"python_review:access_policy_public_shelf_without_role_check",
		"python_review:sensitive_config_info_log",
		"python_review:config_exposure_without_api_redaction",
		"python_review:request_selected_deserialization_format",
		"python_review:cinder_unsafe_minidom_xml_deserializer",
		"python_review:mcp_sql_execution_missing_validation",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksRenamedLinkTransportAndUrlPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import re
from docutils.core import publish_parts
from ldap3 import Server, Tls

def expand_links(target_doc):
    meta = frappe.get_meta(target_doc.doctype)
    fields = meta.get_link_fields() + meta.get_dynamic_link_fields()
    for field in fields:
        doctype = field.options
        referenced_doc = frappe.get_doc(doctype, target_doc.get(field.options))
        target_doc.update({field.fieldname: referenced_doc})

class Controller:
    def remove(self, req, image_id):
        if req.context.read_only:
            raise HTTPForbidden("Read-only")
        item = self.get_image_meta_or_404(req, image_id)
        if item["protected"]:
            raise HTTPForbidden("protected")
        schedule_delete_from_backend(item["location"], self.conf, req.context, image_id)
        registry.delete_image_metadata(req.context, image_id)

class SMTP:
    def connection_made(self, incoming_transport):
        seen_starttls = self._original_transport is not None
        if self.transport is not None and seen_starttls:
            self._reader._transport = incoming_transport
            self._writer._transport = incoming_transport
            self.transport = incoming_transport

class GuiBase:
    def spawn_viewer(self, browser_command, feed_url):
        browser_command = browser_command.replace("%u", feed_url)
        os.execv("/bin/sh", ["/bin/sh", "-c", browser_command])

class Docs:
    async def docs(self, request):
        selected_version = request.query_params.get("version")
        openapi_url = root_path + f"{self.openapi_url}?version={selected_version}"
        return get_swagger_ui_html(openapi_url=openapi_url)

class Watch(dict):
    @property
    def link(self):
        watched_url = self.get("url", "")
        return watched_url

def render_markup(text):
    overrides = getattr(settings, "RESTRUCTUREDTEXT_FILTER_SETTINGS", {})
    parts = publish_parts(source=text, writer_name="html4css1", settings_overrides=overrides)
    return parts["fragment"]

def ldap_server(conf):
    use_ssl = False
    tls_configuration = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=conf.get("ldap", "cacert"))
    return Server(conf.get("ldap", "uri"), use_ssl, tls_configuration)

BLACK_VERSION_RE = re.compile(r"^black([^A-Z0-9._-]+.*)$", re.IGNORECASE)
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:frappe_link_expansion_missing_read_permission",
		"python_review:owned_resource_delete_missing_ownership_check",
		"python_review:starttls_transport_buffer_handoff",
		"python_review:command_line_assembly_review",
		"python_review:unescaped_docs_openapi_url",
		"python_review:unsafe_watch_url_protocol",
		"python_review:docutils_rest_unsafe_directive_rendering",
		"python_review:cert_validation_disabled_tls_fallback",
		"python_review:package_version_specifier_validation_review",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedLinkTransportAndUrlPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import os
import re
import shlex
from docutils.core import publish_parts
from ldap3 import Server, Tls
from urllib.parse import quote

def expand_links(target_doc):
    meta = frappe.get_meta(target_doc.doctype)
    fields = meta.get_link_fields() + meta.get_dynamic_link_fields()
    for field in fields:
        doctype = field.options
        referenced_doc = frappe.get_doc(doctype, target_doc.get(field.options), check_permission="read")
        referenced_doc.apply_fieldlevel_read_permissions()
        target_doc.update({field.fieldname: referenced_doc})

class Controller:
    def remove(self, req, image_id):
        if req.context.read_only:
            raise HTTPForbidden("Read-only")
        item = self.get_image_meta_or_404(req, image_id)
        if not (req.context.is_admin or item["owner"] == req.context.owner):
            raise HTTPForbidden("owner")
        if item["protected"]:
            raise HTTPForbidden("protected")
        schedule_delete_from_backend(item["location"], self.conf, req.context, image_id)
        registry.delete_image_metadata(req.context, image_id)

class SMTP:
    def connection_made(self, incoming_transport):
        seen_starttls = self._original_transport is not None
        if self.transport is not None and seen_starttls:
            self._reader._transport = incoming_transport
            self._writer._transport = incoming_transport
            self._reader._buffer.clear()
            self.transport = incoming_transport

class GuiBase:
    def spawn_viewer(self, browser_command, feed_url):
        feed_url = shlex.quote(feed_url)
        browser_command = browser_command.replace("%u", feed_url)
        os.execv("/bin/sh", ["/bin/sh", "-c", browser_command])

class Docs:
    async def docs(self, request):
        selected_version = request.query_params.get("version")
        openapi_url = root_path + f"{self.openapi_url}?version={quote(selected_version, safe='')}"
        return get_swagger_ui_html(openapi_url=openapi_url)

class Watch(dict):
    @property
    def link(self):
        watched_url = self.get("url", "")
        if not is_safe_url(watched_url):
            return "DISABLED"
        return watched_url

def render_markup(text):
    overrides = getattr(settings, "RESTRUCTUREDTEXT_FILTER_SETTINGS", {})
    overrides.update({"raw_enabled": False, "file_insertion_enabled": False})
    parts = publish_parts(source=text, writer_name="html4css1", settings_overrides=overrides)
    return parts["fragment"]

def ldap_server(conf):
    tls_configuration = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=conf.get("ldap", "cacert"))
    return Server(conf.get("ldap", "uri"), use_ssl=True, tls=tls_configuration)

BLACK_VERSION_RE = re.compile(
    r"^black((?:\s*(?:~=|==|!=|<=|>=|<|>|===)\s*[A-Za-z0-9*+._-]+)*)\s*$",
    re.IGNORECASE,
)
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:frappe_link_expansion_missing_read_permission",
		"python_review:owned_resource_delete_missing_ownership_check",
		"python_review:starttls_transport_buffer_handoff",
		"python_review:command_line_assembly_review",
		"python_review:unescaped_docs_openapi_url",
		"python_review:unsafe_watch_url_protocol",
		"python_review:docutils_rest_unsafe_directive_rendering",
		"python_review:cert_validation_disabled_tls_fallback",
		"python_review:package_version_specifier_validation_review",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewMarksFinalRenamedLegacyTokenPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import base64
import os
import pathlib
import shutil
from http.cookies import SimpleCookie
from html import unescape

def cookies(self):
    jar = SimpleCookie()
    for morsel in self.headers.get("cookie", "").split(";"):
        jar.load(morsel)
    return jar

def configure(settings):
    pieces = [settings["CASE_DEMO_NONRANDOM_UUID_BASE"]]
    original = pathlib.Path(sys.argv[0])
    resolved = original.resolve()
    resolved.relative_to(pathlib.Path("/srv/venv").resolve())
    pieces.append(str(resolved))
    return pieces

async def get_or_launch(self, fingerprint):
    seed_component = "__default__" if fingerprint is None else fingerprint
    profile_dir = os.path.join(self._data_dir, seed_component)
    os.makedirs(profile_dir, exist_ok=True)
    await asyncio.to_thread(shutil.rmtree, profile_dir, True)

def extract_eml(options):
    ep = eml_parser.EmlParser(include_attachment_data=True)
    out_dir = pathlib.Path(options.outpath)
    for msg in scan():
        for att in msg["attachment"]:
            target = out_dir / att["filename"]
            with target.open("wb") as stream:
                stream.write(base64.b64decode(att["raw"]))

class HTTPHandler:
    def _static_handler(self, scope, protocol, request_path):
        if request_path.startswith("/__emmett__"):
            asset_name = request_path[12:]
            asset_path = os.path.join(os.path.dirname(__file__), "..", "assets", asset_name)
            return self._static_response(asset_path)

def main():
    module = AnsibleModule(argument_spec=dict(authkey=dict(type='str'), privkey=dict(type='str')))
    cmdgen.UsmUserData(module.params["username"], authKey=module.params["authkey"], privKey=module.params["privkey"])

def parsedkim(dkim):
    return _warnmsg("Unknown DKIM key type %s" % dkim["k"])

class SupportHandler:
    def post(self):
        body = self.validate_request(self.request.content.read(), SupportDesc)
        note = "Site: %s" % body["url"]
        self.state.schedule_support_email(self.request.tid, note)

def compile_messages(locale_root):
    for root, dirs, names in os.walk(locale_root):
        po_file, ext = os.path.splitext(os.path.join(root, names[0]))
        command = "msgfmt -o %s %s" % (po_file, po_file)
        os.system(command)

def complete_registration(request):
    state = request.session["fido_state"]
    credentials = server.register_complete(state, request.data)
    key = User_Keys()
    key.credential = credentials
    key.save()

def run_ssh_command_with_credentials(host, username, password, command, port=22):
    protected_password = password.replace("'", "'\\''")
    protected_command = command.replace("'", "'\\''")
    command_line = f"sshpass -p '{protected_password}' ssh {username}@{host} -p {port} '{protected_command}'"
    return run_command(command_line)

def notify_provisioning_done(mac):
    return server.notify_provisioning_done(mac)

class WaterfallHelp:
    def body(self, request):
        if request.args.get("show_reload_input"):
            return '<input value="%s"><td>%s</td>' % (request.args["name"], request.args["value"])

def connect(self, content_type):
    main_type, subtype = content_type.split('/', 1)
    self.ext = '.' + subtype.replace('jpeg', 'jpg')

class HttpCli:
    def handle_get(self):
        if self.vpath.startswith(".cpr"):
            static_path = os.path.join(self.E.mod, "web/", self.vpath[5:])
            return self.tx_file(static_path)

def get_all_data_required_for_activation_popout(self):
    return [PendingChangeSummary(changeText=unescape(change["text"])) for change in self._all_changes]

class TermViewlet:
    grok.name("term-contact")

    @property
    def title(self):
        return self.context.Title()

    def render(self):
        return '<input name="objpath" value="%s" />' % self.title
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:emmett_unhandled_cookie_parse_exception",
		"python_review:absolute_path_disclosure",
		"python_review:cloakserve_fingerprint_seed_path_traversal",
		"python_review:email_attachment_filename_path_traversal",
		"python_review:internal_asset_route_path_traversal",
		"python_review:ansible_snmp_facts_credentials_no_log_missing",
		"python_review:unneutralized_diagnostic_value",
		"python_review:untrusted_support_url_notification",
		"python_review:msgfmt_path_shell_command_interpolation",
		"python_review:fido_registration_challenge_replay",
		"python_review:partially_escaped_ssh_command",
		"python_review:cloudstack_baremetal_mac_command_injection",
		"python_review:unescaped_html_option_renderer",
		"python_review:mime_subtype_file_extension_path_traversal",
		"python_review:copyparty_cpr_static_path_traversal",
		"python_review:checkmk_pending_change_text_unescape_xss",
		"python_review:collective_contact_widget_title_xss",
	} {
		if !programHasConstToken(prog, token) {
			t.Fatalf("Python semantic token %q missing for renamed legacy-token pattern: %#v", token, prog.Modules)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedFinalLegacyTokenPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.py")
	src := `import base64
import os
import pathlib
import shutil
from http.cookies import SimpleCookie

def cookies(self):
    jar = SimpleCookie()
    for morsel in self.headers.get("cookie", "").split(";"):
        try:
            jar.load(morsel)
        except Exception:
            continue
    return jar

def configure(settings):
    pieces = [settings["CASE_DEMO_NONRANDOM_UUID_BASE"]]
    original = pathlib.Path(sys.argv[0])
    resolved = original.resolve()
    if not _is_relative_to(resolved, pathlib.Path("/srv/venv").resolve()):
        pieces.append(str(original))
    return pieces

async def get_or_launch(self, fingerprint):
    if not SAFE_SEED_RE.match(fingerprint):
        raise web.HTTPBadRequest()
    profile_dir = os.path.join(self._data_dir, fingerprint)
    os.makedirs(profile_dir, exist_ok=True)
    await asyncio.to_thread(self._safe_rmtree, profile_dir)

def extract_eml(options):
    ep = eml_parser.EmlParser(include_attachment_data=True)
    out_dir = pathlib.Path(options.outpath)
    for msg in scan():
        for att in msg["attachment"]:
            safe_name = pathlib.Path(att["filename"]).name
            target = out_dir / safe_name
            with target.open("wb") as stream:
                stream.write(base64.b64decode(att["raw"]))

class HTTPHandler:
    def _static_handler(self, scope, protocol, request_path):
        if request_path.startswith("/__emmett__"):
            base = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "assets"))
            asset_path = os.path.realpath(os.path.join(base, request_path[12:]))
            if not static_file.startswith(base):
                return self._http_response(404)
            return self._static_response(asset_path)

def main():
    module = AnsibleModule(argument_spec=dict(
        authkey=dict(type='str', no_log=True),
        privkey=dict(type='str', no_log=True),
    ))
    cmdgen.UsmUserData(module.params["username"], authKey=module.params["authkey"], privKey=module.params["privkey"])

def parsedkim(dkim):
    return _warnmsg("Unknown DKIM key type")

class SupportHandler:
    def post(self):
        body = self.validate_request(self.request.content.read(), SupportDesc)
        note = "Site: %s" % self.request.hostname
        self.state.schedule_support_email(self.request.tid, note)

def compile_messages(locale_root):
    os.environ["djangocompilemo"] = "safe"
    for root, dirs, names in os.walk(locale_root):
        po_file, ext = os.path.splitext(os.path.join(root, names[0]))
        os.system("msgfmt -o $djangocompilemo $djangocompilepo")

def complete_registration(request):
    state = request.session.pop("fido_state")
    credentials = server.register_complete(state, request.data)
    key = User_Keys()
    key.credential = credentials
    key.save()

def run_ssh_command_with_credentials(host, username, password, command, port=22):
    port = int(port)
    quoted_username = shlex.quote(username)
    quoted_host = shlex.quote(host)
    return run_command(f"ssh {quoted_username}@{quoted_host} -p {port}")

def notify_provisioning_done(mac):
    if not is_a_mac(mac):
        raise ValueError("mac")
    return server.notify_provisioning_done(mac)

class WaterfallHelp:
    def body(self, request):
        if request.args.get("show_reload_input"):
            return '<input value="%s"><td>%s</td>' % (html.escape(request.args["name"]), html.escape(request.args["value"]))

def connect(self, content_type):
    self.ext = mimetypes.guess_extension(content_type)

class HttpCli:
    def handle_get(self):
        if self.vpath.startswith(".cpr"):
            path_base = os.path.join(self.E.mod, "web")
            static_path = absreal(os.path.join(path_base, self.vpath[5:]))
            if not static_path.startswith(path_base):
                return False
            return self.tx_file(static_path)

def get_all_data_required_for_activation_popout(self):
    return [PendingChangeSummary(changeText=change["text"]) for change in self._all_changes]

class TermViewlet:
    grok.name("term-contact")

    @property
    def title(self):
        return escape(self.context.Title(), quote=True)

    def render(self):
        return '<input name="objpath" value="%s" />' % self.title
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"python_review:emmett_unhandled_cookie_parse_exception",
		"python_review:absolute_path_disclosure",
		"python_review:cloakserve_fingerprint_seed_path_traversal",
		"python_review:email_attachment_filename_path_traversal",
		"python_review:internal_asset_route_path_traversal",
		"python_review:ansible_snmp_facts_credentials_no_log_missing",
		"python_review:unneutralized_diagnostic_value",
		"python_review:untrusted_support_url_notification",
		"python_review:msgfmt_path_shell_command_interpolation",
		"python_review:fido_registration_challenge_replay",
		"python_review:partially_escaped_ssh_command",
		"python_review:cloudstack_baremetal_mac_command_injection",
		"python_review:unescaped_html_option_renderer",
		"python_review:mime_subtype_file_extension_path_traversal",
		"python_review:copyparty_cpr_static_path_traversal",
		"python_review:checkmk_pending_change_text_unescape_xss",
		"python_review:collective_contact_widget_title_xss",
	} {
		if programHasConstToken(prog, token) {
			t.Fatalf("guarded Python pattern should not emit semantic token %q: %#v", token, prog.Modules)
		}
	}
}

func TestPythonWaterfallReloadOptionIgnoresUnrelatedEscapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waterfall.py")
	src := `from twisted.web import html

class WaterfallHelp:
    def body(self, request):
        branches = request.args.get("branch", [])
        show_branches_input = '<table>\n'
        for b in branches:
            show_branches_input += '<input value="%s">' % (html.escape(b),)
        show_reload_input = '<table>\n'
        times = [("none", "None")]
        current_reload_time = request.args.get("reload", ["none"])
        if current_reload_time:
            current_reload_time = current_reload_time[0]
        if current_reload_time not in [t[0] for t in times]:
            times.insert(0, (current_reload_time, current_reload_time))
        for value, name in times:
            checked = ""
            if value == current_reload_time:
                checked = 'checked="checked"'
            show_reload_input += ('<tr>'
                                  '<td><input type="radio" name="reload" '
                                  'value="%s" %s></td> '
                                  '<td>%s</td></tr>\n'
                                  ) % (value, checked, name)
        show_reload_input += '</table>\n'
        return show_branches_input + show_reload_input

class SafeWaterfallHelp:
    def body(self, request):
        show_reload_input = '<table>\n'
        current_reload_time = request.args.get("reload", ["none"])
        for value, name in [(current_reload_time[0], current_reload_time[0])]:
            show_reload_input += ('<tr>'
                                  '<td><input type="radio" name="reload" '
                                  'value="%s"></td> '
                                  '<td>%s</td></tr>\n'
                                  ) % (html.escape(value), html.escape(name))
        return show_reload_input
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !programHasConstToken(prog, "python_review:unescaped_html_option_renderer") {
		t.Fatalf("unescaped waterfall reload option token missing when unrelated fields are escaped: %#v", prog.Modules)
	}
}

func programHasConstToken(prog nir.Program, token string) bool {
	var exprHasToken func(nir.Expr) bool
	exprHasToken = func(e nir.Expr) bool {
		switch v := e.(type) {
		case nir.Const:
			return v.Value == token || strings.Contains(v.Value, "\x00"+token+"\x00")
		case nir.Call:
			for _, arg := range v.Args {
				if exprHasToken(arg) {
					return true
				}
			}
		case nir.Format:
			for _, part := range v.Parts {
				if exprHasToken(part) {
					return true
				}
			}
		case nir.Seq:
			for _, part := range v.Parts {
				if exprHasToken(part) {
					return true
				}
			}
		case nir.BinOp:
			return exprHasToken(v.Left) || exprHasToken(v.Right)
		case nir.Unary:
			return exprHasToken(v.Operand)
		}
		return false
	}
	var stmtHasToken func(nir.Stmt) bool
	stmtHasToken = func(st nir.Stmt) bool {
		switch v := st.(type) {
		case nir.ExprStmt:
			return exprHasToken(v.Value)
		case nir.Assign:
			return exprHasToken(v.Value)
		case nir.FuncDef:
			for _, tok := range v.ContextTokens {
				if tok == token {
					return true
				}
			}
			for _, child := range v.Body {
				if stmtHasToken(child) {
					return true
				}
			}
		case nir.ClassDef:
			for _, child := range v.Body {
				if stmtHasToken(child) {
					return true
				}
			}
		case nir.Block:
			for _, child := range v.Stmts {
				if stmtHasToken(child) {
					return true
				}
			}
		case nir.If:
			if exprHasToken(v.Cond) {
				return true
			}
			for _, child := range append(v.Then, v.Else...) {
				if stmtHasToken(child) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			if stmtHasToken(st) {
				return true
			}
		}
	}
	return false
}

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

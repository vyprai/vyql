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
			"function_name:verify_and_process",
			"param_name:request",
			"assign:self._state=request.query_params.get(\"state\")",
			"assign_call:self._state:request.query_params.get",
			"call_path:request.cookies.get",
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

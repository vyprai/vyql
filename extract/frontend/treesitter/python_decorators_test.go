package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestPythonFunctionContextIncludesDecorators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "views.py")
	src := []byte(`from django.views.decorators.http import require_POST

@require_POST
def sync(request):
    remote.background_sync({}, request.session["token"])
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
		if strings.Contains(args, "name=sync") &&
			strings.Contains(args, "remote.background_sync") &&
			strings.Contains(args, "decorator_path:require_POST") {
			return
		}
	}
	t.Fatalf("python function context did not include decorator token; nodes=%#v", nodes)
}

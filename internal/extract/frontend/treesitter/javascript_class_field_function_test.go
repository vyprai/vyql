package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// A class-property arrow — how a method that must keep `this` bound is written —
// is a field_definition, not a method_definition. Its body has to be lowered as a
// function definition, or the calls and sinks inside it are dead code.
func TestTypeScriptClassFieldArrowFunctionIsLowered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.ts")
	src := []byte(`
export class Runner {
  private readonly run = (cmd: string) => {
    require('child_process').execSync(cmd);
  };

  handle = async (req: Request) => {
    this.sink.write(req.query.name);
  };

  legacy = function (cmd: string) {
    require('child_process').execSync(cmd);
  };
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		call string
	}{
		{"run", "execSync"},
		{"handle", "write"},
		{"legacy", "execSync"},
	} {
		fn, ok := findFuncDef(prog, tc.name)
		if !ok {
			t.Fatalf("class field function %s was not extracted; program=%#v", tc.name, prog)
		}
		if !funcBodyHasCall(fn.Body, tc.call) {
			t.Fatalf("class field function %s body did not include %s call; body=%#v", tc.name, tc.call, fn.Body)
		}
	}
	if fn, _ := findFuncDef(prog, "run"); len(fn.Params) != 1 || fn.Params[0] != "cmd" {
		t.Fatalf("class field arrow parameters were not lowered; params=%#v", fn.Params)
	}

	graph, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := graph.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, n := range nodes {
		if n.Type == "code.Call" && strings.Contains(n.Prop("callee_path"), "execSync") {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("call inside a class field arrow never reached the graph; nodes=%#v", nodes)
	}
}

// The object-literal handler dictionary a class field can also hold keeps its
// existing lowering: the function case must not swallow it.
func TestTypeScriptClassFieldObjectMethodsStillLowered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.ts")
	src := []byte(`
export class Editor {
  static events = {
    paste(event: ClipboardEvent) {
      document.body.innerHTML = event.clipboardData.getData('text');
    },
  };
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "paste")
	if !ok {
		t.Fatalf("class field object method paste was not extracted; program=%#v", prog)
	}
	if !funcBodyHasPath(fn.Body, "document.body.innerHTML") {
		t.Fatalf("class field object method body was not lowered; body=%#v", fn.Body)
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestBashModuleContextIncludesRawAndCompactText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	src := "#!/bin/bash\ninput=$(cat)\npython3 -c \"json.loads('''$input''')\"\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractBash([]string{path}, dir)
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
		"lang=bash",
		"input=$(cat)",
		"python3-c\"json.loads('''$input''')\"",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("module context missing %q in %q", want, joined)
		}
	}
}

func TestBashNestedDefaultExpansionKeepsSourceVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "case.sh")
	src := `payload="${BenchmarkTest00006:-${QUERY_STRING:-}}"
cmd="echo $payload"
eval "$cmd"
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractBash([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(prog.Modules))
	}
	if !moduleHasCallPath(prog.Modules[0], "shell_input") {
		t.Fatalf("nested QUERY_STRING default expansion did not emit shell_input: %#v", prog.Modules[0].Body)
	}
}

func moduleHasCallPath(mod nir.Module, path string) bool {
	var exprHasCallPath func(nir.Expr) bool
	exprHasCallPath = func(e nir.Expr) bool {
		switch v := e.(type) {
		case nir.Call:
			if v.Path == path {
				return true
			}
			for _, arg := range v.Args {
				if exprHasCallPath(arg) {
					return true
				}
			}
		case nir.Format:
			for _, part := range v.Parts {
				if exprHasCallPath(part) {
					return true
				}
			}
		case nir.Seq:
			for _, part := range v.Parts {
				if exprHasCallPath(part) {
					return true
				}
			}
		case nir.BinOp:
			return exprHasCallPath(v.Left) || exprHasCallPath(v.Right)
		case nir.Unary:
			return exprHasCallPath(v.Operand)
		}
		return false
	}
	for _, st := range mod.Body {
		switch v := st.(type) {
		case nir.Assign:
			if exprHasCallPath(v.Value) {
				return true
			}
		case nir.ExprStmt:
			if exprHasCallPath(v.Value) {
				return true
			}
		}
	}
	return false
}

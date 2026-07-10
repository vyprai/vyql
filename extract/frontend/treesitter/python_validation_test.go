package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func extractPythonFunction(t *testing.T, src, name string) nir.FuncDef {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.py")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, mod := range prog.Modules {
		for _, stmt := range mod.Body {
			if fn, ok := stmt.(nir.FuncDef); ok && fn.Name == name {
				return fn
			}
		}
	}
	t.Fatalf("function %q not found", name)
	return nir.FuncDef{}
}

func validationStatements(stmts []nir.Stmt) []nir.Validation {
	var out []nir.Validation
	for _, stmt := range stmts {
		switch st := stmt.(type) {
		case nir.Validation:
			out = append(out, st)
		case nir.Block:
			out = append(out, validationStatements(st.Stmts)...)
		}
	}
	return out
}

func TestPythonTerminalRejectLoopEmitsCharacterValidation(t *testing.T) {
	fn := extractPythonFunction(t, `def sanitize(value):
    blocked = ["<", ">", "'", '"']
    rendered = "<p>{}</p>".format(value)
    for ch in blocked:
        if ch in value:
            return ""
    return rendered
`, "sanitize")
	got := validationStatements(fn.Body)
	if len(got) != 1 || got[0].Target != "value" || got[0].Kind != "character_rejection" {
		t.Fatalf("validations=%#v", got)
	}
	if _, ok := got[0].Evidence.(nir.Name); !ok {
		t.Fatalf("evidence=%T, want nir.Name", got[0].Evidence)
	}
}

func TestPythonCharacterValidationRejectsUnprovenLoops(t *testing.T) {
	cases := map[string]string{
		"non_terminal": `def f(v):
    for ch in ["<", ">"]:
        if ch in v:
            log(ch)
    return v`,
		"different_needle": `def f(v, other):
    for ch in ["<", ">"]:
        if other in v:
            return ""
    return v`,
		"loop_break": `def f(v):
    for ch in ["<", ">"]:
        if ready():
            break
        if ch in v:
            return ""
    return v`,
		"loop_else": `def f(v):
    for ch in ["<", ">"]:
        if ch in v:
            return ""
    else:
        audit(v)
    return v`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			fn := extractPythonFunction(t, src, "f")
			if got := validationStatements(fn.Body); len(got) != 0 {
				t.Fatalf("unexpected validation: %#v", got)
			}
		})
	}
}

func TestPythonTerminalSyntaxUsesTerminateNIR(t *testing.T) {
	fn := extractPythonFunction(t, `def f(v):
    if v:
        raise ValueError(v)
    abort(403)
    return v
`, "f")
	ifNode, ok := fn.Body[0].(nir.If)
	if !ok || len(ifNode.Then) != 1 {
		t.Fatalf("if body=%#v", fn.Body)
	}
	if term, ok := ifNode.Then[0].(nir.Terminate); !ok || term.Kind != "raise" {
		t.Fatalf("raise=%#v", ifNode.Then)
	}
	if term, ok := fn.Body[1].(nir.Terminate); !ok || term.Kind != "abort" {
		t.Fatalf("abort=%#v", fn.Body)
	}
}

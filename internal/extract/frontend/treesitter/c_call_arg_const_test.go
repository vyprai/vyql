package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCCallArgConstTokens pins the fact that carries a constant string's
// content to the call that consumes it: `call_arg_const:<callee>:<content>` and
// `call_arg_const_at:<callee>:<position>:<content>`, the family the compacted
// `call_arg` / `call_arg_at` pair already spells. A launch whose command line
// is decided away from the call -- a static initialiser of a global table, a
// configuration string, a helper's return, a const local -- would otherwise
// arrive at the call as the bare name that reads it, and the bare-name and
// absolute-path spellings of the same launch would be indistinguishable to
// every binding. Each quiet case is a value this file does not fix: a mutable
// object's initialiser, a reassigned local, a helper with two returns, a table
// whose entries disagree at an index the file does not fix.
func TestCCallArgConstTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "launch.c")
	src := []byte(`
#include <windows.h>

struct editor {
    const char *fullPath;
    const char *openFileCmd;
};

/* the configuration spellings: a scalar object and a table of aggregates */
static const char kPinCmd[] = "C:\\Windows\\notepad.exe \"%f\"";
static const char *kBareCmd = "notepad.exe \"%f\"";
static const struct editor kEditors[] = {
    { "C:\\Windows\\edit.exe", "\"C:\\Windows\\edit.exe\" \"%f\"" },
    { "notepad.exe", "notepad.exe \"%f\"" },
};
static const char *kArgs[] = { "--flag", "--flag" };
static const struct editor kNamed[] = {
    { .fullPath = "C:\\Windows\\notepad.exe", .openFileCmd = "C:\\Windows\\notepad.exe /p" },
};

/* the mutable spellings: no store may claim these, in this file or another */
static char kMutableCmd[] = "notepad.exe";
static const char *kRuntimeCmd = load_default_cmd();

static const char *helper_one_return(void) { return "notepad.exe -x"; }
static const char *helper_two_returns(int c) {
    if (c) { return "notepad.exe"; }
    return "C:\\Windows\\notepad.exe";
}

void launch_inline(void) {
    CreateProcessW(NULL, L"notepad.exe \"%f\"", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_global(void) {
    CreateProcessW(NULL, kBareCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, (LPCSTR)kPinCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_table(int i) {
    CreateProcessW(NULL, kEditors[1].openFileCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kEditors[0].openFileCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kArgs[i], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kEditors[i].openFileCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kEditors[i].fullPath, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kNamed[0].openFileCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_helper(void) {
    CreateProcessW(NULL, helper_one_return(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_local(void) {
    const char *cmd = kBareCmd;
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_runtime(int c) {
    char *cmd = kMutableCmd;
    const char *picked = helper_two_returns(c);
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, picked, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessW(NULL, kRuntimeCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void launch_reassigned(void) {
    const char *cmd = "notepad.exe";
    cmd = getenv("EDITOR");
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, fire := range []struct{ fn, token string }{
		// the direct spelling: the literal is the argument
		{"launch_inline", "call_arg_const:CreateProcessW:notepad.exe \"%f\""},
		{"launch_inline", "call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\""},
		// a configuration string read by name, and the same through a cast
		{"launch_global", "call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\""},
		{"launch_global", "call_arg_const_at:CreateProcessW:1:C:\\Windows\\notepad.exe \"%f\""},
		// one entry of a table of aggregates, at a fixed index; the leading
		// quote is content, not a delimiter to strip
		{"launch_table", "call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\""},
		{"launch_table", "call_arg_const_at:CreateProcessW:1:\"C:\\Windows\\edit.exe\" \"%f\""},
		// a table of pointers whose entries agree, at an index the file does not fix
		{"launch_table", "call_arg_const_at:CreateProcessW:1:--flag"},
		// designated initialisers name their field rather than pairing by position
		{"launch_table", "call_arg_const_at:CreateProcessW:1:C:\\Windows\\notepad.exe /p"},
		// a helper whose only return is the literal
		{"launch_helper", "call_arg_const_at:CreateProcessW:1:notepad.exe -x"},
		// a const local the body itself binds, from a global the file fixes
		{"launch_local", "call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\""},
	} {
		if got := cFuncContextTokens(prog.Modules[0].Body, fire.fn); !strings.Contains(got, fire.token) {
			t.Fatalf("%s missing context token %q; context=%q", fire.fn, fire.token, got)
		}
	}
	for _, quiet := range []struct{ fn, token string }{
		// a mutable object's initialiser says nothing about its later value
		{"launch_runtime", "call_arg_const_at:CreateProcessW:1:notepad.exe"},
		// a helper with two returns fixes no content
		{"launch_runtime", "call_arg_const_at:CreateProcessW:1:notepad.exe -x"},
		{"launch_runtime", "call_arg_const_at:CreateProcessW:1:C:\\Windows\\notepad.exe"},
		// an initialiser that is not a literal fixes no content
		{"launch_runtime", "call_arg_const:CreateProcessW:load_default_cmd()"},
		// a local an assignment retargets no longer holds its initialiser
		{"launch_reassigned", "call_arg_const_at:CreateProcessW:1:notepad.exe"},
		// entries that disagree at an unfixed index state nothing for the field
		{"launch_table", "call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\"\""},
	} {
		if got := cFuncContextTokens(prog.Modules[0].Body, quiet.fn); strings.Contains(got, quiet.token) {
			t.Fatalf("%s should not carry context token %q; context=%q", quiet.fn, quiet.token, got)
		}
	}
}

// TestCCallArgConstTableDisagree pins the one aggregate fact an unfixed index
// can carry: a table whose every entry fixes the same content for a field
// states that content, and a table with two different contents for it states
// nothing at all. This is the distinction the bare-name and absolute-path
// spellings of the same launch turn on.
func TestCCallArgConstTableDisagree(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "table.c")
	src := []byte(`
struct rule { const char *cmd; };

static const struct rule kAgree[] = { { "notepad.exe" }, { "notepad.exe" } };
static const struct rule kDiffer[] = { { "notepad.exe" }, { "C:\\Windows\\notepad.exe" } };

void launch_agree(int i) { CreateProcessW(NULL, kAgree[i].cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); }
void launch_differ(int i) { CreateProcessW(NULL, kDiffer[i].cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); }
void launch_whole_entry(int i) { CreateProcessW(NULL, kAgree[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); }
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := cFuncContextTokens(prog.Modules[0].Body, "launch_agree"); !strings.Contains(got, "call_arg_const_at:CreateProcessW:1:notepad.exe") {
		t.Fatalf("a table whose entries agree should state its content; context=%q", got)
	}
	if got := cFuncContextTokens(prog.Modules[0].Body, "launch_differ"); strings.Contains(got, "call_arg_const:CreateProcessW:") {
		t.Fatalf("a table whose entries differ states no content for an unfixed index; context=%q", got)
	}
	// an aggregate entry is not a string however many literals its initialiser
	// quotes; only a field of it is
	if got := cFuncContextTokens(prog.Modules[0].Body, "launch_whole_entry"); strings.Contains(got, "call_arg_const:CreateProcessW:") {
		t.Fatalf("a whole aggregate entry states no content; context=%q", got)
	}
}

// TestCCallArgConstCppTokens pins the same fact for the C++ frontend, whose
// grammar wraps a subscript's index in a subscript_argument_list and spells the
// null application name nullptr -- the shapes of the SumatraPDF launch the
// tokens exist to separate.
func TestCCallArgConstCppTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "launch.cpp")
	src := []byte(`
struct TextEditor {
    const char* binaryFilename = nullptr;
    const char* openFileCmd = nullptr;
};

static const TextEditor editorRules[] = {
    { "notepad.exe", "notepad.exe \"%f\"" },
    { "C:\\edit.exe", "\"C:\\edit.exe\" \"%f\"" },
};

static const char* DefaultCmd() { return "notepad.exe"; }

static void LaunchInverseSearch(int i) {
    const char* pattern = "notepad.exe \"%f\"";
    CreateProcessW(nullptr, editorRules[i].openFileCmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    CreateProcessW(nullptr, editorRules[0].openFileCmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    CreateProcessW(nullptr, DefaultCmd(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    CreateProcessW(nullptr, pattern, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"call_arg_const_at:CreateProcessW:1:notepad.exe \"%f\"",
		"call_arg_const:CreateProcessW:notepad.exe",
		"call_arg_const:CreateProcessW:notepad.exe \"%f\"",
	} {
		if got := cFuncContextTokens(prog.Modules[0].Body, "LaunchInverseSearch"); !strings.Contains(got, token) {
			t.Fatalf("LaunchInverseSearch missing context token %q; context=%q", token, got)
		}
	}
}

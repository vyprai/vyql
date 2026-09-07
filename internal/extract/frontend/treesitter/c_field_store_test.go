package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// A store into a pointer field is where a local stops being the only name for an
// allocation. The C frontend used to lower `sud->directory = data` through
// assignmentFallback to two bare expression statements — the field read on one side and
// the value on the other — so the store itself had no node to label and nothing recorded
// that the two now name one buffer. It emits the Method-less field-write call the other
// frontends already use for a member store instead.
func TestCPointerFieldStoreIsAFieldWriteCall(t *testing.T) {
	prog := extractCSource(t, "publish.c", `
static void publish(STARTUP_DATA *sud, WCHAR *data)
{
    sud->directory = data;
}
`)
	store, ok := cFieldStoreCall(prog, "sud.directory")
	if !ok {
		t.Fatalf("no field-write call for sud->directory: %#v", prog.Modules[0].Body)
	}
	if store.Method != "" {
		t.Errorf("field write method = %q, want empty (the shape lowering reads as a store)", store.Method)
	}
	if len(store.Args) != 1 {
		t.Fatalf("field write args = %d, want the assigned value only", len(store.Args))
	}
	value, ok := store.Args[0].(nir.Name)
	if !ok || value.ID != "data" {
		t.Errorf("field write value = %#v, want the local `data`", store.Args[0])
	}
	attr, ok := store.Callee.(nir.Attr)
	if !ok || attr.Attr != "directory" {
		t.Errorf("field write callee = %#v, want an Attr naming the field", store.Callee)
	}
}

// A dotted store spells the same thing for a value struct, and the same node has to come
// out of it.
func TestCValueFieldStoreIsAFieldWriteCall(t *testing.T) {
	prog := extractCSource(t, "publish_value.c", `
static void publish(STARTUP_DATA sud, WCHAR *data)
{
    sud.directory = data;
}
`)
	if _, ok := cFieldStoreCall(prog, "sud.directory"); !ok {
		t.Fatalf("no field-write call for sud.directory: %#v", prog.Modules[0].Body)
	}
}

// Clearing a field keeps its own analysis event — the fact the rule layer uses to say a
// release is covered — and gains the store node beside it.
func TestCFieldClearStillEmitsItsAnalysisEventAndAStoreNode(t *testing.T) {
	prog := extractCSource(t, "clear.c", `
static void clear(STARTUP_DATA *sud)
{
    sud->directory = NULL;
}
`)
	if _, ok := cFieldStoreCall(prog, "analysis.field.clear_null"); !ok {
		t.Fatalf("field clear event missing: %#v", prog.Modules[0].Body)
	}
	if _, ok := cFieldStoreCall(prog, "sud.directory"); !ok {
		t.Fatalf("no field-write call beside the clear event: %#v", prog.Modules[0].Body)
	}
}

// A store to a plain local stays an Assign: only a member target becomes a field write.
func TestCLocalAssignmentIsNotAFieldWriteCall(t *testing.T) {
	prog := extractCSource(t, "local.c", `
static void publish(WCHAR *data)
{
    WCHAR *copy = data;
    copy = data;
}
`)
	if call, ok := cFieldStoreCall(prog, "copy"); ok {
		t.Fatalf("local assignment became a field write: %#v", call)
	}
}

func extractCSource(t *testing.T, name, src string) nir.Program {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	return prog
}

// cFieldStoreCall finds the call with the given path anywhere in the program.
func cFieldStoreCall(prog nir.Program, path string) (nir.Call, bool) {
	var found nir.Call
	ok := false
	var walkStmts func([]nir.Stmt)
	walkExpr := func(e nir.Expr) {
		call, isCall := e.(nir.Call)
		if isCall && call.Path == path {
			found, ok = call, true
		}
	}
	walkStmts = func(stmts []nir.Stmt) {
		for _, s := range stmts {
			switch st := s.(type) {
			case nir.ExprStmt:
				walkExpr(st.Value)
			case nir.Assign:
				walkExpr(st.Value)
			case nir.FuncDef:
				walkStmts(st.Body)
			case nir.Block:
				walkStmts(st.Stmts)
			case nir.If:
				walkStmts(st.Then)
				walkStmts(st.Else)
			}
		}
	}
	for _, m := range prog.Modules {
		walkStmts(m.Body)
	}
	return found, ok
}

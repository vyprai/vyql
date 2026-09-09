package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccSALFunc is one function as the C frontend saw it.
type ccSALFunc struct {
	Params   []string
	Types    map[string]string
	Exported bool
	Tokens   []string
	Calls    []string
}

// ccSALFuncs extracts one translation unit and indexes the functions by name,
// together with the calls each one makes -- the call-graph edges out of it.
func ccSALFuncs(t *testing.T, file, src string) map[string]ccSALFunc {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(file, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ccSALFunc{}
	var calls func([]nir.Stmt) []string
	calls = func(body []nir.Stmt) []string {
		var got []string
		for _, st := range body {
			switch s := st.(type) {
			case nir.ExprStmt:
				if call, ok := s.Value.(nir.Call); ok {
					got = append(got, call.Path)
				}
			case nir.Return:
				if call, ok := s.Value.(nir.Call); ok {
					got = append(got, call.Path)
				}
			case nir.Block:
				got = append(got, calls(s.Stmts)...)
			case nir.If:
				got = append(got, calls(s.Then)...)
				got = append(got, calls(s.Else)...)
			case nir.Loop:
				got = append(got, calls(s.Body)...)
			}
		}
		return got
	}
	var walk func([]nir.Stmt)
	walk = func(body []nir.Stmt) {
		for _, st := range body {
			switch s := st.(type) {
			case nir.ClassDef:
				walk(s.Body)
			case nir.FuncDef:
				out[s.Name] = ccSALFunc{
					Params:   s.Params,
					Types:    s.ParamTypes,
					Exported: s.Exported,
					Tokens:   s.ContextTokens,
					Calls:    calls(s.Body),
				}
				walk(s.Body)
			}
		}
	}
	walk(prog.Modules[0].Body)
	return out
}

func hasToken(tokens []string, want string) bool {
	for _, tok := range tokens {
		if tok == want {
			return true
		}
	}
	return false
}

// salReceiver is msquic's QuicConnRecvHeader reduced to the shape that breaks
// the parse: SAL annotations stand before the return type and before each
// parameter's type, exactly as <sal.h>-annotated Windows sources spell them.
const salReceiver = `
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    )
{
    QuicConnRelease(Connection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicConnRecvHeader(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet,
    _Out_writes_all_(16) uint8_t* Cipher
    )
{
    if (!QuicPacketValidateInvariant(Connection, Packet)) {
        return FALSE;
    }
    QuicPacketLogDrop(Connection, Packet, "Key no longer accepted");
    return TRUE;
}
`

// A SAL-annotated definition must keep its name, its parameters, its exported
// mark and its call-graph edges. Before the annotations were neutralised, a
// leading `_Success_(...)` read as this definition's declarator and swallowed
// the whole function into one ERROR node, so QuicConnRecvHeader was absent
// from the module entirely and nothing could be asserted about it.
func TestCSALAnnotatedDefinitionKeepsItsFacts(t *testing.T) {
	funcs := ccSALFuncs(t, "connection.c", salReceiver)

	fn, ok := funcs["QuicConnRecvHeader"]
	if !ok {
		var names []string
		for name := range funcs {
			names = append(names, name)
		}
		t.Fatalf("QuicConnRecvHeader missing from the module; got %v", names)
	}
	if got, want := strings.Join(fn.Params, ","), "Connection,Packet,Cipher"; got != want {
		t.Errorf("params = %q, want %q", got, want)
	}
	if fn.Types["Connection"] != "QUIC_CONNECTION" {
		t.Errorf("param type of Connection = %q, want %q", fn.Types["Connection"], "QUIC_CONNECTION")
	}
	if fn.Types["Cipher"] != "uint8_t" {
		t.Errorf("param type of Cipher = %q, want %q", fn.Types["Cipher"], "uint8_t")
	}
	if !fn.Exported {
		t.Errorf("QuicConnRecvHeader lost its exported mark")
	}
	for _, want := range []string{
		"name=QuicConnRecvHeader",
		"call:QuicPacketValidateInvariant",
		"call_path:QuicPacketLogDrop",
		"param_type:QUIC_RX_PACKET",
	} {
		if !hasToken(fn.Tokens, want) {
			t.Errorf("context token %q missing; got %v", want, fn.Tokens)
		}
	}
	if got, want := strings.Join(fn.Calls, ","), "QuicPacketLogDrop"; got != want {
		t.Errorf("call-graph edges = %q, want %q", got, want)
	}

	// The legacy `__drv_freesMem(Mem)` annotation sits between `_In_` and the
	// parameter's type; the parameter's name has to survive both annotations.
	free, ok := funcs["QuicConnFree"]
	if !ok {
		t.Fatalf("QuicConnFree missing from the module")
	}
	if got, want := strings.Join(free.Params, ","), "Connection"; got != want {
		t.Errorf("QuicConnFree params = %q, want %q", got, want)
	}
}

// The same annotations in a C++ translation unit.
func TestCPPSALAnnotatedDefinitionKeepsItsFacts(t *testing.T) {
	funcs := ccSALFuncs(t, "connection.cpp", salReceiver)
	fn, ok := funcs["QuicConnRecvHeader"]
	if !ok {
		t.Fatalf("QuicConnRecvHeader missing from the C++ module")
	}
	if got, want := strings.Join(fn.Params, ","), "Connection,Packet,Cipher"; got != want {
		t.Errorf("params = %q, want %q", got, want)
	}
}

// A second annotated function must not cost the first one its facts: the two
// definitions are independent, and each is extracted the same whether it stands
// alone or beside the other.
func TestCSALSecondAnnotatedFunctionLeavesTheFirstIntact(t *testing.T) {
	const first = `
_Success_(return != FALSE)
BOOLEAN
Alpha(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(Len) const uint8_t* Buffer,
    _In_ uint16_t Len
    )
{
    return AlphaHelper(Connection, Buffer, Len);
}
`
	const second = `
_Success_(return != FALSE)
BOOLEAN
Beta(
    _In_ QUIC_CONNECTION* Connection,
    _Out_writes_all_(Len) uint8_t* Buffer,
    _In_ uint16_t Len
    )
{
    return BetaHelper(Connection, Buffer, Len);
}
`
	alone := ccSALFuncs(t, "a.c", first)["Alpha"]
	together := ccSALFuncs(t, "a.c", first+second)
	if _, ok := together["Beta"]; !ok {
		t.Fatalf("Beta missing when both annotated functions share a file")
	}
	got, ok := together["Alpha"]
	if !ok {
		t.Fatalf("Alpha missing when a second annotated function shares the file")
	}
	if strings.Join(alone.Params, ",") != "Connection,Buffer,Len" {
		t.Fatalf("Alpha params alone = %q", strings.Join(alone.Params, ","))
	}
	if strings.Join(got.Params, ",") != strings.Join(alone.Params, ",") {
		t.Errorf("Alpha params changed when Beta was added: %q vs %q",
			strings.Join(got.Params, ","), strings.Join(alone.Params, ","))
	}
	if !hasToken(got.Tokens, "call:AlphaHelper") {
		t.Errorf("Alpha lost its call-graph edge when Beta was added: %v", got.Tokens)
	}
}

// The blanking must not disturb anything else: it keeps byte offsets and line
// numbers, leaves preprocessor directives (include guards share SAL's shape)
// and string literals alone, and does not touch identifiers that merely start
// with an underscore.
func TestCStripSALLeavesTheRestOfTheFileAlone(t *testing.T) {
	const src = `#ifndef _MY_HEADER_H_
#define _MY_HEADER_H_
#define _In_
static const char *kName = "_In_ is an annotation";
_Bool Ready(_In_ int n) {
    // _In_ marks an input
    _Analysis_assume_(n > 0);
    return _Static_assert_helper(n) != 0;
}
#endif
`
	got := string(ccStripSAL([]byte(src)))
	if len(got) != len(src) {
		t.Fatalf("length changed: %d vs %d", len(got), len(src))
	}
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Errorf("line count changed")
	}
	for _, want := range []string{
		"#ifndef _MY_HEADER_H_",
		"#define _MY_HEADER_H_",
		"#define _In_",
		`"_In_ is an annotation"`,
		"_Bool Ready(",
		"_Static_assert_helper(n)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stripped source lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "_In_ int n") {
		t.Errorf("annotation on the parameter was not blanked:\n%s", got)
	}
	if strings.Contains(got, "_Analysis_assume_(n > 0)") {
		t.Errorf("annotation statement was not blanked:\n%s", got)
	}
}

func TestCIsSALAnnotation(t *testing.T) {
	for _, tok := range []string{"_In_", "_In_opt_", "_Out_writes_all_", "_Success_", "_When_",
		"_IRQL_requires_max_", "_Function_class_", "_Analysis_assume_", "__drv_freesMem"} {
		if !ccIsSALAnnotation([]byte(tok)) {
			t.Errorf("%q should be a SAL annotation", tok)
		}
	}
	for _, tok := range []string{"_", "_Bool", "_Atomic", "_Static_assert", "_Pragma", "_Generic",
		"_T", "_GNU_SOURCE", "__func__", "__attribute__", "__int64", "__inline", "_x_", "Connection"} {
		if ccIsSALAnnotation([]byte(tok)) {
			t.Errorf("%q should not be a SAL annotation", tok)
		}
	}
}

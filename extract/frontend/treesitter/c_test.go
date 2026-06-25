package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func TestCBoolValueNormalizesObjCAndCBoolLiterals(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"YES", "true", true},
		{"TRUE", "true", true},
		{"true", "true", true},
		{"NO", "false", true},
		{"FALSE", "false", true},
		{"false", "false", true},
		{"manager", "", false},
	}
	for _, c := range cases {
		got, ok := cBoolValue(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("cBoolValue(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCExtractsFunctionsInsidePreprocessorWrappers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "wrapped.c")
	src := []byte(`
int before(void) {
  return 1;
}

#ifdef FEATURE_ENABLED
int wrapped(void) {
  sink();
  return 0;
}
#endif
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	if !hasCFuncCall(prog.Modules[0].Body, "wrapped", "sink") {
		t.Fatalf("function inside #ifdef was not extracted with its call: %#v", prog.Modules[0].Body)
	}
}

func TestCExtractsFunctionsInsideRecoverablePreprocessorWrappers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "recoverable.c")
	src := []byte(`
#ifdef FEATURE_ENABLED
int wrapped(void) {
#if DEBUG
  if (ready) {
#endif
  sink();
#if DEBUG
  }
#endif
  return 0;
}
#endif
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	if !hasCFuncCall(prog.Modules[0].Body, "wrapped", "sink") {
		t.Fatalf("function inside recovered preprocessor region was not extracted: %#v", prog.Modules[0].Body)
	}
}

func TestCSwitchIncludesCasesInsidePreprocessorWrappers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "switch_preproc.c")
	src := []byte(`
void process(int tag) {
  switch (tag) {
  case PING_REQUEST:
    reply();
    break;
#if SUPPORT_OUTGOING_PINGS
  case PING_REPLY:
    validate();
    hook();
    break;
#endif
  case NEIGHBOR:
    refresh();
    break;
  }
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cFuncContextTokens(prog.Modules[0].Body, "process")
	for _, want := range []string{
		"switch_case:PING_REPLY",
		"call_path:validate",
		"call_path:hook",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("preprocessor-wrapped switch case missing context token %q; context=%q", want, tokens)
		}
	}
	if !hasCFuncCall(prog.Modules[0].Body, "process", "hook") {
		t.Fatalf("preprocessor-wrapped switch case body was not lowered: %#v", prog.Modules[0].Body)
	}
}

func TestCFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "params.c")
	src := []byte(`
static void merge_param(HashTable *params, zval *zdata) {
  zval **ptr, **test_ptr;
  uint8_t *tmp = pos;
  php_http_array_hashkey_t hkey;
  if (Z_TYPE_PP(test_ptr) == IS_ARRAY) {
    if (SUCCESS == zend_hash_find(Z_ARRVAL_PP(ptr), hkey.str, hkey.len, (void *) &ptr)) {
      value = test_ptr;
    } else if (SUCCESS == zend_hash_index_find(Z_ARRVAL_PP(ptr), hkey.num, (void *) &ptr)) {
      value = test_ptr;
    }
  }
  secret.Data[keyName] = value;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != "merge_param" {
			continue
		}
		tokens := strings.Join(fn.ContextTokens, "\x00")
		for _, want := range []string{
			"name=merge_param",
			"param_type:HashTable",
			"param_type:zval",
			"call_path:Z_TYPE_PP",
			"call_path:zend_hash_find",
			"call_arg:zend_hash_find:Z_ARRVAL_PP",
			"call_arg:Z_ARRVAL_PP:ptr",
			"call_path:zend_hash_index_find",
			"selector:secret.Data",
			"index:secret.Data[]",
			"index_key:keyName",
			"assign:tmp=pos",
			"assign:secret.Data[]=value",
		} {
			if !strings.Contains(tokens, want) {
				t.Fatalf("C function context missing %q; context=%q", want, tokens)
			}
		}
		return
	}
	t.Fatalf("merge_param function not extracted: %#v", prog.Modules[0].Body)
}

func TestCPPFunctionContextIncludesSwitchCaseAndDefaultCallTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "switch.cpp")
	src := []byte(`
bool parse(int tag, XDR* xdrs) {
  switch (tag) {
  case isc_arg_number:
  default:
    if (!xdr_long(xdrs, &tag))
      goto brk;
    break;
  }
brk:
  return false;
}

bool fixed(int tag, XDR* xdrs) {
  switch (tag) {
  case isc_arg_number:
    if (!xdr_long(xdrs, &tag))
      goto brk;
    break;
  default:
    goto brk;
  }
brk:
  return false;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	parseTokens := cFuncContextTokens(prog.Modules[0].Body, "parse")
	for _, want := range []string{
		"switch_case:isc_arg_number",
		"switch_default",
		"switch_default_call:xdr_long",
	} {
		if !strings.Contains(parseTokens, want) {
			t.Fatalf("parse context missing %q; context=%q", want, parseTokens)
		}
	}
	fixedTokens := cFuncContextTokens(prog.Modules[0].Body, "fixed")
	if !strings.Contains(fixedTokens, "switch_case:isc_arg_number") || !strings.Contains(fixedTokens, "switch_default") {
		t.Fatalf("fixed context missing switch case/default tokens; context=%q", fixedTokens)
	}
	if strings.Contains(fixedTokens, "switch_default_call:xdr_long") {
		t.Fatalf("fixed default should not call xdr_long; context=%q", fixedTokens)
	}
}

func TestCFunctionContextIncludesLateCallsInLargeFunction(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "large.c")
	var b strings.Builder
	b.WriteString("int parse(int attrlen) {\n")
	for i := 0; i < 700; i++ {
		b.WriteString("  attrlen += 1;\n")
	}
	b.WriteString("  pairfree(0);\n")
	b.WriteString("  debug_pair(0);\n")
	b.WriteString("  return attrlen;\n")
	b.WriteString("}\n")
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cFuncContextTokens(prog.Modules[0].Body, "parse")
	for _, want := range []string{"call_path:pairfree", "call_path:debug_pair"} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("large function context missing late token %q; context length=%d", want, len(strings.Split(tokens, "\x00")))
		}
	}
}

func TestCFunctionContextIncludesICMPEchoLengthTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "FreeRTOS_ND.c")
	src := []byte(`
void prvProcessICMPMessage_IPv6(NetworkBufferDescriptor_t *pxNetworkBuffer)
{
    switch (pxICMPHeader_IPv6->ucType)
    {
    case ipICMP_PING_REPLY_IPv6:
    {
        const ICMPEcho_IPv6_t * pxICMPEchoHeader = ( ( const ICMPEcho_IPv6_t * ) pxICMPHeader_IPv6 );
        size_t uxDataLength, uxCount;
        const uint8_t * pucByte;
        uxDataLength = ipNUMERIC_CAST( size_t, FreeRTOS_ntohs( pxICMPPacket->xIPHeader.usPayloadLength ) );
        uxDataLength = uxDataLength - sizeof( *pxICMPEchoHeader );
        pucByte = &( pucByte[ sizeof( *pxICMPEchoHeader ) ] );
        for( uxCount = 0; uxCount < uxDataLength; uxCount++ )
        {
            pucByte++;
        }
        vApplicationPingReplyHook( eSuccess, pxICMPEchoHeader->usIdentifier );
        break;
    }
    }
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cFuncContextTokens(prog.Modules[0].Body, "prvProcessICMPMessage_IPv6")
	for _, want := range []string{
		"name=prvProcessICMPMessage_IPv6",
		"switch_case:ipICMP_PING_REPLY_IPv6",
		"selector:pxICMPPacket.xIPHeader.usPayloadLength",
		"assign:uxDataLength=uxDataLength-sizeof(*pxICMPEchoHeader)",
		"selector:pxICMPEchoHeader.usIdentifier",
		"call_path:FreeRTOS_ntohs",
		"call_path:vApplicationPingReplyHook",
		"binary:uxDataLength-sizeof(*pxICMPEchoHeader)",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("ICMP echo context missing %q; context=%q", want, tokens)
		}
	}
}

func TestCModuleContextIncludesMacroBodyTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "xmltok_impl.c")
	src := []byte(`
#define CHECK_NAME_CASE(n, enc, ptr, end, nextTokPtr) \
   case BT_LEAD ## n: \
     if (end - ptr < n) \
       return XML_TOK_PARTIAL_CHAR; \
     if (!IS_NAME_CHAR(enc, ptr, n)) { \
       *nextTokPtr = ptr; \
       return XML_TOK_INVALID; \
     } \
     ptr += n; \
     break;

int marker(void) { return 0; }
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cModuleContextTokens(prog.Modules[0].Body)
	for _, want := range []string{
		"macro_name:CHECK_NAME_CASE",
		"macro_body:CHECK_NAME_CASE:",
		"if(!IS_NAME_CHAR(enc,ptr,n))",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("C module context missing macro token %q; context=%q", want, tokens)
		}
	}
}

func TestCFunctionContextIncludesIsolateLevelCapTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "fribidi-bidi.c")
	src := []byte(`
void vulnerable(void) {
  int isolate_level = 0;
  int this_type;
  int new_level;
  void *pp;
  int base_level_per_iso_level[FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL];
  void *run_per_isolate_level[FRIBIDI_BIDI_MAX_RESOLVED_LEVELS];

  if (FRIBIDI_IS_ISOLATE(this_type)) {
    RL_ISOLATE_LEVEL(pp) = isolate_level++;
    base_level_per_iso_level[isolate_level] = new_level;
  }
  run_per_isolate_level[isolate_level] = pp;
}

void fixed(void) {
  int isolate_level = 0;
  int this_type;
  int new_level;
  void *pp;
  int base_level_per_iso_level[FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL];

  if (FRIBIDI_IS_ISOLATE(this_type)) {
    RL_ISOLATE_LEVEL(pp) = isolate_level;
    if (isolate_level < FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL - 1)
      isolate_level++;
    base_level_per_iso_level[isolate_level] = new_level;
  }
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	vulnTokens := cFuncContextTokens(prog.Modules[0].Body, "vulnerable")
	for _, want := range []string{
		"call_path:FRIBIDI_IS_ISOLATE",
		"assign:RL_ISOLATE_LEVEL=isolate_level++",
		"assign:base_level_per_iso_level[]=new_level",
		"index:run_per_isolate_level[]",
	} {
		if !strings.Contains(vulnTokens, want) {
			t.Fatalf("vulnerable isolate-level context missing %q; context=%q", want, vulnTokens)
		}
	}
	fixedTokens := cFuncContextTokens(prog.Modules[0].Body, "fixed")
	if !strings.Contains(fixedTokens, "binary:isolate_level<FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL-1") {
		t.Fatalf("fixed isolate-level context missing cap guard token; context=%q", fixedTokens)
	}
}

func TestCZeroCountLastIndexObservationRequiresNonZeroGuard(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "frames.c")
	src := []byte(`
struct Frame { int size; };
struct Ctx { unsigned count; struct Frame *items; };

void vulnerable(struct Ctx *ctx) {
  ctx->items[ctx->count - 1].size = 4;
  int later = ctx->count == 0 ? 0 : 1;
}

void fixed(struct Ctx *ctx) {
  if (!ctx->count) {
    return;
  }
  ctx->items[ctx->count - 1].size = 4;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.zero_count.last_index", "guard=missing_nonzero") {
		t.Fatalf("vulnerable function missing zero-count last-index observation: %#v", prog.Modules[0].Body)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.zero_count.last_index", "guard=nonzero") {
		t.Fatalf("fixed function missing guarded zero-count last-index observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.zero_count.last_index", "guard=missing_nonzero") {
		t.Fatalf("fixed function should not emit missing_nonzero zero-count observation: %#v", prog.Modules[0].Body)
	}
}

func hasCFuncCall(stmts []nir.Stmt, funcName, method string) bool {
	for _, st := range stmts {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != funcName {
			continue
		}
		return hasCStmtCall(fn.Body, method)
	}
	return false
}

func cFuncContextTokens(stmts []nir.Stmt, funcName string) string {
	for _, st := range stmts {
		fn, ok := st.(nir.FuncDef)
		if ok && fn.Name == funcName {
			return strings.Join(fn.ContextTokens, "\x00")
		}
	}
	return ""
}

func cModuleContextTokens(stmts []nir.Stmt) string {
	for _, st := range stmts {
		expr, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.Value.(nir.Call)
		if ok && call.Path == "analysis.module.context" {
			var tokens []string
			for _, arg := range call.Args {
				c, ok := arg.(nir.Const)
				if ok {
					tokens = append(tokens, c.Value)
				}
			}
			return strings.Join(tokens, "\x00")
		}
	}
	return ""
}

func cFuncHasAnalysisToken(stmts []nir.Stmt, funcName, path, token string) bool {
	for _, st := range stmts {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != funcName {
			continue
		}
		for _, bodyStmt := range fn.Body {
			exprStmt, ok := bodyStmt.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := exprStmt.Value.(nir.Call)
			if !ok || call.Path != path {
				continue
			}
			for _, arg := range call.Args {
				c, ok := arg.(nir.Const)
				if ok && c.Value == token {
					return true
				}
			}
		}
	}
	return false
}

func hasCStmtCall(stmts []nir.Stmt, method string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.ExprStmt:
			if hasCExprCall(s.Value, method) {
				return true
			}
		case nir.Block:
			if hasCStmtCall(s.Stmts, method) {
				return true
			}
		case nir.If:
			if hasCStmtCall(s.Then, method) || hasCStmtCall(s.Else, method) {
				return true
			}
		case nir.Loop:
			if hasCStmtCall(s.Body, method) {
				return true
			}
		case nir.Switch:
			for _, c := range s.Cases {
				if hasCStmtCall(c, method) {
					return true
				}
			}
			if hasCStmtCall(s.Default, method) {
				return true
			}
		}
	}
	return false
}

func hasCExprCall(expr nir.Expr, method string) bool {
	switch e := expr.(type) {
	case nir.Call:
		return e.Method == method
	case nir.Thru:
		return hasCExprCall(e.Inner, method)
	case nir.Seq:
		for _, part := range e.Parts {
			if hasCExprCall(part, method) {
				return true
			}
		}
	}
	return false
}

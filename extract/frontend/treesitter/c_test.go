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
			return hasCExprCall(s.Value, method)
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

package treesitter

import (
	"bytes"
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
			"call_arg_at:zend_hash_find:0:Z_ARRVAL_PP",
			"call_arg:Z_ARRVAL_PP:ptr",
			"call_arg_at:Z_ARRVAL_PP:0:ptr",
			"call_path:zend_hash_index_find",
			"selector:secret.Data",
			"index:secret.Data[]",
			"index_key:keyName",
			"assign:tmp=pos",
			"assign:secret.Data[]=value",
			"call_arg_shape:Z_TYPE_PP:ID",
			"call_arg_shape:zend_hash_find:Z_ARRVAL_PP(ID)",
			"call_arg_shape_at:zend_hash_find:0:Z_ARRVAL_PP(ID)",
			"call_arg_shape:zend_hash_find:ID.FIELD",
			"binary_shape:Z_TYPE_PP(ID)==ID",
			"index_shape:ID.FIELD[ID]",
			"assign_shape:ID.FIELD[ID]=ID",
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

func TestCFunctionContextIncludesFlowSpecLoopBoundTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "flowspec.c")
	src := []byte(`
int bgp_flowspec_op_decode(int type, unsigned char *nlri_ptr,
                           unsigned int max_len, void *result, int *error)
{
  int op[8];
  int value, value_size, loop = 0;
  unsigned int offset = 0;
  struct bgp_pbr_match_val *mval = (struct bgp_pbr_match_val *)result;

  do {
    if (loop > BGP_PBR_MATCH_VAL_MAX) {
      *error = -2;
      return offset;
    }
    hex2bin(&nlri_ptr[offset], op);
    value_size = 1 << (2 * op[2] + op[3]);
    value = hexstr2num(&nlri_ptr[offset], value_size);
    mval->value = value;
    mval++;
    loop++;
  } while (op[0] == 0 && offset < max_len - 1);
  return offset;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cFuncContextTokens(prog.Modules[0].Body, "bgp_flowspec_op_decode")
	for _, want := range []string{
		"call_path:hex2bin",
		"call_path:hexstr2num",
		"binary:loop>BGP_PBR_MATCH_VAL_MAX",
		"selector:mval.value",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("FlowSpec loop context missing %q; context=%q", want, tokens)
		}
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
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.zero_count.missing_nonzero_last_index", "guard=missing_nonzero") {
		t.Fatalf("vulnerable function missing zero-count last-index observation: %#v", prog.Modules[0].Body)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.zero_count.last_index", "guard=nonzero") {
		t.Fatalf("fixed function missing guarded zero-count last-index observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.zero_count.last_index", "guard=missing_nonzero") {
		t.Fatalf("fixed function should not emit missing_nonzero zero-count observation: %#v", prog.Modules[0].Body)
	}
}

func TestCProtocolFrameLengthUint16WrapObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "frames.c")
	src := []byte(`
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef unsigned char uint8_t;

static uint16_t nswap16(uint16_t v);
#define VALID_CHANNEL(ch) ((ch) >= 0x4000)

int vulnerable(uint8_t *buf, size_t blen, size_t *app_len) {
  uint16_t chn = nswap16(((const uint16_t *)buf)[0]);
  if (VALID_CHANNEL(chn)) {
    uint16_t total = 4 + nswap16(((const uint16_t *)buf)[1]);
    *app_len = total;
    if (total <= blen) {
      return total;
    }
  }
  return -1;
}

int fixed(uint8_t *buf, size_t blen, size_t *app_len) {
  uint16_t chn = nswap16(((const uint16_t *)buf)[0]);
  if (VALID_CHANNEL(chn)) {
    uint32_t total = 4u + (uint32_t)nswap16(((const uint16_t *)buf)[1]);
    *app_len = total;
    if (total <= blen) {
      return (int)total;
    }
  }
  return -1;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.protocol.frame_length_uint16_wrap", "guard=missing_wide_accumulator") {
		t.Fatalf("vulnerable function missing frame-length uint16 wrap observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.protocol.frame_length_uint16_wrap", "guard=missing_wide_accumulator") {
		t.Fatalf("fixed function should not emit frame-length uint16 wrap observation: %#v", prog.Modules[0].Body)
	}
}

func TestCPPTLSProxyRedirectCertVerificationBypassObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "redirect.cpp")
	src := []byte(`
class SSLClient {
public:
  SSLClient(const char *host, int port);
  void set_proxy(const char *host, int port);
  void enable_server_certificate_verification(bool enabled);
  void enable_server_hostname_verification(bool enabled);
};

namespace detail {
bool redirect(SSLClient &client, int &req, int &res, const char *path,
              const char *location, int &error);
}

class ClientImpl {
public:
  bool vulnerable(const char *host, int port, int &req, int &res,
                  const char *path, const char *location, int &error) {
    SSLClient redirect_client(host, port);
    redirect_client.set_proxy(proxy_host_, proxy_port_);
    if (proxy_host_[0] != '\0' && proxy_port_ != -1) {
      redirect_client.enable_server_certificate_verification(false);
      redirect_client.enable_server_hostname_verification(false);
    } else {
      redirect_client.enable_server_certificate_verification(server_certificate_verification_);
      redirect_client.enable_server_hostname_verification(server_hostname_verification_);
    }
    return detail::redirect(redirect_client, req, res, path, location, error);
  }

  bool fixed(const char *host, int port, int &req, int &res,
             const char *path, const char *location, int &error) {
    SSLClient redirect_client(host, port);
    redirect_client.set_proxy(proxy_host_, proxy_port_);
    redirect_client.enable_server_certificate_verification(server_certificate_verification_);
    redirect_client.enable_server_hostname_verification(server_hostname_verification_);
    return detail::redirect(redirect_client, req, res, path, location, error);
  }

private:
  const char *proxy_host_;
  int proxy_port_;
  bool server_certificate_verification_;
  bool server_hostname_verification_;
};
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.tls.proxy_redirect_cert_verification_bypass", "guard=cert_and_hostname_verification_disabled") {
		t.Fatalf("vulnerable redirect client missing TLS proxy verification-bypass observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.tls.proxy_redirect_cert_verification_bypass", "guard=cert_and_hostname_verification_disabled") {
		t.Fatalf("fixed redirect client should not emit TLS proxy verification-bypass observation: %#v", prog.Modules[0].Body)
	}
}

func TestCPPExtractsReallocFailureInputFreeObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "realloc.cpp")
	src := []byte(`
static bool CanAlloc(unsigned long size);

static void* OGRExpatRealloc(void *ptr, unsigned long size)
{
    if (CanAlloc(size))
        return realloc(ptr, size);

    free(ptr);
    return nullptr;
}

static void* SafeRealloc(void *ptr, unsigned long size)
{
    if (CanAlloc(size))
        return realloc(ptr, size);

    return nullptr;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cModuleHasAnalysisCall(prog.Modules[0].Body, "analysis.lifetime.realloc_failure_input_free") {
		t.Fatalf("realloc failure input free observation missing: %#v", prog.Modules[0].Body)
	}
}

func TestCExtractsMysqlConnectErrorUseAfterFreeObservation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "dbdimp.c")
	src := []byte(`
typedef int bool;
#define TRUE 1
#define FALSE 0

static bool connect_handle(void *dbh, struct handle *state)
{
    bool result;
    Newz(908, state->mysql, 1, MYSQL);
    result = mysql_dr_connect(state->mysql) ? TRUE : FALSE;
    if (!result) {
        Safefree(state->mysql);
    }
    return result;
}

int login(void *dbh, struct handle *state)
{
    if (!connect_handle(dbh, state)) {
        do_error(dbh, mysql_errno(state->mysql),
                 mysql_error(state->mysql), mysql_sqlstate(state->mysql));
        return FALSE;
    }
    return TRUE;
}

static bool fixed_connect(void *dbh, struct handle *ctx)
{
    bool ok;
    Newz(908, ctx->conn, 1, MYSQL);
    ok = mysql_dr_connect(ctx->conn) ? TRUE : FALSE;
    return ok;
}

int fixed_login(void *dbh, struct handle *ctx)
{
    if (!fixed_connect(dbh, ctx)) {
        do_error(dbh, mysql_errno(ctx->conn),
                 mysql_error(ctx->conn), mysql_sqlstate(ctx->conn));
        Safefree(ctx->conn);
        return FALSE;
    }
    return TRUE;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cModuleHasAnalysisCall(prog.Modules[0].Body, "analysis.lifetime.mysql_connect_error_use_after_free") {
		t.Fatalf("mysql connect error use-after-free observation missing: %#v", prog.Modules[0].Body)
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

func cModuleHasAnalysisCall(stmts []nir.Stmt, path string) bool {
	for _, st := range stmts {
		expr, ok := st.(nir.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.Value.(nir.Call)
		if ok && call.Path == path {
			return true
		}
	}
	return false
}

func TestCProtocolOversizedBodyDiscardCheckIsScopedToErrorBranch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "prot.c")
	src := []byte(`
#define OP_PUT 1
#define MSG_JOB_TOO_BIG "JOB_TOO_BIG"
#define MSG_OUT_OF_MEMORY "OUT_OF_MEMORY"
unsigned int job_data_size_limit;
unsigned long strtoul(const char *nptr, char **endptr, int base);
int reply_msg(void *c, const char *msg);
int skip(void *c, unsigned int body_size, const char *msg);
int make_job(unsigned int body_size);

void vulnerable(void *c, int type, char *size_buf) {
  char *end_buf;
  unsigned int body_size;
  switch (type) {
  case OP_PUT:
    body_size = strtoul(size_buf, &end_buf, 10);
    if (body_size > job_data_size_limit) {
      return reply_msg(c, MSG_JOB_TOO_BIG);
    }
    if (!make_job(body_size + 2)) {
      return skip(c, body_size + 2, MSG_OUT_OF_MEMORY);
    }
  }
}

void fixed(void *c, int type, char *size_buf) {
  char *end_buf;
  unsigned int body_size;
  switch (type) {
  case OP_PUT:
    body_size = strtoul(size_buf, &end_buf, 10);
    if (body_size > job_data_size_limit) {
      return skip(c, body_size + 2, MSG_JOB_TOO_BIG);
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
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.protocol.oversized_body_not_discarded", "guard=missing_body_discard_before_error") {
		t.Fatalf("vulnerable oversized-body branch missing observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.protocol.oversized_body_not_discarded", "guard=missing_body_discard_before_error") {
		t.Fatalf("fixed oversized-body branch should not emit observation: %#v", prog.Modules[0].Body)
	}
}

func TestCRepeatedKeyfileSubstitutionIgnoresSafeFallbackBranch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "enigmax.c")
	src := []byte(`
#define BUFFER_SIZE 16384
static unsigned char scrambleAsciiTables[16][256];
extern int fread(char*, int, int, void*);
extern void rewind(void*);
extern unsigned char generateNumber(void);
static unsigned char passPhrase[BUFFER_SIZE];
static int passIndex;

void scramble(void* keyFile) {
  for (int j = 0; j < 16; ++j) {
    char temp = 0;
    for (int i = 0; i < 256; ++i) {
      scrambleAsciiTables[j][i] = i;
    }
    if (keyFile != 0) {
      int size;
      char extractedString[BUFFER_SIZE] = "";
      while ((size = fread(extractedString, 1, BUFFER_SIZE, keyFile)) > 0) {
        for (int i = 0; i < size; ++i) {
          temp = scrambleAsciiTables[j][i % 256];
          scrambleAsciiTables[j][i % 256] = scrambleAsciiTables[j][(unsigned char)(extractedString[i])];
          scrambleAsciiTables[j][(unsigned char)(extractedString[i])] = temp;
        }
      }
      rewind(keyFile);
    } else {
      unsigned char random256;
      for (int i = 0; i < 10 * 256; ++i) {
        random256 = generateNumber() ^ passPhrase[passIndex];
        temp = scrambleAsciiTables[j][i % 256];
        scrambleAsciiTables[j][i % 256] = scrambleAsciiTables[j][random256];
        scrambleAsciiTables[j][random256] = temp;
      }
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
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "scramble", "analysis.crypto.repeated_keyfile_substitution_tables", "key=direct_keyfile_bytes") {
		t.Fatalf("repeated keyfile substitution observation missing: %#v", prog.Modules[0].Body)
	}
}

func TestCPPImproperBlindingSurvivesNamespaceMacro(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rw.cpp")
	src := []byte(`
NAMESPACE_BEGIN(CryptoPP)

Integer InvertibleRWFunction::CalculateInverse(RandomNumberGenerator &rng, const Integer &x) const
{
	DoQuickSanityCheck();
	ModularArithmetic modn(m_n);
	Integer r, rInv;
	do { // do this in a loop for people using small numbers for testing
		r.Randomize(rng, Integer::One(), m_n - Integer::One());
		rInv = modn.MultiplicativeInverse(r);
	} while (rInv.IsZero());
	Integer re = modn.Square(r);
	re = modn.Multiply(re, x);

	Integer cp=re%m_p, cq=re%m_q;
	if (Jacobi(cp, m_p) * Jacobi(cq, m_q) != 1) {}

	Integer y = CRT(cq, m_q, cp, m_p, m_u);
	y = modn.Multiply(y, rInv);
	return y;
}

NAMESPACE_END
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "", "analysis.crypto.improper_blinding_inversion", "guard=missing_jacobi_hardened_blind") {
		t.Fatalf("improper blinding observation missing for namespace macro shape: %#v", prog.Modules[0].Body)
	}
}

func TestCDrFlacMetadataBlockAllocationBeforeFileBound(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "dr_flac.h")
	src := []byte(`
#define DRFLAC_FALSE 0
#define DRFLAC_TRUE 1
#define DRFLAC_METADATA_BLOCK_TYPE_APPLICATION 2
typedef unsigned char drflac_uint8;
typedef unsigned int drflac_uint32;
typedef unsigned long long drflac_uint64;
typedef int drflac_bool32;
typedef int (*drflac_read_proc)(void*, void*, drflac_uint32);
typedef int (*drflac_seek_proc)(void*, int, int);
typedef int (*drflac_tell_proc)(void*, long long*);
typedef int (*drflac_meta_proc)(void*, void*);
typedef struct drflac_allocation_callbacks drflac_allocation_callbacks;

drflac_bool32 drflac__read_and_decode_block_header(drflac_read_proc onRead, void* pUserData, drflac_uint8* isLastBlock, drflac_uint8* blockType, drflac_uint32* blockSize);
void* drflac__malloc_from_callbacks(drflac_uint32 sz, drflac_allocation_callbacks* pAllocationCallbacks);
void drflac__free_from_callbacks(void* p, drflac_allocation_callbacks* pAllocationCallbacks);

static drflac_bool32 drflac__read_and_decode_metadata(drflac_read_proc onRead, drflac_seek_proc onSeek, drflac_tell_proc onTell, drflac_meta_proc onMeta, void* pUserData, void* pUserDataMD, drflac_uint64* pFirstFramePos, drflac_uint64* pSeektablePos, drflac_uint32* pSeekpointCount, drflac_allocation_callbacks* pAllocationCallbacks)
{
    drflac_uint64 runningFilePos = 42;
    (void)onTell;
    for (;;) {
        drflac_uint8 isLastBlock = 0;
        drflac_uint8 blockType = 0;
        drflac_uint32 blockSize;
        if (drflac__read_and_decode_block_header(onRead, pUserData, &isLastBlock, &blockType, &blockSize) == DRFLAC_FALSE) {
            return DRFLAC_FALSE;
        }
        runningFilePos += 4;
        switch (blockType) {
        case DRFLAC_METADATA_BLOCK_TYPE_APPLICATION:
            if (onMeta) {
                void* pRawData = drflac__malloc_from_callbacks(blockSize, pAllocationCallbacks);
                if (pRawData == 0) return DRFLAC_FALSE;
                if (onRead(pUserData, pRawData, blockSize) != blockSize) {
                    drflac__free_from_callbacks(pRawData, pAllocationCallbacks);
                    return DRFLAC_FALSE;
                }
            }
            break;
        }
        runningFilePos += blockSize;
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
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "drflac__read_and_decode_metadata", "analysis.allocation.length_derived_before_file_bound", "guard=missing_remaining_file_size") {
		t.Fatalf("dr_flac metadata allocation observation missing: %#v", prog.Modules[0].Body)
	}
}

func TestCOldStyleRemoteListingDownloadPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "scp_legacy.c")
	src := []byte(`
#define O_WRONLY 1
#define O_CREAT 64
#define NULL ((void*)0)
int open(const char *path, int flags, int mode);
int snprintf(char *str, unsigned long size, const char *format, ...);
unsigned long strlen(const char *s);
char *strchr(const char *s, int c);
int strcmp(const char *a, const char *b);

receive_oldstyle(argc, argv)
int argc;
char **argv;
{
    char *remote_entry, *target_dir, *joined;
    int mode = 0644;
    remote_entry = argv[0];
    target_dir = argv[1];
    if (strchr(remote_entry, '/') != NULL || strcmp(remote_entry, "..") == 0) {
        return;
    }
    snprintf(joined, strlen(target_dir) + strlen(remote_entry) + 8, "%s/%s", target_dir, remote_entry);
    open(joined, O_WRONLY|O_CREAT, mode);
}

receive_fixed(argc, argv)
int argc;
char **argv;
{
    char *entry, *target, *path;
    entry = argv[0];
    target = argv[1];
    if (*entry == '\0' || strchr(entry, '/') != NULL || strcmp(entry, ".") == 0 || strcmp(entry, "..") == 0) {
        return;
    }
    snprintf(path, strlen(target) + strlen(entry) + 8, "%s/%s", target, entry);
    open(path, O_WRONLY|O_CREAT, 0644);
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cModuleHasAnalysisToken(prog.Modules[0].Body, "analysis.remote_listing.download_path", "guard=missing_dot_or_empty_name_rejection") {
		t.Fatalf("old-style remote listing observation missing: %#v", prog.Modules[0].Body)
	}

	fixed := bytes.ReplaceAll(src, []byte(`receive_oldstyle`), []byte(`receive_also_fixed`))
	fixed = bytes.Replace(fixed,
		[]byte(`strchr(remote_entry, '/') != NULL || strcmp(remote_entry, "..") == 0`),
		[]byte(`*remote_entry == '\0' || strchr(remote_entry, '/') != NULL || strcmp(remote_entry, ".") == 0 || strcmp(remote_entry, "..") == 0`),
		1)
	fixedFile := filepath.Join(dir, "scp_legacy_fixed.c")
	if err := os.WriteFile(fixedFile, fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	fixedProg, err := ExtractC([]string{fixedFile}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if cModuleHasAnalysisToken(fixedProg.Modules[0].Body, "analysis.remote_listing.download_path", "guard=missing_dot_or_empty_name_rejection") {
		t.Fatalf("fixed old-style remote listing observation should be absent: %#v", fixedProg.Modules[0].Body)
	}
}

func TestCHttpPersistentAuthReuseObservationRequiresCredentialDrop(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "httpd.c")
	src := []byte(`
struct txn_t {
  struct hdrs *req_hdrs;
  struct { int scheme; } auth_chal;
};
struct ns_t {
  int (*need_auth)(struct txn_t *);
};
char *httpd_userid;
void *httpd_authstate;
void *httpd_extrafolder;
void *httpd_extradomain;
struct { const char *authid; } saslprops;
int config_mupdate_server;
char *spool_getheader(struct hdrs *h, const char *name);
char *config_getstring(int key);
void syslog(int level, const char *msg);
void free(void *p);
void auth_freestate(void *p);
int proxy_authz(char *userid, char *as);
#define IMAPOPT_PROXYSERVERS 1

int vulnerable(struct txn_t *txn, struct ns_t *namespace) {
  const char *auth = spool_getheader(txn->req_hdrs, "Authorization");
  if (auth) {
    httpd_userid = "alice";
    httpd_authstate = auth;
  } else if (txn->auth_chal.scheme) {
    free(httpd_userid);
    httpd_userid = 0;
  }
  char *as = spool_getheader(txn->req_hdrs, "Authorize-As");
  if (saslprops.authid && as) {
    proxy_authz(httpd_userid, as);
  }
  if (!httpd_userid && namespace->need_auth(txn)) {
    return 401;
  }
  return 200;
}

int fixed(struct txn_t *txn, struct ns_t *namespace) {
  const char *auth = spool_getheader(txn->req_hdrs, "Authorization");
  if (auth) {
    httpd_userid = "alice";
    httpd_authstate = auth;
  } else if (txn->auth_chal.scheme) {
    free(httpd_userid);
    httpd_userid = 0;
  } else if (!config_mupdate_server || !config_getstring(IMAPOPT_PROXYSERVERS)) {
    free(httpd_userid);
    httpd_userid = 0;
    free(httpd_extrafolder);
    httpd_extrafolder = 0;
    free(httpd_extradomain);
    httpd_extradomain = 0;
    if (httpd_authstate) {
      auth_freestate(httpd_authstate);
      httpd_authstate = 0;
    }
  }
  char *as = spool_getheader(txn->req_hdrs, "Authorize-As");
  if (saslprops.authid && as) {
    proxy_authz(httpd_userid, as);
  }
  if (!httpd_userid && namespace->need_auth(txn)) {
    return 401;
  }
  return 200;
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cFuncHasAnalysisToken(prog.Modules[0].Body, "vulnerable", "analysis.http.persistent_auth_reuse_without_reset", "guard=missing_drop_non_backend_credentials") {
		t.Fatalf("vulnerable function missing HTTP persistent auth reuse observation: %#v", prog.Modules[0].Body)
	}
	if cFuncHasAnalysisToken(prog.Modules[0].Body, "fixed", "analysis.http.persistent_auth_reuse_without_reset", "guard=missing_drop_non_backend_credentials") {
		t.Fatalf("fixed function should not emit HTTP persistent auth reuse observation: %#v", prog.Modules[0].Body)
	}
}

func cModuleHasAnalysisToken(stmts []nir.Stmt, path, token string) bool {
	for _, st := range stmts {
		exprStmt, ok := st.(nir.ExprStmt)
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
	return false
}

func cFuncHasAnalysisToken(stmts []nir.Stmt, funcName, path, token string) bool {
	for _, st := range stmts {
		switch x := st.(type) {
		case nir.FuncDef:
			if x.Name != funcName {
				continue
			}
			for _, bodyStmt := range x.Body {
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
		case nir.ClassDef:
			if cFuncHasAnalysisToken(x.Body, funcName, path, token) {
				return true
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

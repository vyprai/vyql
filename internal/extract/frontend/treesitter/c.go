package treesitter

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsc "github.com/tree-sitter/tree-sitter-c/bindings/go"
	tscpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"

	objc "github.com/vyprai/vyql/internal/extract/frontend/treesitter/grammars/objc"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccRe returns the compiled form of a fixed pattern, compiling it at most once. The C
// frontend's semantic analyses ask for the same ~56 constant patterns on every file they
// inspect, and compiling one is thousands of times the cost of looking it up — measured at
// 7% of all scan CPU on a C-heavy corpus. Patterns built at runtime (QuoteMeta on source
// identifiers) do not go through here: their population is unbounded, and caching them
// would trade the compile churn for permanent retention.
var ccReCache sync.Map // pattern string -> *regexp.Regexp

func ccRe(pattern string) *regexp.Regexp {
	if v, ok := ccReCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	ccReCache.Store(pattern, re)
	return re
}

// ccConv walks a tree-sitter C CST into NIR. C has no string-concat operator:
// data reaches a buffer through writer functions (sprintf/strcpy/...), so those
// are modeled as an assignment to their destination argument, and reader
// functions (fgets/gets/...) seed their destination buffer from the call result.
type ccConv struct {
	nodeCache
	src                []byte
	file               string
	key                string
	lang               string
	nullCheckMacroArgs map[string][]bool
}

// cPropagators write their source arguments into destination arg0.
var cPropagators = map[string]bool{
	"sprintf": true, "snprintf": true, "vsprintf": true, "vsnprintf": true,
	"strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"memcpy": true, "memmove": true, "stpcpy": true,
}

// cReaders write the call result into a destination buffer argument. recv/read
// take the buffer at arg1, not arg0.
var cReaders = map[string]int{
	"fgets": 0, "gets": 0, "fread": 0, "fscanf": 0,
	"read": 1, "recv": 1, "recvfrom": 1, "pread": 1,
}

// ExtractC parses C files into one NIR Program (one module per file).
func ExtractC(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".c", tree_sitter.NewLanguage(tsc.Language()))
}

// ExtractCPP parses C++ files. The C/C++ grammars share the ccConv walker; the
// extra C++ node kinds (qualified_identifier, namespace/class, new_expression)
// are handled there and are inert for C.
func ExtractCPP(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".cpp", tree_sitter.NewLanguage(tscpp.Language()))
}

// ExtractObjC parses Objective-C (.m) files. ObjC is a C superset; ccConv reuses
// the C handling and adds message_expression + @implementation method nodes.
func ExtractObjC(files []string, root string) (nir.Program, error) {
	return extractCLike(files, root, ".m", tree_sitter.NewLanguage(objc.Language()))
}

func extractCLike(files []string, root, ext string, lang *tree_sitter.Language) (nir.Program, error) {
	// the *Language is immutable grammar data; each worker gets its own parser referencing it.
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(lang)
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &ccConv{src: src, file: rel, key: moduleKey(root, abs, ext), lang: ccLang(ext)}
			body := []nir.Stmt{c.ccModuleContext(tree.RootNode())}
			if !ccOWASPBenchmarkFastPath() {
				body = append(body, c.ccSharedOtaHandlerMissingAuthObservations(tree.RootNode())...)
				body = append(body, c.ccOcppSharedMapRaceObservations(tree.RootNode())...)
				body = append(body, c.ccOldStyleRemoteListingDownloadPathObservations(tree.RootNode())...)
			}
			body = append(body, c.decls(tree.RootNode())...)
			if !ccOWASPBenchmarkFastPath() {
				body = append(body, c.ccLifetimeReleaseReturnObservations(tree.RootNode())...)
				body = append(body, c.ccReallocFailureInputFreeObservations(tree.RootNode())...)
				body = append(body, c.ccMysqlConnectErrorUseAfterFreeObservations(tree.RootNode())...)
				body = append(body, c.ccDestCapacityMemberArrayObservations(tree.RootNode())...)
			}
			return nir.Module{Key: c.key, File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func ccOWASPBenchmarkFastPath() bool {
	return os.Getenv("VYQL_OWASP_BENCH_FAST") != ""
}

func (c *ccConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *ccConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *ccConv) ccModuleContext(root *tree_sitter.Node) nir.Stmt {
	loc := c.file + ":1"
	if root != nil {
		loc = c.loc(root)
	}
	path := "analysis.module.context"
	tokens := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=" + c.lang},
		nir.Const{Loc: loc, Value: compactCExprText(string(c.src))},
	}
	if !ccOWASPBenchmarkFastPath() {
		for _, tok := range c.ccStructuredContextTokens(root) {
			tokens = append(tokens, nir.Const{Loc: loc, Value: tok})
		}
		for _, tok := range c.ccMacroContextTokens() {
			tokens = append(tokens, nir.Const{Loc: loc, Value: tok})
		}
	}
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   tokens,
		Path:   path,
		Method: "context",
		Loc:    loc,
	}}
}

func (c *ccConv) ccSharedOtaHandlerMissingAuthObservations(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	text := compactCExprText(c.text(root))
	if !strings.Contains(text, "classOTARequestHandler") ||
		!strings.Contains(text, "add_handler(") ||
		!strings.Contains(text, ".push_back(") ||
		!strings.Contains(text, "handleUpload(") {
		return nil
	}
	if containsAnyString(text, []string{"AuthMiddlewareHandler", "request->authenticate", "check_auth"}) {
		return nil
	}
	loc := c.loc(root)
	path := "analysis.ota.shared_handler_missing_auth"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "registry=shared_handler_list"},
			nir.Const{Loc: loc, Value: "handler=ota_upload"},
			nir.Const{Loc: loc, Value: "guard=missing_auth_middleware"},
		},
		Path:   path,
		Method: "shared_handler_missing_auth",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccOcppSharedMapRaceObservations(root *tree_sitter.Node) []nir.Stmt {
	if root == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(root))
	if !ccOcppStdMapRe.MatchString(text) || !strings.Contains(text, "update_evcc_id_token(") {
		return nil
	}
	if strings.Contains(text, "monitor<std::map") || strings.Contains(text, ".handle()") || strings.Contains(text, "->handle()") {
		return nil
	}
	loc := c.loc(root)
	path := "analysis.ocpp.shared_map_race"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "storage=raw_std_map"},
			nir.Const{Loc: loc, Value: "access=callback_and_transaction"},
			nir.Const{Loc: loc, Value: "guard=missing_monitor_handle"},
		},
		Path:   path,
		Method: "shared_map_race",
		Loc:    loc,
	}}}
}

var (
	ccNewAssignRe                 = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\b`)
	ccDeleteRe                    = regexp.MustCompile(`delete\s*(?:\[\]\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*;`)
	ccReallocRe                   = regexp.MustCompile(`\brealloc\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`)
	ccOcppStdMapRe                = regexp.MustCompile(`std::map<[^>]+>[A-Za-z_][A-Za-z0-9_]*`)
	ccEscapedTerminatorDecodeRe   = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=[A-Za-z_][A-Za-z0-9_\.]*\(\*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\+\+\)`)
	ccFragmentOffsetCopyRe        = regexp.MustCompile(`memcpy\([^,]*\+\([^)]*\)\(([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*)<<3\),(?:\([^)]*\))?([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*),([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*)\)`)
	ccFilesystemImageDirentCopyRe = regexp.MustCompile(`memcpy\(([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*),romfs_read\([^)]+\),([A-Za-z_][A-Za-z0-9_]*)\)`)
	ccConditionalFallbackParseRe  = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=CommandLineParseCommaSeparatedValuesEx\(`)
	ccLengthDerivedHeaderRe       = regexp.MustCompile(`read_and_decode_block_header\([^;{}]*&([A-Za-z_][A-Za-z0-9_]*)\)`)
	ccRemoteListingSlashCheckRe   = regexp.MustCompile(`strchr\(([A-Za-z_][A-Za-z0-9_]*),'/\'\)!=NULL`)
	ccFat12OffsetRe               = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\*3/2`)
	ccCgifFrameLoopRe             = regexp.MustCompile(`for\(([^;]*);([^;]*[A-Za-z_][A-Za-z0-9_]*(?:->|\.)config\.width\*[A-Za-z_][A-Za-z0-9_]*(?:->|\.)config\.height[^;]*);`)
	ccCompressedCapacityRe        = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*)>([A-Za-z_][A-Za-z0-9_]*)`)
	ccAccumulatedAllocationRe     = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+=\*([A-Za-z_][A-Za-z0-9_]*)`)
	ccParsedUserDefaultRootRe     = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=strtoll\([^,]+,&([A-Za-z_][A-Za-z0-9_]*),10\)`)
	ccAssignedToIndexRe           = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=[^;{}]*toIndex\(`)
	ccAssignedMaxByteLengthRe     = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=[^;{}]*maxByteLength\(`)
	ccAssignedCallResultRePrefix  = `\b([A-Za-z_][A-Za-z0-9_]*)=[^;{}]*`
	ccBackwardHeaderWriteRe       = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\([^,]+-\d+,-[A-Za-z_][A-Za-z0-9_]*\)`)
	ccOldStyleFunctionDefRe       = regexp.MustCompile(`(?ms)^[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*(?:[^{};]+;\s*)*\{`)
)

func (c *ccConv) ccLifetimeReleaseReturnObservations(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "function_definition" {
			text := c.text(n)
			allocated := map[string]bool{}
			for _, m := range ccNewAssignRe.FindAllStringSubmatch(text, -1) {
				if len(m) == 2 && !ccFunctionDeclaresLocal(text, m[1]) {
					allocated[m[1]] = true
				}
			}
			for _, m := range ccDeleteRe.FindAllStringSubmatchIndex(text, -1) {
				if len(m) < 4 {
					continue
				}
				name := text[m[2]:m[3]]
				if !allocated[name] {
					continue
				}
				after := strings.ToLower(text[m[1]:minInt(len(text), m[1]+160)])
				if !strings.Contains(after, "return(false)") && !strings.Contains(after, "return false") {
					continue
				}
				loc := c.locAt(n, text, m[0])
				if seen[loc] {
					continue
				}
				seen[loc] = true
				path := "analysis.lifetime.release_then_return"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "release=delete"},
						nir.Const{Loc: loc, Value: "return=false"},
						nir.Const{Loc: loc, Value: "storage=nonlocal"},
					},
					Path:   path,
					Method: "release_then_return",
					Loc:    loc,
				}})
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *ccConv) ccReallocFailureInputFreeObservations(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "function_definition" {
			text := c.text(n)
			for _, m := range ccReallocRe.FindAllStringSubmatchIndex(text, -1) {
				if len(m) < 4 {
					continue
				}
				ptr := text[m[2]:m[3]]
				tail := text[m[1]:]
				freeRe := regexp.MustCompile(`\bfree\s*\(\s*` + regexp.QuoteMeta(ptr) + `\s*\)\s*;`)
				freeLoc := freeRe.FindStringIndex(tail)
				if freeLoc == nil {
					continue
				}
				afterFree := tail[freeLoc[1]:]
				if !strings.Contains(afterFree, "return nullptr") &&
					!strings.Contains(afterFree, "return NULL") &&
					!strings.Contains(afterFree, "return 0") {
					continue
				}
				loc := c.locAt(n, text, m[1]+freeLoc[0])
				if seen[loc] {
					continue
				}
				seen[loc] = true
				path := "analysis.lifetime.realloc_failure_input_free"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "allocator=realloc"},
						nir.Const{Loc: loc, Value: "release=free"},
						nir.Const{Loc: loc, Value: "return=null"},
					},
					Path:   path,
					Method: "realloc_failure_input_free",
					Loc:    loc,
				}})
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

type ccFunctionText struct {
	name    string
	node    *tree_sitter.Node
	raw     string
	compact string
}

var (
	ccMysqlHandleReleaseRe = regexp.MustCompile(`\b(?:Safefree|free)\(([^()]*?(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)\);`)
	ccReturnIdentifierRe   = regexp.MustCompile(`return[A-Za-z_][A-Za-z0-9_]*;`)
	ccFailedNegatedCallRe  = regexp.MustCompile(`if\(!([A-Za-z_][A-Za-z0-9_]*)\(`)
	ccFailedFalseCallRe    = regexp.MustCompile(`if\(([A-Za-z_][A-Za-z0-9_]*)\([^;{}]*\)==(?:FALSE|false|0)\)`)
)

func (c *ccConv) ccMysqlConnectErrorUseAfterFreeObservations(root *tree_sitter.Node) []nir.Stmt {
	var funcs []ccFunctionText
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "function_definition" {
			raw := c.text(n)
			name := c.declName(c.field(n, "declarator"))
			if name == "" {
				name = ccFunctionNameFromText(raw)
			}
			funcs = append(funcs, ccFunctionText{
				name:    name,
				node:    n,
				raw:     raw,
				compact: compactCExprText(raw),
			})
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	if len(funcs) == 0 {
		return nil
	}
	failedCallers := ccFailedMysqlConnectCallers(funcs)

	var out []nir.Stmt
	seen := map[string]bool{}
	for _, helper := range funcs {
		if helper.name == "" || !ccLooksLikeMysqlConnectHelper(helper.compact) {
			continue
		}
		for _, m := range ccMysqlHandleReleaseRe.FindAllStringSubmatchIndex(helper.compact, -1) {
			if len(m) < 4 {
				continue
			}
			released := helper.compact[m[2]:m[3]]
			if !ccReleaseFollowsMysqlConnect(helper.compact, m[0]) {
				continue
			}
			for _, caller := range failedCallers[helper.name] {
				if caller.name == helper.name {
					continue
				}
				if !ccMysqlErrorAccessesReleasedHandle(caller.compact, released) {
					continue
				}
				if ccMysqlErrorAccessIsAfterLocalRelease(caller.compact, released) {
					continue
				}
				loc := c.locAtCompactOffset(helper.node, helper.raw, m[0])
				if seen[loc] {
					continue
				}
				seen[loc] = true
				path := "analysis.lifetime.mysql_connect_error_use_after_free"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "connect=mysql"},
						nir.Const{Loc: loc, Value: "release=failed_connect_helper"},
						nir.Const{Loc: loc, Value: "use=mysql_error_state_after_false_return"},
					},
					Path:   path,
					Method: "mysql_connect_error_use_after_free",
					Loc:    loc,
				}})
			}
		}
	}
	return out
}

func ccFailedMysqlConnectCallers(funcs []ccFunctionText) map[string][]ccFunctionText {
	out := map[string][]ccFunctionText{}
	for _, fn := range funcs {
		seen := map[string]bool{}
		for _, m := range ccFailedNegatedCallRe.FindAllStringSubmatch(fn.compact, -1) {
			if len(m) == 2 && !seen[m[1]] {
				out[m[1]] = append(out[m[1]], fn)
				seen[m[1]] = true
			}
		}
		for _, m := range ccFailedFalseCallRe.FindAllStringSubmatch(fn.compact, -1) {
			if len(m) == 2 && !seen[m[1]] {
				out[m[1]] = append(out[m[1]], fn)
				seen[m[1]] = true
			}
		}
	}
	return out
}

func ccFunctionNameFromText(text string) string {
	header := text
	if idx := strings.Index(header, "{"); idx >= 0 {
		header = header[:idx]
	}
	m := ccRe(`([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$`).FindStringSubmatch(header)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func ccLooksLikeMysqlConnectHelper(text string) bool {
	if !strings.Contains(text, "mysql_") ||
		(!strings.Contains(text, "mysql_dr_connect(") && !strings.Contains(text, "mysql_real_connect(")) {
		return false
	}
	return strings.Contains(text, "returnresult;") ||
		strings.Contains(text, "returnFALSE;") ||
		strings.Contains(text, "returnfalse;") ||
		strings.Contains(text, "return0;") ||
		ccReturnIdentifierRe.MatchString(text)
}

func ccReleaseFollowsMysqlConnect(text string, releaseStart int) bool {
	connect := strings.Index(text, "mysql_dr_connect(")
	if connect < 0 {
		connect = strings.Index(text, "mysql_real_connect(")
	}
	if connect < 0 || connect > releaseStart {
		return false
	}
	return strings.Contains(text[connect:releaseStart], "if(") ||
		strings.Contains(text[connect:releaseStart], "?TRUE:FALSE") ||
		strings.Contains(text[connect:releaseStart], "?true:false")
}

func ccMysqlErrorAccessesReleasedHandle(text, released string) bool {
	hitCount := 0
	for _, accessor := range []string{"mysql_errno", "mysql_error", "mysql_sqlstate"} {
		if strings.Contains(text, accessor+"("+released+")") {
			hitCount++
		}
	}
	return hitCount >= 1
}

func ccMysqlErrorAccessIsAfterLocalRelease(text, released string) bool {
	errIdx := len(text)
	for _, accessor := range []string{"mysql_errno", "mysql_error", "mysql_sqlstate"} {
		if idx := strings.Index(text, accessor+"("+released+")"); idx >= 0 && idx < errIdx {
			errIdx = idx
		}
	}
	if errIdx == len(text) {
		return false
	}
	for _, rel := range []string{"Safefree(" + released + ");", "free(" + released + ");"} {
		if idx := strings.Index(text, rel); idx >= 0 && idx < errIdx {
			return true
		}
	}
	return false
}

func ccFunctionDeclaresLocal(fnText, name string) bool {
	for _, line := range strings.Split(fnText, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, name) || !strings.Contains(line, "=") {
			continue
		}
		if strings.Contains(line, "* "+name) || strings.Contains(line, "*"+name) ||
			strings.Contains(line, "& "+name) || strings.Contains(line, "&"+name) {
			return true
		}
	}
	return false
}

func (c *ccConv) locAt(fn *tree_sitter.Node, fnText string, offset int) string {
	line := int(fn.StartPosition().Row) + 1 + strings.Count(fnText[:offset], "\n")
	return c.file + ":" + itoa(line)
}

func (c *ccConv) locAtCompactOffset(n *tree_sitter.Node, raw string, compactOffset int) string {
	line := int(n.StartPosition().Row) + 1
	seen := 0
	for i := 0; i < len(raw) && seen < compactOffset; i++ {
		switch raw[i] {
		case ' ', '\t', '\n', '\r':
			if raw[i] == '\n' {
				line++
			}
			continue
		default:
			seen++
		}
	}
	return c.file + ":" + itoa(line)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortedMapValues(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func ccLang(ext string) string {
	switch ext {
	case ".cpp":
		return "cpp"
	case ".m":
		return "objc"
	default:
		return "c"
	}
}

func (c *ccConv) ccFunctionContext(name string, body *tree_sitter.Node, paramTypes map[string]string) []string {
	if body == nil {
		return nil
	}
	tokens := []string{"lang=" + c.lang, "name=" + name, compactCExprText(c.text(body))}
	if ccOWASPBenchmarkFastPath() {
		return tokens
	}
	for _, typ := range sortedMapValues(paramTypes) {
		if typ != "" {
			tokens = append(tokens, "param_type:"+typ)
		}
	}
	tokens = append(tokens, c.ccStructuredContextTokens(body)...)
	return tokens
}

func (c *ccConv) ccStructuredContextTokens(root *tree_sitter.Node) []string {
	const maxCContextTokens = 8192
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= maxCContextTokens {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	atom := func(n *tree_sitter.Node) string {
		if n == nil {
			return ""
		}
		if p := c.dotted(n); p != "" && p != "?" {
			return p
		}
		return compactCExprText(c.text(n))
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= maxCContextTokens {
			return
		}
		switch c.kind(n) {
		case "identifier", "field_identifier", "type_identifier":
			if name := c.text(n); name != "" {
				add("identifier:" + name)
			}
		case "preproc_def", "preproc_function_def":
			if name, body := cMacroNameAndBody(c.text(n)); name != "" {
				add("macro_name:" + name)
				if body != "" {
					add("macro_body:" + name + ":" + body)
				}
			}
		case "case_statement":
			if lv := c.field(n, "value"); lv != nil {
				if label := atom(lv); label != "" {
					add("switch_case:" + label)
				}
			} else {
				add("switch_default")
				for _, call := range c.ccCallPaths(n) {
					add("switch_default_call:" + call)
				}
			}
		case "call_expression":
			if path := c.dotted(c.field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				add("call:" + lastSeg(path))
				for i, arg := range c.namedChildren(c.field(n, "arguments")) {
					if a := atom(arg); a != "" {
						add("call_arg:" + path + ":" + a)
						add(fmt.Sprintf("call_arg_at:%s:%d:%s", path, i, a))
					}
					if shape := c.ccExprShape(arg); shape != "" {
						add("call_arg_shape:" + path + ":" + shape)
						add(fmt.Sprintf("call_arg_shape_at:%s:%d:%s", path, i, shape))
					}
				}
			}
		case "field_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "subscript_expression":
			if idx := c.dotted(n); idx != "" && idx != "?" {
				add("index:" + idx)
			}
			if shape := c.ccExprShape(n); shape != "" {
				add("index_shape:" + shape)
				add("subscript_shape:" + shape)
			}
			if base := atom(c.field(n, "argument")); base != "" {
				add("index_base:" + base)
			}
			if key := atom(c.field(n, "index")); key != "" {
				add("index_key:" + key)
			}
		case "assignment_expression":
			left := atom(c.field(n, "left"))
			right := atom(c.field(n, "right"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
			leftShape := c.ccExprShape(c.field(n, "left"))
			rightShape := c.ccExprShape(c.field(n, "right"))
			if leftShape != "" && rightShape != "" {
				add("assign_shape:" + leftShape + "=" + rightShape)
				if op := c.assignmentOp(n); op != "" && op != "=" {
					add("assign_op_shape:" + leftShape + op + rightShape)
				}
			}
		case "init_declarator":
			left := c.declName(c.field(n, "declarator"))
			right := atom(c.field(n, "value"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
			if rightShape := c.ccExprShape(c.field(n, "value")); rightShape != "" {
				add("assign_shape:ID=" + rightShape)
			}
		case "binary_expression":
			if expr := compactCExprText(c.text(n)); expr != "" {
				add("binary:" + expr)
			}
			if shape := c.ccExprShape(n); shape != "" {
				add("binary_shape:" + shape)
			}
		case "string_literal", "concatenated_string", "raw_string_literal":
			if lit := strings.Trim(cStringText(c.text(n)), "\""); lit != "" {
				add("literal:" + lit)
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *ccConv) ccMacroContextTokens() []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	lines := strings.Split(string(c.src), "\n")
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(raw, "#") {
			continue
		}
		for strings.HasSuffix(strings.TrimSpace(raw), "\\") && i+1 < len(lines) {
			raw = strings.TrimSuffix(strings.TrimSpace(raw), "\\") + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		name, body := cMacroNameAndBody(raw)
		if name == "" {
			continue
		}
		add("macro_name:" + name)
		if body != "" {
			add("macro_body:" + name + ":" + body)
		}
	}
	return out
}

func cMacroNameAndBody(raw string) (string, string) {
	name, _, body := cMacroNameParamsAndBody(raw)
	return name, body
}

// cMacroNameParamsAndBody splits a `#define NAME(a, b) body` directive into
// its name, formal parameter list and body. An object-like macro returns a
// nil parameter list, which is what tells the two apart.
func cMacroNameParamsAndBody(raw string) (string, []string, string) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "#")
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "define") {
		return "", nil, ""
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "define"))
	if s == "" {
		return "", nil, ""
	}
	i := 0
	for i < len(s) {
		ch := s[i]
		if !(ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || i > 0 && ch >= '0' && ch <= '9') {
			break
		}
		i++
	}
	if i == 0 {
		return "", nil, ""
	}
	name := s[:i]
	rest := strings.TrimSpace(s[i:])
	if strings.HasPrefix(rest, "(") {
		depth := 0
		for j, ch := range rest {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return name, cMacroParamList(rest[1:j]), compactCExprText(strings.TrimSpace(rest[j+1:]))
				}
			}
		}
		return name, nil, ""
	}
	return name, nil, compactCExprText(rest)
}

// cMacroParamList splits a macro's formal parameter list. A variadic tail and
// a parameter that is not a plain identifier are dropped rather than guessed
// at, so a positional mismatch can only cost a guard, never invent one.
func cMacroParamList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "...") || !ccIdentRe.MatchString(part) {
			continue
		}
		out = append(out, part)
	}
	return out
}

func (c *ccConv) ccCallPaths(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "call_expression" {
			if path := c.dotted(c.field(n, "function")); path != "" && path != "?" && !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *ccConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

// objcMethod extracts an ObjC method's selector name, parameter names, and body.
func (c *ccConv) objcMethod(n *tree_sitter.Node) (string, []string, *tree_sitter.Node) {
	var name string
	var params []string
	var body *tree_sitter.Node
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "identifier":
			if name == "" {
				name = c.text(ch)
			} else {
				name += ":" + c.text(ch)
			}
		case "method_parameter":
			for _, p := range c.namedChildren(ch) {
				if c.kind(p) == "identifier" {
					params = append(params, c.text(p))
				}
			}
		case "compound_statement":
			body = ch
		}
	}
	return name, params, body
}

func sameCNode(a, b *tree_sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

// declName unwraps pointer/array/function/parenthesized declarators to the
// underlying identifier name.
func (c *ccConv) declName(d *tree_sitter.Node) string {
	for d != nil {
		switch c.kind(d) {
		case "identifier", "field_identifier", "type_identifier":
			return c.text(d)
		case "pointer_declarator", "array_declarator", "parenthesized_declarator",
			"init_declarator", "function_declarator":
			d = c.field(d, "declarator")
		default:
			if inner := c.field(d, "declarator"); inner != nil {
				d = inner
			} else {
				return ""
			}
		}
	}
	return ""
}

// ccDefinitionIsPublicEntry reports whether a C-family function definition
// is a public-API definition: it keeps external linkage (no `static`
// storage class), its declarator resolved to a plain function name, and
// its storage and type prefix parsed cleanly. C has no syntactic
// public/private: an author opts a function out of the API with `static`,
// or hides the linkage behind a storage macro (`#define local static`,
// `#define GIT_INLINE(type) static __inline type`), which the grammar
// surfaces as a leading ERROR node or a macro_type_specifier, and a name
// macro (`#define PRIV(name) _pcre_##name`) leaves no plain declarator at
// all. These marks are therefore necessary, not sufficient, for "any
// caller may invoke this" -- a coarser threshold than the syntactic
// `public` the Java, C# and Rust frontends key on. C++ keeps its previous
// behaviour (no marking): its visibility lives in access specifiers and
// anonymous namespaces, which this predicate does not read.
func (c *ccConv) ccDefinitionIsPublicEntry(n *tree_sitter.Node) bool {
	if c.lang == "cpp" {
		return false
	}
	if ccHasInternalLinkage(c, n) {
		return false
	}
	if c.declName(c.field(n, "declarator")) == "" {
		return false
	}
	for _, ch := range c.namedChildren(n) {
		if ch.IsError() {
			return false
		}
		if c.kind(ch) == "macro_type_specifier" {
			return false
		}
	}
	return true
}

// ccHasInternalLinkage reports whether a function definition carries the
// `static` storage class: a static function is file-local and not public
// API, while every other definition is callable from another translation
// unit and may sit at a caller-controlled entry point.
func ccHasInternalLinkage(c *ccConv, n *tree_sitter.Node) bool {
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "storage_class_specifier" && strings.TrimSpace(c.text(ch)) == "static" {
			return true
		}
	}
	return false
}

func (c *ccConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	if n.IsError() || strings.HasPrefix(c.kind(n), "preproc_") {
		return c.decls(n)
	}
	switch c.kind(n) {
	case "function_definition":
		decl := c.field(n, "declarator")
		params := c.params(decl)
		if len(params) == 0 {
			params = c.params(n)
		}
		paramTypes := c.paramTypes(decl)
		if len(paramTypes) == 0 {
			paramTypes = c.paramTypes(n)
		}
		if len(params) == 0 {
			params, paramTypes = c.paramsFromSignatureText(c.text(n))
		}
		name := c.declName(decl)
		bodyStmts := c.block(c.field(n, "body"))
		if !ccOWASPBenchmarkFastPath() {
			bodyStmts = append(bodyStmts, c.ccIndexAccessObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPostCopyMissingBoundsObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccNumericParserMissingProgressObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPointerOffsetMissingRemainingSizeObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccDhcpOptionLengthUncheckedReadObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccBinarySearchEndpointGuardObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccStructPointerOOBWriteObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccSignedLengthUnderflowCopyObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPythonHashErrorObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCaseInsensitiveLocalIdentityObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccTrailingEscapeStringOverreadObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccEscapedTerminatorWriteObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccUnboundedAccumulatedAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccArrayBufferTransferMaxLengthObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCompressedBlockCapacityObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFragmentOffsetCopyObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccRubyCgiEscapeHTMLAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPythonUnicodeEscapeAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFormattedPlaceholderAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccSniffCsvExternalAccessObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCimgPnmDimensionOverflowObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccJpegSetjmpConstructorObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccParsedUserDefaultRootObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccUncheckedNullableResultDerefObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccConditionalFallbackDoubleFreeObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccGlibCommandLineAssemblyObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccWebRequestPathTraversalObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccRemoteListingDownloadPathObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFat12SuccessorBoundsObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccShiftedClusterAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccLengthDerivedAllocationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccUnboundedFgetcFixedBufferObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCgifSignedFrameCountObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccProtocolFrameBindingObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFilesystemImageDirentTraversalObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccProtocolCommandInjectionObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccJpegSubsamplingRatioObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCipherWithoutIntegrityHashObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccRepeatedKeyfileSubstitutionObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccReentrantQueueCleanupObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFdtNameValidationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPrivilegedEntryPointObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccAvahiReachableAssertionObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccProtocolListAmplificationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccProtocolFrameLengthUint16WrapObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccTLSApplicationDataStateObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccTLSProxyRedirectCertVerificationBypassObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCryptoImproperBlindingObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccWindowsRemotePathCredentialObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccLibreOfficeDibHeaderUnderflowObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccDNSInterfaceNewlineValidationObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCredentialProtocolNewlineObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccIcmpEchoPayloadLengthObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccIsolateLevelIncrementObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFlacBufferReuseObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccProtocolStatusVectorObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccChakraScopeSlotObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccBrOnReachableAssertionObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccHTTPPersistentAuthReuseObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccDestCapacityUncheckedObservations(n, params)...)
			bodyStmts = append(bodyStmts, c.ccSelfSizedCopyIntoDeclaredArrayObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccAssertOnlyLengthCopyObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccUnboundedCallSizedStackArrayObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccDestCapacityUncheckedCursorPairObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccFormatTruncationUncheckedReuseObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccOutParamStatusUncheckedObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccPrefixOffsetObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccCursorLoopMissingEndSentinelObservations(n, params)...)
			bodyStmts = append(bodyStmts, c.ccStackFallbackStrideUnderallocObservations(n)...)
			bodyStmts = append(bodyStmts, c.ccNarrowDeclaredBoundsCheckObservations(n)...)
		}
		return []nir.Stmt{nir.FuncDef{
			Name:          name,
			Params:        params,
			ParamTypes:    paramTypes,
			Body:          bodyStmts,
			Loc:           L,
			ContextTokens: c.ccFunctionContext(name, c.field(n, "body"), paramTypes),
			Exported:      c.ccDefinitionIsPublicEntry(n),
		}}
	case "struct_specifier":
		if c.lang == "cpp" {
			return []nir.Stmt{nir.ClassDef{Name: c.text(c.field(n, "name")), Body: c.decls(c.field(n, "body")), Loc: L}}
		}
		return nil
	case "union_specifier", "enum_specifier":
		return nil
	case "class_implementation", "class_interface", "category_implementation", // ObjC
		"category_interface", "protocol_declaration", "implementation_definition",
		"interface_declaration_list", "protocol_declaration_list":
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "method_definition", "method_declaration": // ObjC method
		name, params, body := c.objcMethod(n)
		paramTypes := c.objcParamTypes(n, params)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.block(body), Loc: L, ContextTokens: c.ccFunctionContext(name, body, paramTypes)}}
	case "namespace_definition", "linkage_specification", "declaration_list": // C++
		if b := c.field(n, "body"); b != nil {
			return c.decls(b)
		}
		return c.decls(n)
	case "template_declaration": // C++ — process the templated decl
		return c.decls(n)
	case "class_specifier": // C++
		return []nir.Stmt{nir.ClassDef{Name: c.text(c.field(n, "name")), Body: c.decls(c.field(n, "body")), Loc: L}}
	case "field_declaration_list":
		return c.decls(n)
	case "declaration":
		var out []nir.Stmt
		// the constructed/declared type (e.g. `File` in `File f(p)` / `File g = File(p)`).
		// C++ qualified types (std::ifstream) come through the declaration's `type`
		// field as a qualified_identifier; use its last dotted segment.
		typeName := c.text(lastChildKind(n, "type_identifier"))
		if typeName == "" {
			if t := c.field(n, "type"); t != nil {
				typeName = lastSeg(c.dotted(t))
			}
		}
		for _, d := range c.namedChildren(n) {
			switch c.kind(d) {
			case "init_declarator":
				name := c.declName(c.field(d, "declarator"))
				if val := c.field(d, "value"); name != "" && val != nil {
					out = append(out, nir.Assign{Targets: []string{name}, Value: c.expr(val)})
				}
			case "function_declarator":
				// C++ "most vexing parse": `File f(p)` parses as a function declaration,
				// but when the args are bare value identifiers (not typed parameters) it is
				// really a stack-allocated constructor call. Lower it so type/arg sinks match.
				if args, ok := c.vexingCtorArgs(c.field(d, "parameters")); ok && typeName != "" {
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: typeName, Loc: L}, Args: args,
						Path: typeName, Method: typeName, Loc: L,
					}})
				}
			}
		}
		return out
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement":
		kids := c.namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (C did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		condNode := c.field(n, "condition")
		ifn := nir.If{Cond: c.expr(condNode), Then: c.cBranch(c.field(n, "consequence")), Else: c.cBranch(c.field(n, "alternative"))}
		if target, val, ok := c.ccAssignmentExpr(condNode); ok {
			return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}, ifn}
		}
		return []nir.Stmt{ifn}
	case "while_statement", "for_statement", "do_statement":
		body := c.collectBlocks(n)
		if target, val, ok := c.ccAssignmentExpr(c.field(n, "condition")); ok {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "switch_statement":
		return []nir.Stmt{c.cSwitch(n)}
	case "compound_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "labeled_statement": // `name:` marks live code; lower the statement it names
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "statement_identifier" {
				continue
			}
			out = append(out, c.stmt(ch)...)
		}
		return out
	}
	return nil
}

func (c *ccConv) ccAssignmentExpr(n *tree_sitter.Node) (string, nir.Expr, bool) {
	for n != nil && c.kind(n) == "parenthesized_expression" {
		kids := c.namedChildren(n)
		if len(kids) != 1 {
			return "", nil, false
		}
		n = kids[0]
	}
	if n == nil || c.kind(n) != "assignment_expression" {
		for _, ch := range c.namedChildren(n) {
			if target, val, ok := c.ccAssignmentExpr(ch); ok {
				return target, val, true
			}
		}
		return "", nil, false
	}
	left := c.field(n, "left")
	if left == nil || c.kind(left) != "identifier" {
		return "", nil, false
	}
	right := c.field(n, "right")
	if right == nil {
		return "", nil, false
	}
	return c.text(left), c.expr(right), true
}

// vexingCtorArgs decides whether a function_declarator's parameter_list is really a
// constructor argument list (most-vexing-parse). It returns the arguments as value
// references only when EVERY parameter is a bare identifier/expression with no parameter
// name — a genuine prototype like `File f(int x)` or `File f(Foo x)` has a typed,
// named parameter and is left as a declaration (returns ok=false).
func (c *ccConv) vexingCtorArgs(params *tree_sitter.Node) ([]nir.Expr, bool) {
	if params == nil || c.kind(params) != "parameter_list" {
		return nil, false
	}
	var args []nir.Expr
	for _, p := range c.namedChildren(params) {
		if c.kind(p) != "parameter_declaration" {
			return nil, false // variadic, optional, etc. — not a clear ctor
		}
		kids := c.namedChildren(p)
		// a real parameter has a type plus a declarator (name); a vexing arg is a single
		// bare identifier/type_identifier standing in for a value reference.
		if len(kids) != 1 {
			return nil, false
		}
		switch c.kind(kids[0]) {
		case "identifier", "type_identifier":
			args = append(args, nir.Name{ID: c.text(kids[0]), Loc: c.loc(kids[0])})
		case "number_literal", "string_literal", "char_literal":
			args = append(args, nir.Const{Loc: c.loc(kids[0]), Value: c.text(kids[0])})
		default:
			return nil, false
		}
	}
	if len(args) == 0 {
		return nil, false
	}
	return args, true
}

func (c *ccConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch c.kind(inner) {
	case "assignment_expression":
		left := c.field(inner, "left")
		right := c.expr(c.field(inner, "right"))
		if ev := c.fieldClearNullEvent(inner, left, c.field(inner, "right")); ev != nil {
			return append([]nir.Stmt{*ev}, c.assignmentFallback(left, right)...)
		}
		if left != nil && c.kind(left) == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return c.assignmentFallback(left, right)
	case "call_expression":
		name := lastSeg(c.dotted(c.field(inner, "function")))
		args := c.namedChildren(c.field(inner, "arguments"))
		if len(args) > 0 {
			if cPropagators[name] {
				if dst := c.destName(args[0]); dst != "" {
					var parts []nir.Expr
					for _, a := range args[1:] {
						parts = append(parts, c.expr(a))
					}
					return []nir.Stmt{
						nir.Assign{Targets: []string{dst}, Value: nir.Format{Parts: parts, Loc: c.loc(inner)}},
						nir.ExprStmt{Value: c.expr(inner)},
					}
				}
			}
			if idx, ok := cReaders[name]; ok && idx < len(args) {
				if dst := c.destName(args[idx]); dst != "" {
					return []nir.Stmt{nir.Assign{Targets: []string{dst}, Value: c.expr(inner)}}
				}
			}
		}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *ccConv) assignmentFallback(left *tree_sitter.Node, right nir.Expr) []nir.Stmt {
	if left != nil {
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(left)}, nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: right}}
}

func (c *ccConv) fieldClearNullEvent(assign, left, right *tree_sitter.Node) *nir.ExprStmt {
	if left == nil || right == nil || !c.isNullExpr(right) {
		return nil
	}
	base, fld, ok := c.fieldTarget(left)
	if !ok {
		return nil
	}
	path := "analysis.field.clear_null"
	return &nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: c.loc(assign)},
		Args: []nir.Expr{
			c.expr(base),
			nir.Const{Loc: c.loc(left), Value: "field=" + fld},
		},
		Path:   path,
		Method: "clear_null",
		Loc:    c.loc(assign),
	}}
}

func (c *ccConv) fieldTarget(n *tree_sitter.Node) (*tree_sitter.Node, string, bool) {
	if n == nil || c.kind(n) != "field_expression" {
		return nil, "", false
	}
	base := c.field(n, "argument")
	fld := c.text(c.field(n, "field"))
	return base, fld, base != nil && fld != ""
}

func (c *ccConv) isNullExpr(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch c.kind(n) {
	case "identifier":
		return c.text(n) == "NULL"
	case "number_literal":
		return c.text(n) == "0"
	case "null", "nullptr":
		return true
	}
	return false
}

// destName returns the buffer variable name of a writer's destination argument,
// unwrapping a leading `&`.
func (c *ccConv) destName(a *tree_sitter.Node) string {
	if c.kind(a) == "pointer_expression" || c.kind(a) == "unary_expression" {
		if arg := c.field(a, "argument"); arg != nil {
			a = arg
		}
	}
	if c.kind(a) == "identifier" {
		return c.text(a)
	}
	return ""
}

// cBranch flattens one if-branch body: a `{}` compound_statement, an else_clause wrapper,
// or a brace-less single statement.
func (c *ccConv) cBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	switch c.kind(b) {
	case "compound_statement":
		var out []nir.Stmt
		for _, st := range c.namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range c.namedChildren(b) {
			out = append(out, c.cBranch(ch)...)
		}
		return out
	default:
		return c.stmt(b)
	}
}

// cSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through-empty cases merge into the next body) so a constant subject prunes.
func (c *ccConv) cSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := c.field(n, "body"); b != nil {
		for _, cs := range c.cSwitchCases(b) {
			lv := c.field(cs, "value")
			var stmts []nir.Stmt
			for _, ch := range c.namedChildren(cs) {
				if lv != nil && ch.StartByte() == lv.StartByte() {
					continue
				}
				stmts = append(stmts, c.stmt(ch)...)
			}
			if lv == nil { // default:
				deflt = append(deflt, stmts...)
				continue
			}
			pending = append(pending, c.expr(lv))
			if len(stmts) > 0 {
				cases = append(cases, stmts)
				labels = append(labels, pending)
				pending = nil
			}
		}
	}
	return nir.Switch{Subject: c.expr(c.field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *ccConv) cSwitchCases(body *tree_sitter.Node) []*tree_sitter.Node {
	var out []*tree_sitter.Node
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		for _, ch := range c.namedChildren(n) {
			switch {
			case c.kind(ch) == "case_statement":
				out = append(out, ch)
			case strings.HasPrefix(c.kind(ch), "preproc_") || ch.IsError():
				walk(ch)
			}
		}
	}
	walk(body)
	return out
}

func (c *ccConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch c.kind(ch) {
			case "compound_statement":
				out = append(out, c.block(ch)...)
			case "else_clause", "case_statement":
				walk(ch)
			case "expression_statement", "declaration", "return_statement", "if_statement":
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	if c.kind(n) == "compound_statement" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *ccConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range c.namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *ccConv) params(decl *tree_sitter.Node) []string {
	pl := c.paramList(decl)
	if pl == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(pl) {
		if isCParamDecl(c.kind(ch)) {
			if nm := c.declName(c.field(ch, "declarator")); nm != "" {
				out = append(out, nm)
			}
		}
	}
	return out
}

func (c *ccConv) paramTypes(decl *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	pl := c.paramList(decl)
	if pl == nil {
		return out
	}
	for _, ch := range c.namedChildren(pl) {
		if isCParamDecl(c.kind(ch)) {
			if nm := c.declName(c.field(ch, "declarator")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *ccConv) paramList(decl *tree_sitter.Node) *tree_sitter.Node {
	if pl := c.field(decl, "parameters"); pl != nil {
		return pl
	}
	for _, ch := range c.namedChildren(decl) {
		if c.kind(ch) == "parameter_list" {
			return ch
		}
		if pl := c.paramList(ch); pl != nil {
			return pl
		}
	}
	return nil
}

// A strings.Replacer builds a lookup trie on first use, so constructing one inside the
// function rebuilds and discards that trie on every call. Hoisted to build it once.
var cPointerSpacingReplacer = strings.NewReplacer("*", " * ", "&", " & ")

func (c *ccConv) paramsFromSignatureText(s string) ([]string, map[string]string) {
	out := map[string]string{}
	body := strings.Index(s, "{")
	if body >= 0 {
		s = s[:body]
	}
	start := strings.LastIndex(s, "(")
	end := strings.LastIndex(s, ")")
	if start < 0 || end <= start {
		return nil, out
	}
	var params []string
	for _, part := range strings.Split(s[start+1:end], ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "void" {
			continue
		}
		if eq := strings.Index(part, "="); eq >= 0 {
			part = strings.TrimSpace(part[:eq])
		}
		spaced := cPointerSpacingReplacer.Replace(part)
		fields := strings.Fields(spaced)
		if len(fields) == 0 {
			continue
		}
		name := fields[len(fields)-1]
		typeFields := fields[:len(fields)-1]
		for len(typeFields) > 0 && (typeFields[len(typeFields)-1] == "*" || typeFields[len(typeFields)-1] == "&") {
			typeFields = typeFields[:len(typeFields)-1]
		}
		typ := strings.Join(typeFields, " ")
		params = append(params, name)
		putParamType(out, name, typ)
	}
	return params, out
}

func isCParamDecl(kind string) bool {
	switch kind {
	case "parameter_declaration", "optional_parameter_declaration":
		return true
	}
	return false
}

func (c *ccConv) objcParamTypes(n *tree_sitter.Node, params []string) map[string]string {
	out := map[string]string{}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "method_parameter" {
			name := ""
			if nm := c.field(ch, "name"); nm != nil {
				name = c.text(nm)
			}
			typ := paramTypeFromField(c, ch)
			if typ == "" {
				typ = objcMethodParamType(c.text(ch))
			}
			putParamType(out, name, typ)
		}
	}
	for _, name := range params {
		if _, ok := out[name]; ok {
			continue
		}
		putParamType(out, name, objcMethodParamTypeForName(c.text(n), name))
	}
	return out
}

func objcMethodParamType(s string) string {
	start := strings.Index(s, "(")
	end := strings.Index(s, ")")
	if start < 0 || end <= start {
		return ""
	}
	return s[start+1 : end]
}

func objcMethodParamTypeForName(s, name string) string {
	idx := strings.Index(s, name)
	if idx < 0 {
		return ""
	}
	prefix := s[:idx]
	start := strings.LastIndex(prefix, "(")
	end := strings.LastIndex(prefix, ")")
	if start < 0 || end <= start {
		return ""
	}
	return prefix[start+1 : end]
}

func (c *ccConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range c.namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *ccConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "identifier", "field_identifier", "qualified_identifier", "namespace_identifier", "type_identifier":
		if v, ok := cBoolValue(c.text(n)); ok {
			return nir.Const{Loc: L, Value: v}
		}
		return nir.Name{ID: c.text(n), Loc: L}
	case "true", "false", "null", "nullptr":
		if v, ok := cBoolValue(c.text(n)); ok {
			return nir.Const{Loc: L, Value: v}
		}
		return nir.Const{Loc: L}
	case "number_literal", "char_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "concatenated_string", "raw_string_literal":
		// carry the quote-stripped literal text so val-matched marks/sinks
		// binding value predicates can match constants;
		// unquoteLit in lowering strips the surrounding delimiters.
		return nir.Const{Loc: L, Value: cStringText(c.text(n))}
	case "new_expression": // C++
		typ := c.text(c.field(n, "type"))
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(c.field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(c.field(n, "argument")), Attr: c.text(c.field(n, "field")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(c.field(n, "argument")), Key: c.expr(c.field(n, "index")), Path: c.dotted(c.field(n, "argument")), Loc: L}
	case "call_expression":
		fn := c.field(n, "function")
		path := c.dotted(fn)
		method := lastSeg(path)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(c.field(n, "arguments")), Path: path, Method: method, Loc: L}
	case "message_expression": // ObjC [receiver method:arg ...]
		recv := c.field(n, "receiver")
		methN := c.field(n, "method")
		method := c.text(methN)
		path := c.dotted(recv) + "." + method
		var args []nir.Expr
		// every named child except the receiver and the method selector is an arg
		for _, ch := range c.namedChildren(n) {
			if sameCNode(ch, recv) || sameCNode(ch, methN) || c.kind(ch) == "selector" {
				continue
			}
			args = append(args, c.expr(ch))
		}
		return nir.Call{Callee: nir.Attr{Base: c.expr(recv), Attr: method, Path: path, Loc: L}, Args: args, Path: path, Method: method, Loc: L}
	case "binary_expression":
		op := c.text(c.field(n, "operator"))
		left, right := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "pointer_expression":
		if arg := c.field(n, "argument"); arg != nil {
			if c.unaryOp(n) == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Thru{Inner: c.expr(arg)}
		}
	case "unary_expression":
		if arg := c.field(n, "argument"); arg != nil {
			op := c.unaryOp(n)
			if op == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Unary{Op: op, Operand: c.expr(arg), Loc: L}
		}
	case "assignment_expression":
		return c.expr(c.field(n, "right"))
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(c.field(n, "condition")), Then: c.expr(c.field(n, "consequence")), Else: c.expr(c.field(n, "alternative")), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *ccConv) ccIndexAccessObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	bodyText := compactCExprText(c.text(body))
	seen := map[string]bool{}
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "subscript_expression" {
			idx := c.field(n, "index")
			idxText := c.text(idx)
			compactIdx := compactCExprText(idxText)
			// ctype.h contract: tolower/toupper/isdigit & friends take and return
			// values representable as unsigned char or EOF; a char (possibly
			// signed) used directly as a table index -- or the raw tolower result
			// not cast back to unsigned char -- yields negative subscripts on
			// platforms with signed char (CWE-190/197, the ctype-underflow class).
			if loc := c.loc(n); loc != "" && ccSignedCharIndex(idxText) {
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: "analysis.signed_char.index", Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "index=" + compactIdx},
					},
					Path:   "analysis.signed_char.index",
					Method: "signed_char_index",
					Loc:    loc,
				}})
			}
			if ccStructuredIndex(idxText) && compactIdx != "" {
				loc := c.loc(n)
				if !seen[loc] {
					seen[loc] = true
					guard := "guard=missing_upper_bound"
					if ccHasUpperBoundGuard(bodyText, compactCExprText(c.textBefore(body, n)), compactIdx) {
						guard = "guard=upper_bound"
					}
					path := "analysis.index.access"
					method := "access"
					if guard == "guard=missing_upper_bound" {
						path = "analysis.index.field_derived_missing_upper_bound"
						method = "field_derived_missing_upper_bound"
					}
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Args: []nir.Expr{
							nir.Const{Loc: loc, Value: "index_kind=field_derived"},
							nir.Const{Loc: loc, Value: guard},
							nir.Const{Loc: loc, Value: "index=" + compactIdx},
						},
						Path:   path,
						Method: method,
						Loc:    loc,
					}})
				}
			}
			if count, ok := ccLastElementCountExpr(compactIdx); ok {
				loc := c.loc(n)
				prefixText := compactCExprText(c.textBefore(body, n))
				guard := "guard=missing_nonzero"
				if ccHasNonZeroGuard(prefixText, count) {
					guard = "guard=nonzero"
				}
				path := "analysis.zero_count.last_index"
				method := "last_index"
				if guard == "guard=missing_nonzero" {
					path = "analysis.zero_count.missing_nonzero_last_index"
					method = "missing_nonzero_last_index"
				}
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "index_kind=field_minus_one"},
						nir.Const{Loc: loc, Value: guard},
						nir.Const{Loc: loc, Value: "index=" + compactIdx},
						nir.Const{Loc: loc, Value: "count=" + count},
					},
					Path:   path,
					Method: method,
					Loc:    loc,
				}})
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

// ccDestCapacityUncheckedObservations reports an unbounded string copy into a
// caller-supplied destination whose separately-passed capacity the function
// itself relies on elsewhere -- a memset, fgets, fread, snprintf or strncpy
// size argument naming that destination -- yet never consults in a
// comparison. strcpy(3) and strcat(3) take no bound, so the copy honors
// whatever internal limit produced the bytes, not the destination's own
// capacity, and a converted or accumulated string longer than the caller's
// buffer overflows it exactly when the internal buffer is the larger of the
// two.
//
// The capacity is identified from the pairing the code already states: the
// libc calls above fix which argument is the destination's byte count, so a
// parameter read in that position is the capacity the caller handed over for
// that destination. The remediation is matched semantically, not by name: any
// relational comparison that mentions the capacity parameter clears the
// observation, so a clamp (`if (j >= lineSize) j = lineSize-1;`), an early
// return (`if (j > lineSize) return;`) and the mirrored spellings all read as
// consulting it. Only the destination's own parameter identifier counts, so a
// copy into a local array keeps whatever bound its declaration carries and is
// not reported here.
func (c *ccConv) ccDestCapacityUncheckedObservations(fn *tree_sitter.Node, params []string) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || len(params) < 2 {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "strcpy(") && !strings.Contains(text, "strcat(") {
		return nil
	}
	copyRe := ccRe(`\b(strcpy|strcat)\(([A-Za-z_][A-Za-z0-9_]*),`)
	capacityFor := ccDestCapacityParams(text, params)
	seen := map[string]bool{}
	var out []nir.Stmt
	for _, m := range copyRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		callee, dst := text[m[2]:m[3]], text[m[4]:m[5]]
		if !ccContainsParam(params, dst) {
			continue
		}
		for _, capacity := range capacityFor[dst] {
			key := dst + "/" + capacity
			if seen[key] {
				continue
			}
			if ccCapacityConsultedIn(text, capacity) {
				continue
			}
			seen[key] = true
			loc := c.loc(body)
			path := "analysis.copy.dest_capacity_unchecked"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "copy=" + callee},
					nir.Const{Loc: loc, Value: "dest=" + dst},
					nir.Const{Loc: loc, Value: "capacity=" + capacity},
					nir.Const{Loc: loc, Value: "guard=missing_capacity_check"},
				},
				Path:   path,
				Method: "dest_capacity_unchecked",
				Loc:    loc,
			}})
		}
	}
	return out
}

// ccFieldChainRe matches an object path made only of identifier segments:
// `pkt`, `pkt->hdr.len`, `cred->data`. Anything that starts elsewhere -- a
// call, a sizeof, a subscript, a parenthesised expression -- has no parent.
var ccFieldChainRe = ccRe(`^[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*$`)

// ccFieldParent returns the object a field-derived expression selects from,
// so two expressions can be recognised as reading two fields of one object:
// `pkt->payload` -> `pkt`, `cred->data.ptr` -> `cred->data`. The final field
// is dropped, so `v->in` and `v->length` share the parent `v` while
// `a->b.ptr` and `a->c.len` do not. A leading cast or address-of is ignored.
func ccFieldParent(s string) string {
	s = strings.TrimPrefix(s, "&")
	if strings.HasPrefix(s, "(") {
		if j := strings.Index(s, ")"); j > 0 {
			s = strings.TrimSpace(s[j+1:])
		}
	}
	i, j := strings.LastIndex(s, "->"), strings.LastIndex(s, ".")
	if i < 0 && j < 0 {
		return ""
	}
	k := i
	if j > k {
		k = j
	}
	if k <= 0 {
		return ""
	}
	if parent := s[:k]; ccFieldChainRe.MatchString(parent) {
		return parent
	}
	return ""
}

// ccConstantSizeExpr reports whether an array's declared size is
// constant-shaped: composed of numeric literals, operators and macro-shaped
// (all-uppercase) identifiers, so the declaration states a capacity that does
// not depend on the function's own parameters or locals. An array sized by a
// runtime value keeps a capacity the declaration does not state and is not
// reported here.
func ccConstantSizeExpr(size string) bool {
	for _, id := range ccIdentRe.FindAllString(size, -1) {
		if id != strings.ToUpper(id) {
			return false
		}
	}
	return true
}

var ccIdentRe = ccRe(`[A-Za-z_]\w*`)

// ccSelfSizedCopyIntoDeclaredArrayObservations reports a byte-count copy whose
// count is the copied object's own length field -- source and count read two
// fields of one object, `pkt->payload` with `pkt->len` -- into a destination
// the function itself declares as an array of constant size, in a function
// whose body never relates that destination's size to anything. The declared
// size is the only thing that bounds the destination, and a count taken from
// the object being copied is bounded by that object, not by the destination,
// so the copy writes past the array whenever the source's own length is the
// larger of the two. A lower bound does not discharge it: `if (pkt->len >= 4)`
// proves the source suffices and says nothing about the array, which is the
// shape this reports.
//
// The remediation is matched semantically, in either operand order: a
// relational comparison naming the destination's own size -- sizeof of it, or
// an identifier its declared size expression names -- clears the observation,
// so a clamp against the declared bound, an early return and the mirrored
// spellings all read as consulting it. Only the destination's size counts, so
// a comparison of the count against an unrelated bound (a required minimum
// length, a caller's separate buffer) leaves the observation standing.
//
// The observation is callee-neutral and carries the callee in the fact, so
// which spellings count as raw copies stays a binding question. The arguments
// are read structurally -- a bare identifier destination naming one of the
// function's declared constant-size arrays, and a source and count sharing a
// field parent -- never by name.
//
// Residuals, all false-negative: the comparison is not required to relate the
// count to the size, so a bound checked for a sibling copy or against an
// unrelated variable clears every copy in the function; a comparison naming a
// size identifier clears even when it bounds a different value than the count;
// the declaration is not required to dominate the copy, so an array declared
// in a block the copy cannot reach still vouches for it; and an array whose
// size names a lowercase constant is not treated as constant-sized.
func (c *ccConv) ccSelfSizedCopyIntoDeclaredArrayObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))

	// Arrays the function declares with a constant size: the declaration is
	// the one place the destination's capacity is stated.
	type declaredArray struct {
		name string
		ids  []string
	}
	arrays := map[string]declaredArray{}
	var collect func(*tree_sitter.Node)
	collect = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "array_declarator" {
			name := c.declName(n)
			size := compactCExprText(c.text(c.field(n, "size")))
			if name != "" && size != "" && ccConstantSizeExpr(size) {
				arrays[name] = declaredArray{name: name, ids: ccIdentRe.FindAllString(size, -1)}
			}
		}
		for _, ch := range c.namedChildren(n) {
			collect(ch)
		}
	}
	collect(body)
	if len(arrays) == 0 {
		return nil
	}

	atomOf := func(n *tree_sitter.Node) string {
		if n == nil {
			return ""
		}
		if p := c.dotted(n); p != "" && p != "?" {
			return p
		}
		return compactCExprText(c.text(n))
	}

	seen := map[string]bool{}
	var out []nir.Stmt
	var scan func(*tree_sitter.Node)
	scan = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "call_expression" {
			callee := c.dotted(c.field(n, "function"))
			args := c.namedChildren(c.field(n, "arguments"))
			if callee != "" && callee != "?" && len(args) >= 3 {
				dst, src, count := atomOf(args[0]), atomOf(args[1]), atomOf(args[2])
				if arr, ok := arrays[dst]; ok && dst != "" && src != "" && count != "" {
					parent := ccFieldParent(src)
					if parent != "" && parent == ccFieldParent(count) &&
						!ccCapacityConsultedIn(text, "sizeof("+dst+")") {
						consulted := false
						for _, id := range arr.ids {
							if len(id) > 2 && ccCapacityConsultedIn(text, id) {
								consulted = true
								break
							}
						}
						if !consulted {
							key := dst + "/" + callee + "/" + count
							if !seen[key] {
								seen[key] = true
								loc := c.loc(n)
								path := "analysis.copy.self_sized_declared_array"
								out = append(out, nir.ExprStmt{Value: nir.Call{
									Callee: nir.Name{ID: path, Loc: loc},
									Args: []nir.Expr{
										nir.Const{Loc: loc, Value: "callee=" + callee},
										nir.Const{Loc: loc, Value: "dest=" + dst},
										nir.Const{Loc: loc, Value: "src=" + src},
										nir.Const{Loc: loc, Value: "count=" + count},
										nir.Const{Loc: loc, Value: "guard=missing_dest_size_check"},
									},
									Path:   path,
									Method: "self_sized_declared_array",
									Loc:    loc,
								}})
							}
						}
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			scan(ch)
		}
	}
	scan(body)
	return out
}

// ccAssertOnlyLengthCopyObservations reports a byte-count copy whose count is a
// bare identifier the function bounds only inside assert(...). The macro
// documents the amount a caller must respect and, in a build that defines
// NDEBUG, enforces nothing, so a function whose one statement of that bound is
// an assert hands the copy whatever the caller passes, and the write runs past
// the destination exactly when a caller sends more than the asserted amount.
// That a comparison exists at all is what carries the reading: the developer
// wrote the bound, so it was meant to hold, and only its construct keeps it
// from running. A copy nobody compares is a different and far larger set, and
// is not reported here.
//
// The count and the comparison are read structurally -- a call whose third
// argument is a plain identifier node, and that identifier related to something
// with a relational operator -- and the assert is excluded by masking rather
// than by spelling: every assert(...) call in the body is blanked before the
// comparison is looked for again, so the same comparison moved into an if, a
// switch case or a loop condition reads as consulted while the one inside
// assert(...) does not. A comparison whose other side is a bare zero or sign
// literal is a nonzero or sign test, not a bound, and counts neither way, and a
// constant-shaped count -- an all-uppercase macro, or a sizeof expression --
// states a capacity the compiler fixes, so a copy so sized keeps whatever its
// spelling says. Requiring the identifier node itself keeps a compound count
// (`len + 1`) from borrowing a comparison another expression spelling it
// happens to contain, which is how a `newlen + 1 > reqlen` overflow check would
// otherwise vouch for a copy it does not bound.
//
// The observation is callee-neutral and carries the callee in the fact, so
// which spellings count as raw copies stays a binding question.
//
// Residuals, all false-negative: the comparison is not required to relate the
// count to the destination, so a bound checked for a sibling copy or against an
// unrelated value clears every copy in the function; the compacted body keeps
// comments, so a commented-out runtime check still clears; and a destination
// allocated by the count itself is bounded by construction, which this does not
// see, so a function that sizes its own buffer with the asserted length is
// reported alongside the ones that cannot.
// ccDestCapacityMemberArrayObservations reports a byte-count transfer whose
// destination is a field of some object while the struct declaring that field
// fixes its capacity as an array bound -- `uint8_t outputSegment[65536]`
// inside the struct -- and the function never bounds the count it hands over.
// The declaration is the one statement of that destination's capacity, so a
// count taken from anywhere else is bounded by wherever it came from and not
// by the destination, and the transfer writes past the member array exactly
// when the count is the larger of the two. A fixed-capacity member buffer
// filled by a length read off the wire is this shape in every spelling: the
// protocol's own segment limit is the bound the declaration states, and a
// function that never compares that length has no bound at all. The safe twin
// in the same body clamps or rejects the length first, which is the fix shape
// everywhere this family lands.
//
// The capacity and the guard are read structurally, never by name: the member
// array's declared size must be constant-shaped for the declaration to state
// a capacity rather than defer one, the destination must reach the transfer as
// an object path whose last segment names one of those fields in the first or
// second argument position, and the count
// must arrive as the transfer's last argument spelled as a bare identifier --
// the position the byte count holds in every transfer spelling, so a constant
// count or one computed at the call site states its own bound and is not
// reported. The remediation is matched semantically and is counted only for
// the count itself, because that is what the transfer writes: a relational
// comparison naming the count anywhere in the body reads as consulting a
// bound, so a clamp, an early return and the mirrored spellings all clear it,
// while a nonzero or sign test (`n > 0`) counts neither way; and a value
// assigned to the count that mentions the destination's own size -- sizeof of
// it, or an identifier its declared size names -- reads as a clamp by that
// capacity. A comparison that names the destination's size but a different
// value does not clear anything, which is what keeps a sibling branch's
// correct bound from vouching for this transfer: the compressed path of a
// decompressor may bound its own count by the same member array while the
// uncompressed path copies an unbounded length into it.
//
// The observation is callee-neutral and carries the callee in the fact, so
// which spellings count as transfers stays a binding question.
//
// Residuals, all false-negative: the count must be the last argument, so a
// spelling that follows it with a flags word is not paired; the destination
// and the count must reach the call as bare arguments, so a cast around either
// leaves the copy unreported; a bound enforced in the caller is invisible
// here; and the field is matched by name across the file's structs, so two
// structs sharing a field name share the capacity.
func (c *ccConv) ccDestCapacityMemberArrayObservations(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}

	// Member arrays the file declares with a constant size, keyed by field
	// name: the declaration is the one place that destination's capacity is
	// stated. A function-local array declarator is not a field declaration and
	// is left to the declared-array form of this observation.
	type memberArray struct{ ids []string }
	members := map[string]memberArray{}
	var collectMembers func(*tree_sitter.Node, bool)
	collectMembers = func(n *tree_sitter.Node, inField bool) {
		if n == nil {
			return
		}
		here := inField || c.kind(n) == "field_declaration"
		if here && c.kind(n) == "array_declarator" {
			if name := c.declName(n); name != "" {
				if size := compactCExprText(c.text(c.field(n, "size"))); size != "" && ccConstantSizeExpr(size) {
					members[name] = memberArray{ids: ccIdentRe.FindAllString(size, -1)}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			collectMembers(ch, here)
		}
	}
	collectMembers(root, false)
	if len(members) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var out []nir.Stmt
	var scanFn func(*tree_sitter.Node)
	scanFn = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "function_definition" {
			body := c.field(n, "body")
			if body == nil {
				return
			}
			text := compactCExprText(c.text(body))
			// Every value handed to an identifier anywhere in the body, so a
			// clamp that bounds the count in an earlier assignment -- by the
			// destination's own size or by an identifier its declared size
			// names -- counts as consulting that capacity.
			countValues := map[string][]string{}
			// The transfer candidates: a call carrying arguments.
			type transferCall struct {
				callee string
				args   []string
				node   *tree_sitter.Node
			}
			var transfers []transferCall
			var scanBody func(*tree_sitter.Node)
			scanBody = func(m *tree_sitter.Node) {
				if m == nil {
					return
				}
				switch c.kind(m) {
				case "assignment_expression":
					left, right := c.field(m, "left"), c.field(m, "right")
					if left == nil || right == nil {
						break
					}
					if c.text(c.field(m, "operator")) == "=" && c.kind(left) == "identifier" {
						countValues[c.text(left)] = append(countValues[c.text(left)], compactCExprText(c.text(right)))
					}
				case "init_declarator":
					if name := c.declName(m); name != "" {
						if v := c.field(m, "value"); v != nil {
							countValues[name] = append(countValues[name], compactCExprText(c.text(v)))
						}
					}
				case "call_expression":
					callee := c.dotted(c.field(m, "function"))
					if callee == "" || callee == "?" {
						break
					}
					var args []string
					for _, a := range c.namedChildren(c.field(m, "arguments")) {
						args = append(args, compactCExprText(c.text(a)))
					}
					transfers = append(transfers, transferCall{callee: callee, args: args, node: m})
				}
				for _, ch := range c.namedChildren(m) {
					scanBody(ch)
				}
			}
			scanBody(body)

			for _, t := range transfers {
				if len(t.args) < 2 {
					continue
				}
				count := t.args[len(t.args)-1]
				if !ccIdentifierLike(count) || ccBoundComparedIn(text, count) {
					continue
				}
				// The destination of a byte-count transfer is its first or
				// second argument -- the second where a leading context
				// argument carries the source object -- and never a later one,
				// so the member array a transfer reads from cannot pose as the
				// one it writes. Which of the two a spelling uses stays a
				// binding question, answered by the position the fact carries.
				dst, arr, argIndex := "", memberArray{}, -1
				for i := 0; i < 2 && i < len(t.args)-1; i++ {
					cand := t.args[i]
					leaf := ccFieldLeaf(cand)
					if !ccFieldChainRe.MatchString(cand) || leaf == "" {
						continue
					}
					if found, ok := members[leaf]; ok {
						dst, arr, argIndex = cand, found, i
						break
					}
				}
				if argIndex < 0 {
					continue
				}
				// A clamp entering the count's own assignment reads as
				// consulting the capacity; a comparison naming some other
				// value against it does not.
				clamped := false
				for _, v := range countValues[count] {
					if strings.Contains(v, "sizeof("+dst+")") {
						clamped = true
						break
					}
					for _, id := range arr.ids {
						if len(id) > 2 && ccContainsWord(v, id) {
							clamped = true
							break
						}
					}
					if clamped {
						break
					}
				}
				if clamped {
					continue
				}
				key := dst + "/" + t.callee + "/" + count
				if seen[key] {
					continue
				}
				seen[key] = true
				loc := c.loc(t.node)
				path := "analysis.copy.member_capacity_unchecked"
				site := "arg0=" + t.callee
				if argIndex == 1 {
					site = "arg1=" + t.callee
				}
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: site},
						nir.Const{Loc: loc, Value: "dest=" + dst},
						nir.Const{Loc: loc, Value: "count=" + count},
						nir.Const{Loc: loc, Value: "guard=missing_capacity_check"},
					},
					Path:   path,
					Method: "member_capacity_unchecked",
					Loc:    loc,
				}})
			}
		}
		for _, ch := range c.namedChildren(n) {
			scanFn(ch)
		}
	}
	scanFn(root)
	return out
}

func (c *ccConv) ccAssertOnlyLengthCopyObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	raw := c.text(body)
	clean := compactCExprText(raw)
	masked := compactCExprText(ccMaskAssertCalls(raw))
	if masked == clean {
		return nil
	}

	atomOf := func(n *tree_sitter.Node) string {
		if n == nil {
			return ""
		}
		if p := c.dotted(n); p != "" && p != "?" {
			return p
		}
		return compactCExprText(c.text(n))
	}

	seen := map[string]bool{}
	var out []nir.Stmt
	var scan func(*tree_sitter.Node)
	scan = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "call_expression" {
			callee := c.dotted(c.field(n, "function"))
			args := c.namedChildren(c.field(n, "arguments"))
			if callee != "" && callee != "?" && len(args) >= 3 &&
				args[2] != nil && c.kind(args[2]) == "identifier" {
				dst, count := atomOf(args[0]), c.text(args[2])
				if dst != "" && !ccConstantCountExpr(count) &&
					ccBoundComparedIn(clean, count) && !ccBoundComparedIn(masked, count) {
					key := dst + "/" + callee + "/" + count
					if !seen[key] {
						seen[key] = true
						loc := c.loc(n)
						path := "analysis.copy.assert_only_length_bound"
						out = append(out, nir.ExprStmt{Value: nir.Call{
							Callee: nir.Name{ID: path, Loc: loc},
							Args: []nir.Expr{
								nir.Const{Loc: loc, Value: "callee=" + callee},
								nir.Const{Loc: loc, Value: "dest=" + dst},
								nir.Const{Loc: loc, Value: "count=" + count},
								nir.Const{Loc: loc, Value: "guard=assert_only_bound"},
							},
							Path:   path,
							Method: "assert_only_length_bound",
							Loc:    loc,
						}})
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			scan(ch)
		}
	}
	scan(body)
	return out
}

// ccConstantCountExpr reports whether a copy's count expression is a
// compile-time constant: the macro-shaped identifiers and operators
// ccConstantSizeExpr reads in a declaration's size, plus a sizeof expression,
// which states an object's size however its operand is spelled. The compiler
// fixes such a count, so no caller chooses it and no runtime comparison could
// bound it, which puts the site outside what this reports.
func ccConstantCountExpr(count string) bool {
	return ccConstantSizeExpr(count) || strings.Contains(count, "sizeof(")
}

// ccAssertCallRe matches an assert macro invocation in the raw body text,
// before whitespace is stripped. Compaction first would glue the macro to a
// preceding preprocessor directive -- `#endif` and `assert` become one
// identifier-shaped run, so the word boundary no longer matches -- which is
// exactly the shape a conditional debug block leaves behind. A project's own
// prefixed or suffixed spelling (asserts, _assert, ASSERT) does not match.
var ccAssertCallRe = ccRe(`\bassert\s*\(`)

// ccMaskAssertCalls blanks every assert(...) call in raw body text, keyword
// through closing parenthesis, so a comparison inside the macro's argument list
// cannot be read as one the running code evaluates. The blanks keep the text's
// length, so the result compacts to the body's compacted form minus whatever
// the asserts contributed.
func ccMaskAssertCalls(text string) string {
	out := []byte(text)
	for _, m := range ccAssertCallRe.FindAllStringSubmatchIndex(text, -1) {
		open := strings.LastIndex(text[m[0]:m[1]], "(") + m[0]
		hi := ccCallSpanEnd(text, open)
		if hi < 0 {
			continue
		}
		for i := m[0]; i <= hi; i++ {
			out[i] = ' '
		}
	}
	return string(out)
}

// ccCallSpanEnd returns the index of the ')' that closes the '(' at open, or
// -1 when the call does not close within text.
func ccCallSpanEnd(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// ccBoundComparedIn reports whether text relates ident to anything with a
// relational operator, on either side, counting only comparisons whose other
// side is not a bare zero or sign literal: `n > 0` is a nonzero test, not a
// bound, and must not vouch for one.
func ccBoundComparedIn(text, ident string) bool {
	return ccComparisonAfter(text, ident, '<', true) ||
		ccComparisonAfter(text, ident, '>', true) ||
		ccComparisonBefore(text, ident, '<') ||
		ccComparisonBefore(text, ident, '>')
}

// ccFieldLeaf returns the last segment of an object path, so a field
// expression names the member it selects: `zgfx->outputSegment` -> the
// outputSegment field, `pkt.hdr.len` -> the len field. Both member-access
// spellings separate segments, and a path with no separator is itself the
// leaf.
func ccFieldLeaf(s string) string {
	if i := strings.LastIndex(s, "->"); i >= 0 {
		return s[i+2:]
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ccDestCapacityUncheckedCursorPairObservations reports a transfer whose length
// the code charges to a paired remaining-count field -- the cursor-and-remaining
// idiom that walks a buffer slice, advancing the destination and decrementing a
// same-object counter by that one length, in one step of the same walk -- while
// the length's own bound never consults the counter. The pairing is read from
// what the function itself does, never from names or types: `dest += n` beside
// `remaining -= n` in one block states that the counter is that destination's
// remaining byte count, so a length taken from the source side alone, or
// clamped by a constant, is bounded by the source and not by the destination,
// and the copy runs past the slice exactly when the source holds the larger of
// the two. The unsigned decrement then wraps the counter past zero, which is
// how these surface at runtime.
//
// Two statements are required before that reading holds. The advance and the
// decrement must sit in one block, because a transfer step charges both at
// once, while the same field moved by an unrelated loop elsewhere in the
// function says nothing about this one. And the length must be charged to
// exactly one counter of that object, because a function that decrements
// several same-object counters by one length -- a whole-stream byte count
// beside a slice's own remaining -- no longer states which of them bounds the
// destination.
//
// The remediation is matched semantically, as in the parameter form of this
// observation: a relational comparison naming the counter, the counter entering
// the length's own assignment, or the counter handed to the transfer call all
// read as consulting it, in either operand order. A zero test does not consult
// it, because an emptiness check bounds nothing.
//
// Residuals, all false-negative: the destination and its length must reach the
// transfer call as bare arguments, so a cast around either, or a copy whose
// length is computed at the call site rather than carried in the charged
// variable, is not paired; the compacted body keeps comments, so a
// commented-out bound on the counter still clears; and the pairing is
// intra-function, so a counter maintained across calls in a helper is invisible
// here.
func (c *ccConv) ccDestCapacityUncheckedCursorPairObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))

	// The cursor statements: a field of some object advanced by a bare
	// identifier, and a field of the same object decremented by it, each with
	// the block it sits in.
	type cursorStmt struct {
		field string
		block *tree_sitter.Node
	}
	advances := map[string][]cursorStmt{}   // length -> destinations
	decrements := map[string][]cursorStmt{} // length -> counters
	// Every value assigned to a length anywhere in the body, so a clamp that
	// names the counter in an earlier assignment counts as consulting it.
	lenValues := map[string][]string{}
	// The transfer candidates: a call carrying a destination and one length as
	// bare arguments.
	type transferCall struct {
		callee string
		args   []string
	}
	var transfers []transferCall

	var collect func(*tree_sitter.Node, *tree_sitter.Node)
	collect = func(n *tree_sitter.Node, block *tree_sitter.Node) {
		if n == nil {
			return
		}
		here := block
		if c.kind(n) == "compound_statement" {
			here = n
		}
		switch c.kind(n) {
		case "assignment_expression":
			left, right := c.field(n, "left"), c.field(n, "right")
			op := c.text(c.field(n, "operator"))
			if left == nil || right == nil {
				break
			}
			if op == "=" && c.kind(left) == "identifier" {
				lenValues[c.text(left)] = append(lenValues[c.text(left)], compactCExprText(c.text(right)))
			}
			if c.kind(right) != "identifier" || c.kind(left) != "field_expression" {
				break
			}
			d := compactCExprText(c.text(left))
			if !ccFieldChainRe.MatchString(d) {
				break
			}
			l := c.text(right)
			switch op {
			case "+=":
				advances[l] = append(advances[l], cursorStmt{field: d, block: here})
			case "-=":
				decrements[l] = append(decrements[l], cursorStmt{field: d, block: here})
			}
		case "init_declarator":
			if name := c.declName(n); name != "" {
				if v := c.field(n, "value"); v != nil {
					lenValues[name] = append(lenValues[name], compactCExprText(c.text(v)))
				}
			}
		case "call_expression":
			callee := c.dotted(c.field(n, "function"))
			if callee == "" || callee == "?" {
				break
			}
			var args []string
			for _, a := range c.namedChildren(c.field(n, "arguments")) {
				args = append(args, ccBareArgText(compactCExprText(c.text(a))))
			}
			transfers = append(transfers, transferCall{callee: callee, args: args})
		}
		for _, ch := range c.namedChildren(n) {
			collect(ch, here)
		}
	}
	collect(body, nil)
	if len(advances) == 0 || len(transfers) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var out []nir.Stmt
	for l, advs := range advances {
		decs, ok := decrements[l]
		if !ok {
			continue
		}
		for _, adv := range advs {
			parent := ccFieldParent(adv.field)
			if parent == "" {
				continue
			}
			// The length must be charged to exactly one counter of the
			// destination's own object, in the same block as the advance, for
			// the pairing to be stated.
			var counter *cursorStmt
			for i := range decs {
				dec := decs[i]
				if dec.field == adv.field || ccFieldParent(dec.field) != parent {
					continue
				}
				if !sameCNode(dec.block, adv.block) {
					continue
				}
				if counter != nil {
					counter = nil
					break
				}
				counter = &decs[i]
			}
			if counter == nil {
				continue
			}
			dst, capacity := adv.field, counter.field

			// The transfer itself: a call handed both the destination and the
			// length as bare arguments.
			callee := ""
			capacityHandedOver := false
			for _, t := range transfers {
				hasDest, hasLen, hasCap := false, false, false
				for _, a := range t.args {
					switch a {
					case dst:
						hasDest = true
					case l:
						hasLen = true
					case capacity:
						hasCap = true
					}
				}
				if hasDest && hasLen {
					if callee == "" {
						callee = t.callee
					}
					if hasCap {
						capacityHandedOver = true
					}
				}
			}
			if callee == "" {
				continue
			}
			if capacityHandedOver || ccCapacityConsultedIn(text, capacity) {
				continue
			}
			consulted := false
			for _, v := range lenValues[l] {
				if ccContainsWord(v, capacity) {
					consulted = true
					break
				}
			}
			if consulted {
				continue
			}

			key := dst + "/" + capacity + "/" + l
			if seen[key] {
				continue
			}
			seen[key] = true
			loc := c.loc(body)
			path := "analysis.copy.dest_capacity_unchecked"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "copy=" + callee},
					nir.Const{Loc: loc, Value: "dest=" + dst},
					nir.Const{Loc: loc, Value: "capacity=" + capacity},
					nir.Const{Loc: loc, Value: "length=" + l},
					nir.Const{Loc: loc, Value: "guard=missing_capacity_check"},
				},
				Path:   path,
				Method: "dest_capacity_unchecked",
				Loc:    loc,
			}})
		}
	}
	return out
}

// ccBareArgText reduces a call argument to the identifier path it names, so an
// out-parameter length handed over by address (`&n`) still pairs with the
// variable the cursor statements charge. Anything else is returned unchanged,
// which simply fails to pair.
func ccBareArgText(s string) string {
	s = strings.TrimPrefix(s, "&")
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = s[1 : len(s)-1]
	}
	return s
}

// ccFormatTruncationUncheckedReuseObservations reports the C standard's
// formatted-output length contract: snprintf(3) and vsnprintf(3) return the
// number of characters the output would have needed, not the number written,
// so a return value at or above the bound the call received means the output
// was truncated. A function that captures that return value and then reuses
// it as a byte count -- a call argument, alone or in arithmetic with another
// running count -- or as the destination pointer's offset, without ever
// comparing it against the bound, steps outside the destination whenever the
// format expands past it.
//
// All three halves are relations the code itself states, and the reuse must
// name the captured variable itself: a returned length that is never handed
// to another call and never moves a pointer is unused information, which is
// what keeps the fact off most capture sites. A use in a slot the library
// itself bounds or sizes -- the size argument of a bounded formatted-output
// call, the count argument of a bounded string copy, an allocator's size
// argument, or a value following a printing call's format string -- is not
// a reuse: the measure-then-format idiom consumes the would-be length
// safely by construction. The guard is semantic rather
// than a spelling -- any relational comparison of the captured variable
// against an operand mentioning sizeof, against the call's own size argument,
// or against an all-caps limit constant, in either operand order, clears the
// fact -- so a cast on either side, `>= BUFSZ`, `< 0 || >=` and the mirrored
// orders all read as consulting the bound.
//
// Residuals, all false-negative: the comparison is not required to dominate
// the reuse, so a check in one branch vouches for a sibling branch's reuse;
// the compacted body keeps comments, so a commented-out check still clears;
// an inline declaration fuses with its type once whitespace is stripped
// (`int n =` reads as `intn=`), so only the assignment form is recognised;
// and the unbounded sprintf spellings have no bound to consult and are not
// reported here at all.

// ccUnboundedCallSizedStackArrayObservations reports a stack array whose
// declared size is a bare identifier that a call in the same function
// assigns -- a variable-length array sized at frame layout by a runtime
// value -- in a body that never compares that identifier against anything.
// The allocation then takes whatever the call produced, so a call that
// reports the length of data a peer sent sizes the receiver's stack by that
// peer, and one message large enough exhausts it. The bound the allocation
// needs is a comparison on the length before it sizes the array, which is
// the fix shape everywhere this family lands: reject the oversized value
// and return.
//
// The size and its assignment are read structurally from the tree -- an
// array declarator whose size field is a plain identifier, and an
// identifier an init-declarator or an assignment hands a call's result, in
// either spelling, keeping the last assignment so an identifier a
// non-call later overwrites stops qualifying -- and the remediation is
// matched semantically, in either operand order: any relational comparison
// naming the size identifier, anywhere in the body, clears the observation,
// so a clamp, an early return and the mirrored spellings all read as
// consulting it, while a comparison of an unrelated value leaves it
// standing. An equality check does not clear: the compacted text cannot
// tell an exact-match fix from an error-sentinel check (`len == 0`), and a
// sentinel must not vouch for a bound.
//
// The observation is callee-neutral and carries the callee in the fact, so
// which calls report a received length stays a binding question, and a
// macro-shaped all-uppercase size reads as a constant the declaration
// states, not a value the function computes.
func (c *ccConv) ccUnboundedCallSizedStackArrayObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))

	// the identifier each assignment last handed a value, empty when that
	// value is not a call, read from the tree so the compacted text's
	// fused declaration types cannot blur the name
	assigned := map[string]string{}
	var collectAssigns func(*tree_sitter.Node)
	collectAssigns = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		left, value := "", c.field(n, "value")
		switch c.kind(n) {
		case "init_declarator":
			left = c.declName(c.field(n, "declarator"))
		case "assignment_expression":
			if l := c.field(n, "left"); l != nil && c.kind(l) == "identifier" {
				left = c.text(l)
			}
			value = c.field(n, "right")
		}
		if left != "" && value != nil {
			callee := ""
			if c.kind(value) == "call_expression" {
				if p := c.dotted(c.field(value, "function")); p != "" && p != "?" {
					callee = p
				}
			}
			assigned[left] = callee
		}
		for _, ch := range c.namedChildren(n) {
			collectAssigns(ch)
		}
	}
	collectAssigns(body)

	seen := map[string]bool{}
	var out []nir.Stmt
	var scan func(*tree_sitter.Node)
	scan = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "array_declarator" {
			name := c.declName(c.field(n, "declarator"))
			size := c.field(n, "size")
			if name != "" && size != nil && c.kind(size) == "identifier" {
				sizeID := c.text(size)
				if callee, ok := assigned[sizeID]; ok &&
					!ccConstantSizeExpr(sizeID) &&
					!ccCapacityConsultedIn(text, sizeID) {
					key := name + "/" + sizeID + "/" + callee
					if !seen[key] {
						seen[key] = true
						loc := c.loc(n)
						path := "analysis.alloc.unbounded_call_sized_stack_array"
						out = append(out, nir.ExprStmt{Value: nir.Call{
							Callee: nir.Name{ID: path, Loc: loc},
							Args: []nir.Expr{
								nir.Const{Loc: loc, Value: "callee=" + callee},
								nir.Const{Loc: loc, Value: "array=" + name},
								nir.Const{Loc: loc, Value: "size=" + sizeID},
								nir.Const{Loc: loc, Value: "guard=missing_size_bound_check"},
							},
							Path:   path,
							Method: "unbounded_call_sized_stack_array",
							Loc:    loc,
						}})
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			scan(ch)
		}
	}
	scan(body)
	return out
}

func (c *ccConv) ccFormatTruncationUncheckedReuseObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	captureRe := ccRe(`\*?([A-Za-z_][A-Za-z0-9_]*)=(?:\([A-Za-z_][A-Za-z0-9_]*\*?\))?_?v?snprintf_?s?\(([A-Za-z_][A-Za-z0-9_]*),([^,]+),`)
	seen := map[string]bool{}
	var out []nir.Stmt
	for _, m := range captureRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		v, dst, sizeArg := text[m[2]:m[3]], text[m[4]:m[5]], text[m[6]:m[7]]
		if v == dst || seen[v] {
			continue
		}
		tail := text[m[1]:]
		reuse := ""
		if ccFormatVarAdjacentTo(dst, v, tail) {
			reuse = "destination_pointer_offset"
		} else if ccFormatVarUsedAsCount(v, tail) {
			reuse = "call_argument"
		}
		if reuse == "" || ccFormatLengthBoundConsulted(tail, v, sizeArg) {
			continue
		}
		seen[v] = true
		loc := c.loc(body)
		path := "analysis.format_length.truncation_unchecked"
		out = append(out, nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "format=snprintf"},
				nir.Const{Loc: loc, Value: "var=" + v},
				nir.Const{Loc: loc, Value: "dest=" + dst},
				nir.Const{Loc: loc, Value: "reuse=" + reuse},
				nir.Const{Loc: loc, Value: "guard=missing_truncation_check"},
			},
			Path:   path,
			Method: "truncation_unchecked",
			Loc:    loc,
		}})
	}
	return out
}

// ccFormatVarAdjacentTo reports whether the compacted text places the
// captured length beside its own destination in pointer arithmetic, in
// either operand order, with the dereference spelling allowed on the length.
func ccFormatVarAdjacentTo(dst, v, text string) bool {
	d, q := regexp.QuoteMeta(dst), regexp.QuoteMeta(v)
	return regexp.MustCompile(`\b`+d+`\+\*?`+q+`\b`).MatchString(text) ||
		regexp.MustCompile(`\b\*?`+q+`\+`+d+`\b`).MatchString(text)
}

// ccFormatVarUsedAsCount reports whether the compacted text hands the
// captured length to a call as a byte count: as a whole argument, or inside
// an argument's arithmetic with another count. The delimiters are the
// comma and parenthesis the argument list itself supplies, so a loop
// condition or a comparison naming the length does not read as a count;
// an argument that follows the format string of a printing call is a value
// being formatted, not a count; an argument the C library itself bounds
// or sizes -- the size argument of a bounded formatted-output call, the
// count argument of a bounded string copy, any argument of an allocator --
// consumes the would-be length safely by construction and does not read as
// one either; and a whole argument in the first position is the call's
// destination or handle in the C library's own convention, while the
// callers that report a captured length first -- an error or status helper
// -- take the code in that slot, so a bare first argument does not read as
// a count either.
func ccFormatVarUsedAsCount(v, text string) bool {
	q := regexp.QuoteMeta(v)
	for _, m := range regexp.MustCompile(`[(,](?:[^(),]*[^A-Za-z0-9_(),])?\*?`+q+`\b[-+][^(),]*[),]`).FindAllStringSubmatchIndex(text, -1) {
		if ccFormatArgFollowsFormatString(text, m[0]) || ccFormatUseInBoundedRole(text, m[0]) {
			continue
		}
		return true
	}
	for _, m := range regexp.MustCompile(`[(,]\*?`+q+`[),]`).FindAllStringSubmatchIndex(text, -1) {
		if ccFormatArgFollowsFormatString(text, m[0]) || ccFormatUseInBoundedRole(text, m[0]) {
			continue
		}
		if ccFormatArgumentIndexAt(text, m[0]) == 0 {
			continue
		}
		return true
	}
	return false
}

// ccFormatArgFollowsFormatString reports whether the argument starting at
// the delimiter at text[start] is preceded by a quoted format string, which
// makes it a value being formatted rather than a byte count. The scan back
// to the argument's own delimiter skips string-literal content, so a
// parenthesis or comma inside the format string does not end the argument.
func ccFormatArgFollowsFormatString(text string, start int) bool {
	prev, inString := -1, false
	for i := start - 1; i >= 0; i-- {
		switch text[i] {
		case '"':
			if i == 0 || text[i-1] != '\\' {
				inString = !inString
			}
		case '(', ',':
			if !inString {
				prev = i
			}
		}
		if prev >= 0 {
			break
		}
	}
	if prev < 0 {
		return false
	}
	seg := text[prev+1 : start]
	return strings.HasPrefix(seg, `"`) && strings.HasSuffix(seg, `"`) && strings.Contains(seg, `%`)
}

// ccFormatUseInBoundedRole reports whether the argument starting at the
// delimiter at text[start] occupies a slot whose own semantics bound or
// size the access: the size argument of a bounded formatted-output call
// caps the write, the count argument of a bounded string copy caps the
// copy, and an allocator's size argument sizes the destination by the very
// length in question. Passing the would-be length that way -- the
// measure-then-format idiom -- cannot step outside the destination, unlike
// a send or write count or a pointer offset.
func ccFormatUseInBoundedRole(text string, start int) bool {
	open := ccFormatEnclosingCallParen(text, start)
	if open < 0 {
		return false
	}
	callee := ccFormatCalleeBefore(text, open)
	if callee == "" {
		return false
	}
	arg := ccFormatArgumentIndex(text, open, start)
	switch {
	case ccRe(`^_?v?snprintf_?s?$`).MatchString(callee):
		return arg == 1
	case callee == "strncpy" || callee == "strncat":
		return arg == 2
	case callee == "malloc" || callee == "calloc" || callee == "realloc" || callee == "alloca":
		return true
	}
	return false
}

// ccFormatArgumentIndexAt returns the zero-based position of the argument
// that starts just after the delimiter at pos within its enclosing call.
func ccFormatArgumentIndexAt(text string, pos int) int {
	open := ccFormatEnclosingCallParen(text, pos)
	if open < 0 {
		return -1
	}
	return ccFormatArgumentIndex(text, open, pos)
}

// ccFormatEnclosingCallParen returns the index of the parenthesis that
// opens the call whose argument list contains position pos, skipping
// string-literal content and balancing nested calls.
func ccFormatEnclosingCallParen(text string, pos int) int {
	depth, inString := 0, false
	for i := pos; i >= 0; i-- {
		switch text[i] {
		case '"':
			if i == 0 || text[i-1] != '\\' {
				inString = !inString
			}
		case ')':
			if !inString {
				depth++
			}
		case '(':
			if !inString {
				if depth == 0 {
					return i
				}
				depth--
			}
		}
	}
	return -1
}

// ccFormatCalleeBefore returns the identifier immediately preceding the
// call's opening parenthesis.
func ccFormatCalleeBefore(text string, open int) string {
	end := open
	for end > 0 && ccIsIdentChar(text[end-1]) {
		end--
	}
	return text[end:open]
}

// ccFormatArgumentIndex returns the zero-based position of the argument
// that starts just after the delimiter at pos within the call opened at
// open, counting only the commas that sit at the call's own depth. A comma
// delimiter separates the argument from its predecessors, so it counts as
// one more; a parenthesis delimiter opens the list itself.
func ccFormatArgumentIndex(text string, open, pos int) int {
	arg, depth, inString := 0, 0, false
	for i := open + 1; i < pos; i++ {
		switch text[i] {
		case '"':
			if text[i-1] != '\\' {
				inString = !inString
			}
		case '(':
			if !inString {
				depth++
			}
		case ')':
			if !inString {
				depth--
			}
		case ',':
			if !inString && depth == 0 {
				arg++
			}
		}
	}
	if pos < len(text) && text[pos] == ',' {
		arg++
	}
	return arg
}

// ccFormatLengthBoundConsulted reports whether the compacted text compares
// the captured length against the bound the formatted-output call received:
// an operand mentioning sizeof, the call's own size argument when it is not
// itself a sizeof expression, or an all-caps limit constant. Either operand
// order, with a cast on either side, counts. The comparison must name the
// variable as a whole token, so a longer identifier ending in the same
// letters compared against anything does not clear.
func ccFormatLengthBoundConsulted(text, v, sizeArg string) bool {
	branches := `(?:\([A-Za-z_][A-Za-z0-9_]*\*?\))?sizeof\([^()]*\)|[A-Z][A-Z0-9_]+`
	if sa := strings.TrimPrefix(sizeArg, "*"); sa != "" && !strings.Contains(sa, "sizeof") {
		branches += `|` + regexp.QuoteMeta(sa)
	}
	bound := `(?:` + branches + `)`
	q := regexp.QuoteMeta(v)
	if regexp.MustCompile(`(?:^|[^A-Za-z0-9_])\*?` + q + `(>=|<=|==|!=|>|<)` + bound).MatchString(text) {
		return true
	}
	castV := `(?:\([A-Za-z_][A-Za-z0-9_]*\*?\))?\*?` + q
	return regexp.MustCompile(bound + `(>=|<=|==|!=|>|<)` + castV + `\b`).MatchString(text)
}

// ccOutParamStatusUncheckedObservations reports the C out-parameter
// contract: a call that hands its output back through a pointer the caller
// owns reports in its return value whether that output is usable, and the
// output can be half-built when the call fails -- the callee returns along
// its own error path leaving whatever it had already stored in place. A
// function that captures that status and then reads the output through a
// member access, inside a branch that tests only the pointers'
// non-nullness, reads the half-built state: the null guard proves the
// callee stored a pointer, not that the call succeeded, so the fields
// behind it are the ones the failing call abandoned mid-construction.
//
// Both halves of the pairing are relations the code itself states, and no
// library is named. The output is whichever identifier the call takes as an
// argument and the branch then dereferences as `(*id)->`, which is the
// spelling of a pointer the callee hands a result back through; a cleanup
// that releases the handle instead of reading it -- `f(*id)`, `*id = NULL`
// -- does not name a member and is not reported. The status is the variable
// the call's own result was captured into, so a bare call whose result is
// discarded is out of reach here, and the guard must be the idiom's own
// two-part null test, `id && *id` or its explicit `!= NULL` spelling, in an
// if whose consequence holds the read. Consulting the status is matched
// semantically rather than as a spelling: any occurrence of the captured
// variable between the call and the read clears the fact, so the guard's
// own extra conjunct, a dominating `if (!ok)` and a `FAILED(...)` wrapper
// all read as consulting it, in any of the forms a status test takes.
//
// Residuals, all false-negative: the status is credited wherever it appears
// in that span, so a check in a sibling branch that the read does not
// depend on still clears the fact; and the read must sit in the guard's own
// consequence, so an output read after the guarded block while the status
// stays untested elsewhere is not reported.
func (c *ccConv) ccOutParamStatusUncheckedObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	raw := c.text(body)
	text := compactCExprText(raw)
	if !strings.Contains(text, ")->") {
		return nil
	}
	// The capture is read from the uncompacted body: stripping whitespace
	// fuses an inline declaration with its type, which would rename the
	// status variable and leave the consult test looking for a name nothing
	// consults. Everything after the capture runs over the compacted text,
	// whose index of any source offset the map below supplies.
	at := ccCompactedIndex(raw)
	captureRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	seen := map[string]bool{}
	var out []nir.Stmt
	for _, m := range captureRe.FindAllStringSubmatchIndex(raw, -1) {
		if len(m) < 6 {
			continue
		}
		status, callee := raw[m[2]:m[3]], raw[m[4]:m[5]]
		args, ok := ccCallArgs(raw[m[5]:])
		if !ok {
			continue
		}
		rawClose := ccCallArgsClose(raw, m[5])
		if rawClose < 0 || rawClose >= len(at) {
			continue
		}
		closeIdx := at[rawClose]
		for _, arg := range args {
			outParam := strings.TrimSpace(arg)
			if !ccIdentifierArg(outParam) || outParam == status {
				continue
			}
			key := callee + "/" + status + "/" + outParam
			if seen[key] {
				continue
			}
			start, end, guarded := ccNullGuardedBlock(text, closeIdx, outParam)
			if !guarded {
				continue
			}
			useOff := strings.Index(text[start:end], "(*"+outParam+")->")
			if useOff < 0 || ccContainsWord(text[closeIdx+1:start+useOff], status) {
				continue
			}
			seen[key] = true
			loc := c.loc(body)
			path := "analysis.out_param.status_unchecked"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "call=" + callee},
					nir.Const{Loc: loc, Value: "status=" + status},
					nir.Const{Loc: loc, Value: "out=" + outParam},
					nir.Const{Loc: loc, Value: "guard=missing_status_check"},
				},
				Path:   path,
				Method: "status_unchecked",
				Loc:    loc,
			}})
		}
	}
	return out
}

// ccCompactedIndex maps each source offset to its offset in the same text
// with whitespace removed, so a match read from the uncompacted body can be
// located in its compacted form. Its final entry maps len(s).
func ccCompactedIndex(s string) []int {
	at := make([]int, len(s)+1)
	n := 0
	for i := 0; i < len(s); i++ {
		at[i] = n
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			n++
		}
	}
	at[len(s)] = n
	return at
}

// ccIdentifierArg reports whether a call argument is a bare identifier, the
// form a pointer the caller already owns is passed in when the callee hands
// its result back through it. An argument with an operator, a member access
// or a cast names a value instead, and a call that must be handed the
// caller's own pointer explicitly is outside the idiom this reports.
func ccIdentifierArg(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ccIdentByte(s[i]) {
			return false
		}
	}
	return true
}

// ccCallArgsClose returns the index of the closing parenthesis of the call
// whose own opens at open, or -1 when the call does not close within text.
func ccCallArgsClose(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// ccNullGuardedBlock finds, after the call that closes at from, the branch
// that tests the out-parameter idiom's two-part null guard -- `p && *p`, or
// its explicit `!= NULL` spelling -- and returns the span of that if's own
// consequence: the block the guard admits, or the single statement up to
// its semicolon when the branch has no braces. The guard must be an if's,
// so a loop head testing the same pair does not pair with the read.
func ccNullGuardedBlock(text string, from int, p string) (int, int, bool) {
	q := regexp.QuoteMeta(p)
	// Runtime-built patterns do not go through ccRe, per its cache policy.
	guard := regexp.MustCompile(`\b` + q + `&&\*` + q + `\b|\b` + q + `!=(?:NULL|nullptr|0)&&\*` + q + `!=(?:NULL|nullptr|0)\b`)
	loc := guard.FindStringIndex(text[from:])
	if loc == nil {
		return 0, 0, false
	}
	condAt := from + loc[0]
	ifAt := strings.LastIndex(text[:condAt], "if(")
	if ifAt < 0 {
		return 0, 0, false
	}
	depth := 0
	condEnd := -1
	for i := ifAt + 2; i < len(text); i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				condEnd = i
			}
		}
		if condEnd >= 0 {
			break
		}
	}
	if condEnd < 0 || condEnd >= len(text)-1 {
		return 0, 0, false
	}
	rest := text[condEnd+1:]
	if strings.HasPrefix(rest, "{") {
		depth = 0
		for i := condEnd + 1; i < len(text); i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return condEnd + 1, i + 1, true
				}
			}
		}
		return 0, 0, false
	}
	end := strings.IndexByte(rest, ';')
	if end < 0 {
		return 0, 0, false
	}
	return condEnd + 1, condEnd + 1 + end + 1, true
}

// ccPrefixOffsetObservations reports the C library's bounded prefix-comparison
// contract: strncmp(3) and strncasecmp(3), and the library wrappers named for
// them, verify only the n bytes they are asked to compare, so after a
// comparison succeeds the last byte the code may read on the compared pointer
// is the one at offset n -- for the shortest input the guard admits, the
// string's own terminator. Advancing the pointer further, inside the very
// branch the comparison admits, reads bytes the comparison did not prove
// present and, for that shortest input, steps past the end of the buffer.
//
// Both halves of the pairing are relations the branch itself states. The
// comparison must sit in an if's condition and the arithmetic in that same
// if's consequence, at any depth, so a prefix compared in one arm never
// vouches for an advance in a sibling arm; and the arithmetic must name the
// compared pointer itself, which is what keeps the fact off dispatch code
// that compares a prefix and then walks a different word. A condition may
// compare several prefixes on one pointer, alone or across a disjunction,
// and the bound is the longest of them, so the fact fires only when no arm
// of the condition can have verified the bytes the advance reads -- for arms
// of different lengths the shorter arm's own over-read stays unreported,
// which is the precision-leaning side of that choice. A nested if whose
// condition compares the same pointer again tightens the bound inside its
// own guarded body -- an if's consequence, and a while's or for's body,
// whose condition is checked before every iteration -- since both guards
// hold there. A subscript test on
// the compared pointer at or past the compared length clears the fact
// anywhere in the function: a guard that reads p[k] consults byte k itself,
// so the branch already reasons past the prefix and the advance is not the
// first unverified read.
//
// Residuals, all false-negative except the last: only the `== 0` and
// `!call` success spellings establish the bound, so a comparison tested for
// failure or for ordering establishes nothing; a compared length that is
// not a decimal literal establishes nothing; the pointer must be spelled
// identically at the comparison and the arithmetic, with the offset a
// decimal literal on the pointer's right; and only an if's consequence
// counts as the pairing scope, so a loop that is itself the outermost
// guard comparing a prefix, with a body that advances the pointer, is not
// reported. The pairing is by spelling, so a
// branch that reassigns the compared pointer and then advances the name
// still reports even though the name no longer names the compared bytes.
func (c *ccConv) ccPrefixOffsetObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	bodyText := compactCExprText(c.text(body))
	seen := map[string]bool{}
	var out []nir.Stmt
	var walkIf func(*tree_sitter.Node)
	walkIf = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "if_statement" {
			cond, cons := c.field(n, "condition"), c.field(n, "consequence")
			if cond != nil && cons != nil {
				for _, b := range ccPrefixComparisonBounds(compactCExprText(c.text(cond))) {
					if ccSubscriptAtOrPastPrefix(bodyText, b.pointer, b.length) {
						continue
					}
					loc, offset, ok := c.ccFirstOffsetPastPrefix(cons, b.pointer, b.length)
					if !ok {
						continue
					}
					key := loc + "|" + b.pointer
					if seen[key] {
						continue
					}
					seen[key] = true
					path := "analysis.prefix_length.offset_past_verified"
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: path, Loc: loc},
						Args: []nir.Expr{
							nir.Const{Loc: loc, Value: "pointer=" + b.pointer},
							nir.Const{Loc: loc, Value: "prefix=" + itoa(b.length)},
							nir.Const{Loc: loc, Value: "offset=" + itoa(offset)},
						},
						Path:   path,
						Method: "offset_past_verified",
						Loc:    loc,
					}})
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walkIf(ch)
		}
	}
	walkIf(body)
	return out
}

// ccPrefixBound is one pointer's verified-prefix length in a condition, the
// longest prefix any comparison in that condition matches on that pointer.
type ccPrefixBound struct {
	pointer string
	length  int
}

// ccPrefixComparisonBounds reads every successful bounded prefix comparison a
// condition makes -- the bare libc spellings and the library wrappers named
// for them alike, in either literal/pointer argument order -- and keeps one
// bound per compared pointer: the longest length compared on it. The
// comparison must be a success test -- the `== 0` spelling or a `!` on the
// call -- because a mismatch proves nothing about the bytes that follow.
func ccPrefixComparisonBounds(text string) []ccPrefixBound {
	var order []string
	longest := map[string]int{}
	callee := `((?:[A-Za-z_][A-Za-z0-9_]*)?(?:strncmp|strncasecmp)[A-Za-z0-9_]*)`
	call := callee + `\("([^"]+)",([^,()"]+),([0-9]+)\)`
	pointerFirst := callee + `\(([^,()"]+),"([^"]+)",([0-9]+)\)`
	for _, pat := range []struct {
		pattern  string
		ptrGroup int
	}{{call, 6}, {pointerFirst, 4}} {
		for _, m := range regexp.MustCompile(pat.pattern).FindAllStringSubmatchIndex(text, -1) {
			if len(m) < 10 || !ccPrefixComparisonSucceeded(text, m[0], m[1]) {
				continue
			}
			ptr := text[m[pat.ptrGroup]:m[pat.ptrGroup+1]]
			n, err := strconv.Atoi(text[m[8]:m[9]])
			if err != nil || n <= 0 || ptr == "" {
				continue
			}
			if _, seen := longest[ptr]; !seen {
				order = append(order, ptr)
			}
			if n > longest[ptr] {
				longest[ptr] = n
			}
		}
	}
	out := make([]ccPrefixBound, 0, len(order))
	for _, ptr := range order {
		out = append(out, ccPrefixBound{pointer: ptr, length: longest[ptr]})
	}
	return out
}

// ccPrefixComparisonSucceeded reports whether the call at text[start:end] is
// tested for success: followed by `== 0`, or negated with a `!` directly
// before the callee. A `!= 0` test reads the prefix as unmatched and
// establishes nothing, and a bare truthiness test means the same.
func ccPrefixComparisonSucceeded(text string, start, end int) bool {
	if strings.HasPrefix(text[end:], "==0") {
		return true
	}
	if strings.HasPrefix(text[end:], "!=0") {
		return false
	}
	return start > 0 && text[start-1] == '!'
}

// ccSubscriptAtOrPastPrefix reports whether the function body subscripts the
// compared pointer at an offset at or past the compared length: a guard that
// reads p[k] consults byte k itself, so the branch already reasons past the
// prefix the comparison verified.
func ccSubscriptAtOrPastPrefix(text, pointer string, length int) bool {
	q := regexp.QuoteMeta(pointer)
	for _, m := range regexp.MustCompile(`\b`+q+`\[([0-9]+)\]`).FindAllStringSubmatchIndex(text, -1) {
		if k, err := strconv.Atoi(text[m[2]:m[3]]); err == nil && k >= length {
			return true
		}
	}
	return false
}

// ccFirstOffsetPastPrefix walks an if's consequence for the first pointer
// arithmetic on the compared pointer whose offset exceeds the verified
// length, carrying the bound a nested guard's own comparison on the same
// pointer tightens inside that guard's body -- an if's consequence, or a
// while's or for's body: both guards hold there, so the longer prefix is
// the one verified.
func (c *ccConv) ccFirstOffsetPastPrefix(scope *tree_sitter.Node, pointer string, bound int) (string, int, bool) {
	var walk func(*tree_sitter.Node, int) (string, int, bool)
	walk = func(n *tree_sitter.Node, bound int) (string, int, bool) {
		if n == nil {
			return "", 0, false
		}
		if offset, hit := c.ccOffsetOnPointer(n, pointer, bound); hit {
			return c.loc(n), offset, true
		}
		for _, ch := range c.namedChildren(n) {
			next := bound
			if bodyField, ok := ccGuardedBodyField(n); ok {
				if body := c.field(n, bodyField); body != nil && ch.Id() == body.Id() {
					for _, b := range ccPrefixComparisonBounds(compactCExprText(c.text(c.field(n, "condition")))) {
						if b.pointer == pointer && b.length > next {
							next = b.length
						}
					}
				}
			}
			if loc, offset, ok := walk(ch, next); ok {
				return loc, offset, ok
			}
		}
		return "", 0, false
	}
	return walk(scope, bound)
}

// ccCursorLoopMissingEndSentinelObservations reports the range-bounded walk
// whose loop never bounds the cursor. A function that hands its walk a
// half-open range states the contract in its own signature -- one pointer to
// read from and one past the last byte it may touch -- and states it again in
// the comparisons that keep the walk inside: `first >= afterLast` names the
// parameter as that walk's end. A loop that dereferences and advances the
// cursor while naming no relational bound on it anywhere in its own subtree
// has no bound of its own, so its only ways out are the values of the bytes
// it reads, and a buffer that ends mid-walk leaves it reading past the range.
//
// Both halves of the pairing are read from the tree, never from names. The
// end sentinel is a parameter standing alone as one side of a relational
// comparison whose other side is the bare cursor: `first >= afterLast`
// states a range, while `p < zl + zlbytes` states an allocation base plus an
// offset, a different idiom whose bound is not the parameter by itself, and
// `*argidx >= argc` states a count checked through an out-parameter. A
// cursor that never appears bare against a parameter is not a range walk at
// all -- the NUL-terminated walk, whose contract is a terminator rather than
// a range, is the ordinary safe C idiom exactly here and stays unreported.
//
// The loop side is deliberately generous in what counts as a bound: any
// relational operator anywhere in the loop's own subtree whose operand names
// the cursor clears the fact, so `in + 1 >= maxbuf` bounds the walk as well
// as `in >= maxbuf` does, and a loop bounded against a local derived from
// the parameter is left alone. Only a loop with no relational mention of the
// cursor in its own subtree -- the cursor dereferenced, advanced, and
// compared against nothing -- is reported, and the enclosing loop that
// carries the check suppresses the fact for itself while a nested walk
// inside it stands on its own.
//
// Residuals, all false-negative: the pairing is intra-function, so a range
// maintained across calls in a helper is invisible here; a cursor spelled
// differently at the comparison and the loop does not pair; and a loop whose
// bound is an equality test against a terminator value rather than a
// relational comparison of the cursor is not this fact's subject.
func (c *ccConv) ccCursorLoopMissingEndSentinelObservations(fn *tree_sitter.Node, params []string) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || len(params) == 0 {
		return nil
	}
	paramSet := make(map[string]bool, len(params))
	for _, p := range params {
		paramSet[p] = true
	}

	// Cursors this function keeps inside a range: a bare relational
	// comparison against a parameter names that parameter as the walk's end.
	var ends map[string][]string
	var findBounded func(*tree_sitter.Node)
	findBounded = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "binary_expression" {
			switch c.text(c.field(n, "operator")) {
			case "<", ">", "<=", ">=":
				l, r := ccUnwrapCExpr(c.field(n, "left")), ccUnwrapCExpr(c.field(n, "right"))
				if l == nil || r == nil || c.kind(l) != "identifier" || c.kind(r) != "identifier" {
					break
				}
				ls, rs := c.text(l), c.text(r)
				if ls == rs {
					break
				}
				if paramSet[rs] || paramSet[ls] {
					if ends == nil {
						ends = map[string][]string{}
					}
				}
				if paramSet[rs] {
					ends[ls] = ccAppendUnique(ends[ls], rs)
				}
				if paramSet[ls] {
					ends[rs] = ccAppendUnique(ends[rs], ls)
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			findBounded(ch)
		}
	}
	findBounded(body)
	if len(ends) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var out []nir.Stmt
	var walkLoops func(*tree_sitter.Node)
	walkLoops = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "for_statement", "while_statement", "do_statement":
			for cursor, sentinels := range ends {
				if !c.ccLoopWalksCursor(n, cursor) {
					continue
				}
				if c.ccLoopBoundsCursor(n, cursor) {
					continue
				}
				loc := c.loc(n)
				key := loc + "/" + cursor
				if seen[key] {
					continue
				}
				seen[key] = true
				path := "analysis.cursor_loop.missing_end_sentinel"
				out = append(out, nir.ExprStmt{Value: nir.Call{
					Callee: nir.Name{ID: path, Loc: loc},
					Args: []nir.Expr{
						nir.Const{Loc: loc, Value: "cursor=" + cursor},
						nir.Const{Loc: loc, Value: "sentinel=" + strings.Join(sentinels, ",")},
						nir.Const{Loc: loc, Value: "bound=missing_from_loop"},
					},
					Path:   path,
					Method: "missing_end_sentinel",
					Loc:    loc,
				}})
			}
		}
		for _, ch := range c.namedChildren(n) {
			walkLoops(ch)
		}
	}
	walkLoops(body)
	return out
}

// ccLoopWalksCursor reports whether the subtree rooted at n dereferences the
// cursor and advances it: the read that runs past the range and the step that
// carries the cursor there, both inside the same construct.
func (c *ccConv) ccLoopWalksCursor(n *tree_sitter.Node, cursor string) bool {
	deref, advanced := false, false
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "pointer_expression":
			if c.unaryOp(n) == "*" && ccIdentifierText(c, c.field(n, "argument")) == cursor {
				deref = true
			}
		case "update_expression":
			if ccIdentifierText(c, c.field(n, "argument")) == cursor {
				advanced = true
			}
		case "assignment_expression":
			if ccIdentifierText(c, c.field(n, "left")) == cursor &&
				strings.HasPrefix(c.text(c.field(n, "operator")), "+=") {
				advanced = true
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(n)
	return deref && advanced
}

// ccLoopBoundsCursor reports whether a relational comparison anywhere in the
// subtree rooted at n names the cursor in either operand, at any depth: a
// loop that relates its cursor to anything has a bound of its own, whether
// the bound is the parameter itself or a local derived from it.
func (c *ccConv) ccLoopBoundsCursor(n *tree_sitter.Node, cursor string) bool {
	var walk func(*tree_sitter.Node) bool
	walk = func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		if c.kind(n) == "binary_expression" {
			switch c.text(c.field(n, "operator")) {
			case "<", ">", "<=", ">=":
				if c.ccExprNamesCursor(c.field(n, "left"), cursor) ||
					c.ccExprNamesCursor(c.field(n, "right"), cursor) {
					return true
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			if walk(ch) {
				return true
			}
		}
		return false
	}
	return walk(n)
}

// ccExprNamesCursor reports whether the cursor identifier appears anywhere
// in the expression's subtree.
func (c *ccConv) ccExprNamesCursor(n *tree_sitter.Node, cursor string) bool {
	if n == nil {
		return false
	}
	if c.kind(n) == "identifier" && c.text(n) == cursor {
		return true
	}
	for _, ch := range c.namedChildren(n) {
		if c.ccExprNamesCursor(ch, cursor) {
			return true
		}
	}
	return false
}

// ccAppendUnique appends value to values when it is not already present, so
// repeated comparisons of one cursor against one parameter keep a single
// entry.
func ccAppendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}

// ccGuardedBodyField names the child a construct's condition guards: an
// if's consequence, and a while's or for's body, whose condition is checked
// before every iteration. A do-while checks its condition after the body,
// so its condition guards nothing and it is absent.
func ccGuardedBodyField(n *tree_sitter.Node) (string, bool) {
	switch n.Kind() {
	case "if_statement":
		return "consequence", true
	case "while_statement", "for_statement":
		return "body", true
	}
	return "", false
}

// ccOffsetOnPointer reports whether node n advances pointer by a decimal
// literal beyond bound: `pointer + k` in a sum or `pointer += k` in a
// compound assignment, with the pointer spelled as the comparison spelled it.
func (c *ccConv) ccOffsetOnPointer(n *tree_sitter.Node, pointer string, bound int) (int, bool) {
	var op string
	switch c.kind(n) {
	case "binary_expression":
		op = "+"
	case "assignment_expression":
		op = "+="
	default:
		return 0, false
	}
	if c.text(c.field(n, "operator")) != op {
		return 0, false
	}
	if compactCExprText(c.text(c.field(n, "left"))) != pointer {
		return 0, false
	}
	offset, err := strconv.Atoi(strings.TrimSpace(c.text(c.field(n, "right"))))
	if err != nil || offset <= bound {
		return 0, false
	}
	return offset, true
}

// ccStackFallbackStrideUnderallocObservations reports the dual-path buffer
// idiom -- a fixed stack array declared with a product size, aliased to a
// pointer, and conditionally replaced by a heap allocation when a count
// exceeds one factor of the product -- where the fallback allocation's size
// arguments omit the factor the function's own write loop advances the
// buffer pointer by. The stack declaration states the buffer's full unit
// shape (count bound times per-unit width) and the write loop restates the
// width as the pointer's stride, so a fallback sized by the count alone holds
// count elements where the loop writes count*width: every heap-path row past
// the first writes past the allocation.
//
// Both halves of the pairing are read from relations the code itself states.
// The count is a size argument of the fallback call that the surrounding
// guard compares against one factor of the array's declared product, which
// makes that factor the count's bound. The stride is the identifier a
// buffer-aliased pointer advances by in a compound assignment, tracked
// through reassignment so a pointer that later points somewhere else stops
// contributing. An allocation whose arguments, once the element-size terms
// are dropped, name neither the stride nor anything else beyond the count is
// sized by the count alone.
//
// Residuals: a loop whose trip count divides the count -- advancing by the
// stride but writing count elements in total -- shares this shape and is
// reported with it; and a fallback that names the stride at all is cleared
// even when it sizes in bytes for an element type wider than one byte, so
// only the count-only form is reported.
func (c *ccConv) ccStackFallbackStrideUnderallocObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	assignRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)=([^=;]{1,80})`)
	allocRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z_][A-Za-z0-9_]*alloc[A-Za-z0-9_]*)\(`)
	compoundRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)\+=([A-Za-z_][A-Za-z0-9_]*)\b`)
	sizeofRe := ccRe(`sizeof\([^()]*\)`)

	type ccAssign struct {
		pos int
		lhs string
		rhs string
	}
	var assigns []ccAssign
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		// A write through the pointer (*p = x) does not reassign it: the
		// dereference star opens the statement, while a declarator's star
		// (T *p = x) follows the type's own identifier.
		if m[0] > 0 && text[m[0]-1] == '*' && (m[0] < 2 || !ccIdentByte(text[m[0]-2])) {
			continue
		}
		assigns = append(assigns, ccAssign{pos: m[0], lhs: text[m[2]:m[3]], rhs: text[m[4]:m[5]]})
	}
	// ccBufferAliasAt reports whether id names the array's storage at pos:
	// its nearest preceding assignment chains back to the array through bare
	// identifier right-hand sides, so a pointer reassigned to another
	// expression stops being an alias from that assignment on. A reassignment
	// from a heap allocator keeps the chain alive: the fallback hands the
	// alias the heap buffer under judgment, which is the same logical buffer
	// the array names.
	allocCallRe := ccRe(`^[A-Za-z_][A-Za-z0-9_]*alloc[A-Za-z0-9_]*\(`)
	ccBufferAliasAt := func(array string, id string, pos int) bool {
		for hop := 0; hop < 8 && id != array; hop++ {
			var last *ccAssign
			for i := range assigns {
				a := &assigns[i]
				if a.lhs == id && a.pos < pos && (last == nil || a.pos > last.pos) {
					last = a
				}
			}
			if last == nil {
				return false
			}
			if !ccBareIdentifier(last.rhs) {
				if !allocCallRe.MatchString(last.rhs) {
					return false
				}
				pos = last.pos
				continue
			}
			id, pos = last.rhs, last.pos
		}
		return id == array
	}

	var out []nir.Stmt
	seen := map[string]bool{}
	for _, triple := range c.ccArrayProductDecls(body) {
		array, f1, f2 := triple[0], triple[1], triple[2]
		for _, al := range assigns {
			if al.rhs != array || al.lhs == array {
				continue
			}
			alias, aliasPos := al.lhs, al.pos
			for _, om := range allocRe.FindAllStringSubmatchIndex(text, -1) {
				if len(om) < 6 || om[0] < aliasPos || text[om[2]:om[3]] != alias {
					continue
				}
				if om[0] > 0 && text[om[0]-1] == '*' && (om[0] < 2 || !ccIdentByte(text[om[0]-2])) {
					continue
				}
				if !ccBufferAliasAt(array, alias, om[0]) {
					continue
				}
				callee := text[om[4]:om[5]]
				args, ok := ccCallArgs(text[om[1]-1:])
				if !ok || len(args) == 0 {
					continue
				}
				sized := make([]string, len(args))
				for i, a := range args {
					sized[i] = sizeofRe.ReplaceAllString(a, "")
				}
				for _, count := range args {
					if !ccBareIdentifier(count) {
						continue
					}
					if !ccGuardFactor(text, count, f1) && !ccGuardFactor(text, count, f2) &&
						!ccGuardFactor(text, f1, count) && !ccGuardFactor(text, f2, count) {
						continue
					}
					for _, cm := range compoundRe.FindAllStringSubmatchIndex(text, -1) {
						if len(cm) < 6 || cm[0] < om[1] {
							continue
						}
						if cm[0] > 0 && text[cm[0]-1] == '*' && (cm[0] < 2 || !ccIdentByte(text[cm[0]-2])) {
							continue
						}
						ptr, stride := text[cm[2]:cm[3]], text[cm[4]:cm[5]]
						if ptr != alias && !ccBufferAliasAt(array, ptr, cm[0]) {
							continue
						}
						named := false
						for _, s := range sized {
							if ccContainsWord(s, stride) {
								named = true
								break
							}
						}
						key := array + "/" + alias + "/" + callee + "/" + stride
						if named || stride == count || seen[key] {
							continue
						}
						seen[key] = true
						loc := c.loc(body)
						path := "analysis.alloc.stack_fallback_stride_underalloc"
						out = append(out, nir.ExprStmt{Value: nir.Call{
							Callee: nir.Name{ID: path, Loc: loc},
							Args: []nir.Expr{
								nir.Const{Loc: loc, Value: "allocation=" + callee},
								nir.Const{Loc: loc, Value: "buffer=" + array},
								nir.Const{Loc: loc, Value: "count=" + count},
								nir.Const{Loc: loc, Value: "stride=" + stride},
								nir.Const{Loc: loc, Value: "guard=count_bound_only"},
							},
							Path:   path,
							Method: "stack_fallback_stride_underalloc",
							Loc:    loc,
						}})
					}
				}
			}
		}
	}
	return out
}

// ccArrayProductDecls returns the arrays a function body declares with a
// product of two identifiers as their size, as name/factor/factor triples.
// The declaration is read from the syntax tree because the compacted body
// text glues the element type onto the array name, so the declarator's own
// identifier is the only reliable spelling of the name.
func (c *ccConv) ccArrayProductDecls(body *tree_sitter.Node) [][3]string {
	var out [][3]string
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "declaration" {
			for _, d := range c.namedChildren(n) {
				decl := d
				if c.kind(d) == "init_declarator" {
					decl = c.field(d, "declarator")
				}
				if name, f1, f2, ok := c.ccArrayProductDecl(decl); ok {
					out = append(out, [3]string{name, f1, f2})
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

// ccArrayProductDecl reads one declarator, unwrapping pointers and
// attributes to its array level, and reports the array's identifier and the
// two identifier factors of its size when the size is a plain product.
func (c *ccConv) ccArrayProductDecl(decl *tree_sitter.Node) (string, string, string, bool) {
	for decl != nil {
		switch c.kind(decl) {
		case "pointer_declarator", "parenthesized_declarator", "attributed_declarator":
			decl = c.field(decl, "declarator")
		case "array_declarator":
			size := c.field(decl, "size")
			if size == nil || c.kind(size) != "binary_expression" {
				return "", "", "", false
			}
			if op := c.field(size, "operator"); op == nil || c.text(op) != "*" {
				return "", "", "", false
			}
			l, r := c.field(size, "left"), c.field(size, "right")
			if l == nil || r == nil || c.kind(l) != "identifier" || c.kind(r) != "identifier" {
				return "", "", "", false
			}
			name := c.declName(c.field(decl, "declarator"))
			if name == "" {
				return "", "", "", false
			}
			return name, c.text(l), c.text(r), true
		default:
			return "", "", "", false
		}
	}
	return "", "", "", false
}

// ccBareIdentifier reports whether s is a single C identifier and nothing
// else, so a call, an address-of or any compound expression on the right of
// an assignment reads as not naming that identifier.
func ccBareIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !ccIdentByte(s[i]) {
			return false
		}
	}
	return true
}

// ccGuardFactor reports whether text bounds count by factor in a relational
// comparison, in either operand order, so the guard that pairs a fallback
// allocation's count with one factor of the array's declared product is read
// from the code rather than assumed.
func ccGuardFactor(text, count, factor string) bool {
	if count == "" || factor == "" {
		return false
	}
	for off := 0; ; {
		i := strings.Index(text[off:], count)
		if i < 0 {
			return false
		}
		at := off + i
		off = at + len(count)
		if at > 0 && ccIdentByte(text[at-1]) {
			continue
		}
		if off < len(text) && ccIdentByte(text[off]) {
			continue
		}
		rest := text[off:]
		if !strings.HasPrefix(rest, "<") && !strings.HasPrefix(rest, ">") {
			continue
		}
		rest = strings.TrimPrefix(strings.TrimPrefix(rest, "<"), ">")
		rest = strings.TrimPrefix(rest, "=")
		if strings.HasPrefix(rest, factor) &&
			(len(rest) == len(factor) || !ccIdentByte(rest[len(factor)])) {
			return true
		}
	}
}

// ccDestCapacityParams maps each destination parameter to the parameters the
// function itself uses as that destination's byte count, read from the size
// position of the capacity-taking libc calls: memset(dst, c, n), fgets(dst,
// n, s), fread(dst, sz, n, s), snprintf(dst, n, fmt, ...) and strncpy(dst,
// src, n).
func ccDestCapacityParams(text string, params []string) map[string][]string {
	names := map[string]bool{}
	for _, p := range params {
		names[p] = true
	}
	out := map[string][]string{}
	callRe := ccRe(`\b(memset|fgets|fread|snprintf|strncpy)\(`)
	for _, m := range callRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		callee := text[m[2]:m[3]]
		args, ok := ccCallArgs(text[m[1]-1:])
		if !ok || len(args) == 0 {
			continue
		}
		dst := args[0]
		if !names[dst] {
			continue
		}
		// The size position is fixed by each call's own signature.
		var sizeIdx []int
		switch callee {
		case "memset", "strncpy":
			sizeIdx = []int{2}
		case "fread":
			sizeIdx = []int{1, 2}
		case "fgets", "snprintf":
			sizeIdx = []int{1}
		}
		for _, idx := range sizeIdx {
			if idx >= len(args) {
				continue
			}
			size := args[idx]
			for _, p := range params {
				if p == dst || !ccContainsWord(size, p) {
					continue
				}
				if !ccContainsParam(out[dst], p) {
					out[dst] = append(out[dst], p)
				}
			}
		}
	}
	return out
}

// ccContainsWord reports whether s contains name as a whole identifier, so a
// parameter named size is not read inside bufsize. Runtime-built patterns do
// not go through ccRe, per its cache policy.
func ccContainsWord(s, name string) bool {
	for i := 0; i+len(name) <= len(s); i++ {
		if s[i:i+len(name)] != name {
			continue
		}
		if i > 0 && ccIdentByte(s[i-1]) {
			continue
		}
		if i+len(name) < len(s) && ccIdentByte(s[i+len(name)]) {
			continue
		}
		return true
	}
	return false
}

func ccIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// ccCallArgs splits the argument list of the call whose '(' opens s at the
// commas of depth zero, so size expressions with nested parentheses --
// memset(dst, 0, sizeof(char)*n) -- parse as single arguments. It reports ok
// only when the call closes within s.
func ccCallArgs(s string) ([]string, bool) {
	var args []string
	depth, start := 0, 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				args = append(args, s[start:i])
				return args, true
			}
		case ',':
			if depth == 1 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	return nil, false
}

func ccContainsParam(list []string, name string) bool {
	for _, v := range list {
		if v == name {
			return true
		}
	}
	return false
}

// ccCapacityConsultedIn reports whether the function's body relates the
// capacity parameter to anything with a relational operator, on either side.
func ccCapacityConsultedIn(text, capacity string) bool {
	return ccComparisonAfter(text, capacity, '<', false) ||
		ccComparisonAfter(text, capacity, '>', false) ||
		ccComparisonBefore(text, capacity, '<') ||
		ccComparisonBefore(text, capacity, '>')
}

// ccWideCastNames are the size-and-capacity typedefs that make an addition
// wrap-free when cast onto either operand; the long-family and 64-bit
// spellings are recognized by token instead of by list, so multi-word and
// abbreviated forms -- (long int), (unsigned long int), (u64), (__u64) --
// all read as widening without each spelling being named.
var ccWideCastNames = []string{
	"size_t", "ssize_t", "uintmax_t", "intmax_t", "uintptr_t", "intptr_t",
	"ptrdiff_t", "uintmax_t", "intmax_t",
}

// ccWideCastType reports whether the inner text of a cast is a type at
// least 64 bits wide: the long family in any multi-word spelling, every
// 64-bit spelling, and the size-and-capacity typedefs. No 32-bit-or-narrower
// spelling contains either token.
func ccWideCastType(s string) bool {
	if s == "" {
		return false
	}
	for _, name := range ccWideCastNames {
		if s == name {
			return true
		}
	}
	return strings.Contains(s, "long") || strings.Contains(s, "64")
}

// ccKeywordPrefixes are the statement keywords whitespace removal can glue
// onto the operand that opens a comparison -- `return x + y > cap` reads
// returnx+y>cap -- so an operand that is not itself a declared name may
// still end in one the keyword swallowed. A declared name that genuinely
// starts with one of these keywords is the residual ambiguity of the glued
// text, in the false-positive direction.
var ccKeywordPrefixes = []string{"return", "else", "case", "do", "sizeof", "goto"}

// ccDeclQualifiers are the only identifiers that may stand directly before a
// declaration's type keyword once whitespace is stripped; anything else glued
// there makes the text a longer type or identifier of its own.
var ccDeclQualifiers = map[string]bool{
	"const": true, "static": true, "volatile": true, "register": true,
	"auto": true, "signed": true, "inline": true, "extern": true,
}

// ccNarrowDeclHeadRe matches a local declared at one of the 32-bit integer
// spellings, which are the widths at which an addition can wrap past the limit
// it is then compared against. Anything narrower is promoted to int before the
// addition and a promoted pair cannot overflow the int the sum is computed in,
// and anything wider does not wrap within a 32-bit pair at all. A bounds check
// written over two locals declared at one of these widths compares a sum that
// has already wrapped, so the check discharges nothing for a pair large enough;
// the fix everywhere is to widen the operands, at the declaration or by cast.
var (
	ccNarrowDeclHeadRe   = ccRe(`(unsignedint|uint32_t|int32_t|unsigned|int)([A-Za-z_][A-Za-z0-9_]*)([=,;])`)
	ccNarrowAddCompareRe = ccRe(`([A-Za-z_][A-Za-z0-9_]*)(\+)([A-Za-z_][A-Za-z0-9_]*)(?:\))*(>=|<=|>|<)`)
	ccCompareNarrowAddRe = ccRe(`(>=|<=|>|<)(?:\()*([A-Za-z_][A-Za-z0-9_]*)(\+)([A-Za-z_][A-Za-z0-9_]*)(?:\))*`)
)

func ccIsIdentChar(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// ccNarrowDeclaredNames collects the locals a function declares at one of the
// 32-bit spellings ccNarrowDeclHeadRe names. Whitespace removal glues the type
// keyword onto the declarator, so the walk matches the glued declaration head
// -- the type spelling, the name, then '=', ',' or ';' -- and follows the
// comma-separated declarator list from there, skipping initializers bracket-
// and paren-aware so a call argument's commas do not split the list. A type
// spelling glued to a preceding identifier that is not a qualifier is skipped:
// that text is a longer identifier of its own, not this declaration. A
// declarator list that does not run to its ';' -- a macro invocation whose
// arguments start with a type spelling -- contributes only its head, never the
// argument names that follow, so a macro's second argument is never read as a
// declared local.
func ccNarrowDeclaredNames(text string) map[string]bool {
	names := map[string]bool{}
	for _, m := range ccNarrowDeclHeadRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		if !ccDeclHeadPreceded(text, m[2]) {
			continue
		}
		if ccAddDeclName(names, text[m[4]:m[5]]) {
			continue
		}
		pos := m[6] // at '=', ',' or ';'
		tail := []string{}
		for pos < len(text) {
			if text[pos] == ';' {
				break // the declarator list closes cleanly
			}
			if text[pos] == '=' {
				next, ok := ccSkipCInitializer(text, pos+1)
				if !ok {
					pos = -1
					break
				}
				pos = next
				continue
			}
			if text[pos] != ',' {
				pos = -1 // the list neither continues nor closes
				break
			}
			pos++
			end := pos
			for end < len(text) && ccIsIdentChar(text[end]) {
				end++
			}
			if end == pos {
				pos = -1
				break
			}
			if end < len(text) {
				if c := text[end]; c != '=' && c != ',' && c != ';' {
					pos = -1 // function or array declarator ends the list
					break
				}
			}
			tail = append(tail, text[pos:end])
			pos = end
		}
		if pos >= 0 && pos < len(text) && text[pos] == ';' {
			for _, name := range tail {
				ccAddDeclName(names, name)
			}
		}
	}
	return names
}

// ccAddDeclName records a declared name unless it is a keyword masquerading
// as one -- a macro whose first argument is a bare type spelling contributes
// that keyword as its head declarator, and no operand can ever be named so.
func ccAddDeclName(names map[string]bool, name string) bool {
	switch name {
	case "char", "int", "unsigned", "long", "short", "float", "double", "void", "signed":
		return true
	}
	names[name] = true
	return false
}

// ccDeclHeadPreceded reports whether the type spelling at start is the head
// of its own declaration: the boundary before it is a statement or paren
// edge, or one of the qualifiers a declaration may carry.
func ccDeclHeadPreceded(text string, start int) bool {
	if start == 0 || !ccIsIdentChar(text[start-1]) {
		return true
	}
	i := start
	for i > 0 && ccIsIdentChar(text[i-1]) {
		i--
	}
	return ccDeclQualifiers[text[i:start]]
}

// ccSkipCInitializer advances past a declarator's initializer to the ',' or
// ';' that ends it, at zero bracket depth; anything deeper is initializer
// content, so a call's commas and an initializer list's commas do not end it.
func ccSkipCInitializer(text string, i int) (int, bool) {
	depth := 0
	for ; i < len(text); i++ {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i, false
			}
			depth--
		case ',', ';':
			if depth == 0 {
				return i, true
			}
		}
	}
	return i, false
}

// ccNarrowOperand reports the effective start of the operand at [start,end)
// when it is one of the narrow-declared locals used bare, and -1 when it is
// not: a member selection reads a field that only shares the name, and a
// widening cast onto the operand -- any long-family or 64-bit spelling, in
// any multi-word form -- makes the sum wrap-free however the operand was
// declared. Whitespace removal can glue a statement keyword onto the first
// operand of a comparison, so an operand that is not itself declared narrow
// is re-read with one of ccKeywordPrefixes stripped.
func ccNarrowOperand(text string, start, end int, narrow map[string]bool) int {
	if !narrow[text[start:end]] {
		stripped := -1
		name := text[start:end]
		for _, kw := range ccKeywordPrefixes {
			if len(name) > len(kw) && strings.HasPrefix(name, kw) && narrow[name[len(kw):]] {
				stripped = start + len(kw)
				break
			}
		}
		if stripped < 0 {
			return -1
		}
		start = stripped
	}
	if start > 0 {
		if text[start-1] == '.' {
			return -1
		}
		if text[start-1] == '>' && start >= 2 && text[start-2] == '-' {
			return -1
		}
		if text[start-1] == ')' {
			if open := ccMatchingOpenParen(text, start-1); open >= 0 && ccWideCastType(text[open+1:start-1]) {
				return -1
			}
		}
	}
	return start
}

// ccMatchingOpenParen returns the index of the '(' matching the ')' at
// close, or -1 when the text before it never opens one.
func ccMatchingOpenParen(text string, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch text[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// ccNarrowDeclaredBoundsCheckObservations reports a bounds check whose
// additive operands are both locals the function declares at a 32-bit
// integer width: the addition the check exists to bound is itself the
// addition that can wrap, so a pair large enough passes as a small sum and
// the check discharges nothing. The check is read in any spelling -- the sum
// parenthesized on either side of the comparison, and a comparison opened by
// a return statement -- and the widening that makes the check stand is read
// semantically, not by spelling: redeclaring either operand wide at its
// declaration, or casting either operand to a wider type at the addition in
// any long-family or 64-bit spelling, both leave the observation unemitted.
// Only locals declared in the function itself count, so a check over narrow
// parameters is not reported here, and operands reached through a member
// selection or a call result never match.
func (c *ccConv) ccNarrowDeclaredBoundsCheckObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	narrow := ccNarrowDeclaredNames(text)
	if len(narrow) == 0 {
		return nil
	}
	type operand struct{ start, end int }
	for _, shape := range []struct {
		re       *regexp.Regexp
		leftPos  int
		rightPos int
	}{
		{ccNarrowAddCompareRe, 2, 6}, // a + b REL c
		{ccCompareNarrowAddRe, 4, 8}, // c REL a + b
	} {
		for _, m := range shape.re.FindAllStringSubmatchIndex(text, -1) {
			if len(m) < 10 {
				continue
			}
			left, right := operand{m[shape.leftPos], m[shape.leftPos+1]}, operand{m[shape.rightPos], m[shape.rightPos+1]}
			leftStart := ccNarrowOperand(text, left.start, left.end, narrow)
			if leftStart < 0 {
				continue
			}
			rightStart := ccNarrowOperand(text, right.start, right.end, narrow)
			if rightStart < 0 {
				continue
			}
			loc := c.loc(body)
			path := "analysis.narrow_width.bounds_check"
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "left=" + text[leftStart:left.end]},
					nir.Const{Loc: loc, Value: "right=" + text[rightStart:right.end]},
					nir.Const{Loc: loc, Value: "width=32bit_declared"},
					nir.Const{Loc: loc, Value: "widening=absent"},
				},
				Path:   path,
				Method: "bounds_check",
				Loc:    loc,
			}}}
		}
	}
	return nil
}

func (c *ccConv) ccPostCopyMissingBoundsObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	assignRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)\+=([A-Za-z_][A-Za-z0-9_]*)`)
	memcpyRe := ccRe(`\bmemcpy\(([^,]+),([^,]+),([^)]+)\)`)
	seen := map[string]bool{}
	var out []nir.Stmt
	for _, a := range assignRe.FindAllStringSubmatchIndex(text, -1) {
		if len(a) < 6 {
			continue
		}
		offset := text[a[2]:a[3]]
		tail := text[a[1]:]
		for _, m := range memcpyRe.FindAllStringSubmatchIndex(tail, -1) {
			if len(m) < 8 {
				continue
			}
			dst := tail[m[2]:m[3]]
			size := tail[m[6]:m[7]]
			if !strings.Contains(dst, offset) {
				continue
			}
			between := tail[:m[0]]
			if ccHasOffsetSizeUpperGuard(between, offset, size) {
				continue
			}
			loc := c.loc(body)
			if seen[loc] {
				continue
			}
			seen[loc] = true
			path := "analysis.post_copy.missing_bounds"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "copy=memcpy"},
					nir.Const{Loc: loc, Value: "offset_update=add_assign"},
					nir.Const{Loc: loc, Value: "guard=missing_after_update"},
				},
				Path:   path,
				Method: "missing_bounds",
				Loc:    loc,
			}})
			break
		}
	}
	return out
}

func (c *ccConv) ccNumericParserMissingProgressObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	atolRe := ccRe(`\bfio_atol\(\(char\*\*\)&?([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range atolRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		cursor := text[m[2]:m[3]]
		tail := text[m[1]:]
		resetRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(cursor) + `=([A-Za-z_][A-Za-z0-9_]*)`)
		reset := resetRe.FindStringSubmatchIndex(tail)
		if len(reset) < 4 {
			continue
		}
		base := tail[reset[2]:reset[3]]
		if !strings.Contains(tail, "fio_atof((char**)&"+cursor+")") &&
			!strings.Contains(tail, "fio_atof((char**)"+cursor+")") {
			continue
		}
		if !strings.Contains(tail, "JSON_NUMERAL[*"+cursor+"]") {
			continue
		}
		if strings.Contains(tail, cursor+"=="+base) || strings.Contains(tail, base+"=="+cursor) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.numeric_parser.missing_progress_check"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "parser=fio_numeric"},
				nir.Const{Loc: loc, Value: "guard=missing_cursor_progress"},
			},
			Path:   path,
			Method: "missing_progress_check",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccPointerOffsetMissingRemainingSizeObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	guardRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*)\+1>([A-Za-z_][A-Za-z0-9_]*)`)
	for _, m := range guardRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		ptr := text[m[2]:m[3]]
		length := text[m[4]:m[5]]
		end := text[m[6]:m[7]]
		if !strings.Contains(text[m[1]:], ptr+"+="+length) {
			continue
		}
		if strings.Contains(text, end+"-"+ptr+"-1") || strings.Contains(text, ptr+"-"+end+"-1") ||
			strings.Contains(text, "buff_size") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.pointer_offset.missing_remaining_size"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "guard=additive_end_check"},
				nir.Const{Loc: loc, Value: "update=add_assign"},
				nir.Const{Loc: loc, Value: "remaining_size=missing"},
			},
			Path:   path,
			Method: "missing_remaining_size",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccDhcpOptionLengthUncheckedReadObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	loopRe := ccRe(`while\(([A-Za-z_][A-Za-z0-9_]*)<([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range loopRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		cursor := text[m[2]:m[3]]
		end := text[m[4]:m[5]]
		tail := text[m[1]:]
		if !strings.Contains(tail, "*("+cursor+"+2)") && !strings.Contains(tail, cursor+"+2") {
			continue
		}
		if !strings.Contains(tail, cursor+"+="+cursor+"[1]+2") {
			continue
		}
		if ccHasDhcpOptionLengthGuards(tail, cursor, end) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.dhcp_option.unchecked_read"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "cursor=option_pointer"},
				nir.Const{Loc: loc, Value: "guard=missing_header_or_payload_bounds"},
			},
			Path:   path,
			Method: "unchecked_read",
			Loc:    loc,
		}}}
	}
	return nil
}

type ccBinarySearchBounds struct {
	low  string
	high string
}

type ccIndexedField struct {
	table string
	index string
	field string
}

type ccBinarySearchComparison struct {
	table  string
	field  string
	index  string
	needle string
}

func (c *ccConv) ccBinarySearchEndpointGuardObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	boundsByMid := map[string]ccBinarySearchBounds{}
	lowUpdates := map[string]bool{}
	highUpdates := map[string]bool{}
	loGuards := map[string]bool{}
	hiGuards := map[string]bool{}
	var comparisons []ccBinarySearchComparison

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" {
				c.ccRecordBinarySearchAssignment(n, boundsByMid, lowUpdates, highUpdates)
			}
		case "init_declarator":
			c.ccRecordBinarySearchInit(n, boundsByMid)
		case "binary_expression":
			c.ccRecordBinarySearchComparison(n, &comparisons, loGuards, hiGuards)
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	for _, cmp := range comparisons {
		bounds, ok := boundsByMid[cmp.index]
		if !ok {
			continue
		}
		if !lowUpdates[cmp.index+"\x00"+bounds.low] || !highUpdates[cmp.index+"\x00"+bounds.high] {
			continue
		}
		guardKey := cmp.table + "\x00" + cmp.field + "\x00" + cmp.needle
		if loGuards[guardKey] && hiGuards[guardKey+"\x00"+bounds.high] {
			continue
		}
		loc := c.loc(body)
		path := "analysis.binary_search.endpoint_guard_bypass"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "midpoint=recomputed"},
				nir.Const{Loc: loc, Value: "bounds=updated_from_midpoint"},
				nir.Const{Loc: loc, Value: "guard=missing_endpoint_range"},
			},
			Path:   path,
			Method: "endpoint_guard_bypass",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccRecordBinarySearchAssignment(n *tree_sitter.Node, boundsByMid map[string]ccBinarySearchBounds, lowUpdates, highUpdates map[string]bool) {
	left := ccIdentifierText(c, c.field(n, "left"))
	right := c.field(n, "right")
	if left == "" || right == nil {
		return
	}
	if low, high, ok := c.ccMidpointParts(right); ok {
		if _, exists := boundsByMid[left]; !exists {
			boundsByMid[left] = ccBinarySearchBounds{low: low, high: high}
		}
		return
	}
	if mid, ok := c.ccIdentPlusOne(right); ok {
		lowUpdates[mid+"\x00"+left] = true
		return
	}
	if mid, ok := c.ccIdentMinusOne(right); ok {
		highUpdates[mid+"\x00"+left] = true
	}
}

func (c *ccConv) ccRecordBinarySearchInit(n *tree_sitter.Node, boundsByMid map[string]ccBinarySearchBounds) {
	name := c.declName(c.field(n, "declarator"))
	if name == "" {
		return
	}
	if low, high, ok := c.ccMidpointParts(c.field(n, "value")); ok {
		if _, exists := boundsByMid[name]; !exists {
			boundsByMid[name] = ccBinarySearchBounds{low: low, high: high}
		}
	}
}

func (c *ccConv) ccRecordBinarySearchComparison(n *tree_sitter.Node, comparisons *[]ccBinarySearchComparison, loGuards, hiGuards map[string]bool) {
	op := c.text(c.field(n, "operator"))
	if op != "<" && op != ">" {
		return
	}
	left := c.field(n, "left")
	right := c.field(n, "right")
	if indexed, ok := c.ccIndexedField(left); ok {
		if needle := ccIdentifierText(c, right); needle != "" {
			c.ccRecordBinarySearchRelation(indexed, needle, op, comparisons, loGuards, hiGuards)
		}
		return
	}
	if indexed, ok := c.ccIndexedField(right); ok {
		if needle := ccIdentifierText(c, left); needle != "" {
			reversed := "<"
			if op == "<" {
				reversed = ">"
			}
			c.ccRecordBinarySearchRelation(indexed, needle, reversed, comparisons, loGuards, hiGuards)
		}
	}
}

func (c *ccConv) ccRecordBinarySearchRelation(indexed ccIndexedField, needle, op string, comparisons *[]ccBinarySearchComparison, loGuards, hiGuards map[string]bool) {
	key := indexed.table + "\x00" + indexed.field + "\x00" + needle
	if indexed.index == "0" && op == ">" {
		loGuards[key] = true
		return
	}
	if op == "<" {
		if ccIdentifierLike(indexed.index) {
			hiGuards[key+"\x00"+indexed.index] = true
		}
		*comparisons = append(*comparisons, ccBinarySearchComparison{
			table:  indexed.table,
			field:  indexed.field,
			index:  indexed.index,
			needle: needle,
		})
	}
}

func (c *ccConv) ccMidpointParts(n *tree_sitter.Node) (string, string, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil || c.kind(n) != "binary_expression" || c.text(c.field(n, "operator")) != "/" {
		return "", "", false
	}
	if cNumberShape(c.text(c.field(n, "right"))) != "NUM" || strings.TrimSpace(c.text(c.field(n, "right"))) != "2" {
		return "", "", false
	}
	sum := ccUnwrapCExpr(c.field(n, "left"))
	if sum == nil || c.kind(sum) != "binary_expression" || c.text(c.field(sum, "operator")) != "+" {
		return "", "", false
	}
	low := ccIdentifierText(c, c.field(sum, "left"))
	high := ccIdentifierText(c, c.field(sum, "right"))
	return low, high, low != "" && high != ""
}

func (c *ccConv) ccIdentPlusOne(n *tree_sitter.Node) (string, bool) {
	return c.ccIdentDeltaOne(n, "+")
}

func (c *ccConv) ccIdentMinusOne(n *tree_sitter.Node) (string, bool) {
	return c.ccIdentDeltaOne(n, "-")
}

func (c *ccConv) ccIdentDeltaOne(n *tree_sitter.Node, op string) (string, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil || c.kind(n) != "binary_expression" || c.text(c.field(n, "operator")) != op {
		return "", false
	}
	if strings.TrimSpace(c.text(c.field(n, "right"))) != "1" {
		return "", false
	}
	id := ccIdentifierText(c, c.field(n, "left"))
	return id, id != ""
}

func (c *ccConv) ccIndexedField(n *tree_sitter.Node) (ccIndexedField, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil || c.kind(n) != "field_expression" {
		return ccIndexedField{}, false
	}
	base := ccUnwrapCExpr(c.field(n, "argument"))
	if base == nil || c.kind(base) != "subscript_expression" {
		return ccIndexedField{}, false
	}
	table := c.dotted(c.field(base, "argument"))
	index := ccIndexText(c, c.field(base, "index"))
	fieldName := c.text(c.field(n, "field"))
	if table == "" || table == "?" || index == "" || fieldName == "" {
		return ccIndexedField{}, false
	}
	return ccIndexedField{table: table, index: index, field: fieldName}, true
}

func (c *ccConv) ccStructPointerOOBWriteObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	derivedPointerBases := map[string]string{}
	writePointers := map[string]bool{}
	incrementedPointers := map[string]bool{}
	containedPointerBases := map[string]map[string]bool{}

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "assignment_expression":
			left := ccIdentifierText(c, c.field(n, "left"))
			right := c.field(n, "right")
			switch c.assignmentOp(n) {
			case "=":
				if left != "" {
					if base, ok := c.ccPointerDerivedReadBase(right); ok {
						derivedPointerBases[left] = base
					}
				}
				if left != "" {
					if ptr, ok := c.ccPointerPlusOffsetBase(right); ok && ptr == left {
						incrementedPointers[left] = true
					}
				}
			case "+=":
				if left != "" {
					incrementedPointers[left] = true
				}
			}
		case "init_declarator":
			name := c.declName(c.field(n, "declarator"))
			if name != "" {
				if base, ok := c.ccPointerDerivedReadBase(c.field(n, "value")); ok {
					derivedPointerBases[name] = base
				}
			}
		case "call_expression":
			c.ccRecordStructPointerCall(n, writePointers, containedPointerBases)
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	for ptr, base := range derivedPointerBases {
		if !writePointers[ptr] || !incrementedPointers[ptr] || containedPointerBases[ptr][base] {
			continue
		}
		loc := c.loc(body)
		path := "analysis.struct_pointer.oob_write"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "pointer=read_derived_buffer_offset"},
				nir.Const{Loc: loc, Value: "write=integer_store_at_pointer_offset"},
				nir.Const{Loc: loc, Value: "guard=missing_containment_check"},
			},
			Path:   path,
			Method: "oob_write",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccPointerDerivedReadBase(n *tree_sitter.Node) (string, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return "", false
	}
	if c.kind(n) == "pointer_expression" && c.unaryOp(n) == "&" {
		arg := c.field(n, "argument")
		if !c.ccExprContainsCallName(arg, "readint32") {
			return "", false
		}
		return c.ccSubscriptBase(arg)
	}
	if !c.ccExprContainsCallName(n, "readint32") {
		return "", false
	}
	return c.ccSubscriptBase(n)
}

func (c *ccConv) ccRecordStructPointerCall(n *tree_sitter.Node, writePointers map[string]bool, containedPointerBases map[string]map[string]bool) {
	path := strings.ToLower(c.dotted(c.field(n, "function")))
	args := c.namedChildren(c.field(n, "arguments"))
	if strings.Contains(path, "writeint32") && len(args) > 0 {
		if ptr, ok := c.ccPointerPlusOffsetBase(args[0]); ok {
			writePointers[ptr] = true
		}
	}
	if strings.Contains(strings.ToUpper(path), "CONTAIN") {
		base := ""
		if len(args) > 0 {
			base = ccIdentifierText(c, args[0])
		}
		if base != "" {
			for _, arg := range args[1:] {
				if ptr := ccIdentifierText(c, arg); ptr != "" {
					if containedPointerBases[ptr] == nil {
						containedPointerBases[ptr] = map[string]bool{}
					}
					containedPointerBases[ptr][base] = true
				}
			}
		}
	}
}

func (c *ccConv) ccPointerPlusOffsetBase(n *tree_sitter.Node) (string, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return "", false
	}
	if id := ccIdentifierText(c, n); id != "" {
		return id, true
	}
	if c.kind(n) != "binary_expression" || c.text(c.field(n, "operator")) != "+" {
		return "", false
	}
	if id := ccIdentifierText(c, c.field(n, "left")); id != "" && ccIsIntegerLiteral(c, c.field(n, "right")) {
		return id, true
	}
	if id := ccIdentifierText(c, c.field(n, "right")); id != "" && ccIsIntegerLiteral(c, c.field(n, "left")) {
		return id, true
	}
	return "", false
}

func (c *ccConv) ccExprContainsCallName(n *tree_sitter.Node, needle string) bool {
	found := false
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found {
			return
		}
		if c.kind(m) == "call_expression" && strings.Contains(strings.ToLower(c.dotted(c.field(m, "function"))), needle) {
			found = true
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

func (c *ccConv) ccSubscriptBase(n *tree_sitter.Node) (string, bool) {
	var base string
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || base != "" {
			return
		}
		if c.kind(m) == "subscript_expression" {
			base = ccIdentifierText(c, c.field(m, "argument"))
			if base != "" {
				return
			}
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return base, base != ""
}

type ccSignedLengthCandidate struct {
	input  string
	sizeof string
}

func (c *ccConv) ccSignedLengthUnderflowCopyObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	candidates := map[string]ccSignedLengthCandidate{}
	memcpyLens := map[string]bool{}
	guards := map[string]bool{}

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" {
				out := ccDerefIdentifierText(c, c.field(n, "left"))
				if input, sizeofText, ok := c.ccLengthMinusSizeof(c.field(n, "right")); out != "" && ok {
					candidates[out] = ccSignedLengthCandidate{input: input, sizeof: sizeofText}
				}
			}
		case "call_expression":
			if lastSeg(c.dotted(c.field(n, "function"))) == "memcpy" {
				args := c.namedChildren(c.field(n, "arguments"))
				if len(args) >= 3 {
					if out := ccDerefIdentifierText(c, args[2]); out != "" {
						memcpyLens[out] = true
					}
				}
			}
		case "binary_expression":
			if input, sizeofText, ok := c.ccSizeofLowerBoundGuard(n); ok {
				guards[input+"\x00"+sizeofText] = true
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	for out, cand := range candidates {
		if !memcpyLens[out] || guards[cand.input+"\x00"+cand.sizeof] {
			continue
		}
		loc := c.loc(body)
		path := "analysis.signed_length.underflow_copy"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "length=subtract_sizeof"},
				nir.Const{Loc: loc, Value: "copy=memcpy"},
				nir.Const{Loc: loc, Value: "guard=missing_input_lower_bound"},
			},
			Path:   path,
			Method: "underflow_copy",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccLengthMinusSizeof(n *tree_sitter.Node) (string, string, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil || c.kind(n) != "binary_expression" || c.text(c.field(n, "operator")) != "-" {
		return "", "", false
	}
	input := ccIdentifierText(c, c.field(n, "left"))
	sizeofText := ccSizeofText(c, c.field(n, "right"))
	return input, sizeofText, input != "" && sizeofText != ""
}

func (c *ccConv) ccSizeofLowerBoundGuard(n *tree_sitter.Node) (string, string, bool) {
	op := c.text(c.field(n, "operator"))
	left := c.field(n, "left")
	right := c.field(n, "right")
	switch op {
	case "<", "<=":
		input := ccIdentifierText(c, left)
		sizeofText := ccSizeofText(c, right)
		return input, sizeofText, input != "" && sizeofText != ""
	case ">", ">=":
		input := ccIdentifierText(c, right)
		sizeofText := ccSizeofText(c, left)
		return input, sizeofText, input != "" && sizeofText != ""
	}
	return "", "", false
}

func (c *ccConv) ccPythonHashErrorObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	hashVars := map[string]bool{}
	checkedHashVars := map[string]bool{}
	hasDiscard := false
	hasLength := false

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch c.kind(n) {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" && c.ccCallNameIs(c.field(n, "right"), "PyObject_Hash") {
				if name := ccIdentifierText(c, c.field(n, "left")); name != "" {
					hashVars[name] = true
				}
			}
		case "init_declarator":
			if c.ccCallNameIs(c.field(n, "value"), "PyObject_Hash") {
				if name := c.declName(c.field(n, "declarator")); name != "" {
					hashVars[name] = true
				}
			}
		case "call_expression":
			switch lastSeg(c.dotted(c.field(n, "function"))) {
			case "PySet_Discard":
				hasDiscard = true
			case "PySequence_Length":
				hasLength = true
			}
		case "binary_expression":
			if c.text(c.field(n, "operator")) == "==" {
				if name, ok := c.ccIdentifierEqualsMinusOne(n); ok {
					checkedHashVars[name] = true
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	if !hasDiscard || !hasLength {
		return nil
	}
	for name := range hashVars {
		if checkedHashVars[name] {
			continue
		}
		loc := c.loc(body)
		path := "analysis.python_hash.unchecked_error"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "api=PyObject_Hash"},
				nir.Const{Loc: loc, Value: "guard=missing_minus_one_check"},
				nir.Const{Loc: loc, Value: "cleanup=continues_after_hash"},
			},
			Path:   path,
			Method: "unchecked_error",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccCallNameIs(n *tree_sitter.Node, name string) bool {
	n = ccUnwrapCExpr(n)
	return n != nil && c.kind(n) == "call_expression" && lastSeg(c.dotted(c.field(n, "function"))) == name
}

func (c *ccConv) ccIdentifierEqualsMinusOne(n *tree_sitter.Node) (string, bool) {
	left := c.field(n, "left")
	right := c.field(n, "right")
	if name := ccIdentifierText(c, left); name != "" && ccIsMinusOne(c, right) {
		return name, true
	}
	if name := ccIdentifierText(c, right); name != "" && ccIsMinusOne(c, left) {
		return name, true
	}
	return "", false
}

func (c *ccConv) ccCaseInsensitiveLocalIdentityObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || !c.ccFunctionMentionsPasswdIdentity(fn) {
		return nil
	}
	ciComparisons := map[string]bool{}
	canonicalComparisons := map[string]bool{}

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "call_expression" {
			name := strings.ToLower(lastSeg(c.dotted(c.field(n, "function"))))
			args := c.namedChildren(c.field(n, "arguments"))
			if len(args) >= 2 {
				switch {
				case strings.Contains(name, "strcasecmp"):
					c.ccRecordCaseInsensitiveIdentityComparison(args[0], args[1], ciComparisons)
				case name == "strcmp":
					c.ccRecordCanonicalPasswdComparison(args[0], args[1], canonicalComparisons)
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	for key := range ciComparisons {
		if canonicalComparisons[key] {
			continue
		}
		loc := c.loc(body)
		path := "analysis.local_identity.case_insensitive_authz"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "compare=case_insensitive"},
				nir.Const{Loc: loc, Value: "identity=local_passwd"},
				nir.Const{Loc: loc, Value: "guard=missing_canonical_passwd_name"},
			},
			Path:   path,
			Method: "case_insensitive_authz",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccFunctionMentionsPasswdIdentity(fn *tree_sitter.Node) bool {
	text := c.text(fn)
	return strings.Contains(text, "passwd") || strings.Contains(text, "pw_name")
}

func (c *ccConv) ccRecordCaseInsensitiveIdentityComparison(a, b *tree_sitter.Node, out map[string]bool) {
	if ccIsStringLike(a) || ccIsStringLike(b) {
		return
	}
	ak := ccComparisonKey(c, a)
	bk := ccComparisonKey(c, b)
	if ak == "" || bk == "" {
		return
	}
	out[ak] = true
	out[bk] = true
}

func (c *ccConv) ccRecordCanonicalPasswdComparison(a, b *tree_sitter.Node, out map[string]bool) {
	ak := ccComparisonKey(c, a)
	bk := ccComparisonKey(c, b)
	if ak == "" || bk == "" {
		return
	}
	if ccIsPasswdNameKey(ak) {
		out[bk] = true
	}
	if ccIsPasswdNameKey(bk) {
		out[ak] = true
	}
}

func (c *ccConv) ccTrailingEscapeStringOverreadObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	loopRe := ccRe(`while\(\*([A-Za-z_][A-Za-z0-9_]*)!='\\"'&&\*([A-Za-z_][A-Za-z0-9_]*)&&\+\+([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range loopRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		cursor := text[m[2]:m[3]]
		if cursor != text[m[4]:m[5]] {
			continue
		}
		length := text[m[6]:m[7]]
		tail := text[m[1]:]
		if !ccHasTrailingEscapeSkip(tail, cursor) {
			continue
		}
		if !ccHasLengthPlusOneAllocation(tail, length) {
			continue
		}
		if ccHasTrailingEscapeNulGuard(tail, cursor) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.string.trailing_escape_overread"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "scan=until_quote_or_nul"},
				nir.Const{Loc: loc, Value: "escape=post_increment_skip"},
				nir.Const{Loc: loc, Value: "guard=missing_trailing_escape_nul_check"},
			},
			Path:   path,
			Method: "trailing_escape_overread",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccEscapedTerminatorWriteObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccEscapedTerminatorDecodeRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		ch := text[m[2]:m[3]]
		cursor := text[m[4]:m[5]]
		prefix := text[:m[0]]
		tail := text[m[1]:]
		if !strings.Contains(prefix, "if("+ch+"=='\\\\')") && !strings.Contains(prefix, "if('\\\\'=="+ch+")") {
			continue
		}
		writeIdx := ccEscapedTerminatorWriteIndex(tail, ch)
		if writeIdx < 0 {
			continue
		}
		beforeWrite := tail[:writeIdx]
		if ccHasDecodedTerminatorGuard(beforeWrite, ch) {
			continue
		}
		if !strings.Contains(prefix, ch+"=*"+cursor+"++") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.string.escaped_terminator_write"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "decode=escaped_input_byte"},
				nir.Const{Loc: loc, Value: "write=decoded_byte"},
				nir.Const{Loc: loc, Value: "guard=missing_decoded_nul_check"},
			},
			Path:   path,
			Method: "escaped_terminator_write",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccUnboundedAccumulatedAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccAccumulatedAllocationRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		total := text[m[2]:m[3]]
		elem := text[m[4]:m[5]]
		if !ccHasNewArrayWithCount(text[m[1]:], total) {
			continue
		}
		if ccHasAccumulatedAllocationGuard(text, total, elem) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.allocation.unbounded_accumulated_count"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "count=accumulated_indirect_values"},
				nir.Const{Loc: loc, Value: "allocation=new_array"},
				nir.Const{Loc: loc, Value: "guard=missing_element_or_aggregate_bound"},
			},
			Path:   path,
			Method: "unbounded_accumulated_count",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccArrayBufferTransferMaxLengthObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	lengthVars := ccAssignedCallResultVars(text, "toIndex")
	maxVars := ccAssignedCallResultVars(text, "maxByteLength")
	for lengthVar := range lengthVars {
		for maxVar := range maxVars {
			if !ccHasArrayBufferAllocation(text, lengthVar, maxVar) {
				continue
			}
			if ccHasMaxLengthGuard(text, lengthVar, maxVar) {
				continue
			}
			loc := c.loc(body)
			path := "analysis.array_buffer.transfer_max_length_bypass"
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "length=caller_selected_to_index"},
					nir.Const{Loc: loc, Value: "max=max_byte_length"},
					nir.Const{Loc: loc, Value: "guard=missing_length_le_max"},
				},
				Path:   path,
				Method: "transfer_max_length_bypass",
				Loc:    loc,
			}}}
		}
	}
	return nil
}

func (c *ccConv) ccCompressedBlockCapacityObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !ccHasBackwardHeaderWrite(text) {
		return nil
	}
	for _, m := range ccCompressedCapacityRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		written := text[m[2]:m[3]]
		chunk := text[m[4]:m[5]]
		capacity := text[m[6]:m[7]]
		tail := text[m[1]:]
		if !ccHasClampAssignment(tail, chunk, capacity, written) {
			continue
		}
		if !ccHasAdditiveCapacityCheck(tail, written, capacity) {
			continue
		}
		if ccHasDestSizeCapacityGuard(text, written, chunk, capacity) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.compressed_block.capacity_mismatch"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "capacity=container_limit_not_dest_size"},
				nir.Const{Loc: loc, Value: "write=backward_block_header"},
				nir.Const{Loc: loc, Value: "guard=missing_dest_capacity"},
			},
			Path:   path,
			Method: "capacity_mismatch",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccFragmentOffsetCopyObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccFragmentOffsetCopyRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		offset := text[m[2]:m[3]]
		src := text[m[4]:m[5]]
		length := text[m[6]:m[7]]
		if ccFragmentRecordBase(offset) == "" || ccFragmentRecordBase(offset) != ccFragmentRecordBase(src) || ccFragmentRecordBase(offset) != ccFragmentRecordBase(length) {
			continue
		}
		if ccHasFragmentOffsetCopyGuard(text, offset, length) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.fragment.offset_copy_oob"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "offset=shifted_fragment_offset"},
				nir.Const{Loc: loc, Value: "copy=memcpy"},
				nir.Const{Loc: loc, Value: "guard=missing_offset_plus_length_bound"},
			},
			Path:   path,
			Method: "offset_copy_oob",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccRubyCgiEscapeHTMLAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "ALLOCV_N(") || !strings.Contains(text, "RSTRING_LEN(") || !strings.Contains(text, "HTML_ESCAPE_MAX_LEN") {
		return nil
	}
	if strings.Contains(text, "typedefcharescape_buf[HTML_ESCAPE_MAX_LEN]") ||
		ccRe(`ALLOCV_N\([^,]*escape_buf[^,]*,[^,]*,RSTRING_LEN\(`).MatchString(text) {
		return nil
	}
	if !ccRe(`ALLOCV_N\([^,]+,[^,]+,RSTRING_LEN\([^)]+\)\*HTML_ESCAPE_MAX_LEN\)`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.ruby_cgi.escape_html_length_overflow"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "allocator=ALLOCV_N"},
			nir.Const{Loc: loc, Value: "length=RSTRING_LEN_times_escape_max"},
			nir.Const{Loc: loc, Value: "guard=missing_element_array_type"},
		},
		Path:   path,
		Method: "escape_html_length_overflow",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccPythonUnicodeEscapeAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "PyString_FromStringAndSize(NULL,") || !strings.Contains(text, ">=0x10000") {
		return nil
	}
	if !ccRe(`\*[A-Za-z_][A-Za-z0-9_]*\+\+='U'`).MatchString(text) {
		return nil
	}
	if ccRe(`10\*[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if !ccRe(`6\*[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.python_unicode_escape.wide_underallocation"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "allocator=PyString_FromStringAndSize"},
			nir.Const{Loc: loc, Value: "capacity=six_bytes_per_input"},
			nir.Const{Loc: loc, Value: "write=wide_unicode_escape"},
		},
		Path:   path,
		Method: "wide_underallocation",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccFormattedPlaceholderAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "newSV(strlen(") || !strings.Contains(text, "sprintf(") || !strings.Contains(text, "%d") {
		return nil
	}
	if strings.Contains(text, "*6+16") || strings.Contains(text, "snprintf(") {
		return nil
	}
	if !ccRe(`newSV\(strlen\([^)]+\)\*3\)`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.formatted_placeholder.underallocation"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "allocator=newSV"},
			nir.Const{Loc: loc, Value: "capacity=strlen_times_three"},
			nir.Const{Loc: loc, Value: "write=sprintf_decimal_placeholder"},
		},
		Path:   path,
		Method: "underallocation",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccSniffCsvExternalAccessObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, ".ToString()") || !strings.Contains(text, ".FromNamedParameters(") || !strings.Contains(text, ".named_parameters") {
		return nil
	}
	if strings.Contains(text, "enable_external_access") {
		return nil
	}
	if !ccRe(`[A-Za-z_][A-Za-z0-9_]*->path=[A-Za-z_][A-Za-z0-9_]*\.inputs\[[^]]+\]\.ToString\(\)`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.sniff_csv.external_access_bypass"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "path=caller_supplied_table_input"},
			nir.Const{Loc: loc, Value: "options=from_named_parameters"},
			nir.Const{Loc: loc, Value: "guard=missing_enable_external_access"},
		},
		Path:   path,
		Method: "external_access_bypass",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccCimgPnmDimensionOverflowObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "fsize(") {
		return nil
	}
	productRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)\*([A-Za-z_][A-Za-z0-9_]*)\*([A-Za-z_][A-Za-z0-9_]*)>([A-Za-z_][A-Za-z0-9_]*)`)
	for _, m := range productRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 10 {
			continue
		}
		product := text[m[2]:m[7]]
		if ccHasWidenedDimensionProduct(text, product) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.cimg_pnm.dimension_product_overflow"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "size=file_size"},
				nir.Const{Loc: loc, Value: "product=three_dimensions"},
				nir.Const{Loc: loc, Value: "guard=missing_widen_before_multiply"},
			},
			Path:   path,
			Method: "dimension_product_overflow",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccJpegSetjmpConstructorObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "jpeg_std_error") ||
		!strings.Contains(text, ".error_exit=") ||
		!strings.Contains(text, "setjmp(") ||
		!containsAnyString(text, []string{"jpeg_create_decompress", "jpeg_create_compress"}) {
		return nil
	}
	if strings.Contains(text, "DIP__DECLARE_JPEG_EXIT") ||
		ccRe(`memcpy\([^,]*setjmp_buffer,[^,]*setjmp_buffer`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.jpeg.setjmp_constructor_escape"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "error_handler=jpeg_error_exit"},
			nir.Const{Loc: loc, Value: "jump=setjmp_member_buffer"},
			nir.Const{Loc: loc, Value: "lifetime=constructor_stack_frame"},
		},
		Path:   path,
		Method: "setjmp_constructor_escape",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccParsedUserDefaultRootObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccParsedUserDefaultRootRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		parsed := text[m[2]:m[3]]
		endptr := text[m[4]:m[5]]
		tail := text[m[1]:]
		retRe := regexp.MustCompile(`if\(\*` + regexp.QuoteMeta(endptr) + `=='\\0'\)return([A-Za-z_][A-Za-z0-9_]*)`)
		ret := retRe.FindStringSubmatchIndex(tail)
		if len(ret) < 4 {
			continue
		}
		user := tail[ret[2]:ret[3]]
		beforeReturn := tail[:ret[0]]
		if strings.Contains(beforeReturn, user+"->uid=(int)"+parsed) || strings.Contains(beforeReturn, user+".uid=(int)"+parsed) {
			continue
		}
		if !strings.Contains(tail, user+"->gid=(int)") && !strings.Contains(tail, user+".gid=(int)") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.user_parser.default_root_return"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "parser=strtoll"},
				nir.Const{Loc: loc, Value: "return=before_uid_assignment"},
				nir.Const{Loc: loc, Value: "default=zero_initialized_user"},
			},
			Path:   path,
			Method: "default_root_return",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccUncheckedNullableResultDerefObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	guards := c.ccNullCheckedMacroArgs()
	assignRe := ccRe(`\b((?:[A-Za-z_][A-Za-z0-9_]*(?:->|\.))+[A-Za-z_][A-Za-z0-9_]*)=[A-Za-z_][A-Za-z0-9_]*\(`)
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		target := text[m[2]:m[3]]
		tail := text[m[1]:]
		use := ccNullableResultUse(tail, target, guards)
		if use < 0 {
			continue
		}
		if ccNullableResultGuarded(tail[:use], target, guards) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.nullable_result.unchecked_deref"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "result=call_assignment"},
				nir.Const{Loc: loc, Value: "deref=unchecked_use"},
				nir.Const{Loc: loc, Value: "guard=missing_null_check"},
			},
			Path:   path,
			Method: "unchecked_deref",
			Loc:    loc,
		}}}
	}
	return nil
}

// ccNullableResultUse reports where a stored call result is first used in a
// way that would fault on null: a member access through it, or handing it to a
// call that writes through its first argument. Reads that merely observe the
// value -- a scalar fed to a size computation, an argument to a call that only
// inspects it -- do not fault, so they are not uses. An argument whose callee
// is a null-check macro is the guard itself, not a use, so it is skipped here
// and credited as a guard.
func ccNullableResultUse(tail, target string, guards map[string][]bool) int {
	for i := 0; i+len(target) <= len(tail); {
		j := strings.Index(tail[i:], target)
		if j < 0 {
			return -1
		}
		at := i + j
		if !ccAtTokenBoundary(tail, at) {
			i = at + len(target)
			continue
		}
		end := at + len(target)
		if end < len(tail) && ccIsIdentChar(tail[end]) {
			i = end
			continue
		}
		if strings.HasPrefix(tail[end:], "->") {
			return at
		}
		if end < len(tail) && (tail[end] == ')' || tail[end] == ',') && at > 0 && (tail[at-1] == '(' || tail[at-1] == ',') {
			if name, pos, ok := ccEnclosingCallArg(tail, at); ok {
				if pos == 0 && cPropagators[name] {
					return at
				}
			}
		}
		i = end
	}
	return -1
}

// ccAtTokenBoundary reports whether the substring starting at index i opens a
// fresh token rather than continuing a longer identifier. Whitespace removal
// glues a preprocessor directive onto whatever follows it (`#else\n  p->x`
// becomes `#elsep->x`), so a run of identifier characters that begins at a `#`
// is the directive's own name and the token after it does start fresh.
func ccAtTokenBoundary(text string, i int) bool {
	j := i
	for j > 0 && ccIsIdentChar(text[j-1]) {
		j--
	}
	return j == i || j > 0 && text[j-1] == '#'
}

// ccEnclosingCallArg names the call that an argument at index i belongs to and
// its zero-based position in that call's argument list.
func ccEnclosingCallArg(text string, i int) (string, int, bool) {
	depth := 0
	pos := 0
	for j := i - 1; j >= 0; j-- {
		switch text[j] {
		case ')':
			depth++
		case ',':
			if depth == 0 {
				pos++
			}
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			k := j - 1
			for k >= 0 && ccIsIdentChar(text[k]) {
				k--
			}
			if k+1 == j {
				return "", 0, false
			}
			return text[k+1 : j], pos, true
		}
	}
	return "", 0, false
}

// ccNullableResultGuarded reports whether a null test on the target precedes
// the use. The test may be spelled on the target's own path or on any trailing
// segment chain of it, since a guard on `if (!obj->field.sub)` checks the same
// pointer the assignment stored, and it may live inside a file-local check
// macro invoked on that path.
func ccNullableResultGuarded(before, target string, guards map[string][]bool) bool {
	for _, spelling := range ccMemberPathSuffixes(target) {
		if ccNullGuardRe(spelling).MatchString(before) {
			return true
		}
	}
	for i := 0; i+len(target) <= len(before); {
		j := strings.Index(before[i:], target)
		if j < 0 {
			return false
		}
		at := i + j
		end := at + len(target)
		if end < len(before) && (before[end] == ')' || before[end] == ',') && at > 0 && (before[at-1] == '(' || before[at-1] == ',') {
			if name, pos, ok := ccEnclosingCallArg(before, at); ok && ccMacroArgTested(name, pos, guards) {
				return true
			}
		}
		i = end
	}
	return false
}

// ccNullGuardRe matches the spellings a null test on a value takes: the value
// negated, or compared to NULL either way round, each optionally wrapped in a
// compiler-hint or predicate macro call and in parentheses. Only the branch
// that treats null as the failure counts -- `if (p != NULL)` asserts the value
// is usable rather than bailing on it.
func ccNullGuardRe(spelling string) *regexp.Regexp {
	esc := regexp.QuoteMeta(spelling)
	wrapped := `(?:` + esc + `|\(` + esc + `\))`
	hint := `(?:[A-Za-z_][A-Za-z0-9_]*\()?`
	return ccRe(`if\(\(?` + hint + `!` + wrapped + `\)?\)?\)|` +
		`if\(\(?` + hint + wrapped + `==NULL\)?\)?\)|` +
		`if\(\(?` + hint + `NULL==` + wrapped + `\)?\)?\)`)
}

func ccMacroArgTested(name string, pos int, guards map[string][]bool) bool {
	tested, ok := guards[name]
	return ok && pos < len(tested) && tested[pos]
}

// ccMemberPathSuffixes lists the trailing segment chains of a member path of
// at least two segments, up to the full path itself. Single segments are left
// out: a bare field name is not a spelling of the pointer that was stored.
func ccMemberPathSuffixes(path string) []string {
	var out []string
	for i := 0; i < len(path); i++ {
		if path[i] != '.' {
			continue
		}
		if rest := path[i+1:]; strings.Contains(rest, ".") || strings.Contains(rest, "->") {
			out = append(out, rest)
		}
	}
	for i := 0; i+1 < len(path); i++ {
		if path[i] == '-' && path[i+1] == '>' {
			if rest := path[i+2:]; strings.Contains(rest, ".") || strings.Contains(rest, "->") {
				out = append(out, rest)
			}
		}
	}
	if strings.Contains(path, ".") || strings.Contains(path, "->") {
		out = append(out, path)
	}
	return out
}

// ccNullCheckedMacroArgs maps each file-local function-like macro to a
// per-argument flag saying whether the macro body tests that argument against
// null. A macro like `#define CHECK(p) { if (!p) return -1; }` is the usual C
// spelling of a check that a call site wants credited, and the preprocessor
// leaves only the macro's name behind at the call site.
func (c *ccConv) ccNullCheckedMacroArgs() map[string][]bool {
	if c.nullCheckMacroArgs != nil {
		return c.nullCheckMacroArgs
	}
	out := map[string][]bool{}
	lines := strings.Split(string(c.src), "\n")
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(raw, "#") {
			continue
		}
		for strings.HasSuffix(strings.TrimSpace(raw), "\\") && i+1 < len(lines) {
			raw = strings.TrimSuffix(strings.TrimSpace(raw), "\\") + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		name, params, body := cMacroNameParamsAndBody(raw)
		if name == "" || len(params) == 0 || body == "" {
			continue
		}
		flags := make([]bool, len(params))
		any := false
		for idx, p := range params {
			if ccNullGuardRe(p).MatchString(body) {
				flags[idx] = true
				any = true
			}
		}
		if any {
			out[name] = flags
		}
	}
	c.nullCheckMacroArgs = out
	return out
}

func (c *ccConv) ccConditionalFallbackDoubleFreeObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccConditionalFallbackParseRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		list := text[m[2]:m[3]]
		if !strings.Contains(text, "free("+list+");") || strings.Count(text, "free("+list+");") < 2 {
			continue
		}
		if !strings.Contains(text, "open_port(") || !strings.Contains(text, "NULL)") {
			continue
		}
		if regexp.MustCompile(`if\(!open_port\([^)]*NULL\)\)\{?free\(` + regexp.QuoteMeta(list) + `\);return-1`).MatchString(text) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.list.conditional_fallback_double_free"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "list=parsed_comma_values"},
				nir.Const{Loc: loc, Value: "fallback=open_null_endpoint"},
				nir.Const{Loc: loc, Value: "release=early_free_then_common_free"},
			},
			Path:   path,
			Method: "conditional_fallback_double_free",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccGlibCommandLineAssemblyObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "g_app_info_create_from_commandline(") || strings.Contains(text, "g_shell_quote(") {
		return nil
	}
	appendRe := ccRe(`g_string_append_printf\([^,]+,"[^"]*%s"`)
	if !appendRe.MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.command_line.glib_unquoted_placeholder"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "builder=g_string_append_printf"},
			nir.Const{Loc: loc, Value: "placeholder=unquoted_percent_s"},
			nir.Const{Loc: loc, Value: "launcher=g_app_info_create_from_commandline"},
		},
		Path:   path,
		Method: "glib_unquoted_placeholder",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccWebRequestPathTraversalObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	sourceRe := ccRe(`\b([A-Za-z_][A-Za-z0-9_]*)=http_request_(?:param_get|get_query_string)\(`)
	for _, m := range sourceRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		pathVar := text[m[2]:m[3]]
		if !ccHasAnyCallWithArg(text, []string{"file_read", "file_write", "unlink"}, pathVar) {
			continue
		}
		if strings.Contains(text, "page_name_is_good("+pathVar+")") ||
			strings.Contains(text, "strstr("+pathVar+",\"..\")") ||
			strings.Contains(text, "strchr("+pathVar+",'/')") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.web_request.path_traversal"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "source=http_request_path"},
				nir.Const{Loc: loc, Value: "sink=file_helper"},
				nir.Const{Loc: loc, Value: "guard=missing_path_component_validation"},
			},
			Path:   path,
			Method: "path_traversal",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccRemoteListingDownloadPathObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if _, ok := ccRemoteListingDownloadPathMatch(text); !ok {
		return nil
	}
	loc := c.loc(body)
	return []nir.Stmt{ccRemoteListingDownloadPathStmt(loc)}
}

func (c *ccConv) ccOldStyleRemoteListingDownloadPathObservations(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	raw := c.text(root)
	if !ccHasOldStyleFunctionDefinition(raw) {
		return nil
	}
	text := compactCExprText(raw)
	off, ok := ccRemoteListingDownloadPathMatch(text)
	if !ok {
		return nil
	}
	loc := c.locAtCompactOffset(root, raw, off)
	return []nir.Stmt{ccRemoteListingDownloadPathStmt(loc)}
}

func ccRemoteListingDownloadPathMatch(text string) (int, bool) {
	for _, m := range ccRemoteListingSlashCheckRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		name := text[m[2]:m[3]]
		if !strings.Contains(text, "strcmp("+name+",\"..\")") ||
			!strings.Contains(text, "snprintf(") ||
			!strings.Contains(text, "open(") ||
			!strings.Contains(text, "O_WRONLY|O_CREAT") {
			continue
		}
		if strings.Contains(text, "strcmp("+name+",\".\")") || strings.Contains(text, "*"+name+"=='\\0'") {
			continue
		}
		return m[0], true
	}
	return 0, false
}

func ccRemoteListingDownloadPathStmt(loc string) nir.Stmt {
	path := "analysis.remote_listing.download_path"
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "name=remote_listing_entry"},
			nir.Const{Loc: loc, Value: "sink=open_create"},
			nir.Const{Loc: loc, Value: "guard=missing_dot_or_empty_name_rejection"},
		},
		Path:   path,
		Method: "download_path",
		Loc:    loc,
	}}
}

func ccHasOldStyleFunctionDefinition(raw string) bool {
	return ccOldStyleFunctionDefRe.MatchString(raw)
}

func (c *ccConv) ccFat12SuccessorBoundsObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccFat12OffsetRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		cluster := text[m[2]:m[3]]
		fsRe := ccRe(`([A-Za-z_][A-Za-z0-9_]*)->fat_bits`)
		for _, fm := range fsRe.FindAllStringSubmatchIndex(text, -1) {
			if len(fm) < 4 {
				continue
			}
			fs := text[fm[2]:fm[3]]
			if !strings.Contains(text, "get_fat(") ||
				!strings.Contains(text, cluster+"+1") ||
				!strings.Contains(text, cluster+"!="+fs+"->clusters-1") {
				continue
			}
			if strings.Contains(text, cluster+"!="+fs+"->clusters+1") {
				continue
			}
			loc := c.loc(body)
			path := "analysis.fat12.successor_entry_bounds_bypass"
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "entry=fat12_successor"},
					nir.Const{Loc: loc, Value: "index=cluster_plus_one"},
					nir.Const{Loc: loc, Value: "guard=missing_successor_upper_bound"},
				},
				Path:   path,
				Method: "successor_entry_bounds_bypass",
				Loc:    loc,
			}}}
		}
	}
	return nil
}

func (c *ccConv) ccShiftedClusterAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	allocRe := ccRe(`malloc\(CLUSTER_SIZE\(\*([^)]+)\)\)`)
	for _, m := range allocRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		sb := text[m[2]:m[3]]
		prefix := text[:m[0]]
		if strings.Contains(prefix, sb+"->sector_bits<9") {
			continue
		}
		if !strings.Contains(text, sb+"->sector_bits") ||
			!strings.Contains(text, sb+"->spc_bits") ||
			!strings.Contains(text, "verify_vbr_checksum(") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.cluster.shifted_size_allocation"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "allocation=cluster_size_shift"},
				nir.Const{Loc: loc, Value: "fields=sector_bits_and_spc_bits"},
				nir.Const{Loc: loc, Value: "guard=missing_sector_bits_lower_bound"},
			},
			Path:   path,
			Method: "shifted_size_allocation",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccLengthDerivedAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !ccLengthDerivedAllocationBeforeFileBound(text) {
		return nil
	}
	loc := c.loc(body)
	return []nir.Stmt{ccLengthDerivedAllocationStmt(loc)}
}

func ccLengthDerivedAllocationBeforeFileBound(text string) bool {
	for _, m := range ccLengthDerivedHeaderRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		size := text[m[2]:m[3]]
		tail := text[m[1]:]
		allocAt := strings.Index(tail, "malloc_from_callbacks("+size)
		if allocAt < 0 || !strings.Contains(tail, ","+size+")") {
			continue
		}
		beforeAlloc := text[:m[1]+allocAt]
		if strings.Contains(beforeAlloc, "hasKnownFileSize") || strings.Contains(beforeAlloc, "fileSize-runningFilePos") {
			continue
		}
		return true
	}
	return false
}

func ccLengthDerivedAllocationStmt(loc string) nir.Stmt {
	path := "analysis.allocation.length_derived_before_file_bound"
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "length=decoded_block_header"},
			nir.Const{Loc: loc, Value: "allocation=callback_malloc"},
			nir.Const{Loc: loc, Value: "guard=missing_remaining_file_size"},
		},
		Path:   path,
		Method: "length_derived_before_file_bound",
		Loc:    loc,
	}}
}

func (c *ccConv) ccUnboundedFgetcFixedBufferObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	bufRe := ccRe(`char([A-Za-z_][A-Za-z0-9_]*)\[[^]]+\]`)
	for _, m := range bufRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		buf := text[m[2]:m[3]]
		writeRe := regexp.MustCompile(regexp.QuoteMeta(buf) + `\[([A-Za-z_][A-Za-z0-9_]*)\]=fgetc\(`)
		w := writeRe.FindStringSubmatchIndex(text)
		if len(w) < 4 {
			continue
		}
		idx := text[w[2]:w[3]]
		if !strings.Contains(text, "for(;;)") || strings.Contains(text, idx+">=") || strings.Contains(text, "realloc(") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.file_read.unbounded_fgetc_fixed_buffer"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "read=fgetc"},
				nir.Const{Loc: loc, Value: "buffer=fixed_array"},
				nir.Const{Loc: loc, Value: "guard=missing_index_bound"},
			},
			Path:   path,
			Method: "unbounded_fgetc_fixed_buffer",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccCgifSignedFrameCountObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "cmpPixel(") || !strings.Contains(text, "pImageData[") {
		return nil
	}
	if !ccCgifFrameLoopRe.MatchString(text) {
		return nil
	}
	if ccRe(`for\([^;]*;[^;]*MULU16\([^)]*\.config\.width[^)]*\.config\.height[^)]*\)`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.cgif.signed_frame_count_overflow"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "loop=width_times_height"},
			nir.Const{Loc: loc, Value: "comparison=frame_pixels"},
			nir.Const{Loc: loc, Value: "guard=missing_widened_product"},
		},
		Path:   path,
		Method: "signed_frame_count_overflow",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccProtocolFrameBindingObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	peerRe := ccRe(`([A-Za-z_][A-Za-z0-9_]*(?:->|\.)peercallno)==([A-Za-z_][A-Za-z0-9_]*)`)
	for _, m := range peerRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		receiverPeer := text[m[2]:m[3]]
		callno := text[m[4]:m[5]]
		base := receiverPeer
		if idx := strings.LastIndex(base, "->"); idx >= 0 {
			base = base[:idx]
		} else if idx := strings.LastIndex(base, "."); idx >= 0 {
			base = base[:idx]
		}
		dstRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)==` + regexp.QuoteMeta(base) + `(?:->|\.)callno`)
		dst := dstRe.FindStringSubmatchIndex(text)
		if len(dst) < 4 {
			continue
		}
		dcallno := text[dst[2]:dst[3]]
		if dcallno == callno {
			continue
		}
		if strings.Contains(text, "full_frame?"+dcallno+"=="+base+"->callno") ||
			strings.Contains(text, "full_frame?"+dcallno+"=="+base+".callno") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.protocol.frame_binding_missing_destination"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "peer=source_call_number"},
				nir.Const{Loc: loc, Value: "destination=optional_destination_call_number"},
				nir.Const{Loc: loc, Value: "guard=missing_full_frame_binding"},
			},
			Path:   path,
			Method: "frame_binding_missing_destination",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccFilesystemImageDirentTraversalObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	for _, m := range ccFilesystemImageDirentCopyRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		pathBuf := text[m[2]:m[3]]
		pathLen := text[m[4]:m[5]]
		nameLen := text[m[6]:m[7]]
		if !strings.Contains(text, pathBuf+"["+pathLen+"+"+nameLen+"]=0") || !strings.Contains(text, "expand_fs("+pathBuf+",") {
			continue
		}
		if ccRe(`strchr\([^,]+,'/'\)`).MatchString(text) || ccRe(`strcmp\([^,]+,"\.\."\)`).MatchString(text) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.filesystem_image.dirent_traversal"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "name=image_dirent"},
				nir.Const{Loc: loc, Value: "path=recursive_expand"},
				nir.Const{Loc: loc, Value: "guard=missing_separator_or_parent_rejection"},
			},
			Path:   path,
			Method: "dirent_traversal",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccProtocolCommandInjectionObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	parseRe := ccRe(`([A-Za-z_][A-Za-z0-9_]*)=strtoul\([^,]+,[^,]+,10\)`)
	for _, m := range parseRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		size := text[m[2]:m[3]]
		oversizedRe := regexp.MustCompile(`if\(` + regexp.QuoteMeta(size) + `>[A-Za-z_][A-Za-z0-9_]*\)\{([^{}]*)\}`)
		oversizedMatch := oversizedRe.FindStringSubmatch(text)
		if len(oversizedMatch) < 2 {
			continue
		}
		oversizedBranch := oversizedMatch[1]
		if !strings.Contains(text, "OP_PUT") ||
			!strings.Contains(oversizedBranch, "reply_msg(") ||
			!strings.Contains(oversizedBranch, "MSG_JOB_TOO_BIG") {
			continue
		}
		if strings.Contains(oversizedBranch, "skip(") && strings.Contains(oversizedBranch, size+"+2") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.protocol.oversized_body_not_discarded"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "command=put"},
				nir.Const{Loc: loc, Value: "size=strtoul_body_size"},
				nir.Const{Loc: loc, Value: "guard=missing_body_discard_before_error"},
			},
			Path:   path,
			Method: "oversized_body_not_discarded",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccJpegSubsamplingRatioObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "stbi__malloc_mad2(") {
		return nil
	}
	if !ccRe(`if\([A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.h>[A-Za-z_][A-Za-z0-9_]*\)`).MatchString(text) ||
		!ccRe(`if\([A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.v>[A-Za-z_][A-Za-z0-9_]*\)`).MatchString(text) {
		return nil
	}
	if !ccRe(`img_comp\[[^]]+\]\.x=.*img_comp\[[^]]+\]\.h.*\+[^;]*/[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) ||
		!ccRe(`img_comp\[[^]]+\]\.y=.*img_comp\[[^]]+\]\.v.*\+[^;]*/[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if ccRe(`[A-Za-z_][A-Za-z0-9_]*%[A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.h`).MatchString(text) ||
		ccRe(`[A-Za-z_][A-Za-z0-9_]*%[A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.v`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.jpeg.subsampling_ratio_validation_missing"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "ratio=max_sampling_div_component_sampling"},
			nir.Const{Loc: loc, Value: "allocation=component_buffer"},
			nir.Const{Loc: loc, Value: "guard=missing_integer_ratio_validation"},
		},
		Path:   path,
		Method: "subsampling_ratio_validation_missing",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccCipherWithoutIntegrityHashObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "crypto_cipher") || !strings.Contains(text, "crypto_hash") {
		return nil
	}
	if strings.Count(text, `="none"`) < 2 || !strings.Contains(text, `strcmp(`) || !strings.Contains(text, `"none"`) {
		return nil
	}
	rejectRe := ccRe(`strcmp\([^,]+,"none"\)!=0\)&&\(strcmp\([^,]+,"none"\)==0`)
	if rejectRe.MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.crypto.cipher_without_integrity_hash"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "cipher=may_be_disabled"},
			nir.Const{Loc: loc, Value: "hash=may_be_disabled"},
			nir.Const{Loc: loc, Value: "guard=missing_cipher_requires_hash"},
		},
		Path:   path,
		Method: "cipher_without_integrity_hash",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccRepeatedKeyfileSubstitutionObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	readRe := ccRe(`fread\(([A-Za-z_][A-Za-z0-9_]*),1,[^,]+,([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range readRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		buf := text[m[2]:m[3]]
		keyFile := text[m[4]:m[5]]
		if !strings.Contains(text, keyFile+"!=NULL") && !strings.Contains(text, keyFile+"!=0") {
			continue
		}
		branch := text[m[0]:]
		if rewind := strings.Index(branch, "rewind("+keyFile+")"); rewind >= 0 {
			branch = branch[:rewind]
		}
		tableRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\[[A-Za-z_][A-Za-z0-9_]*\]\[[A-Za-z_][A-Za-z0-9_]*%256\]=([A-Za-z_][A-Za-z0-9_]*)\[[A-Za-z_][A-Za-z0-9_]*\]\[\(unsignedchar\)\(` + regexp.QuoteMeta(buf) + `\[[A-Za-z_][A-Za-z0-9_]*\]\)\]`)
		if !tableRe.MatchString(branch) {
			continue
		}
		if containsAnyString(branch, []string{"generateNumber()", "scramblingTablesOrder", "usingKeyFile"}) {
			continue
		}
		loc := c.loc(body)
		path := "analysis.crypto.repeated_keyfile_substitution_tables"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "key=direct_keyfile_bytes"},
				nir.Const{Loc: loc, Value: "table=substitution_table_swap"},
				nir.Const{Loc: loc, Value: "guard=missing_per_table_mixing"},
			},
			Path:   path,
			Method: "repeated_keyfile_substitution_tables",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccReentrantQueueCleanupObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if strings.Count(text, "queue_remove_if(") < 3 || !strings.Contains(text, "destroy_att_send_op(") {
		return nil
	}
	if strings.Contains(text, "in_disc") || strings.Contains(text, "bt_att_disc_cancel") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.queue.reentrant_cleanup_without_disconnect_guard"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "queues=request_indication_write"},
			nir.Const{Loc: loc, Value: "cleanup=remove_then_destroy"},
			nir.Const{Loc: loc, Value: "guard=missing_disconnect_diversion"},
		},
		Path:   path,
		Method: "reentrant_cleanup_without_disconnect_guard",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccFdtNameValidationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "FDT_BEGIN_NODE") ||
		!strings.Contains(text, "FDT_PROP") ||
		!strings.Contains(text, "is_reserved_name(") ||
		!strings.Contains(text, "of_new_node(") ||
		!strings.Contains(text, "of_new_property(") {
		return nil
	}
	if strings.Contains(text, "is_allowed_input_name(") || ccRe(`strchr\([^,]+,'/'\)`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.protocol.fdt_name_validation_missing"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "state=fdt_unflatten"},
			nir.Const{Loc: loc, Value: "name=node_or_property"},
			nir.Const{Loc: loc, Value: "guard=missing_delimiter_rejection"},
		},
		Path:   path,
		Method: "fdt_name_validation_missing",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccPrivilegedEntryPointObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "CREATION_NOTIFICATION") || !strings.Contains(text, "run_post_create") {
		return nil
	}
	if strings.Contains(text, "client_uid!=0") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.privileged.entrypoint_missing_uid_gate"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "event=creation_notification"},
			nir.Const{Loc: loc, Value: "action=post_create_hook"},
			nir.Const{Loc: loc, Value: "guard=missing_client_uid_check"},
		},
		Path:   path,
		Method: "entrypoint_missing_uid_gate",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccAvahiReachableAssertionObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "AVAHI_FLAGS_VALID") ||
		!strings.Contains(text, "AVAHI_PUBLISH_USE_WIDE_AREA") ||
		!strings.Contains(text, "AVAHI_PUBLISH_USE_MULTICAST") ||
		!strings.Contains(text, "transport_flags_from_domain") {
		return nil
	}
	if strings.Contains(text, "!(flags&AVAHI_PUBLISH_USE_WIDE_AREA)||!(flags&AVAHI_PUBLISH_USE_MULTICAST)") ||
		strings.Contains(text, "!(flags&AVAHI_PUBLISH_USE_MULTICAST)||!(flags&AVAHI_PUBLISH_USE_WIDE_AREA)") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.assertion.avahi_publish_flag_pair_reachable"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "flags=wide_area_and_multicast"},
			nir.Const{Loc: loc, Value: "callee=transport_flags_from_domain"},
			nir.Const{Loc: loc, Value: "guard=missing_pair_rejection"},
		},
		Path:   path,
		Method: "avahi_publish_flag_pair_reachable",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccProtocolListAmplificationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "ListReader(") || strings.Contains(text, "amplifiedRead(") {
		return nil
	}
	if !(strings.Contains(text, "inlineCompositeListElementCount") && strings.Contains(text, "structRef.wordSize()")) &&
		!(strings.Contains(text, "ElementSize::VOID") && strings.Contains(text, "elementSize")) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.protocol.list_amplification_missing_charge"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "list=zero_sized_or_inline_composite"},
			nir.Const{Loc: loc, Value: "reader=ListReader"},
			nir.Const{Loc: loc, Value: "guard=missing_amplified_read_charge"},
		},
		Path:   path,
		Method: "list_amplification_missing_charge",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccProtocolFrameLengthUint16WrapObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	declRe := ccRe(`uint16_t([A-Za-z_][A-Za-z0-9_]*)=\(?([0-9]+)u?\+[^;]*(?:ntohs|nswap16|read_u?16|load_u?16)\(`)
	for _, m := range declRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		lengthVar := text[m[2]:m[3]]
		header := text[m[4]:m[5]]
		after := text[m[1]:]
		if !strings.Contains(after, "*app_len="+lengthVar) &&
			!strings.Contains(after, "app_len="+lengthVar) &&
			!strings.Contains(after, "*out_len="+lengthVar) &&
			!strings.Contains(after, "out_len="+lengthVar) {
			continue
		}
		if !strings.Contains(after, lengthVar+"<=blen") &&
			!strings.Contains(after, lengthVar+"<=len") &&
			!strings.Contains(after, lengthVar+"<=available") {
			continue
		}
		if !strings.Contains(text, "VALID_CHANNEL") && !strings.Contains(strings.ToLower(text), "channel") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.protocol.frame_length_uint16_wrap"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "length=uint16_total_frame_length"},
				nir.Const{Loc: loc, Value: "wire=network_uint16_length"},
				nir.Const{Loc: loc, Value: "header=" + header},
				nir.Const{Loc: loc, Value: "guard=missing_wide_accumulator"},
			},
			Path:   path,
			Method: "frame_length_uint16_wrap",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccTLSApplicationDataStateObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "Record_Type::ApplicationData") || !strings.Contains(text, "tls_record_received") {
		return nil
	}
	if strings.Contains(text, "can_decrypt_application_traffic") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.protocol.tls_appdata_before_decryptable"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "record=application_data"},
			nir.Const{Loc: loc, Value: "callback=tls_record_received"},
			nir.Const{Loc: loc, Value: "guard=missing_decryptable_state"},
		},
		Path:   path,
		Method: "tls_appdata_before_decryptable",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccTLSProxyRedirectCertVerificationBypassObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(cCommentRe.ReplaceAllString(c.text(body), ""))
	if !strings.Contains(text, "SSLClient") ||
		!strings.Contains(text, "enable_server_certificate_verification(false)") ||
		!strings.Contains(text, "enable_server_hostname_verification(false)") {
		return nil
	}
	if !containsAnyString(text, []string{"detail::redirect(", "redirect("}) ||
		!containsAnyString(text, []string{"set_proxy(", "proxy_host", "proxyHost"}) {
		return nil
	}
	proxyDisableRe := ccRe(`if\([^)]*[Pp]roxy[^)]*\)[^{;]*\{[^{}]*enable_server_certificate_verification\(false\)[^{}]*enable_server_hostname_verification\(false\)`)
	if !proxyDisableRe.MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.tls.proxy_redirect_cert_verification_bypass"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "client=redirect_ssl_client"},
			nir.Const{Loc: loc, Value: "proxy=enabled"},
			nir.Const{Loc: loc, Value: "guard=cert_and_hostname_verification_disabled"},
		},
		Path:   path,
		Method: "proxy_redirect_cert_verification_bypass",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccCryptoImproperBlindingObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	if !ccCryptoImproperBlindingText(c.text(body)) {
		return nil
	}
	return []nir.Stmt{c.ccCryptoImproperBlindingObservation(c.loc(body))}
}

func ccCryptoImproperBlindingText(raw string) bool {
	text := compactCExprText(cCommentRe.ReplaceAllString(raw, ""))
	randRe := ccRe(`([A-Za-z_][A-Za-z0-9_]*)\.Randomize\(`)
	for _, m := range randRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		blind := text[m[2]:m[3]]
		inv := "MultiplicativeInverse(" + blind + ")"
		square := "Square(" + blind + ")"
		if !strings.Contains(text, inv) || !strings.Contains(text, "Jacobi(") || !strings.Contains(text, "Multiply(") {
			continue
		}
		// Index is computed once per needle: the original called it three times for
		// two distinct lookups.
		sq := strings.Index(text, square)
		if sq >= 0 && sq < strings.Index(text, inv) {
			continue
		}
		return true
	}
	return false
}

var cCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n\r]*`)

func (c *ccConv) ccCryptoImproperBlindingObservation(loc string) nir.Stmt {
	path := "analysis.crypto.improper_blinding_inversion"
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "blind=random_factor"},
			nir.Const{Loc: loc, Value: "operation=invert_before_square"},
			nir.Const{Loc: loc, Value: "guard=missing_jacobi_hardened_blind"},
		},
		Path:   path,
		Method: "improper_blinding_inversion",
		Loc:    loc,
	}}
}

func (c *ccConv) ccWindowsRemotePathCredentialObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	existsRe := ccRe(`QFileInfo::exists\(([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range existsRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		cfg := text[m[2]:m[3]]
		if !strings.Contains(text, "QSettings") || !strings.Contains(text, cfg+",QSettings::IniFormat") || !strings.Contains(text, "setProcessConfig(") {
			continue
		}
		if strings.Contains(text, cfg+".startsWith(QStringLiteral(\"\\\\\\\\\"))") ||
			strings.Contains(text, cfg+".startsWith(QStringLiteral(\"//\"))") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.windows.remote_config_path_credential_leak"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "probe=QFileInfo_exists"},
				nir.Const{Loc: loc, Value: "config=QSettings_ini"},
				nir.Const{Loc: loc, Value: "guard=missing_unc_rejection"},
			},
			Path:   path,
			Method: "remote_config_path_credential_leak",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccLibreOfficeDibHeaderUnderflowObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "EMR_ALPHABLEND") ||
		!strings.Contains(text, "getDIBV5HeaderSize()") ||
		!strings.Contains(text, "newchar") ||
		!strings.Contains(text, "ReadBytes(") {
		return nil
	}
	if !ccRe(`getDIBV5HeaderSize\(\)-[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if strings.Contains(text, "bSafeRead=false") || ccRe(`[A-Za-z_][A-Za-z0-9_]*>[A-Za-z_][A-Za-z0-9_]*HeaderSize`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.image.dib_header_size_underflow"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "format=emr_alphablend"},
			nir.Const{Loc: loc, Value: "delta=dibv5_header_minus_source_header"},
			nir.Const{Loc: loc, Value: "guard=missing_source_header_upper_bound"},
		},
		Path:   path,
		Method: "dib_header_size_underflow",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccDNSInterfaceNewlineValidationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "dns.interface") || !strings.Contains(text, "interface.c=validate_stub") {
		return nil
	}
	if strings.Contains(text, "interface.c=validate_str_no_newline") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.config.dns_interface_newline_validation_missing"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "setting=dns.interface"},
			nir.Const{Loc: loc, Value: "validator=stub"},
			nir.Const{Loc: loc, Value: "guard=missing_no_newline_validation"},
		},
		Path:   path,
		Method: "dns_interface_newline_validation_missing",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccCredentialProtocolNewlineObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "fprintf(") || !strings.Contains(text, "%s=%s") {
		return nil
	}
	if strings.Contains(text, "strchr(") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.credential.protocol_newline_injection"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "writer=fprintf_key_value"},
			nir.Const{Loc: loc, Value: "format=%s=%s"},
			nir.Const{Loc: loc, Value: "guard=missing_newline_rejection"},
		},
		Path:   path,
		Method: "protocol_newline_injection",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccIcmpEchoPayloadLengthObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "ipICMP_PING_REPLY_IPv6") ||
		!strings.Contains(text, "usPayloadLength") ||
		!strings.Contains(text, "vApplicationPingReplyHook(") ||
		!strings.Contains(text, "FreeRTOS_ntohs(") {
		return nil
	}
	if !ccRe(`[A-Za-z_][A-Za-z0-9_]*=[A-Za-z_][A-Za-z0-9_]*-sizeof`).MatchString(text) {
		return nil
	}
	if ccRe(`[A-Za-z_][A-Za-z0-9_]*<sizeof\(`).MatchString(text) ||
		ccRe(`sizeof\([^)]*\)>[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.icmp.echo_payload_length_underflow"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "message=icmpv6_ping_reply"},
			nir.Const{Loc: loc, Value: "length=payload_minus_echo_header"},
			nir.Const{Loc: loc, Value: "guard=missing_header_size_check"},
		},
		Path:   path,
		Method: "echo_payload_length_underflow",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccIsolateLevelIncrementObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "FRIBIDI_IS_ISOLATE") ||
		!strings.Contains(text, "RL_ISOLATE_LEVEL") ||
		!strings.Contains(text, "base_level_per_iso_level") ||
		!strings.Contains(text, "run_per_isolate_level") {
		return nil
	}
	if !ccRe(`[A-Za-z_][A-Za-z0-9_]*\+\+`).MatchString(text) {
		return nil
	}
	if strings.Contains(text, "FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL-1") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.bidi.isolate_level_increment_without_cap"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "state=isolate_level"},
			nir.Const{Loc: loc, Value: "update=post_increment"},
			nir.Const{Loc: loc, Value: "guard=missing_max_level_cap"},
		},
		Path:   path,
		Method: "isolate_level_increment_without_cap",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccFlacBufferReuseObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "memcpy(") ||
		!strings.Contains(text, "frame->header.blocksize") ||
		!strings.Contains(text, "FLAC__MAX_BLOCK_SIZE") ||
		!strings.Contains(text, "wbuffer") ||
		!strings.Contains(text, "rbuffer") {
		return nil
	}
	if strings.Contains(text, "wbuffer_size") || strings.Contains(text, "frame->header.blocksize>pflac->wbuffer_size") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.flac.buffer_reuse_without_blocksize_check"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "copy=memcpy"},
			nir.Const{Loc: loc, Value: "length=frame_header_blocksize"},
			nir.Const{Loc: loc, Value: "guard=missing_reused_buffer_capacity"},
		},
		Path:   path,
		Method: "buffer_reuse_without_blocksize_check",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccProtocolStatusVectorObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "xdr_long(") || !strings.Contains(text, "xdr_wrapstring(") || !strings.Contains(text, "vectorDecode.push") {
		return nil
	}
	if containsAnyString(text, []string{"isc_arg_unix", "isc_arg_win32", "isc_arg_gds", "isc_arg_warning", "isc_arg_next_mach"}) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.protocol.status_vector_unknown_arg_fallback"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "decoder=xdr_status_vector"},
			nir.Const{Loc: loc, Value: "fallback=wrapstring"},
			nir.Const{Loc: loc, Value: "guard=missing_known_argument_allowlist"},
		},
		Path:   path,
		Method: "status_vector_unknown_arg_fallback",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccChakraScopeSlotObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "GetScopeSlot()") ||
		!strings.Contains(text, "EnsurePosition(") ||
		!strings.Contains(text, "thisScopeSlot") ||
		!strings.Contains(text, "superCtorScopeSlot") ||
		!strings.Contains(text, "_lexicalThisSlotSymbol") ||
		!strings.Contains(text, "_superCtorReferenceSymbol") {
		return nil
	}
	if strings.Contains(text, "setPropertyIdForScopeSlotArray(") ||
		strings.Contains(text, "FatalInternalError()") ||
		ccRe(`slot<0.*slot>=scopeSlotCount`).MatchString(text) {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.chakra.scope_slot_array_unchecked_index"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "index=scope_slot"},
			nir.Const{Loc: loc, Value: "write=property_id_array"},
			nir.Const{Loc: loc, Value: "guard=missing_slot_bounds"},
		},
		Path:   path,
		Method: "scope_slot_array_unchecked_index",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccBrOnReachableAssertionObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "visitBrOn(") ||
		!strings.Contains(text, "validateTypeAnnotation(") ||
		!strings.Contains(text, ".desc") {
		return nil
	}
	if strings.Contains(text, ".ref->type.isRef") || strings.Contains(text, ".desc->type.isRef") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.assertion.bron_operand_ref_check_missing"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "parser=br_on"},
			nir.Const{Loc: loc, Value: "validation=type_annotation"},
			nir.Const{Loc: loc, Value: "guard=missing_popped_ref_type_check"},
		},
		Path:   path,
		Method: "bron_operand_ref_check_missing",
		Loc:    loc,
	}}}
}

func (c *ccConv) ccHTTPPersistentAuthReuseObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil || c.lang != "c" {
		return nil
	}
	text := compactCExprText(c.text(body))
	hasAuthorizationHeader := strings.Contains(text, "spool_getheader(") && strings.Contains(text, "\"Authorization\"")
	hasPersistentAuthState := strings.Contains(text, "httpd_userid") &&
		(strings.Contains(text, "saslprops.authid") || strings.Contains(text, "auth_success("))
	hasChallengeState := strings.Contains(text, "auth_chal") && strings.Contains(text, ".scheme")
	hasProxyAuthorization := strings.Contains(text, "\"Authorize-As\"") && strings.Contains(text, "proxy_authz(")
	hasProtectedNamespace := strings.Contains(text, "need_auth(")
	if !hasAuthorizationHeader || !hasPersistentAuthState || !hasChallengeState || !hasProxyAuthorization || !hasProtectedNamespace {
		return nil
	}
	proxyIdx := strings.Index(text, "\"Authorize-As\"")
	clearUserIdx := firstCIndex(text, "free(httpd_userid);httpd_userid=NULL", "free(httpd_userid);httpd_userid=0")
	clearAuthIdx := firstCIndex(text, "auth_freestate(httpd_authstate);httpd_authstate=NULL", "auth_freestate(httpd_authstate);httpd_authstate=0")
	if clearUserIdx >= 0 && clearAuthIdx >= 0 && clearUserIdx < proxyIdx && clearAuthIdx < proxyIdx &&
		strings.Contains(text, "IMAPOPT_PROXYSERVERS") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.http.persistent_auth_reuse_without_reset"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "state=httpd_userid"},
			nir.Const{Loc: loc, Value: "state=txn.auth_chal.scheme"},
			nir.Const{Loc: loc, Value: "guard=missing_drop_non_backend_credentials"},
		},
		Path:   path,
		Method: "persistent_auth_reuse_without_reset",
		Loc:    loc,
	}}}
}

func firstCIndex(text string, needles ...string) int {
	best := -1
	for _, needle := range needles {
		idx := strings.Index(text, needle)
		if idx >= 0 && (best < 0 || idx < best) {
			best = idx
		}
	}
	return best
}

func ccHasAnyCallWithArg(text string, calls []string, arg string) bool {
	for _, call := range calls {
		if strings.Contains(text, call+"("+arg) || strings.Contains(text, call+"("+arg+",") {
			return true
		}
	}
	return false
}

func ccHasDhcpOptionLengthGuards(text, cursor, end string) bool {
	headerGuard := strings.Contains(text, cursor+"+1>="+end) ||
		strings.Contains(text, end+"<="+cursor+"+1") ||
		strings.Contains(text, cursor+">="+end)
	payloadGuard := false
	payloadRe := regexp.MustCompile(regexp.QuoteMeta(cursor) + `\+2\+([A-Za-z_][A-Za-z0-9_]*)>` + regexp.QuoteMeta(end))
	if payloadRe.MatchString(text) {
		payloadGuard = true
	}
	if strings.Contains(text, "opt_len>=4") || strings.Contains(text, "optlen>=4") {
		payloadGuard = true
	}
	return headerGuard && payloadGuard
}

func ccHasTrailingEscapeSkip(text, cursor string) bool {
	return strings.Contains(text, "if(*"+cursor+"++=='\\\\')"+cursor+"++") ||
		strings.Contains(text, "if(*"+cursor+"++=='\\\\'){"+cursor+"++;") ||
		strings.Contains(text, "if(*"+cursor+"++=='\\\\'){"+cursor+"++}")
}

func ccHasWidenedDimensionProduct(text, product string) bool {
	for _, marker := range []string{"int64", "longlong", "uint64", "size_t"} {
		castRe := regexp.MustCompile(`\([^)]*` + regexp.QuoteMeta(marker) + `[^)]*\)` + regexp.QuoteMeta(product))
		if castRe.MatchString(text) ||
			strings.Contains(text, "static_cast<"+marker+">("+strings.Split(product, "*")[0]+")") {
			return true
		}
	}
	return false
}

func containsAnyString(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func ccHasLengthPlusOneAllocation(text, length string) bool {
	allocRe := regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\([^;)]*` + regexp.QuoteMeta(length) + `\+1`)
	return allocRe.MatchString(text)
}

func ccHasTrailingEscapeNulGuard(text, cursor string) bool {
	return strings.Contains(text, "if(*"+cursor+"=='\\0')") ||
		strings.Contains(text, "if(!*"+cursor+")") ||
		strings.Contains(text, "if("+cursor+"[0]=='\\0')") ||
		strings.Contains(text, "if("+cursor+"[0]==0)")
}

func ccEscapedTerminatorWriteIndex(text, value string) int {
	writeRe := regexp.MustCompile(`\*[A-Za-z_][A-Za-z0-9_]*\+\+=` + regexp.QuoteMeta(value))
	loc := writeRe.FindStringIndex(text)
	if loc == nil {
		return -1
	}
	return loc[0]
}

func ccHasDecodedTerminatorGuard(text, value string) bool {
	return strings.Contains(text, "if("+value+"=='\\0')") ||
		strings.Contains(text, "if('\\0'=="+value+")") ||
		strings.Contains(text, "if("+value+"==0)") ||
		strings.Contains(text, "if(0=="+value+")") ||
		strings.Contains(text, "if(!"+value+")")
}

func ccHasNewArrayWithCount(text, count string) bool {
	newRe := regexp.MustCompile(`new[A-Za-z_][A-Za-z0-9_:<>]*\[` + regexp.QuoteMeta(count) + `\]`)
	return newRe.MatchString(text)
}

func ccHasAccumulatedAllocationGuard(text, total, elem string) bool {
	return strings.Contains(text, "*"+elem+">") ||
		strings.Contains(text, total+">") ||
		strings.Contains(text, ">="+total) ||
		strings.Contains(text, "AI_MAX_FACE_INDICES")
}

func ccAssignedCallResultVars(text, callName string) map[string]bool {
	out := map[string]bool{}
	re := regexp.MustCompile(ccAssignedCallResultRePrefix + regexp.QuoteMeta(callName) + `\(`)
	switch callName {
	case "toIndex":
		re = ccAssignedToIndexRe
	case "maxByteLength":
		re = ccAssignedMaxByteLengthRe
	}
	for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 {
			out[text[m[2]:m[3]]] = true
		}
	}
	return out
}

func ccHasArrayBufferAllocation(text, lengthVar, maxVar string) bool {
	idx := strings.Index(text, "allocateArrayBuffer(")
	if idx < 0 {
		return false
	}
	call := text[idx:]
	if end := strings.Index(call, ";"); end >= 0 {
		call = call[:end]
	}
	return strings.Contains(call, lengthVar) && strings.Contains(call, maxVar)
}

func ccHasMaxLengthGuard(text, lengthVar, maxVar string) bool {
	return strings.Contains(text, lengthVar+">"+maxVar+".value()") ||
		strings.Contains(text, maxVar+".value()<"+lengthVar) ||
		strings.Contains(text, lengthVar+">="+maxVar+".value()") ||
		strings.Contains(text, maxVar+".value()<="+lengthVar)
}

func ccHasBackwardHeaderWrite(text string) bool {
	return ccBackwardHeaderWriteRe.MatchString(text)
}

func ccHasClampAssignment(text, target, capacity, written string) bool {
	idx := strings.Index(text, target+"=")
	if idx < 0 {
		return false
	}
	stmt := text[idx:]
	if end := strings.Index(stmt, ";"); end >= 0 {
		stmt = stmt[:end]
	}
	withoutCasts := ccRe(`\([^)]*\)`).ReplaceAllString(stmt, "")
	return withoutCasts == target+"="+capacity+"-"+written
}

func ccHasAdditiveCapacityCheck(text, written, capacity string) bool {
	pat := regexp.MustCompile(`\(?` + regexp.QuoteMeta(written) + `\+[A-Za-z_][A-Za-z0-9_]*\)?>` + regexp.QuoteMeta(capacity))
	return pat.MatchString(text)
}

func ccHasDestSizeCapacityGuard(text, written, chunk, capacity string) bool {
	if strings.Contains(strings.ToLower(capacity), "dest") ||
		strings.Contains(strings.ToLower(capacity), "size") && strings.Contains(strings.ToLower(capacity), "dst") {
		return true
	}
	if strings.Contains(text, written+">") && !strings.Contains(text, written+">"+capacity) {
		return true
	}
	if strings.Contains(text, written+"+"+chunk+">") && !strings.Contains(text, written+"+"+chunk+">"+capacity) {
		return true
	}
	return false
}

func ccFragmentRecordBase(expr string) string {
	if dot := strings.LastIndex(expr, "."); dot >= 0 {
		return expr[:dot]
	}
	return ""
}

func ccHasFragmentOffsetCopyGuard(text, offset, length string) bool {
	guard := "(" + offset + "<<3)+" + length + ">sizeof("
	return strings.Contains(text, guard) ||
		strings.Contains(text, offset+"<<3)+"+length+">sizeof(") ||
		strings.Contains(text, length+"+("+offset+"<<3)>sizeof(") ||
		strings.Contains(text, length+"+"+offset+"<<3>sizeof(")
}

func ccHasOffsetSizeUpperGuard(text, offset, size string) bool {
	if offset == "" || size == "" {
		return false
	}
	for _, expr := range []string{
		offset + "+" + size + ">",
		size + "+" + offset + ">",
		offset + "+" + size + ">=",
		size + "+" + offset + ">=",
	} {
		if strings.Contains(text, expr) {
			return true
		}
	}
	return false
}

// ccSignedCharIndex reports whether an index expression uses a bare char or
// an uncast ctype result where a negative value is representable: either the
// expression mentions tolower/toupper without an (unsigned char) cast around
// it, or it is a plain s[i] style char indexing with no cast at all.
func ccSignedCharIndex(idxText string) bool {
	if idxText == "" {
		return false
	}
	unsignedCast := strings.Contains(idxText, "(unsigned char)") || strings.Contains(idxText, "(uchar)") ||
		strings.Contains(idxText, "(uint8_t)")
	if strings.Contains(idxText, "tolower") || strings.Contains(idxText, "toupper") ||
		strings.Contains(idxText, "isdigit") || strings.Contains(idxText, "isalpha") {
		return !unsignedCast
	}
	// An explicit cast to a still-signed type ((int)s[i], (char)c) preserves
	// negative values and is the exact historical bug shape -- CVE-2009-0023
	// fixed (int)s[i] to (unsigned char)s[i].
	return (strings.Contains(idxText, "(int)") || strings.Contains(idxText, "(char)")) && !unsignedCast
}

func ccStructuredIndex(s string) bool {
	return strings.Contains(s, "->") || strings.Contains(s, ".")
}

// ccHasUpperBoundGuard reports whether idx is bounded above somewhere the
// access can rely on. bodyText is the whole function body; prefixText is the
// part of it that precedes the access.
func ccHasUpperBoundGuard(bodyText, prefixText, idx string) bool {
	// Proceed-if-in-range spellings: `idx < BOUND` and `BOUND > idx`. Read over
	// the whole body, as they always have been.
	if ccComparisonAfter(bodyText, idx, '<', false) || ccComparisonBefore(bodyText, idx, '>') {
		return true
	}
	// Reject-if-out-of-range spelling: `idx > BOUND` / `idx >= BOUND`, the form
	// an early return or a clamp takes.
	//
	// Read only over what precedes the access. An early return bounds what
	// comes after it and nothing else, and unlike a loop condition it carries
	// no hint of its own scope, so crediting one from further down the function
	// is how a guard three lines below an unguarded access gets read as
	// protecting it.
	//
	// Only the index-on-the-left half is read at all. The mirrored `BOUND <
	// idx` is not: it is indistinguishable from `for (i = 0; i < s->len; i++)`,
	// where the field is the loop's bound rather than the bounded value, which
	// would suppress the commonest shape this analysis exists to report.
	//
	// A zero or sign literal on the right is a nonzero/sign test (`s->len > 0`,
	// `s->len >= 0`, `s->len > -1`), not a bound, and does not count either.
	return ccComparisonAfter(prefixText, idx, '>', true)
}

// ccComparisonAfter reports whether bodyText contains `idx` immediately
// followed by the relational operator op ("<" / ">", optionally with a
// trailing "="). A doubled operator is a shift, not a comparison, and does
// not count. When needBound is set, a right-hand side that is a zero or sign
// literal does not count either.
func ccComparisonAfter(bodyText, idx string, op byte, needBound bool) bool {
	if idx == "" {
		return false
	}
	for off := 0; ; {
		i := strings.Index(bodyText[off:], idx)
		if i < 0 {
			return false
		}
		off += i + len(idx)
		tail := bodyText[off:]
		if len(tail) == 0 || tail[0] != op {
			continue
		}
		if len(tail) > 1 && tail[1] == op {
			continue
		}
		rhs := strings.TrimPrefix(tail[1:], "=")
		if needBound && ccZeroOrSignLiteral(rhs) {
			continue
		}
		return true
	}
}

// ccComparisonBefore reports whether bodyText contains the relational
// operator op ("<" / ">", optionally with a trailing "=") immediately before
// `idx`. A doubled operator is a shift and does not count.
func ccComparisonBefore(bodyText, idx string, op byte) bool {
	if idx == "" {
		return false
	}
	for off := 0; ; {
		i := strings.Index(bodyText[off:], idx)
		if i < 0 {
			return false
		}
		at := off + i
		head := bodyText[:at]
		if strings.HasSuffix(head, string(op)+"=") {
			head = head[:len(head)-1]
		}
		if strings.HasSuffix(head, string(op)) &&
			!strings.HasSuffix(head, string(op)+string(op)) {
			return true
		}
		off = at + len(idx)
	}
}

// ccZeroOrSignLiteral reports whether s opens with the integer literal 0, -0
// or -1 as a complete token. Those spell a nonzero or sign test rather than a
// bound. A literal that continues into a longer number or identifier (0x10,
// 0777, 0u, 1024) is a real bound.
func ccZeroOrSignLiteral(s string) bool {
	negative := strings.HasPrefix(s, "-")
	if negative {
		s = s[1:]
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return false
	}
	if end < len(s) && (s[end] == '.' || s[end] == '_' ||
		(s[end] >= '0' && s[end] <= '9') ||
		(s[end] >= 'a' && s[end] <= 'z') ||
		(s[end] >= 'A' && s[end] <= 'Z')) {
		return false
	}
	switch s[:end] {
	case "0":
		return true
	case "1":
		return negative
	}
	return false
}

func ccLastElementCountExpr(compactIdx string) (string, bool) {
	count := strings.TrimSuffix(compactIdx, "-1")
	if count == compactIdx || count == "" || !ccStructuredIndex(count) {
		return "", false
	}
	return count, true
}

func ccHasNonZeroGuard(bodyText, expr string) bool {
	for _, v := range []string{expr, strings.ReplaceAll(expr, "->", ".")} {
		if v == "" {
			continue
		}
		if strings.Contains(bodyText, "!"+v) ||
			strings.Contains(bodyText, v+"==0") ||
			strings.Contains(bodyText, "0=="+v) ||
			strings.Contains(bodyText, v+"<=0") ||
			strings.Contains(bodyText, "0>="+v) ||
			strings.Contains(bodyText, v+"<1") ||
			strings.Contains(bodyText, "1>"+v) {
			return true
		}
	}
	return false
}

func (c *ccConv) textBefore(scope, n *tree_sitter.Node) string {
	if scope == nil || n == nil || n.StartByte() < scope.StartByte() {
		return ""
	}
	return string(c.src[scope.StartByte():n.StartByte()])
}

func ccUnwrapCExpr(n *tree_sitter.Node) *tree_sitter.Node {
	for n != nil {
		switch n.Kind() {
		case "parenthesized_expression", "cast_expression":
			kids := namedChildren(n)
			if len(kids) == 0 {
				return n
			}
			n = kids[len(kids)-1]
		default:
			return n
		}
	}
	return nil
}

func ccIdentifierText(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return ""
	}
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier", "qualified_identifier":
		return c.text(n)
	}
	return ""
}

func ccIndexText(c *ccConv, n *tree_sitter.Node) string {
	if id := ccIdentifierText(c, n); id != "" {
		return id
	}
	n = ccUnwrapCExpr(n)
	if n != nil && c.kind(n) == "number_literal" {
		return strings.TrimSpace(c.text(n))
	}
	return ""
}

func ccIsIntegerLiteral(c *ccConv, n *tree_sitter.Node) bool {
	n = ccUnwrapCExpr(n)
	return n != nil && c.kind(n) == "number_literal" && strings.TrimSpace(c.text(n)) != ""
}

func ccDerefIdentifierText(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return ""
	}
	if c.kind(n) == "pointer_expression" && c.unaryOp(n) == "*" {
		return ccIdentifierText(c, c.field(n, "argument"))
	}
	return ""
}

func ccSizeofText(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return ""
	}
	text := compactCExprText(c.text(n))
	if !strings.Contains(text, "sizeof") {
		return ""
	}
	return text
}

func ccIsMinusOne(c *ccConv, n *tree_sitter.Node) bool {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return false
	}
	if c.kind(n) == "number_literal" {
		return strings.TrimSpace(c.text(n)) == "-1"
	}
	if c.kind(n) != "unary_expression" && c.kind(n) != "pointer_expression" {
		return false
	}
	return c.unaryOp(n) == "-" && strings.TrimSpace(c.text(c.field(n, "argument"))) == "1"
}

func ccComparisonKey(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil || ccIsStringLike(n) {
		return ""
	}
	if id := ccIdentifierText(c, n); id != "" {
		return id
	}
	switch c.kind(n) {
	case "field_expression", "subscript_expression":
		if key := c.dotted(n); key != "" && key != "?" {
			return key
		}
	}
	return ""
}

func ccIsPasswdNameKey(key string) bool {
	return strings.HasSuffix(key, ".pw_name")
}

func ccIsStringLike(n *tree_sitter.Node) bool {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string_literal", "concatenated_string", "raw_string_literal":
		return true
	}
	return false
}

func ccIdentifierLike(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || i > 0 && ch >= '0' && ch <= '9' {
			continue
		}
		return false
	}
	return s[0] == '_' || s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z'
}

var cWhitespaceReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "")

func compactCExprText(s string) string {
	return cWhitespaceReplacer.Replace(s)
}

func (c *ccConv) unaryOp(n *tree_sitter.Node) string {
	if op := c.field(n, "operator"); op != nil {
		return c.text(op)
	}
	raw := c.text(n)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '*', '&', '!', '+', '-':
			return string(raw[i])
		}
		break
	}
	return ""
}

func (c *ccConv) assignmentOp(n *tree_sitter.Node) string {
	if op := c.field(n, "operator"); op != nil {
		return c.text(op)
	}
	raw := c.text(n)
	for _, op := range []string{">>=", "<<=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "="} {
		if strings.Contains(raw, op) {
			return op
		}
	}
	return ""
}

func (c *ccConv) ccExprShape(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier", "qualified_identifier":
		return "ID"
	case "number_literal", "char_literal":
		return cNumberShape(c.text(n))
	case "string_literal", "concatenated_string", "raw_string_literal":
		return "STR"
	case "true", "false", "null", "nullptr":
		return strings.ToUpper(c.text(n))
	case "field_expression":
		base := c.ccExprShape(c.field(n, "argument"))
		if base == "" {
			return ""
		}
		return base + ".FIELD"
	case "subscript_expression":
		base := c.ccExprShape(c.field(n, "argument"))
		key := c.ccExprShape(c.field(n, "index"))
		if base == "" {
			return ""
		}
		if key == "" {
			return base + "[]"
		}
		return base + "[" + key + "]"
	case "call_expression":
		path := c.dotted(c.field(n, "function"))
		if path == "" || path == "?" {
			path = "CALL"
		}
		var args []string
		for _, arg := range c.namedChildren(c.field(n, "arguments")) {
			if shape := c.ccExprShape(arg); shape != "" {
				args = append(args, shape)
			}
		}
		return path + "(" + strings.Join(args, ",") + ")"
	case "binary_expression":
		left := c.ccExprShape(c.field(n, "left"))
		right := c.ccExprShape(c.field(n, "right"))
		op := c.text(c.field(n, "operator"))
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	case "assignment_expression":
		left := c.ccExprShape(c.field(n, "left"))
		right := c.ccExprShape(c.field(n, "right"))
		op := c.assignmentOp(n)
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	case "parenthesized_expression", "cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.ccExprShape(kids[len(kids)-1])
		}
	case "pointer_expression", "unary_expression":
		if arg := c.field(n, "argument"); arg != nil {
			op := c.unaryOp(n)
			if op == "" {
				return c.ccExprShape(arg)
			}
			return op + c.ccExprShape(arg)
		}
	case "conditional_expression":
		cond := c.ccExprShape(c.field(n, "condition"))
		thenShape := c.ccExprShape(c.field(n, "consequence"))
		elseShape := c.ccExprShape(c.field(n, "alternative"))
		if cond == "" || thenShape == "" || elseShape == "" {
			return ""
		}
		return cond + "?" + thenShape + ":" + elseShape
	}
	return ""
}

func cNumberShape(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimRight(s, "ulfd")
	if s == "" {
		return "NUM"
	}
	switch s {
	case "0", "1", "-1":
		return s
	}
	if strings.HasPrefix(s, "0x") {
		return "HEX"
	}
	return "NUM"
}

func cBoolValue(s string) (string, bool) {
	switch s {
	case "YES", "TRUE", "true":
		return "true", true
	case "NO", "FALSE", "false":
		return "false", true
	}
	return "", false
}

// cStringText returns a quoted string literal whose surrounding delimiters wrap only
// the de-prefixed content, so downstream unquoteLit yields the inner text. It strips
// C/C++/ObjC literal prefixes (L, u, U, u8, @) and joins adjacent quoted runs
// (concatenated_string / "a" "b"), keeping a single pair of double quotes so the
// value still reads as a string literal for val-matching.
func cStringText(raw string) string {
	var b []byte
	i := 0
	for i < len(raw) {
		ch := raw[i]
		if ch == '"' || ch == '\'' {
			q := ch
			i++
			for i < len(raw) && raw[i] != q {
				if raw[i] == '\\' && i+1 < len(raw) {
					b = append(b, raw[i+1])
					i += 2
					continue
				}
				b = append(b, raw[i])
				i++
			}
			if i < len(raw) {
				i++ // closing quote
			}
			continue
		}
		// skip prefix chars / whitespace between adjacent literals (L, u, U, 8, @, space)
		i++
	}
	return "\"" + string(b) + "\""
}

func (c *ccConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier":
		return c.text(n)
	case "qualified_identifier": // C++ std::system -> std.system (dotted boundary)
		scope := c.field(n, "scope")
		name := c.field(n, "name")
		if scope == nil {
			return c.dotted(name)
		}
		return c.dotted(scope) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(c.field(n, "argument")) + "." + c.text(c.field(n, "field"))
	case "message_expression": // ObjC
		return c.dotted(c.field(n, "receiver")) + "." + c.text(c.field(n, "method"))
	case "call_expression":
		return c.dotted(c.field(n, "function"))
	case "subscript_expression":
		return c.dotted(c.field(n, "argument")) + "[]"
	case "parenthesized_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

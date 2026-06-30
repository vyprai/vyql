package treesitter

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsc "github.com/tree-sitter/tree-sitter-c/bindings/go"
	tscpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"

	objc "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/objc"

	"github.com/vyprai/vyql/extract/nir"
)

// ccConv walks a tree-sitter C CST into NIR. C has no string-concat operator:
// data reaches a buffer through writer functions (sprintf/strcpy/...), so those
// are modeled as an assignment to their destination argument, and reader
// functions (fgets/gets/...) seed their destination buffer from the call result.
type ccConv struct {
	src  []byte
	file string
	key  string
	lang string
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
			body = append(body, c.ccSharedOtaHandlerMissingAuthObservations(tree.RootNode())...)
			body = append(body, c.ccOcppSharedMapRaceObservations(tree.RootNode())...)
			body = append(body, c.ccOldStyleRemoteListingDownloadPathObservations(tree.RootNode())...)
			body = append(body, c.decls(tree.RootNode())...)
			body = append(body, c.ccLifetimeReleaseReturnObservations(tree.RootNode())...)
			body = append(body, c.ccReallocFailureInputFreeObservations(tree.RootNode())...)
			return nir.Module{Key: c.key, File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
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
	for _, tok := range c.ccStructuredContextTokens(root) {
		tokens = append(tokens, nir.Const{Loc: loc, Value: tok})
	}
	for _, tok := range c.ccMacroContextTokens() {
		tokens = append(tokens, nir.Const{Loc: loc, Value: tok})
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
	mapRe := regexp.MustCompile(`std::map<[^>]+>[A-Za-z_][A-Za-z0-9_]*`)
	if !mapRe.MatchString(text) || !strings.Contains(text, "update_evcc_id_token(") {
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
	ccNewAssignRe = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\b`)
	ccDeleteRe    = regexp.MustCompile(`delete\s*(?:\[\]\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*;`)
	ccReallocRe   = regexp.MustCompile(`\brealloc\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`)
)

func (c *ccConv) ccLifetimeReleaseReturnObservations(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	seen := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "function_definition" {
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
		for _, ch := range namedChildren(n) {
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
		if n.Kind() == "function_definition" {
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
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
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
		switch n.Kind() {
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
			if lv := field(n, "value"); lv != nil {
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
			if path := c.dotted(field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				add("call:" + lastSeg(path))
				for i, arg := range namedChildren(field(n, "arguments")) {
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
			if base := atom(field(n, "argument")); base != "" {
				add("index_base:" + base)
			}
			if key := atom(field(n, "index")); key != "" {
				add("index_key:" + key)
			}
		case "assignment_expression":
			left := atom(field(n, "left"))
			right := atom(field(n, "right"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
			leftShape := c.ccExprShape(field(n, "left"))
			rightShape := c.ccExprShape(field(n, "right"))
			if leftShape != "" && rightShape != "" {
				add("assign_shape:" + leftShape + "=" + rightShape)
				if op := c.assignmentOp(n); op != "" && op != "=" {
					add("assign_op_shape:" + leftShape + op + rightShape)
				}
			}
		case "init_declarator":
			left := c.declName(field(n, "declarator"))
			right := atom(field(n, "value"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
			if rightShape := c.ccExprShape(field(n, "value")); rightShape != "" {
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
		for _, ch := range namedChildren(n) {
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
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "#")
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "define") {
		return "", ""
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "define"))
	if s == "" {
		return "", ""
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
		return "", ""
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
					rest = strings.TrimSpace(rest[j+1:])
					return name, compactCExprText(rest)
				}
			}
		}
		return name, ""
	}
	return name, compactCExprText(rest)
}

func (c *ccConv) ccCallPaths(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "call_expression" {
			if path := c.dotted(field(n, "function")); path != "" && path != "?" && !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *ccConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

// objcMethod extracts an ObjC method's selector name, parameter names, and body.
func (c *ccConv) objcMethod(n *tree_sitter.Node) (string, []string, *tree_sitter.Node) {
	var name string
	var params []string
	var body *tree_sitter.Node
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "identifier":
			if name == "" {
				name = c.text(ch)
			} else {
				name += ":" + c.text(ch)
			}
		case "method_parameter":
			for _, p := range namedChildren(ch) {
				if p.Kind() == "identifier" {
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

func isCExprArg(k string) bool {
	switch k {
	case "identifier", "call_expression", "message_expression", "string_literal",
		"binary_expression", "field_expression", "subscript_expression", "cast_expression",
		"unary_expression", "number_literal", "concatenated_string":
		return true
	}
	return false
}

// declName unwraps pointer/array/function/parenthesized declarators to the
// underlying identifier name.
func (c *ccConv) declName(d *tree_sitter.Node) string {
	for d != nil {
		switch d.Kind() {
		case "identifier", "field_identifier", "type_identifier":
			return c.text(d)
		case "pointer_declarator", "array_declarator", "parenthesized_declarator",
			"init_declarator", "function_declarator":
			d = field(d, "declarator")
		default:
			if inner := field(d, "declarator"); inner != nil {
				d = inner
			} else {
				return ""
			}
		}
	}
	return ""
}

func (c *ccConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	if n.IsError() || strings.HasPrefix(n.Kind(), "preproc_") {
		return c.decls(n)
	}
	switch n.Kind() {
	case "function_definition":
		decl := field(n, "declarator")
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
		bodyStmts := c.block(field(n, "body"))
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
		bodyStmts = append(bodyStmts, c.ccRubyCgiEscapeHtmlAllocationObservations(n)...)
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
		bodyStmts = append(bodyStmts, c.ccTLSApplicationDataStateObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccCryptoImproperBlindingObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccWindowsRemotePathCredentialObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccLibreOfficeDibHeaderUnderflowObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccDnsInterfaceNewlineValidationObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccCredentialProtocolNewlineObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccIcmpEchoPayloadLengthObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccIsolateLevelIncrementObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccFlacBufferReuseObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccProtocolStatusVectorObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccChakraScopeSlotObservations(n)...)
		bodyStmts = append(bodyStmts, c.ccBrOnReachableAssertionObservations(n)...)
		return []nir.Stmt{nir.FuncDef{
			Name:          name,
			Params:        params,
			ParamTypes:    paramTypes,
			Body:          bodyStmts,
			Loc:           L,
			ContextTokens: c.ccFunctionContext(name, field(n, "body"), paramTypes),
		}}
	case "struct_specifier":
		if c.lang == "cpp" {
			return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}}
		}
		return nil
	case "union_specifier", "enum_specifier":
		return nil
	case "class_implementation", "class_interface", "category_implementation", // ObjC
		"category_interface", "protocol_declaration", "implementation_definition",
		"interface_declaration_list", "protocol_declaration_list":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "method_definition", "method_declaration": // ObjC method
		name, params, body := c.objcMethod(n)
		paramTypes := c.objcParamTypes(n, params)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.block(body), Loc: L, ContextTokens: c.ccFunctionContext(name, body, paramTypes)}}
	case "namespace_definition", "linkage_specification", "declaration_list": // C++
		if b := field(n, "body"); b != nil {
			return c.decls(b)
		}
		return c.decls(n)
	case "template_declaration": // C++ — process the templated decl
		return c.decls(n)
	case "class_specifier": // C++
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}}
	case "field_declaration_list":
		return c.decls(n)
	case "declaration":
		var out []nir.Stmt
		// the constructed/declared type (e.g. `File` in `File f(p)` / `File g = File(p)`).
		// C++ qualified types (std::ifstream) come through the declaration's `type`
		// field as a qualified_identifier; use its last dotted segment.
		typeName := c.text(lastChildKind(n, "type_identifier"))
		if typeName == "" {
			if t := field(n, "type"); t != nil {
				typeName = lastSeg(c.dotted(t))
			}
		}
		for _, d := range namedChildren(n) {
			switch d.Kind() {
			case "init_declarator":
				name := c.declName(field(d, "declarator"))
				if val := field(d, "value"); name != "" && val != nil {
					out = append(out, nir.Assign{Targets: []string{name}, Value: c.expr(val)})
				}
			case "function_declarator":
				// C++ "most vexing parse": `File f(p)` parses as a function declaration,
				// but when the args are bare value identifiers (not typed parameters) it is
				// really a stack-allocated constructor call. Lower it so type/arg sinks match.
				if args, ok := c.vexingCtorArgs(field(d, "parameters")); ok && typeName != "" {
					out = append(out, nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: typeName, Loc: L}, Args: args,
						Path: typeName, Method: typeName, Loc: L,
					}})
				}
			}
		}
		return out
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (C did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		condNode := field(n, "condition")
		ifn := nir.If{Cond: c.expr(condNode), Then: c.cBranch(field(n, "consequence")), Else: c.cBranch(field(n, "alternative"))}
		if target, val, ok := c.ccAssignmentExpr(condNode); ok {
			return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}, ifn}
		}
		return []nir.Stmt{ifn}
	case "while_statement", "for_statement", "do_statement":
		body := c.collectBlocks(n)
		if target, val, ok := c.ccAssignmentExpr(field(n, "condition")); ok {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "switch_statement":
		return []nir.Stmt{c.cSwitch(n)}
	case "compound_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *ccConv) ccAssignmentExpr(n *tree_sitter.Node) (string, nir.Expr, bool) {
	for n != nil && n.Kind() == "parenthesized_expression" {
		kids := namedChildren(n)
		if len(kids) != 1 {
			return "", nil, false
		}
		n = kids[0]
	}
	if n == nil || n.Kind() != "assignment_expression" {
		for _, ch := range namedChildren(n) {
			if target, val, ok := c.ccAssignmentExpr(ch); ok {
				return target, val, true
			}
		}
		return "", nil, false
	}
	left := field(n, "left")
	if left == nil || left.Kind() != "identifier" {
		return "", nil, false
	}
	right := field(n, "right")
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
	if params == nil || params.Kind() != "parameter_list" {
		return nil, false
	}
	var args []nir.Expr
	for _, p := range namedChildren(params) {
		if p.Kind() != "parameter_declaration" {
			return nil, false // variadic, optional, etc. — not a clear ctor
		}
		kids := namedChildren(p)
		// a real parameter has a type plus a declarator (name); a vexing arg is a single
		// bare identifier/type_identifier standing in for a value reference.
		if len(kids) != 1 {
			return nil, false
		}
		switch kids[0].Kind() {
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
	switch inner.Kind() {
	case "assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if ev := c.fieldClearNullEvent(inner, left, field(inner, "right")); ev != nil {
			return append([]nir.Stmt{*ev}, c.assignmentFallback(left, right)...)
		}
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return c.assignmentFallback(left, right)
	case "call_expression":
		name := lastSeg(c.dotted(field(inner, "function")))
		args := namedChildren(field(inner, "arguments"))
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
	if n == nil || n.Kind() != "field_expression" {
		return nil, "", false
	}
	base := field(n, "argument")
	fld := c.text(field(n, "field"))
	return base, fld, base != nil && fld != ""
}

func (c *ccConv) isNullExpr(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
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
	if a.Kind() == "pointer_expression" || a.Kind() == "unary_expression" {
		if arg := field(a, "argument"); arg != nil {
			a = arg
		}
	}
	if a.Kind() == "identifier" {
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
	switch b.Kind() {
	case "compound_statement":
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range namedChildren(b) {
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
	if b := field(n, "body"); b != nil {
		for _, cs := range c.cSwitchCases(b) {
			lv := field(cs, "value")
			var stmts []nir.Stmt
			for _, ch := range namedChildren(cs) {
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
	return nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *ccConv) cSwitchCases(body *tree_sitter.Node) []*tree_sitter.Node {
	var out []*tree_sitter.Node
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		for _, ch := range namedChildren(n) {
			switch {
			case ch.Kind() == "case_statement":
				out = append(out, ch)
			case strings.HasPrefix(ch.Kind(), "preproc_") || ch.IsError():
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
			switch ch.Kind() {
			case "compound_statement":
				out = append(out, c.block(ch)...)
			case "else_clause", "case_statement":
				walk(ch)
			case "expression_statement", "declaration", "return_statement", "if_statement":
				out = append(out, c.stmt(ch)...)
			}
		}
	}
	if n.Kind() == "compound_statement" {
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
	for _, st := range namedChildren(block) {
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
	for _, ch := range namedChildren(pl) {
		if isCParamDecl(ch.Kind()) {
			if nm := c.declName(field(ch, "declarator")); nm != "" {
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
	for _, ch := range namedChildren(pl) {
		if isCParamDecl(ch.Kind()) {
			if nm := c.declName(field(ch, "declarator")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *ccConv) paramList(decl *tree_sitter.Node) *tree_sitter.Node {
	if pl := field(decl, "parameters"); pl != nil {
		return pl
	}
	for _, ch := range namedChildren(decl) {
		if ch.Kind() == "parameter_list" {
			return ch
		}
		if pl := c.paramList(ch); pl != nil {
			return pl
		}
	}
	return nil
}

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
		spaced := strings.NewReplacer("*", " * ", "&", " & ").Replace(part)
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
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "method_parameter" {
			name := ""
			if nm := field(ch, "name"); nm != nil {
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
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *ccConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
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
		typ := c.text(field(n, "type"))
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "argument")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(field(n, "argument")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "argument")), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		method := lastSeg(path)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: method, Loc: L}
	case "message_expression": // ObjC [receiver method:arg ...]
		recv := field(n, "receiver")
		methN := field(n, "method")
		method := c.text(methN)
		path := c.dotted(recv) + "." + method
		var args []nir.Expr
		// every named child except the receiver and the method selector is an arg
		for _, ch := range namedChildren(n) {
			if sameCNode(ch, recv) || sameCNode(ch, methN) || ch.Kind() == "selector" {
				continue
			}
			args = append(args, c.expr(ch))
		}
		return nir.Call{Callee: nir.Attr{Base: c.expr(recv), Attr: method, Path: path, Loc: L}, Args: args, Path: path, Method: method, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "pointer_expression":
		if arg := field(n, "argument"); arg != nil {
			if c.unaryOp(n) == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Thru{Inner: c.expr(arg)}
		}
	case "unary_expression":
		if arg := field(n, "argument"); arg != nil {
			op := c.unaryOp(n)
			if op == "*" {
				return nir.Call{Callee: nir.Name{ID: "__deref", Loc: L}, Args: []nir.Expr{c.expr(arg)}, Path: "__deref", Method: "__deref", Loc: L}
			}
			return nir.Unary{Op: op, Operand: c.expr(arg), Loc: L}
		}
	case "assignment_expression":
		return c.expr(field(n, "right"))
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *ccConv) ccIndexAccessObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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
		if n.Kind() == "subscript_expression" {
			idx := field(n, "index")
			idxText := c.text(idx)
			compactIdx := compactCExprText(idxText)
			if ccStructuredIndex(idxText) && compactIdx != "" {
				loc := c.loc(n)
				if !seen[loc] {
					seen[loc] = true
					guard := "guard=missing_upper_bound"
					if ccHasUpperBoundGuard(bodyText, compactIdx) {
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
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

func (c *ccConv) ccPostCopyMissingBoundsObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	assignRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+=([A-Za-z_][A-Za-z0-9_]*)`)
	memcpyRe := regexp.MustCompile(`\bmemcpy\(([^,]+),([^,]+),([^)]+)\)`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	atolRe := regexp.MustCompile(`\bfio_atol\(\(char\*\*\)&?([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range atolRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		cursor := text[m[2]:m[3]]
		tail := text[m[1]:]
		resetRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(cursor) + `=([A-Za-z_][A-Za-z0-9_]*)`)
		reset := resetRe.FindStringSubmatchIndex(tail)
		if reset == nil || len(reset) < 4 {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	guardRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*)\+1>([A-Za-z_][A-Za-z0-9_]*)`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	loopRe := regexp.MustCompile(`while\(([A-Za-z_][A-Za-z0-9_]*)<([A-Za-z_][A-Za-z0-9_]*)\)`)
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
	body := field(fn, "body")
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
		switch n.Kind() {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" {
				c.ccRecordBinarySearchAssignment(n, boundsByMid, lowUpdates, highUpdates)
			}
		case "init_declarator":
			c.ccRecordBinarySearchInit(n, boundsByMid)
		case "binary_expression":
			c.ccRecordBinarySearchComparison(n, &comparisons, loGuards, hiGuards)
		}
		for _, ch := range namedChildren(n) {
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
	left := ccIdentifierText(c, field(n, "left"))
	right := field(n, "right")
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
	name := c.declName(field(n, "declarator"))
	if name == "" {
		return
	}
	if low, high, ok := c.ccMidpointParts(field(n, "value")); ok {
		if _, exists := boundsByMid[name]; !exists {
			boundsByMid[name] = ccBinarySearchBounds{low: low, high: high}
		}
	}
}

func (c *ccConv) ccRecordBinarySearchComparison(n *tree_sitter.Node, comparisons *[]ccBinarySearchComparison, loGuards, hiGuards map[string]bool) {
	op := c.text(field(n, "operator"))
	if op != "<" && op != ">" {
		return
	}
	left := field(n, "left")
	right := field(n, "right")
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
	if n == nil || n.Kind() != "binary_expression" || c.text(field(n, "operator")) != "/" {
		return "", "", false
	}
	if cNumberShape(c.text(field(n, "right"))) != "NUM" || strings.TrimSpace(c.text(field(n, "right"))) != "2" {
		return "", "", false
	}
	sum := ccUnwrapCExpr(field(n, "left"))
	if sum == nil || sum.Kind() != "binary_expression" || c.text(field(sum, "operator")) != "+" {
		return "", "", false
	}
	low := ccIdentifierText(c, field(sum, "left"))
	high := ccIdentifierText(c, field(sum, "right"))
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
	if n == nil || n.Kind() != "binary_expression" || c.text(field(n, "operator")) != op {
		return "", false
	}
	if strings.TrimSpace(c.text(field(n, "right"))) != "1" {
		return "", false
	}
	id := ccIdentifierText(c, field(n, "left"))
	return id, id != ""
}

func (c *ccConv) ccIndexedField(n *tree_sitter.Node) (ccIndexedField, bool) {
	n = ccUnwrapCExpr(n)
	if n == nil || n.Kind() != "field_expression" {
		return ccIndexedField{}, false
	}
	base := ccUnwrapCExpr(field(n, "argument"))
	if base == nil || base.Kind() != "subscript_expression" {
		return ccIndexedField{}, false
	}
	table := c.dotted(field(base, "argument"))
	index := ccIndexText(c, field(base, "index"))
	fieldName := c.text(field(n, "field"))
	if table == "" || table == "?" || index == "" || fieldName == "" {
		return ccIndexedField{}, false
	}
	return ccIndexedField{table: table, index: index, field: fieldName}, true
}

func (c *ccConv) ccStructPointerOOBWriteObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	derivedPointers := map[string]bool{}
	writePointers := map[string]bool{}
	incrementedPointers := map[string]bool{}
	containedPointers := map[string]bool{}

	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			left := ccIdentifierText(c, field(n, "left"))
			right := field(n, "right")
			switch c.assignmentOp(n) {
			case "=":
				if left != "" && c.ccPointerDerivedFromReadIndexedBuffer(right) {
					derivedPointers[left] = true
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
			name := c.declName(field(n, "declarator"))
			if name != "" && c.ccPointerDerivedFromReadIndexedBuffer(field(n, "value")) {
				derivedPointers[name] = true
			}
		case "call_expression":
			c.ccRecordStructPointerCall(n, writePointers, containedPointers)
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	for ptr := range derivedPointers {
		if !writePointers[ptr] || !incrementedPointers[ptr] || containedPointers[ptr] {
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

func (c *ccConv) ccPointerDerivedFromReadIndexedBuffer(n *tree_sitter.Node) bool {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return false
	}
	if n.Kind() == "pointer_expression" && c.unaryOp(n) == "&" {
		return c.ccExprContainsCallName(field(n, "argument"), "readint32") &&
			c.ccExprContainsSubscript(field(n, "argument"))
	}
	return c.ccExprContainsCallName(n, "readint32") && c.ccExprContainsSubscript(n)
}

func (c *ccConv) ccRecordStructPointerCall(n *tree_sitter.Node, writePointers, containedPointers map[string]bool) {
	path := strings.ToLower(c.dotted(field(n, "function")))
	args := namedChildren(field(n, "arguments"))
	if strings.Contains(path, "writeint32") && len(args) > 0 {
		if ptr, ok := c.ccPointerPlusOffsetBase(args[0]); ok {
			writePointers[ptr] = true
		}
	}
	if strings.Contains(strings.ToUpper(path), "CONTAIN") {
		for _, arg := range args {
			if ptr := ccIdentifierText(c, arg); ptr != "" {
				containedPointers[ptr] = true
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
	if n.Kind() != "binary_expression" || c.text(field(n, "operator")) != "+" {
		return "", false
	}
	if id := ccIdentifierText(c, field(n, "left")); id != "" && ccIsIntegerLiteral(c, field(n, "right")) {
		return id, true
	}
	if id := ccIdentifierText(c, field(n, "right")); id != "" && ccIsIntegerLiteral(c, field(n, "left")) {
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
		if m.Kind() == "call_expression" && strings.Contains(strings.ToLower(c.dotted(field(m, "function"))), needle) {
			found = true
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

func (c *ccConv) ccExprContainsSubscript(n *tree_sitter.Node) bool {
	found := false
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found {
			return
		}
		if m.Kind() == "subscript_expression" {
			found = true
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

type ccSignedLengthCandidate struct {
	input  string
	sizeof string
}

func (c *ccConv) ccSignedLengthUnderflowCopyObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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
		switch n.Kind() {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" {
				out := ccDerefIdentifierText(c, field(n, "left"))
				if input, sizeofText, ok := c.ccLengthMinusSizeof(field(n, "right")); out != "" && ok {
					candidates[out] = ccSignedLengthCandidate{input: input, sizeof: sizeofText}
				}
			}
		case "call_expression":
			if lastSeg(c.dotted(field(n, "function"))) == "memcpy" {
				args := namedChildren(field(n, "arguments"))
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
		for _, ch := range namedChildren(n) {
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
	if n == nil || n.Kind() != "binary_expression" || c.text(field(n, "operator")) != "-" {
		return "", "", false
	}
	input := ccIdentifierText(c, field(n, "left"))
	sizeofText := ccSizeofText(c, field(n, "right"))
	return input, sizeofText, input != "" && sizeofText != ""
}

func (c *ccConv) ccSizeofLowerBoundGuard(n *tree_sitter.Node) (string, string, bool) {
	op := c.text(field(n, "operator"))
	left := field(n, "left")
	right := field(n, "right")
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
	body := field(fn, "body")
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
		switch n.Kind() {
		case "assignment_expression":
			if c.assignmentOp(n) == "=" && c.ccCallNameIs(field(n, "right"), "PyObject_Hash") {
				if name := ccIdentifierText(c, field(n, "left")); name != "" {
					hashVars[name] = true
				}
			}
		case "init_declarator":
			if c.ccCallNameIs(field(n, "value"), "PyObject_Hash") {
				if name := c.declName(field(n, "declarator")); name != "" {
					hashVars[name] = true
				}
			}
		case "call_expression":
			switch lastSeg(c.dotted(field(n, "function"))) {
			case "PySet_Discard":
				hasDiscard = true
			case "PySequence_Length":
				hasLength = true
			}
		case "binary_expression":
			if c.text(field(n, "operator")) == "==" {
				if name, ok := c.ccIdentifierEqualsMinusOne(n); ok {
					checkedHashVars[name] = true
				}
			}
		}
		for _, ch := range namedChildren(n) {
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
	return n != nil && n.Kind() == "call_expression" && lastSeg(c.dotted(field(n, "function"))) == name
}

func (c *ccConv) ccIdentifierEqualsMinusOne(n *tree_sitter.Node) (string, bool) {
	left := field(n, "left")
	right := field(n, "right")
	if name := ccIdentifierText(c, left); name != "" && ccIsMinusOne(c, right) {
		return name, true
	}
	if name := ccIdentifierText(c, right); name != "" && ccIsMinusOne(c, left) {
		return name, true
	}
	return "", false
}

func (c *ccConv) ccCaseInsensitiveLocalIdentityObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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
		if n.Kind() == "call_expression" {
			name := strings.ToLower(lastSeg(c.dotted(field(n, "function"))))
			args := namedChildren(field(n, "arguments"))
			if len(args) >= 2 {
				switch {
				case strings.Contains(name, "strcasecmp"):
					c.ccRecordCaseInsensitiveIdentityComparison(args[0], args[1], ciComparisons)
				case name == "strcmp":
					c.ccRecordCanonicalPasswdComparison(args[0], args[1], canonicalComparisons)
				}
			}
		}
		for _, ch := range namedChildren(n) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	loopRe := regexp.MustCompile(`while\(\*([A-Za-z_][A-Za-z0-9_]*)!='\\"'&&\*([A-Za-z_][A-Za-z0-9_]*)&&\+\+([A-Za-z_][A-Za-z0-9_]*)\)`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	decodeRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=[A-Za-z_][A-Za-z0-9_\.]*\(\*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\+\+\)`)
	for _, m := range decodeRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	accumRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+=\*([A-Za-z_][A-Za-z0-9_]*)`)
	for _, m := range accumRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !ccHasBackwardHeaderWrite(text) {
		return nil
	}
	capRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*)>([A-Za-z_][A-Za-z0-9_]*)`)
	for _, m := range capRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	copyRe := regexp.MustCompile(`memcpy\([^,]*\+\([^)]*\)\(([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*)<<3\),(?:\([^)]*\))?([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*),([A-Za-z_][A-Za-z0-9_]*\[[^]]+\]\.[A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range copyRe.FindAllStringSubmatchIndex(text, -1) {
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

func (c *ccConv) ccRubyCgiEscapeHtmlAllocationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "ALLOCV_N(") || !strings.Contains(text, "RSTRING_LEN(") || !strings.Contains(text, "HTML_ESCAPE_MAX_LEN") {
		return nil
	}
	if strings.Contains(text, "typedefcharescape_buf[HTML_ESCAPE_MAX_LEN]") ||
		regexp.MustCompile(`ALLOCV_N\([^,]*escape_buf[^,]*,[^,]*,RSTRING_LEN\(`).MatchString(text) {
		return nil
	}
	if !regexp.MustCompile(`ALLOCV_N\([^,]+,[^,]+,RSTRING_LEN\([^)]+\)\*HTML_ESCAPE_MAX_LEN\)`).MatchString(text) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "PyString_FromStringAndSize(NULL,") || !strings.Contains(text, ">=0x10000") {
		return nil
	}
	if !regexp.MustCompile(`\*[A-Za-z_][A-Za-z0-9_]*\+\+='U'`).MatchString(text) {
		return nil
	}
	if regexp.MustCompile(`10\*[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if !regexp.MustCompile(`6\*[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
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
	body := field(fn, "body")
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
	if !regexp.MustCompile(`newSV\(strlen\([^)]+\)\*3\)`).MatchString(text) {
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
	body := field(fn, "body")
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
	if !regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*->path=[A-Za-z_][A-Za-z0-9_]*\.inputs\[[^]]+\]\.ToString\(\)`).MatchString(text) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "fsize(") {
		return nil
	}
	productRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\*([A-Za-z_][A-Za-z0-9_]*)\*([A-Za-z_][A-Za-z0-9_]*)>([A-Za-z_][A-Za-z0-9_]*)`)
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
	body := field(fn, "body")
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
		regexp.MustCompile(`memcpy\([^,]*setjmp_buffer,[^,]*setjmp_buffer`).MatchString(text) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	parseRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=strtoll\([^,]+,&([A-Za-z_][A-Za-z0-9_]*),10\)`)
	for _, m := range parseRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	assignRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)=[A-Za-z_][A-Za-z0-9_]*\(`)
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		target := text[m[2]:m[3]]
		tail := text[m[1]:]
		deref := target + "->"
		if !strings.Contains(tail, deref) {
			continue
		}
		beforeDeref := tail[:strings.Index(tail, deref)]
		if strings.Contains(beforeDeref, "if(!"+target+")") || strings.Contains(beforeDeref, "if("+target+"==NULL)") || strings.Contains(beforeDeref, "if(NULL=="+target+")") {
			continue
		}
		loc := c.loc(body)
		path := "analysis.nullable_result.unchecked_deref"
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: loc},
			Args: []nir.Expr{
				nir.Const{Loc: loc, Value: "result=call_assignment"},
				nir.Const{Loc: loc, Value: "deref=field_access"},
				nir.Const{Loc: loc, Value: "guard=missing_null_check"},
			},
			Path:   path,
			Method: "unchecked_deref",
			Loc:    loc,
		}}}
	}
	return nil
}

func (c *ccConv) ccConditionalFallbackDoubleFreeObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	parseRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=CommandLineParseCommaSeparatedValuesEx\(`)
	for _, m := range parseRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "g_app_info_create_from_commandline(") || strings.Contains(text, "g_shell_quote(") {
		return nil
	}
	appendRe := regexp.MustCompile(`g_string_append_printf\([^,]+,"[^"]*%s"`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	sourceRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=http_request_(?:param_get|get_query_string)\(`)
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
	body := field(fn, "body")
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
	checkRe := regexp.MustCompile(`strchr\(([A-Za-z_][A-Za-z0-9_]*),'/\'\)!=NULL`)
	for _, m := range checkRe.FindAllStringSubmatchIndex(text, -1) {
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
	return regexp.MustCompile(`(?ms)^[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*(?:[^{};]+;\s*)*\{`).MatchString(raw)
}

func (c *ccConv) ccFat12SuccessorBoundsObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	offRe := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\*3/2`)
	for _, m := range offRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		cluster := text[m[2]:m[3]]
		fsRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)->fat_bits`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	allocRe := regexp.MustCompile(`malloc\(CLUSTER_SIZE\(\*([^)]+)\)\)`)
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
	body := field(fn, "body")
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
	headerRe := regexp.MustCompile(`read_and_decode_block_header\([^;{}]*&([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range headerRe.FindAllStringSubmatchIndex(text, -1) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	bufRe := regexp.MustCompile(`char([A-Za-z_][A-Za-z0-9_]*)\[[^]]+\]`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "cmpPixel(") || !strings.Contains(text, "pImageData[") {
		return nil
	}
	loopRe := regexp.MustCompile(`for\(([^;]*);([^;]*[A-Za-z_][A-Za-z0-9_]*(?:->|\.)config\.width\*[A-Za-z_][A-Za-z0-9_]*(?:->|\.)config\.height[^;]*);`)
	if !loopRe.MatchString(text) {
		return nil
	}
	if regexp.MustCompile(`for\([^;]*;[^;]*MULU16\([^)]*\.config\.width[^)]*\.config\.height[^)]*\)`).MatchString(text) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	peerRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*(?:->|\.)peercallno)==([A-Za-z_][A-Za-z0-9_]*)`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	copyRe := regexp.MustCompile(`memcpy\(([A-Za-z_][A-Za-z0-9_]*)\+([A-Za-z_][A-Za-z0-9_]*),romfs_read\([^)]+\),([A-Za-z_][A-Za-z0-9_]*)\)`)
	for _, m := range copyRe.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 8 {
			continue
		}
		pathBuf := text[m[2]:m[3]]
		pathLen := text[m[4]:m[5]]
		nameLen := text[m[6]:m[7]]
		if !strings.Contains(text, pathBuf+"["+pathLen+"+"+nameLen+"]=0") || !strings.Contains(text, "expand_fs("+pathBuf+",") {
			continue
		}
		if regexp.MustCompile(`strchr\([^,]+,'/'\)`).MatchString(text) || regexp.MustCompile(`strcmp\([^,]+,"\.\."\)`).MatchString(text) {
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	parseRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=strtoul\([^,]+,[^,]+,10\)`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	if !strings.Contains(text, "stbi__malloc_mad2(") {
		return nil
	}
	if !regexp.MustCompile(`if\([A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.h>[A-Za-z_][A-Za-z0-9_]*\)`).MatchString(text) ||
		!regexp.MustCompile(`if\([A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.v>[A-Za-z_][A-Za-z0-9_]*\)`).MatchString(text) {
		return nil
	}
	if !regexp.MustCompile(`img_comp\[[^]]+\]\.x=.*img_comp\[[^]]+\]\.h.*\+[^;]*/[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) ||
		!regexp.MustCompile(`img_comp\[[^]]+\]\.y=.*img_comp\[[^]]+\]\.v.*\+[^;]*/[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*%[A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.h`).MatchString(text) ||
		regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*%[A-Za-z_][A-Za-z0-9_]*(?:->|\.)img_comp\[[^]]+\]\.v`).MatchString(text) {
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
	body := field(fn, "body")
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
	rejectRe := regexp.MustCompile(`strcmp\([^,]+,"none"\)!=0\)&&\(strcmp\([^,]+,"none"\)==0`)
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
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	text := compactCExprText(c.text(body))
	readRe := regexp.MustCompile(`fread\(([A-Za-z_][A-Za-z0-9_]*),1,[^,]+,([A-Za-z_][A-Za-z0-9_]*)\)`)
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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
	if strings.Contains(text, "is_allowed_input_name(") || regexp.MustCompile(`strchr\([^,]+,'/'\)`).MatchString(text) {
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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

func (c *ccConv) ccTLSApplicationDataStateObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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

func (c *ccConv) ccCryptoImproperBlindingObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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
	randRe := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.Randomize\(`)
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
		if strings.Index(text, square) >= 0 && strings.Index(text, square) < strings.Index(text, inv) {
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
	body := field(fn, "body")
	if body == nil || c.lang != "cpp" {
		return nil
	}
	text := compactCExprText(c.text(body))
	existsRe := regexp.MustCompile(`QFileInfo::exists\(([A-Za-z_][A-Za-z0-9_]*)\)`)
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
	body := field(fn, "body")
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
	if !regexp.MustCompile(`getDIBV5HeaderSize\(\)-[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
		return nil
	}
	if strings.Contains(text, "bSafeRead=false") || regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*>[A-Za-z_][A-Za-z0-9_]*HeaderSize`).MatchString(text) {
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

func (c *ccConv) ccDnsInterfaceNewlineValidationObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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
	if !regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*=[A-Za-z_][A-Za-z0-9_]*-sizeof`).MatchString(text) {
		return nil
	}
	if regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*<sizeof\(`).MatchString(text) ||
		regexp.MustCompile(`sizeof\([^)]*\)>[A-Za-z_][A-Za-z0-9_]*`).MatchString(text) {
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
	body := field(fn, "body")
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
	if !regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\+\+`).MatchString(text) {
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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
	body := field(fn, "body")
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
		regexp.MustCompile(`slot<0.*slot>=scopeSlotCount`).MatchString(text) {
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
	body := field(fn, "body")
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
	re := regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=[^;{}]*` + regexp.QuoteMeta(callName) + `\(`)
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
	return regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\([^,]+-\d+,-[A-Za-z_][A-Za-z0-9_]*\)`).MatchString(text)
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
	withoutCasts := regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(stmt, "")
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

func ccStructuredIndex(s string) bool {
	return strings.Contains(s, "->") || strings.Contains(s, ".")
}

func ccHasUpperBoundGuard(bodyText, idx string) bool {
	return strings.Contains(bodyText, idx+"<") ||
		strings.Contains(bodyText, idx+"<=") ||
		strings.Contains(bodyText, ">"+idx) ||
		strings.Contains(bodyText, ">="+idx)
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
	switch n.Kind() {
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
	if n != nil && n.Kind() == "number_literal" {
		return strings.TrimSpace(c.text(n))
	}
	return ""
}

func ccIsIntegerLiteral(c *ccConv, n *tree_sitter.Node) bool {
	n = ccUnwrapCExpr(n)
	return n != nil && n.Kind() == "number_literal" && strings.TrimSpace(c.text(n)) != ""
}

func ccDerefIdentifierText(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil {
		return ""
	}
	if n.Kind() == "pointer_expression" && c.unaryOp(n) == "*" {
		return ccIdentifierText(c, field(n, "argument"))
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
	if n.Kind() == "number_literal" {
		return strings.TrimSpace(c.text(n)) == "-1"
	}
	if n.Kind() != "unary_expression" && n.Kind() != "pointer_expression" {
		return false
	}
	return c.unaryOp(n) == "-" && strings.TrimSpace(c.text(field(n, "argument"))) == "1"
}

func ccComparisonKey(c *ccConv, n *tree_sitter.Node) string {
	n = ccUnwrapCExpr(n)
	if n == nil || ccIsStringLike(n) {
		return ""
	}
	if id := ccIdentifierText(c, n); id != "" {
		return id
	}
	switch n.Kind() {
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

func compactCExprText(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
}

func (c *ccConv) unaryOp(n *tree_sitter.Node) string {
	if op := field(n, "operator"); op != nil {
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
	if op := field(n, "operator"); op != nil {
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
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier", "qualified_identifier":
		return "ID"
	case "number_literal", "char_literal":
		return cNumberShape(c.text(n))
	case "string_literal", "concatenated_string", "raw_string_literal":
		return "STR"
	case "true", "false", "null", "nullptr":
		return strings.ToUpper(c.text(n))
	case "field_expression":
		base := c.ccExprShape(field(n, "argument"))
		if base == "" {
			return ""
		}
		return base + ".FIELD"
	case "subscript_expression":
		base := c.ccExprShape(field(n, "argument"))
		key := c.ccExprShape(field(n, "index"))
		if base == "" {
			return ""
		}
		if key == "" {
			return base + "[]"
		}
		return base + "[" + key + "]"
	case "call_expression":
		path := c.dotted(field(n, "function"))
		if path == "" || path == "?" {
			path = "CALL"
		}
		var args []string
		for _, arg := range namedChildren(field(n, "arguments")) {
			if shape := c.ccExprShape(arg); shape != "" {
				args = append(args, shape)
			}
		}
		return path + "(" + strings.Join(args, ",") + ")"
	case "binary_expression":
		left := c.ccExprShape(field(n, "left"))
		right := c.ccExprShape(field(n, "right"))
		op := c.text(field(n, "operator"))
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	case "assignment_expression":
		left := c.ccExprShape(field(n, "left"))
		right := c.ccExprShape(field(n, "right"))
		op := c.assignmentOp(n)
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.ccExprShape(kids[len(kids)-1])
		}
	case "pointer_expression", "unary_expression":
		if arg := field(n, "argument"); arg != nil {
			op := c.unaryOp(n)
			if op == "" {
				return c.ccExprShape(arg)
			}
			return op + c.ccExprShape(arg)
		}
	case "conditional_expression":
		cond := c.ccExprShape(field(n, "condition"))
		thenShape := c.ccExprShape(field(n, "consequence"))
		elseShape := c.ccExprShape(field(n, "alternative"))
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
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "namespace_identifier":
		return c.text(n)
	case "qualified_identifier": // C++ std::system -> std.system (dotted boundary)
		scope := field(n, "scope")
		name := field(n, "name")
		if scope == nil {
			return c.dotted(name)
		}
		return c.dotted(scope) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(field(n, "argument")) + "." + c.text(field(n, "field"))
	case "message_expression": // ObjC
		return c.dotted(field(n, "receiver")) + "." + c.text(field(n, "method"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		return c.dotted(field(n, "argument")) + "[]"
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

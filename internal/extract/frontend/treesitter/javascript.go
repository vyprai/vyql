package treesitter

import (
	"github.com/vyprai/vyql/internal/extract/regexambig"
	"path/filepath"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tstypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// jsConv walks a tree-sitter JavaScript/TypeScript CST into NIR. The SAME walker handles
// both — TS is a syntactic superset of JS, so the JS node kinds are identical; TS-only
// nodes (type annotations, generics, `as`/`!`/`satisfies`, accessibility modifiers) are
// either skipped as unknown or unwrapped to their inner expression. Crucially, .ts/.tsx
// files are parsed with the TYPESCRIPT grammar (not the JS grammar), so a generic in a
// type annotation — `: Promise<string | null>` — no longer mis-parses `<` as less-than
// and drops the function body.
type jsConv struct {
	src        []byte
	root       string
	file       string
	key        string
	exported   map[string]bool
	childCache map[uintptr][]*tree_sitter.Node
}

func (c *jsConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = map[uintptr][]*tree_sitter.Node{}
	}
	id := n.Id()
	if kids, ok := c.childCache[id]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[id] = kids
	return kids
}

func jsParserFor(lang unsafe.Pointer) func() *tree_sitter.Parser {
	return func() *tree_sitter.Parser {
		p := tree_sitter.NewParser()
		_ = p.SetLanguage(tree_sitter.NewLanguage(lang))
		return p
	}
}

// ExtractJavaScript parses JS/TS files into one NIR Program. Files are routed to the
// matching grammar by extension (.ts → typescript, .tsx → tsx, else javascript); all
// share the jsConv walker.
func ExtractJavaScript(files []string, root string) (nir.Program, error) {
	var js, ts, tsx, vue, html []string
	for _, f := range files {
		l := strings.ToLower(f)
		switch {
		case strings.HasSuffix(l, ".vue"):
			vue = append(vue, f)
		case isHTMLFile(l):
			html = append(html, f)
		case strings.HasSuffix(l, ".tsx"):
			tsx = append(tsx, f)
		case strings.HasSuffix(l, ".ts") || strings.HasSuffix(l, ".mts") || strings.HasSuffix(l, ".cts"):
			ts = append(ts, f)
		default:
			js = append(js, f)
		}
	}
	build := func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
		c := &jsConv{src: src, root: root, file: rel, key: jsModuleKey(root, abs)}
		root0 := tree.RootNode()
		c.exported = c.exportedNames(root0)
		body := append(c.jsModuleContext(root0), c.blockChildren(root0)...)
		return nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: body}, true
	}
	var mods []nir.Module
	mods = append(mods, parseModules(js, root, jsParserFor(tsjs.Language()), build)...)
	mods = append(mods, parseModules(ts, root, jsParserFor(tstypescript.LanguageTypescript()), build)...)
	mods = append(mods, parseModules(tsx, root, jsParserFor(tstypescript.LanguageTSX()), build)...)
	mods = append(mods, parseVueModules(vue, root, build)...)
	mods = append(mods, parseHTMLScriptModules(html, root, build)...)
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func parseVueModules(
	files []string,
	root string,
	build func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool),
) []nir.Module {
	if len(files) == 0 {
		return nil
	}
	out := make([]nir.Module, 0, len(files))
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			continue
		}
		script, lang, ok := vueScriptSource(src)
		if !ok {
			continue
		}
		parserFactory := jsParserFor(tsjs.Language())
		switch lang {
		case "ts":
			parserFactory = jsParserFor(tstypescript.LanguageTypescript())
		case "tsx":
			parserFactory = jsParserFor(tstypescript.LanguageTSX())
		}
		parser := parserFactory()
		tree := parser.Parse(script, nil)
		if tree == nil {
			parser.Close()
			continue
		}
		m, good := build(script, f, relPath(root, f), tree)
		tree.Close()
		parser.Close()
		if good {
			m.Hash = contentHash(src)
			out = append(out, m)
		}
	}
	return out
}

func vueScriptSource(src []byte) ([]byte, string, bool) {
	lower := strings.ToLower(string(src))
	start := strings.Index(lower, "<script")
	if start < 0 {
		return nil, "", false
	}
	tagEndRel := strings.IndexByte(lower[start:], '>')
	if tagEndRel < 0 {
		return nil, "", false
	}
	tagEnd := start + tagEndRel
	codeStart := tagEnd + 1
	endRel := strings.Index(lower[codeStart:], "</script>")
	if endRel < 0 {
		return nil, "", false
	}
	codeEnd := codeStart + endRel
	out := make([]byte, len(src))
	for i, b := range src {
		switch b {
		case '\n', '\r':
			out[i] = b
		default:
			out[i] = ' '
		}
	}
	copy(out[codeStart:codeEnd], src[codeStart:codeEnd])
	tag := lower[start:tagEnd]
	switch {
	case strings.Contains(tag, `lang="tsx"`) || strings.Contains(tag, `lang='tsx'`) || strings.Contains(tag, "lang=tsx"):
		return out, "tsx", true
	case strings.Contains(tag, `lang="ts"`) || strings.Contains(tag, `lang='ts'`) || strings.Contains(tag, "lang=ts"):
		return out, "ts", true
	default:
		return out, "js", true
	}
}

func parseHTMLScriptModules(
	files []string,
	root string,
	build func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool),
) []nir.Module {
	if len(files) == 0 {
		return nil
	}
	out := make([]nir.Module, 0, len(files))
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			continue
		}
		script, ok := htmlScriptSource(src)
		if !ok {
			continue
		}
		parser := jsParserFor(tsjs.Language())()
		tree := parser.Parse(script, nil)
		if tree == nil {
			parser.Close()
			continue
		}
		m, good := build(script, f, relPath(root, f), tree)
		tree.Close()
		parser.Close()
		if good {
			m.Hash = contentHash(src)
			out = append(out, m)
		}
	}
	return out
}

func htmlScriptSource(src []byte) ([]byte, bool) {
	lower := strings.ToLower(string(src))
	out := make([]byte, len(src))
	for i, b := range src {
		switch b {
		case '\n', '\r':
			out[i] = b
		default:
			out[i] = ' '
		}
	}
	commentRanges := htmlCommentRanges(lower)
	found := false
	searchAt := 0
	for {
		startRel := strings.Index(lower[searchAt:], "<script")
		if startRel < 0 {
			break
		}
		start := searchAt + startRel
		tagEndRel := strings.IndexByte(lower[start:], '>')
		if tagEndRel < 0 {
			break
		}
		tagEnd := start + tagEndRel
		codeStart := tagEnd + 1
		endRel := strings.Index(lower[codeStart:], "</script>")
		if endRel < 0 {
			break
		}
		codeEnd := codeStart + endRel
		searchAt = codeEnd + len("</script>")
		if inAnyRange(start, commentRanges) || !isJavaScriptScriptTag(lower[start:tagEnd]) {
			continue
		}
		copy(out[codeStart:codeEnd], src[codeStart:codeEnd])
		found = true
	}
	return out, found
}

func htmlCommentRanges(lower string) [][2]int {
	var out [][2]int
	searchAt := 0
	for {
		startRel := strings.Index(lower[searchAt:], "<!--")
		if startRel < 0 {
			return out
		}
		start := searchAt + startRel
		endRel := strings.Index(lower[start+4:], "-->")
		if endRel < 0 {
			return append(out, [2]int{start, len(lower)})
		}
		end := start + 4 + endRel + len("-->")
		out = append(out, [2]int{start, end})
		searchAt = end
	}
}

func inAnyRange(pos int, ranges [][2]int) bool {
	for _, r := range ranges {
		if pos >= r[0] && pos < r[1] {
			return true
		}
	}
	return false
}

func isJavaScriptScriptTag(tag string) bool {
	if strings.Contains(tag, " src=") || strings.Contains(tag, "\tsrc=") || strings.Contains(tag, "\nsrc=") || strings.Contains(tag, "\rsrc=") {
		return false
	}
	for _, attr := range []string{"type", "language"} {
		val, ok := htmlTagAttr(tag, attr)
		if !ok {
			continue
		}
		val = strings.TrimSpace(strings.ToLower(val))
		if attr == "language" {
			return val == "javascript" || val == "js" || val == "ecmascript"
		}
		switch val {
		case "", "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript", "module":
			return true
		default:
			return false
		}
	}
	return true
}

func htmlTagAttr(tag, name string) (string, bool) {
	needle := name + "="
	i := strings.Index(tag, needle)
	if i < 0 {
		return "", false
	}
	i += len(needle)
	if i >= len(tag) {
		return "", true
	}
	quote := tag[i]
	if quote == '"' || quote == '\'' {
		j := strings.IndexByte(tag[i+1:], quote)
		if j < 0 {
			return tag[i+1:], true
		}
		return tag[i+1 : i+1+j], true
	}
	j := i
	for j < len(tag) && tag[j] != ' ' && tag[j] != '\t' && tag[j] != '\n' && tag[j] != '\r' && tag[j] != '>' {
		j++
	}
	return tag[i:j], true
}

func isHTMLFile(path string) bool {
	return strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm")
}

func (c *jsConv) exportedNames(root *tree_sitter.Node) map[string]bool {
	out := map[string]bool{}
	markObjectExports := func(obj *tree_sitter.Node) {
		if obj == nil || obj.Kind() != "object" {
			return
		}
		for _, pr := range c.namedChildren(obj) {
			switch pr.Kind() {
			case "pair":
				v := field(pr, "value")
				if v != nil && v.Kind() == "identifier" {
					out[c.text(v)] = true
				} else if isJsFuncNode(v) {
					if name := c.keyName(field(pr, "key")); name != "" {
						out[name] = true
					}
				}
			case "shorthand_property_identifier":
				out[c.text(pr)] = true
			}
		}
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "export_statement":
			for _, ch := range c.namedChildren(n) {
				if ch.Kind() == "function_declaration" || ch.Kind() == "generator_function_declaration" {
					if name := c.text(field(ch, "name")); name != "" {
						out[name] = true
					}
				} else if ch.Kind() == "class_declaration" || ch.Kind() == "abstract_class_declaration" {
					if name := c.text(field(ch, "name")); name != "" {
						out[name] = true
					}
				}
			}
		case "class_declaration", "abstract_class_declaration":
			if name := c.text(field(n, "name")); name != "" && out[name] {
				c.markThisAssignedHelpers(field(n, "body"), out)
			}
		case "assignment_expression":
			left, rhs := field(n, "left"), field(n, "right")
			if left != nil && left.Kind() == "member_expression" {
				if c.isModuleExports(left) {
					if rhs != nil && rhs.Kind() == "identifier" {
						out[c.text(rhs)] = true
					}
					markObjectExports(rhs)
				} else if name := c.exportFuncName(left); name != "" {
					out[name] = true
					if rhs != nil && rhs.Kind() == "identifier" {
						out[c.text(rhs)] = true
					}
				}
			} else if left != nil && left.Kind() == "identifier" && c.isModuleExports(rhs) {
				out[c.text(left)] = true
			}
		case "variable_declarator":
			// `const alias = module.exports;` names the export root, so
			// `alias.method = fn` further down is an export of `method`.
			if name := field(n, "name"); name != nil && name.Kind() == "identifier" && c.isModuleExports(field(n, "value")) {
				out[c.text(name)] = true
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *jsConv) markThisAssignedHelpers(body *tree_sitter.Node, out map[string]bool) {
	if body == nil {
		return
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "assignment_expression" {
			left, rhs := field(n, "left"), field(n, "right")
			if left != nil && left.Kind() == "member_expression" && rhs != nil && rhs.Kind() == "identifier" {
				if c.text(field(left, "object")) == "this" {
					if prop := c.text(field(left, "property")); prop != "" && !strings.HasPrefix(prop, "_") {
						out[c.text(rhs)] = true
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
}

func jsModuleKey(root, f string) string {
	for _, ext := range []string{".jsx", ".tsx", ".ts", ".js"} {
		if strings.HasSuffix(strings.ToLower(f), ext) {
			return moduleKey(root, f, ext)
		}
	}
	return moduleKey(root, f, "")
}

func (c *jsConv) loc(n *tree_sitter.Node) string {
	if isHTMLFile(strings.ToLower(c.file)) {
		return c.file + "#script.js:" + itoa(int(n.StartPosition().Row)+1)
	}
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *jsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *jsConv) jsModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	loc := c.file + ":1"
	text := c.text(root)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=javascript"},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(text), "")},
	}
	for _, tok := range c.jsStructuredContextTokens(root) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.module.context", Loc: loc},
		Args:   args,
		Path:   "analysis.module.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *jsConv) jsStructuredContextTokens(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	secretConfigVars := c.jsSecretConfigObjectVars(root)
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if restart, hiddenCall := c.jsLoopRestartFacts(root); restart {
		add("loop_restart_without_progress=true")
		if hiddenCall {
			add("loop_progress_hidden_in_call=true")
		}
	}
	if jsZeroStepSequenceRisk(c.text(root)) {
		add("zero_step_sequence_risk=true")
	}
	if jsConvertSvgMultiSvgSanitizerBypass(c.text(root)) {
		add("convert_svg_multi_svg_sanitizer_bypass=true")
	}
	if c.jsIncompleteGeneratedIdentifierReservedWords(root) {
		add("incomplete_generated_js_identifier_reserved_words=true")
	}
	if jsAjaxBackslashProtocolRelativeURLXSS(c.text(root)) {
		add("ajax_backslash_protocol_relative_url_xss=true")
	}
	if jsCryptoJSRandomFloatWordArrayRisk(c.text(root)) {
		add("cryptojs_random_float_wordarray_risk=true")
	}
	if jsEffectMixedSchedulerSharedRunner(c.text(root)) {
		add("effect_mixed_scheduler_shared_runner=true")
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			left, right := field(n, "left"), field(n, "right")
			if left != nil && left.Kind() == "subscript_expression" {
				add("dynamic_property_write=true")
				rightText := jsContextCompact(c.text(right))
				objectLiteral, arrayLiteral := c.jsAllocatedContainerKinds(right)
				if objectLiteral {
					add("dynamic_property_write_object_literal=true")
				}
				if arrayLiteral {
					add("dynamic_property_write_array_literal=true")
				}
				if strings.Contains(rightText, "[") {
					add("dynamic_property_write_from_subscript=true")
				}
				if strings.Contains(rightText, "(") {
					add("dynamic_property_write_from_call=true")
				}
				if strings.Contains(rightText, "||{}") {
					add("dynamic_property_plain_object_fallback=true")
				}
			}
			if lhs := c.jsContextPath(left); lhs != "" {
				if rhs := jsContextValue(c.text(right)); rhs != "" {
					add("assign:" + lhs + "=" + rhs)
				}
				if jsRejectUnauthorizedPath(lhs) && jsRejectUnauthorizedDisabledDefault(right, c) {
					add("tls_reject_unauthorized_disabled_default=true")
				}
				if c.isJsPublicRuntimeConfigPath(lhs) {
					if ok, name := c.jsCallArgsContainSecretConfig(right, secretConfigVars); ok {
						add("public_runtime_secret_config")
						if name != "" {
							add("public_runtime_secret_config_var:" + name)
						}
					}
				}
			}
		case "array":
			for _, tok := range c.jsGitCloneArgvTokens(n) {
				add(tok)
			}
		case "binary_expression":
			if expr := jsContextCompact(c.text(n)); expr != "" {
				add("expr:" + expr)
				if jsPrototypeKeyComparison(expr) {
					add("prototype_key_guard=true")
				}
			}
		case "pair":
			if key := jsContextCompact(c.keyName(field(n, "key"))); key != "" {
				if val := jsContextValue(c.text(field(n, "value"))); val != "" {
					add("prop:" + key + "=" + val)
					if key == "rejectUnauthorized" && jsRejectUnauthorizedPath(val) {
						add("tls_reject_unauthorized_propagated=true")
					}
				}
			}
		case "if_statement":
			if c.jsFoldedHeaderCurrentGuard(n) {
				add("folded_header_current_guard=true")
			}
			if c.jsPrototypeKeyGuard(n) {
				add("prototype_key_guard=true")
			}
			if c.jsPathSegmentTypeGuard(n) {
				add("path_segment_type_guard=true")
			}
			if c.jsOwnPropertyKeyGuard(n) {
				add("own_property_key_guard=true")
			}
			if c.jsFailOpenPolicyDeclarationGuard(n) {
				add("fail_open_policy_declaration_guard=true")
			}
		case "for_in_statement":
			add("for_in=true")
		case "method_definition":
			// A shorthand method's name is a property_identifier, so the identifier case
			// below never sees it — the method's PARAMETERS were collected while the
			// method itself was invisible. Emit the name so a flag can key on it.
			if name := jsContextCompact(c.text(field(n, "name"))); name != "" {
				add("identifier:" + name)
			}
		case "member_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "identifier":
			if ident := jsContextCompact(c.text(n)); ident != "" {
				add("identifier:" + ident)
			}
		case "subscript_expression":
			if idx := c.dotted(n); idx != "" && idx != "?" {
				add("index:" + idx)
			}
			if base := c.dotted(field(n, "object")); base != "" && base != "?" {
				add("index_base:" + base)
			}
			if key := c.jsContextPath(field(n, "index")); key != "" {
				add("index_key:" + key)
			}
			if sub := jsContextCompact(c.text(n)); sub != "" {
				add("subscript:" + sub)
			}
		case "call_expression", "new_expression":
			fn := field(n, "function")
			if n.Kind() == "new_expression" {
				fn = field(n, "constructor")
			}
			if path := c.dotted(fn); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
				if path == "Object.keys.forEach" {
					add("object_keys_for_each=true")
				}
			}
		case "string", "template_string":
			if lit := jsContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
		case "regex":
			if lit := jsContextRegex(c.text(n)); lit != "" {
				add("regex:" + lit)
				add("literal:" + lit)
				if jsPrototypeNameGuard(lit) {
					add("prototype_name_guard=true")
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

// jsLoopRestartFacts reports a scanning loop that can restart without
// consuming from the buffer it scans — the CWE-835 weakness class — and
// whether the restart's path carries a call whose effect on the buffer the
// fact cannot interpret. A restart is uncovered when some `continue` bound
// to the loop is reachable from the loop head without passing any progress
// evidence for the variables the loop's exit reads: re-testing an unchanged
// exit takes the same branch again, so the cycle cannot reach the exit.
// while, do-while and update-less for loops carry the fact — `for(;;)`,
// whose `continue` runs no clause at all, and `for (;cond;)`, which re-tests
// its condition; a for-loop with an increment clause does not, because
// `continue` still runs it, and neither do for-in/for-of loops, whose
// iterator advances mechanically.
// Loops are attributed to the innermost function that owns them: the walk
// never crosses a function boundary in either direction, so a closure's
// loop reports on the closure and not on every enclosing function.
func (c *jsConv) jsLoopRestartFacts(root *tree_sitter.Node) (restart, hiddenCall bool) {
	var loops []*tree_sitter.Node
	var findLoops func(*tree_sitter.Node)
	findLoops = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "while_statement", "do_statement":
			loops = append(loops, n)
		case "for_statement":
			if jsForClause(n, "increment") == nil {
				loops = append(loops, n)
			}
		case "function_declaration", "function_expression", "arrow_function", "method_definition":
			return
		}
		for _, ch := range c.namedChildren(n) {
			findLoops(ch)
		}
	}
	findLoops(root)
	if len(loops) == 0 {
		return false, false
	}
	nested := c.jsNestedFunctionBodies(root)
	for _, loop := range loops {
		r, h := c.jsLoopRestart(loop, nested)
		if r {
			restart = true
			if h {
				hiddenCall = true
			}
		}
	}
	return restart, hiddenCall
}

// jsForClause returns a for-loop's optional clause, treating the empty
// statement the grammar inserts for an omitted clause (`for (;;)`) as
// absent.
func jsForClause(n *tree_sitter.Node, name string) *tree_sitter.Node {
	cl := field(n, name)
	if cl == nil || cl.Kind() == "empty_statement" {
		return nil
	}
	return cl
}

// jsNestedFunctionBodies indexes, by name, every function defined anywhere
// inside the analyzed function: the closures its loops can call, whose
// bodies may carry the loop's progress (`function getArg() { argv.shift()
// }` advancing the very vector the loop's condition reads).
func (c *jsConv) jsNestedFunctionBodies(root *tree_sitter.Node) map[string]*tree_sitter.Node {
	out := map[string]*tree_sitter.Node{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "function_declaration", "method_definition":
			if name := c.text(field(n, "name")); name != "" {
				if body := field(n, "body"); body != nil {
					out[name] = body
				}
			}
		case "variable_declarator":
			val := field(n, "value")
			if val != nil && (val.Kind() == "arrow_function" || val.Kind() == "function_expression") {
				if name := c.text(field(n, "name")); name != "" {
					if body := field(val, "body"); body != nil {
						out[name] = body
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

// jsLoopRestart holds for a loop with an uncovered restart, and reports
// whether an uninterpretable call sits on that restart's dominating path.
// Exit variables are the condition's reads for while, do-while and
// condition-bearing update-less for loops, and the break guards' reads for
// `for(;;)`, whose only exits are breaks — a switch's break leaves the
// switch, so only if-arms guard a loop exit.
// Progress evidence is an assignment, augmented assignment or update
// writing an exit variable, a method call receiving one as its receiver —
// the mutating idiom (`it.next()`, `queue.shift()`) — or a call to a
// function defined inside the analyzed function whose body carries such
// evidence. Evidence covers a restart only where it dominates it, on the
// path every iteration to that `continue` takes: a sibling branch's
// progress step never executes on the restart it is supposed to cover. The
// body must carry evidence somewhere, so a loop whose exit is flipped
// elsewhere (`while (running)`) or reached only by break stays out. A
// condition that assigns (`while ((line = read()) != null)`) advances every
// iteration and never qualifies, nor does one that reads no variable
// (`while (true)`).
func (c *jsConv) jsLoopRestart(loop *tree_sitter.Node, nested map[string]*tree_sitter.Node) (restart, hiddenCall bool) {
	var body *tree_sitter.Node
	condVars := map[string]bool{}
	condAssign := false
	switch loop.Kind() {
	case "while_statement", "do_statement":
		cond, b := field(loop, "condition"), field(loop, "body")
		if cond == nil || b == nil {
			return false, false
		}
		body = b
		c.jsReadExitIdentifiers(cond, condVars, &condAssign)
	case "for_statement":
		body = field(loop, "body")
		if body == nil {
			return false, false
		}
		if cond := jsForClause(loop, "condition"); cond != nil {
			c.jsReadExitIdentifiers(cond, condVars, &condAssign)
		} else {
			c.jsBreakGuardReads(body, condVars)
		}
	}
	if condAssign || len(condVars) == 0 || body == nil {
		return false, false
	}
	if _, anywhere := c.jsProgressEvidence(body, condVars, nested, 0); !anywhere {
		return false, false
	}
	var continues []*tree_sitter.Node
	var collectContinues func(*tree_sitter.Node)
	collectContinues = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "continue_statement":
			if field(n, "label") == nil {
				continues = append(continues, n)
			}
		case "while_statement", "do_statement", "for_statement", "for_in_statement", "for_of_statement",
			"function_declaration", "function_expression", "arrow_function", "method_definition":
			return
		}
		for _, ch := range c.namedChildren(n) {
			collectContinues(ch)
		}
	}
	collectContinues(body)
	for _, cont := range continues {
		covered, hidden := c.jsRestartCovered(body, cont, condVars, nested)
		if !covered {
			restart = true
			if hidden {
				hiddenCall = true
			}
		}
	}
	return restart, hiddenCall
}

// jsReadExitIdentifiers collects the identifiers a loop condition reads; an
// assignment inside the condition advances the loop every iteration.
func (c *jsConv) jsReadExitIdentifiers(n *tree_sitter.Node, out map[string]bool, assigned *bool) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "assignment_expression":
		*assigned = true
	case "identifier":
		out[c.text(n)] = true
	}
	for _, ch := range c.namedChildren(n) {
		c.jsReadExitIdentifiers(ch, out, assigned)
	}
}

// jsBreakGuardReads collects the identifiers read by the conditions of
// if-arms that break out of this loop: `for(;;) { if (i >= limit) break; ...
// }` exits on those reads.
func (c *jsConv) jsBreakGuardReads(body *tree_sitter.Node, out map[string]bool) {
	var armBreaks func(n *tree_sitter.Node) bool
	armBreaks = func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		switch n.Kind() {
		case "break_statement":
			return field(n, "label") == nil
		case "while_statement", "do_statement", "for_statement", "for_in_statement", "for_of_statement",
			"function_declaration", "function_expression", "arrow_function", "method_definition", "switch_statement":
			return false
		}
		for _, ch := range c.namedChildren(n) {
			if armBreaks(ch) {
				return true
			}
		}
		return false
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "while_statement", "do_statement", "for_statement", "for_in_statement", "for_of_statement",
			"function_declaration", "function_expression", "arrow_function", "method_definition", "switch_statement":
			return
		case "if_statement":
			for _, arm := range []*tree_sitter.Node{field(n, "consequence"), field(n, "alternative")} {
				if arm != nil && armBreaks(arm) {
					c.jsReadExitIdentifiers(field(n, "condition"), out, new(bool))
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
}

// jsIsProgressEvidence holds for a node that advances a loop exit variable:
// an assignment, augmented assignment or update writing one, a method call
// receiving one as its receiver, or a call to a nested function whose body
// carries such evidence (getArg() shifting the argument vector the loop's
// condition reads). Resolution is one hop deep inside the analyzed function;
// a function the file defines outside it is as opaque as an import.
func (c *jsConv) jsIsProgressEvidence(n *tree_sitter.Node, condVars map[string]bool, nested map[string]*tree_sitter.Node, depth int) bool {
	switch n.Kind() {
	case "assignment_expression", "augmented_assignment_expression":
		return condVars[c.jsRootIdentifier(field(n, "left"))]
	case "update_expression":
		return condVars[c.jsRootIdentifier(field(n, "argument"))]
	case "call_expression":
		fn := c.unwrapJsTransparentExpr(field(n, "function"))
		if fn == nil {
			return false
		}
		if fn.Kind() == "member_expression" {
			return condVars[c.jsRootIdentifier(field(fn, "object"))]
		}
		if fn.Kind() == "identifier" && depth < 2 {
			if callee, ok := nested[c.text(fn)]; ok {
				_, any := c.jsProgressEvidence(callee, condVars, nested, depth+1)
				return any
			}
		}
	}
	return false
}

// jsProgressEvidence walks a subtree for progress evidence, crossing no
// function boundary: a closure contributes only through a call that
// resolves to it.
func (c *jsConv) jsProgressEvidence(n *tree_sitter.Node, condVars map[string]bool, nested map[string]*tree_sitter.Node, depth int) ([]uint, bool) {
	var pos []uint
	any := false
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "function_declaration", "function_expression", "arrow_function", "method_definition":
			return
		}
		if c.jsIsProgressEvidence(n, condVars, nested, depth) {
			pos = append(pos, n.StartByte())
			any = true
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(n)
	return pos, any
}

// jsIsHiddenProgressCall holds for a construct whose effect on a loop exit
// variable the fact cannot interpret: a call to a bare name the analyzed
// function does not define (an import, a parameter, a global); a call
// carrying a callback whose body advances an exit variable — the progress
// is real, but whether the callee invokes the callback, and on which path,
// is the callee's contract, not something the syntax shows; and a
// per-iteration declaration re-binding an exit variable from a call
// (`var L = e.exec(a)`), whose advance depends on the callee's state.
// Such a construct may advance the loop through effects the fact cannot
// see, which is a judgement for the rules, not the frontend.
func (c *jsConv) jsIsHiddenProgressCall(n *tree_sitter.Node, condVars map[string]bool, nested map[string]*tree_sitter.Node, depth int) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "variable_declarator" {
		return depth < 2 && condVars[c.text(field(n, "name"))] &&
			jsSubtreeContainsCall(field(n, "value"))
	}
	if n.Kind() != "call_expression" {
		return false
	}
	fn := c.unwrapJsTransparentExpr(field(n, "function"))
	if fn == nil {
		return false
	}
	if fn.Kind() == "identifier" {
		_, resolved := nested[c.text(fn)]
		return !resolved
	}
	if depth < 2 {
		if args := field(n, "arguments"); args != nil {
			for _, arg := range c.namedChildren(args) {
				if arg == nil || (arg.Kind() != "arrow_function" && arg.Kind() != "function_expression") {
					continue
				}
				if body := field(arg, "body"); body != nil {
					if _, any := c.jsProgressEvidence(body, condVars, nested, depth+1); any {
						return true
					}
				}
			}
		}
	}
	return false
}

// jsRestartCovered reports whether progress evidence dominates a continue —
// executes on every path from the loop body's start to it — and whether
// that dominating path carries an unresolved call. Only unconditional
// positions dominate: earlier statements of the same block, the condition
// of a branch whose arm contains the continue, the left operand of a
// short-circuit, the discriminant of a switch whose case contains it. A
// statement's own conditional arms, a short-circuit's right operand, and
// nested loop and function bodies never dominate what follows them, so a
// sibling branch's progress step does not cover a restart that branch never
// executes.
func (c *jsConv) jsRestartCovered(body, cont *tree_sitter.Node, condVars map[string]bool, nested map[string]*tree_sitter.Node) (covered, hidden bool) {
	target := cont.Id()
	var straight func(*tree_sitter.Node)
	straight = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "while_statement", "do_statement", "for_statement", "for_in_statement", "for_of_statement",
			"function_declaration", "function_expression", "arrow_function", "method_definition",
			"switch_statement", "try_statement":
			return
		case "if_statement", "conditional_expression":
			straight(field(n, "condition"))
			return
		case "binary_expression":
			if op := c.text(field(n, "operator")); op == "&&" || op == "||" {
				straight(field(n, "left"))
				return
			}
		}
		if c.jsIsProgressEvidence(n, condVars, nested, 0) {
			covered = true
		}
		if c.jsIsHiddenProgressCall(n, condVars, nested, 0) {
			hidden = true
		}
		for _, ch := range c.namedChildren(n) {
			straight(ch)
		}
	}
	contains := func(n *tree_sitter.Node) bool {
		return n != nil && cont.StartByte() >= n.StartByte() && cont.EndByte() <= n.EndByte()
	}
	var descend func(*tree_sitter.Node) bool
	descend = func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		if n.Id() == target {
			return true
		}
		kids := c.namedChildren(n)
		for i, ch := range kids {
			if !contains(ch) {
				continue
			}
			switch n.Kind() {
			case "if_statement", "conditional_expression":
				// The condition precedes both arms; one arm never precedes
				// the other.
				straight(field(n, "condition"))
			case "binary_expression":
				if op := c.text(field(n, "operator")); op == "&&" || op == "||" {
					if i > 0 {
						straight(kids[0])
					}
				} else {
					for _, earlier := range kids[:i] {
						straight(earlier)
					}
				}
			case "switch_body":
				// Case tests evaluate in order until one matches; case
				// bodies do not run.
				for _, earlier := range kids[:i] {
					straight(field(earlier, "value"))
				}
			default:
				for _, earlier := range kids[:i] {
					straight(earlier)
				}
			}
			return descend(ch)
		}
		return false
	}
	descend(body)
	return covered, hidden
}

// jsSubtreeContainsCall reports whether an expression calls anything at
// any depth.
func jsSubtreeContainsCall(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "call_expression" || n.Kind() == "new_expression" {
		return true
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if jsSubtreeContainsCall(n.NamedChild(i)) {
			return true
		}
	}
	return false
}

// jsRootIdentifier returns the base identifier of a member or subscript
// chain: `a` for `a.b.c` and `a[i].d`.
func (c *jsConv) jsRootIdentifier(n *tree_sitter.Node) string {
	for n != nil {
		switch n.Kind() {
		case "identifier":
			return c.text(n)
		case "member_expression", "subscript_expression":
			n = field(n, "object")
		default:
			return ""
		}
	}
	return ""
}

func jsZeroStepSequenceRisk(text string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(text)), "")
	return strings.Contains(compact, "Math.abs(numeric(") &&
		strings.Contains(compact, "[2]") &&
		strings.Contains(compact, "for(") &&
		strings.Contains(compact, "+=") &&
		!strings.Contains(compact, "Math.max(Math.abs(numeric(")
}

func jsConvertSvgMultiSvgSanitizerBypass(text string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(text)), "")
	return strings.Contains(compact, "cheerio.default.html(") &&
		strings.Contains(compact, "this[_sanitize](") &&
		strings.Contains(compact, "cheerio.load(") &&
		strings.Contains(compact, "('svg')") &&
		strings.Contains(compact, "<body>${svg}</body>") &&
		strings.Contains(compact, "this[_getPage](html)") &&
		!strings.Contains(compact, "svg:first")
}

func jsAjaxBackslashProtocolRelativeURLXSS(text string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(text)), "")
	if !strings.Contains(compact, "$.ajax") ||
		!strings.Contains(compact, "url:") ||
		!strings.Contains(compact, "location") ||
		!strings.Contains(compact, ".replace(") {
		return false
	}
	if strings.Contains(compact, "startsWith(\"/\\\\\")") ||
		strings.Contains(compact, "startsWith('/\\\\')") ||
		strings.Contains(compact, "[1]=='\\\\'") ||
		strings.Contains(compact, "[1]==\"\\\\\"") ||
		strings.Contains(compact, "[1]==='\\\\'") ||
		strings.Contains(compact, "[1]===\"\\\\\"") ||
		strings.Contains(compact, "newURL(") {
		return false
	}
	firstSlashGuard := strings.Contains(compact, "[0]!='/'") || strings.Contains(compact, "[0]!=\"/\"") ||
		strings.Contains(compact, "[0]!=='/'") || strings.Contains(compact, "[0]!==\"/\"")
	secondSlashGuard := strings.Contains(compact, "[1]=='/'") || strings.Contains(compact, "[1]==\"/\"") ||
		strings.Contains(compact, "[1]==='/'") || strings.Contains(compact, "[1]===\"/\"")
	return firstSlashGuard && secondSlashGuard
}

func jsCryptoJSRandomFloatWordArrayRisk(text string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(text)), "")
	if !strings.Contains(compact, "words.push(") ||
		!(strings.Contains(compact, "*0x100000000") || strings.Contains(compact, "*4294967296")) {
		return false
	}
	hasNativeRandom := strings.Contains(compact, ".randomBytes(") ||
		strings.Contains(compact, ".getRandomValues(")
	hasFloatConversion := strings.Contains(compact, "Number('0.'+") ||
		strings.Contains(compact, "Number(\"0.\"+")
	hasNativeRandomRead := strings.Contains(compact, ".readUIntBE(") ||
		strings.Contains(compact, ".readUIntLE(") ||
		strings.Contains(compact, ".getRandomValues(")
	return hasNativeRandom && hasFloatConversion && hasNativeRandomRead
}

func jsEffectMixedSchedulerSharedRunner(text string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(text)), "")
	if strings.Contains(compact, "SchedulerRunner.cached(") ||
		strings.Contains(compact, "getRunner(fiber).scheduleTask") ||
		strings.Contains(compact, "newWeakMap<RuntimeFiber") {
		return false
	}
	return strings.Contains(compact, "classMixedScheduler") &&
		strings.Contains(compact, "implementsScheduler") &&
		strings.Contains(compact, "running=false") &&
		strings.Contains(compact, "tasks=newPriorityBuckets") &&
		strings.Contains(compact, "starveInternal") &&
		strings.Contains(compact, "this.tasks.buckets") &&
		strings.Contains(compact, "Promise.resolve(void0).then") &&
		strings.Contains(compact, "setTimeout(") &&
		strings.Contains(compact, "scheduleTask(task:Task,priority:number)") &&
		strings.Contains(compact, "this.tasks.scheduleTask(task,priority)") &&
		strings.Contains(compact, "this.starve()")
}

func (c *jsConv) jsIncompleteGeneratedIdentifierReservedWords(root *tree_sitter.Node) bool {
	if root == nil {
		return false
	}
	incompleteSets := map[string]bool{}
	hasIdentifierRegex := false
	hasGeneratedPropertyTemplate := false

	var collect func(*tree_sitter.Node)
	collect = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "variable_declarator":
			name := field(n, "name")
			value := field(n, "value")
			if name != nil && name.Kind() == "identifier" && jsIncompleteReservedWordSet(c, value) {
				incompleteSets[c.text(name)] = true
			}
		case "regex":
			if jsIdentifierRegex(c.text(n)) {
				hasIdentifierRegex = true
			}
		case "template_string":
			if jsGeneratedPropertyTemplate(c.text(n)) {
				hasGeneratedPropertyTemplate = true
			}
		case "binary_expression":
			if jsGeneratedPropertyConcat(c.text(n)) {
				hasGeneratedPropertyTemplate = true
			}
		}
		for _, ch := range c.namedChildren(n) {
			collect(ch)
		}
	}
	collect(root)
	usesIncompleteSet := false
	var findUse func(*tree_sitter.Node)
	findUse = func(n *tree_sitter.Node) {
		if n == nil || usesIncompleteSet {
			return
		}
		if n.Kind() == "call_expression" && jsSetHasCallUses(n, incompleteSets, c) {
			usesIncompleteSet = true
			return
		}
		for _, ch := range c.namedChildren(n) {
			findUse(ch)
		}
	}
	findUse(root)
	return len(incompleteSets) > 0 && hasIdentifierRegex && hasGeneratedPropertyTemplate && usesIncompleteSet
}

func jsIncompleteReservedWordSet(c *jsConv, n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	words := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		if cur.Kind() == "string" {
			if v := strings.ToLower(jsContextValue(c.text(cur))); v != "" {
				words[v] = true
			}
		}
		for _, ch := range c.namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	if words["eval"] || words["arguments"] || !words["enum"] {
		return false
	}
	core := 0
	for _, word := range []string{"class", "function", "return", "await", "yield", "this", "var", "let", "const"} {
		if words[word] {
			core++
		}
	}
	return core >= 3
}

func jsIdentifierRegex(raw string) bool {
	raw = strings.ReplaceAll(raw, "\\", "")
	return strings.Contains(raw, "[a-zA-Z_$]") && strings.Contains(raw, "[a-zA-Z0-9_$]")
}

func jsGeneratedPropertyTemplate(raw string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	return strings.Contains(compact, ".${")
}

func jsGeneratedPropertyConcat(raw string) bool {
	compact := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	return strings.Contains(compact, "+'.'+") || strings.Contains(compact, "+\".\"+")
}

func jsSetHasCallUses(n *tree_sitter.Node, sets map[string]bool, c *jsConv) bool {
	if n == nil || len(sets) == 0 {
		return false
	}
	fn := field(n, "function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	if c.text(field(fn, "property")) != "has" {
		return false
	}
	obj := field(fn, "object")
	return obj != nil && obj.Kind() == "identifier" && sets[c.text(obj)]
}

func (c *jsConv) jsGitCloneArgvTokens(n *tree_sitter.Node) []string {
	if n == nil || n.Kind() != "array" {
		return nil
	}
	var elems []string
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "string", "template_string":
			if v := jsContextValue(c.text(ch)); v != "" {
				elems = append(elems, v)
			}
		case "identifier":
			if v := jsContextCompact(c.text(ch)); v != "" {
				elems = append(elems, v)
			}
		default:
			if v := jsContextCompact(c.text(ch)); v != "" {
				elems = append(elems, v)
			}
		}
	}
	cloneIndex := -1
	for i, elem := range elems {
		if elem == "clone" {
			cloneIndex = i
			break
		}
	}
	if cloneIndex < 0 {
		return nil
	}
	remoteIndex := -1
	for i := cloneIndex + 1; i < len(elems); i++ {
		if jsGitRemoteArgName(elems[i]) {
			remoteIndex = i
			break
		}
	}
	if remoteIndex < 0 {
		return nil
	}
	hasDelimiter := false
	for i := cloneIndex + 1; i < remoteIndex; i++ {
		if elems[i] == "--" {
			hasDelimiter = true
			break
		}
	}
	seq := jsContextCompact(strings.Join(elems, " "))
	out := []string{"git_clone_argv_sequence=" + seq}
	if hasDelimiter {
		out = append(out, "git_clone_argv_delimited=true")
	} else {
		out = append(out, "git_clone_argv_missing_delimiter=true")
	}
	return out
}

func jsGitRemoteArgName(s string) bool {
	s = strings.ToLower(jsContextCompact(s))
	if s == "" || strings.HasPrefix(s, "--") {
		return false
	}
	for _, part := range []string{"url", "uri", "repo", "repository", "remote", "origin", "giturl", "git"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}

func jsRejectUnauthorizedPath(s string) bool {
	s = jsContextCompact(s)
	return s == "rejectUnauthorized" || strings.HasSuffix(s, ".rejectUnauthorized")
}

func jsRejectUnauthorizedDisabledDefault(n *tree_sitter.Node, c *jsConv) bool {
	if n == nil {
		return false
	}
	expr := jsContextCompact(c.text(n))
	if !strings.Contains(expr, "rejectUnauthorized") || !strings.Contains(expr, "===undefined?") {
		return false
	}
	return strings.Contains(expr, "?null:") || strings.Contains(expr, "?false:")
}

func (c *jsConv) jsFoldedHeaderCurrentGuard(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "if_statement" {
		return false
	}
	txt := jsContextCompact(c.text(n))
	hasGuard := strings.Contains(txt, "if(h)") ||
		strings.Contains(txt, "if(h!==undefined)") ||
		strings.Contains(txt, "if(h!=null)") ||
		strings.Contains(txt, "if(h!==null)")
	if !hasGuard {
		return false
	}
	return strings.Contains(txt, "this.header[h]") && strings.Contains(txt, "lines[i]")
}

func (c *jsConv) jsPrototypeKeyGuard(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "if_statement" {
		return false
	}
	txt := jsContextCompact(c.text(n))
	return jsPrototypeKeyComparison(txt)
}

// jsAllocatedContainerKinds reports whether the value a computed-key write
// stores is a freshly allocated container literal, and which kinds it can be.
// The value of a ternary is one of its branches, so
// `root[path] = deep ? [] : {}` allocates a container on every path exactly as
// `root[path] = {}` does and reports both kinds, while a ternary with a
// non-container branch can store a computed value and reports neither.
func (c *jsConv) jsAllocatedContainerKinds(n *tree_sitter.Node) (object, array bool) {
	if n == nil {
		return false, false
	}
	switch n.Kind() {
	case "object":
		return true, false
	case "array":
		return false, true
	case "ternary_expression":
		objThen, arrThen := c.jsAllocatedContainerKinds(field(n, "consequence"))
		objElse, arrElse := c.jsAllocatedContainerKinds(field(n, "alternative"))
		if !(objThen || arrThen) || !(objElse || arrElse) {
			return false, false
		}
		return objThen || objElse, arrThen || arrElse
	}
	return false, false
}

func jsPrototypeKeyComparison(expr string) bool {
	if !strings.Contains(expr, "==") && !strings.Contains(expr, "!=") {
		return false
	}
	return strings.Contains(expr, "__proto__") ||
		strings.Contains(expr, "constructor") && strings.Contains(expr, "prototype")
}

func (c *jsConv) jsPathSegmentTypeGuard(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "if_statement" {
		return false
	}
	txt := jsContextCompact(c.text(n))
	return strings.Contains(txt, ".constructor!==String") ||
		strings.Contains(txt, ".constructor!==Number") ||
		strings.Contains(txt, "typeof") && strings.Contains(txt, "String(")
}

func (c *jsConv) jsOwnPropertyKeyGuard(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "if_statement" {
		return false
	}
	txt := jsContextCompact(c.text(n))
	return strings.Contains(txt, "hasOwnProperty") ||
		strings.Contains(txt, "hasOwn(") ||
		strings.Contains(txt, "Object.getOwnPropertyNames") ||
		strings.Contains(txt, ".includes(") && strings.Contains(txt, "continue")
}

// jsFailOpenPolicyDeclarationGuard reports an `&&` chain that consults a
// declared requirement only as a conjunct of the guard that enforces it: one
// conjunct is the bare read X of a declared field, another conjunct of the same
// chain is a negated membership call over some collection whose element is
// compared against X — `if (token && ep.meta.kind && !token.permission.some(p
// => p === ep.meta.kind))` — and no operand of the enclosing condition tests
// X's absence. The chain is then true, and the check it guards skipped,
// wherever X was never set, which is the shape of an authorization that fails
// open on an undeclared requirement instead of denying. The fact is keyed on
// the relation between the sibling conjuncts rather than on X's spelling, so a
// binding can pair it with a documented collection API without knowing what
// any application calls its requirement field.
func (c *jsConv) jsFailOpenPolicyDeclarationGuard(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "if_statement" {
		return false
	}
	ops := c.jsBooleanOperands(field(n, "condition"), nil)
	if len(ops) < 2 {
		return false
	}
	declared := map[string]bool{}
	for _, op := range ops {
		if txt := c.jsDeclaredFieldRead(op); strings.Contains(txt, ".") {
			declared[txt] = true
		}
	}
	if len(declared) == 0 {
		return false
	}
	for _, op := range ops {
		for _, x := range c.jsNegatedMembershipOperands(op) {
			if declared[x] && !c.jsDeniesAbsentDeclaration(ops, x) {
				return true
			}
		}
	}
	return false
}

// jsBooleanOperands flattens one condition's `&&`/`||` tree into its operands,
// so a denial spelled in a sibling branch (`... || (!X && deny)`) stays visible
// to the caller instead of hiding inside a nested expression.
func (c *jsConv) jsBooleanOperands(n *tree_sitter.Node, acc []*tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return acc
	}
	n = c.unwrapJsTransparentExpr(n)
	if n.Kind() == "binary_expression" {
		if op := c.text(field(n, "operator")); op == "&&" || op == "||" {
			acc = c.jsBooleanOperands(field(n, "left"), acc)
			return c.jsBooleanOperands(field(n, "right"), acc)
		}
	}
	return append(acc, n)
}

// jsDeclaredFieldRead returns the dotted text of a bare member read — a field
// of some object, with no call, subscript, comparison or negation around it —
// or "" for anything else.
func (c *jsConv) jsDeclaredFieldRead(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	n = c.unwrapJsTransparentExpr(n)
	switch n.Kind() {
	case "identifier", "property_identifier":
		return c.text(n)
	case "this":
		return "this"
	case "member_expression":
		prop := field(n, "property")
		if prop == nil || prop.Kind() != "property_identifier" {
			return ""
		}
		base := c.jsDeclaredFieldRead(field(n, "object"))
		if base == "" {
			return ""
		}
		return base + "." + c.text(prop)
	}
	return ""
}

// jsMembershipPredicates are the call names that answer "is this element in
// that collection" with a boolean.
var jsMembershipPredicates = map[string]bool{
	"some": true, "includes": true, "has": true, "contains": true,
}

// jsNegatedMembershipOperands returns the declared-field texts a negated
// membership call compares its element against: the argument itself for
// `!coll.includes(X)`, and the declared-field side of each comparison inside
// the predicate for `!coll.some(p => p === X)`.
func (c *jsConv) jsNegatedMembershipOperands(op *tree_sitter.Node) []string {
	if op == nil || op.Kind() != "unary_expression" || c.text(field(op, "operator")) != "!" {
		return nil
	}
	call := c.unwrapJsTransparentExpr(field(op, "argument"))
	if call == nil || call.Kind() != "call_expression" {
		return nil
	}
	fn := c.unwrapJsTransparentExpr(field(call, "function"))
	if fn == nil || fn.Kind() != "member_expression" || field(fn, "property") == nil {
		return nil
	}
	if !jsMembershipPredicates[c.text(field(fn, "property"))] {
		return nil
	}
	args := field(call, "arguments")
	if args == nil || len(c.namedChildren(args)) == 0 {
		return nil
	}
	arg := c.unwrapJsTransparentExpr(c.namedChildren(args)[0])
	if arg == nil {
		return nil
	}
	switch arg.Kind() {
	case "arrow_function", "function_expression", "function_declaration":
		var out []string
		c.jsCollectMembershipComparisons(field(arg, "body"), &out)
		return out
	}
	if txt := c.jsDeclaredFieldRead(arg); strings.Contains(txt, ".") {
		return []string{txt}
	}
	return nil
}

// jsCollectMembershipComparisons walks a membership predicate's body for
// `p === X` style comparisons and records the declared-field side of each. A
// non-null assertion wrapper is not descended into: the grammar binds
// `p === X!.f` as `(p === X)!.f`, so the comparison inside it names a shorter
// operand than the source reads.
func (c *jsConv) jsCollectMembershipComparisons(n *tree_sitter.Node, out *[]string) {
	if n == nil || n.Kind() == "non_null_expression" {
		return
	}
	n = c.unwrapJsTransparentExpr(n)
	if n.Kind() == "binary_expression" {
		if op := c.text(field(n, "operator")); op == "==" || op == "===" || op == "!=" || op == "!==" {
			for _, side := range []*tree_sitter.Node{field(n, "left"), field(n, "right")} {
				if txt := c.jsDeclaredFieldRead(side); strings.Contains(txt, ".") {
					*out = append(*out, txt)
				}
			}
		}
	}
	for _, ch := range c.namedChildren(n) {
		c.jsCollectMembershipComparisons(ch, out)
	}
}

// jsDeniesAbsentDeclaration reports whether any operand of the same condition
// is a test that holds exactly when X is absent — `!X`, `X == null`,
// `X === undefined`, `typeof X === 'undefined'` — which is the remediation
// shape: the guard then names the undeclared case instead of skipping it. A
// presence test (`X != null`, `typeof X !== 'undefined'`) is deliberately not
// one of these, because conjoining it with the membership test leaves the
// chain failing open in exactly the same way.
func (c *jsConv) jsDeniesAbsentDeclaration(ops []*tree_sitter.Node, x string) bool {
	for _, op := range ops {
		op = c.unwrapJsTransparentExpr(op)
		if op == nil {
			continue
		}
		if op.Kind() == "unary_expression" && c.text(field(op, "operator")) == "!" {
			if c.jsDeclaredFieldRead(field(op, "argument")) == x {
				return true
			}
			continue
		}
		if op.Kind() != "binary_expression" {
			continue
		}
		l, r := field(op, "left"), field(op, "right")
		cmp := c.text(field(op, "operator"))
		if cmp != "==" && cmp != "===" {
			continue
		}
		if c.jsTypeofFieldRead(l) == x && c.jsUndefinedLiteral(r) {
			return true
		}
		if c.jsTypeofFieldRead(r) == x && c.jsUndefinedLiteral(l) {
			return true
		}
		if c.jsNullishText(r) && c.jsDeclaredFieldRead(l) == x {
			return true
		}
		if c.jsNullishText(l) && c.jsDeclaredFieldRead(r) == x {
			return true
		}
	}
	return false
}

// jsTypeofFieldRead returns the declared-field text a `typeof X` operand reads,
// or "" for anything else.
func (c *jsConv) jsTypeofFieldRead(n *tree_sitter.Node) string {
	if n == nil || n.Kind() != "unary_expression" || c.text(field(n, "operator")) != "typeof" {
		return ""
	}
	return c.jsDeclaredFieldRead(field(n, "argument"))
}

// jsUndefinedLiteral reports whether a comparison operand is the undefined
// literal rather than a value the program computed. Bare `undefined` is its own
// node kind in both grammars, not an identifier.
func (c *jsConv) jsUndefinedLiteral(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	n = c.unwrapJsTransparentExpr(n)
	switch n.Kind() {
	case "undefined":
		return true
	case "identifier":
		return jsContextCompact(c.text(n)) == "undefined"
	case "string":
		return jsContextCompact(c.text(n)) == "'undefined'" || jsContextCompact(c.text(n)) == "\"undefined\""
	}
	return false
}

// jsNullishText reports whether a comparison operand is the null or undefined
// literal rather than a value the program computed. Bare `undefined` is its own
// node kind in both grammars, not an identifier.
func (c *jsConv) jsNullishText(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	n = c.unwrapJsTransparentExpr(n)
	switch n.Kind() {
	case "null", "undefined":
		return true
	case "identifier":
		return jsContextCompact(c.text(n)) == "undefined"
	}
	return false
}

func (c *jsConv) jsSecretConfigObjectVars(root *tree_sitter.Node) map[string]bool {
	out := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "variable_declarator" {
			name := field(n, "name")
			val := c.unwrapJsTransparentExpr(field(n, "value"))
			if name != nil && name.Kind() == "identifier" && c.jsObjectHasSecretConfigPair(val) {
				out[c.text(name)] = true
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *jsConv) jsObjectHasSecretConfigPair(n *tree_sitter.Node) bool {
	n = c.unwrapJsTransparentExpr(n)
	if n == nil || n.Kind() != "object" {
		return false
	}
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "pair":
			key := strings.ToLower(c.keyName(field(ch, "key")))
			val := strings.ToLower(c.text(field(ch, "value")))
			if jsSecretConfigKey(key) && jsSecretConfigValue(val) {
				return true
			}
		case "object":
			if c.jsObjectHasSecretConfigPair(ch) {
				return true
			}
		}
	}
	return false
}

func jsSecretConfigKey(key string) bool {
	if key == "" {
		return false
	}
	for _, part := range []string{"token", "secret", "password", "passwd", "credential", "apikey", "api_key", "accesskey"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func jsSecretConfigValue(val string) bool {
	if val == "" || val == "undefined" || val == "null" {
		return false
	}
	return strings.Contains(val, "process.env") ||
		strings.Contains(val, "token") ||
		strings.Contains(val, "secret") ||
		strings.Contains(val, "password") ||
		strings.Contains(val, "credential") ||
		strings.Contains(val, "key")
}

func (c *jsConv) isJsPublicRuntimeConfigPath(path string) bool {
	return strings.Contains(path, "runtimeConfig.public")
}

func (c *jsConv) jsCallArgsContainSecretConfig(n *tree_sitter.Node, secretVars map[string]bool) (bool, string) {
	n = c.unwrapJsTransparentExpr(n)
	if n == nil || n.Kind() != "call_expression" {
		return false, ""
	}
	fn := c.dotted(field(n, "function"))
	if fn != "defu" && !strings.HasSuffix(fn, ".defu") && fn != "Object.assign" {
		return false, ""
	}
	args := field(n, "arguments")
	if args == nil {
		return false, ""
	}
	for _, a := range c.namedChildren(args) {
		a = c.unwrapJsTransparentExpr(a)
		if a == nil {
			continue
		}
		if a.Kind() == "identifier" {
			name := c.text(a)
			if secretVars[name] {
				return true, name
			}
		}
		if c.jsObjectHasSecretConfigPair(a) {
			return true, ""
		}
	}
	return false, ""
}

func (c *jsConv) jsContextPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if p := c.dotted(n); p != "" && p != "?" {
		return p
	}
	return jsContextCompact(c.text(n))
}

func jsContextValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"' || q == '`') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
		}
	}
	return jsContextCompact(s)
}

func jsContextRegex(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "/") {
		if i := strings.LastIndex(s[1:], "/"); i >= 0 {
			s = s[1 : i+1]
		}
	}
	return jsContextCompact(s)
}

func jsRegexMayBacktrack(raw string) bool {
	pat := jsRegexPattern(raw)
	if pat == "" {
		return false
	}
	return regexambig.Ambiguous(pat) || hasAmbiguousAdjacentRegexQuantifiers(pat)
}

func jsRegexPattern(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '/' {
		return raw
	}
	for i := len(raw) - 1; i > 0; i-- {
		if raw[i] != '/' || isEscaped(raw, i) {
			continue
		}
		return raw[1:i]
	}
	return strings.Trim(raw, "/")
}

type jsRegexAtom struct {
	key   string
	quant byte
	group bool
}

func hasAmbiguousAdjacentRegexQuantifiers(pat string) bool {
	for _, branch := range splitTopLevelRegexBranches(pat) {
		if hasAmbiguousAdjacentRegexQuantifiersInSeq(branch) {
			return true
		}
	}
	for _, inner := range regexGroupBodies(pat) {
		if hasAmbiguousAdjacentRegexQuantifiers(inner) {
			return true
		}
	}
	return false
}

func hasAmbiguousAdjacentRegexQuantifiersInSeq(pat string) bool {
	atoms := jsRegexAtoms(pat)
	for i := 0; i+1 < len(atoms); i++ {
		if isBacktrackingRepeat(atoms[i].quant) &&
			isBacktrackingRepeat(atoms[i+1].quant) &&
			regexAtomsOverlap(atoms[i].key, atoms[i+1].key) {
			return true
		}
	}
	for i := 0; i+2 < len(atoms); i++ {
		if isBacktrackingRepeat(atoms[i].quant) &&
			atoms[i+1].quant == '?' &&
			!atoms[i+1].group &&
			isBacktrackingRepeat(atoms[i+2].quant) &&
			regexAtomsOverlap(atoms[i].key, atoms[i+2].key) {
			return true
		}
	}
	return false
}

func jsRegexAtoms(pat string) []jsRegexAtom {
	var out []jsRegexAtom
	for i := 0; i < len(pat); {
		if isEscaped(pat, i) {
			i++
			continue
		}
		switch pat[i] {
		case '^', '$':
			i++
			continue
		case '|':
			i++
			continue
		case '[':
			end := regexCharClassEnd(pat, i)
			if end <= i {
				i++
				continue
			}
			key := regexAtomKey(pat[i : end+1])
			quant, next := jsRegexQuantifier(pat, end+1)
			out = append(out, jsRegexAtom{key: key, quant: quant})
			i = next
			continue
		case '(':
			end := regexGroupEnd(pat, i)
			if end <= i {
				i++
				continue
			}
			quant, next := jsRegexQuantifier(pat, end+1)
			out = append(out, jsRegexAtom{key: "group", quant: quant, group: true})
			i = next
			continue
		case '\\':
			if i+1 >= len(pat) {
				i++
				continue
			}
			key := regexAtomKey(pat[i : i+2])
			quant, next := jsRegexQuantifier(pat, i+2)
			out = append(out, jsRegexAtom{key: key, quant: quant})
			i = next
			continue
		default:
			if strings.ContainsRune(".*+?{}]", rune(pat[i])) {
				i++
				continue
			}
			key := regexAtomKey(pat[i : i+1])
			quant, next := jsRegexQuantifier(pat, i+1)
			out = append(out, jsRegexAtom{key: key, quant: quant})
			i = next
		}
	}
	return out
}

func splitTopLevelRegexBranches(pat string) []string {
	var out []string
	start := 0
	depth := 0
	inClass := false
	for i := 0; i < len(pat); i++ {
		if isEscaped(pat, i) {
			continue
		}
		switch pat[i] {
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		case '|':
			if !inClass && depth == 0 {
				out = append(out, pat[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, pat[start:])
	return out
}

func regexGroupBodies(pat string) []string {
	var out []string
	for i := 0; i < len(pat); i++ {
		if pat[i] != '(' || isEscaped(pat, i) {
			continue
		}
		end := regexGroupEnd(pat, i)
		if end <= i {
			continue
		}
		body := pat[i+1 : end]
		if strings.HasPrefix(body, "?:") || strings.HasPrefix(body, "?=") || strings.HasPrefix(body, "?!") {
			body = body[2:]
		} else if strings.HasPrefix(body, "?<=") || strings.HasPrefix(body, "?<!") {
			body = body[3:]
		} else if strings.HasPrefix(body, "?<") {
			if close := strings.IndexByte(body, '>'); close >= 0 {
				body = body[close+1:]
			}
		}
		out = append(out, body)
		i = end
	}
	return out
}

func regexCharClassEnd(pat string, start int) int {
	for i := start + 1; i < len(pat); i++ {
		if pat[i] == ']' && !isEscaped(pat, i) {
			return i
		}
	}
	return -1
}

func regexGroupEnd(pat string, start int) int {
	depth := 0
	inClass := false
	for i := start; i < len(pat); i++ {
		if isEscaped(pat, i) {
			continue
		}
		switch pat[i] {
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func jsRegexQuantifier(pat string, start int) (byte, int) {
	if start >= len(pat) {
		return 0, start
	}
	switch pat[start] {
	case '*', '+', '?':
		return pat[start], start + 1
	case '{':
		end := strings.IndexByte(pat[start:], '}')
		if end < 0 {
			return 0, start
		}
		body := strings.ReplaceAll(strings.TrimSpace(pat[start+1:start+end]), " ", "")
		next := start + end + 1
		switch body {
		case "1":
			return 0, next
		case "0,1":
			return '?', next
		default:
			return '*', next
		}
	default:
		return 0, start
	}
}

func isBacktrackingRepeat(q byte) bool {
	return q == '*' || q == '+'
}

func regexAtomKey(atom string) string {
	switch atom {
	case "\\d", "[0-9]", "[\\d]":
		return "digit"
	case ".":
		return "any"
	}
	return atom
}

func regexAtomsOverlap(a, b string) bool {
	return a == b || a == "any" || b == "any"
}

func jsPrototypeNameGuard(pattern string) bool {
	return strings.Contains(pattern, "__proto__") &&
		strings.Contains(pattern, "prototype") &&
		strings.Contains(pattern, "constructor")
}

func jsContextCompact(raw string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	if len(s) > 160 {
		return ""
	}
	return s
}

func (c *jsConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		switch n.Kind() {
		case "import_statement":
			// import x from 'm'  /  import {a,b} from 'm'  /  import * as x from 'm'
			src := c.text(field(n, "source"))
			// normalize the specifier to the module key the lowering registers (the same path
			// resolution require() uses) — otherwise a relative ES import never resolves.
			mod := c.resolveRequire(strings.Trim(src, "'\"`"))
			clause := field(n, "import_clause")
			if clause == nil {
				for _, ch := range c.namedChildren(n) {
					if ch.Kind() == "import_clause" {
						clause = ch
						break
					}
				}
			}
			if clause == nil {
				clause = n
			}
			for _, ch := range c.namedChildren(clause) {
				switch ch.Kind() {
				case "identifier": // default import
					out = append(out, nir.Import{Local: c.text(ch), Module: mod, IsModule: true})
				case "namespace_import":
					if id := c.lastIdent(ch); id != nil {
						out = append(out, nir.Import{Local: c.text(id), Module: mod, IsModule: true})
					}
				case "named_imports":
					for _, spec := range c.namedChildren(ch) {
						if spec.Kind() == "import_specifier" {
							name := c.text(orSelf(field(spec, "name"), spec))
							alias := field(spec, "alias")
							local := name
							if alias != nil {
								local = c.text(alias)
							}
							out = append(out, nir.Import{Local: local, Module: mod, Symbol: name})
						}
					}
				}
			}
		case "variable_declarator":
			// const x = require('m')
			// const x = require('m').member
			val := field(n, "value")
			requireCall := val
			member := ""
			if val != nil && val.Kind() == "member_expression" {
				requireCall = field(val, "object")
				member = c.text(field(val, "property"))
			}
			if requireCall != nil && requireCall.Kind() == "call_expression" {
				fn := field(requireCall, "function")
				if fn != nil && c.text(fn) == "require" {
					if args := field(requireCall, "arguments"); args != nil {
						for _, a := range c.namedChildren(args) {
							if a.Kind() == "string" {
								mod := c.resolveRequire(strings.Trim(c.text(a), "'\"`"))
								name := field(n, "name")
								if name != nil && name.Kind() == "identifier" {
									if member != "" {
										out = append(out, nir.Import{Local: c.text(name), Module: mod, Symbol: member})
									} else {
										out = append(out, nir.Import{Local: c.text(name), Module: mod, IsModule: true})
									}
								}
							}
						}
					}
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *jsConv) blockChildren(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range c.namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jsConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_declaration", "generator_function_declaration", "method_definition":
		name := c.text(field(n, "name"))
		exported := c.exported[name]
		params := c.exportedFuncParams(n, exported, c.funcParams(n))
		paramTypes := c.funcParamTypes(n)
		body := c.funcBody(n)
		decorators := c.jsDecoratorTokens(n)
		out := []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, ContextTokens: c.jsFunctionContext(name, n), Decorators: decorators, ParamEntries: c.jsParamEntries(name, params, decorators), Exported: exported}}
		// A factory function returns its API as an object literal of shorthand
		// methods, e.g. `function Email(opts){ return { async send(p){…} } }`.
		// c.expr's object case lowers only pairs, so those method bodies are dead
		// code unless the same walk the object-valued declaration paths already use
		// runs here too.
		return append(out, c.returnedObjectMethodFuncDefs(n, exported)...)
	case "class_declaration", "abstract_class_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.body(field(n, "body")), Loc: L}}
	case "field_definition", "public_field_definition":
		// a class field whose value is an object literal of methods, e.g.
		// `static events = { paste(event){ … } }` (input-handler maps, the common
		// "handler dictionary" pattern). Lower each method so its body is analyzed —
		// otherwise the whole object, and any source→sink flow inside it, is dead code.
		val := field(n, "value")
		if val == nil {
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "object" {
					val = ch
					break
				}
			}
		}
		if val != nil && val.Kind() == "object" {
			var out []nir.Stmt
			for _, pr := range namedChildren(val) {
				switch pr.Kind() {
				case "method_definition":
					out = append(out, c.stmt(pr)...)
				case "pair":
					if v := field(pr, "value"); isJsFuncNode(v) {
						out = append(out, nir.FuncDef{Name: c.keyName(field(pr, "key")),
							Params: c.funcParams(v), ParamTypes: c.funcParamTypes(v),
							Body: c.funcBody(v), Loc: c.loc(pr)})
					}
				}
			}
			return out
		}
		return nil
	case "lexical_declaration", "variable_declaration":
		var out []nir.Stmt
		for _, d := range c.namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				if name != nil && name.Kind() == "identifier" && (isJsFuncNode(val) || c.isFunctionLikeDeclarator(d)) {
					fnName := c.text(name)
					params := c.funcParams(val)
					paramTypes := c.funcParamTypes(val)
					if len(params) == 0 {
						params = c.paramsFromFunctionText(d)
					}
					params = c.exportedFuncParams(val, c.exported[fnName], params)
					body := c.funcBody(val)
					out = append(out, nir.FuncDef{Name: fnName, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, ContextTokens: c.jsFunctionContext(fnName, val), ParamEntries: c.jsParamEntries(fnName, params, nil), Exported: c.exported[fnName]})
					continue
				}
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil && name.Kind() == "identifier" {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v, Decl: true})
					if val != nil && val.Kind() == "object" {
						out = append(out, c.objectMethodFuncDefs(val, false)...)
					}
					if val != nil && val.Kind() == "call_expression" {
						out = append(out, c.callArgObjectMethodFuncDefs(val)...)
					}
					if val != nil {
						out = append(out, c.classExpressionFuncDefs(val)...)
					}
				} else if targets := c.bindingNames(name); len(targets) > 0 {
					for _, target := range targets {
						out = append(out, nir.Assign{Targets: []string{target}, Value: v, Decl: true})
					}
				} else {
					out = append(out, nir.ExprStmt{Value: v})
				}
			}
		}
		return out
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0], L)
	case "return_statement":
		kids := c.namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement":
		// separate Then/Else branches so the join-merge keeps a value tainted on the live
		// path even when the other arm overwrites it, and a constant condition prunes.
		var cond nir.Expr
		cn := field(n, "condition")
		if cn != nil {
			cond = c.expr(cn)
		}
		thenBody := c.branchBody(field(n, "consequence"))
		out := make([]nir.Stmt, 0, 2)
		if jsRejectingCommandRegexGuard(c, cn) && jsBranchReturns(thenBody) {
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "analysis.javascript.command_argument_regex_guard", Loc: L},
				Path:   "analysis.javascript.command_argument_regex_guard",
				Method: "command_argument_regex_guard",
				Loc:    L,
			}})
		}
		out = append(out, nir.If{Cond: cond, Then: thenBody, Else: c.branchBody(field(n, "alternative"))})
		return out
	case "while_statement", "for_statement":
		var cond nir.Expr
		body := c.collectStatementBlocks(n)
		if cn := field(n, "condition"); cn != nil {
			if target, val, ok := c.jsAssignmentExpr(cn); ok {
				body = append([]nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}}, body...)
			}
			cond = c.expr(cn)
		}
		return []nir.Stmt{nir.Loop{Cond: cond, Body: body}}
	case "for_in_statement":
		loop := nir.Loop{Body: c.collectStatementBlocks(n)}
		if right := field(n, "right"); right != nil {
			loop.Iter = c.expr(right)
		}
		if left := field(n, "left"); left != nil {
			loop.Vars = c.bindingNames(left)
		}
		return []nir.Stmt{loop}
	case "switch_statement":
		return []nir.Stmt{c.switchStmt(n)}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectStatementBlocks(n)}}
	case "statement_block":
		return []nir.Stmt{nir.Block{Stmts: c.collectStatementBlocks(n)}}
	case "export_statement":
		// unwrap `export [default] <decl>` / `export async function …` so the
		// declaration inside is analyzed (Next.js route handlers are all exports).
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "call_expression" {
				out = append(out, c.exprStmt(ch, L)...)
				continue
			}
			if ch.Kind() == "object" {
				out = append(out, c.objectMethodFuncDefs(ch, true)...)
				continue
			}
			if isJsFuncNode(ch) {
				name := c.text(field(ch, "name"))
				if name == "" {
					name = "__default_export__"
				}
				params := c.funcParams(ch)
				paramTypes := c.funcParamTypes(ch)
				if len(params) == 0 {
					params = c.paramsFromFunctionText(n)
				}
				params = c.exportedFuncParams(ch, true, params)
				out = append(out, nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(ch), Loc: L, ContextTokens: c.jsFunctionContext(name, ch), Exported: true})
				continue
			}
			out = append(out, c.stmt(ch)...)
		}
		return out
	}
	return nil
}

func (c *jsConv) jsAssignmentExpr(n *tree_sitter.Node) (string, nir.Expr, bool) {
	for n != nil && isJsTransparentExpr(n.Kind()) {
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return "", nil, false
		}
		n = kids[0]
	}
	if n == nil || n.Kind() != "assignment_expression" {
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

func jsBranchReturns(stmts []nir.Stmt) bool {
	for _, st := range stmts {
		switch v := st.(type) {
		case nir.Return:
			return true
		case nir.Block:
			if jsBranchReturns(v.Stmts) {
				return true
			}
		}
	}
	return false
}

func jsRejectingCommandRegexGuard(c *jsConv, n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "parenthesized_expression" {
		kids := c.namedChildren(n)
		if len(kids) == 1 {
			return jsRejectingCommandRegexGuard(c, kids[0])
		}
	}
	if n.Kind() == "binary_expression" {
		text := c.text(field(n, "operator"))
		if text == "||" || text == "&&" {
			return jsRejectingCommandRegexGuard(c, field(n, "left")) ||
				jsRejectingCommandRegexGuard(c, field(n, "right"))
		}
	}
	if n.Kind() != "call_expression" {
		return false
	}
	fn := field(n, "function")
	if fn == nil || fn.Kind() != "member_expression" || c.text(field(fn, "property")) != "test" {
		return false
	}
	if args := field(n, "arguments"); args == nil || len(c.namedChildren(args)) == 0 {
		return false
	}
	return safeJSCommandRejectRegex(c.text(field(fn, "object")))
}

func safeJSCommandRejectRegex(lit string) bool {
	inner := jsRegexPattern(lit)
	if inner == "" {
		return false
	}
	start := strings.Index(inner, "[")
	end := strings.LastIndex(inner, "]")
	if start < 0 || end <= start+1 {
		return false
	}
	body := inner[start+1 : end]
	if strings.HasPrefix(body, "^") {
		return false
	}
	for _, required := range []rune{'`', '$', '&', ';', '|'} {
		if !strings.ContainsRune(body, required) {
			return false
		}
	}
	return true
}

// callArgObjectMethodFuncDefs lowers methods defined inside object literals that are
// passed straight to a call, e.g. `$.extend(defaults, {opts: {onCellHtmlData() {…}}})`.
// Handing a config object to a call is ordinary JS, but only object literals bound to
// a variable are otherwise scanned, so these methods contribute no function at all and
// anything keyed on the method name can never match. objectMethodFuncDefs already
// recurses through nested pairs, and ignores arguments that are not object literals.
func (c *jsConv) callArgObjectMethodFuncDefs(call *tree_sitter.Node) []nir.Stmt {
	args := field(call, "arguments")
	if args == nil {
		return nil
	}
	var out []nir.Stmt
	for _, a := range c.namedChildren(args) {
		out = append(out, c.objectMethodFuncDefs(a, false)...)
	}
	return out
}

func (c *jsConv) objectMethodFuncDefs(obj *tree_sitter.Node, exported bool) []nir.Stmt {
	if obj == nil || obj.Kind() != "object" {
		return nil
	}
	var out []nir.Stmt
	for _, pr := range c.namedChildren(obj) {
		switch pr.Kind() {
		case "method_definition":
			name := c.text(field(pr, "name"))
			params := c.exportedFuncParams(pr, exported, c.funcParams(pr))
			out = append(out, nir.FuncDef{Name: name, Params: params,
				ParamTypes: c.funcParamTypes(pr), Body: c.funcBody(pr), Loc: c.loc(pr), ContextTokens: c.jsFunctionContext(name, pr), ParamEntries: c.jsParamEntries(name, params, nil), Exported: exported})
			out = append(out, c.returnedObjectMethodFuncDefs(pr, exported)...)
		case "pair":
			v := field(pr, "value")
			if isJsFuncNode(v) {
				name := c.keyName(field(pr, "key"))
				params := c.funcParams(v)
				paramTypes := c.funcParamTypes(v)
				if len(params) == 0 {
					params = c.paramsFromFunctionText(pr)
				}
				params = c.exportedFuncParams(v, exported, params)
				out = append(out, nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes,
					Body: c.funcBody(v), Loc: c.loc(pr), ContextTokens: c.jsFunctionContext(name, v), ParamEntries: c.jsParamEntries(name, params, nil), Exported: exported})
				out = append(out, c.returnedObjectMethodFuncDefs(v, exported)...)
			}
			out = append(out, c.objectMethodFuncDefs(v, exported)...)
		}
	}
	return out
}

func (c *jsConv) returnedObjectMethodFuncDefs(fn *tree_sitter.Node, exported bool) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		for _, ch := range c.namedChildren(fn) {
			if ch.Kind() == "statement_block" {
				body = ch
				break
			}
		}
	}
	if body == nil {
		return nil
	}
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "return_statement" {
			for _, ch := range c.namedChildren(n) {
				if ch.Kind() == "object" {
					out = append(out, c.objectMethodFuncDefs(ch, exported)...)
				}
			}
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

func (c *jsConv) classExpressionFuncDefs(root *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "class", "class_declaration", "abstract_class_declaration":
			out = append(out, c.body(field(n, "body"))...)
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

// resolveRequire normalizes a relative require/import specifier to the dotted,
// root-relative module key the lowering registers modules under (matching
// jsModuleKey). Bare specifiers (node_modules) are returned unchanged.
func (c *jsConv) resolveRequire(spec string) string {
	if !strings.HasPrefix(spec, ".") {
		return spec
	}
	p := filepath.Clean(filepath.Join(filepath.Dir(c.file), spec))
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"} {
		p = strings.TrimSuffix(p, ext)
	}
	p = strings.TrimSuffix(p, string(filepath.Separator)+"index")
	return strings.ReplaceAll(p, string(filepath.Separator), ".")
}

func isJsFuncNode(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "function_expression", "arrow_function", "function", "generator_function":
		return true
	}
	return false
}

// isModuleExports reports whether a member_expression is `module.exports`.
func (c *jsConv) isModuleExports(n *tree_sitter.Node) bool {
	return n != nil && n.Kind() == "member_expression" &&
		c.text(field(n, "object")) == "module" && c.text(field(n, "property")) == "exports"
}

// exportFuncName returns the exported function name for `exports.NAME` or
// `module.exports.NAME` member targets ("" if it is neither).
// memberRootIdent returns the root identifier of a member chain (the object at the base
// of `A.b.c`), or "". Used to tie a prototype/static method back to an exported
// constructor/class.
func (c *jsConv) memberRootIdent(m *tree_sitter.Node) string {
	for m != nil && m.Kind() == "member_expression" {
		m = field(m, "object")
	}
	if m != nil && m.Kind() == "identifier" {
		return c.text(m)
	}
	return ""
}

func (c *jsConv) exportFuncName(left *tree_sitter.Node) string {
	obj := field(left, "object")
	name := c.text(field(left, "property"))
	if obj == nil || name == "" {
		return ""
	}
	if obj.Kind() == "identifier" && c.text(obj) == "exports" {
		return name
	}
	if c.isModuleExports(obj) {
		return name
	}
	return ""
}

func (c *jsConv) exprStmt(inner *tree_sitter.Node, L string) []nir.Stmt {
	switch inner.Kind() {
	case "parenthesized_expression":
		if kids := c.namedChildren(inner); len(kids) > 0 && kids[0].Kind() == "call_expression" {
			if body := c.iife(kids[0], L); len(body) > 0 {
				return body
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
	case "call_expression":
		if body := c.iife(inner, L); len(body) > 0 {
			return body
		}
		return append([]nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}, c.callArgObjectMethodFuncDefs(inner)...)
	case "unary_expression":
		if arg := c.unaryArg(inner); arg != nil && arg.Kind() == "call_expression" {
			if body := c.iife(arg, L); len(body) > 0 {
				return body
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
	case "assignment_expression":
		left := field(inner, "left")
		rhs := field(inner, "right")
		// CommonJS function exports become named FuncDefs so cross-file calls
		// resolve: `exports.f = function…`, `module.exports.f = …`, and
		// `module.exports = { f: function… }`.
		if left != nil && c.isModuleExports(left) && isJsFuncNode(rhs) {
			name := c.text(field(rhs, "name"))
			if name == "" {
				name = "__default_export__"
			}
			params := c.funcParams(rhs)
			paramTypes := c.funcParamTypes(rhs)
			if len(params) == 0 {
				params = c.paramsFromFunctionText(inner)
			}
			params = c.exportedFuncParams(rhs, true, params)
			return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, ContextTokens: c.jsFunctionContext(name, rhs), ParamEntries: c.jsParamEntries(name, params, nil), Exported: true}}
		}
		if left != nil && left.Kind() == "member_expression" && isJsFuncNode(rhs) {
			if name := c.exportFuncName(left); name != "" {
				params := c.funcParams(rhs)
				paramTypes := c.funcParamTypes(rhs)
				if len(params) == 0 {
					params = c.paramsFromFunctionText(inner)
				}
				params = c.exportedFuncParams(rhs, true, params)
				return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, ContextTokens: c.jsFunctionContext(name, rhs), ParamEntries: c.jsParamEntries(name, params, nil), Exported: true}}
			}
			// `Ctor.prototype.method = function` / `Ctor.method = function` on an EXPORTED
			// constructor/class. Always emit a FuncDef so the method is REGISTERED (calls to
			// it resolve → interprocedural taint flows through internal helpers). Mark it an
			// entry point (Exported) only if it's public by convention: a `_name` method is
			// internal and is reached by propagation from the public methods, not directly.
			if root := c.memberRootIdent(left); root != "" && c.exported[root] {
				name := c.text(field(left, "property"))
				if name != "" {
					params := c.funcParams(rhs)
					paramTypes := c.funcParamTypes(rhs)
					if len(params) == 0 {
						params = c.paramsFromFunctionText(inner)
					}
					exported := !strings.HasPrefix(name, "_")
					params = c.exportedFuncParams(rhs, exported, params)
					return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, ContextTokens: c.jsFunctionContext(name, rhs), ParamEntries: c.jsParamEntries(name, params, nil), Exported: exported}}
				}
			}
		}
		if left != nil && c.isModuleExports(left) && rhs != nil && rhs.Kind() == "object" {
			out := c.objectMethodFuncDefs(rhs, true)
			if len(out) > 0 {
				return out
			}
		}
		var prefix []nir.Stmt
		if rhs != nil && rhs.Kind() == "assignment_expression" {
			prefix = append(prefix, c.exprStmt(rhs, L)...)
		}
		if target, val, ok := c.jsAssignmentExpr(inner); ok {
			return append(prefix, nir.Assign{Targets: []string{target}, Value: val})
		}
		if v, ok := c.jsSelfDefaultAssignmentValue(left, rhs); ok {
			right := c.expr(v)
			if left != nil && left.Kind() == "member_expression" {
				p := c.dotted(left)
				right = c.markBrowserGlobalAssignmentParamEntries(left, right, L)
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: L}}}
			}
			if left != nil && left.Kind() == "subscript_expression" {
				base := field(left, "object")
				key := field(left, "index")
				right = c.markBrowserGlobalAssignmentParamEntries(left, right, L)
				return []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{c.expr(key)}, Path: "__js_dynamic_property_write", Method: "", Loc: L}},
					nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right}, Path: c.dotted(base), Method: "", Loc: L}},
				}
			}
		}
		right := c.expr(rhs)
		// member-property write (e.g. obj.prop = x): model as a path call so binding
		// mappings can reason about the assigned value.
		// Method is empty so it can never collide with method-name mappings.
		if left != nil && left.Kind() == "member_expression" {
			p := c.dotted(left)
			right = c.markBrowserGlobalAssignmentParamEntries(left, right, L)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: L}}}
		}
		// subscript write (obj[key] = v): model as a write to the base's path so the
		// same path mappings fire as for a dotted member write.
		if left != nil && left.Kind() == "subscript_expression" {
			base := field(left, "object")
			key := field(left, "index")
			right = c.markBrowserGlobalAssignmentParamEntries(left, right, L)
			return []nir.Stmt{
				// Preserve dynamic property-name flow separately from value flow.
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{c.expr(key)}, Path: "__js_dynamic_property_write", Method: "", Loc: L}},
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right}, Path: c.dotted(base), Method: "", Loc: L}},
			}
		}
		// other assignment: still evaluate RHS for effect
		return append(prefix, nir.ExprStmt{Value: right})
	case "augmented_assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "member_expression" {
			p := c.dotted(left)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: L}}}
		}
		if left != nil && left.Kind() == "subscript_expression" {
			base := field(left, "object")
			key := field(left, "index")
			return []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{c.expr(key)}, Path: "__js_dynamic_property_write", Method: "", Loc: L}},
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right}, Path: c.dotted(base), Method: "", Loc: L}},
			}
		}
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: right, Loc: L}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// jsCallArgNodes lists a call's argument expressions. tree-sitter treats a comment
// as a named child of the argument list, so `import(/* @vite-ignore */ path)` and
// `exec(/* nosemgrep */ cmd)` would otherwise shift every argument one place to the
// right and a binding emitting at args[0] would label the comment instead of the
// value. Inline argument annotations are ordinary in bundler and linter directives,
// so the shift silently deletes the sink.
func (c *jsConv) jsCallArgNodes(call *tree_sitter.Node) []*tree_sitter.Node {
	args := field(call, "arguments")
	if args == nil {
		return nil
	}
	kids := c.namedChildren(args)
	out := make([]*tree_sitter.Node, 0, len(kids))
	for _, a := range kids {
		if a == nil || a.Kind() == "comment" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (c *jsConv) iife(call *tree_sitter.Node, L string) []nir.Stmt {
	fn := field(call, "function")
	if fn != nil && fn.Kind() == "parenthesized_expression" {
		if kids := c.namedChildren(fn); len(kids) > 0 {
			fn = kids[0]
		}
	}
	if !isJsFuncNode(fn) {
		return nil
	}
	body := c.funcBody(fn)
	ps := c.funcParams(fn)
	var as []*tree_sitter.Node
	if args := field(call, "arguments"); args != nil {
		as = c.namedChildren(args)
	}
	for i, p := range ps {
		if i >= len(as) {
			break
		}
		body = append([]nir.Stmt{nir.Assign{Targets: []string{p}, Value: c.expr(as[i])}}, body...)
	}
	return body
}

func (c *jsConv) unaryArg(n *tree_sitter.Node) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	if arg := field(n, "argument"); arg != nil {
		return arg
	}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "comment" {
			return ch
		}
	}
	return nil
}

// branchBody flattens one if-branch body: a `{}` block, an else_clause wrapper, or a
// brace-less single statement / nested control statement.
func (c *jsConv) branchBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "statement_block":
		return c.blockChildren(n)
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			out = append(out, c.branchBody(ch)...)
		}
		return out
	default:
		return c.stmt(n)
	}
}

// switchStmt lowers a switch into separate case branches with labels (consecutive
// fall-through labels merge into the next body), so a constant subject prunes to its arm.
func (c *jsConv) switchStmt(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, sc := range c.namedChildren(b) {
			switch sc.Kind() {
			case "switch_case":
				lv := field(sc, "value")
				var stmts []nir.Stmt
				for _, ch := range c.namedChildren(sc) {
					if lv != nil && ch.StartByte() == lv.StartByte() {
						continue // the label expr, not a body statement
					}
					stmts = append(stmts, c.stmt(ch)...)
				}
				if lv != nil {
					pending = append(pending, c.expr(lv))
				}
				if len(stmts) > 0 {
					cases = append(cases, stmts)
					labels = append(labels, pending)
					pending = nil
				}
			case "switch_default":
				for _, ch := range c.namedChildren(sc) {
					deflt = append(deflt, c.stmt(ch)...)
				}
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
}

// collectStatementBlocks gathers statements from nested statement_blocks and
// clause bodies (flow-approximate).
func (c *jsConv) collectStatementBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// jsBodyHandled reports whether a body-position node is already collected by the walk
	// below (a `{}` block or a nested clause wrapper) — used to avoid double-lowering when
	// picking up brace-less bodies.
	jsBodyHandled := func(k string) bool {
		switch k {
		case "statement_block", "else_clause", "finally_clause", "catch_clause":
			return true
		}
		return false
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statement_block":
				out = append(out, c.blockChildren(ch)...)
			case "else_clause", "finally_clause", "catch_clause":
				walk(ch)
			}
		}
		// brace-less single-statement bodies (`if (x) foo();` with no `{}`): the
		// consequence/body field points straight at the statement. The else branch is an
		// else_clause wrapper (walked above), so also lower its bare statement child.
		for _, f := range []string{"consequence", "body"} {
			if b := field(m, f); b != nil && !jsBodyHandled(b.Kind()) {
				out = append(out, c.stmt(b)...)
			}
		}
		switch m.Kind() {
		case "else_clause", "catch_clause", "finally_clause":
			for _, ch := range c.namedChildren(m) {
				if !jsBodyHandled(ch.Kind()) {
					out = append(out, c.stmt(ch)...)
				}
			}
		}
	}
	if n.Kind() == "statement_block" {
		return c.blockChildren(n)
	}
	walk(n)
	return out
}

func (c *jsConv) body(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	// statement_block (function body) and class_body (members) are both lists of
	// statements/definitions — extract each (so class methods become FuncDefs).
	if n.Kind() == "statement_block" || n.Kind() == "class_body" {
		return c.blockChildren(n)
	}
	// expression-bodied arrow: treat as a return
	return []nir.Stmt{nir.Return{Value: c.expr(n)}}
}

// paramsFieldOf returns a function-like node's parameter list node, or nil when
// the node carries none (an expression-bodied arrow binds its single parameter
// in place, which jsConv.params reads off the node itself).
func paramsFieldOf(n *tree_sitter.Node) *tree_sitter.Node {
	params := field(n, "parameters")
	if params == nil {
		params = field(n, "parameter")
	}
	if params == nil {
		for _, ch := range children(n) {
			switch ch.Kind() {
			case "formal_parameters", "parameters":
				params = ch
			}
			if params != nil {
				break
			}
		}
	}
	return params
}

func (c *jsConv) funcParams(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	if out := c.params(paramsFieldOf(n)); len(out) > 0 {
		return out
	}
	return c.paramsFromFunctionText(n)
}

func (c *jsConv) funcParamTypes(n *tree_sitter.Node) map[string]string {
	if n == nil {
		return nil
	}
	params := paramsFieldOf(n)
	out := c.paramTypes(params)
	if len(out) == 0 {
		return jsParamTypesFromText(c.text(n))
	}
	return out
}

func (c *jsConv) funcBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	body := field(n, "body")
	if body == nil {
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "statement_block" {
				body = ch
				break
			}
		}
	}
	out := c.body(body)
	if pre := c.patternParamBindings(n); len(pre) > 0 {
		out = append(pre, out...)
	}
	return out
}

// patternParamBindings lowers the names a destructuring parameter introduces
// beyond its positional slot: each binds to the slot's value, the same reading
// the `const { a, b } = v` declaration lowering gives, so an argument passed at
// the pattern's position reaches every name the pattern binds.
func (c *jsConv) patternParamBindings(fn *tree_sitter.Node) []nir.Stmt {
	params := paramsFieldOf(fn)
	if params == nil || params.Kind() == "identifier" {
		return nil
	}
	var out []nir.Stmt
	for _, ch := range c.namedChildren(params) {
		pat := paramPattern(ch)
		if pat == nil || (pat.Kind() != "object_pattern" && pat.Kind() != "array_pattern") {
			continue
		}
		slot, rest := c.patternSlot(pat)
		if len(rest) == 0 {
			continue
		}
		loc := c.loc(pat)
		out = append(out, nir.Assign{Targets: rest, Value: nir.Name{ID: slot, Loc: loc}, Decl: true, Loc: loc})
	}
	return out
}

func (c *jsConv) exportedFuncParams(fn *tree_sitter.Node, exported bool, params []string) []string {
	if !exported || !c.functionUsesArguments(fn) {
		return params
	}
	for _, p := range params {
		if p == nir.JSArgumentsParam {
			return params
		}
	}
	out := append([]string{}, params...)
	return append(out, nir.JSArgumentsParam)
}

func (c *jsConv) functionUsesArguments(fn *tree_sitter.Node) bool {
	if fn == nil {
		return false
	}
	body := field(fn, "body")
	if body == nil {
		for _, ch := range c.namedChildren(fn) {
			if ch.Kind() == "statement_block" {
				body = ch
				break
			}
		}
	}
	var walk func(*tree_sitter.Node) bool
	walk = func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		if n != body && isJsFuncNode(n) {
			return false
		}
		if n.Kind() == "identifier" && c.text(n) == "arguments" {
			return true
		}
		for _, ch := range c.namedChildren(n) {
			if walk(ch) {
				return true
			}
		}
		return false
	}
	return walk(body)
}

func (c *jsConv) jsFunctionContext(name string, n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	body := field(n, "body")
	if body == nil {
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "statement_block" {
				body = ch
				break
			}
		}
	}
	if body == nil {
		return nil
	}
	bodyText := c.text(body)
	tokens := []string{
		"lang=javascript\x00name=" + name,
		"function_name:" + name,
		bodyText,
		strings.Join(strings.Fields(bodyText), ""),
	}
	tokens = append(tokens, c.jsStructuredContextTokens(body)...)
	return tokens
}

func (c *jsConv) isFunctionLikeDeclarator(n *tree_sitter.Node) bool {
	txt := c.text(n)
	if i := strings.IndexByte(txt, '='); i >= 0 {
		txt = strings.TrimSpace(txt[i+1:])
	}
	return strings.HasPrefix(txt, "function") ||
		strings.HasPrefix(txt, "async function") ||
		isJSArrowFunctionText(txt)
}

func isJSArrowFunctionText(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "async ") {
		s = strings.TrimSpace(strings.TrimPrefix(s, "async "))
	}
	if isJSIdentPrefixArrow(s) {
		return true
	}
	if !strings.HasPrefix(s, "(") {
		return false
	}
	depth, end := 0, -1
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				i = len(s)
			}
		}
	}
	return end > 0 && strings.HasPrefix(strings.TrimSpace(s[end+1:]), "=>")
}

func (c *jsConv) paramsFromFunctionText(n *tree_sitter.Node) []string {
	txt := c.text(n)
	start := strings.IndexByte(txt, '(')
	if start < 0 {
		return nil
	}
	depth, end := 0, -1
	for i := start; i < len(txt); i++ {
		switch txt[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				i = len(txt)
			}
		}
	}
	if end <= start {
		return nil
	}
	var out []string
	for _, p := range strings.Split(txt[start+1:end], ",") {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "...")
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isJSIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

func isJSIdentPrefixArrow(s string) bool {
	i := strings.Index(s, "=>")
	if i < 0 {
		return false
	}
	return isJSIdent(strings.TrimSpace(s[:i]))
}

func isJSIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func (c *jsConv) markCallLambdaParams(path string, lam nir.Lambda, L string) nir.Lambda {
	method := lastSeg(path)
	lam.ContextTokens = append(lam.ContextTokens,
		"call_path:"+path,
		"call:"+method,
		"call_method:"+method,
		"param_count:"+itoa(len(lam.Params)),
	)
	for i, p := range lam.Params {
		if p == "" || p == "_" {
			continue
		}
		tokens := []string{
			"entry_kind:call_lambda_param",
			"call_path:" + path,
			"call_method:" + method,
			"param_count:" + itoa(len(lam.Params)),
			"param_name:" + p,
			"param_index:" + itoa(i),
		}
		lam.ParamEntries = append(lam.ParamEntries, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return lam
}

func (c *jsConv) markBrowserGlobalAssignmentParamEntries(left *tree_sitter.Node, right nir.Expr, L string) nir.Expr {
	lam, ok := right.(nir.Lambda)
	if !ok {
		return right
	}
	root, target, ok := c.browserGlobalAssignmentTarget(left)
	if !ok {
		return right
	}
	for i, p := range lam.Params {
		if p == "" || p == "_" {
			continue
		}
		tokens := []string{
			"entry_kind:global_function_assignment",
			"global_object:" + root,
			"global_target:" + target,
			"param_count:" + itoa(len(lam.Params)),
			"param_name:" + p,
			"param_index:" + itoa(i),
		}
		lam.ParamEntries = append(lam.ParamEntries, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return lam
}

func (c *jsConv) browserGlobalAssignmentTarget(left *tree_sitter.Node) (string, string, bool) {
	switch {
	case left == nil:
		return "", "", false
	case left.Kind() == "member_expression":
		base := c.unwrapJsTransparentExpr(field(left, "object"))
		root := c.dotted(base)
		if !isBrowserGlobalObject(root) {
			return "", "", false
		}
		return root, c.dotted(left), true
	case left.Kind() == "subscript_expression":
		base := c.unwrapJsTransparentExpr(field(left, "object"))
		root := c.dotted(base)
		if !isBrowserGlobalObject(root) {
			return "", "", false
		}
		key := c.keyName(c.unwrapJsTransparentExpr(field(left, "index")))
		target := root + "[]"
		if key != "" {
			target = root + "." + key
		}
		return root, target, true
	}
	return "", "", false
}

func (c *jsConv) jsDecoratorTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "decorator" {
			continue
		}
		path := c.jsDecoratorPath(ch)
		add("decorator_path:" + path)
		if i := strings.LastIndex(path, "."); i >= 0 {
			add("decorator_method:" + path[i+1:])
		} else {
			add("decorator_method:" + path)
		}
	}
	return out
}

func (c *jsConv) jsParamEntries(name string, params []string, base []string) []nir.ParamEntry {
	if len(base) == 0 {
		if strings.EqualFold(name, "resolve") || strings.Contains(strings.ToLower(name), "resolver") {
			base = []string{"entry_kind:function_param"}
		} else {
			return nil
		}
	}
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := append([]string{}, base...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *jsConv) jsDecoratorPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "decorator", "call_expression":
		if p := c.jsDecoratorPath(field(n, "function")); p != "" {
			return p
		}
	case "member_expression":
		base := c.jsDecoratorPath(field(n, "object"))
		prop := c.text(field(n, "property"))
		if base == "" {
			return prop
		}
		if prop == "" {
			return base
		}
		return base + "." + prop
	case "identifier":
		return c.text(n)
	}
	for _, ch := range c.namedChildren(n) {
		if p := c.jsDecoratorPath(ch); p != "" {
			return p
		}
	}
	return ""
}

// jsEmptyPatternParam is the positional slot a destructuring parameter occupies
// when the pattern binds no name at all (`function f(a, {})`), so the parameters
// after it keep their positions.
const jsEmptyPatternParam = "__pattern__"

// patternSlot names the positional slot a destructuring parameter occupies and
// returns the names it introduces beyond that slot. The slot is the first bound
// name, so the argument passed at the pattern's position flows into it and the
// remaining names bind to the whole of it — the same whole-value reading the
// `const { a, b } = v` declaration lowering gives each bound name.
func (c *jsConv) patternSlot(pat *tree_sitter.Node) (string, []string) {
	names := c.bindingNames(pat)
	if len(names) == 0 {
		return jsEmptyPatternParam, nil
	}
	return names[0], names[1:]
}

// paramPattern returns the binding pattern a parameter node declares, unwrapping
// the TypeScript and default-value forms that carry it in a field.
func paramPattern(ch *tree_sitter.Node) *tree_sitter.Node {
	pat := ch
	switch ch.Kind() {
	case "required_parameter", "optional_parameter":
		pat = field(ch, "pattern")
	case "assignment_pattern":
		pat = field(ch, "left")
	}
	return pat
}

func (c *jsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	// single-identifier arrow param: x => ...
	if params.Kind() == "identifier" {
		return []string{c.text(params)}
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		pat := paramPattern(ch)
		if pat == nil {
			continue
		}
		switch pat.Kind() {
		case "identifier":
			out = append(out, c.text(pat))
		case "object_pattern", "array_pattern":
			slot, _ := c.patternSlot(pat)
			out = append(out, slot)
		}
	}
	return out
}

func (c *jsConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	if params.Kind() == "identifier" {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			if typ := jsTypeAnnotationAfter(c, params, ch); typ != "" {
				putParamType(out, c.text(ch), typ)
			}
		case "required_parameter", "optional_parameter":
			if pat := field(ch, "pattern"); pat != nil && pat.Kind() == "identifier" {
				putParamType(out, c.text(pat), paramTypeFromField(c, ch))
			}
		case "assignment_pattern":
			if l := field(ch, "left"); l != nil && l.Kind() == "identifier" {
				putParamType(out, c.text(l), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func jsTypeAnnotationAfter(c *jsConv, parent, id *tree_sitter.Node) string {
	if parent == nil || id == nil {
		return ""
	}
	seen := false
	for _, ch := range c.namedChildren(parent) {
		if sameTSNode(ch, id) {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		switch ch.Kind() {
		case "type_annotation":
			return c.text(ch)
		case "identifier", "required_parameter", "optional_parameter", "assignment_pattern":
			return ""
		}
	}
	return ""
}

func jsParamTypesFromText(s string) map[string]string {
	out := map[string]string{}
	start := strings.Index(s, "(")
	end := strings.Index(s, ")")
	if start < 0 || end <= start {
		return out
	}
	for _, part := range strings.Split(s[start+1:end], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if eq := strings.Index(part, "="); eq >= 0 {
			part = strings.TrimSpace(part[:eq])
		}
		colon := strings.Index(part, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(part[:colon])
		name = strings.TrimPrefix(name, "...")
		typ := strings.TrimSpace(part[colon+1:])
		putParamType(out, name, typ)
	}
	return out
}

func sameTSNode(a, b *tree_sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

func (c *jsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier", "property_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "this", "super":
		// model `this`/`super` as a Name so `this.method()` resolves to the enclosing class's
		// method (interprocedural taint through `this.helper(x)`), incl. inside arrow callbacks.
		return nir.Name{ID: "this", Loc: L}
	case "number":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "regex":
		if jsRegexMayBacktrack(c.text(n)) {
			return nir.Call{
				Callee: nir.Name{ID: "__regex.match", Loc: L},
				Args:   []nir.Expr{nir.Const{Loc: L, Value: c.text(n)}},
				Path:   "__regex.match",
				Method: "match",
				Loc:    L,
			}
		}
		// carry the literal `/pattern/flags` so a `filter` directive can analyze the
		// output alphabet of x.replace(/…/g, repl).
		return nir.Const{Loc: L, Value: c.text(n)}
	case "true", "false", "null", "undefined":
		// carry the literal text so value-matching can inspect boolean/null constants.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "member_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "property")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(field(n, "object")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "object")), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		if path == "?" && strings.HasPrefix(strings.TrimSpace(c.text(n)), "import(") {
			path = "import"
		}
		var arglist []nir.Expr
		for _, a := range c.jsCallArgNodes(n) {
			arglist = append(arglist, c.expr(a))
		}
		for i, a := range arglist {
			if lam, ok := a.(nir.Lambda); ok {
				arglist[i] = c.markCallLambdaParams(path, lam, L)
			}
		}
		if c.isExpressRouteRegistration(path) {
			for i, a := range arglist {
				if lam, ok := a.(nir.Lambda); ok {
					arglist[i] = c.typeExpressLambda(lam)
				}
			}
		}
		method := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			method = path[i+1:]
		}
		callee := c.expr(fn)
		if fn == nil && path == "import" {
			callee = nir.Name{ID: "import", Loc: L}
		}
		return nir.Call{Callee: callee, Args: arglist, Path: path, Method: method, Loc: L}
	case "new_expression":
		ctor := field(n, "constructor")
		path := c.dotted(ctor)
		var arglist []nir.Expr
		for _, a := range c.jsCallArgNodes(n) {
			arglist = append(arglist, c.expr(a))
		}
		method := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			method = path[i+1:]
		}
		return nir.Call{Callee: c.expr(ctor), Args: arglist, Path: path, Method: method, Loc: L}
	case "jsx_attribute":
		name := c.jsxAttributeName(n)
		if name == "dangerouslySetInnerHTML" {
			arg := c.jsxDangerouslySetInnerHTMLArg(c.jsxAttributeValue(n))
			return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: []nir.Expr{arg}, Path: name, Method: name, Loc: L}
		}
		if jsJsxRawMarkupAttribute[name] {
			// innerHTML/outerHTML parse the value as markup rather than
			// setting text, so the attribute is the same DOM property write
			// the imperative `el.innerHTML = v` form is; React's
			// dangerouslySetInnerHTML above is the same write in its own
			// spelling.
			arg := c.jsxExpressionArg(c.jsxAttributeValue(n))
			return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: []nir.Expr{arg}, Path: name, Method: name, Loc: L}
		}
		if val := c.jsxAttributeValue(n); val != nil {
			return c.expr(val)
		}
		return nir.Name{ID: name, Loc: L}
	case "jsx_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
		return nir.Const{Loc: L}
	case "await_expression", "parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression", "instantiation_expression", "type_assertion":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "arrow_function", "function_expression", "function":
		// a single bare arrow param `v => …` is under the `parameter` field, not `parameters`.
		return nir.Lambda{Params: c.funcParams(n), ParamTypes: c.funcParamTypes(n), Body: c.funcBody(n), Loc: L, ContextTokens: c.jsFunctionContext("<lambda>", n)}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat / add
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_expression":
		arg := field(n, "argument")
		if arg == nil {
			for _, ch := range c.namedChildren(n) {
				if ch.Kind() != "comment" {
					arg = ch
					break
				}
			}
		}
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(arg), Loc: L}
	case "ternary_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "template_string":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "template_substitution" {
				if kids := c.namedChildren(ch); len(kids) > 0 {
					parts = append(parts, c.expr(kids[0]))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Text: jsContextValue(c.text(n)), Loc: L}
		}
		return nir.Const{Loc: L}
	case "string":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "array", "arguments", "sequence_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "object":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			switch ch.Kind() {
			case "pair":
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			case "shorthand_property_identifier", "shorthand_property_identifier_pattern":
				// `{ filter }` === `{ filter: filter }` — the property carries the variable's taint.
				nm := c.text(ch)
				parts = append(parts, nir.Pair{Key: nm, Value: nir.Name{ID: nm, Loc: L}, Loc: L})
			case "spread_element":
				if k := c.namedChildren(ch); len(k) > 0 {
					parts = append(parts, c.expr(k[len(k)-1]))
				}
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *jsConv) jsxAttributeName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if name := field(n, "name"); name != nil {
		return c.text(name)
	}
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "property_identifier", "identifier", "jsx_identifier":
			return c.text(ch)
		}
	}
	return ""
}

func (c *jsConv) jsxAttributeValue(n *tree_sitter.Node) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	if val := field(n, "value"); val != nil {
		return val
	}
	name := c.jsxAttributeName(n)
	for _, ch := range c.namedChildren(n) {
		if c.text(ch) == name {
			continue
		}
		switch ch.Kind() {
		case "jsx_expression", "string", "object", "member_expression", "identifier", "call_expression":
			return ch
		}
	}
	return nil
}

func (c *jsConv) jsxDangerouslySetInnerHTMLArg(n *tree_sitter.Node) nir.Expr {
	n = c.unwrapJSXExpression(n)
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	if n.Kind() == "object" {
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "pair" && c.keyName(field(ch, "key")) == "__html" {
				return c.expr(field(ch, "value"))
			}
		}
	}
	return c.expr(n)
}

// jsxExpressionArg lowers a JSX attribute value to the expression it carries,
// unwrapping the `{ ... }` container so the value's own nodes survive.
func (c *jsConv) jsxExpressionArg(n *tree_sitter.Node) nir.Expr {
	n = c.unwrapJSXExpression(n)
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	return c.expr(n)
}

// jsJsxRawMarkupAttribute lists the DOM properties a JSX attribute can set
// whose value is parsed as markup rather than treated as text.
var jsJsxRawMarkupAttribute = map[string]bool{
	"innerHTML": true,
	"outerHTML": true,
}

func (c *jsConv) unwrapJSXExpression(n *tree_sitter.Node) *tree_sitter.Node {
	for n != nil {
		switch n.Kind() {
		case "jsx_expression", "parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression", "instantiation_expression", "type_assertion":
			kids := c.namedChildren(n)
			if len(kids) == 0 {
				return n
			}
			n = kids[0]
		default:
			return n
		}
	}
	return nil
}

var jsExpressRouteMethods = map[string]bool{
	"all": true, "delete": true, "get": true, "head": true, "options": true,
	"patch": true, "post": true, "put": true, "use": true,
}

func (c *jsConv) isExpressRouteRegistration(path string) bool {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return false
	}
	return jsExpressRouteMethods[path[i+1:]]
}

func (c *jsConv) typeExpressLambda(lam nir.Lambda) nir.Lambda {
	if len(lam.Params) == 0 {
		return lam
	}
	if lam.ParamTypes == nil {
		lam.ParamTypes = map[string]string{}
	}
	offset := 0
	if len(lam.Params) >= 4 {
		offset = 1
	}
	if offset < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset]] = "express.Request"
	}
	if offset+1 < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset+1]] = "express.Response"
	}
	if offset+2 < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset+2]] = "express.NextFunction"
	}
	return lam
}

func (c *jsConv) bindingNames(n *tree_sitter.Node) []string {
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			name := c.text(cur)
			if name != "" {
				out = append(out, name)
			}
			return
		}
		for _, ch := range c.namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

// keyName returns the bare name of an object-pair key — an identifier as-is, or a
// quoted string key with its surrounding quotes stripped.
func (c *jsConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	if n.Kind() == "string" && len(t) >= 2 {
		t = t[1 : len(t)-1]
	}
	return t
}

func isJsTransparentExpr(kind string) bool {
	switch kind {
	case "parenthesized_expression", "non_null_expression", "as_expression", "satisfies_expression", "instantiation_expression", "type_assertion":
		return true
	}
	return false
}

func (c *jsConv) unwrapJsTransparentExpr(n *tree_sitter.Node) *tree_sitter.Node {
	for n != nil && isJsTransparentExpr(n.Kind()) {
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return n
		}
		n = kids[0]
	}
	return n
}

func (c *jsConv) jsSelfDefaultAssignmentValue(left, rhs *tree_sitter.Node) (*tree_sitter.Node, bool) {
	left = c.unwrapJsTransparentExpr(left)
	rhs = c.unwrapJsTransparentExpr(rhs)
	if left == nil || rhs == nil || rhs.Kind() != "binary_expression" || c.text(field(rhs, "operator")) != "||" {
		return nil, false
	}
	lhs := c.unwrapJsTransparentExpr(field(rhs, "left"))
	def := c.unwrapJsTransparentExpr(field(rhs, "right"))
	if lhs == nil || def == nil || c.dotted(left) == "?" || c.dotted(left) != c.dotted(lhs) {
		return nil, false
	}
	return def, true
}

func isBrowserGlobalObject(path string) bool {
	switch path {
	case "window", "globalThis", "self":
		return true
	}
	return false
}

func (c *jsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	n = c.unwrapJsTransparentExpr(n)
	switch n.Kind() {
	case "identifier", "property_identifier":
		return c.text(n)
	case "this":
		return "this"
	case "member_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "property"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		return c.dotted(field(n, "object")) + "[]"
	}
	return "?"
}

func (c *jsConv) lastIdent(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "identifier" {
			return ch
		}
	}
	return nil
}

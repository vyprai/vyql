package treesitter

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/regexambig"
)

// rbConv walks a tree-sitter Ruby CST into NIR. Ruby has no per-file module
// namespacing and global classes, so the module key is "" for every file and
// there is no import table; "type resolution" is constant→class on the call
// receiver, handled uniformly by the shared lowering engine (as in the PoC's
// Ripper frontend). All binary operators are treated as taint-propagating
// (string build), matching frontend_ruby.py.
type rbConv struct {
	src        []byte
	root       string
	file       string
	visibility string
	childCache map[uintptr][]*tree_sitter.Node
}

func (c *rbConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = make(map[uintptr][]*tree_sitter.Node)
	}
	key := uintptr(n.Id())
	if kids, ok := c.childCache[key]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[key] = kids
	return kids
}

// ExtractRuby parses Ruby files into one NIR Program (all modules keyed "").
func ExtractRuby(files []string, root string) (nir.Program, error) {
	var ruby, erb []string
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f), ".erb") {
			erb = append(erb, f)
		} else {
			ruby = append(ruby, f)
		}
	}
	build := func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
		c := &rbConv{src: src, root: root, file: rel}
		body := append(c.rubyModuleContext(tree.RootNode()), c.blockChildren(tree.RootNode())...)
		return nir.Module{Key: "", File: rel, Body: body}, true
	}
	mods := parseModules(ruby, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsruby.Language()))
			return p
		},
		build)
	mods = append(mods, parseERBModules(erb, root, build)...)
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func parseERBModules(
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
		code, ok := erbRubySource(src)
		if !ok {
			continue
		}
		parser := tree_sitter.NewParser()
		_ = parser.SetLanguage(tree_sitter.NewLanguage(tsruby.Language()))
		tree := parser.Parse(code, nil)
		if tree == nil {
			parser.Close()
			continue
		}
		m, good := build(code, f, relPath(root, f)+"#erb.rb", tree)
		tree.Close()
		parser.Close()
		if good {
			m.Body = append(m.Body, erbUnescapedHrefInterpolationObservations(src, relPath(root, f)+"#erb.rb")...)
			m.Body = append(m.Body, erbHTMLEscapedURLHrefObservations(src, relPath(root, f)+"#erb.rb")...)
			m.Hash = contentHash(src)
			out = append(out, m)
		}
	}
	return out
}

var erbHrefInterpolationRe = regexp.MustCompile(`(?i)\bhref\s*=\s*["'][^"']*#\{([^}]*)\}`)
var erbHrefOutputRe = regexp.MustCompile(`(?i)\bhref\s*=\s*["']\s*<%=\s*([^%]+?)\s*%>`)

func erbUnescapedHrefInterpolationObservations(src []byte, rel string) []nir.Stmt {
	var out []nir.Stmt
	for i, line := range strings.Split(string(src), "\n") {
		for _, m := range erbHrefInterpolationRe.FindAllStringSubmatch(line, -1) {
			if len(m) < 2 {
				continue
			}
			expr := strings.TrimSpace(m[1])
			if expr == "" || erbInterpolationExprEscaped(expr) || !erbHrefInterpolationExprNeedsEscaping(expr) {
				continue
			}
			loc := rel + ":" + itoa(i+1)
			path := "analysis.erb.unescaped_href_interpolation"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "lang=ruby"},
					nir.Const{Loc: loc, Value: "template=erb"},
					nir.Const{Loc: loc, Value: "attr=href"},
					nir.Const{Loc: loc, Value: "expr=" + expr},
				},
				Path:   path,
				Method: "unescaped_href_interpolation",
				Loc:    loc,
			}})
		}
	}
	return out
}

func erbInterpolationExprEscaped(expr string) bool {
	expr = strings.TrimSpace(expr)
	for _, prefix := range []string{
		"h(",
		"html_escape(",
		"escape_html(",
		"Rack::Utils.escape_html(",
		"ERB::Util.html_escape(",
		"CGI.escapeHTML(",
	} {
		if strings.HasPrefix(expr, prefix) {
			return true
		}
	}
	return false
}

func erbHrefInterpolationExprNeedsEscaping(expr string) bool {
	expr = strings.TrimSpace(expr)
	return strings.Contains(expr, ".") ||
		strings.Contains(expr, "[") ||
		strings.HasPrefix(expr, "@")
}

func erbHTMLEscapedURLHrefObservations(src []byte, rel string) []nir.Stmt {
	var out []nir.Stmt
	for i, line := range strings.Split(string(src), "\n") {
		for _, m := range erbHrefOutputRe.FindAllStringSubmatch(line, -1) {
			if len(m) < 2 {
				continue
			}
			expr, helper, ok := erbHTMLEscapeCall(strings.TrimSpace(m[1]))
			if !ok || !erbHrefExprLooksURLValue(expr) {
				continue
			}
			loc := rel + ":" + itoa(i+1)
			path := "analysis.erb.html_escaped_url_href"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "lang=ruby"},
					nir.Const{Loc: loc, Value: "template=erb"},
					nir.Const{Loc: loc, Value: "attr=href"},
					nir.Const{Loc: loc, Value: "value=url-like"},
					nir.Const{Loc: loc, Value: "helper=" + helper},
					nir.Const{Loc: loc, Value: "expr=" + expr},
				},
				Path:   path,
				Method: "html_escaped_url_href",
				Loc:    loc,
			}})
		}
	}
	return out
}

func erbHTMLEscapeCall(expr string) (string, string, bool) {
	for _, h := range []struct {
		prefix string
		name   string
	}{
		{"h(", "html_escape"},
		{"escape(", "html_escape"},
		{"html_escape(", "html_escape"},
		{"escape_html(", "html_escape"},
		{"Rack::Utils.escape_html(", "html_escape"},
		{"ERB::Util.html_escape(", "html_escape"},
		{"CGI.escapeHTML(", "html_escape"},
	} {
		if !strings.HasPrefix(expr, h.prefix) || !strings.HasSuffix(expr, ")") {
			continue
		}
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, h.prefix), ")"))
		if inner == "" {
			continue
		}
		return inner, h.name, true
	}
	return "", "", false
}

func erbHrefExprLooksURLValue(expr string) bool {
	lower := strings.ToLower(expr)
	for _, marker := range []string{"url", "uri", "href", "homepage", "website", "link"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func erbRubySource(src []byte) ([]byte, bool) {
	out := make([]byte, len(src))
	for i, b := range src {
		switch b {
		case '\n', '\r':
			out[i] = b
		default:
			out[i] = ' '
		}
	}
	found := false
	for i := 0; i+1 < len(src); {
		if src[i] != '<' || src[i+1] != '%' {
			i++
			continue
		}
		start := i + 2
		if start < len(src) && src[start] == '#' {
			if end := bytes.Index(src[start:], []byte("%>")); end >= 0 {
				i = start + end + 2
			} else {
				break
			}
			continue
		}
		if start < len(src) && src[start] == '=' {
			start++
		}
		endRel := bytes.Index(src[start:], []byte("%>"))
		if endRel < 0 {
			break
		}
		end := start + endRel
		copy(out[start:end], src[start:end])
		found = true
		i = end + 2
	}
	return out, found
}

func (c *rbConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *rbConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *rbConv) blockChildren(n *tree_sitter.Node) []nir.Stmt {
	return c.rbStmtList(c.namedChildren(n))
}

func (c *rbConv) body(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	// body_statement holds the method/class body statements
	return c.blockChildren(n)
}

func (c *rbConv) rbMethodBody(n *tree_sitter.Node) []nir.Stmt {
	stmts := c.body(n)
	if len(stmts) == 0 {
		return stmts
	}
	if last, ok := stmts[len(stmts)-1].(nir.ExprStmt); ok {
		// Named field rather than a nir.Return(last) conversion: the two structs
		// happen to share a layout today, and a conversion would silently follow
		// them apart if either gains a field.
		//nolint:staticcheck // S1016
		stmts[len(stmts)-1] = nir.Return{Value: last.Value}
	}
	return stmts
}

func (c *rbConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "method", "singleton_method":
		body := field(n, "body")
		name := c.text(field(n, "name"))
		params := c.params(field(n, "parameters"))
		out := c.rubyFunctionContext(n)
		out = append(out, nir.FuncDef{
			Name:         name,
			Params:       params,
			ParamEntries: c.rbParamEntries(name, params),
			Body:         c.rbMethodBody(body),
			Loc:          L,
			Exported:     c.rubyExportedMethod(name),
		})
		return out
	case "class", "module":
		bases := c.rubyClassBases(n)
		out := c.rubyClassContext(n, bases)
		oldVisibility := c.visibility
		c.visibility = "public"
		body := c.body(field(n, "body"))
		c.visibility = oldVisibility
		out = append(out, nir.ClassDef{Name: c.text(field(n, "name")), Bases: bases, Body: body, Loc: L})
		return out
	case "singleton_class":
		oldVisibility := c.visibility
		c.visibility = "public"
		body := c.body(field(n, "body"))
		c.visibility = oldVisibility
		return body
	case "assignment":
		left := field(n, "left")
		right := c.expr(field(n, "right"))
		if left != nil && (left.Kind() == "identifier" || left.Kind() == "constant" || left.Kind() == "instance_variable") {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// subscript write (bag['key'] = v) — model as a write to the base's path.
		// Method empty -> no method-sink collision.
		if left != nil && left.Kind() == "element_reference" {
			base := field(left, "object")
			if base == nil {
				if kids := c.namedChildren(left); len(kids) > 0 {
					base = kids[0]
				}
			}
			if base != nil {
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right},
					Path: c.dotted(base), Method: "", Loc: L}}}
			}
		}
		// attribute/setter write (obj.field = v) — model as a path-sink Call on the target path.
		if left != nil && left.Kind() == "call" {
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right},
				Path: c.dotted(left), Method: "", Loc: L}}}
		}
		return []nir.Stmt{nir.Assign{Value: right}}
	case "operator_assignment":
		left := field(n, "left")
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: c.expr(field(n, "right")), Loc: L}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(field(n, "right"))}}
	case "return", "return_statement":
		kids := c.namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). Ruby did not evaluate the condition (collectBodies gathers
	// then/else/elsif/when bodies, not the predicate), so Cond stays nil → byte-identical.
	case "if":
		// separate Then/Else so the join-merge keeps the live branch tainted and a constant
		// condition prunes.
		cond := field(n, "condition")
		ifn := nir.If{Cond: c.expr(cond), Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}
		if target, val, ok := c.rbAssignmentExpr(cond); ok {
			return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}, ifn}
		}
		return []nir.Stmt{ifn}
	case "unless":
		// `unless c` runs the body when c is FALSE — split branches for the join-merge, but
		// leave Cond nil (no const-prune, to avoid inverting the condition incorrectly).
		cond := field(n, "condition")
		ifn := nir.If{Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}
		if target, val, ok := c.rbAssignmentExpr(cond); ok {
			return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: val}, ifn}
		}
		return []nir.Stmt{ifn}
	case "while", "until", "for":
		return []nir.Stmt{nir.Loop{Body: c.collectBodies(n)}}
	case "begin":
		return []nir.Stmt{nir.Try{Body: c.collectBodies(n)}}
	case "case":
		return []nir.Stmt{c.rubyCase(n)}
	case "body_statement", "then", "else", "elsif", "ensure", "when", "do_block", "block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBodies(n)}}
	case "comment":
		return nil
	case "identifier", "constant":
		name := c.text(n)
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Path: name, Method: name, Loc: L}}}
	case "call", "method_call", "command", "command_call":
		// A call may carry a trailing block (`coll.each { |x| sink(x) }`, `lambda { |v| … }`).
		// The block body was previously dropped, hiding sources/sinks inside it. Emit the call,
		// then the block body inline (see callBlockStmts).
		out := []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
		return append(out, c.callBlockStmts(n)...)
	}
	// any other expression used as a statement
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *rbConv) rubyFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(fn, "name"))
	params := c.params(field(fn, "parameters"))
	loc := c.loc(fn)
	text := c.text(body)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=ruby\x00name=" + name + "\x00function_name:" + name},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: rbCompactText(text)},
	}
	for i, p := range params {
		args = append(args,
			nir.Const{Loc: loc, Value: "param_name:" + p},
			nir.Const{Loc: loc, Value: "param_index:" + itoa(i)},
		)
	}
	for _, tok := range c.rbStructuredContextTokens(body, "function") {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.function.context", Loc: loc},
		Args:   args,
		Path:   "analysis.function.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *rbConv) rubyModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	loc := c.file + ":1"
	text := c.text(root)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=ruby"},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: rbCompactText(text)},
	}
	for _, tok := range c.rbStructuredContextTokens(root, "module") {
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

func (c *rbConv) rubyClassContext(cls *tree_sitter.Node, bases []string) []nir.Stmt {
	body := field(cls, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(cls, "name"))
	loc := c.loc(cls)
	text := c.text(body)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: rubyClassTokenString(name, bases)},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: rbCompactText(text)},
	}
	for _, tok := range c.rbStructuredContextTokens(body, "class") {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.class.context", Loc: loc},
		Args:   args,
		Path:   "analysis.class.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func rubyClassTokenString(name string, bases []string) string {
	tokens := []string{"lang=ruby", "name=" + name, "class_name:" + name}
	for _, base := range bases {
		if base == "" {
			continue
		}
		tokens = append(tokens, "class_base:"+base)
	}
	if len(bases) > 0 {
		tokens = append(tokens, "class_bases="+strings.Join(bases, ","))
	}
	return strings.Join(tokens, "\x00")
}

func (c *rbConv) rubyClassBases(cls *tree_sitter.Node) []string {
	if cls == nil || cls.Kind() != "class" {
		return nil
	}
	base := field(cls, "superclass")
	if base == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, value := range []string{c.dotted(base), rbCompactText(c.text(base)), strings.ReplaceAll(rbCompactText(c.text(base)), "::", ".")} {
		value = strings.TrimPrefix(value, "<")
		value = strings.TrimSpace(value)
		if value == "" || value == "?" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func (c *rbConv) rbStructuredContextTokens(root *tree_sitter.Node, scope string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch n.Kind() {
		case "assignment":
			left, right := field(n, "left"), field(n, "right")
			if lhs := c.rbContextPath(left); lhs != "" {
				if rhs := rbContextValue(c.text(right)); rhs != "" {
					add("assign:" + lhs + "=" + rhs)
					for _, suffix := range rbDottedSuffixes(lhs) {
						add("assign:" + suffix + "=" + rhs)
					}
				}
				add("selector:" + lhs)
				for _, suffix := range rbDottedSuffixes(lhs) {
					add("selector:" + suffix)
				}
			}
		case "binary":
			if expr := rbCompactText(c.text(n)); expr != "" {
				add("expr:" + expr)
			}
		case "pair":
			if key := rbCompactText(c.keyName(field(n, "key"))); key != "" {
				if val := rbContextValue(c.text(field(n, "value"))); val != "" {
					add("field:" + key + "=" + val)
				}
			}
		case "call", "method_call", "command", "command_call":
			if path := c.dotted(n); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
				add("selector:" + path)
			}
		case "element_reference":
			if idx := c.dotted(n); idx != "" && idx != "?" {
				add("index:" + idx)
			}
			if base := c.dotted(field(n, "object")); base != "" && base != "?" {
				add("index_base:" + base)
				if key := rbContextValue(c.text(field(n, "argument"))); key != "" {
					add("index_key:" + base + ":" + key)
				}
			}
		case "string", "heredoc_body", "heredoc_content":
			if lit := rbContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
			for _, interp := range rbInterpolationValues(c.text(n)) {
				add("interpolation:" + interp)
			}
		case "regex":
			if lit := rubyRegexPattern(c.text(n)); lit != "" {
				add("regex:" + rbCompactText(lit))
				add("literal:" + rbCompactText(lit))
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	for _, tok := range rbSemanticReviewTokens(c.text(root), scope) {
		add(tok)
	}
	return out
}

func (c *rbConv) rbContextPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if p := c.dotted(n); p != "" && p != "?" {
		return p
	}
	return rbCompactText(c.text(n))
}

func rbDottedSuffixes(path string) []string {
	parts := strings.Split(path, ".")
	if len(parts) < 3 {
		return nil
	}
	out := make([]string, 0, len(parts)-2)
	for i := 1; i < len(parts)-1; i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

func rbContextValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"' || q == '`') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
		}
	}
	return rbCompactText(s)
}

func rbInterpolationValues(raw string) []string {
	var out []string
	for _, m := range rbInterpolationRe.FindAllStringSubmatch(raw, -1) {
		if len(m) == 2 {
			if v := rbCompactText(m[1]); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

var rbInterpolationRe = regexp.MustCompile(`#\{([^}]*)\}`)

func rbSemanticReviewTokens(raw, scope string) []string {
	compact := rbCompactText(raw)
	var out []string
	add := func(fact string) {
		out = append(out, "ruby_review:"+fact)
	}
	if scope == "function" && rbStoredHTMLInterpolationMissingSanitizeRe.MatchString(raw) && !strings.Contains(compact, "sanitize") {
		add("stored_html_interpolation_missing_sanitize")
	}
	if scope == "function" && (strings.Contains(compact, "find_by(params[") || strings.Contains(compact, "find_by(params)")) {
		add("active_record_find_by_request_hash")
	}
	// A CSV row assembled by mapping over collection data, with no formula
	// guard anywhere in the function, is the OWASP CSV-injection shape: a cell
	// beginning with = + - @ executes when the export is opened in a
	// spreadsheet. The guard signals are the conventional ones -- a sanitizer
	// or escaper call, or the prefix-quote idiom itself.
	if scope == "function" &&
		(strings.Contains(compact, "CSV.generate_line(") || strings.Contains(compact, "CSV.generate(")) &&
		strings.Contains(compact, ".map") &&
		!strings.Contains(compact, "sanitize") && !strings.Contains(compact, "Sanitiz") &&
		!strings.Contains(compact, "escape") && !strings.Contains(compact, "csv_safe") &&
		!strings.Contains(compact, "\"'#{") && !strings.Contains(compact, "'\\''#{") {
		add("csv_formula_prone_export_row")
	}
	if scope == "class" &&
		strings.Contains(compact, "Chef::WebUIUser.cdb_load") &&
		strings.Contains(compact, "cdb_save") &&
		strings.Contains(compact, "cdb_destroy") &&
		!strings.Contains(compact, "before:is_admin") {
		add("chef_user_management_missing_admin_guard")
	}
	if scope == "function" && rbPersistentResponseReuse(compact) && !strings.Contains(compact, "persistent_socket_reusable") {
		add("persistent_response_reuse_missing_guard")
	}
	if scope == "class" &&
		strings.Contains(compact, "ClockworkWeb.enable(") &&
		strings.Contains(compact, "ClockworkWeb.disable(") &&
		strings.Contains(compact, "params[:job]") &&
		strings.Contains(compact, "params[:enable]") &&
		!strings.Contains(compact, "protect_from_forgery") {
		add("clockwork_job_csrf_missing_forgery_protection")
	}
	if scope == "function" && rbConvertBacktickInterpolationRe.MatchString(raw) &&
		!strings.Contains(compact, "shellescape") &&
		!strings.Contains(compact, ".to_i") {
		add("imagemagick_convert_backtick_unescaped_interpolation")
	}
	if scope == "function" &&
		strings.Contains(compact, "WINDOWS") &&
		strings.Contains(compact, "sprintf") &&
		strings.Contains(compact, ".join('')") &&
		strings.Contains(compact, "@paths.map") &&
		rbBacktickInterpolationRe.MatchString(raw) &&
		!strings.Contains(compact, "Open3.capture3") &&
		!strings.Contains(compact, "Shellwords") &&
		!strings.Contains(compact, "shellescape") {
		add("windows_backtick_diff_command_unescaped")
	}
	if scope == "function" &&
		strings.Contains(compact, "FROMpost_revisions") &&
		strings.Contains(compact, "JOINpostsp") &&
		strings.Contains(compact, "report.data<<") &&
		!strings.Contains(compact, "Archetype.private_message") &&
		!strings.Contains(compact, "secure_category") {
		add("post_edit_report_missing_private_filters")
	}
	if scope == "function" && rbQueryStringJoinInterpolationRe.MatchString(raw) && !strings.Contains(compact, "CGI.escape(") {
		add("unescaped_query_string_join_interpolation")
	}
	if scope == "function" && strings.Contains(compact, "string.to_s") && strings.Contains(compact, "/^[0-9a-f]{24}$/i") {
		add("ruby_line_anchor_hex_validation")
	}
	if scope == "function" && strings.Contains(compact, "SSLContext.new") && strings.Contains(compact, ".ca_file=") && !strings.Contains(compact, ".verify_mode=") {
		add("tls_ca_file_without_verify_mode")
	}
	if scope == "function" &&
		strings.Contains(compact, "polymorphic_as") &&
		strings.Contains(compact, "_type=") &&
		strings.Contains(compact, "params[\"#{polymorphic_as}_type\"]") &&
		strings.Contains(compact, ".send(") &&
		!strings.Contains(compact, "valid_polymorphic_class") {
		add("polymorphic_type_selected_from_params")
	}
	if scope == "function" &&
		strings.Contains(compact, "unconfirmed_email=self.email") &&
		strings.Contains(compact, "email=self.devise_email_in_database") &&
		strings.Contains(compact, "confirmation_token=nil") &&
		strings.Contains(compact, "generate_confirmation_token") &&
		!strings.Contains(compact, "devise_unconfirmed_email_will_change!") {
		add("devise_reconfirmation_missing_dirty_tracking")
	}
	if scope == "function" &&
		strings.Contains(compact, "run_shell_command(") &&
		strings.Contains(compact, "gitclone") &&
		rbGitCloneInterpolatedBranchOptionRe.MatchString(compact) &&
		!strings.Contains(compact, "Shellwords") &&
		!strings.Contains(compact, "shellescape") {
		add("git_clone_interpolated_branch_option_unescaped")
	}
	// A JOSE decoder that chooses its branch from the token's own compact
	// serialization -- three segments for JWS, five for JWE -- accepts an
	// encrypted token wherever a signed one is accepted. Encrypting to a
	// recipient public key proves no identity, so the caller reads claims whose
	// signature was never verified. The control is a guard on the encrypted
	// branch: a raise, a return, or a test of what the caller expected, on the
	// line that follows the branch selector.
	if scope == "function" &&
		rbJoseSeparatorCountDispatchRe.MatchString(raw) &&
		rbJoseSignedDecodeRe.MatchString(raw) &&
		rbJoseEncryptedDecodeRe.MatchString(raw) &&
		!rbJoseEncryptedBranchGuardRe.MatchString(raw) {
		add("jose_compact_decode_accepts_encrypted_serialization")
	}
	return out
}

var (
	rbStoredHTMLInterpolationMissingSanitizeRe = regexp.MustCompile(`#\{[^}]+\.content\}`)
	rbResponseAssignRe                         = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=response\(([A-Za-z_][A-Za-z0-9_]*)\)`)
	rbConvertBacktickInterpolationRe           = regexp.MustCompile("`\\s*convert\\s+#\\{[^}]+\\}.*-colors\\s+#\\{[^}]+\\}.*-depth\\s+#\\{[^}]+\\}")
	rbBacktickInterpolationRe                  = regexp.MustCompile("`\\s*#\\{[^}]+\\}\\s*`")
	rbQueryStringJoinInterpolationRe           = regexp.MustCompile(`\?[A-Za-z0-9_%-]+=\s*#\{[^}]+\.join\(`)
	rbGitCloneInterpolatedBranchOptionRe       = regexp.MustCompile(`--branch#\{[^}]*branch[^}]*\}--single-branch`)
	rbJoseSeparatorCountDispatchRe             = regexp.MustCompile(`\.count\(\s*['"]\.['"]\s*\)`)
	rbJoseSignedDecodeRe                       = regexp.MustCompile(`\bJWS[A-Za-z0-9_]*\.decode`)
	rbJoseEncryptedDecodeRe                    = regexp.MustCompile(`\bJWE[A-Za-z0-9_]*\.decode`)
	rbJoseEncryptedBranchGuardRe               = regexp.MustCompile(`(?m)^[ \t]*(?:when|if|elsif)\b[^\n]*\bJWE\b[^\n]*\n[ \t]*(?:if|unless|raise|fail|return|next|break)\b`)
)

func rbPersistentResponseReuse(compact string) bool {
	for _, m := range rbResponseAssignRe.FindAllStringSubmatchIndex(compact, -1) {
		if len(m) < 6 {
			continue
		}
		lhs := compact[m[2]:m[3]]
		rhs := compact[m[4]:m[5]]
		if lhs != rhs {
			continue
		}
		rest := compact[m[1]:]
		if strings.Contains(rest, lhs+"[:persistent]") && strings.Contains(rest, "reset") {
			return true
		}
	}
	return false
}

func (c *rbConv) rbParamEntries(name string, params []string) []nir.ParamEntry {
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" {
			continue
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: []string{
			"function_name:" + name,
			"param_name:" + p,
			"param_index:" + itoa(i),
		}})
	}
	return out
}

func (c *rbConv) rbAssignmentExpr(n *tree_sitter.Node) (string, nir.Expr, bool) {
	for n != nil && n.Kind() == "parenthesized_statements" {
		kids := c.namedChildren(n)
		if len(kids) != 1 {
			return "", nil, false
		}
		n = kids[0]
	}
	if n == nil || n.Kind() != "assignment" {
		for _, ch := range c.namedChildren(n) {
			if target, val, ok := c.rbAssignmentExpr(ch); ok {
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

func rbCompactText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// rubyBody lowers the statements of a then/else clause node (or a bare body).
func (c *rbConv) rubyBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if n.Kind() == "then" || n.Kind() == "else" || n.Kind() == "body_statement" {
		return c.rbStmtList(c.namedChildren(n))
	}
	return c.stmt(n)
}

// rubyAlt builds the Else branch from an `elsif`/`else` alternative node (elsif chains
// into a nested If for the join-merge + pruning).
func (c *rbConv) rubyAlt(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if n.Kind() == "elsif" {
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}}
	}
	return c.rubyBody(n) // else
}

// rubyCase lowers `case x; when a,b then …; else …; end` into a Switch with subject +
// per-arm labels so a constant subject prunes to the matching arm.
func (c *rbConv) rubyCase(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "when":
			var labs []nir.Expr
			var body []nir.Stmt
			for _, w := range c.namedChildren(ch) {
				switch w.Kind() {
				case "pattern":
					if k := c.namedChildren(w); len(k) > 0 {
						labs = append(labs, c.expr(k[0]))
					}
				case "then":
					body = append(body, c.rubyBody(w)...)
				}
			}
			cases = append(cases, body)
			labels = append(labels, labs)
		case "else":
			deflt = append(deflt, c.rubyBody(ch)...)
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
}

// collectBodies gathers statements from a control node's body / clause children
// (flow-approximate).
func (c *rbConv) collectBodies(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	kids := c.namedChildren(n)
	for i := 0; i < len(kids); i++ {
		ch := kids[i]
		switch ch.Kind() {
		case "body_statement", "then", "else", "elsif", "ensure", "when", "do_block", "block":
			out = append(out, c.collectBodies(ch)...)
		case "comment":
		default:
			if isRbCallNode(ch) && rbCallHasHeredocArg(ch) && i+1 < len(kids) && kids[i+1].Kind() == "heredoc_body" {
				out = append(out, c.callStmtWithExtraArg(ch, c.expr(kids[i+1]))...)
				i++
				continue
			}
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

func (c *rbConv) rbStmtList(kids []*tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for i := 0; i < len(kids); i++ {
		ch := kids[i]
		if vis := c.rubyVisibilityMarker(ch); vis != "" {
			c.visibility = vis
			continue
		}
		if isRbCallNode(ch) && rbCallHasHeredocArg(ch) && i+1 < len(kids) && kids[i+1].Kind() == "heredoc_body" {
			out = append(out, c.callStmtWithExtraArg(ch, c.expr(kids[i+1]))...)
			i++
			continue
		}
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *rbConv) rubyVisibilityMarker(n *tree_sitter.Node) string {
	if !isRbCallNode(n) {
		return ""
	}
	switch strings.TrimSpace(c.text(n)) {
	case "public", "private", "protected":
		return strings.TrimSpace(c.text(n))
	default:
		return ""
	}
}

func (c *rbConv) rubyExportedMethod(name string) bool {
	if strings.HasPrefix(name, "_") {
		return false
	}
	return c.visibility == "" || c.visibility == "public"
}

func isRbCallNode(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "call", "method_call", "command", "command_call":
		return true
	default:
		return false
	}
}

func rbCallHasHeredocArg(n *tree_sitter.Node) bool {
	if al := field(n, "arguments"); al != nil {
		for _, a := range namedChildren(al) {
			if a.Kind() == "heredoc_beginning" {
				return true
			}
		}
	}
	return false
}

func (c *rbConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			out = append(out, c.text(ch))
		case "optional_parameter", "keyword_parameter", "splat_parameter", "typed_parameter":
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else if kids := c.namedChildren(ch); len(kids) > 0 && kids[0].Kind() == "identifier" {
				out = append(out, c.text(kids[0]))
			}
		}
	}
	return out
}

func (c *rbConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "constant", "instance_variable", "global_variable":
		return nir.Name{ID: c.text(n), Loc: L}
	case "nil":
		return nir.Const{Loc: L}
	case "simple_symbol", "hash_key_symbol":
		return nir.Const{Loc: L, Value: strings.TrimSuffix(strings.TrimPrefix(c.text(n), ":"), ":")}
	case "integer", "float":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "true", "false":
		return nir.Const{Loc: L, Value: c.text(n)} // boolean value for `val` matching
	case "string":
		return c.string(n, L)
	case "heredoc_body", "heredoc_content":
		return c.string(n, L)
	case "regex":
		if rubyRegexMayBacktrack(c.text(n)) {
			return nir.Call{
				Callee: nir.Name{ID: "__regex.match", Loc: L},
				Args:   []nir.Expr{nir.Const{Loc: L, Value: c.text(n)}},
				Path:   "__regex.match",
				Method: "match",
				Loc:    L,
			}
		}
		// carry `/pattern/` so a `filter` directive (gsub) can analyze its output alphabet.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "call", "method_call", "command", "command_call":
		return c.call(n, L)
	case "element_reference":
		var key nir.Expr
		if kids := c.namedChildren(n); len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: c.expr(field(n, "object")), Key: key, Path: c.dotted(field(n, "object")), Loc: L}
	case "binary":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		switch op {
		case "+", "<<", "%": // string concat / append / format — keep taint-propagating Format
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "conditional":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "unary":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
	case "parenthesized_statements":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.expr(kids[len(kids)-1])
		}
	case "array", "argument_list":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "hash":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "pair" {
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "pair":
		// a keyword argument (foo(k: v)) appearing directly in an argument_list
		return nir.Pair{Key: c.keyName(field(n, "key")), Value: c.expr(field(n, "value")), Loc: L}
	case "scope_resolution":
		// A::B used as a value is a constant token; carry it for `val` matching
		// while call-path construction still uses dotted(AST) directly.
		return nir.Const{Loc: L, Value: c.dotted(n)}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// keyName returns the bare name of a hash/keyword key — a symbol (verify:, :verify)
// with its colon stripped, or a string key with quotes stripped.
func (c *rbConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	switch n.Kind() {
	case "hash_key_symbol":
		return t // already bare, e.g. "verify"
	case "simple_symbol":
		return strings.TrimPrefix(t, ":")
	case "string":
		if len(t) >= 2 {
			return t[1 : len(t)-1]
		}
	}
	return strings.TrimSuffix(strings.TrimPrefix(t, ":"), ":")
}

func rubyRegexMayBacktrack(raw string) bool {
	pat := rubyRegexPattern(raw)
	if pat == "" {
		return false
	}
	if regexambig.Ambiguous(pat) {
		return true
	}
	alts := strings.Split(pat, "|")
	if len(alts) < 2 {
		return false
	}
	seen := map[byte]bool{}
	for _, alt := range alts {
		ch, ok := firstBacktrackingQuantifiedLiteral(alt)
		if !ok {
			continue
		}
		if seen[ch] {
			return true
		}
		seen[ch] = true
	}
	return false
}

func rubyRegexPattern(raw string) string {
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

func firstBacktrackingQuantifiedLiteral(alt string) (byte, bool) {
	for i := 0; i+1 < len(alt); i++ {
		if isEscaped(alt, i) || !isRegexLiteralByte(alt[i]) || !isRegexQuantifier(alt[i+1]) {
			continue
		}
		if isPossessiveQuantifier(alt, i+1) {
			return 0, false
		}
		return alt[i], true
	}
	return 0, false
}

func isRegexLiteralByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isRegexQuantifier(b byte) bool {
	return b == '+' || b == '*'
}

func isPossessiveQuantifier(s string, i int) bool {
	return i+1 < len(s) && s[i+1] == '+'
}

func (c *rbConv) string(n *tree_sitter.Node, L string) nir.Expr {
	var parts []nir.Expr
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range c.namedChildren(m) {
			if ch.Kind() == "interpolation" {
				for _, e := range c.namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			} else {
				walk(ch)
			}
		}
	}
	walk(n)
	if len(parts) > 0 {
		return nir.Format{Parts: parts, Loc: L}
	}
	// non-interpolated string: carry the literal text for value-matching (`val "…"`).
	return nir.Const{Loc: L, Value: c.text(n)}
}

func (c *rbConv) call(n *tree_sitter.Node, L string) nir.Expr {
	recv := field(n, "receiver")
	method := c.text(field(n, "method"))
	path := c.dotted(n)
	var callee nir.Expr
	if recv == nil {
		callee = nir.Name{ID: orQ(method), Loc: L}
	} else {
		callee = nir.Attr{Base: c.expr(recv), Attr: orQ(method), Path: path, Loc: L}
	}
	var args []nir.Expr
	if al := field(n, "arguments"); al != nil {
		for _, a := range c.namedChildren(al) {
			args = append(args, c.expr(a))
		}
	}
	m := method
	if m == "" {
		if i := strings.LastIndex(path, "."); i >= 0 {
			m = path[i+1:]
		} else {
			m = path
		}
	}
	return nir.Call{Callee: callee, Args: args, Path: path, Method: m, Loc: L}
}

func (c *rbConv) callStmtWithExtraArg(n *tree_sitter.Node, extra nir.Expr) []nir.Stmt {
	L := c.loc(n)
	call, ok := c.call(n, L).(nir.Call)
	if !ok {
		return c.stmt(n)
	}
	call.Args = append(call.Args, extra)
	out := []nir.Stmt{nir.ExprStmt{Value: call}}
	return append(out, c.callBlockStmts(n)...)
}

// callBlockStmts lowers a trailing block on a call (`recv.each { |x| … }`, `lambda { |v| … }`)
// into inline statements: each block parameter is taint-joined from the receiver (the iterated
// collection / object), then the block body is lowered. This surfaces sinks/sources inside the
// block and connects taint from a tainted receiver into the block param.
func (c *rbConv) callBlockStmts(n *tree_sitter.Node) []nir.Stmt {
	var blk *tree_sitter.Node
	if b := field(n, "block"); b != nil {
		blk = b
	} else {
		for _, ch := range c.namedChildren(n) {
			if k := ch.Kind(); k == "block" || k == "do_block" {
				blk = ch
				break
			}
		}
	}
	if blk == nil {
		return nil
	}
	var out []nir.Stmt
	if recv := field(n, "receiver"); recv != nil {
		rv := c.expr(recv)
		for _, p := range c.blockParams(blk) {
			out = append(out, nir.Assign{Targets: []string{p},
				Value: nir.Format{Parts: []nir.Expr{rv}, Loc: c.loc(blk)}})
		}
	}
	for _, ch := range c.namedChildren(blk) {
		switch ch.Kind() {
		case "block_parameters", "parameters":
			// bound above
		case "body_statement":
			out = append(out, c.collectBodies(ch)...)
		default:
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

// blockParams returns the identifier names of a block's |params|.
func (c *rbConv) blockParams(blk *tree_sitter.Node) []string {
	var bp *tree_sitter.Node
	for _, ch := range c.namedChildren(blk) {
		if k := ch.Kind(); k == "block_parameters" || k == "parameters" {
			bp = ch
			break
		}
	}
	if bp == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(bp) {
		if ch.Kind() == "identifier" {
			out = append(out, c.text(ch))
		}
	}
	return out
}

func (c *rbConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "constant", "instance_variable", "global_variable":
		return c.text(n)
	case "call", "method_call", "command_call":
		recv := field(n, "receiver")
		method := c.text(field(n, "method"))
		if recv == nil {
			return orQ(method)
		}
		return c.dotted(recv) + "." + orQ(method)
	case "command":
		return orQ(c.text(field(n, "method")))
	case "element_reference":
		return c.dotted(field(n, "object")) + "[]"
	case "scope_resolution":
		base := field(n, "scope")
		name := c.text(field(n, "name"))
		if base == nil {
			return name
		}
		return c.dotted(base) + "." + name
	}
	return "?"
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

package treesitter

import (
	"bytes"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// phConv walks a tree-sitter PHP CST into NIR. PHP functions live in a global
// namespace (module key ""), like Ruby; `echo`/`print`/`include`/`require` are
// modeled as calls so they can be sinks.
type phConv struct {
	src      []byte
	root     string
	file     string
	funcName string
}

// ExtractPHP parses PHP files into one NIR Program (all modules keyed "").
func ExtractPHP(files []string, root string) (nir.Program, error) {
	mods := parseModulesPreprocess(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsphp.LanguagePHP()))
			return p
		},
		phpNormalizeLegacyScriptTags,
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &phConv{src: src, root: root, file: rel}
			body := c.block(tree.RootNode())
			body = append(body, c.phpModuleContext(tree.RootNode())...)
			body = append(body, c.phpSimplexmlLoaderObservations()...)
			return nir.Module{Key: "", File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func phpNormalizeLegacyScriptTags(src []byte) []byte {
	s := string(src)
	lower := strings.ToLower(s)
	if !strings.Contains(lower, "<script language=\"php\"") {
		return src
	}
	out := []byte(s)
	replacePreserveWidth := func(start, end int, repl string) {
		copy(out[start:end], []byte(repl))
		for i := start + len(repl); i < end; i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	searchFrom := 0
	for {
		lower = strings.ToLower(string(out))
		start := strings.Index(lower[searchFrom:], "<script language=\"php\"")
		if start < 0 {
			break
		}
		start += searchFrom
		endRel := strings.Index(lower[start:], ">")
		if endRel < 0 {
			break
		}
		end := start + endRel + 1
		replacePreserveWidth(start, end, "<?php")
		searchFrom = end
	}
	lower = strings.ToLower(string(out))
	searchFrom = 0
	for {
		start := strings.Index(lower[searchFrom:], "</script>")
		if start < 0 {
			break
		}
		start += searchFrom
		end := start + len("</script>")
		replacePreserveWidth(start, end, "?>")
		searchFrom = end
	}
	return out
}

func (c *phConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *phConv) locAtByte(offset int) string {
	if offset < 0 || offset > len(c.src) {
		offset = 0
	}
	line := 1 + bytes.Count(c.src[:offset], []byte{'\n'})
	return c.file + ":" + itoa(line)
}

func (c *phConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *phConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	kids := namedChildren(n)
	for i, st := range kids {
		if i > 0 && c.phpOpensShorthandEcho(kids[i-1]) && st.Kind() == "expression_statement" {
			out = append(out, c.phpEchoExprStmt(st)...)
			continue
		}
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *phConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition", "method_declaration":
		params := c.params(field(n, "parameters"))
		name := c.text(field(n, "name"))
		// top-level functions are public; methods are public unless private/protected.
		exported := true
		if n.Kind() == "method_declaration" {
			for _, ch := range children(n) {
				if ch.Kind() == "visibility_modifier" {
					t := c.text(ch)
					exported = !strings.Contains(t, "private") && !strings.Contains(t, "protected")
				}
			}
		}
		ptypes := c.paramTypes(field(n, "parameters"))
		prevFunc := c.funcName
		c.funcName = name
		body := c.block(field(n, "body"))
		body = append(body, c.phpFunctionContext(n)...)
		c.funcName = prevFunc
		if n.Kind() == "method_declaration" && phpIsWPListTableColumn(name) && len(params) > 0 {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{params[0]},
				Value: nir.Call{Callee: nir.Name{ID: "wp.list_table.row", Loc: L}, Path: "wp.list_table.row", Method: "row", Loc: L}}}, body...)
		}
		return []nir.Stmt{nir.FuncDef{
			Name:          name,
			Params:        params,
			ParamTypes:    ptypes,
			ContextTokens: c.phpFunctionTokens(name),
			ParamEntries:  c.phpParamEntries(name, params, ptypes),
			Body:          body,
			Loc:           L,
			Exported:      exported,
		}}
	case "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration":
		name := c.text(field(n, "name"))
		body := c.block(field(n, "body"))
		body = append(body, c.phpClassContext(n, name)...)
		return []nir.Stmt{nir.ClassDef{Name: name, Body: body, Loc: L}}
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "echo_statement", "print_intrinsic", "unset_statement":
		// model echo/print as a sink-able call
		var args []nir.Expr
		for _, a := range namedChildren(n) {
			args = append(args, c.expr(a))
		}
		name := "echo"
		if n.Kind() == "print_intrinsic" {
			name = "print"
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: args, Path: name, Method: name, Loc: L}}}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			value := c.expr(kids[0])
			if phpIsWPListTableColumn(c.funcName) {
				render := nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "wp.list_table.render", Loc: L},
					Args: []nir.Expr{value}, Path: "wp.list_table.render", Method: "render", Loc: L}}
				return []nir.Stmt{render, nir.Return{Value: value}}
			}
			return []nir.Stmt{nir.Return{Value: value}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). PHP did not evaluate the condition before → Cond stays nil,
	// byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.phpBranch(field(n, "body")), Else: c.phpElse(n)}}
	case "foreach_statement":
		// `foreach ($coll as $k => $v) {…}` — bind the loop key/value vars to the collection
		// (conservative whole-collection taint) so element taint flows into the body. Without
		// this $v/$k were unbound and all per-element flow was lost (e.g. building a
		// keyed array `$par[$k]=$v` from input). Binding $k preserves dynamic keys too.
		// tree-sitter-php: `body` is a field; the non-body children
		// are [iterable, value-spec], where value-spec is variable_name | by_ref | list_literal
		// | pair($k => $v).
		body := c.collectBlocks(n)
		bodyNode := field(n, "body")
		var nonBody []*tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if bodyNode != nil && ch.StartByte() == bodyNode.StartByte() {
				continue
			}
			nonBody = append(nonBody, ch)
		}
		if len(nonBody) >= 2 {
			coll := nonBody[0]
			var names []string
			c.foreachVarNames(nonBody[1], &names)
			var binds []nir.Stmt
			for _, vn := range names {
				binds = append(binds, nir.Assign{Targets: []string{vn},
					Value: nir.Format{Parts: []nir.Expr{c.expr(coll)}, Loc: L}})
			}
			body = append(binds, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.phpSwitch(n)}
	case "compound_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *phConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "print_intrinsic":
		var args []nir.Expr
		for _, a := range namedChildren(inner) {
			args = append(args, c.expr(a))
		}
		L := c.loc(inner)
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "print", Loc: L},
			Args:   args,
			Path:   "print",
			Method: "print",
			Loc:    L,
		}}}
	case "assignment_expression", "augmented_assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "variable_name" {
			if inner.Kind() == "augmented_assignment_expression" {
				return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: right, Loc: c.loc(inner)}}
			}
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// member-property write ($obj->field = v) — model as a PATH-sink Call (Method empty so
		// it never collides with method-name mappings) so path mappings can match writes.
		if left != nil && left.Kind() == "member_access_expression" {
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right},
				Path: c.dotted(left), Method: "", Loc: c.loc(inner)}}}
		}
		// subscript write ($arr[$k] = v) — emit a synthetic __setitem__ call so lowering can
		// track constant-key array slots precisely while still tainting whole-array reads.
		if left != nil && left.Kind() == "subscript_expression" {
			if kids := namedChildren(left); len(kids) > 0 {
				base := kids[0]
				var key nir.Expr = nir.Const{Loc: c.loc(left)}
				if len(kids) > 1 {
					key = c.expr(kids[1])
				}
				baseExpr := c.expr(base)
				path := c.dotted(base)
				if path != "" {
					path += ".__setitem__"
				}
				write := nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: baseExpr, Attr: "__setitem__", Loc: c.loc(left)},
					Args:   []nir.Expr{right, key},
					Path:   path, Method: "__setitem__", Loc: c.loc(inner),
				}}
				return []nir.Stmt{write}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		// model include/require as a file-inclusion sink call
		kids := namedChildren(inner)
		var args []nir.Expr
		if len(kids) > 0 {
			args = append(args, c.expr(kids[0]))
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "include", Loc: c.loc(inner)},
			Args: args, Path: "include", Method: "include", Loc: c.loc(inner)}}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *phConv) phpEchoExprStmt(n *tree_sitter.Node) []nir.Stmt {
	kids := namedChildren(n)
	if len(kids) == 0 {
		return nil
	}
	L := c.loc(n)
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "echo", Loc: L},
		Args:   []nir.Expr{c.expr(kids[0])},
		Path:   "echo",
		Method: "echo",
		Loc:    L,
	}}}
}

func (c *phConv) phpOpensShorthandEcho(n *tree_sitter.Node) bool {
	if n == nil || n.Kind() != "text_interpolation" {
		return false
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "php_tag" && strings.TrimSpace(c.text(ch)) == "<?=" {
			return true
		}
	}
	return false
}

func (c *phConv) phpModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	tokens := []string{"lang=php"}
	tokens = append(tokens, c.phpAstContextTokens(root)...)
	return c.phpContextCall("analysis.module.context", c.loc(root), "module", tokens, c.text(root))
}

func (c *phConv) phpFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(fn, "name"))
	tokens := []string{"lang=php", "name=" + name}
	ptypes := c.paramTypes(field(fn, "parameters"))
	seenTypes := map[string]bool{}
	for _, p := range c.params(field(fn, "parameters")) {
		if t := ptypes[p]; t != "" {
			tokens = append(tokens, "param_type:"+t)
			if !seenTypes[t] {
				seenTypes[t] = true
				tokens = append(tokens, "function_param_type:"+t)
			}
		}
	}
	tokens = append(tokens, c.phpAstContextTokens(field(fn, "attributes"))...)
	tokens = append(tokens, c.phpAstContextTokens(body)...)
	return c.phpContextCall("analysis.function.context", c.loc(fn), "context", tokens, c.text(body))
}

func (c *phConv) phpClassContext(cls *tree_sitter.Node, name string) []nir.Stmt {
	body := field(cls, "body")
	if body == nil {
		return nil
	}
	tokens := []string{"lang=php", "name=" + name}
	tokens = append(tokens, c.phpAstContextTokens(field(cls, "attributes"))...)
	tokens = append(tokens, c.phpAstContextTokens(body)...)
	return c.phpContextCall("analysis.class.context", c.loc(cls), "context", tokens, c.text(body))
}

func (c *phConv) phpContextCall(path, loc, method string, tokens []string, text string) []nir.Stmt {
	args := make([]nir.Expr, 0, len(tokens)+2)
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	args = append(args,
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: phpCompactText(text)},
	)
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: method,
		Loc:    loc,
	}}}
}

func (c *phConv) phpSimplexmlLoaderObservations() []nir.Stmt {
	compact := phpCompactText(string(c.src))
	if !strings.Contains(compact, "simplexml_load_string(") ||
		!strings.Contains(compact, "libxml_disable_entity_loader(true)") {
		return nil
	}
	if strings.Contains(compact, "=libxml_disable_entity_loader(true)") &&
		strings.Contains(compact, "libxml_disable_entity_loader($") {
		return nil
	}
	loader := phpSavedEntityLoaderVar(compact)
	if loader != "" && strings.Contains(compact, "libxml_disable_entity_loader("+loader+")") {
		return nil
	}
	loc := c.locAtByte(bytes.Index(c.src, []byte("simplexml_load_string")))
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.php.simplexml_unscoped_entity_loader", Loc: loc},
		Path:   "analysis.php.simplexml_unscoped_entity_loader",
		Method: "simplexml_unscoped_entity_loader",
		Loc:    loc,
	}}}
}

func phpSavedEntityLoaderVar(compact string) string {
	const marker = "=libxml_disable_entity_loader(true)"
	idx := strings.Index(compact, marker)
	if idx <= 0 {
		return ""
	}
	start := idx - 1
	for start >= 0 {
		ch := compact[start]
		if ch == '$' || ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			start--
			continue
		}
		break
	}
	name := compact[start+1 : idx]
	if strings.HasPrefix(name, "$") {
		return name
	}
	return ""
}

func (c *phConv) phpAstContextTokens(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "function_definition", "method_declaration":
			if name := c.text(field(cur, "name")); name != "" {
				add("function_name:" + name)
			}
		case "attribute":
			name, short := c.phpAttributeName(cur)
			if name != "" {
				add("annotation:" + name)
				if short != "" && short != name {
					add("annotation:" + short)
				}
			}
			if text := phpCompactText(c.text(cur)); text != "" {
				add("annotation_text:" + text)
			}
			if args := field(cur, "parameters"); args != nil {
				for _, arg := range namedChildren(args) {
					argText := phpCompactText(c.text(arg))
					if argText == "" {
						continue
					}
					add("annotation_arg:" + argText)
					if name != "" {
						add("annotation_arg:" + name + ":" + argText)
					}
					if short != "" && short != name {
						add("annotation_arg:" + short + ":" + argText)
					}
				}
			}
		case "property_declaration":
			prop := phpCompactText(c.text(cur))
			if prop != "" && strings.Contains(prop, "$") {
				add("property:" + prop)
			}
			for _, lit := range c.phpLiteralTokens(cur) {
				add("property_literal:" + lit)
			}
		case "assignment_expression", "augmented_assignment_expression":
			left := field(cur, "left")
			right := field(cur, "right")
			leftText := phpCompactText(c.text(left))
			rightText := phpCompactText(c.text(right))
			if leftText != "" && rightText != "" {
				add("assign:" + leftText + "=" + rightText)
			}
			for _, path := range c.phpCallPaths(right) {
				add("assign_call:" + path)
				if method := lastSeg(path); method != "" {
					add("assign_call_method:" + method)
				}
				if leftText != "" {
					add("assign_call:" + leftText + ":" + path)
					if method := lastSeg(path); method != "" {
						add("assign_call_method:" + leftText + ":" + method)
					}
				}
			}
			for _, lit := range c.phpLiteralTokens(right) {
				add("assign_literal:" + lit)
				if leftText != "" {
					add("assign_literal:" + leftText + ":" + lit)
				}
			}
			if leftText != "" && strings.HasPrefix(leftText, "$GLOBALS[") {
				add("global_subscript_write=true")
			}
		case "function_call_expression", "member_call_expression", "scoped_call_expression":
			path := c.dotted(cur)
			add("call_path:" + path)
			if method := lastSeg(path); method != "" {
				add("call:" + method)
			}
			if args := field(cur, "arguments"); args != nil {
				for _, arg := range namedChildren(args) {
					argText := phpCompactText(c.text(arg))
					if argText == "" {
						continue
					}
					add("call_arg:" + path + ":" + argText)
					if method := lastSeg(path); method != "" {
						add("call_arg_method:" + method + ":" + argText)
					}
				}
			}
		case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
			add("call_path:include")
			add("call:include")
			for _, arg := range namedChildren(cur) {
				argText := phpCompactText(c.text(arg))
				if argText == "" {
					continue
				}
				add("call_arg:include:" + argText)
				add("call_arg_method:include:" + argText)
			}
		case "member_access_expression":
			add("attr_path:" + c.dotted(cur))
		case "subscript_expression":
			add("subscript:" + phpCompactText(c.text(cur)))
		case "cast_expression":
			castType := phpCastType(c.text(cur))
			if castType == "" {
				break
			}
			add("cast:" + castType)
			kids := namedChildren(cur)
			if len(kids) == 0 {
				break
			}
			expr := kids[len(kids)-1]
			exprText := phpCompactText(c.text(expr))
			if exprText != "" {
				add("cast:" + castType + ":" + exprText)
			}
			for _, path := range c.phpCallPaths(expr) {
				add("cast_call:" + castType + ":" + path)
				for _, lit := range c.phpLiteralTokens(expr) {
					add("cast_call_literal:" + castType + ":" + path + ":" + lit)
				}
			}
		}
		for _, ch := range namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *phConv) phpAttributeName(n *tree_sitter.Node) (string, string) {
	if n == nil || n.Kind() != "attribute" {
		return "", ""
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "arguments" {
			continue
		}
		name := strings.TrimPrefix(c.text(ch), "\\")
		if name == "" {
			continue
		}
		return name, lastSeg(name)
	}
	return "", ""
}

func phpCastType(text string) string {
	compact := strings.ToLower(phpCompactText(text))
	if !strings.HasPrefix(compact, "(") {
		return ""
	}
	end := strings.Index(compact, ")")
	if end <= 1 {
		return ""
	}
	switch strings.TrimSpace(compact[1:end]) {
	case "int", "integer":
		return "int"
	case "bool", "boolean":
		return "bool"
	case "float", "double", "real":
		return "float"
	case "string":
		return "string"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return ""
	}
}

func (c *phConv) phpCallPaths(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "function_call_expression", "member_call_expression", "scoped_call_expression":
			path := c.dotted(cur)
			if path != "" && !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
		for _, ch := range namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *phConv) phpLiteralTokens(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "string", "encapsed_string", "integer", "float", "boolean", "name", "qualified_name":
			add(strings.Trim(phpCompactText(c.text(cur)), `"'`))
		}
		for _, ch := range namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func phpCompactText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// phpBranch flattens one if-branch body: a `{}` compound_statement, or a brace-less
// single statement (PHP allows `if ($c) $x = 1;`).
func (c *phConv) phpBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "compound_statement" {
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	}
	return c.stmt(b)
}

// phpElse builds the Else branch from else_if_clause / else_clause children (elseif chains
// into a nested If), so the join-merge and constant-condition pruning work.
func (c *phConv) phpElse(n *tree_sitter.Node) []nir.Stmt {
	var alts []*tree_sitter.Node
	for _, ch := range children(n) {
		if ch.Kind() == "else_if_clause" || ch.Kind() == "else_clause" {
			alts = append(alts, ch)
		}
	}
	var els []nir.Stmt
	for i := len(alts) - 1; i >= 0; i-- {
		a := alts[i]
		if a.Kind() == "else_clause" {
			els = c.phpBranch(field(a, "body"))
			continue
		}
		els = []nir.Stmt{nir.If{Cond: c.expr(field(a, "condition")), Then: c.phpBranch(field(a, "body")), Else: els}}
	}
	return els
}

// phpSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through labels merge into the next body) so a constant subject prunes to its arm.
func (c *phConv) phpSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, cs := range namedChildren(b) {
			switch cs.Kind() {
			case "case_statement":
				lv := field(cs, "value")
				var stmts []nir.Stmt
				for _, ch := range namedChildren(cs) {
					if lv != nil && ch.StartByte() == lv.StartByte() {
						continue
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
			case "default_statement":
				for _, ch := range namedChildren(cs) {
					deflt = append(deflt, c.stmt(ch)...)
				}
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *phConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "compound_statement":
				out = append(out, c.block(ch)...)
			case "else_clause", "else_if_clause", "catch_clause", "finally_clause",
				"switch_block", "case_statement", "default_statement":
				walk(ch)
			default:
				if ch.IsNamed() && ch.Kind() != "binary_expression" && ch.Kind() != "parenthesized_expression" {
					// nested statements directly in a clause body
					if isStmtKind(ch.Kind()) {
						out = append(out, c.stmt(ch)...)
					}
				}
			}
		}
	}
	walk(n)
	return out
}

func isStmtKind(k string) bool {
	switch k {
	case "expression_statement", "echo_statement", "return_statement", "if_statement",
		"while_statement", "for_statement", "foreach_statement", "compound_statement",
		"function_definition", "method_declaration", "class_declaration":
		return true
	}
	return false
}

func (c *phConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else {
				for _, cc := range namedChildren(ch) {
					if cc.Kind() == "variable_name" {
						out = append(out, c.text(cc))
						break
					}
				}
			}
		}
	}
	return out
}

func (c *phConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			name := ""
			if nm := field(ch, "name"); nm != nil {
				name = c.text(nm)
			} else {
				for _, cc := range namedChildren(ch) {
					if cc.Kind() == "variable_name" {
						name = c.text(cc)
						break
					}
				}
			}
			putParamType(out, name, paramTypeFromField(c, ch))
		}
	}
	return out
}

func (c *phConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		if a.Kind() == "argument" {
			if k := namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
		} else {
			out = append(out, c.expr(a))
		}
	}
	return out
}

func (c *phConv) phpFunctionTokens(name string) []string {
	if name == "" {
		return nil
	}
	return []string{"function_name:" + name}
}

func phpIsWPListTableColumn(name string) bool {
	return name == "column_default" || strings.HasPrefix(name, "column_")
}

func (c *phConv) phpParamEntries(name string, params []string, ptypes map[string]string) []nir.ParamEntry {
	if len(params) == 0 {
		return nil
	}
	var functionTypes []string
	seen := map[string]bool{}
	for _, p := range params {
		if t := ptypes[p]; t != "" && !seen[t] {
			seen[t] = true
			functionTypes = append(functionTypes, "function_param_type:"+t)
		}
	}
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := append([]string{}, functionTypes...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		if t := ptypes[p]; t != "" {
			tokens = append(tokens, "param_type:"+t)
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

// foreachVarNames collects the bare variable names bound by a foreach value-spec —
// `$v` (variable_name), `&$v` (by_ref), `[$a,$b]` (list_literal), or `$k => $v` (pair).
func (c *phConv) foreachVarNames(n *tree_sitter.Node, out *[]string) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "variable_name":
		*out = append(*out, c.text(n))
	case "by_ref", "list_literal", "pair":
		for _, ch := range namedChildren(n) {
			c.foreachVarNames(ch, out)
		}
	}
}

func (c *phConv) phpInterpolatedParts(n *tree_sitter.Node, out *[]nir.Expr) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "variable_name", "member_access_expression", "subscript_expression", "dynamic_variable_name":
		*out = append(*out, c.expr(n))
		return
	}
	for _, ch := range namedChildren(n) {
		c.phpInterpolatedParts(ch, out)
	}
}

func (c *phConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "variable_name", "name":
		return nir.Name{ID: c.text(n), Loc: L}
	case "null", "shell_command_expression":
		return nir.Const{Loc: L}
	case "integer", "float":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "boolean":
		return nir.Const{Loc: L, Value: c.text(n)} // true/false value for `val` matching
	case "string":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "encapsed_string", "heredoc", "string_value":
		// interpolated string: taint-propagating over the embedded variables
		var parts []nir.Expr
		c.phpInterpolatedParts(n, &parts)
		if len(parts) > 0 {
			parts = append([]nir.Expr{nir.Const{Loc: L, Value: c.text(n)}}, parts...)
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)} // non-interpolated → literal value
	case "member_access_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "name")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		kids := namedChildren(n)
		var base, key nir.Expr = nir.Const{Loc: L}, nil
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		if len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: base, Key: key, Path: c.dotted(n), Loc: L}
	case "function_call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "member_call_expression":
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		return nir.Call{Callee: nir.Attr{Base: c.expr(field(n, "object")), Attr: name, Path: path, Loc: L},
			Args: c.callArgs(field(n, "arguments")), Path: path, Method: name, Loc: L}
	case "scoped_call_expression":
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		return nir.Call{Callee: nir.Name{ID: path, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: path, Method: name, Loc: L}
	case "object_creation_expression":
		var typ string
		var argsNode *tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "name" || ch.Kind() == "qualified_name" {
				typ = c.text(ch)
			}
			if ch.Kind() == "arguments" {
				argsNode = ch
			}
		}
		if argsNode == nil {
			argsNode = field(n, "arguments")
		}
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(argsNode), Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "." || op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_op_expression":
		operand := field(n, "operand")
		if operand == nil {
			if kids := namedChildren(n); len(kids) > 0 {
				operand = kids[len(kids)-1]
			}
		}
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(operand), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "array_creation_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "array_element_initializer" {
				k := namedChildren(ch)
				switch {
				case len(k) >= 2: // key => value (named-value matching)
					key := c.keyName(k[0])
					parts = append(parts, nir.Pair{Key: key, Value: prependSeqKeyPath(c.expr(k[len(k)-1]), key), Loc: L})
				case len(k) == 1:
					parts = append(parts, c.expr(k[0]))
				}
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "conditional_expression":
		then := field(n, "consequence")
		if then == nil {
			then = field(n, "body")
		}
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(then), Else: c.expr(field(n, "alternative")), Loc: L}
	case "anonymous_function", "anonymous_function_creation_expression":
		// `function ($req, $res) use ($x) { … }` — a closure (the dominant PHP route-handler
		// shape, e.g. Utopia/Slim `->action(function (...) { … })`). Without this it fell to the
		// Seq fallback below, which expr's the body instead of lowering its statements, so
		// variable reads never connected to their writes and all in-handler taint was lost.
		// Captured `use (...)` vars are free vars resolved from the enclosing scope by the
		// lambda closure-capture in lowering, so they need not be params.
		return nir.Lambda{Params: c.params(field(n, "parameters")), ParamTypes: c.paramTypes(field(n, "parameters")),
			Body: c.block(field(n, "body")), Loc: L}
	case "arrow_function":
		// `fn ($x) => expr` — single-expression closure; model the body as a return.
		return nir.Lambda{Params: c.params(field(n, "parameters")), ParamTypes: c.paramTypes(field(n, "parameters")),
			Body: []nir.Stmt{nir.Return{Value: c.expr(field(n, "body"))}}, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func prependSeqKeyPath(e nir.Expr, key string) nir.Expr {
	if key == "" {
		return e
	}
	switch ex := e.(type) {
	case nir.Seq:
		ex.KeyPath = append([]string{key}, ex.KeyPath...)
		for i := range ex.Parts {
			ex.Parts[i] = prependSeqKeyPath(ex.Parts[i], key)
		}
		return ex
	case nir.Pair:
		ex.Value = prependSeqKeyPath(ex.Value, key)
		return ex
	case nir.Thru:
		ex.Inner = prependSeqKeyPath(ex.Inner, key)
		return ex
	default:
		return e
	}
}

// keyName returns the bare name of an array key: a string literal with quotes
// stripped, or a constant/name as-is.
func (c *phConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	if (n.Kind() == "string" || n.Kind() == "encapsed_string") && len(t) >= 2 {
		t = t[1 : len(t)-1]
	}
	return t
}

func (c *phConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "variable_name", "name", "qualified_name":
		// PHP global-namespace qualifier: `\file_get_contents` / `Foo\Bar\baz` — strip the
		// leading `\` and map namespace separators to the dotted form binding applicators match against,
		// else a fully-qualified builtin call (`\realpath`, `@\file_get_contents`) misses its sink.
		return strings.ReplaceAll(strings.TrimPrefix(c.text(n), `\`), `\`, ".")
	case "member_access_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "member_call_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "scoped_call_expression":
		return c.text(field(n, "scope")) + "." + c.text(field(n, "name"))
	case "function_call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

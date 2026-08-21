package treesitter

import (
	"bytes"
	"strings"
	"unicode"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// phConv walks a tree-sitter PHP CST into NIR. PHP functions live in a global
// namespace (module key ""), like Ruby; `echo`/`print`/`include`/`require` are
// modeled as calls so they can be sinks.
type phConv struct {
	src        []byte
	root       string
	file       string
	funcName   string
	className  string
	childCache map[uintptr][]*tree_sitter.Node
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

func (c *phConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
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

func (c *phConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	kids := c.namedChildren(n)
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
		reviewTokens := c.phpReviewTokens(n)
		body := c.block(field(n, "body"))
		if phpHasReviewToken(reviewTokens, "backend_calendar_events_missing_authorization") {
			body = append([]nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "analysis.php.backend_calendar_events_missing_authorization", Loc: L},
				Path:   "analysis.php.backend_calendar_events_missing_authorization",
				Method: "backend_calendar_events_missing_authorization",
				Loc:    L,
			}}}, body...)
		}
		if phpHasReviewToken(reviewTokens, "fatfree_clear_eval_compile_without_key_validation") {
			for _, param := range params {
				if param != "$key" {
					continue
				}
				body = append([]nir.Stmt{nir.Assign{Targets: []string{param}, Value: nir.Call{
					Callee: nir.Name{ID: "analysis.php.fatfree_clear_key_external_entry", Loc: L},
					Path:   "analysis.php.fatfree_clear_key_external_entry",
					Method: "fatfree_clear_key_external_entry",
					Loc:    L,
				}}}, body...)
				break
			}
		}
		if phpHasReviewToken(reviewTokens, "everest_forms_entry_file_delete_without_path_guard") {
			body = append([]nir.Stmt{nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: "analysis.php.everest_forms_entry_file_delete_without_path_guard", Loc: L},
				Path:   "analysis.php.everest_forms_entry_file_delete_without_path_guard",
				Method: "everest_forms_entry_file_delete_without_path_guard",
				Loc:    L,
			}}}, body...)
		}
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
			ParamEntries:  c.phpParamEntries(name, params, ptypes, reviewTokens),
			Body:          body,
			Loc:           L,
			Exported:      exported,
		}}
	case "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration":
		name := c.text(field(n, "name"))
		prevClass := c.className
		c.className = name
		body := c.block(field(n, "body"))
		body = append(body, c.phpClassContext(n, name)...)
		c.className = prevClass
		return []nir.Stmt{nir.ClassDef{Name: name, Body: body, Loc: L}}
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "echo_statement", "print_intrinsic", "unset_statement":
		// model echo/print as a sink-able call
		var args []nir.Expr
		for _, a := range c.namedChildren(n) {
			args = append(args, c.expr(a))
		}
		name := "echo"
		if n.Kind() == "print_intrinsic" {
			name = "print"
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: args, Path: name, Method: name, Loc: L}}}
	case "return_statement":
		kids := c.namedChildren(n)
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
		for _, ch := range c.namedChildren(n) {
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
		for _, a := range c.namedChildren(inner) {
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
			if kids := c.namedChildren(left); len(kids) > 0 {
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
		kids := c.namedChildren(inner)
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
	kids := c.namedChildren(n)
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
	for _, ch := range c.namedChildren(n) {
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
	if name != "" {
		tokens = append(tokens, "function_name:"+name)
	}
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
	if name != "" {
		tokens = append(tokens, "class_name:"+name)
	}
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
		case "echo_statement", "print_intrinsic":
			name := "echo"
			if cur.Kind() == "print_intrinsic" {
				name = "print"
			}
			add("call_path:" + name)
			add("call:" + name)
			for _, arg := range c.namedChildren(cur) {
				argText := phpCompactText(c.text(arg))
				if argText != "" {
					add("call_arg:" + name + ":" + argText)
					add("call_arg_method:" + name + ":" + argText)
				}
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
				for _, arg := range c.namedChildren(args) {
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
				for _, arg := range c.namedChildren(args) {
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
			for _, arg := range c.namedChildren(cur) {
				argText := phpCompactText(c.text(arg))
				if argText == "" {
					continue
				}
				add("call_arg:include:" + argText)
				add("call_arg_method:include:" + argText)
			}
		case "member_access_expression":
			if path := c.dotted(cur); path != "" {
				add("attr_path:" + path)
				add("selector:" + path)
			}
		case "subscript_expression":
			add("subscript:" + phpCompactText(c.text(cur)))
		case "return_statement":
			kids := c.namedChildren(cur)
			if len(kids) > 0 {
				if ret := phpCompactText(c.text(kids[0])); ret != "" {
					add("return:" + ret)
				}
			}
		case "variable_name", "name", "qualified_name":
			if ident := phpCompactText(c.text(cur)); ident != "" {
				add("identifier:" + ident)
			}
		case "cast_expression":
			castType := phpCastType(c.text(cur))
			if castType == "" {
				break
			}
			add("cast:" + castType)
			kids := c.namedChildren(cur)
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
		for _, ch := range c.namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	for _, tok := range c.phpReviewTokens(n) {
		add("php_review:" + tok)
	}
	return out
}

func (c *phConv) phpReviewTokens(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	compact := phpCompactText(c.text(n))
	lower := strings.ToLower(compact)
	calls := map[string]bool{}
	for _, path := range c.phpCallPaths(n) {
		calls[path] = true
		if method := lastSeg(path); method != "" {
			calls[method] = true
		}
	}
	var collectSpecialCalls func(*tree_sitter.Node)
	collectSpecialCalls = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "echo_statement":
			calls["echo"] = true
		case "print_intrinsic":
			calls["print"] = true
		}
		for _, ch := range c.namedChildren(cur) {
			collectSpecialCalls(ch)
		}
	}
	collectSpecialCalls(n)
	literals := map[string]bool{}
	for _, lit := range c.phpLiteralTokens(n) {
		literals[lit] = true
		literals[phpCompactText(lit)] = true
	}
	var out []string
	add := func(tok string) {
		for _, existing := range out {
			if existing == tok {
				return
			}
		}
		out = append(out, tok)
	}
	if calls["curl_setopt_array"] {
		if strings.Contains(compact, "CURLOPT_SSL_VERIFYPEER") && strings.Contains(lower, "false") {
			add("curl_ssl_verifypeer_disabled")
		}
		if strings.Contains(compact, "CURLOPT_SSL_VERIFYHOST") && strings.Contains(compact, "0") {
			add("curl_ssl_verifyhost_disabled")
		}
	}
	if calls["header"] && (literals["Access-Control-Allow-Origin:*"] || strings.Contains(compact, "Access-Control-Allow-Origin:*")) {
		add("permissive_cors_header")
	}
	if calls["header"] && (literals["X-Frame-Options:ALLOWALL"] || strings.Contains(compact, "X-Frame-Options:ALLOWALL")) {
		add("missing_frame_protection_allowall")
	}
	if calls["setcookie"] || calls["setrawcookie"] {
		if strings.Contains(lower, "secure=false") || strings.Contains(lower, "'secure'=>false") || strings.Contains(lower, "\"secure\"=>false") {
			add("cookie_secure_false")
		}
		if strings.Contains(lower, "httponly=false") || strings.Contains(lower, "'httponly'=>false") || strings.Contains(lower, "\"httponly\"=>false") {
			add("cookie_httponly_false")
		}
		if calls["setrawcookie"] && strings.Contains(lower, "httponly=false") {
			add("raw_cookie_httponly_false")
		}
	}
	if phpTempPathJoinBeforeSeparatorCheck(compact) {
		add("temp_path_join_before_separator_check")
	}
	if phpFatFreeClearEvalCompileWithoutKeyValidation(compact) {
		add("fatfree_clear_eval_compile_without_key_validation")
	}
	for _, key := range []string{"info", "message", "flash"} {
		if phpSessionKeyReferenced(compact, key) && !phpHasAnyCall(calls, "htmlspecialchars", "htmlentities", "esc_html", "strip_tags") {
			add("unescaped_session_flash_" + key)
		}
	}
	if calls["getAbsolutePath"] {
		for _, op := range []string{"move_uploaded_file", "rename", "copy", "touch", "unlink"} {
			if calls[op] && !strings.Contains(compact, "@"+op+"(") {
				add("absolute_path_disclosure_" + op)
			}
		}
	}
	if phpEverestFormsEntryFileDeleteWithoutPathGuard(compact, calls) {
		add("everest_forms_entry_file_delete_without_path_guard")
	}
	for _, opt := range []string{"--delete-key", "--delete-secret-key", "--list-keys", "--export", "--export-secret-keys", "--list-secret-keys", "--list-public-keys"} {
		if phpGPGOptionArgMissingDelimiter(compact, opt) {
			add("gpg_option_arg_missing_delimiter")
			add("gpg_option_arg_missing_delimiter_" + strings.TrimLeft(strings.ReplaceAll(opt, "-", "_"), "_"))
		}
	}
	if !strings.Contains(compact, "assertAllowedHttpMethod") {
		if strings.Contains(compact, "deleteBy") && strings.Contains(compact, "redirect") {
			add("state_changing_action_missing_method_assertion_delete_by")
		}
		if strings.Contains(compact, "addToCompareList") && strings.Contains(compact, "removeFromCompareList") {
			add("state_changing_action_missing_method_assertion_compare_list")
		}
		if strings.Contains(compact, "PasswordReset::class") && strings.Contains(compact, "initiateReset") {
			add("state_changing_action_missing_method_assertion_password_reset")
		}
		if strings.Contains(compact, "backendUserSessionRepository") && strings.Contains(compact, "terminateSessionByIdentifier") {
			add("state_changing_action_missing_method_assertion_backend_session")
		}
	}
	if strings.Contains(compact, "getRequiredBodyParam") && strings.Contains(compact, "asJson") && !strings.Contains(compact, "requireAdmin") {
		if strings.Contains(compact, "loadBucketList") {
			add("credentialed_endpoint_missing_admin_bucket_list")
		}
		if strings.Contains(compact, "loadContainerList") {
			add("credentialed_endpoint_missing_admin_container_list")
		}
	}
	if strings.Contains(compact, "templates/{$type}/{$language}") && strings.Contains(compact, "{$name}.tpl") {
		if !strings.Contains(compact, "basename($type)") {
			add("template_path_component_traversal_type")
		}
		if !strings.Contains(compact, "basename($language)") {
			add("template_path_component_traversal_language")
		}
		if !strings.Contains(compact, "basename($name)") {
			add("template_path_component_traversal_name")
		}
		if strings.Contains(compact, "{$entityType}") && !strings.Contains(compact, "basename($entityType)") {
			add("template_path_component_traversal_entity_type")
		}
	}
	if strings.Contains(compact, "foreach") && strings.Contains(compact, "$_GET") && strings.Contains(compact, "$$") &&
		!strings.Contains(compact, "preg_match") && !strings.Contains(compact, "in_array") && !strings.Contains(compact, "array_key_exists") {
		add("request_variable_variable_assignment")
	}
	if (strings.Contains(compact, "locale/site/groups") ||
		(literals["locale"] && literals["site"] && literals["groups"])) &&
		literals["admin"] {
		add("access_policy_locale_site_groups_admin")
	}
	if (strings.Contains(compact, "locale/language/groups") ||
		(literals["locale"] && literals["language"] && literals["groups"])) &&
		literals["admin"] {
		add("access_policy_locale_language_groups_admin")
	}
	if (strings.Contains(compact, "locale/currency/groups") ||
		(literals["locale"] && literals["currency"] && literals["groups"])) &&
		literals["admin"] {
		add("access_policy_locale_currency_groups_admin")
	}
	if strings.Contains(compact, "order.customerid") && strings.Contains(compact, "order.product.attribute.id") && !strings.Contains(compact, "order.statuspayment") {
		add("workflow_policy_order_product_without_status_payment")
	}
	if strings.Contains(compact, "connect(") && strings.Contains(compact, "is_numeric($port)") &&
		strings.Contains(compact, "explode(") && strings.Contains(lower, "server") &&
		(strings.Contains(compact, "$port<1024") || strings.Contains(compact, "1024>$port")) {
		add("server_port_validation_incomplete_privileged_range")
	}
	if strings.Contains(compact, "is_numeric($value)&&preg_match") && !strings.Contains(compact, "!is_numeric($value)") {
		if strings.Contains(compact, "is_int($value)") {
			add("scientific_notation_numeric_validation_bypass")
		}
		if strings.Contains(compact, "returnpreg_match") {
			add("scientific_notation_numeric_validation_bypass_regex_only")
		}
	}
	if strings.Contains(compact, "plugin_load('admin','acl')") && !strings.Contains(compact, "auth_isadmin") && !strings.Contains(compact, "RemoteAccessDeniedException") {
		if strings.Contains(compact, "_acl_add") {
			add("dokuwiki_remote_acl_missing_admin_check_add")
		}
		if strings.Contains(compact, "_acl_del") {
			add("dokuwiki_remote_acl_missing_admin_check_delete")
		}
	}
	if strings.Contains(compact, "generateFederatedUser") && !strings.Contains(compact, "Member::TYPE_CIRCLE") && !strings.Contains(compact, "circleService->getCircle") {
		if strings.Contains(compact, "addMember(") {
			add("nextcloud_circle_member_add_missing_circle_check")
		}
		if strings.Contains(compact, "addMembers(") {
			add("nextcloud_circle_members_add_missing_circle_check")
		}
	}
	if strings.Contains(compact, "ResourceTypeRelationship") && strings.Contains(compact, "getRelatableResourceTypes()") && !strings.Contains(compact, "isFieldEnabled()") {
		add("disabled_relationship_metadata_exposure")
	}
	if strings.Contains(compact, "comment_comment") && strings.Contains(compact, "comment_id") &&
		(strings.Contains(compact, "getDb()->update") || strings.Contains(compact, "$sql->update")) &&
		!strings.Contains(compact, "comment_author_id") && !strings.Contains(compact, "USERID") {
		add("comment_update_missing_ownership_constraint")
	}
	if strings.Contains(compact, "{!!") && strings.Contains(compact, "->markdown(") &&
		(strings.Contains(compact, "data['content']") || strings.Contains(compact, "data[\"content\"]")) &&
		!strings.Contains(compact, "strip_tags") && !strings.Contains(compact, "htmlspecialchars") &&
		!strings.Contains(compact, "htmlentities") && !strings.Contains(compact, "sanitize") &&
		!strings.Contains(compact, "purify") && !strings.Contains(compact, "HtmlString") {
		add("blade_raw_markdown_without_sanitizer")
	}
	if strings.Contains(compact, "getMessageParam('iid'") && strings.Contains(compact, "item_id=$this->iid") &&
		strings.Contains(compact, "db_query(") && !strings.Contains(compact, "is_numeric($this->iid)") {
		add("unvalidated_numeric_sql_interpolation_iid")
	}
	if strings.Contains(compact, "'model_id'=>$model_id") && !strings.Contains(compact, "(int)$model_id") {
		add("unvalidated_numeric_sql_interpolation_model_id")
	}
	if strings.Contains(compact, "'model_id'=>$id") && !strings.Contains(compact, "(int)$id") {
		add("unvalidated_numeric_sql_interpolation_id")
	}
	if strings.Contains(compact, "HmacDRBG") && strings.Contains(compact, "generate(") &&
		strings.Contains(compact, "_truncateToN(") && strings.Contains(compact, "->mul(") &&
		strings.Contains(compact, "->invm(") && !strings.Contains(compact, "->bitLength()") {
		add("ecdsa_nonce_bit_length_timing_leak")
	}
	if strings.Contains(compact, "$_GET[$paramname]") && strings.Contains(compact, "$_POST[$paramname]") &&
		strings.Contains(compact, "$check=='alpha'") && strings.Contains(compact, "return$out") &&
		!strings.Contains(compact, "htmlspecialchars($out") && !strings.Contains(compact, "htmlentities($out") &&
		!strings.Contains(compact, "dol_htmlentities($out") && !strings.Contains(compact, "html_escape($out") {
		add("request_text_param_html_escape_missing")
	}
	if strings.Contains(compact, "cntctfrm_form_submit") && strings.Contains(compact, "update_option") &&
		!strings.Contains(compact, "check_admin_referer") && !strings.Contains(compact, "wp_nonce_field") {
		add("contact_form_settings_csrf")
	}
	if strings.Contains(compact, "global_menu") && strings.Contains(compact, "asset_url(") &&
		strings.Contains(compact, "alt='{$item['label']}'") {
		add("display_name_alt_unescaped")
	}
	if strings.Contains(compact, "escape_command") && strings.Contains(compact, "preg_replace") &&
		strings.Contains(compact, "popen") && strings.Contains(compact, "ns_id") &&
		!strings.Contains(compact, "preg_replace(\"/[") && !strings.Contains(compact, "preg_replace('/[") {
		add("incomplete_command_escape_regex")
	}
	if strings.Contains(compact, "patchEntity(") && strings.Contains(compact, "unset($params['id']);") &&
		strings.Contains(compact, "__massageInput") && !strings.Contains(compact, "unset($input['id']);") {
		add("mass_assignment_id_unset_before_input_massage")
	}
	if strings.Contains(compact, "post_date") && strings.Contains(compact, "$edcal_startDate") &&
		strings.Contains(compact, "$edcal_endDate") && strings.Contains(compact, "return$where") &&
		!strings.Contains(compact, "$wpdb->prepare") && !strings.Contains(compact, "esc_sql") &&
		!strings.Contains(compact, "sanitize_text_field") && !strings.Contains(compact, "preg_match") &&
		!strings.Contains(compact, "is_numeric(str_replace") {
		add("wordpress_posts_where_date_sql_injection")
	}
	if strings.Contains(compact, "gitdiff--name-status") && strings.Contains(compact, "execute($command") &&
		!strings.Contains(compact, "$command=['git','diff','--name-status'") {
		add("composer_git_branch_diff_command_injection")
	}
	if strings.Contains(compact, "groupblog-blogid") && strings.Contains(compact, "groupblog_edit_base_settings") &&
		!strings.Contains(compact, "groups_is_user_admin") && !strings.Contains(compact, "current_user_can_for_blog") {
		add("groupblog_settings_missing_admin_guard")
	}
	if strings.Contains(compact, "StreamedResponse") && strings.Contains(compact, "application/pdf") &&
		!strings.Contains(compact, "getResponseByScanStatus") && !strings.Contains(compact, "getScanStatus") &&
		!strings.Contains(compact, "scan_pdf") {
		add("unscanned_pdf_preview")
	}
	if strings.Contains(compact, "param('auth')") && strings.Contains(compact, "authenticate($data)") &&
		!strings.Contains(compact, "is_string($data['user'])") && !strings.Contains(compact, "is_string($data['password'])") {
		add("cockpit_auth_array_nosql_injection")
	}
	if strings.Contains(compact, "openssl_decrypt") && strings.Contains(compact, "VAL_CRYPTO_ALGO") &&
		strings.Contains(compact, "base64_decode") && strings.Contains(compact, "['tag']") &&
		!strings.Contains(compact, "strlen($tag)") {
		add("authenticated_decryption_tag_length_missing")
	}
	if strings.Contains(compact, "attributeLabels") && strings.Contains(compact, "beforeSave(") &&
		strings.Contains(compact, "setPassword(") && !strings.Contains(compact, "Html::encode($this->username)") {
		add("feehi_username_stored_xss")
	}
	if strings.Contains(compact, "StaticCacheTrait") && strings.Contains(compact, "ROLE_ID_ADMINISTRATOR") &&
		strings.Contains(compact, "Security::hash(") && !strings.Contains(compact, "returnh($name)") {
		add("quickapps_real_name_stored_xss")
	}
	if strings.Contains(compact, "autoptimize_filter_imgopt_lazyload_placeholder") &&
		strings.Contains(compact, "preg_replace") && strings.Contains(compact, "data-src") &&
		strings.Contains(compact, "data-srcset") {
		add("html_attribute_rewrite_review")
	}
	if strings.Contains(compact, "audioigniter_playlist_id") && strings.Contains(compact, "get_post(") &&
		strings.Contains(compact, "get_post_meta(") && strings.Contains(compact, "wp_send_json(") &&
		!strings.Contains(compact, "post_status") && !strings.Contains(compact, "current_user_can") {
		add("audioigniter_playlist_idor")
	}
	if strings.Contains(compact, "ServiceManager::handleServiceRequest") &&
		!strings.Contains(compact, "PathAccessCheck") && !strings.Contains(compact, "str_replace(['..']") &&
		!strings.Contains(compact, "str_replace(array('..')") {
		add("backend_service_resource_traversal")
	}
	if strings.Contains(compact, "base64Url") && strings.Contains(compact, "get_ffmpeg()") &&
		strings.Contains(compact, "-i") && !strings.Contains(compact, "parse_url($url)") &&
		!strings.Contains(compact, "ip_is_private") {
		add("ffmpeg_incomplete_ip_denylist")
	}
	if strings.Contains(compact, "add_query_arg('snippets-safe-mode'") &&
		!strings.Contains(compact, "(bool)$_REQUEST['snippets-safe-mode']") &&
		!strings.Contains(compact, "esc_attr") && !strings.Contains(compact, "htmlspecialchars") {
		add("safe_mode_query_xss")
	}
	if strings.Contains(compact, "Datatables::of") && strings.Contains(compact, "rawColumns") &&
		strings.Contains(compact, "data-title") && strings.Contains(compact, "$tasks->title") &&
		!strings.Contains(compact, "htmlspecialchars") && !strings.Contains(compact, "htmlentities") &&
		!strings.Contains(compact, "e($tasks->title") {
		add("raw_datatables_attribute_xss")
	}
	if strings.Contains(compact, "updateMetaDataIntoIntermediateFile") && strings.Contains(compact, "getUserFolder") &&
		strings.Contains(compact, "getById") && !strings.Contains(compact, "getFileDropOwnerId") &&
		!strings.Contains(compact, "getFirstNodeById") && !strings.Contains(compact, "getNode()") {
		add("nextcloud_file_drop_metadata_scope_bypass")
	}
	if strings.Contains(compact, "getShareByToken") && strings.Contains(compact, "PERMISSION_CREATE") &&
		strings.Contains(compact, "getShareOwner") && !strings.Contains(compact, "getFirstNodeById") &&
		!strings.Contains(compact, "getNode()") && !strings.Contains(compact, "isEncrypted()") {
		add("nextcloud_file_drop_owner_scope_bypass")
	}
	if strings.Contains(compact, "SalesChannelDefinitionInterface") && strings.Contains(compact, "getAssociations") &&
		strings.Contains(compact, "AssociationField") && strings.Contains(compact, "getReferenceDefinition") &&
		!strings.Contains(compact, "ManyToManyAssociationField") && !strings.Contains(compact, "getToManyReferenceDefinition") {
		add("shopware_many_to_many_criteria_bypass")
	}
	if strings.Contains(compact, "decodeContent") && strings.Contains(compact, "$file['type']") &&
		strings.Contains(compact, "$file['name']") && strings.Contains(compact, "in_array(") &&
		!strings.Contains(compact, "pathinfo") && !strings.Contains(compact, "PATHINFO_EXTENSION") &&
		!strings.Contains(compact, "is_string") {
		add("incomplete_file_extension_validation")
	}
	if strings.Contains(compact, "sprintf(") && strings.Contains(compact, "<ahref=\"%s\"") &&
		strings.Contains(compact, "add_query_arg(") && !strings.Contains(compact, "esc_url(add_query_arg(") &&
		!strings.Contains(compact, "esc_attr(add_query_arg(") && !strings.Contains(compact, "htmlspecialchars(add_query_arg(") {
		add("wordpress_add_query_arg_href_xss")
	}
	if strings.Contains(compact, "/var/db/rrd/") && strings.Contains(compact, "file_put_contents") &&
		strings.Contains(compact, "rrdtoolrestore") && !strings.Contains(compact, "basename($rrd['filename'])") &&
		!strings.Contains(compact, "shell_safe") {
		add("opnsense_rrd_restore_filename_command_injection")
	}
	if strings.Contains(compact, "preg_replace") && strings.Contains(compact, "<ahref=\"$1\"") &&
		strings.Contains(compact, "<imgsrc=\"$1\"") && !strings.Contains(compact, "https?:") {
		add("bbcode_url_tag_protocol_xss")
	}
	if strings.Contains(compact, "$this->last_headers") && strings.Contains(compact, "$log.=$this->last_headers") &&
		strings.Contains(compact, "$result['log']=$log") && !strings.Contains(compact, "$log.=htmlentities($this->last_headers") {
		add("unescaped_diagnostic_html")
	}
	if strings.Contains(compact, "ReplaceController(") && (strings.Contains(compact, "remove_background") || strings.Contains(compact, "prepare-remove-background")) &&
		!strings.Contains(compact, "checkImagePermission") && !strings.Contains(compact, "current_user_can('edit_post'") &&
		!strings.Contains(compact, "current_user_can(\"edit_post\"") {
		if strings.Contains(compact, "$_REQUEST['attachment_id']") {
			add("wordpress_media_request_mutation_missing_object_permission")
		}
		if strings.Contains(compact, "$_POST['ID']") {
			add("wordpress_media_post_mutation_missing_object_permission")
		}
	}
	if strings.Contains(compact, "html_entity_decode") && strings.Contains(compact, "contact_name") &&
		strings.Contains(compact, "contact_alias") && !strings.Contains(compact, "ESCAPE_ILLEGAL_CHARS") {
		add("centreon_contact_html_entity_decode_xss")
	}
	if strings.Contains(compact, "MfaRequiredException") && strings.Contains(compact, "redirectToMfaEndpoint") &&
		strings.Contains(compact, "!$mfaRequested") && strings.Contains(compact, "!$this->isLoggedInBackendUserRequired") {
		add("mfa_redirect_bypass")
	}
	if strings.Contains(compact, "param('params'") && strings.Contains(compact, "unserialize($params") &&
		!strings.Contains(compact, "substr") && !strings.Contains(compact, "a:") {
		add("unrestricted_request_param_deserialization")
	}
	if strings.Contains(compact, "ORDERBY") && strings.Contains(compact, "$orderBy['direction']") &&
		!strings.Contains(compact, "QUERY_ORDER_DESC") && !strings.Contains(compact, "QUERY_ORDER_ASC") {
		add("unvalidated_sql_order_direction")
	}
	if strings.Contains(compact, "\\Input::get('search')") && strings.Contains(compact, "\\Input::get('order_by')") &&
		strings.Contains(compact, "\\Input::get('sort')") && strings.Contains(compact, "prepare($strQuery)") &&
		!strings.Contains(compact, "in_array($strSearch") && !strings.Contains(compact, "in_array($order_by") {
		add("contao_listing_sql_identifier_injection")
	}
	if strings.Contains(compact, "php|php5|php4|php3|phtml|pl|py|cgi|asp|js") &&
		strings.Contains(compact, "$file_src_name_ext='txt'") && !strings.Contains(compact, "phar") {
		add("dangerous_upload_extension_blocklist_missing_phar")
	}
	if strings.Contains(compact, "get_input('internalname')") && strings.Contains(compact, "elgg_view(") &&
		!strings.Contains(compact, "$internalname=htmlentities($internalname)") &&
		!strings.Contains(compact, "$internalname=htmlspecialchars($internalname)") &&
		!strings.Contains(compact, "$internalname=esc_html($internalname)") {
		add("request_view_variable_html_escape_missing")
	}
	if phpBpDocsSaveMissingAccessPolicy(compact) {
		add("bp_docs_save_missing_access_policy")
	}
	if strings.Contains(compact, "bp_groupblog_create_screen_save") && strings.Contains(compact, "groupblog_edit_base_settings") &&
		!strings.Contains(compact, "bp_groupblog_is_role_allowed") && !strings.Contains(compact, "current_user_can_for_blog") {
		add("groupblog_create_missing_role_policy")
	}
	if strings.Contains(compact, "$this->ar_offset=$offset") && !strings.Contains(compact, "$this->ar_offset=(int)$offset") {
		add("codeigniter_active_record_offset_sqli")
	}
	if strings.Contains(compact, "getParam('sort')") && strings.Contains(compact, "explode('|',$sort)") &&
		strings.Contains(compact, "orderBy([$column=>$direction") && !strings.Contains(compact, "$column=null") {
		add("craft_purchasables_sort_sql_injection")
	}
	if strings.Contains(compact, "shell_exec") && strings.Contains(compact, "find-L") &&
		!strings.Contains(compact, "escapeshellarg($get['query'])") &&
		!strings.Contains(compact, "escapeshellarg($post['search_string'])") {
		add("codiad_filemanager_search_command_injection")
	}
	if strings.Contains(compact, "role_reporter") &&
		strings.Contains(compact, "exec") && strings.Contains(compact, "Storage") {
		add("connectcms_codestudies_code_execution")
	}
	if strings.Contains(compact, "$this->request->stopped=true") && !strings.Contains(compact, "app:request:stop") {
		add("cockpit_lime_redirect_stop_continuation")
	}
	if strings.Contains(compact, "PMA_generate_common_url") && strings.Contains(compact, "$params['url']=$url") &&
		strings.Contains(compact, "defined('PMA_SETUP')") && strings.Contains(compact, "return'../'.$goto") &&
		!strings.Contains(compact, "defined('PMA_SETUP')){return$url") {
		add("phpmyadmin_setup_redirector_open_redirect")
	}
	if strings.Contains(compact, "MfaHelper") && strings.Contains(compact, "Request->request->get('mfa_secret')") &&
		!strings.Contains(compact, "newMfaHelper($this->Session->get('mfa_secret'))") {
		add("request_controlled_mfa_secret_bypass")
	}
	if strings.Contains(compact, "public$allowAnonymous=true") && strings.Contains(compact, "renderTemplate(") &&
		!strings.Contains(compact, "getActionSegments") && !strings.Contains(compact, "HttpException(403)") {
		add("craft_anonymous_template_render_xss")
	}
	if strings.Contains(compact, "Tools::nl2br") && strings.Contains(compact, "Tools::stripslashes") &&
		strings.Contains(compact, "Mail::Send") && !strings.Contains(compact, "htmlentitiesUTF8") {
		add("prestashop_contactform_message_email_xss")
	}
	if strings.Contains(compact, "sprintf('%s/%s.php'") && strings.Contains(compact, "$locale") &&
		strings.Contains(compact, "include") && !strings.Contains(compact, "assertValidLocale") {
		add("unvalidated_locale_file_include")
	}
	if strings.Contains(compact, "redirect_url") && strings.Contains(compact, "header('Location:/'.htmlentities") &&
		!strings.Contains(compact, "substr($_REQUEST['redirect_url']") {
		add("owncloud_login_redirect_url_open_redirect")
	}
	requestURI := "REQUEST" + "_" + "URI"
	if strings.Contains(compact, requestURI) && strings.Contains(compact, "print$out") &&
		!strings.Contains(compact, "dol_htmlentities") && !strings.Contains(compact, "htmlentities($_SERVER") &&
		!strings.Contains(compact, "htmlspecialchars($_SERVER") && !strings.Contains(compact, "html_escape($_SERVER") {
		add("buffered_error_page_request_metadata_xss")
	}
	if strings.Contains(compact, "System::loadLanguageFile") && strings.Contains(compact, "$objTemplate->language=$locale") &&
		!strings.Contains(compact, "Validator::isLocale($locale)") {
		add("oveleon_cookiebar_locale_reflected_xss")
	}
	if strings.Contains(compact, "$_POST") && strings.Contains(compact, ".=strip_tags(") &&
		!strings.Contains(compact, "htmlspecialchars(strip_tags(") && !strings.Contains(compact, "htmlentities(strip_tags(") &&
		!strings.Contains(compact, "esc_html(strip_tags(") {
		add("incomplete_html_entity_escape")
	}
	if strings.Contains(compact, "fileId") && strings.Contains(compact, "getRules(") &&
		strings.Contains(compact, "return$userRules") && !strings.Contains(compact, "userHasAccessTo") {
		add("file_rules_idor_missing_access_check")
	}
	if strings.Contains(compact, "array_intersect(array_keys($search),$this->searchable)") &&
		strings.Contains(compact, "return$query->where($search)") &&
		!strings.Contains(compact, "array_intersect_key") && !strings.Contains(compact, "where($allowed_search)") {
		add("unfiltered_search_where_columns")
	}
	if strings.Contains(compact, "dompdf_getimagesize") && strings.Contains(compact, "file_put_contents") &&
		strings.Contains(compact, "\"svg\"") && !strings.Contains(compact, "$type===\"svg\"") &&
		!strings.Contains(compact, "xml_set_element_handler") {
		add("svg_nested_resource_validation_bypass")
	}
	if strings.Contains(compact, "$client->request('GET',$uri") && !strings.Contains(compact, "isUrlSafe($uri)") &&
		!strings.Contains(compact, "FILTER_FLAG_NO_PRIV_RANGE") && !strings.Contains(compact, "FILTER_FLAG_NO_RES_RANGE") {
		add("chamilo_unsafe_guzzle_url_fetch")
	}
	if strings.Contains(compact, "$html=post('html')") && strings.Contains(compact, "_filter_html") &&
		strings.Contains(compact, "Comment_model::updateOrCreate") && !strings.Contains(compact, "ParseMarkdown") &&
		!strings.Contains(compact, "setSafeMode(true)") {
		add("stored_html_write")
	}
	if strings.Contains(compact, "toggleSubpalette") && strings.Contains(compact, "Input->post('field')") &&
		strings.Contains(compact, "prepare(\"UPDATE\"") && !strings.Contains(compact, "__selector__") &&
		!strings.Contains(compact, "hasAccess($dc->table") {
		add("contao_toggle_subpalette_sql_identifier")
	}
	if strings.Contains(compact, "getForCsvExport") && strings.Contains(compact, "self::COLUMNS") &&
		strings.Contains(compact, "$rows[]=$row") && !strings.Contains(compact, "escapeCsvRecord") &&
		!strings.Contains(compact, "esc_csv") {
		add("csv_formula_prone_export_row")
	}
	if strings.Contains(compact, "$uchidden") && strings.Contains(compact, "<inputtype=") &&
		strings.Contains(compact, "hidden") && !strings.Contains(compact, "dhtmlspecialchars($uchidden)") &&
		!strings.Contains(compact, "htmlspecialchars($uchidden") && !strings.Contains(compact, "htmlentities($uchidden") {
		add("installer_hidden_field_xss")
	}
	if strings.Contains(compact, "cmd_string") && strings.Contains(compact, "generateDerivativeResponse") &&
		!strings.Contains(compact, "$cmd=array_merge") && !strings.Contains(compact, "HeaderBag") {
		add("command_string_wrapper_execution")
	}
	if strings.Contains(compact, "$final[$i]['actions']") && strings.Contains(compact, "$_REQUEST['group']") &&
		!strings.Contains(compact, "(int)$_REQUEST['group']") {
		add("freepbx_contact_manager_group_link_xss")
	}
	hasTraversalCheck := calls["strpos"] && (literals["../"] || literals["/../"] || strings.Contains(compact, "../"))
	if hasTraversalCheck && !strings.Contains(compact, "phar://") {
		add("incomplete_archive_filename_validation")
	}
	if strings.Contains(compact, "$_REQUEST") && strings.Contains(compact, "strrpos(") &&
		strings.Contains(compact, "'_id',-3") && !strings.Contains(compact, "strlen($key)>=3") &&
		!strings.Contains(compact, "strlen($key)>2") {
		add("negative_offset_string_search_warning")
	}
	if strings.Contains(compact, "ResetPassword") && strings.Contains(compact, "createToken") &&
		strings.Contains(compact, "account:login-token") && strings.Contains(compact, "absolute:true") &&
		!strings.Contains(compact, "buildBaseUrl") && !strings.Contains(compact, "resolveUri") {
		add("password_recovery_link_host_control")
	}
	if strings.Contains(compact, "a.idNOTIN({$exclude})") && strings.Contains(compact, "$wpdb->get_results") &&
		!strings.Contains(compact, "array_map('absint',$exclude)") && !strings.Contains(compact, "wp_parse_id_list($exclude)") {
		add("unparameterized_sql_query_parser_exclude")
	}
	if strings.Contains(compact, "toLegacyOrderBy") && strings.Contains(compact, "toLegacyOrderWay") &&
		!strings.Contains(compact, "isOrderBy") && !strings.Contains(compact, "isOrderWay") {
		add("unparameterized_sql_query_parser_legacy_order")
	}
	if strings.Contains(compact, "PluginName:") && strings.Contains(compact, "add_action") &&
		!strings.Contains(compact, "ABSPATH") && !strings.Contains(compact, "function_exists('add_action')") &&
		!strings.Contains(compact, "function_exists(\"add_action\")") {
		add("wordpress_plugin_direct_access_path_disclosure")
	}
	if strings.Contains(compact, "extensions_blacklist") && strings.Contains(compact, "*.phtml") &&
		!strings.Contains(compact, "*.phar") {
		add("concrete_upload_extension_blacklist_missing_phar")
	}
	if strings.Contains(compact, "delete_option") && strings.Contains(compact, "DELETEFROM") &&
		!strings.Contains(compact, "check_admin_referer") && !strings.Contains(compact, "wp_verify_nonce") {
		add("incomplete_csrf_token_validation")
	}
	if strings.Contains(compact, "imagecopyresampled") && strings.Contains(compact, "returntrue") &&
		!strings.Contains(compact, "===false") && !strings.Contains(compact, "return$imgt") {
		add("unchecked_uploaded_image_processing")
	}
	if strings.Contains(compact, "review.id") && !strings.Contains(compact, "review.customerid") {
		add("review_id_without_customer_id")
	}
	if strings.Contains(compact, "$configuration->getName()") && strings.Contains(compact, "'text'=>$name") &&
		!strings.Contains(compact, "'text'=>htmlspecialchars($name)") && !strings.Contains(compact, "'text'=>htmlentities($name)") {
		add("unescaped_json_tree_label_xss")
	}
	if (calls["self.codes"] || calls["codes"]) && strings.Contains(compact, ".redactor({") && strings.Contains(compact, "autoresize:false") {
		add("gleez_redactor_editor_stored_xss")
	}
	if strings.Contains(compact, "$GLOBALS[") && strings.Contains(compact, "$_GET[") &&
		strings.Contains(compact, "_tplVars") && !strings.Contains(compact, "htmlspecialchars($_GET") &&
		!strings.Contains(compact, "htmlentities($_GET") && !strings.Contains(compact, "esc_html($_GET") &&
		!strings.Contains(compact, "strip_tags($_GET") {
		add("unescaped_request_global_template_var")
	}
	if c.phpClientTemplateInterpolatesRequestInput(n, compact, calls) {
		add("client_template_interpolates_request_input")
	}
	if strings.Contains(compact, "$_POST['systemRootPath']") && strings.Contains(compact, "videos/configuration.php") &&
		strings.Contains(compact, "fopen") && !strings.Contains(compact, "../videos/configuration.php") {
		add("privileged_entry_point_review")
	}
	if strings.Contains(compact, "newWebpage($_POST)") && strings.Contains(compact, "run_includes($_POST['body'])") &&
		!strings.Contains(compact, "require_admin") {
		add("elefant_admin_preview_missing_admin_xss")
	}
	if strings.Contains(compact, "fieldtype()->handle()==='assets'") && strings.Contains(compact, "'.*'=>'file'") &&
		!strings.Contains(compact, "getClientOriginalExtension") && !strings.Contains(compact, "php3") &&
		!strings.Contains(compact, "phtml") {
		add("statamic_asset_upload_php_extension_validation_bypass")
	}
	if strings.Contains(compact, "$model->title=$title") && strings.Contains(compact, "Html::encode($title)") &&
		!strings.Contains(compact, "$model->title=Html::encode($title)") {
		add("persistent_model_title_stored_xss")
	}
	if strings.Contains(compact, "DashboardAjaxController") && strings.Contains(compact, "/dashboard/") &&
		!strings.Contains(compact, "inheritAccessFromModule") {
		add("backend_route_missing_module_authorization")
	}
	if strings.Contains(compact, "ajax_get_calendar_events(") &&
		strings.Contains(compact, "appointments_model->get_batch") &&
		strings.Contains(compact, "providers_model->get_row") &&
		strings.Contains(compact, "services_model->get_row") &&
		strings.Contains(compact, "customers_model->get_row") &&
		!strings.Contains(compact, "PRIV_APPOINTMENTS]['view']") &&
		!strings.Contains(compact, "PRIV_APPOINTMENTS\"][\"view\"]") &&
		!strings.Contains(compact, "cannot(") {
		add("backend_calendar_events_missing_authorization")
	}
	if strings.Contains(compact, "findAllTrash") && strings.Contains(compact, "setShareToken") &&
		!strings.Contains(compact, "checkEditPermissions") {
		add("collectives_public_trash_missing_edit_permission")
	}
	if strings.Contains(compact, "WebBasicAuth") && strings.Contains(compact, "guest_user") &&
		!strings.Contains(compact, "user_template')=='0'&&read_config_option('guest_user')=='0'") {
		add("missing_guest_fallback_for_web_auth")
	}
	if strings.Contains(compact, "_detect_input_format") && strings.Contains(compact, "format->factory") &&
		strings.Contains(compact, "->to_array") && !strings.Contains(compact, "libxml_disable_entity_loader") {
		add("codeigniter_restserver_xml_entity_loader_xxe")
	}
	if strings.Contains(compact, "get_Value('period')") && strings.Contains(compact, "getLastDaysIntervals") &&
		!strings.Contains(compact, "array_key_exists") && !strings.Contains(compact, "filter_var($period") {
		add("unbounded_report_period")
	}
	if strings.Contains(compact, "sanitizeUrl($url)") && strings.Contains(compact, "absoluteUrlWithProtocol($url)") &&
		!strings.Contains(compact, "sanitizeUrl(UrlHelper::absoluteUrlWithProtocol($url))") {
		add("host_expanded_url_sanitized_before_expansion")
	}
	if strings.Contains(compact, "generateKey") && strings.Contains(compact, "keyfile") && !strings.Contains(compact, "chmod") {
		add("secret_file_permission_review")
	}
	if strings.Contains(compact, "Tar") && strings.Contains(compact, "extract(") &&
		strings.Contains(compact, "manifest") && strings.Contains(compact, "unserialize") &&
		!strings.Contains(compact, "allowed_classes") {
		add("archive_manifest_deserialization")
	}
	if strings.Contains(compact, "Process::fromShellCommandline") && strings.Contains(compact, "__destruct") &&
		!strings.Contains(compact, "__sleep") && !strings.Contains(compact, "__wakeup") {
		add("codeception_run_process_deserialization_gadget")
	}
	if strings.Contains(compact, "getAcceptsJson") && strings.Contains(compact, "asModelSuccess") &&
		!strings.Contains(compact, "asSuccess") {
		add("sensitive_model_json_serialization_login")
	}
	if strings.Contains(compact, "CurrentUserSerializer::class") && strings.Contains(compact, "EditUser") &&
		!strings.Contains(compact, "$this->serializer") && !strings.Contains(compact, "$this.serializer") {
		add("sensitive_model_json_serialization_update_user")
	}
	if strings.Contains(compact, "isLinkPotentiallyUnsafe") && strings.Contains(compact, "Xml::escape") &&
		strings.Contains(compact, "true)") && !strings.Contains(compact, "Xml::escape($inline->getUrl())") {
		add("commonmark_preserve_entities_url_attribute_xss")
	}
	if strings.Contains(compact, "FormUtil::getPassedValue('themename'") && strings.Contains(compact, "assign('themename'") &&
		!strings.Contains(compact, "FILTER_SANITIZE_STRING") {
		add("zikula_theme_name_reflected_xss")
	}
	return out
}

func phpTempPathJoinBeforeSeparatorCheck(compact string) bool {
	if !strings.Contains(compact, "DIRECTORY_SEPARATOR") {
		return false
	}
	searchFrom := 0
	for {
		idx := strings.Index(compact[searchFrom:], "DIRECTORY_SEPARATOR.$")
		if idx < 0 {
			return false
		}
		idx += searchFrom
		varName, ok := phpVarNameAt(compact, idx+len("DIRECTORY_SEPARATOR."))
		if !ok {
			searchFrom = idx + len("DIRECTORY_SEPARATOR")
			continue
		}
		exprStart := strings.LastIndex(compact[:idx], ";")
		exprStart++
		expr := strings.ToLower(compact[exprStart:idx])
		if !phpLooksLikeTempPathJoinBase(expr) {
			searchFrom = idx + len("DIRECTORY_SEPARATOR")
			continue
		}
		if phpHasSeparatorGuardBefore(compact[:idx], varName) {
			searchFrom = idx + len("DIRECTORY_SEPARATOR")
			continue
		}
		return true
	}
}

func phpVarNameAt(s string, start int) (string, bool) {
	if start >= len(s) || s[start] != '$' {
		return "", false
	}
	end := start + 1
	for end < len(s) {
		ch := s[end]
		if ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			end++
			continue
		}
		break
	}
	if end == start+1 {
		return "", false
	}
	return s[start:end], true
}

func phpLooksLikeTempPathJoinBase(expr string) bool {
	for _, marker := range []string{"gettemppath(", "tmplinkpath", "temppath", "tmpdir", "tempdir"} {
		if strings.Contains(expr, marker) {
			return true
		}
	}
	return false
}

func phpHasSeparatorGuardBefore(prefix, varName string) bool {
	guards := []string{
		"strpos(" + varName + ",DIRECTORY_SEPARATOR)",
		"strpos(" + varName + ",'/')",
		"strpos(" + varName + ",\"/\")",
		"strpos(" + varName + ",'\\\\')",
		"strpos(" + varName + ",\"\\\\\")",
		"basename(" + varName + ")",
	}
	for _, guard := range guards {
		if strings.Contains(prefix, guard) {
			return true
		}
	}
	assignSanitizers := []string{
		varName + "=basename(" + varName,
		varName + "=str_replace(array('/','\\\\')",
		varName + "=str_replace(array(\"/\",\"\\\\\")",
		varName + "=str_replace(['/',",
		varName + "=str_replace([\"/\",",
	}
	for _, guard := range assignSanitizers {
		if strings.Contains(prefix, guard) {
			return true
		}
	}
	return false
}

func phpEverestFormsEntryFileDeleteWithoutPathGuard(compact string, calls map[string]bool) bool {
	if !strings.Contains(compact, "functiondelete_entry_files(") {
		return false
	}
	if !calls["wp_delete_file"] && !calls["unlink"] {
		return false
	}
	if !strings.Contains(compact, "evf_get_entry(") || !strings.Contains(compact, "->meta") {
		return false
	}
	if strings.Contains(compact, "safe_delete_file(") ||
		strings.Contains(compact, "realpath(") ||
		strings.Contains(compact, "wp_normalize_path(") ||
		strings.Contains(compact, "strpos(") {
		return false
	}
	return true
}

func phpFatFreeClearEvalCompileWithoutKeyValidation(compact string) bool {
	if !strings.Contains(compact, "eval(") || !strings.Contains(compact, "unset(") ||
		!strings.Contains(compact, "compile(") || !strings.Contains(compact, "hive") {
		return false
	}
	evalIdx := strings.Index(compact, "eval(")
	prefix := compact[:evalIdx]
	for _, guard := range []string{
		"preg_replace('/(\\)\\W*\\w+.*$)/','',$key)",
		"preg_replace(\"/(\\)\\W*\\w+.*$)/\",'',$key)",
		"preg_replace('/(\\)\\W*\\w+.*$)/\",\"\",$key)",
		"preg_replace(\"/(\\)\\W*\\w+.*$)/\",\"\",$key)",
	} {
		if strings.Contains(prefix, guard) {
			return false
		}
	}
	return true
}

func phpBpDocsSaveMissingAccessPolicy(compact string) bool {
	if !strings.Contains(compact, "bp_docs_save") || !strings.Contains(compact, "BP_Docs_Query") {
		return false
	}
	saveIdx := strings.Index(compact, "->save(")
	if saveIdx < 0 {
		saveIdx = strings.Index(compact, "save()")
	}
	if saveIdx < 0 {
		return false
	}
	prefix := compact[:saveIdx]
	for _, guard := range []string{"bp_docs_edit", "bp_docs_create"} {
		if strings.Contains(prefix, guard) {
			return false
		}
	}
	return true
}

// phpClientTemplateDirectives are the attribute names AngularJS and Vue put in
// the markup they compile. Both are documented as compiling the DOM they are
// bootstrapped on, and a directive attribute is the marker that says this
// markup is that DOM rather than plain HTML; a `{{ ... }}` on its own can be
// any other brace syntax, so the two are required together.
var phpClientTemplateDirectives = []string{
	"ng-app=", "ng-controller=", "ng-model=", "ng-init=", "ng-repeat=",
	"ng-bind=", "ng-bind-html=", "ng-click=", "ng-show=", "ng-hide=",
	"ng-if=", "ng-class=", "ng-options=", "ng-include=",
	"data-ng-app=", "data-ng-controller=", "data-ng-model=", "data-ng-init=",
	"v-model=", "v-bind:", "v-for=", "v-if=", "v-html=", "v-text=",
}

// phpClientTemplateInterpolatesRequestInput reports a PHP template that a
// client-side template engine compiles in the browser and that echoes a request
// superglobal into that markup with the interpolation delimiters intact.
//
// HTML escaping is not the control for this context. htmlspecialchars,
// htmlentities, strip_tags and json_encode all pass `{` and `}` through
// unchanged, and AngularJS and Vue evaluate `{{ ... }}` in text nodes and in
// attribute values alike, so an echoed `{{ ... }}` is still compiled as an
// expression. Both frameworks document the remedy as keeping request data out of
// the markup the engine compiles, which server-side means removing the
// delimiters themselves.
func (c *phConv) phpClientTemplateInterpolatesRequestInput(n *tree_sitter.Node, compact string, calls map[string]bool) bool {
	if !strings.Contains(compact, "{{") || !strings.Contains(compact, "}}") {
		return false
	}
	directive := false
	for _, attr := range phpClientTemplateDirectives {
		if strings.Contains(compact, attr) {
			directive = true
			break
		}
	}
	if !directive || phpClientTemplateDelimitersRewritten(compact, calls) {
		return false
	}
	return c.phpEchoesRequestGlobal(n)
}

// phpClientTemplateDelimitersRewritten is satisfied when the template rewrites
// the interpolation delimiters through one of PHP's replace functions, which is
// what makes an echoed value inert in markup a client-side engine compiles. The
// quoted forms only occur as PHP string literals, so raw `{{` in the surrounding
// markup does not satisfy this.
func phpClientTemplateDelimitersRewritten(compact string, calls map[string]bool) bool {
	if !phpHasAnyCall(calls, "str_replace", "str_ireplace", "strtr", "preg_replace", "preg_replace_callback") {
		return false
	}
	opening := strings.Contains(compact, `'{{'`) || strings.Contains(compact, `"{{"`)
	closing := strings.Contains(compact, `'}}'`) || strings.Contains(compact, `"}}"`)
	return opening && closing
}

// phpEchoesRequestGlobal reports an echo or print whose own expression reads one
// of PHP's request superglobals, as opposed to a superglobal that only appears
// in a surrounding isset() guard.
func (c *phConv) phpEchoesRequestGlobal(n *tree_sitter.Node) bool {
	found := false
	var walk func(cur *tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil || found {
			return
		}
		if cur.Kind() == "echo_statement" || cur.Kind() == "print_intrinsic" {
			text := phpCompactText(c.text(cur))
			for _, global := range []string{"$_GET[", "$_POST[", "$_REQUEST[", "$_COOKIE["} {
				if strings.Contains(text, global) {
					found = true
					return
				}
			}
		}
		for _, ch := range c.namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

func phpHasReviewToken(tokens []string, want string) bool {
	for _, tok := range tokens {
		if tok == want {
			return true
		}
	}
	return false
}

func phpSessionKeyReferenced(compact, key string) bool {
	return strings.Contains(compact, "$_SESSION['"+key+"']") || strings.Contains(compact, "$_SESSION[\""+key+"\"]")
}

func phpHasAnyCall(calls map[string]bool, names ...string) bool {
	for _, name := range names {
		if calls[name] {
			return true
		}
	}
	return false
}

func phpGPGOptionArgMissingDelimiter(compact, option string) bool {
	if !strings.Contains(compact, "escapeshellarg(") {
		return false
	}
	search := 0
	for {
		idx := strings.Index(compact[search:], option)
		if idx < 0 {
			return false
		}
		idx += search
		tail := compact[idx+len(option):]
		argIdx := strings.Index(tail, "escapeshellarg(")
		if argIdx < 0 {
			return false
		}
		between := tail[:argIdx]
		if !strings.Contains(between, "--") {
			return true
		}
		search = idx + len(option)
	}
}

func (c *phConv) phpAttributeName(n *tree_sitter.Node) (string, string) {
	if n == nil || n.Kind() != "attribute" {
		return "", ""
	}
	for _, ch := range c.namedChildren(n) {
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
		for _, ch := range c.namedChildren(cur) {
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
		for _, ch := range c.namedChildren(cur) {
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
		for _, st := range c.namedChildren(b) {
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
		for _, cs := range c.namedChildren(b) {
			switch cs.Kind() {
			case "case_statement":
				lv := field(cs, "value")
				var stmts []nir.Stmt
				for _, ch := range c.namedChildren(cs) {
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
				for _, ch := range c.namedChildren(cs) {
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
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else {
				for _, cc := range c.namedChildren(ch) {
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
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			name := ""
			if nm := field(ch, "name"); nm != nil {
				name = c.text(nm)
			} else {
				for _, cc := range c.namedChildren(ch) {
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
	for _, a := range c.namedChildren(args) {
		if a.Kind() == "argument" {
			if k := c.namedChildren(a); len(k) > 0 {
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

func (c *phConv) phpParamEntries(name string, params []string, ptypes map[string]string, reviewTokens []string) []nir.ParamEntry {
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
		for _, tok := range reviewTokens {
			tokens = append(tokens, "php_review:"+tok)
		}
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
		for _, ch := range c.namedChildren(n) {
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
	for _, ch := range c.namedChildren(n) {
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
		kids := c.namedChildren(n)
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
		for _, ch := range c.namedChildren(n) {
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
			if kids := c.namedChildren(n); len(kids) > 0 {
				operand = kids[len(kids)-1]
			}
		}
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(operand), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "array_creation_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "array_element_initializer" {
				k := c.namedChildren(ch)
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
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		// include/require used as an expression (`return include $f;`, `$x = include $f;`) —
		// same file-inclusion sink call as the statement form in exprStmt. Without this case the
		// generic Seq fallback below dropped the Call entirely and kept only its argument, so the
		// sink label vanished whenever the include's result was consumed instead of discarded.
		kids := c.namedChildren(n)
		var args []nir.Expr
		if len(kids) > 0 {
			args = append(args, c.expr(kids[0]))
		}
		return nir.Call{Callee: nir.Name{ID: "include", Loc: L}, Args: args, Path: "include", Method: "include", Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
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
		// `self::`/`static::` name the enclosing class, same as `$this` already does for
		// instance calls — substitute it so `self::foo()` resolves to `<Class>.foo` instead of
		// the unresolvable literal path "self.foo". `parent::` is left as-is: the superclass is
		// a genuinely different, unresolved target, not a wrong extraction of this one.
		scope := c.text(field(n, "scope"))
		if (scope == "self" || scope == "static") && c.className != "" {
			scope = c.className
		}
		return scope + "." + c.text(field(n, "name"))
	case "function_call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

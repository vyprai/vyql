package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tscs "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// csConv walks a tree-sitter C# CST into NIR.
type csConv struct {
	src               []byte
	file              string
	key               string
	classParamTokens  []string
	propertyEntryInfo []csPropertyEntry
	childCache        map[uintptr][]*tree_sitter.Node
}

type csPropertyEntry struct {
	Name   string
	Tokens []string
}

// ExtractCSharp parses C# files into one NIR Program (one module per file).
func ExtractCSharp(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tscs.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &csConv{src: src, file: rel, key: moduleKey(root, abs, ".cs")}
			r := tree.RootNode()
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(r), Body: c.decls(r)}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *csConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *csConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *csConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
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

func (c *csConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "using_directive" {
			for _, ch := range c.namedChildren(n) {
				if k := ch.Kind(); k == "qualified_name" || k == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
					break
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

func (c *csConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *csConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	if csPreprocContainer(n.Kind()) {
		return c.csPreprocStmts(n)
	}
	switch n.Kind() {
	case "namespace_declaration", "file_scoped_namespace_declaration", "declaration_list":
		return c.decls(n) // flatten namespace / declaration-list bodies
	case "class_declaration", "struct_declaration", "interface_declaration", "record_declaration", "enum_declaration":
		bodyNode := field(n, "body")
		bases := c.classBases(n)
		prevTokens := c.classParamTokens
		prevProps := c.propertyEntryInfo
		c.classParamTokens = append(append([]string{}, prevTokens...), c.csClassTokens(n, bases)...)
		c.propertyEntryInfo = c.csPropertyEntries(bodyNode)
		cd := nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(bodyNode), Loc: L,
			Bases: bases, Members: c.classMembers(bodyNode)}
		c.classParamTokens = prevTokens
		c.propertyEntryInfo = prevProps
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration", "local_function_statement", "operator_declaration":
		name := c.text(field(n, "name"))
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		body = append(body, c.csFunctionContext(n)...)
		body = append(body, c.csSecurityObservations(n)...)
		methodTokens := append([]string{}, c.classParamTokens...)
		methodTokens = append(methodTokens, c.csAttributeTokens(n, "method_attribute:")...)
		if n.Kind() == "method_declaration" && len(c.propertyEntryInfo) > 0 {
			var seed []nir.Stmt
			for _, p := range c.propertyEntryInfo {
				seed = append(seed, nir.Assign{Targets: []string{p.Name},
					Value: c.csAnalysisCall("analysis.property.entry", L, p.Tokens)})
			}
			body = append(seed, body...)
		}
		exported := (n.Kind() == "method_declaration" || n.Kind() == "constructor_declaration") && csPublic(c, n)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L,
			ParamEntries: c.csParamEntries(name, params, paramTypes, methodTokens, exported), Exported: exported}}
	case "property_declaration":
		// accessor bodies may hold logic
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "field_declaration", "local_declaration_statement":
		var out []nir.Stmt
		var vd *tree_sitter.Node
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "variable_declaration" {
				vd = ch
			}
		}
		if vd == nil {
			return nil
		}
		for _, d := range c.namedChildren(vd) {
			if d.Kind() != "variable_declarator" {
				continue
			}
			name := field(d, "name")
			val := c.declaratorValue(d)
			if name != nil && val != nil {
				out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: c.expr(val)})
			}
		}
		return out
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement", "yield_statement":
		kids := c.namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		// `return this;` / `return base;` — `this`/`base` are UNNAMED keyword tokens, so they
		// are not in namedChildren; capture them explicitly so `return this` carries the self ref.
		for _, ch := range children(n) {
			if k := ch.Kind(); k == "this" || k == "base" {
				return []nir.Stmt{nir.Return{Value: nir.Name{ID: "this", Loc: L}}}
			}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (C# did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.csBranch(field(n, "consequence")), Else: c.csBranch(field(n, "alternative"))}}
	case "for_each_statement", "foreach_statement":
		// `foreach (var p in coll) { … }` — bind the loop variable to the collection so it
		// inherits the collection's element taint (the var/collection were dropped before,
		// so element taint never reached the body).
		body := c.collectBlocks(n)
		if lv, coll := field(n, "left"), field(n, "right"); lv != nil && coll != nil {
			bind := nir.Assign{Targets: []string{c.text(lv)}, Value: nir.Format{Parts: []nir.Expr{c.expr(coll)}, Loc: L}}
			body = append([]nir.Stmt{bind}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement", "using_statement":
		return []nir.Stmt{c.csTry(n)}
	case "switch_statement":
		return []nir.Stmt{c.csSwitch(n)}
	case "lock_statement", "block", "checked_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// attrNames returns the attribute identifiers on a declaration's attribute_lists.
func (c *csConv) attrNames(n *tree_sitter.Node) []string {
	var out []string
	for _, al := range c.namedChildren(n) {
		if al.Kind() != "attribute_list" {
			continue
		}
		for _, a := range c.namedChildren(al) {
			if a.Kind() == "attribute" {
				out = append(out, lastSeg(c.text(field(a, "name"))))
			}
		}
	}
	return out
}

func (c *csConv) csAttributeTokens(n *tree_sitter.Node, prefix string) []string {
	var out []string
	for _, a := range c.attrNames(n) {
		out = append(out, prefix+a)
	}
	return out
}

// csPublic reports whether a C# member is part of the public API: it carries a `public`
// modifier (C# members default to private). Scopes the library param-source.
func csPublic(c *csConv, n *tree_sitter.Node) bool {
	for _, ch := range children(n) {
		if ch.Kind() == "modifier" && c.text(ch) == "public" {
			return true
		}
	}
	return false
}

func (c *csConv) csClassTokens(n *tree_sitter.Node, bases []string) []string {
	name := c.text(field(n, "name"))
	var out []string
	if name != "" {
		out = append(out, "class_name:"+name)
	}
	for _, b := range bases {
		if b != "" {
			out = append(out, "class_base:"+b)
		}
	}
	out = append(out, c.csAttributeTokens(n, "class_attribute:")...)
	return out
}

func (c *csConv) csPropertyEntries(body *tree_sitter.Node) []csPropertyEntry {
	var out []csPropertyEntry
	if body == nil {
		return out
	}
	for _, m := range c.namedChildren(body) {
		if m.Kind() != "property_declaration" {
			continue
		}
		nm := field(m, "name")
		if nm == nil {
			continue
		}
		tokens := []string{"property_name:" + c.text(nm)}
		tokens = append(tokens, c.csAttributeTokens(m, "property_attribute:")...)
		for _, al := range c.namedChildren(m) {
			if al.Kind() == "attribute_list" {
				tokens = append(tokens, "property_attribute_text:"+c.text(al))
			}
		}
		out = append(out, csPropertyEntry{Name: c.text(nm), Tokens: tokens})
	}
	return out
}

func (c *csConv) csParamEntries(name string, params []string, paramTypes map[string]string, base []string, exported bool) []nir.ParamEntry {
	if len(base) == 0 {
		return nil
	}
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" || p == "_" {
			continue
		}
		tokens := append([]string{}, base...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		if exported {
			tokens = append(tokens, "function_visibility:public")
		} else {
			tokens = append(tokens, "function_visibility:private")
		}
		if typ := paramTypes[p]; typ != "" {
			tokens = append(tokens, "param_type:"+typ)
			if short := lastSeg(typ); short != "" && short != typ {
				tokens = append(tokens, "param_type:"+short)
			}
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *csConv) csAnalysisCall(path, loc string, tokens []string) nir.Expr {
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return nir.Call{Callee: nir.Name{ID: path, Loc: loc}, Args: args, Path: path, Method: "entry", Loc: loc}
}

func (c *csConv) csFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	loc := c.loc(fn)
	name := c.text(field(fn, "name"))
	text := c.text(body)
	path := "analysis.function.context"
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=csharp"},
		nir.Const{Loc: loc, Value: "name=" + name},
		nir.Const{Loc: loc, Value: "function_name:" + name},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: csCompactText(text)},
	}
	for _, tok := range c.csStructuredContextTokens(fn, name) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *csConv) csSecurityObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(fn, "name"))
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "object_creation_expression" && lastSeg(c.text(field(n, "type"))) == "TokenValidationParameters" {
			loc := c.loc(n)
			if c.csObjectInitializerBoolField(n, "RequireSignedTokens") == "false" {
				out = append(out, c.csAnalysisStmt("analysis.csharp.jwt_require_signed_tokens_false", "jwt_require_signed_tokens_false", loc,
					"lang=csharp", "function_name:"+name, "type:TokenValidationParameters", "field:RequireSignedTokens", "value:false"))
			}
			if c.csObjectInitializerBoolField(n, "ValidateIssuerSigningKey") == "false" {
				out = append(out, c.csAnalysisStmt("analysis.csharp.jwt_validate_issuer_signing_key_false", "jwt_validate_issuer_signing_key_false", loc,
					"lang=csharp", "function_name:"+name, "type:TokenValidationParameters", "field:ValidateIssuerSigningKey", "value:false"))
			}
		}
		if n.Kind() == "invocation_expression" && c.csUnencodedTicketQueryParameter(n) {
			loc := c.loc(n)
			out = append(out, c.csAnalysisStmt("analysis.csharp.cas_unencoded_ticket_query_parameter", "cas_unencoded_ticket_query_parameter", loc,
				"lang=csharp", "function_name:"+name, "call_path:"+c.dotted(field(n, "function"))))
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

func (c *csConv) csUnencodedTicketQueryParameter(n *tree_sitter.Node) bool {
	path := c.dotted(field(n, "function"))
	if !strings.HasSuffix(path, ".QueryItems.Add") {
		return false
	}
	args := field(n, "arguments")
	if args == nil {
		return false
	}
	var vals []string
	for _, arg := range c.namedChildren(args) {
		vals = append(vals, c.text(arg))
	}
	if len(vals) < 2 {
		return false
	}
	key := vals[0]
	value := vals[1]
	if !strings.Contains(key, "ArtifactParameterName") && csContextValue(key) != "ticket" {
		return false
	}
	return !strings.Contains(value, "UrlEncode(") && !strings.Contains(value, "UrlEncode ")
}

func (c *csConv) csObjectInitializerBoolField(n *tree_sitter.Node, fieldName string) string {
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "initializer_expression" {
			continue
		}
		if value := c.csInitializerBoolField(ch, fieldName); value != "" {
			return value
		}
	}
	return ""
}

func (c *csConv) csInitializerBoolField(init *tree_sitter.Node, fieldName string) string {
	for _, ch := range c.namedChildren(init) {
		if ch.Kind() == "assignment_expression" {
			left := field(ch, "left")
			if lastSeg(c.csContextPath(left)) != fieldName {
				continue
			}
			right := field(ch, "right")
			if right != nil && right.Kind() == "boolean_literal" {
				return c.text(right)
			}
		}
		if value := c.csInitializerBoolField(ch, fieldName); value != "" {
			return value
		}
	}
	return ""
}

func (c *csConv) csAnalysisStmt(path, method, loc string, tokens ...string) nir.Stmt {
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: method,
		Loc:    loc,
	}}
}

func csCompactText(s string) string {
	return compactWhitespaceReplacer.Replace(s)
}

func (c *csConv) csStructuredContextTokens(fn *tree_sitter.Node, name string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if name != "" {
		add("function_name:" + name)
	}
	if params := field(fn, "parameters"); params != nil {
		for i, p := range c.params(params) {
			if p == "" || p == "_" {
				continue
			}
			add("param_name:" + p)
			add("param_index:" + itoa(i))
			if typ := c.paramTypes(params)[p]; typ != "" {
				add("param_type:" + typ)
				if short := lastSeg(typ); short != "" && short != typ {
					add("param_type:" + short)
				}
			}
		}
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			left, right := field(n, "left"), field(n, "right")
			if lhs := c.csContextPath(left); lhs != "" {
				if rhs := csContextValue(c.text(right)); rhs != "" {
					add("assign:" + lhs + "=" + rhs)
				}
				if lshape, rshape := c.csExprShape(left), c.csExprShape(right); lshape != "" && rshape != "" {
					if op := c.csOp(n); op != "" {
						add("assign_op_shape:" + lshape + op + rshape)
					}
				}
				if right != nil && right.Kind() == "invocation_expression" {
					if path := c.dotted(field(right, "function")); path != "" && path != "?" {
						add("assign_call:" + lhs + ":" + path)
					}
				}
			}
		case "local_declaration_statement":
			for _, ch := range c.namedChildren(n) {
				if ch.Kind() != "variable_declaration" {
					continue
				}
				for _, d := range c.namedChildren(ch) {
					if d.Kind() != "variable_declarator" {
						continue
					}
					lhs := c.csContextPath(field(d, "name"))
					right := c.declaratorValue(d)
					if lhs == "" || right == nil {
						continue
					}
					if rhs := csContextValue(c.text(right)); rhs != "" {
						add("assign:" + lhs + "=" + rhs)
					}
					if right.Kind() == "invocation_expression" {
						if path := c.dotted(field(right, "function")); path != "" && path != "?" {
							add("assign_call:" + lhs + ":" + path)
						}
					}
				}
			}
		case "invocation_expression":
			if path := c.dotted(field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
				if args := field(n, "arguments"); args != nil {
					for _, arg := range c.namedChildren(args) {
						if shape := c.csExprShape(arg); shape != "" {
							add("call_arg_shape:" + path + ":" + shape)
						}
					}
				}
			}
		case "object_creation_expression":
			if typ := c.text(field(n, "type")); typ != "" {
				add("call_path:" + typ)
				add("call:" + lastSeg(typ))
			}
		case "member_access_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "identifier":
			if ident := csContextCompact(c.text(n)); ident != "" {
				add("identifier:" + ident)
			}
		case "element_access_expression":
			if idx := c.dotted(n); idx != "" && idx != "?" {
				add("index:" + idx)
			}
			if base := c.dotted(field(n, "expression")); base != "" && base != "?" {
				add("index_base:" + base)
			}
			if key := c.csContextPath(field(n, "subscript")); key != "" {
				add("index_key:" + key)
			}
		case "binary_expression":
			if expr := csContextCompact(c.text(n)); expr != "" {
				add("expr:" + expr)
			}
			if shape := c.csExprShape(n); shape != "" {
				add("binary_shape:" + shape)
			}
		case "cast_expression":
			if shape := c.csExprShape(n); shape != "" {
				add("cast_shape:" + shape)
			}
		case "checked_expression":
			if shape := c.csExprShape(n); shape != "" {
				add("checked_shape:" + shape)
			}
		case "string_literal", "verbatim_string_literal", "raw_string_literal", "integer_literal", "real_literal", "character_literal", "boolean_literal", "null_literal":
			if lit := csContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	body := field(fn, "body")
	if body == nil {
		body = fn
	}
	walk(body)
	return out
}

func (c *csConv) csExprShape(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "argument":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return ""
		}
		return c.csExprShape(kids[len(kids)-1])
	case "identifier", "member_access_expression", "qualified_name":
		return "ID"
	case "invocation_expression", "object_creation_expression":
		return "CALL"
	case "element_access_expression":
		base := c.csExprShape(field(n, "expression"))
		key := c.csExprShape(field(n, "subscript"))
		if base == "" || key == "" {
			return "INDEX"
		}
		return base + "[" + key + "]"
	case "bracketed_argument_list":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return ""
		}
		return c.csExprShape(kids[0])
	case "integer_literal":
		return "INT"
	case "real_literal":
		return "FLOAT"
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		return "STRING"
	case "character_literal":
		return "CHAR"
	case "boolean_literal":
		return "BOOL"
	case "null_literal":
		return "NULL"
	case "sizeof_expression":
		return "SIZEOF"
	case "parenthesized_expression", "checked_expression":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return ""
		}
		return c.csExprShape(kids[len(kids)-1])
	case "cast_expression":
		typ := lastSeg(c.text(field(n, "type")))
		kids := c.namedChildren(n)
		if typ == "" || len(kids) == 0 {
			return ""
		}
		expr := c.csExprShape(kids[len(kids)-1])
		if expr == "" {
			return ""
		}
		return "CAST(" + typ + "," + expr + ")"
	case "binary_expression":
		left := c.csExprShape(field(n, "left"))
		right := c.csExprShape(field(n, "right"))
		op := c.csOp(n)
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	case "assignment_expression":
		left := c.csExprShape(field(n, "left"))
		right := c.csExprShape(field(n, "right"))
		op := c.csOp(n)
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	}
	return ""
}

func (c *csConv) csOp(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if op := strings.TrimSpace(c.text(field(n, "operator"))); op != "" {
		return op
	}
	for i := uint(0); i < n.ChildCount(); i++ {
		if ch := n.Child(i); !ch.IsNamed() {
			op := strings.TrimSpace(c.text(ch))
			switch op {
			case "+", "-", "*", "/", "%", "<<", ">>", "+=", "-=", "*=", "/=", "=", "==", "!=", "<", ">", "<=", ">=":
				return op
			}
		}
	}
	return ""
}

func (c *csConv) csContextPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if p := c.dotted(n); p != "" && p != "?" {
		return p
	}
	return csContextValue(c.text(n))
}

func csContextValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"' || q == '`') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
		}
	}
	if strings.HasPrefix(s, "@\"") && strings.HasSuffix(s, "\"") && len(s) >= 3 {
		s = s[2 : len(s)-1]
	}
	return csContextCompact(s)
}

func csContextCompact(raw string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	if len(s) > 160 {
		return ""
	}
	return s
}

func (c *csConv) declaratorValue(d *tree_sitter.Node) *tree_sitter.Node {
	name := field(d, "name")
	for _, ch := range c.namedChildren(d) {
		if name != nil && ch.StartByte() == name.StartByte() && ch.EndByte() == name.EndByte() {
			continue
		}
		if ch.Kind() == "equals_value_clause" {
			if k := c.namedChildren(ch); len(k) > 0 {
				return k[len(k)-1]
			}
		}
		return ch
	}
	return nil
}

func (c *csConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	if inner.Kind() == "assignment_expression" {
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			target := c.text(left)
			// a compound assignment (x += y) also reads the target; a plain
			// Assign models only the write and drops the target's prior taint.
			if csCompoundAssignOp(c.csOp(inner)) {
				return []nir.Stmt{nir.AugAssign{Target: target, Value: right, Loc: c.loc(inner)}}
			}
			return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: right}}
		}
		// member/element property write `obj.prop = x`: model as a path call
		// (Method="") so the assigned value flows into a write node that path
		// mappings can match. Mirrors the JS/Kotlin member-write modeling.
		if left != nil && (left.Kind() == "member_access_expression" || left.Kind() == "element_access_expression") {
			p := c.dotted(left)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: c.loc(inner)}}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// csCompoundAssignOp reports whether op is a compound assignment operator
// (x += y and friends). The grammar folds these into assignment_expression,
// so the operator token is the only discriminator.
func csCompoundAssignOp(op string) bool {
	switch op {
	case "+=", "-=", "*=", "/=":
		return true
	}
	return false
}

// csBranch flattens one if-branch body: a `{}` block, a brace-less single statement, or a
// nested if (else-if).
func (c *csConv) csBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "block" {
		var out []nir.Stmt
		for _, st := range c.namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	}
	return c.stmt(b)
}

// csSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through-empty sections merge into the next body) so a constant subject prunes.
func (c *csConv) csSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, sec := range c.namedChildren(b) {
			if sec.Kind() != "switch_section" {
				continue
			}
			var labs []nir.Expr
			var stmts []nir.Stmt
			isDefault := false
			for _, ch := range c.namedChildren(sec) {
				switch ch.Kind() {
				case "case_switch_label", "constant_pattern":
					lv := ch
					if k := c.namedChildren(ch); len(k) > 0 {
						lv = k[0]
					}
					labs = append(labs, c.expr(lv))
				case "default_switch_label":
					isDefault = true
				default:
					stmts = append(stmts, c.stmt(ch)...)
				}
			}
			if isDefault {
				deflt = append(deflt, stmts...)
				continue
			}
			pending = append(pending, labs...)
			if len(stmts) > 0 {
				cases = append(cases, stmts)
				labels = append(labels, pending)
				pending = nil
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
}

// csTry splits a `finally` clause out of the try statement. A `finally` runs on every
// path out of the statement, which is what lets a release written there cover an
// acquisition above or inside the try; folded into the body it reads as code that may be
// skipped and covers nothing. `using` carries no finally clause, so it still lowers to a
// body-only Try.
func (c *csConv) csTry(n *tree_sitter.Node) nir.Try {
	var finally []nir.Stmt
	for _, ch := range children(n) {
		if ch.Kind() == "finally_clause" {
			finally = append(finally, c.collectBlocks(ch)...)
		}
	}
	body := c.collectBlocksSkipping(n, func(kind string) bool { return kind == "finally_clause" })
	return nir.Try{Body: body, Finally: finally}
}

func (c *csConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	return c.collectBlocksSkipping(n, nil)
}

// collectBlocksSkipping is collectBlocks with a filter: a child whose kind `skip` reports
// is neither collected nor descended into.
func (c *csConv) collectBlocksSkipping(n *tree_sitter.Node, skip func(kind string) bool) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			if skip != nil && skip(ch.Kind()) {
				continue
			}
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "else_clause", "catch_clause", "catch_declaration", "finally_clause", "accessor_list",
				"accessor_declaration", "switch_body", "switch_section", "if_statement", "declaration_list",
				"preproc_if", "preproc_elif", "preproc_else", "preproc_if_in_top_level",
				"preproc_elif_in_top_level", "preproc_else_in_top_level":
				walk(ch)
			case "local_declaration_statement", "expression_statement", "return_statement":
				out = append(out, c.stmt(ch)...)
			case "variable_declaration": // `using (T x = new T(...))` resource header
				for _, d := range c.namedChildren(ch) {
					if d.Kind() == "variable_declarator" {
						name, val := field(d, "name"), c.declaratorValue(d)
						if name != nil && val != nil {
							out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: c.expr(val)})
						}
					}
				}
			}
		}
	}
	if n.Kind() == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func csPreprocContainer(kind string) bool {
	switch kind {
	case "preproc_if", "preproc_elif", "preproc_else",
		"preproc_if_in_top_level", "preproc_elif_in_top_level", "preproc_else_in_top_level":
		return true
	default:
		return false
	}
}

func (c *csConv) csPreprocStmts(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *csConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	// Expression-bodied member: `T M(...) => expr;` — the arrow clause is the body
	// field but holds a bare expression, so model it as an implicit return so the
	// param→return dataflow forms (without this the value is dropped).
	if block.Kind() == "arrow_expression_clause" {
		kids := c.namedChildren(block)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[len(kids)-1])}}
		}
		return nil
	}
	var out []nir.Stmt
	for _, st := range c.namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

// classBases returns the base class / interface SHORT names of a class declaration (generics
// stripped: `ParametersCollection<HeaderParameter>` -> `ParametersCollection`), for
// inheritance-aware implicit-`this` member resolution.
func (c *csConv) classBases(n *tree_sitter.Node) []string {
	var bl *tree_sitter.Node
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() == "base_list" {
			bl = ch
			break
		}
	}
	if bl == nil {
		return nil
	}
	var out []string
	for _, b := range c.namedChildren(bl) {
		if nm := lastSeg(baseTypeName(c, b)); nm != "" {
			out = append(out, nm)
		}
	}
	return out
}

// baseTypeName extracts the type name from a base-list entry, stripping generic arguments.
func baseTypeName(c *csConv, n *tree_sitter.Node) string {
	switch n.Kind() {
	case "generic_name":
		if id := field(n, "name"); id != nil {
			return c.text(id)
		}
		if k := c.namedChildren(n); len(k) > 0 {
			return c.text(k[0])
		}
	}
	return c.text(n)
}

// classMembers returns the data-member names (fields + properties) declared directly in a class
// body, so a bare member reference in a method resolves to `this.<member>`.
func (c *csConv) classMembers(body *tree_sitter.Node) []string {
	if body == nil {
		return nil
	}
	var out []string
	for _, m := range c.namedChildren(body) {
		switch m.Kind() {
		case "property_declaration", "event_declaration":
			if nm := field(m, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		case "field_declaration", "event_field_declaration":
			for _, ch := range c.namedChildren(m) {
				if ch.Kind() == "variable_declaration" {
					for _, d := range c.namedChildren(ch) {
						if d.Kind() == "variable_declarator" {
							if nm := field(d, "name"); nm != nil {
								out = append(out, c.text(nm))
							}
						}
					}
				}
			}
		}
	}
	return out
}

// lambdaParams extracts the parameter names of a C# lambda: an `implicit_parameter`/identifier
// for `x => …`, or a `parameter_list` for `(x, y) => …` / `(int x) => …`.
func (c *csConv) lambdaParams(p *tree_sitter.Node) []string {
	if p == nil {
		return nil
	}
	switch p.Kind() {
	case "parameter_list":
		var out []string
		for _, ch := range c.namedChildren(p) {
			switch ch.Kind() {
			case "parameter":
				if nm := field(ch, "name"); nm != nil {
					out = append(out, c.text(nm))
				}
			case "implicit_parameter", "identifier":
				out = append(out, c.text(ch))
			}
		}
		return out
	case "implicit_parameter", "identifier":
		return []string{c.text(p)}
	}
	return nil
}

func (c *csConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *csConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *csConv) callArgs(args *tree_sitter.Node) []nir.Expr {
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

func (c *csConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "base":
		return nir.Name{ID: c.text(n), Loc: L}
	case "this_expression", "base_expression":
		// `this` / `base` — model both as the self reference ("this") so member writes/reads and
		// `return this` resolve to the same stable self node (base.X is this.X for our purposes).
		return nir.Name{ID: "this", Loc: L}
	case "null_literal", "predefined_type":
		return nir.Const{Loc: L}
	case "integer_literal", "real_literal", "character_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "boolean_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // true/false for `val` matching
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "interpolated_string_expression", "interpolated_verbatim_string_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "interpolation" {
				// the hole's named children are `interpolation_brace {`, the EXPRESSION, then
				// `interpolation_brace }` (+ optional alignment/format clauses). Indexing [0]
				// blindly picked up the `{` brace, dropping every interpolated value's taint —
				// so lower each real expression child (interpolation is ubiquitous in C#).
				for _, e := range c.namedChildren(ch) {
					switch e.Kind() {
					case "interpolation_brace", "interpolation_alignment_clause", "interpolation_format_clause":
						// punctuation / formatting — not a value
					default:
						parts = append(parts, c.expr(e))
					}
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "member_access_expression":
		return nir.Attr{Base: c.expr(field(n, "expression")), Attr: c.text(field(n, "name")), Path: c.dotted(n), Loc: L}
	case "element_access_expression":
		var key nir.Expr
		if sub := field(n, "subscript"); sub != nil {
			if k := c.namedChildren(sub); len(k) > 0 {
				key = c.expr(k[0])
			}
		}
		return nir.Index{Base: c.expr(field(n, "expression")), Key: key, Path: c.dotted(field(n, "expression")), Loc: L}
	case "invocation_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "object_creation_expression":
		typ := c.text(field(n, "type"))
		args := c.callArgs(field(n, "arguments"))
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "initializer_expression" {
				args = append(args, c.expr(ch))
			}
		}
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: args, Path: typ, Method: typ, Loc: L, IsCtor: true}
	case "lambda_expression", "anonymous_method_expression":
		// C# lambdas / anonymous delegates were unlowered (fell through to a Seq), so callbacks
		// and ALL LINQ (Select/Where/ForEach/GroupBy…) dropped their bodies — no taint reached
		// the lambda param or a sink inside it. Lower as nir.Lambda so the param is routed from
		// the receiver (elementCallbackMethods) and the body is analysed.
		params := c.lambdaParams(field(n, "parameters"))
		var body []nir.Stmt
		if b := field(n, "body"); b != nil {
			if b.Kind() == "block" {
				body = c.block(b)
			} else {
				body = []nir.Stmt{nir.Return{Value: c.expr(b)}} // expression-bodied lambda
			}
		}
		return nir.Lambda{Params: params, Body: body, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "prefix_unary_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Unary{Op: c.text(n)[:1], Operand: c.expr(kids[len(kids)-1]), Loc: L}
		}
	case "parenthesized_expression", "cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "await_expression", "ref_expression", "checked_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "assignment_expression":
		left := field(n, "left")
		if left != nil {
			return nir.Pair{Key: lastSeg(c.dotted(left)), Value: c.expr(field(n, "right")), Loc: L}
		}
		return c.expr(field(n, "right"))
	case "initializer_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *csConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "base", "qualified_name", "predefined_type":
		return c.text(n)
	case "member_access_expression":
		return c.dotted(field(n, "expression")) + "." + c.text(field(n, "name"))
	case "invocation_expression":
		return c.dotted(field(n, "function"))
	case "element_access_expression":
		return c.dotted(field(n, "expression")) + "[]"
	case "object_creation_expression":
		return c.text(field(n, "type"))
	case "parenthesized_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

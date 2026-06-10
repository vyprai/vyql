package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// rsConv walks a tree-sitter Rust CST into NIR.
type rsConv struct {
	src  []byte
	file string
	key  string
}

// rsFormatMacros build a string from their arguments (taint-propagating).
var rsFormatMacros = map[string]bool{
	"format": true, "println": true, "print": true, "eprintln": true,
	"eprint": true, "write": true, "writeln": true, "panic": true, "format_args": true,
}

// rsHandlerAttrs mark a function as a web request handler (actix/rocket/axum).
var rsHandlerAttrs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "route": true, "handler": true,
}

// ExtractRust parses Rust files into one NIR Program (one module per file).
func ExtractRust(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsrust.Language()))

	var prog nir.Program
	prog.SelfName = "self"
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		rel := relPath(root, f)
		c := &rsConv{src: src, file: rel, key: moduleKey(root, f, ".rs")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *rsConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *rsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls walks a list, tracking a preceding attribute_item so request-handler
// functions can seed their params as sources.
func (c *rsConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	handler := false
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "attribute_item" {
			handler = handler || c.isHandlerAttr(ch)
			continue
		}
		out = append(out, c.stmtH(ch, handler)...)
		handler = false
	}
	return out
}

func (c *rsConv) isHandlerAttr(n *tree_sitter.Node) bool {
	// #[get("/..")] → attribute_item > attribute > identifier "get"
	var name string
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m.Kind() == "attribute" {
			for _, ch := range namedChildren(m) {
				if ch.Kind() == "identifier" || ch.Kind() == "scoped_identifier" {
					name = lastSeg(c.dotted(ch))
					return
				}
			}
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return rsHandlerAttrs[name]
}

func (c *rsConv) stmt(n *tree_sitter.Node) []nir.Stmt { return c.stmtH(n, false) }

func (c *rsConv) stmtH(n *tree_sitter.Node, handler bool) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_item":
		params := c.params(field(n, "parameters"))
		body := c.block(field(n, "body"))
		if handler {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, Body: body, Loc: L}}
	case "impl_item", "mod_item", "trait_item":
		return c.decls(field(n, "body"))
	case "struct_item", "enum_item", "use_declaration", "const_item", "static_item":
		return nil
	case "let_declaration":
		name := c.patName(field(n, "pattern"))
		if val := field(n, "value"); name != "" && val != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(val)}}
		}
		return nil
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "block":
		return c.block(n)
	}
	// a bare tail expression (block value) still matters for taint
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *rsConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	if inner.Kind() == "assignment_expression" {
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *rsConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *rsConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "else_clause", "match_block", "match_arm":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *rsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := c.patName(field(ch, "pattern")); nm != "" {
				out = append(out, nm)
			}
		}
	}
	return out
}

// patName extracts the bound identifier from a pattern (unwrapping ref/mut).
func (c *rsConv) patName(p *tree_sitter.Node) string {
	for p != nil {
		switch p.Kind() {
		case "identifier":
			return c.text(p)
		case "ref_pattern", "mut_pattern", "reference_pattern":
			kids := namedChildren(p)
			if len(kids) == 0 {
				return ""
			}
			p = kids[len(kids)-1]
		default:
			return ""
		}
	}
	return ""
}

func (c *rsConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *rsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "self", "field_identifier", "type_identifier", "scoped_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer_literal", "float_literal", "boolean_literal", "char_literal", "unit_expression":
		return nir.Const{Loc: L}
	case "string_literal", "raw_string_literal":
		return nir.Const{Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "value")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "index_expression":
		kids := namedChildren(n)
		var base nir.Expr = nir.Const{Loc: L}
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		return nir.Index{Base: base, Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "macro_invocation":
		name := lastSeg(c.dotted(field(n, "macro")))
		var parts []nir.Expr
		if tt := lastChildKind(n, "token_tree"); tt != nil {
			for _, ch := range namedChildren(tt) {
				if isRustExprTok(ch.Kind()) {
					parts = append(parts, c.expr(ch))
				}
			}
		}
		if rsFormatMacros[name] {
			return nir.Format{Parts: parts, Loc: L}
		}
		// other macros (e.g. query!) — model as a call so they can be sinks
		return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: parts, Path: name, Method: name, Loc: L}
	case "binary_expression":
		if c.text(field(n, "operator")) == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "reference_expression", "unary_expression", "try_expression", "await_expression",
		"parenthesized_expression", "type_cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "if_expression", "match_expression", "block":
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *rsConv) blockValues(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	for _, ch := range namedChildren(n) {
		out = append(out, c.expr(ch))
	}
	return out
}

func (c *rsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "self", "primitive_type":
		return c.text(n)
	case "scoped_identifier", "scoped_type_identifier":
		path := field(n, "path")
		name := field(n, "name")
		if path == nil {
			return c.dotted(name)
		}
		return c.dotted(path) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(field(n, "value")) + "." + c.text(field(n, "field"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "generic_function":
		return c.dotted(field(n, "function"))
	case "generic_type":
		return c.dotted(field(n, "type"))
	case "index_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0]) + "[]"
		}
	}
	return "?"
}

func isRustExprTok(k string) bool {
	switch k {
	case "identifier", "scoped_identifier", "field_expression", "call_expression",
		"macro_invocation", "index_expression", "reference_expression", "self":
		return true
	}
	return false
}

func lastChildKind(n *tree_sitter.Node, kind string) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == kind {
			return ch
		}
	}
	return nil
}

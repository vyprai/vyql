package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tscs "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// csConv walks a tree-sitter C# CST into NIR.
type csConv struct {
	src          []byte
	file         string
	key          string
	inController bool // inside an MVC controller → action params are user input
}

var csHTTPAttrs = map[string]bool{
	"HttpGet": true, "HttpPost": true, "HttpPut": true, "HttpDelete": true,
	"HttpPatch": true, "HttpHead": true, "Route": true, "ApiController": true,
}

// ExtractCSharp parses C# files into one NIR Program (one module per file).
func ExtractCSharp(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tscs.Language()))

	var prog nir.Program
	prog.SelfName = "this"
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
		c := &csConv{src: src, file: rel, key: moduleKey(root, f, ".cs")}
		root := tree.RootNode()
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Imports: c.imports(root), Body: c.decls(root)})
		tree.Close()
	}
	return prog, nil
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

func (c *csConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "using_directive" {
			for _, ch := range namedChildren(n) {
				if k := ch.Kind(); k == "qualified_name" || k == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
					break
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func (c *csConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *csConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "namespace_declaration", "file_scoped_namespace_declaration", "declaration_list":
		return c.decls(n) // flatten namespace / declaration-list bodies
	case "class_declaration", "struct_declaration", "interface_declaration", "record_declaration", "enum_declaration":
		prev := c.inController
		c.inController = prev || c.isController(n)
		cd := nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}
		c.inController = prev
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration", "local_function_statement", "operator_declaration":
		params := c.params(field(n, "parameters"))
		body := c.block(field(n, "body"))
		// ASP.NET Core MVC: an action's parameters are model-bound from the request
		// (route/query/body), so they are user input. Seed each as an HttpInput
		// source at the top of the body.
		if n.Kind() == "method_declaration" && (c.inController || c.hasHTTPAttr(n)) {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, Body: body, Loc: L}}
	case "property_declaration":
		// accessor bodies may hold logic
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "field_declaration", "local_declaration_statement":
		var out []nir.Stmt
		var vd *tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "variable_declaration" {
				vd = ch
			}
		}
		if vd == nil {
			return nil
		}
		for _, d := range namedChildren(vd) {
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
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement", "yield_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement", "while_statement", "for_statement", "for_each_statement", "foreach_statement",
		"do_statement", "try_statement", "using_statement", "switch_statement", "lock_statement", "block", "checked_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// attrNames returns the attribute identifiers on a declaration's attribute_lists.
func (c *csConv) attrNames(n *tree_sitter.Node) []string {
	var out []string
	for _, al := range namedChildren(n) {
		if al.Kind() != "attribute_list" {
			continue
		}
		for _, a := range namedChildren(al) {
			if a.Kind() == "attribute" {
				out = append(out, lastSeg(c.text(field(a, "name"))))
			}
		}
	}
	return out
}

func (c *csConv) hasHTTPAttr(n *tree_sitter.Node) bool {
	for _, a := range c.attrNames(n) {
		if csHTTPAttrs[a] {
			return true
		}
	}
	return false
}

// isController reports whether a class is an MVC controller (by base type,
// [ApiController]/[Route] attribute, or the *Controller naming convention).
func (c *csConv) isController(n *tree_sitter.Node) bool {
	name := c.text(field(n, "name"))
	if len(name) >= 10 && name[len(name)-10:] == "Controller" {
		return true
	}
	if c.hasHTTPAttr(n) {
		return true
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "base_list" {
			for _, b := range namedChildren(ch) {
				t := lastSeg(c.text(b))
				if t == "Controller" || t == "ControllerBase" || t == "ApiController" {
					return true
				}
			}
		}
	}
	return false
}

func (c *csConv) declaratorValue(d *tree_sitter.Node) *tree_sitter.Node {
	name := field(d, "name")
	for _, ch := range namedChildren(d) {
		if name != nil && ch.StartByte() == name.StartByte() && ch.EndByte() == name.EndByte() {
			continue
		}
		if ch.Kind() == "equals_value_clause" {
			if k := namedChildren(ch); len(k) > 0 {
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
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *csConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "else_clause", "catch_clause", "catch_declaration", "finally_clause", "accessor_list",
				"accessor_declaration", "switch_body", "switch_section", "if_statement", "declaration_list":
				walk(ch)
			case "local_declaration_statement", "expression_statement", "return_statement":
				out = append(out, c.stmt(ch)...)
			case "variable_declaration": // `using (T x = new T(...))` resource header
				for _, d := range namedChildren(ch) {
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

func (c *csConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *csConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
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

func (c *csConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "base":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer_literal", "real_literal", "null_literal", "character_literal", "predefined_type":
		return nir.Const{Loc: L}
	case "boolean_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // true/false for `val` matching
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "interpolated_string_expression", "interpolated_verbatim_string_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "interpolation" {
				if k := namedChildren(ch); len(k) > 0 {
					parts = append(parts, c.expr(k[0]))
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
		return nir.Index{Base: c.expr(field(n, "expression")), Path: c.dotted(field(n, "expression")), Loc: L}
	case "invocation_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "object_creation_expression":
		typ := c.text(field(n, "type"))
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		if c.text(field(n, "operator")) == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "conditional_expression":
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "consequence")), c.expr(field(n, "alternative"))}, Loc: L}
	case "await_expression", "ref_expression", "checked_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "assignment_expression":
		return c.expr(field(n, "right"))
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
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
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

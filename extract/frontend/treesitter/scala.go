package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsscala "github.com/tree-sitter/tree-sitter-scala/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// scConvScala walks a tree-sitter Scala CST into NIR.
type scConvScala struct {
	src  []byte
	file string
	key  string
}

// ExtractScala parses Scala files into one NIR Program (one module per file).
func ExtractScala(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsscala.Language()))

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
		c := &scConvScala{src: src, file: rel, key: moduleKey(root, f, ".scala")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *scConvScala) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *scConvScala) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *scConvScala) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *scConvScala) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "package_clause", "package_object":
		if b := field(n, "body"); b != nil {
			return c.decls(b)
		}
		return c.decls(n)
	case "object_definition", "class_definition", "trait_definition", "enum_definition":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}}
	case "function_definition":
		return []nir.Stmt{nir.FuncDef{
			Name:   c.text(field(n, "name")),
			Params: c.params(field(n, "parameters")),
			Body:   c.bodyStmts(field(n, "body")),
			Loc:    L,
		}}
	case "val_definition", "var_definition", "val_declaration", "var_declaration":
		name := c.patName(field(n, "pattern"))
		if v := field(n, "value"); name != "" && v != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
		}
		return nil
	case "assignment_expression":
		left := field(n, "left")
		right := c.expr(field(n, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "if_expression", "match_expression", "try_expression", "for_expression", "while_expression", "block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *scConvScala) bodyStmts(body *tree_sitter.Node) []nir.Stmt {
	if body == nil {
		return nil
	}
	if body.Kind() == "block" {
		return c.block(body)
	}
	return []nir.Stmt{nir.Return{Value: c.expr(body)}}
}

func (c *scConvScala) block(block *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *scConvScala) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "indented_block", "case_clause", "catch_clause", "finally_clause", "else_clause", "guard":
				walk(ch)
			default:
				if ch.IsNamed() {
					out = append(out, c.stmt(ch)...)
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

func (c *scConvScala) params(params *tree_sitter.Node) []string {
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

func (c *scConvScala) patName(p *tree_sitter.Node) string {
	if p == nil {
		return ""
	}
	switch p.Kind() {
	case "identifier":
		return c.text(p)
	case "typed_pattern", "tuple_pattern":
		if kids := namedChildren(p); len(kids) > 0 {
			return c.patName(kids[0])
		}
	}
	return ""
}

func (c *scConvScala) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *scConvScala) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "stable_identifier", "wildcard":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer_literal", "floating_point_literal", "boolean_literal", "null_literal", "character_literal", "unit":
		return nir.Const{Loc: L}
	case "string", "symbol_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "interpolated_string_expression":
		var parts []nir.Expr
		if is := lastChildKind(n, "interpolated_string"); is != nil {
			var walk func(m *tree_sitter.Node)
			walk = func(m *tree_sitter.Node) {
				for _, ch := range namedChildren(m) {
					if ch.Kind() == "interpolation" {
						for _, e := range namedChildren(ch) {
							parts = append(parts, c.expr(e))
						}
					} else {
						walk(ch)
					}
				}
			}
			walk(is)
		}
		return nir.Format{Parts: parts, Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "value")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "generic_function":
		return c.expr(field(n, "function"))
	case "infix_expression":
		op := c.text(field(n, "operator"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "if_expression", "match_expression", "block":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *scConvScala) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "operator_identifier", "type_identifier":
		return c.text(n)
	case "stable_identifier":
		return c.text(n)
	case "field_expression":
		return c.dotted(field(n, "value")) + "." + c.text(field(n, "field"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "generic_function":
		return c.dotted(field(n, "function"))
	}
	return "?"
}

package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// jvConv walks a tree-sitter Java CST into NIR.
type jvConv struct {
	src  []byte
	root string
	file string
	key  string
}

// ExtractJava parses Java files into one NIR Program (one module per file, keyed
// by source-root-relative dotted path).
func ExtractJava(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsjava.Language()))

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
		c := &jvConv{src: src, root: root, file: rel, key: moduleKey(root, f, ".java")}
		r := tree.RootNode()
		mod := nir.Module{Key: c.key, File: rel, Imports: c.imports(r), Body: c.decls(r)}
		prog.Modules = append(prog.Modules, mod)
		tree.Close()
	}
	return prog, nil
}

func (c *jvConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *jvConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *jvConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "import_declaration" {
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "scoped_identifier" || ch.Kind() == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
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

// decls lowers top-level + class-member declarations.
func (c *jvConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *jvConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}}
	case "method_declaration", "constructor_declaration":
		return []nir.Stmt{nir.FuncDef{
			Name:   c.text(field(n, "name")),
			Params: c.params(field(n, "parameters")),
			Body:   c.block(field(n, "body")),
			Loc:    L,
		}}
	case "field_declaration", "local_variable_declaration":
		var out []nir.Stmt
		for _, d := range namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v})
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
	case "if_statement", "while_statement", "for_statement", "enhanced_for_statement", "do_statement",
		"try_statement", "try_with_resources_statement", "switch_expression", "block", "synchronized_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "static_initializer", "constructor_body":
		return []nir.Stmt{nir.Block{Stmts: c.block(n)}}
	}
	return nil
}

func (c *jvConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *jvConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block", "constructor_body":
				out = append(out, c.block(ch)...)
			case "switch_block", "switch_block_statement_group", "catch_clause", "finally_clause",
				"resource_specification", "if_statement", "else":
				walk(ch)
			}
		}
	}
	if n.Kind() == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *jvConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jvConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "formal_parameter" || ch.Kind() == "spread_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *jvConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "super":
		return nir.Name{ID: c.text(n), Loc: L}
	case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
		"true", "false", "null_literal", "character_literal":
		return nir.Const{Loc: L}
	case "string_literal":
		// pick up interpolation in text blocks if any; otherwise constant
		return nir.Const{Loc: L, Value: c.text(n)}
	case "field_access":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "array_access":
		return nir.Index{Base: c.expr(field(n, "array")), Path: c.dotted(field(n, "array")), Loc: L}
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		var callee nir.Expr
		if obj != nil {
			callee = nir.Attr{Base: c.expr(obj), Attr: name, Path: path, Loc: L}
		} else {
			callee = nir.Name{ID: name, Loc: L}
		}
		return nir.Call{Callee: callee, Args: arglist, Path: path, Method: name, Loc: L}
	case "object_creation_expression":
		typ := c.text(field(n, "type"))
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		// model `new T(args)` as a constructor call with callee path "T", so
		// sinks/types can match (e.g. new ProcessBuilder, new File, new URL).
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: arglist, Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		if c.text(field(n, "operator")) == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "ternary_expression":
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "consequence")), c.expr(field(n, "alternative"))}, Loc: L}
	case "array_initializer":
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

func (c *jvConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "super", "type_identifier", "scoped_identifier":
		return c.text(n)
	case "field_access":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "field"))
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		if obj == nil {
			return name
		}
		return c.dotted(obj) + "." + name
	case "array_access":
		return c.dotted(field(n, "array")) + "[]"
	case "object_creation_expression":
		return c.text(field(n, "type"))
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	if strings.Contains(c.text(n), ".") {
		return c.text(n)
	}
	return "?"
}

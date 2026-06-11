package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tslua "github.com/tree-sitter-grammars/tree-sitter-lua/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// luaConv walks a tree-sitter Lua CST into NIR.
type luaConv struct {
	src  []byte
	file string
	key  string
}

// ExtractLua parses Lua files into one NIR Program (one module per file).
func ExtractLua(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tslua.Language()))

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
		c := &luaConv{src: src, file: rel, key: moduleKey(root, f, ".lua")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *luaConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *luaConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *luaConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *luaConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_declaration", "function_definition_statement", "local_function_declaration_statement":
		return []nir.Stmt{nir.FuncDef{
			Name:   lastSeg(c.dotted(field(n, "name"))),
			Params: c.params(field(n, "parameters")),
			Body:   c.block(field(n, "body")),
			Loc:    L,
		}}
	case "variable_declaration", "local_variable_declaration":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "assignment_statement" {
				out = append(out, c.stmt(ch)...)
			}
		}
		if len(out) > 0 {
			return out
		}
		// local x = v  with fields directly on the node
		return c.assign(field(n, "name"), field(n, "value"), namedChildren(n))
	case "assignment_statement":
		return c.assignStmt(n)
	case "function_call":
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (Lua did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Then: c.collectBlocks(n)}}
	case "while_statement", "for_statement", "for_numeric_statement", "for_generic_statement", "repeat_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "do_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// assignStmt pairs a variable_list with an expression_list.
func (c *luaConv) assignStmt(n *tree_sitter.Node) []nir.Stmt {
	var names []string
	var vals []nir.Expr
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "variable_list":
			for _, v := range namedChildren(ch) {
				names = append(names, c.lvalName(v))
			}
		case "expression_list":
			for _, v := range namedChildren(ch) {
				vals = append(vals, c.expr(v))
			}
		}
	}
	var out []nir.Stmt
	for i, nm := range names {
		if nm == "" || i >= len(vals) {
			continue
		}
		out = append(out, nir.Assign{Targets: []string{nm}, Value: vals[i]})
	}
	return out
}

func (c *luaConv) assign(nameNode, valNode *tree_sitter.Node, kids []*tree_sitter.Node) []nir.Stmt {
	if nameNode != nil && valNode != nil {
		return []nir.Stmt{nir.Assign{Targets: []string{c.lvalName(nameNode)}, Value: c.expr(valNode)}}
	}
	return nil
}

// lvalName returns a simple assignable name (bare identifier only; field/index
// targets aren't tracked as scalar vars).
func (c *luaConv) lvalName(n *tree_sitter.Node) string {
	if n != nil && n.Kind() == "identifier" {
		return c.text(n)
	}
	return ""
}

func (c *luaConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "elseif_statement", "else_statement":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *luaConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "identifier" {
			out = append(out, c.text(ch))
		}
	}
	return out
}

func (c *luaConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *luaConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "self", "vararg_expression":
		return nir.Name{ID: c.text(n), Loc: L}
	case "true", "false", "nil":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "number":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string":
		return nir.Const{Loc: L}
	case "dot_index_expression":
		return nir.Attr{Base: c.expr(field(n, "table")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "bracket_index_expression":
		return nir.Index{Base: c.expr(field(n, "table")), Key: c.expr(field(n, "field")), Path: c.dotted(field(n, "table")), Loc: L}
	case "method_index_expression":
		return nir.Attr{Base: c.expr(field(n, "table")), Attr: c.text(field(n, "method")), Path: c.dotted(n), Loc: L}
	case "function_call":
		fn := field(n, "name")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == ".." || op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *luaConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "self":
		return c.text(n)
	case "dot_index_expression":
		return c.dotted(field(n, "table")) + "." + c.text(field(n, "field"))
	case "method_index_expression":
		return c.dotted(field(n, "table")) + "." + c.text(field(n, "method"))
	case "bracket_index_expression":
		return c.dotted(field(n, "table")) + "[]"
	case "function_call":
		return c.dotted(field(n, "name"))
	}
	return "?"
}

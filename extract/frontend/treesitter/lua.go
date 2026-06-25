package treesitter

import (
	"strings"

	tslua "github.com/tree-sitter-grammars/tree-sitter-lua/bindings/go"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

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
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tslua.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &luaConv{src: src, file: rel, key: moduleKey(root, abs, ".lua")}
			return nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
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
	// branch-structured with predicate attached so constant-false arms are pruned.
	case "if_statement":
		return []nir.Stmt{c.luaIf(n)}
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

// luaIf lowers an if with its predicate so a constant-false arm is pruned. elseif/else
// bodies are folded into Else as an over-approximation (no per-elseif pruning) — FN-safe.
func (c *luaConv) luaIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	if cond := field(n, "condition"); cond != nil {
		it.Cond = c.expr(cond)
	}
	if cons := field(n, "consequence"); cons != nil {
		it.Then = c.block(cons)
	}
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "else_statement", "elseif_statement":
			for _, b := range namedChildren(ch) {
				if b.Kind() == "block" {
					it.Else = append(it.Else, c.block(b)...)
				}
			}
		}
	}
	return it
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
		// carry the quote-stripped literal text so value-matched mappings can read it
		// through str_args.
		return nir.Const{Loc: L, Value: luaStringValue(c.text(n))}
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
	case "unary_expression":
		op := c.text(field(n, "operator"))
		var operand nir.Expr = nir.Const{Loc: L}
		if k := namedChildren(n); len(k) > 0 {
			operand = c.expr(k[len(k)-1])
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
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

// luaStringValue strips the surrounding delimiters of a Lua string literal so the
// inner text is carried as the Const value (for `val`-matched marks/sinks). Handles
// "..." / '...' short strings and [[...]] / [=[...]=] long-bracket strings.
func luaStringValue(s string) string {
	if len(s) >= 2 {
		if q := s[0]; (q == '"' || q == '\'') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
		if strings.HasPrefix(s, "[[") && strings.HasSuffix(s, "]]") {
			return s[2 : len(s)-2]
		}
	}
	return s
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

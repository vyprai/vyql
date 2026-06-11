package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	pl "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/perl"

	"github.com/vyprai/vyql/extract/nir"
)

// plConv walks a tree-sitter Perl CST into NIR.
type plConv struct {
	src  []byte
	file string
	key  string
}

// ExtractPerl parses .pl/.pm/.cgi files into one NIR Program.
func ExtractPerl(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(pl.Language()))

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
		c := &plConv{src: src, file: rel, key: moduleKey(root, f, ".pl")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *plConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *plConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *plConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *plConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "subroutine_declaration_statement", "named_block_statement":
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Body: c.block(field(n, "body")), Loc: L}}
	case "package_statement":
		return c.block(n)
	case "expression_statement":
		k := namedChildren(n)
		if len(k) == 0 {
			return nil
		}
		return c.exprStmt(k[0])
	case "return_expression", "return_statement":
		k := namedChildren(n)
		if len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[len(k)-1])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement", "unless_statement", "while_statement", "until_statement",
		"for_statement", "foreach_statement", "block_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	if isPlExpr(n.Kind()) {
		return c.exprStmt(n)
	}
	return nil
}

func (c *plConv) exprStmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "assignment_expression":
		left := field(n, "left")
		right := c.expr(field(n, "right"))
		if nm := c.lvalName(left); nm != "" {
			return []nir.Stmt{nir.Assign{Targets: []string{nm}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// lvalName extracts a scalar variable name from an assignment target
// (my $x / $x), returning the bare name without the sigil.
func (c *plConv) lvalName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "variable_declaration":
		for _, ch := range namedChildren(n) {
			if nm := c.lvalName(ch); nm != "" {
				return nm
			}
		}
	case "scalar":
		if v := field(n, "name"); v != nil {
			return c.text(v)
		}
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "varname" {
				return c.text(ch)
			}
		}
	}
	return ""
}

func (c *plConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "elsif", "else", "elsif_clause", "else_clause":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *plConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	switch args.Kind() {
	case "comma_expression", "list_expression", "parenthesized_expression", "arguments":
		var out []nir.Expr
		for _, ch := range namedChildren(args) {
			out = append(out, c.expr(ch))
		}
		return out
	}
	return []nir.Expr{c.expr(args)}
}

func (c *plConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "scalar", "array", "hash", "varname":
		return nir.Name{ID: c.plVarName(n), Loc: L}
	case "number", "boolean":
		return nir.Const{Loc: L}
	case "string_literal", "bareword", "heredoc_content":
		return nir.Const{Loc: L}
	case "interpolated_string_literal", "qq_string", "command_string":
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range namedChildren(m) {
				if k := ch.Kind(); k == "scalar" || k == "array" || k == "hash_element_expression" || k == "scalar_deref_expression" {
					parts = append(parts, c.expr(ch))
				} else {
					walk(ch)
				}
			}
		}
		walk(n)
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "method_call_expression":
		inv := field(n, "invocant")
		method := c.text(field(n, "method"))
		path := c.dotted(inv) + "." + method
		return nir.Call{Callee: nir.Attr{Base: c.expr(inv), Attr: method, Path: path, Loc: L},
			Args: c.callArgs(field(n, "arguments")), Path: path, Method: method, Loc: L}
	case "function_call_expression", "ambiguous_function_call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "func0op_call_expression", "func1op_call_expression":
		// builtins: system LIST / eval BLOCK etc.
		fn := c.text(field(n, "function"))
		if fn == "" {
			if k := namedChildren(n); len(k) > 0 {
				fn = c.text(k[0])
			}
		}
		return nir.Call{Callee: nir.Name{ID: fn, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: fn, Method: fn, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		if op == "." {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "hash_element_expression":
		// $ENV{X} / $hash{key}
		return nir.Index{Base: c.expr(field(n, "variable")), Path: c.dotted(field(n, "variable")), Loc: L}
	case "parenthesized_expression":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "assignment_expression":
		return c.expr(field(n, "right"))
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *plConv) plVarName(n *tree_sitter.Node) string {
	if v := field(n, "name"); v != nil {
		return c.text(v)
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "varname" {
			return c.text(ch)
		}
	}
	t := c.text(n)
	for len(t) > 0 && (t[0] == '$' || t[0] == '@' || t[0] == '%') {
		t = t[1:]
	}
	return t
}

func (c *plConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "scalar", "array", "hash", "varname":
		return c.plVarName(n)
	case "function", "bareword", "method":
		// normalize package separator `::` to `.` so dotted paths are boundary-
		// matchable like every other language (Digest::MD5::md5_hex -> Digest.MD5.md5_hex).
		return strings.ReplaceAll(c.text(n), "::", ".")
	case "method_call_expression":
		return c.dotted(field(n, "invocant")) + "." + strings.ReplaceAll(c.text(field(n, "method")), "::", ".")
	case "function_call_expression", "ambiguous_function_call_expression":
		return c.dotted(field(n, "function"))
	case "hash_element_expression":
		return c.dotted(field(n, "variable"))
	}
	return "?"
}

func isPlExpr(k string) bool {
	switch k {
	case "function_call_expression", "method_call_expression", "assignment_expression",
		"func0op_call_expression", "func1op_call_expression", "ambiguous_function_call_expression":
		return true
	}
	return false
}

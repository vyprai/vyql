package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	pl "github.com/vyprai/vyql/internal/extract/frontend/treesitter/grammars/perl"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// plConv walks a tree-sitter Perl CST into NIR.
type plConv struct {
	nodeCache
	src        []byte
	file       string
	key        string
	childCache map[uintptr][]*tree_sitter.Node
}

func (c *plConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = make(map[uintptr][]*tree_sitter.Node)
	}
	key := uintptr(n.Id())
	if kids, ok := c.childCache[key]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[key] = kids
	return kids
}

// ExtractPerl parses .pl/.pm/.cgi files into one NIR Program.
func ExtractPerl(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(pl.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &plConv{src: src, file: rel, key: moduleKey(root, abs, ".pl")}
			return nir.Module{Key: c.key, File: rel, Body: c.block(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
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
	for _, st := range c.namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *plConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch c.kind(n) {
	case "subroutine_declaration_statement", "named_block_statement":
		return []nir.Stmt{nir.FuncDef{Name: c.text(c.field(n, "name")), Body: c.block(c.field(n, "body")), Loc: L}}
	case "package_statement":
		return c.block(n)
	case "expression_statement":
		k := c.namedChildren(n)
		if len(k) == 0 {
			return nil
		}
		return c.exprStmt(k[0])
	case "return_expression", "return_statement":
		k := c.namedChildren(n)
		if len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[len(k)-1])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured with predicate attached so constant-false arms are pruned.
	// (The block-form `if`/`unless` parses as conditional_statement in this grammar.)
	case "conditional_statement", "if_statement", "unless_statement":
		return []nir.Stmt{c.plIf(n)}
	case "while_statement", "until_statement", "for_statement", "foreach_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "block_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	if isPlExpr(c.kind(n)) {
		return c.exprStmt(n)
	}
	return nil
}

func (c *plConv) exprStmt(n *tree_sitter.Node) []nir.Stmt {
	switch c.kind(n) {
	case "assignment_expression":
		left := c.field(n, "left")
		right := c.expr(c.field(n, "right"))
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
	switch c.kind(n) {
	case "variable_declaration":
		for _, ch := range c.namedChildren(n) {
			if nm := c.lvalName(ch); nm != "" {
				return nm
			}
		}
	case "scalar":
		if v := c.field(n, "name"); v != nil {
			return c.text(v)
		}
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "varname" {
				return c.text(ch)
			}
		}
	}
	return ""
}

// plIf lowers a block-form if/unless with its predicate so a constant-false arm is
// pruned. The predicate is only attached for plain `if` (not `unless`, whose inverted
// sense we don't fold) — keeping the over-approximation FN-safe.
func (c *plConv) plIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	isIf := false
	for i := uint(0); i < n.ChildCount(); i++ {
		if ch := n.Child(i); !ch.IsNamed() && c.text(ch) == "if" {
			isIf = true
		}
	}
	if isIf {
		if cond := c.field(n, "condition"); cond != nil {
			it.Cond = c.expr(cond)
		}
	}
	if blk := c.field(n, "block"); blk != nil {
		it.Then = c.block(blk)
	}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "else", "elsif", "elsif_clause", "else_clause":
			if b := c.field(ch, "block"); b != nil {
				it.Else = append(it.Else, c.block(b)...)
			}
		}
	}
	return it
}

func (c *plConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch c.kind(ch) {
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
	switch c.kind(args) {
	case "comma_expression", "list_expression", "parenthesized_expression", "arguments":
		var out []nir.Expr
		for _, ch := range c.namedChildren(args) {
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
	switch c.kind(n) {
	case "scalar", "array", "hash", "varname", "container_variable":
		return nir.Name{ID: c.plVarName(n), Loc: L}
	case "number", "boolean":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal":
		// plain single/double-quoted literal with no interpolation: carry the
		// quote-stripped source text so val-matched marks can inspect the literal
		// value. q/qq strings handled below.
		return nir.Const{Loc: L, Value: strings.Trim(c.text(n), "\"'")}
	case "bareword", "heredoc_content":
		return nir.Const{Loc: L}
	case "interpolated_string_literal", "qq_string", "command_string":
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range c.namedChildren(m) {
				if k := c.kind(ch); k == "scalar" || k == "array" || k == "hash_element_expression" || k == "scalar_deref_expression" {
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
		// no interpolation: a constant double-quoted/qq string. Carry the quote-
		// stripped text so val-matched marks can inspect the literal value.
		return nir.Const{Loc: L, Value: strings.Trim(c.text(n), "\"'")}
	case "method_call_expression":
		inv := c.field(n, "invocant")
		method := c.text(c.field(n, "method"))
		path := c.dotted(inv) + "." + method
		return nir.Call{Callee: nir.Attr{Base: c.expr(inv), Attr: method, Path: path, Loc: L},
			Args: c.callArgs(c.field(n, "arguments")), Path: path, Method: method, Loc: L}
	case "function_call_expression", "ambiguous_function_call_expression":
		fn := c.field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(c.field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "func0op_call_expression", "func1op_call_expression":
		// builtins: system LIST / eval BLOCK etc.
		fn := c.text(c.field(n, "function"))
		if fn == "" {
			if k := c.namedChildren(n); len(k) > 0 {
				fn = c.text(k[0])
			}
		}
		return nir.Call{Callee: nir.Name{ID: fn, Loc: L}, Args: c.callArgs(c.field(n, "arguments")), Path: fn, Method: fn, Loc: L}
	case "eval_expression":
		return nir.Call{Callee: nir.Name{ID: "eval", Loc: L}, Args: c.childArgs(n), Path: "eval", Method: "eval", Loc: L}
	case "require_expression":
		return nir.Call{Callee: nir.Name{ID: "require", Loc: L}, Args: c.childArgs(n), Path: "require", Method: "require", Loc: L}
	case "binary_expression", "relational_expression", "equality_expression", "comparison_expression":
		op := c.text(c.field(n, "operator"))
		left, right := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
		if op == "." {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "conditional_expression", "ternary_expression":
		// The grammar tags several children `condition`, so take the first named child
		// as the predicate and fall back to positional consequent/alternative.
		kids := c.namedChildren(n)
		t := nir.Ternary{Loc: L}
		if len(kids) > 0 {
			t.Cond = c.expr(kids[0])
		}
		if then := c.field(n, "consequent"); then != nil {
			t.Then = c.expr(then)
		} else if len(kids) > 1 {
			t.Then = c.expr(kids[1])
		}
		if alt := c.field(n, "alternative"); alt != nil {
			t.Else = c.expr(alt)
		} else if len(kids) > 2 {
			t.Else = c.expr(kids[2])
		}
		return t
	case "unary_expression":
		op := c.text(c.field(n, "operator"))
		var operand nir.Expr = nir.Const{Loc: L}
		if k := c.namedChildren(n); len(k) > 0 {
			operand = c.expr(k[len(k)-1])
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "hash_element_expression":
		// $ENV{X} / $hash{key}
		base := c.field(n, "hash")
		if base == nil {
			base = c.field(n, "variable")
		}
		return nir.Index{Base: c.expr(base), Key: c.expr(c.field(n, "key")), Path: c.dotted(base), Loc: L}
	case "parenthesized_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "assignment_expression":
		return c.expr(c.field(n, "right"))
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *plConv) childArgs(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.expr(ch))
	}
	return out
}

func (c *plConv) plVarName(n *tree_sitter.Node) string {
	if v := c.field(n, "name"); v != nil {
		return c.text(v)
	}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "varname" {
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
	switch c.kind(n) {
	case "scalar", "array", "hash", "varname", "container_variable":
		return c.plVarName(n)
	case "function", "bareword", "method":
		// normalize package separator `::` to `.` so dotted paths are boundary-
		// matchable like every other language (Pkg::Thing::call -> Pkg.Thing.call).
		return strings.ReplaceAll(c.text(n), "::", ".")
	case "method_call_expression":
		return c.dotted(c.field(n, "invocant")) + "." + strings.ReplaceAll(c.text(c.field(n, "method")), "::", ".")
	case "function_call_expression", "ambiguous_function_call_expression":
		return c.dotted(c.field(n, "function"))
	case "hash_element_expression":
		return c.dotted(c.field(n, "variable"))
	}
	return "?"
}

func isPlExpr(k string) bool {
	switch k {
	case "function_call_expression", "method_call_expression", "assignment_expression",
		"func0op_call_expression", "func1op_call_expression", "ambiguous_function_call_expression",
		"eval_expression", "require_expression":
		return true
	}
	return false
}

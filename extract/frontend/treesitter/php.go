package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// phConv walks a tree-sitter PHP CST into NIR. PHP functions live in a global
// namespace (module key ""), like Ruby; `echo`/`print`/`include`/`require` are
// modeled as calls so they can be sinks.
type phConv struct {
	src  []byte
	root string
	file string
}

// ExtractPHP parses PHP files into one NIR Program (all modules keyed "").
func ExtractPHP(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsphp.LanguagePHP()))

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
		c := &phConv{src: src, root: root, file: rel}
		mod := nir.Module{Key: "", File: rel, Body: c.block(tree.RootNode())}
		prog.Modules = append(prog.Modules, mod)
		tree.Close()
	}
	return prog, nil
}

func (c *phConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *phConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *phConv) block(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *phConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition", "method_declaration":
		return []nir.Stmt{nir.FuncDef{
			Name:   c.text(field(n, "name")),
			Params: c.params(field(n, "parameters")),
			Body:   c.block(field(n, "body")),
			Loc:    L,
		}}
	case "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.block(field(n, "body")), Loc: L}}
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "echo_statement", "print_intrinsic", "unset_statement":
		// model echo/print as a sink-able call
		var args []nir.Expr
		for _, a := range namedChildren(n) {
			args = append(args, c.expr(a))
		}
		name := "echo"
		if n.Kind() == "print_intrinsic" {
			name = "print"
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: args, Path: name, Method: name, Loc: L}}}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). PHP did not evaluate the condition before → Cond stays nil,
	// byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.phpBranch(field(n, "body")), Else: c.phpElse(n)}}
	case "while_statement", "for_statement", "foreach_statement", "do_statement":
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
	case "assignment_expression", "augmented_assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "variable_name" {
			if inner.Kind() == "augmented_assignment_expression" {
				return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: right, Loc: c.loc(inner)}}
			}
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		// model include/require as a file-inclusion sink call
		kids := namedChildren(inner)
		var args []nir.Expr
		if len(kids) > 0 {
			args = append(args, c.expr(kids[0]))
		}
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: "include", Loc: c.loc(inner)},
			Args: args, Path: "include", Method: "include", Loc: c.loc(inner)}}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// phpBranch flattens one if-branch body: a `{}` compound_statement, or a brace-less
// single statement (PHP allows `if ($c) $x = 1;`).
func (c *phConv) phpBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "compound_statement" {
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
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
		for _, cs := range namedChildren(b) {
			switch cs.Kind() {
			case "case_statement":
				lv := field(cs, "value")
				var stmts []nir.Stmt
				for _, ch := range namedChildren(cs) {
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
				for _, ch := range namedChildren(cs) {
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
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "simple_parameter" || ch.Kind() == "variadic_parameter" || ch.Kind() == "property_promotion_parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else {
				for _, cc := range namedChildren(ch) {
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

func (c *phConv) callArgs(args *tree_sitter.Node) []nir.Expr {
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
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "variable_name" || ch.Kind() == "member_access_expression" ||
				ch.Kind() == "subscript_expression" || ch.Kind() == "dynamic_variable_name" {
				parts = append(parts, c.expr(ch))
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)} // non-interpolated → literal value
	case "member_access_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "name")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		kids := namedChildren(n)
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
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "name" || ch.Kind() == "qualified_name" {
				typ = c.text(ch)
				break
			}
		}
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: c.callArgs(field(n, "arguments")), Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "." || op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_op_expression":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "array_creation_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "array_element_initializer" {
				k := namedChildren(ch)
				switch {
				case len(k) >= 2: // key => value (named-value matching)
					parts = append(parts, nir.Pair{Key: c.keyName(k[0]), Value: c.expr(k[len(k)-1]), Loc: L})
				case len(k) == 1:
					parts = append(parts, c.expr(k[0]))
				}
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// keyName returns the bare name of an array key — a string literal with quotes
// stripped (e.g. 'httponly'), or a constant/name as-is (e.g. CURLOPT_SSL_VERIFYPEER).
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
		return c.text(n)
	case "member_access_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "member_call_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "name"))
	case "scoped_call_expression":
		return c.text(field(n, "scope")) + "." + c.text(field(n, "name"))
	case "function_call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	dart "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/dart"

	"github.com/vyprai/vyql/extract/nir"
)

// dartConv walks a tree-sitter Dart CST into NIR. Dart models method calls as a
// flat selector chain (base · .method · (args)) and splits a function into a
// `function_signature` followed by a sibling `function_body`.
type dartConv struct {
	src  []byte
	file string
	key  string
}

// ExtractDart parses Dart files into one NIR Program (one module per file).
func ExtractDart(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(dart.Language()))

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
		c := &dartConv{src: src, file: rel, key: moduleKey(root, f, ".dart")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *dartConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *dartConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls walks a list, pairing each function/method signature with the
// function_body that follows it.
func (c *dartConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	kids := namedChildren(n)
	for i := 0; i < len(kids); i++ {
		ch := kids[i]
		switch ch.Kind() {
		case "function_signature", "method_signature":
			var body *tree_sitter.Node
			if i+1 < len(kids) && kids[i+1].Kind() == "function_body" {
				body = kids[i+1]
				i++
			}
			out = append(out, c.funcDef(ch, body))
		case "class_definition", "mixin_declaration", "extension_declaration":
			if b := field(ch, "body"); b != nil {
				out = append(out, c.decls(b)...)
			}
		case "function_body", "block":
			out = append(out, c.block(ch)...)
		default:
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

func (c *dartConv) funcDef(sig, body *tree_sitter.Node) nir.Stmt {
	L := c.loc(sig)
	fs := sig
	if sig.Kind() == "method_signature" {
		if inner := lastChildKind(sig, "function_signature"); inner != nil {
			fs = inner
		}
	}
	name := c.text(field(fs, "name"))
	var params []string
	if pl := lastChildKind(fs, "formal_parameter_list"); pl != nil {
		for _, p := range namedChildren(pl) {
			if nm := field(p, "name"); nm != nil {
				params = append(params, c.text(nm))
			} else if id := lastChildKind(p, "identifier"); id != nil {
				params = append(params, c.text(id))
			}
		}
	}
	var bstmts []nir.Stmt
	if body != nil {
		bstmts = c.block(body)
	}
	return nir.FuncDef{Name: name, Params: params, Body: bstmts, Loc: L}
}

func (c *dartConv) block(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if n.Kind() == "function_body" {
		if b := lastChildKind(n, "block"); b != nil {
			return c.block(b)
		}
		// expression-bodied `=> expr`
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, nir.ExprStmt{Value: c.expr(ch)})
		}
		return out
	}
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *dartConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "local_variable_declaration":
		if ivd := lastChildKind(n, "initialized_variable_definition"); ivd != nil {
			name := c.text(field(ivd, "name"))
			// The initializer is a flat `base · selector · …` chain after the name
			// identifier, so fold all value-side siblings (the `value` field only
			// exposes the chain's base).
			if name != "" {
				if v := c.chainAfterName(ivd, name); v != nil {
					return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: v}}
				}
			}
		}
		return nil
	case "expression_statement":
		// a bare `c = v;` parses as expression_statement>assignment_expression; route it
		// through the assignment case so block-nested reassignments are tracked (no FN).
		kids := namedChildren(n)
		if len(kids) == 1 && kids[0].Kind() == "assignment_expression" {
			return c.stmt(kids[0])
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.foldChain(kids)}}
	case "assignment_expression":
		if name := c.assignTargetName(field(n, "left")); name != "" {
			if v := field(n, "right"); v != nil {
				return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "return_statement":
		if k := namedChildren(n); len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured with predicate attached so constant-false arms are pruned.
	case "if_statement":
		return []nir.Stmt{c.dartIf(n)}
	case "for_statement", "while_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.dartSwitch(n)}
	case "block":
		return c.block(n)
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// chainAfterName folds the selector chain that forms an initializer's value when
// it is not exposed via the `value` field (base identifier + selectors).
func (c *dartConv) chainAfterName(ivd *tree_sitter.Node, name string) nir.Expr {
	kids := namedChildren(ivd)
	for i, k := range kids {
		if k.Kind() == "identifier" && c.text(k) == name {
			if i+1 < len(kids) {
				return c.foldChain(kids[i+1:])
			}
		}
	}
	return nil
}

// assignTargetName returns the scalar variable name of an assignment target, or ""
// for member/index targets (a.b = …, arr[i] = …) which aren't tracked as scalars.
func (c *dartConv) assignTargetName(left *tree_sitter.Node) string {
	if left == nil {
		return ""
	}
	switch left.Kind() {
	case "identifier":
		return c.text(left)
	case "assignable_expression":
		if k := namedChildren(left); len(k) == 1 && k[0].Kind() == "identifier" {
			return c.text(k[0])
		}
	}
	return ""
}

// dartBranch lowers an if branch: a block's statements, or a single/else-if statement.
func (c *dartConv) dartBranch(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "block":
		return c.block(n)
	case "if_statement":
		return []nir.Stmt{c.dartIf(n)}
	}
	return c.stmt(n)
}

// dartIf lowers an if with its predicate so a constant-false arm is pruned.
func (c *dartConv) dartIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	for i := uint(0); i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if !ch.IsNamed() {
			continue
		}
		switch n.FieldNameForChild(uint32(i)) {
		case "consequence":
			it.Then = c.dartBranch(ch)
		case "alternative":
			it.Else = c.dartBranch(ch)
		default:
			if it.Cond == nil {
				it.Cond = c.expr(ch)
			}
		}
	}
	return it
}

// dartSwitch lowers a switch to subject+labelled branches so dead arms are pruned.
func (c *dartConv) dartSwitch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n)}
	if cond := field(n, "condition"); cond != nil {
		sw.Subject = c.expr(cond)
	}
	body := field(n, "body")
	if body == nil {
		return sw
	}
	for _, cs := range namedChildren(body) {
		switch cs.Kind() {
		case "switch_statement_case":
			var labs []nir.Expr
			var stmts []nir.Stmt
			for _, ch := range namedChildren(cs) {
				switch ch.Kind() {
				case "case_builtin":
					// the `case` keyword wrapper
				case "constant_pattern":
					labs = append(labs, c.expr(ch))
				case "break_statement", "continue_statement":
					// drop terminators
				default:
					stmts = append(stmts, c.stmt(ch)...)
				}
			}
			sw.Cases = append(sw.Cases, stmts)
			sw.Labels = append(sw.Labels, labs)
		case "switch_statement_default":
			for _, ch := range namedChildren(cs) {
				if k := ch.Kind(); k == "break_statement" || k == "continue_statement" {
					continue
				}
				sw.Default = append(sw.Default, c.stmt(ch)...)
			}
		}
	}
	return sw
}

func (c *dartConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			if ch.Kind() == "block" {
				out = append(out, c.block(ch)...)
			} else {
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

// foldChain folds a flat `base · selector · selector …` sequence into nested
// Attr/Call/Index expressions, tracking the dotted callee path as it goes.
func (c *dartConv) foldChain(nodes []*tree_sitter.Node) nir.Expr {
	if len(nodes) == 0 {
		return nir.Const{Loc: "?:0"}
	}
	cur := c.expr(nodes[0])
	path := c.dotted(nodes[0])
	for _, sel := range nodes[1:] {
		if sel.Kind() != "selector" {
			continue
		}
		inner := firstNamed(sel)
		if inner == nil {
			continue
		}
		L := c.loc(sel)
		switch inner.Kind() {
		case "unconditional_assignable_selector", "conditional_assignable_selector":
			nm := lastChildKind(inner, "identifier")
			name := c.text(nm)
			if path == "?" {
				path = name
			} else {
				path = path + "." + name
			}
			cur = nir.Attr{Base: cur, Attr: name, Path: path, Loc: L}
		case "argument_part":
			cur = nir.Call{Callee: cur, Args: c.args(inner), Path: path, Method: lastSeg(path), Loc: L}
		default: // index selector etc.
			var key nir.Expr
			if inner.Kind() == "index_selector" {
				if k := namedChildren(inner); len(k) > 0 {
					key = c.expr(k[0])
				}
			}
			cur = nir.Index{Base: cur, Key: key, Path: path + "[]", Loc: L}
		}
	}
	return cur
}

// args lowers an argument_part's arguments. Each argument may itself be a chain.
func (c *dartConv) args(argPart *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	a := lastChildKind(argPart, "arguments")
	if a == nil {
		return nil
	}
	for _, arg := range namedChildren(a) {
		if arg.Kind() == "argument" {
			out = append(out, c.foldChain(namedChildren(arg)))
		} else {
			out = append(out, c.expr(arg))
		}
	}
	return out
}

func (c *dartConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "type_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "true", "false", "null":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "decimal_integer_literal", "decimal_floating_point_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "relational_expression", "equality_expression", "multiplicative_expression":
		// Dart wraps the operator in a NAMED *_operator node, so pull it out explicitly
		// rather than assuming it is an unnamed token.
		var ops []nir.Expr
		op := "?"
		for _, ch := range namedChildren(n) {
			switch ch.Kind() {
			case "relational_operator", "equality_operator", "multiplicative_operator":
				op = c.text(ch)
			default:
				ops = append(ops, c.expr(ch))
			}
		}
		if len(ops) == 2 {
			return nir.BinOp{Op: op, Left: ops[0], Right: ops[1], Loc: L}
		}
		return nir.Seq{Parts: ops, Loc: L}
	case "string_literal":
		// interpolated strings ("$x"/"${x}") carry taint via template_substitution.
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "template_substitution" || ch.Kind() == "interpolation" {
				for _, e := range namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "additive_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "additive_operator" {
				continue
			}
			parts = append(parts, c.expr(ch))
		}
		return nir.Format{Parts: parts, Loc: L}
	case "conditional_expression":
		t := nir.Ternary{Loc: L}
		for i := uint(0); i < n.ChildCount(); i++ {
			ch := n.Child(i)
			if !ch.IsNamed() {
				continue
			}
			switch n.FieldNameForChild(uint32(i)) {
			case "consequence":
				t.Then = c.expr(ch)
			case "alternative":
				t.Else = c.expr(ch)
			default:
				if t.Cond == nil {
					t.Cond = c.expr(ch)
				}
			}
		}
		return t
	case "unary_expression":
		var op string
		var operand nir.Expr = nir.Const{Loc: L}
		for _, ch := range namedChildren(n) {
			if k := ch.Kind(); k == "prefix_operator" || k == "postfix_operator" {
				op = c.text(ch)
			} else {
				operand = c.expr(ch)
			}
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "argument":
		return c.foldChain(namedChildren(n))
	case "expression_statement":
		return c.foldChain(namedChildren(n))
	case "parenthesized_expression", "await_expression", "postfix_expression":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "selector_expression", "cascade_section":
		return c.foldChain(namedChildren(n))
	case "list_literal", "set_or_map_literal":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	// node that begins a selector chain (identifier followed by selectors)
	kids := namedChildren(n)
	if len(kids) > 1 && kids[1].Kind() == "selector" {
		return c.foldChain(kids)
	}
	if len(kids) == 1 {
		return c.expr(kids[0])
	}
	var parts []nir.Expr
	for _, ch := range kids {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *dartConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "type_identifier", "this":
		return c.text(n)
	}
	return "?"
}

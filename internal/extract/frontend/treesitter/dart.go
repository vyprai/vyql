package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	dart "github.com/vyprai/vyql/internal/extract/frontend/treesitter/grammars/dart"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// dartConv walks a tree-sitter Dart CST into NIR. Dart models method calls as a
// flat selector chain (base · .method · (args)) and splits a function into a
// `function_signature` followed by a sibling `function_body`.
type dartConv struct {
	nodeCache
	src  []byte
	file string
	key  string
}

// ExtractDart parses Dart files into one NIR Program (one module per file).
func ExtractDart(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(dart.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &dartConv{src: src, file: rel, key: moduleKey(root, abs, ".dart")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
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
	kids := c.namedChildren(n)
	for i := 0; i < len(kids); i++ {
		ch := kids[i]
		switch c.kind(ch) {
		case "function_signature", "method_signature":
			var body *tree_sitter.Node
			if i+1 < len(kids) && c.kind(kids[i+1]) == "function_body" {
				body = kids[i+1]
				i++
			}
			out = append(out, c.funcDef(ch, body))
		case "class_definition", "mixin_declaration", "extension_declaration":
			if b := c.field(ch, "body"); b != nil {
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
	if c.kind(sig) == "method_signature" {
		if inner := lastChildKind(sig, "function_signature"); inner != nil {
			fs = inner
		}
	}
	name := c.text(c.field(fs, "name"))
	var params []string
	paramTypes := map[string]string{}
	if pl := lastChildKind(fs, "formal_parameter_list"); pl != nil {
		for _, p := range c.namedChildren(pl) {
			if nm := c.field(p, "name"); nm != nil {
				name := c.text(nm)
				params = append(params, name)
				putParamType(paramTypes, name, paramTypeFromField(c, p))
			} else if id := lastChildKind(p, "identifier"); id != nil {
				name := c.text(id)
				params = append(params, name)
				putParamType(paramTypes, name, paramTypeFromField(c, p))
			}
		}
	}
	var bstmts []nir.Stmt
	if body != nil {
		bstmts = c.block(body)
	}
	return nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: bstmts, Loc: L}
}

func (c *dartConv) block(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if c.kind(n) == "function_body" {
		if b := lastChildKind(n, "block"); b != nil {
			return c.block(b)
		}
		// expression-bodied `=> expr`
		var out []nir.Stmt
		for _, ch := range c.namedChildren(n) {
			out = append(out, nir.ExprStmt{Value: c.expr(ch)})
		}
		return out
	}
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *dartConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch c.kind(n) {
	case "local_variable_declaration":
		if ivd := lastChildKind(n, "initialized_variable_definition"); ivd != nil {
			name := c.text(c.field(ivd, "name"))
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
		kids := c.namedChildren(n)
		if len(kids) == 1 && c.kind(kids[0]) == "assignment_expression" {
			return c.stmt(kids[0])
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.foldChain(kids)}}
	case "assignment_expression":
		if name := c.assignTargetName(c.field(n, "left")); name != "" {
			if v := c.field(n, "right"); v != nil {
				return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "return_statement":
		if k := c.namedChildren(n); len(k) > 0 {
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
	kids := c.namedChildren(ivd)
	for i, k := range kids {
		if c.kind(k) == "identifier" && c.text(k) == name {
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
	switch c.kind(left) {
	case "identifier":
		return c.text(left)
	case "assignable_expression":
		if k := c.namedChildren(left); len(k) == 1 && c.kind(k[0]) == "identifier" {
			return c.text(k[0])
		}
	}
	return ""
}

func (c *dartConv) assignTargetPath(left *tree_sitter.Node) string {
	if left == nil {
		return ""
	}
	ex := c.foldChain(c.namedChildren(left))
	switch t := ex.(type) {
	case nir.Attr:
		return t.Path
	case nir.Index:
		return t.Path
	case nir.Name:
		if raw := dartAssignTargetText(c.text(left)); strings.Contains(raw, ".") {
			return raw
		}
		return t.ID
	}
	return dartAssignTargetText(c.text(left))
}

func dartAssignTargetText(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "?.", ".")
	raw = strings.ReplaceAll(raw, "!", "")
	return raw
}

// dartBranch lowers an if branch: a block's statements, or a single/else-if statement.
func (c *dartConv) dartBranch(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch c.kind(n) {
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
	if cond := c.field(n, "condition"); cond != nil {
		sw.Subject = c.expr(cond)
	}
	body := c.field(n, "body")
	if body == nil {
		return sw
	}
	for _, cs := range c.namedChildren(body) {
		switch c.kind(cs) {
		case "switch_statement_case":
			var labs []nir.Expr
			var stmts []nir.Stmt
			for _, ch := range c.namedChildren(cs) {
				switch c.kind(ch) {
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
			for _, ch := range c.namedChildren(cs) {
				if k := c.kind(ch); k == "break_statement" || k == "continue_statement" {
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
			if c.kind(ch) == "block" {
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
		if c.kind(sel) != "selector" {
			continue
		}
		inner := firstNamed(sel)
		if inner == nil {
			continue
		}
		L := c.loc(sel)
		switch c.kind(inner) {
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
			if c.kind(inner) == "index_selector" {
				if k := c.namedChildren(inner); len(k) > 0 {
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
	for _, arg := range c.namedChildren(a) {
		if c.kind(arg) == "argument" {
			out = append(out, c.foldChain(c.namedChildren(arg)))
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
	switch c.kind(n) {
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
		for _, ch := range c.namedChildren(n) {
			switch c.kind(ch) {
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
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "template_substitution" || c.kind(ch) == "interpolation" {
				for _, e := range c.namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		// plain literal: the content is an unnamed token, so carry the source text with
		// surrounding quotes (and optional `r` raw prefix) stripped for val-matched marks.
		return nir.Const{Loc: L, Value: strings.Trim(strings.TrimPrefix(c.text(n), "r"), "\"'")}
	case "additive_expression":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "additive_operator" {
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
		for _, ch := range c.namedChildren(n) {
			if k := c.kind(ch); k == "prefix_operator" || k == "postfix_operator" {
				op = c.text(ch)
			} else {
				operand = c.expr(ch)
			}
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "assignment_expression":
		path := c.assignTargetPath(c.field(n, "left"))
		right := c.expr(c.field(n, "right"))
		if path != "" {
			return nir.Call{Callee: nir.Name{ID: path, Loc: L}, Args: []nir.Expr{right}, Path: path, Method: lastSeg(path), Loc: L}
		}
		return right
	case "new_expression", "const_object_expression":
		// `new File(p)` / `const File(p)` — model as a constructor call so type/arg
		// sinks and marks match (e.g. new File(userPath)). The grammar nests the type
		// (type_identifier, possibly with type_arguments) plus an `arguments` node
		// directly, NOT a selector/argument_part chain.
		path := "?"
		var args []nir.Expr
		for _, ch := range c.namedChildren(n) {
			switch c.kind(ch) {
			case "type_identifier", "identifier", "scoped_identifier":
				if path == "?" {
					path = c.text(ch)
				}
			case "arguments":
				for _, arg := range c.namedChildren(ch) {
					if c.kind(arg) == "argument" {
						args = append(args, c.foldChain(c.namedChildren(arg)))
					} else {
						args = append(args, c.expr(arg))
					}
				}
			}
		}
		return nir.Call{Callee: nir.Name{ID: path, Loc: L}, Args: args, Path: path, Method: lastSeg(path), Loc: L}
	case "argument":
		return c.foldChain(c.namedChildren(n))
	case "expression_statement":
		return c.foldChain(c.namedChildren(n))
	case "parenthesized_expression", "await_expression", "postfix_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "selector_expression", "cascade_section":
		return c.foldChain(c.namedChildren(n))
	case "list_literal", "set_or_map_literal":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	// node that begins a selector chain (identifier followed by selectors)
	kids := c.namedChildren(n)
	if len(kids) > 1 && c.kind(kids[1]) == "selector" {
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
	switch c.kind(n) {
	case "identifier", "type_identifier", "this":
		return c.text(n)
	}
	return "?"
}

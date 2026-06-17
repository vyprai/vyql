package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	sol "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/solidity"

	"github.com/vyprai/vyql/extract/nir"
)

// solConv walks a tree-sitter Solidity CST into NIR. Solidity wraps operands in
// `expression` nodes (peeled by solUnwrap). For a low-level call
// (to.call/to.transfer) the receiver address is modeled as arg0.
type solConv struct {
	src  []byte
	file string
	key  string
}

// ExtractSolidity parses .sol files into one NIR Program.
func ExtractSolidity(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(sol.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &solConv{src: src, file: rel, key: moduleKey(root, abs, ".sol")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *solConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *solConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *solConv) unwrap(n *tree_sitter.Node) *tree_sitter.Node {
	for n != nil && n.Kind() == "expression" {
		k := namedChildren(n)
		if len(k) != 1 {
			break
		}
		n = k[0]
	}
	return n
}

func (c *solConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *solConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "contract_declaration", "interface_declaration", "library_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(c.solBody(n)), Loc: L}}
	case "function_definition", "modifier_definition", "constructor_definition", "fallback_receive_definition":
		params := c.params(n)
		body := c.block(c.solBody(n))
		return []nir.Stmt{nir.FuncDef{
			Name:         c.text(field(n, "name")),
			Params:       params,
			ParamTypes:   c.paramTypes(n),
			ParamEntries: c.solParamEntries(n, params),
			Body:         body,
			Loc:          L,
		}}
	case "statement":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	case "expression_statement":
		k := namedChildren(n)
		if len(k) == 0 {
			return nil
		}
		return c.exprStmt(c.unwrap(k[0]))
	case "variable_declaration_statement":
		return c.varDeclStmt(n)
	case "return_statement":
		k := namedChildren(n)
		if len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[len(k)-1])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured with predicate attached so constant-false arms are pruned.
	case "if_statement":
		return []nir.Stmt{c.solIf(n)}
	case "for_statement", "while_statement", "do_while_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "block_statement", "unchecked_block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *solConv) varDeclStmt(n *tree_sitter.Node) []nir.Stmt {
	var name string
	var val *tree_sitter.Node
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "variable_declaration":
			name = c.text(field(ch, "name"))
		case "expression":
			val = ch
		}
	}
	if name != "" && val != nil {
		return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(val)}}
	}
	return nil
}

func (c *solConv) exprStmt(n *tree_sitter.Node) []nir.Stmt {
	if n != nil && (n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression") {
		left := c.unwrap(field(n, "left"))
		right := c.expr(field(n, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// a member / index target (balances[x] = …, self.owner = …) is a STORAGE write —
		// emit a markable state_write node (B2 reentrancy: external_call before state_write).
		L := c.loc(n)
		sw := nir.Call{Callee: nir.Name{ID: "state_write", Loc: L}, Path: "state_write", Method: "state_write", Loc: L}
		return []nir.Stmt{nir.ExprStmt{Value: right}, nir.ExprStmt{Value: sw}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *solConv) solBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "contract_body", "interface_body", "library_body", "function_body":
			return ch
		}
	}
	return nil
}

func (c *solConv) block(body *tree_sitter.Node) []nir.Stmt {
	if body == nil {
		return nil
	}
	var out []nir.Stmt
	for _, ch := range namedChildren(body) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

// solIf lowers an if with its predicate so a constant-false arm is pruned. Solidity
// labels both the consequence and alternative blocks with the field name "body", so
// the first body-fielded child is the then-branch and the second is the else-branch.
func (c *solConv) solIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	if cond := field(n, "condition"); cond != nil {
		it.Cond = c.expr(cond)
	}
	afterElse := false
	for i := uint(0); i < n.ChildCount(); i++ {
		ch := n.Child(i)
		if !ch.IsNamed() {
			if c.text(ch) == "else" {
				afterElse = true
			}
			continue
		}
		switch ch.Kind() {
		case "block_statement", "unchecked_block", "if_statement", "statement",
			"expression_statement", "variable_declaration_statement", "return_statement":
			if afterElse {
				it.Else = append(it.Else, c.solStmts(ch)...)
			} else if it.Then == nil {
				it.Then = c.solStmts(ch)
			}
		}
	}
	return it
}

// solStmts lowers a branch body: a block's contained statements, or a single
// (possibly brace-less or else-if) statement.
func (c *solConv) solStmts(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "block_statement", "unchecked_block":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	}
	return c.stmt(n)
}

func (c *solConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "function_body", "block_statement":
				out = append(out, c.block(ch)...)
			case "statement":
				out = append(out, c.stmt(ch)...)
			case "if_statement", "else", "for_statement", "while_statement":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *solConv) params(n *tree_sitter.Node) []string {
	var out []string
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *solConv) paramTypes(n *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *solConv) isPublicFn(n *tree_sitter.Node) bool {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "visibility" {
			v := c.text(ch)
			return v == "public" || v == "external"
		}
	}
	// fallback/receive and constructors have no visibility child here; functions
	// with no explicit visibility default to public in old Solidity.
	k := n.Kind()
	return k == "fallback_receive_definition" || k == "constructor_definition" || k == "function_definition"
}

func (c *solConv) solVisibility(n *tree_sitter.Node) string {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "visibility" {
			return c.text(ch)
		}
	}
	if c.isPublicFn(n) {
		return "implicit_public"
	}
	return ""
}

func (c *solConv) solParamEntries(fn *tree_sitter.Node, params []string) []nir.ParamEntry {
	vis := c.solVisibility(fn)
	if vis == "" {
		return nil
	}
	var out []nir.ParamEntry
	for i, p := range params {
		out = append(out, nir.ParamEntry{Param: p, Tokens: []string{
			"function_kind:" + fn.Kind(),
			"function_visibility:" + vis,
			"param_name:" + p,
			"param_index:" + itoa(i),
		}})
	}
	return out
}

func (c *solConv) expr(n *tree_sitter.Node) nir.Expr {
	n = c.unwrap(n)
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this":
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "hex_string_literal":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "number_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "string":
		return nir.Const{Loc: L}
	case "member_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "property")), Path: c.dotted(n), Loc: L}
	case "array_access", "slice_access":
		return nir.Index{Base: c.expr(field(n, "base")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "base")), Loc: L}
	case "call_expression":
		return c.call(n)
	case "struct_expression":
		// `to.call{value: x}` — the call options; the real callee is its `type`.
		return c.expr(field(n, "type"))
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "ternary_expression":
		if k := namedChildren(n); len(k) == 3 {
			return nir.Ternary{Cond: c.expr(k[0]), Then: c.expr(k[1]), Else: c.expr(k[2]), Loc: L}
		}
	case "unary_expression":
		arg := field(n, "argument")
		if arg == nil {
			if k := namedChildren(n); len(k) > 0 {
				arg = k[len(k)-1]
			}
		}
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(arg), Loc: L}
	case "parenthesized_expression", "type_cast_expression":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "tuple_expression", "inline_array_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
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

// call models a call_expression. For a member call (to.call(...), to.transfer(x))
// the RECEIVER is prepended as arg0 so a sink can flag a tainted target address.
func (c *solConv) call(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	callee := c.unwrap(field(n, "function"))
	if callee != nil && callee.Kind() == "struct_expression" {
		callee = c.unwrap(field(callee, "type"))
	}
	path := c.dotted(callee)
	method := lastSeg(path)

	var args []nir.Expr
	if callee != nil && callee.Kind() == "member_expression" {
		args = append(args, c.expr(field(callee, "object"))) // receiver as arg0
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "call_argument" {
			k := namedChildren(ch)
			if len(k) > 0 {
				args = append(args, c.expr(k[len(k)-1]))
			}
		}
	}
	return nir.Call{Callee: c.expr(callee), Args: args, Path: path, Method: method, Loc: L}
}

func (c *solConv) dotted(n *tree_sitter.Node) string {
	n = c.unwrap(n)
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "primitive_type":
		return c.text(n)
	case "member_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "property"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "struct_expression":
		return c.dotted(field(n, "type"))
	case "array_access":
		return c.dotted(field(n, "base")) + "[]"
	}
	if t := c.text(n); strings.Contains(t, ".") {
		return t
	}
	return "?"
}

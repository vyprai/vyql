package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	sw "github.com/vyprai/vyql/internal/extract/frontend/treesitter/grammars/swift"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// swConv walks a tree-sitter Swift CST into NIR.
type swConv struct {
	src        []byte
	file       string
	key        string
	childCache map[uintptr][]*tree_sitter.Node
}

// ExtractSwift parses .swift files into one NIR Program (one module per file).
func ExtractSwift(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(sw.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &swConv{src: src, file: rel, key: moduleKey(root, abs, ".swift")}
			body := append(c.swModuleContext(tree.RootNode()), c.decls(tree.RootNode())...)
			return nir.Module{Key: c.key, File: rel, Body: body}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *swConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *swConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *swConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = map[uintptr][]*tree_sitter.Node{}
	}
	id := n.Id()
	if kids, ok := c.childCache[id]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[id] = kids
	return kids
}

func (c *swConv) swModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	loc := c.file + ":1"
	text := c.text(root)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=swift"},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(text), "")},
	}
	for _, tok := range c.swStructuredContextTokens(root) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	for _, tok := range c.swSemanticModuleTokens(text) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.module.context", Loc: loc},
		Args:   args,
		Path:   "analysis.module.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *swConv) swSemanticModuleTokens(text string) []string {
	var out []string
	add := func(tok string) {
		for _, existing := range out {
			if existing == tok {
				return
			}
		}
		out = append(out, tok)
	}
	if swHasClearancePolicyBeforeAdapterStart(text) {
		add("startup_order:clearance_policy_before_adapter_start")
	}
	return out
}

func swHasClearancePolicyBeforeAdapterStart(text string) bool {
	lastApply := -1
	for _, method := range []string{"applyPolicyToFilter(", "applyAllowlistToFilter(", "applyJailRulesToFilter("} {
		idx := strings.Index(text, method)
		if idx < 0 {
			return false
		}
		lastApply = max(lastApply, idx)
	}
	return strings.Contains(text[lastApply:], ".start(initialRules:")
}

func (c *swConv) swStructuredContextTokens(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 2048 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 2048 {
			return
		}
		switch n.Kind() {
		case "function_declaration", "init_declaration":
			if name := c.text(field(n, "name")); name != "" {
				add("function_name:" + name)
			}
			for _, p := range c.paramPairs(n) {
				if p[0] != "" && p[0] != "_" {
					add("param_label:" + p[0])
				}
				if p[1] != "" && p[1] != "_" {
					add("param_name:" + p[1])
				}
			}
			for _, typ := range c.paramTypes(n) {
				if typ != "" {
					add("param_type:" + typ)
				}
			}
		case "call_expression", "navigation_expression":
			if path := c.dotted(n); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
				add("selector:" + path)
			}
		case "simple_identifier":
			if ident := swContextValue(c.text(n)); ident != "" {
				add("identifier:" + ident)
			}
		case "line_string_literal", "multi_line_string_literal", "raw_string_literal", "integer_literal", "real_literal", "boolean_literal", "nil_literal":
			if lit := swContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func swContextValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	s = strings.Join(strings.Fields(s), "")
	if len(s) > 160 {
		return ""
	}
	return s
}

func (c *swConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *swConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "class_declaration", "protocol_declaration", "extension_declaration", "enum_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(c.swBody(n)), Loc: L}}
	case "function_declaration", "init_declaration", "deinit_declaration":
		name := c.text(field(n, "name"))
		pairs := c.paramPairs(n)
		params := make([]string, 0, len(pairs))
		for _, p := range pairs {
			params = append(params, p[1])
		}
		paramTypes := c.paramTypes(n)
		body := c.block(c.swBody(n))
		// Platform callback entry points seeded as external input:
		// application(_:open:) URL param and userContentController(_:didReceive:) message.
		var seedParam string
		switch name {
		case "application":
			seedParam = labeledInternal(pairs, "open")
		case "userContentController":
			seedParam = labeledInternal(pairs, "didReceive")
		}
		if seedParam != "" {
			seed := nir.Assign{Targets: []string{seedParam},
				Value: nir.Call{Callee: nir.Name{ID: "url_scheme_input", Loc: L}, Path: "url_scheme_input", Method: "url_scheme_input", Loc: L}}
			body = append([]nir.Stmt{seed}, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L}}
	case "property_declaration":
		v := field(n, "value")
		if v == nil {
			return nil
		}
		name := c.bindingName(field(n, "name"))
		if name != "" {
			out := []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
			return append(out, c.trailingLambdaStmts(v)...)
		}
		// `let _ = expr` binds no name, but the call still matters for sinks/marks.
		out := []nir.Stmt{nir.ExprStmt{Value: c.expr(v)}}
		return append(out, c.trailingLambdaStmts(v)...)
	case "assignment":
		target := field(n, "target")
		resultNode := field(n, "result")
		result := c.expr(resultNode)
		if nm := c.assignTargetName(target); nm != "" {
			out := []nir.Stmt{nir.Assign{Targets: []string{nm}, Value: result}}
			return append(out, c.trailingLambdaStmts(resultNode)...)
		}
		out := []nir.Stmt{nir.ExprStmt{Value: result}}
		return append(out, c.trailingLambdaStmts(resultNode)...)
	case "call_expression", "navigation_expression":
		out := []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
		return append(out, c.trailingLambdaStmts(n)...)
	case "control_transfer_statement":
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() != "throw_keyword" {
				return []nir.Stmt{nir.Return{Value: c.expr(ch)}}
			}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (Swift did not evaluate the predicate) -> byte-identical.
	case "if_statement", "guard_statement":
		// Swift if: condition(s) then a body block, optionally `else` + block/if. Split the
		// first body from the else so the join-merge keeps the live branch and a constant
		// condition prunes.
		var cond nir.Expr
		var then, els []nir.Stmt
		seenBody := false
		for _, ch := range c.namedChildren(n) {
			switch ch.Kind() {
			case "statements":
				if !seenBody {
					then = c.decls(ch)
					seenBody = true
				} else {
					els = c.decls(ch)
				}
			case "else":
				els = c.collectBlocks(ch)
			case "if_statement":
				els = c.stmt(ch) // else-if
			default:
				if cond == nil && n.Kind() == "if_statement" {
					cond = c.expr(ch)
				}
			}
		}
		return []nir.Stmt{nir.If{Cond: cond, Then: then, Else: els}}
	case "for_statement", "while_statement", "repeat_while_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "do_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.swSwitch(n)}
	}
	return nil
}

func (c *swConv) swBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range c.namedChildren(n) {
		switch ch.Kind() {
		case "function_body", "class_body", "enum_class_body", "protocol_body", "statements":
			return ch
		}
	}
	return nil
}

func (c *swConv) block(body *tree_sitter.Node) []nir.Stmt {
	if body == nil {
		return nil
	}
	var out []nir.Stmt
	for _, ch := range c.namedChildren(body) {
		if ch.Kind() == "statements" {
			out = append(out, c.decls(ch)...)
		} else {
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

// swSwitch lowers a switch to subject+labelled branches so a constant subject prunes
// the non-matching arms (and so arm bodies are no longer flattened — which previously
// let a later arm's clean reassignment mask a live arm's taint).
func (c *swConv) swSwitch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n)}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "switch_entry" {
			if sw.Subject == nil {
				sw.Subject = c.expr(ch) // the scrutinee precedes the entries
			}
			continue
		}
		isDefault := false
		var labs []nir.Expr
		var stmts []nir.Stmt
		for _, e := range c.namedChildren(ch) {
			switch e.Kind() {
			case "default_keyword":
				isDefault = true
			case "switch_pattern":
				lbl := e // descend to the innermost single child (the literal)
				for {
					k := c.namedChildren(lbl)
					if len(k) != 1 {
						break
					}
					lbl = k[0]
				}
				labs = append(labs, c.expr(lbl))
			case "statements":
				stmts = append(stmts, c.decls(e)...)
			}
		}
		if isDefault || len(labs) == 0 {
			sw.Default = append(sw.Default, stmts...)
		} else {
			sw.Cases = append(sw.Cases, stmts)
			sw.Labels = append(sw.Labels, labs)
		}
	}
	return sw
}

// swOp returns the operator symbol of a binary node (first non-named child).
func (c *swConv) swOp(n *tree_sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		if ch := n.Child(i); !ch.IsNamed() {
			return c.text(ch)
		}
	}
	return "?"
}

func (c *swConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statements", "function_body":
				out = append(out, c.decls(ch)...)
			case "if_statement", "else", "switch_entry", "catch_block", "lambda_literal":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

// trailingLambdaStmts lowers synchronously executed Swift closure bodies that are
// attached to a call (`foo { ... }` or `foo({ ... })`). Without this, calls inside
// buffer/read/write helper closures disappear from the graph.
func (c *swConv) trailingLambdaStmts(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "lambda_literal":
				out = append(out, c.collectBlocks(ch)...)
			case "call_suffix", "value_arguments", "_fn_call_lambda_arguments", "value_argument":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

// paramPairs returns (external-label, internal-name) for each parameter. A swift
// parameter `open url: URL` has external label "open" and internal name "url" — the
// internal name is what the body binds to. `name: T` has both equal; `_ x:` → ("_","x").
func (c *swConv) paramPairs(n *tree_sitter.Node) [][2]string {
	var out [][2]string
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "parameter" {
			continue
		}
		var ids []string
		for _, id := range c.namedChildren(ch) {
			if id.Kind() == "simple_identifier" {
				ids = append(ids, c.text(id))
			}
		}
		if len(ids) == 0 {
			continue
		}
		out = append(out, [2]string{ids[0], ids[len(ids)-1]})
	}
	return out
}

func (c *swConv) paramTypes(n *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	for _, ch := range c.namedChildren(n) {
		if ch.Kind() != "parameter" {
			continue
		}
		var ids []string
		for _, id := range c.namedChildren(ch) {
			if id.Kind() == "simple_identifier" {
				ids = append(ids, c.text(id))
			}
		}
		if len(ids) > 0 {
			putParamType(out, ids[len(ids)-1], paramTypeFromField(c, ch))
		}
	}
	return out
}

// labeledInternal returns the internal name of the parameter with the given
// external label, or "" if none.
func labeledInternal(pairs [][2]string, label string) string {
	for _, p := range pairs {
		if p[0] == label {
			return p[1]
		}
	}
	return ""
}

func (c *swConv) bindingName(pat *tree_sitter.Node) string {
	if pat == nil {
		return ""
	}
	if pat.Kind() == "simple_identifier" {
		return c.text(pat)
	}
	for _, ch := range c.namedChildren(pat) {
		if ch.Kind() == "simple_identifier" || ch.Kind() == "bound_identifier" {
			return c.text(ch)
		}
		if nm := c.bindingName(ch); nm != "" {
			return nm
		}
	}
	return ""
}

func (c *swConv) assignTargetName(t *tree_sitter.Node) string {
	if t == nil {
		return ""
	}
	if t.Kind() == "simple_identifier" {
		return c.text(t)
	}
	if t.Kind() == "directly_assignable_expression" {
		k := c.namedChildren(t)
		if len(k) == 1 && k[0].Kind() == "simple_identifier" {
			return c.text(k[0])
		}
	}
	return ""
}

func (c *swConv) callArgs(suffix *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	var va *tree_sitter.Node
	for _, ch := range c.namedChildren(suffix) {
		if ch.Kind() == "value_arguments" {
			va = ch
		}
	}
	if va == nil {
		return nil
	}
	for _, a := range c.namedChildren(va) {
		if a.Kind() == "value_argument" {
			if v := field(a, "value"); v != nil {
				out = append(out, c.expr(v))
			} else if k := c.namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
		}
	}
	return out
}

func (c *swConv) callArgLabels(suffix *tree_sitter.Node) []string {
	var out []string
	var va *tree_sitter.Node
	for _, ch := range c.namedChildren(suffix) {
		if ch.Kind() == "value_arguments" {
			va = ch
		}
	}
	if va == nil {
		return nil
	}
	for _, a := range c.namedChildren(va) {
		if a.Kind() != "value_argument" {
			continue
		}
		for _, ch := range c.namedChildren(a) {
			if ch.Kind() != "value_argument_label" {
				continue
			}
			if ids := c.namedChildren(ch); len(ids) > 0 {
				out = append(out, c.text(ids[0]))
			}
			break
		}
	}
	return out
}

func (c *swConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "simple_identifier", "self_expression", "super_expression":
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "nil_literal":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer_literal", "real_literal", "hex_literal", "oct_literal", "bin_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "line_string_literal", "multi_line_string_literal", "raw_string_literal":
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range c.namedChildren(m) {
				if ch.Kind() == "interpolated_expression" || ch.Kind() == "interpolation" {
					if v := field(ch, "value"); v != nil {
						parts = append(parts, c.expr(v))
					} else {
						for _, e := range c.namedChildren(ch) {
							parts = append(parts, c.expr(e))
						}
					}
				} else {
					walk(ch)
				}
			}
		}
		walk(n)
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "navigation_expression":
		tgt := field(n, "target")
		suf := field(n, "suffix")
		return nir.Attr{Base: c.expr(tgt), Attr: c.navSuf(suf), Path: c.dotted(n), Loc: L}
	case "call_expression":
		callee := c.swCallee(n)
		path := c.dotted(callee)
		method := lastSeg(path)
		var args []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "call_suffix" {
				args = c.callArgs(ch)
				if labels := c.callArgLabels(ch); len(labels) > 0 {
					path += "." + strings.Join(labels, ".")
				}
			}
		}
		return nir.Call{Callee: c.expr(callee), Args: args, Path: path, Method: method, Loc: L}
	case "additive_expression":
		l, r := c.expr(field(n, "lhs")), c.expr(field(n, "rhs"))
		op := c.swOp(n)
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{l, r}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: l, Right: r, Loc: L}
	case "multiplicative_expression", "comparison_expression", "equality_expression",
		"conjunction_expression", "disjunction_expression":
		return nir.BinOp{Op: c.swOp(n), Left: c.expr(field(n, "lhs")), Right: c.expr(field(n, "rhs")), Loc: L}
	case "prefix_expression":
		// `-x`, `!x` — operator is the leading token, operand the trailing child.
		var operand nir.Expr = nir.Const{Loc: L}
		if k := c.namedChildren(n); len(k) > 0 {
			operand = c.expr(k[len(k)-1])
		}
		return nir.Unary{Op: c.swOp(n), Operand: operand, Loc: L}
	case "array_literal":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "subscript_expression":
		k := c.namedChildren(n)
		if len(k) > 0 {
			var key nir.Expr
			if len(k) > 1 {
				key = c.expr(k[1])
			}
			return nir.Index{Base: c.expr(k[0]), Key: key, Path: c.dotted(k[0]), Loc: L}
		}
	case "postfix_expression":
		// force-unwrap / optional-chaining: operand is the FIRST child, the
		// trailing operator (e.g. `bang`) is a separate named node — pass the operand.
		if k := c.namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[0])}
		}
	case "try_expression", "await_expression", "as_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "ternary_expression":
		k := c.namedChildren(n)
		if len(k) >= 3 {
			return nir.Ternary{Cond: c.expr(k[0]), Then: c.expr(k[1]), Else: c.expr(k[2]), Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{}, Loc: L}
	case "if_statement":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
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

// swCallee returns the function part of a call expression: its first named child,
// unless that child is already the argument list, in which case there is no
// callee to return.
func (c *swConv) swCallee(n *tree_sitter.Node) *tree_sitter.Node {
	kids := c.namedChildren(n)
	if len(kids) == 0 || kids[0].Kind() == "call_suffix" {
		return nil
	}
	return kids[0]
}

func (c *swConv) navSuf(suf *tree_sitter.Node) string {
	if suf == nil {
		return ""
	}
	if s := field(suf, "suffix"); s != nil {
		return c.text(s)
	}
	for _, ch := range c.namedChildren(suf) {
		if ch.Kind() == "simple_identifier" {
			return c.text(ch)
		}
	}
	return c.text(suf)
}

func (c *swConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "simple_identifier", "self_expression", "type_identifier":
		return c.text(n)
	case "navigation_expression":
		return c.dotted(field(n, "target")) + "." + c.navSuf(field(n, "suffix"))
	case "call_expression":
		return c.dotted(c.swCallee(n))
	case "subscript_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return c.dotted(k[0]) + "[]"
		}
	}
	return "?"
}

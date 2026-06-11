package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	sw "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/swift"

	"github.com/vyprai/vyql/extract/nir"
)

// swConv walks a tree-sitter Swift CST into NIR.
type swConv struct {
	src  []byte
	file string
	key  string
}

// ExtractSwift parses .swift files into one NIR Program (one module per file).
func ExtractSwift(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(sw.Language()))

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
		c := &swConv{src: src, file: rel, key: moduleKey(root, f, ".swift")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
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

func (c *swConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
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
		body := c.block(c.swBody(n))
		// iOS attacker-controlled entry points seeded as URL-scheme input:
		//   application(_:open:) — deep-link URL param `open url:`
		//   userContentController(_:didReceive:) — WKScriptMessage param (.body is web JS)
		var seedParam string
		if name == "application" {
			seedParam = labeledInternal(pairs, "open")
		} else if name == "userContentController" {
			seedParam = labeledInternal(pairs, "didReceive")
		}
		if seedParam != "" {
			seed := nir.Assign{Targets: []string{seedParam},
				Value: nir.Call{Callee: nir.Name{ID: "url_scheme_input", Loc: L}, Path: "url_scheme_input", Method: "url_scheme_input", Loc: L}}
			body = append([]nir.Stmt{seed}, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, Body: body, Loc: L}}
	case "property_declaration":
		v := field(n, "value")
		if v == nil {
			return nil
		}
		name := c.bindingName(field(n, "name"))
		if name != "" {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
		}
		// `let _ = expr` binds no name, but the call still matters for sinks/marks.
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(v)}}
	case "assignment":
		target := field(n, "target")
		result := c.expr(field(n, "result"))
		if nm := c.assignTargetName(target); nm != "" {
			return []nir.Stmt{nir.Assign{Targets: []string{nm}, Value: result}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: result}}
	case "call_expression", "navigation_expression":
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "control_transfer_statement":
		for _, ch := range namedChildren(n) {
			if ch.Kind() != "throw_keyword" {
				return []nir.Stmt{nir.Return{Value: c.expr(ch)}}
			}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement", "guard_statement", "for_statement", "while_statement",
		"repeat_while_statement", "do_statement", "switch_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *swConv) swBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
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
	for _, ch := range namedChildren(body) {
		if ch.Kind() == "statements" {
			out = append(out, c.decls(ch)...)
		} else {
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

func (c *swConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statements", "function_body":
				out = append(out, c.decls(ch)...)
			case "if_statement", "else", "switch_entry", "catch_block":
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
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "parameter" {
			continue
		}
		var ids []string
		for _, id := range namedChildren(ch) {
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

func (c *swConv) params(n *tree_sitter.Node) []string {
	pairs := c.paramPairs(n)
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p[1]) // internal name (the body binding)
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
	for _, ch := range namedChildren(pat) {
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
		k := namedChildren(t)
		if len(k) == 1 && k[0].Kind() == "simple_identifier" {
			return c.text(k[0])
		}
	}
	return ""
}

func (c *swConv) callArgs(suffix *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	var va *tree_sitter.Node
	for _, ch := range namedChildren(suffix) {
		if ch.Kind() == "value_arguments" {
			va = ch
		}
	}
	if va == nil {
		return nil
	}
	for _, a := range namedChildren(va) {
		if a.Kind() == "value_argument" {
			if v := field(a, "value"); v != nil {
				out = append(out, c.expr(v))
			} else if k := namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
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
	case "integer_literal", "real_literal", "boolean_literal", "nil_literal", "hex_literal", "oct_literal", "bin_literal":
		return nir.Const{Loc: L}
	case "line_string_literal", "multi_line_string_literal", "raw_string_literal":
		var parts []nir.Expr
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			for _, ch := range namedChildren(m) {
				if ch.Kind() == "interpolated_expression" || ch.Kind() == "interpolation" {
					if v := field(ch, "value"); v != nil {
						parts = append(parts, c.expr(v))
					} else {
						for _, e := range namedChildren(ch) {
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
		return nir.Const{Loc: L}
	case "navigation_expression":
		tgt := field(n, "target")
		suf := field(n, "suffix")
		return nir.Attr{Base: c.expr(tgt), Attr: c.navSuf(suf), Path: c.dotted(n), Loc: L}
	case "call_expression":
		callee := c.swCallee(n)
		path := c.dotted(callee)
		var args []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "call_suffix" {
				args = c.callArgs(ch)
			}
		}
		return nir.Call{Callee: c.expr(callee), Args: args, Path: path, Method: lastSeg(path), Loc: L}
	case "additive_expression", "multiplicative_expression":
		l, r := field(n, "lhs"), field(n, "rhs")
		return nir.Format{Parts: []nir.Expr{c.expr(l), c.expr(r)}, Loc: L}
	case "array_literal":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "subscript_expression":
		k := namedChildren(n)
		if len(k) > 0 {
			return nir.Index{Base: c.expr(k[0]), Path: c.dotted(k[0]), Loc: L}
		}
	case "postfix_expression":
		// force-unwrap / optional-chaining: operand is the FIRST child, the
		// trailing operator (e.g. `bang`) is a separate named node — pass the operand.
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[0])}
		}
	case "try_expression", "await_expression", "prefix_expression", "as_expression":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "ternary_expression", "if_statement":
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
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *swConv) swCallee(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "call_suffix" {
			break
		}
		return ch
	}
	return nil
}

func (c *swConv) navSuf(suf *tree_sitter.Node) string {
	if suf == nil {
		return ""
	}
	if s := field(suf, "suffix"); s != nil {
		return c.text(s)
	}
	for _, ch := range namedChildren(suf) {
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
		if k := namedChildren(n); len(k) > 0 {
			return c.dotted(k[0]) + "[]"
		}
	}
	return "?"
}

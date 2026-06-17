package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// rsConv walks a tree-sitter Rust CST into NIR.
type rsConv struct {
	src  []byte
	file string
	key  string
}

// rsFormatMacros build a string from their arguments (taint-propagating).
var rsFormatMacros = map[string]bool{
	"format": true, "println": true, "print": true, "eprintln": true,
	"eprint": true, "write": true, "writeln": true, "panic": true, "format_args": true,
}

// rsHandlerAttrs mark a function as a web request handler (actix/rocket/axum).
var rsHandlerAttrs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "route": true, "handler": true,
}

// ExtractRust parses Rust files into one NIR Program (one module per file).
func ExtractRust(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsrust.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &rsConv{src: src, file: rel, key: moduleKey(root, abs, ".rs")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *rsConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *rsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls walks a list, tracking a preceding attribute_item so request-handler
// functions can seed their params as sources.
func (c *rsConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	handler := false
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "attribute_item" {
			handler = handler || c.isHandlerAttr(ch)
			continue
		}
		out = append(out, c.stmtH(ch, handler)...)
		handler = false
	}
	return out
}

func (c *rsConv) isHandlerAttr(n *tree_sitter.Node) bool {
	// #[get("/..")] → attribute_item > attribute > identifier "get"
	var name string
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m.Kind() == "attribute" {
			for _, ch := range namedChildren(m) {
				if ch.Kind() == "identifier" || ch.Kind() == "scoped_identifier" {
					name = lastSeg(c.dotted(ch))
					return
				}
			}
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return rsHandlerAttrs[name]
}

func (c *rsConv) stmt(n *tree_sitter.Node) []nir.Stmt { return c.stmtH(n, false) }

func (c *rsConv) stmtH(n *tree_sitter.Node, handler bool) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_item":
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		body = append(body, c.rsIncompleteIPv4DenylistChecks(n)...)
		if handler {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		exported := handler // `pub fn` is the public API; trait methods are public too
		for _, ch := range children(n) {
			if ch.Kind() == "visibility_modifier" {
				exported = true
				break
			}
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, ParamTypes: paramTypes, Body: body, Loc: L, Exported: exported}}
	case "impl_item", "mod_item", "trait_item":
		return c.decls(field(n, "body"))
	case "struct_item", "enum_item", "use_declaration", "const_item", "static_item":
		return nil
	case "let_declaration":
		val := field(n, "value")
		if val == nil {
			return nil
		}
		name := c.patName(field(n, "pattern"))
		if name != "" {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(val)}}
		}
		// `let _ = expr;` binds no name, but the call still matters for sinks/marks.
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(val)}}
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	// if/match in statement position become branch-structured control flow (predicate
	// attached) so dead arms prune AND nested reassignments are tracked (no FN). The
	// value-context forms (`let x = if …`) are still handled in expr() as a Ternary.
	case "if_expression":
		return []nir.Stmt{c.rsIf(n)}
	case "match_expression":
		return []nir.Stmt{c.rsMatch(n)}
	case "block":
		return c.block(n)
	}
	// a bare tail expression (block value) still matters for taint
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *rsConv) rsIncompleteIPv4DenylistChecks(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	type seenSet map[string]bool
	byReceiver := map[string]seenSet{}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "call_expression" {
			path := c.dotted(field(n, "function"))
			if recv, meth, ok := rustReceiverMethod(path); ok && rustIPv4DenylistMethod(meth) {
				if byReceiver[recv] == nil {
					byReceiver[recv] = seenSet{}
				}
				byReceiver[recv][meth] = true
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)

	var out []nir.Stmt
	for _, seen := range byReceiver {
		if !rustLooksLikeIPv4Denylist(seen) {
			continue
		}
		var missing []string
		for _, meth := range []string{"is_unspecified", "is_broadcast"} {
			if !seen[meth] {
				missing = append(missing, meth)
			}
		}
		if len(missing) == 0 {
			continue
		}
		path := "security.ipv4.denylist.incomplete." + strings.Join(missing, ".")
		out = append(out, nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: path, Loc: c.loc(fn)},
			Path:   path,
			Method: lastSeg(path),
			Loc:    c.loc(fn),
		}})
	}
	return out
}

func rustReceiverMethod(path string) (string, string, bool) {
	i := strings.LastIndex(path, ".")
	if i <= 0 || i == len(path)-1 {
		return "", "", false
	}
	return path[:i], path[i+1:], true
}

func rustIPv4DenylistMethod(meth string) bool {
	switch meth {
	case "is_private", "is_loopback", "is_link_local", "is_multicast", "is_documentation",
		"is_unspecified", "is_broadcast":
		return true
	default:
		return false
	}
}

func rustLooksLikeIPv4Denylist(seen map[string]bool) bool {
	core := 0
	for _, meth := range []string{"is_private", "is_loopback", "is_link_local", "is_multicast", "is_documentation"} {
		if seen[meth] {
			core++
		}
	}
	return core >= 3
}

func (c *rsConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch inner.Kind() {
	case "if_expression":
		return []nir.Stmt{c.rsIf(inner)}
	case "match_expression":
		return []nir.Stmt{c.rsMatch(inner)}
	}
	if inner.Kind() == "assignment_expression" {
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *rsConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *rsConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "else_clause", "match_block", "match_arm":
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *rsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := c.patName(field(ch, "pattern")); nm != "" {
				out = append(out, nm)
			}
		}
	}
	return out
}

func (c *rsConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := c.patName(field(ch, "pattern")); nm != "" {
				putParamType(out, nm, paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

// patName extracts the bound identifier from a pattern (unwrapping ref/mut).
func (c *rsConv) patName(p *tree_sitter.Node) string {
	for p != nil {
		switch p.Kind() {
		case "identifier":
			return c.text(p)
		case "ref_pattern", "mut_pattern", "reference_pattern":
			kids := namedChildren(p)
			if len(kids) == 0 {
				return ""
			}
			p = kids[len(kids)-1]
		default:
			return ""
		}
	}
	return ""
}

func (c *rsConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *rsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "self", "field_identifier", "type_identifier", "scoped_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "unit_expression":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer_literal", "float_literal", "char_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: rustStringValue(c.text(n))}
	case "field_expression":
		return nir.Attr{Base: c.expr(field(n, "value")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "index_expression":
		kids := namedChildren(n)
		var base, key nir.Expr = nir.Const{Loc: L}, nil
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		if len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: base, Key: key, Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "macro_invocation":
		name := lastSeg(c.dotted(field(n, "macro")))
		var parts []nir.Expr
		if tt := lastChildKind(n, "token_tree"); tt != nil {
			for _, ch := range namedChildren(tt) {
				if isRustExprTok(ch.Kind()) {
					parts = append(parts, c.expr(ch))
				}
			}
		}
		if rsFormatMacros[name] {
			return nir.Format{Parts: parts, Loc: L}
		}
		// other macros (e.g. query!) — model as a call so they can be sinks
		return nir.Call{Callee: nir.Name{ID: name, Loc: L}, Args: parts, Path: name, Method: name, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "reference_expression", "try_expression", "await_expression",
		"parenthesized_expression", "type_cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "unary_expression":
		// `-x`, `!x` — the operator is the leading unnamed token.
		op := "?"
		for i := uint(0); i < n.ChildCount(); i++ {
			if ch := n.Child(i); !ch.IsNamed() {
				op = c.text(ch)
				break
			}
		}
		var operand nir.Expr = nir.Const{Loc: L}
		if kids := namedChildren(n); len(kids) > 0 {
			operand = c.expr(kids[len(kids)-1])
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "if_expression":
		// `let x = if c { A } else { B }` — model as a Ternary on the arms' tail values so a
		// constant condition prunes. Falls back to Seq when an arm isn't a simple value.
		then := c.blockTail(field(n, "consequence"))
		var els nir.Expr
		if alt := field(n, "alternative"); alt != nil {
			if k := namedChildren(alt); len(k) > 0 {
				if k[0].Kind() == "block" {
					els = c.blockTail(k[0])
				} else {
					els = c.expr(k[0]) // else if …
				}
			}
		}
		if then != nil && els != nil {
			return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: then, Else: els, Loc: L}
		}
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	case "match_expression", "block":
		return nir.Seq{Parts: c.blockValues(n), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// rustStringValue returns a quoted string literal whose inner text reflects the
// Rust literal payload. It covers normal, byte, raw, and byte-raw strings well
// enough for adapter `val` matching; escape handling is intentionally simple
// because security mappings match substrings such as "/tmp/" or static IV bytes.
func rustStringValue(raw string) string {
	s := raw
	for len(s) > 0 {
		switch s[0] {
		case 'b':
			s = s[1:]
		case 'r':
			hashes := 0
			i := 1
			for i < len(s) && s[i] == '#' {
				hashes++
				i++
			}
			if i < len(s) && s[i] == '"' {
				start := i + 1
				end := len(s) - 1 - hashes
				if end >= start && end < len(s) {
					return "\"" + s[start:end] + "\""
				}
			}
			return "\"" + raw + "\""
		default:
			goto unquote
		}
	}
unquote:
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		body := s[1 : len(s)-1]
		out := make([]byte, 0, len(body))
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				out = append(out, body[i+1])
				i++
				continue
			}
			out = append(out, body[i])
		}
		return "\"" + string(out) + "\""
	}
	return "\"" + raw + "\""
}

// rsIf lowers a statement-position if with its predicate so constant-false arms prune.
func (c *rsConv) rsIf(n *tree_sitter.Node) nir.Stmt {
	it := nir.If{Loc: c.loc(n)}
	it.Cond = c.expr(field(n, "condition"))
	it.Then = c.block(field(n, "consequence"))
	if alt := field(n, "alternative"); alt != nil {
		it.Else = c.rsElse(alt)
	}
	return it
}

// rsElse unwraps an else branch: a block, a chained else-if, or an else_clause wrapper.
func (c *rsConv) rsElse(alt *tree_sitter.Node) []nir.Stmt {
	switch alt.Kind() {
	case "block":
		return c.block(alt)
	case "if_expression":
		return []nir.Stmt{c.rsIf(alt)}
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range namedChildren(alt) {
			out = append(out, c.rsElse(ch)...)
		}
		return out
	}
	return nil
}

// rsMatch lowers a statement-position match to a subject+labelled Switch so dead arms
// prune. A wildcard `_` arm is the default; literal patterns become case labels.
func (c *rsConv) rsMatch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n), Subject: c.expr(field(n, "value"))}
	body := field(n, "body")
	if body == nil {
		return sw
	}
	for _, arm := range namedChildren(body) {
		if arm.Kind() != "match_arm" {
			continue
		}
		pat := field(arm, "pattern")
		stmts := c.rsArmBody(field(arm, "value"))
		if pat == nil || c.text(pat) == "_" {
			sw.Default = append(sw.Default, stmts...)
			continue
		}
		label := pat // unwrap match_pattern -> the inner literal so labels are foldable
		if k := namedChildren(pat); len(k) == 1 {
			label = k[0]
		}
		sw.Cases = append(sw.Cases, stmts)
		sw.Labels = append(sw.Labels, []nir.Expr{c.expr(label)})
	}
	return sw
}

func (c *rsConv) rsArmBody(v *tree_sitter.Node) []nir.Stmt {
	if v == nil {
		return nil
	}
	if v.Kind() == "block" {
		return c.block(v)
	}
	return c.exprStmt(v)
}

// blockTail returns the tail (value) expression of a `{ … }` block, or nil if the last
// element isn't a bare expression (e.g. a let/assignment) — used to model an if-as-value.
func (c *rsConv) blockTail(block *tree_sitter.Node) nir.Expr {
	if block == nil || block.Kind() != "block" {
		return nil
	}
	kids := namedChildren(block)
	if len(kids) == 0 {
		return nil
	}
	last := kids[len(kids)-1]
	switch last.Kind() {
	case "let_declaration", "expression_statement", "empty_statement":
		return nil
	}
	return c.expr(last)
}

func (c *rsConv) blockValues(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	for _, ch := range namedChildren(n) {
		out = append(out, c.expr(ch))
	}
	return out
}

func (c *rsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "field_identifier", "type_identifier", "self", "primitive_type":
		return c.text(n)
	case "scoped_identifier", "scoped_type_identifier":
		path := field(n, "path")
		name := field(n, "name")
		if path == nil {
			return c.dotted(name)
		}
		return c.dotted(path) + "." + c.dotted(name)
	case "field_expression":
		return c.dotted(field(n, "value")) + "." + c.text(field(n, "field"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "generic_function":
		return c.dotted(field(n, "function"))
	case "generic_type":
		return c.dotted(field(n, "type"))
	case "index_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0]) + "[]"
		}
	}
	return "?"
}

func isRustExprTok(k string) bool {
	switch k {
	case "identifier", "scoped_identifier", "field_expression", "call_expression",
		"macro_invocation", "index_expression", "reference_expression", "self":
		return true
	}
	return false
}

func lastChildKind(n *tree_sitter.Node, kind string) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == kind {
			return ch
		}
	}
	return nil
}

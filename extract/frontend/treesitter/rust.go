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

// decls walks a list, tracking preceding attribute_item syntax for the next item.
func (c *rsConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var attrs []string
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "attribute_item" {
			attrs = append(attrs, c.rsAttrTokens(ch)...)
			continue
		}
		out = append(out, c.stmtH(ch, attrs)...)
		attrs = nil
	}
	return out
}

func (c *rsConv) rsAttrTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	rawItem := strings.Join(strings.Fields(c.text(n)), "")
	if strings.HasPrefix(rawItem, "#[repr(") && strings.HasSuffix(rawItem, ")]") {
		arg := strings.TrimSuffix(strings.TrimPrefix(rawItem, "#[repr("), ")]")
		add("attr_name:repr")
		add("attr_repr:" + arg)
		add("attr:repr(" + arg + ")")
		add("repr:" + arg)
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m.Kind() == "attribute" {
			for _, ch := range namedChildren(m) {
				if ch.Kind() == "identifier" || ch.Kind() == "scoped_identifier" {
					path := c.dotted(ch)
					add("attr_path:" + path)
					add("attr_name:" + lastSeg(path))
				}
			}
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *rsConv) stmt(n *tree_sitter.Node) []nir.Stmt { return c.stmtH(n, nil) }

func (c *rsConv) stmtH(n *tree_sitter.Node, attrs []string) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_item":
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		body = append(body, c.rsFunctionContext(n)...)
		exported := false
		for _, ch := range children(n) {
			if ch.Kind() == "visibility_modifier" {
				exported = true
				break
			}
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, ParamTypes: paramTypes, ParamEntries: c.rsParamEntries(c.text(field(n, "name")), params, attrs), Body: body, Loc: L, Exported: exported}}
	case "impl_item":
		out := c.rsUnsafeImplMetadata(n)
		out = append(out, c.decls(field(n, "body"))...)
		return out
	case "mod_item", "trait_item":
		return c.decls(field(n, "body"))
	case "enum_item":
		return c.rsEnumMetadata(n, attrs)
	case "struct_item", "use_declaration", "const_item", "static_item":
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
	if meta := c.rsUninitializedMetadata(n); meta != nil {
		return append(meta, nir.ExprStmt{Value: c.expr(n)})
	}
	// a bare tail expression (block value) still matters for taint
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *rsConv) rsUninitializedMetadata(n *tree_sitter.Node) []nir.Stmt {
	text := c.text(n)
	compact := rustCompactText(text)
	if !strings.Contains(compact, "mem::uninitialized") {
		return nil
	}
	loc := c.loc(n)
	path := "analysis.rust.uninitialized"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "lang=rust"},
			nir.Const{Loc: loc, Value: "mem::uninitialized"},
		},
		Path:   path,
		Method: "uninitialized",
		Loc:    loc,
	}}}
}

func (c *rsConv) rsEnumMetadata(n *tree_sitter.Node, attrs []string) []nir.Stmt {
	if len(attrs) == 0 {
		return nil
	}
	loc := c.loc(n)
	path := "analysis.rust.enum"
	name := c.text(field(n, "name"))
	tokens := []string{"lang=rust", "kind:enum"}
	if name != "" {
		tokens = append(tokens, "enum_name:"+name)
	}
	tokens = append(tokens, attrs...)
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "enum",
		Loc:    loc,
	}}}
}

func (c *rsConv) rsUnsafeImplMetadata(n *tree_sitter.Node) []nir.Stmt {
	text := c.text(n)
	compact := rustCompactText(text)
	if !strings.HasPrefix(strings.TrimSpace(text), "unsafe impl") {
		return nil
	}
	var trait string
	for _, name := range []string{"Send", "Sync"} {
		if strings.Contains(compact, name+"for") || strings.Contains(compact, name+"<") {
			trait = name
			break
		}
	}
	if trait == "" {
		return nil
	}
	loc := c.loc(n)
	tokens := []string{"lang=rust", "kind:unsafe_impl", "trait:" + trait}
	for _, bound := range []string{"Send", "Sync"} {
		if strings.Contains(compact, "+"+bound) || strings.Contains(compact, ":"+bound) {
			tokens = append(tokens, "bound:"+bound)
		}
	}
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	path := "analysis.rust.unsafe_impl"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "unsafe_impl",
		Loc:    loc,
	}}}
}

func (c *rsConv) rsParamEntries(name string, params []string, attrs []string) []nir.ParamEntry {
	if len(params) == 0 || len(attrs) == 0 {
		return nil
	}
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := append([]string{}, attrs...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *rsConv) rsFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	loc := c.loc(fn)
	text := c.text(body)
	path := "analysis.function.context"
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=rust"},
		nir.Const{Loc: loc, Value: "name=" + c.text(field(fn, "name"))},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: rustCompactText(text)},
	}
	for _, tok := range c.rsStructuredContextTokens(body) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args:   args,
		Path:   path,
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *rsConv) rsStructuredContextTokens(root *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	atom := func(n *tree_sitter.Node) string {
		if n == nil {
			return ""
		}
		if p := c.dotted(n); p != "" && p != "?" {
			return p
		}
		return rustCompactText(c.text(n))
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			left := atom(field(n, "left"))
			right := atom(field(n, "right"))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
		case "call_expression":
			if path := c.dotted(field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				add("call:" + lastSeg(path))
				for _, arg := range namedChildren(field(n, "arguments")) {
					if a := atom(arg); a != "" {
						add("call_arg:" + path + ":" + a)
					}
				}
			}
		case "field_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "match_arm":
			if pat := rustMatchArmPattern(n); pat != nil {
				if label := atom(pat); label != "" {
					add("match_arm:" + label)
				}
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func rustMatchArmPattern(n *tree_sitter.Node) *tree_sitter.Node {
	if p := field(n, "pattern"); p != nil {
		return p
	}
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "identifier", "scoped_identifier", "match_pattern", "tuple_struct_pattern", "literal_pattern":
			return ch
		}
	}
	return nil
}

func rustCompactText(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
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
// because value-matched mappings need literal substrings such as path fragments
// or byte constants.
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

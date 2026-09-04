package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsscala "github.com/tree-sitter/tree-sitter-scala/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// scConvScala walks a tree-sitter Scala CST into NIR.
type scConvScala struct {
	nodeCache
	src         []byte
	file        string
	key         string
	currentFunc string
	childCache  map[uintptr][]*tree_sitter.Node
}

func (c *scConvScala) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
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

// ExtractScala parses Scala files into one NIR Program (one module per file).
func ExtractScala(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsscala.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &scConvScala{src: src, file: rel, key: moduleKey(root, abs, ".scala")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *scConvScala) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *scConvScala) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *scConvScala) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *scConvScala) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch c.kind(n) {
	case "package_clause", "package_object":
		if b := c.field(n, "body"); b != nil {
			return c.decls(b)
		}
		return c.decls(n)
	case "object_definition", "class_definition", "trait_definition", "enum_definition":
		return []nir.Stmt{nir.ClassDef{Name: c.text(c.field(n, "name")), Body: c.decls(c.field(n, "body")), Loc: L}}
	case "function_definition":
		params := c.params(c.field(n, "parameters"))
		name := c.text(c.field(n, "name"))
		prev := c.currentFunc
		c.currentFunc = name
		body := c.bodyStmts(c.field(n, "body"))
		c.currentFunc = prev
		return []nir.Stmt{nir.FuncDef{
			Name:          name,
			Params:        params,
			ParamTypes:    c.paramTypes(c.field(n, "parameters")),
			Body:          body,
			Loc:           L,
			ContextTokens: c.scFunctionContext(name, c.field(n, "body")),
		}}
	case "val_definition", "var_definition", "val_declaration", "var_declaration":
		name := c.patName(c.field(n, "pattern"))
		if v := c.field(n, "value"); name != "" && v != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(v)}}
		}
		return nil
	case "assignment_expression":
		left := c.field(n, "left")
		right := c.expr(c.field(n, "right"))
		if left != nil {
			switch c.kind(left) {
			case "identifier":
				return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
			case "field_expression", "indexed_expression":
				// member/subscript write `obj.field = p` / `a(k) = p` — model as a path-sink
				// Call (Method="") so the assigned value flows into a write node.
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: c.expr(left), Args: []nir.Expr{right},
					Path: c.dotted(left), Method: "", Loc: L,
				}}}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	// branch-structured (B1); Cond nil (Scala did not evaluate the predicate) -> byte-identical.
	case "if_expression":
		condNode := c.field(n, "condition")
		cond := c.expr(condNode)
		ifn := nir.If{Cond: cond}
		if cons := c.field(n, "consequence"); cons != nil {
			ifn.Then = c.collectBlocks(cons)
		}
		if alt := c.field(n, "alternative"); alt != nil {
			ifn.Else = c.collectBlocks(alt)
		}
		return []nir.Stmt{
			nir.ExprStmt{Value: c.conditionContextCall(condNode, L)},
			ifn,
		}
	case "for_expression", "while_expression":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_expression":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "match_expression":
		return []nir.Stmt{c.scMatch(n)}
	case "block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *scConvScala) conditionContextCall(cond *tree_sitter.Node, loc string) nir.Call {
	raw := c.text(cond)
	compact := strings.Join(strings.Fields(raw), "")
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: raw},
		nir.Const{Loc: loc, Value: compact},
		nir.Const{Loc: loc, Value: c.currentFunc},
	}
	if scHasIncompleteCsrfDoubleSubmit(raw, c.currentFunc) {
		args = append(args, nir.Const{Loc: loc, Value: "csrf_validation:double_submit_missing_nonempty_guard"})
	}
	return nir.Call{
		Callee: nir.Name{ID: "analysis.condition.if", Loc: loc},
		Args:   args,
		Path:   "analysis.condition.if",
		Method: "if",
		Loc:    loc,
	}
}

func scHasIncompleteCsrfDoubleSubmit(raw, fn string) bool {
	compact := strings.Join(strings.Fields(raw), "")
	lower := strings.ToLower(compact)
	if !strings.Contains(strings.ToLower(fn), "csrf") {
		return false
	}
	if !strings.Contains(lower, "submitted==cookie") && !strings.Contains(lower, "cookie==submitted") {
		return false
	}
	for _, guard := range []string{".isempty", ".nonempty", "!=null", "!=''", "!=\"\""} {
		if strings.Contains(lower, guard) {
			return false
		}
	}
	return true
}

// scMatch lowers a `x match { case … }` to a subject+labelled nir.Switch so a constant
// subject prunes non-matching arms (instead of flattening, which let a later arm mask a
// live arm's taint). A wildcard `_` pattern is the default.
func (c *scConvScala) scMatch(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n), Subject: c.expr(c.field(n, "value"))}
	body := c.field(n, "body")
	if body == nil {
		return sw
	}
	for _, cl := range c.namedChildren(body) {
		if c.kind(cl) != "case_clause" {
			continue
		}
		pat := c.field(cl, "pattern")
		stmts := c.scArmBody(c.field(cl, "body"))
		if pat == nil || c.kind(pat) == "wildcard" || c.text(pat) == "_" {
			sw.Default = append(sw.Default, stmts...)
			continue
		}
		sw.Cases = append(sw.Cases, stmts)
		sw.Labels = append(sw.Labels, []nir.Expr{c.expr(pat)})
	}
	return sw
}

func (c *scConvScala) scArmBody(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	switch c.kind(b) {
	case "block", "indented_block":
		return c.collectBlocks(b)
	}
	return c.stmt(b)
}

func (c *scConvScala) bodyStmts(body *tree_sitter.Node) []nir.Stmt {
	if body == nil {
		return nil
	}
	if c.kind(body) == "block" {
		return c.block(body)
	}
	return []nir.Stmt{nir.Return{Value: c.expr(body)}}
}

func (c *scConvScala) block(block *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range c.namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *scConvScala) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch c.kind(ch) {
			case "block":
				out = append(out, c.block(ch)...)
			case "indented_block", "case_clause", "catch_clause", "finally_clause", "else_clause", "guard":
				walk(ch)
			default:
				if ch.IsNamed() {
					out = append(out, c.stmt(ch)...)
				}
			}
		}
	}
	if c.kind(n) == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *scConvScala) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) == "parameter" {
			if nm := c.field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *scConvScala) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) == "parameter" {
			if nm := c.field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *scConvScala) scFunctionContext(name string, body *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	add("lang=scala")
	if name != "" {
		add("function_name:" + name)
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= 512 {
			return
		}
		switch c.kind(n) {
		case "val_definition", "var_definition":
			left := c.patName(c.field(n, "pattern"))
			if right := scContextValue(c.text(c.field(n, "value"))); left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
		case "assignment_expression":
			left := scContextPath(c, c.field(n, "left"))
			right := scContextValue(c.text(c.field(n, "right")))
			if left != "" && right != "" {
				add("assign:" + left + "=" + right)
			}
		case "call_expression":
			if path := c.dotted(c.field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
				for _, arg := range c.namedChildren(c.field(n, "arguments")) {
					if a := scContextPath(c, arg); a != "" {
						add("call_arg:" + path + ":" + a)
					}
				}
			}
		case "field_expression":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "infix_expression":
			if expr := scContextCompact(c.text(n)); expr != "" {
				add("expr:" + expr)
			}
		case "string", "interpolated_string_expression", "integer_literal", "floating_point_literal", "boolean_literal", "null_literal":
			if lit := scContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(body)
	return out
}

func scContextPath(c *scConvScala, n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if p := c.dotted(n); p != "" && p != "?" {
		return p
	}
	return scContextCompact(c.text(n))
}

func scContextValue(raw string) string {
	return scContextCompact(raw)
}

func scContextCompact(raw string) string {
	s := strings.Join(strings.Fields(raw), "")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func (c *scConvScala) patName(p *tree_sitter.Node) string {
	if p == nil {
		return ""
	}
	switch c.kind(p) {
	case "identifier":
		return c.text(p)
	case "typed_pattern", "tuple_pattern":
		if kids := c.namedChildren(p); len(kids) > 0 {
			return c.patName(kids[0])
		}
	}
	return ""
}

func (c *scConvScala) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range c.namedChildren(args) {
		out = append(out, c.expr(a))
	}
	return out
}

func (c *scConvScala) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "identifier", "this", "stable_identifier", "wildcard":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer_literal", "floating_point_literal", "character_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "boolean_literal", "null_literal", "unit":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for matching
	case "string", "symbol_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "interpolated_string_expression":
		var parts []nir.Expr
		if is := lastChildKind(n, "interpolated_string"); is != nil {
			var walk func(m *tree_sitter.Node)
			walk = func(m *tree_sitter.Node) {
				for _, ch := range c.namedChildren(m) {
					if c.kind(ch) == "interpolation" {
						for _, e := range c.namedChildren(ch) {
							parts = append(parts, c.expr(e))
						}
					} else {
						walk(ch)
					}
				}
			}
			walk(is)
		}
		return nir.Format{Parts: parts, Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(c.field(n, "value")), Attr: c.text(c.field(n, "field")), Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := c.field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(c.field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "generic_function":
		return c.expr(c.field(n, "function"))
	case "instance_expression":
		// `new Type(args)` — model as a constructor call so type/arg sinks and marks match
		// (e.g. new pkg.Widget(p), new pkg.Builder()). Grammar nests a call_expression
		// (type applied to arguments) or carries the type + arguments directly.
		for _, ch := range c.namedChildren(n) {
			if k := c.kind(ch); k == "call_expression" || k == "generic_function" {
				return c.expr(ch)
			}
		}
		kids := c.namedChildren(n)
		if len(kids) >= 1 {
			// the type may be a stable_type_identifier (`pkg.Widget`) that c.dotted can't
			// resolve (returns "?"); fall back to its source text for the constructor path.
			path := c.dotted(kids[0])
			if path == "" || path == "?" {
				path = c.text(kids[0])
			}
			var args []nir.Expr
			if a := c.field(n, "arguments"); a != nil {
				args = c.callArgs(a)
			} else if len(kids) >= 2 && c.kind(kids[1]) == "arguments" {
				args = c.callArgs(kids[1])
			}
			return nir.Call{Callee: nir.Name{ID: path, Loc: L}, Args: args, Path: path, Method: lastSeg(path), Loc: L}
		}
	case "infix_expression":
		op := c.text(c.field(n, "operator"))
		left, right := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "parenthesized_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "prefix_expression", "unary_expression":
		op := c.text(c.field(n, "operator"))
		var operand nir.Expr = nir.Const{Loc: L}
		if kids := c.namedChildren(n); len(kids) > 0 {
			operand = c.expr(kids[len(kids)-1])
		}
		return nir.Unary{Op: op, Operand: operand, Loc: L}
	case "if_expression":
		// if-as-expression `if (c) a else b` → Ternary so the engine merges both branch
		// values into a Phi (a tainted branch then taints the result).
		condNode := c.field(n, "condition")
		cond := c.expr(condNode)
		t := nir.Ternary{Cond: cond, Loc: L}
		t.Then = c.blockTail(c.field(n, "consequence"))
		if alt := c.field(n, "alternative"); alt != nil {
			t.Else = c.blockTail(alt)
		} else {
			t.Else = nir.Const{Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.conditionContextCall(condNode, L), t}, Loc: L}
	case "match_expression", "block":
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
	return nir.Seq{Parts: parts, Loc: L}
}

// blockTail yields the value a branch evaluates to — for a `{…}` block / indented_block
// the last expression, otherwise the expression itself.
func (c *scConvScala) blockTail(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	if k := c.kind(n); k == "block" || k == "indented_block" {
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nir.Const{Loc: c.loc(n)}
		}
		return c.expr(kids[len(kids)-1])
	}
	return c.expr(n)
}

func (c *scConvScala) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch c.kind(n) {
	case "identifier", "this", "operator_identifier", "type_identifier":
		return c.text(n)
	case "stable_identifier":
		return c.text(n)
	case "field_expression":
		return c.dotted(c.field(n, "value")) + "." + c.text(c.field(n, "field"))
	case "call_expression":
		return c.dotted(c.field(n, "function"))
	case "generic_function":
		return c.dotted(c.field(n, "function"))
	}
	return "?"
}

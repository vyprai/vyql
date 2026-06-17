package treesitter

import (
	"strings"

	tskotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/vyprai/vyql/extract/nir"
)

// ktConv walks a tree-sitter Kotlin CST into NIR.
type ktConv struct {
	src              []byte
	file             string
	key              string
	classParamTokens []string
}

// ExtractKotlin parses Kotlin files into one NIR Program (one module per file).
func ExtractKotlin(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tskotlin.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &ktConv{src: src, file: rel, key: moduleKey(root, abs, ".kt")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *ktConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *ktConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *ktConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *ktConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "class_declaration", "object_declaration", "interface_declaration":
		prev := c.classParamTokens
		c.classParamTokens = append(append([]string{}, prev...), c.ktAnnotationTokens(n, "class_annotation:")...)
		cd := nir.ClassDef{Name: c.declName(n), Body: c.decls(c.classBody(n)), Loc: L}
		c.classParamTokens = prev
		return []nir.Stmt{cd}
	case "function_declaration":
		name := c.declName(n)
		params := c.params(n)
		paramTypes := c.paramTypes(n)
		body := c.block(c.funcBody(n))
		tokens := append([]string{}, c.classParamTokens...)
		tokens = append(tokens, c.ktAnnotationTokens(n, "annotation:")...)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L,
			ParamEntries: c.ktParamEntries(name, params, tokens), Exported: ktPublic(c, n)}}
	case "property_declaration":
		name := c.propName(n)
		val := c.propValue(n)
		if name != "" && val != nil {
			return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(val)}}
		}
		return nil
	case "assignment":
		left := field(n, "left")
		if left == nil {
			if k := namedChildren(n); len(k) > 0 {
				left = k[0]
			}
		}
		right := c.lastExpr(n)
		if left != nil {
			switch left.Kind() {
			case "identifier", "simple_identifier":
				return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
			case "navigation_expression", "indexing_expression":
				// member/subscript write `obj.role = p` / `a[k] = p` — model as a path-sink
				// Call (Method="") so the assigned value flows into a write node, matching how
				// JS path-sink-writes and python __setitem__ are modeled.
				L := c.loc(n)
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: c.expr(left), Args: []nir.Expr{right},
					Path: c.dotted(left), Method: "", Loc: L,
				}}}
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "call_expression", "navigation_expression":
		out := []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
		// trailing-lambda bodies (`stream.use { reader.parse(it) }`, `x.let { … }`,
		// `apply/also/run`) execute synchronously — lower their statements inline so
		// code inside scope functions is actually analyzed (it was being dropped).
		return append(out, c.trailingLambdaStmts(n)...)
	case "jump_expression", "return_expression":
		if k := namedChildren(n); len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[len(k)-1])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (Kotlin did not evaluate the predicate) -> byte-identical.
	case "if_expression":
		var cond nir.Expr
		var bodies []*tree_sitter.Node
		for _, ch := range namedChildren(n) {
			// a then/else body is a `{…}` block or a brace-less control_structure_body; the
			// first remaining child is the condition. (Only control_structure_body was matched
			// before, so braced `if (c) { sink(x) }` dropped its body → no CFG region.)
			if k := ch.Kind(); k == "control_structure_body" || k == "block" {
				bodies = append(bodies, ch)
			} else if cond == nil {
				cond = c.expr(ch)
			}
		}
		ifn := nir.If{Cond: cond}
		if len(bodies) > 0 {
			ifn.Then = c.collectBlocks(bodies[0])
		}
		if len(bodies) > 1 {
			ifn.Else = c.collectBlocks(bodies[1])
		}
		return []nir.Stmt{ifn}
	case "for_statement", "while_statement", "do_while_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_expression":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "when_expression":
		return []nir.Stmt{c.ktWhen(n)}
	case "statements", "control_structure_body":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// ktWhen lowers a `when` to a subject+labelled nir.Switch so a constant subject prunes
// the non-matching arms (instead of flattening, which let a later arm's clean
// reassignment mask a live arm's taint).
func (c *ktConv) ktWhen(n *tree_sitter.Node) nir.Stmt {
	sw := nir.Switch{Loc: c.loc(n)}
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "when_subject":
			if k := namedChildren(ch); len(k) > 0 {
				sw.Subject = c.expr(k[len(k)-1])
			}
		case "when_entry":
			var labs []nir.Expr
			var stmts []nir.Stmt
			hasCond := false
			for i := uint(0); i < ch.ChildCount(); i++ {
				e := ch.Child(i)
				if !e.IsNamed() {
					continue
				}
				if ch.FieldNameForChild(uint32(i)) == "condition" {
					hasCond = true
					labs = append(labs, c.expr(e))
					continue
				}
				switch e.Kind() {
				case "block", "control_structure_body", "statements":
					stmts = append(stmts, c.collectBlocks(e)...)
				}
			}
			if !hasCond { // the `else` arm
				sw.Default = append(sw.Default, stmts...)
			} else {
				sw.Cases = append(sw.Cases, stmts)
				sw.Labels = append(sw.Labels, labs)
			}
		}
	}
	return sw
}

// opToken returns the operator symbol of a binary node (the first non-named child).
func (c *ktConv) opToken(n *tree_sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		if ch := n.Child(i); !ch.IsNamed() {
			return c.text(ch)
		}
	}
	return "?"
}

// trailingLambdaStmts lowers the bodies of any lambda arguments of a call
// (trailing `{ … }` or `(…, { … })`). Kotlin scope functions (use/let/apply/
// also/run/with/forEach) run their lambda synchronously, so the statements
// inside must be analyzed; they were previously dropped.
func (c *ktConv) trailingLambdaStmts(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "annotated_lambda", "lambda_literal":
				out = append(out, c.collectBlocks(ch)...)
			case "value_arguments", "call_suffix":
				walk(ch) // lambda passed as a regular arg: `foo({ … })`
			}
		}
	}
	walk(n)
	return out
}

// ktPublic reports whether a Kotlin function is public API. Kotlin is public BY DEFAULT;
// only an explicit private/internal/protected modifier hides it. Used to scope the
// library param-source to the public surface.
func ktPublic(c *ktConv, n *tree_sitter.Node) bool {
	for _, ch := range children(n) {
		if ch.Kind() == "modifiers" {
			t := c.text(ch)
			if strings.Contains(t, "private") || strings.Contains(t, "internal") || strings.Contains(t, "protected") {
				return false
			}
		}
	}
	return true
}

func (c *ktConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statements":
				out = append(out, c.decls(ch)...)
			case "control_structure_body", "when_entry", "catch_block", "finally_block", "block",
				"annotated_lambda", "lambda_literal":
				walk(ch)
			default:
				if ch.IsNamed() && isKtStmt(ch.Kind()) {
					out = append(out, c.stmt(ch)...)
				}
			}
		}
	}
	walk(n)
	return out
}

func isKtStmt(k string) bool {
	switch k {
	case "property_declaration", "assignment", "call_expression", "navigation_expression",
		"function_declaration", "class_declaration", "if_expression", "when_expression",
		"for_statement", "while_statement", "jump_expression", "return_expression":
		return true
	}
	return false
}

// --- node accessors (Kotlin uses positional children more than named fields) ---

func (c *ktConv) declName(n *tree_sitter.Node) string {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "identifier" || ch.Kind() == "type_identifier" {
			return c.text(ch)
		}
	}
	return ""
}

func (c *ktConv) classBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "class_body" || ch.Kind() == "enum_class_body" {
			return ch
		}
	}
	return nil
}

func (c *ktConv) funcBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "function_body" {
			return ch
		}
	}
	return nil
}

func (c *ktConv) block(body *tree_sitter.Node) []nir.Stmt {
	if body == nil {
		return nil
	}
	var out []nir.Stmt
	for _, ch := range namedChildren(body) {
		if ch.Kind() == "block" || ch.Kind() == "statements" {
			out = append(out, c.decls(ch)...)
		} else {
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

func (c *ktConv) params(n *tree_sitter.Node) []string {
	var out []string
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "function_value_parameters" {
			for _, p := range namedChildren(ch) {
				if p.Kind() == "parameter" {
					for _, id := range namedChildren(p) {
						if id.Kind() == "identifier" {
							out = append(out, c.text(id))
							break
						}
					}
				}
			}
		}
	}
	return out
}

func (c *ktConv) paramTypes(n *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "function_value_parameters" {
			continue
		}
		for _, p := range namedChildren(ch) {
			if p.Kind() != "parameter" {
				continue
			}
			name := ""
			for _, id := range namedChildren(p) {
				if id.Kind() == "identifier" {
					name = c.text(id)
					break
				}
			}
			putParamType(out, name, paramTypeFromField(c, p))
		}
	}
	return out
}

func (c *ktConv) propName(n *tree_sitter.Node) string {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "variable_declaration" {
			for _, id := range namedChildren(ch) {
				if id.Kind() == "identifier" {
					return c.text(id)
				}
			}
		}
	}
	return ""
}

func (c *ktConv) propValue(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "variable_declaration", "modifiers", "type_annotation":
			continue
		default:
			return ch
		}
	}
	return nil
}

func (c *ktConv) lastExpr(n *tree_sitter.Node) nir.Expr {
	k := namedChildren(n)
	if len(k) == 0 {
		return nir.Const{Loc: c.loc(n)}
	}
	return c.expr(k[len(k)-1])
}

// branchValue yields the value an if/when branch evaluates to — the last expression of
// a `{…}` block / control_structure_body, unwrapping nested block layers.
func (c *ktConv) branchValue(n *tree_sitter.Node) nir.Expr {
	cur := n
	for cur != nil {
		k := namedChildren(cur)
		if len(k) == 0 {
			return nir.Const{Loc: c.loc(cur)}
		}
		last := k[len(k)-1]
		if kind := last.Kind(); kind == "block" || kind == "control_structure_body" || kind == "statements" {
			cur = last
			continue
		}
		return c.expr(last)
	}
	return nir.Const{Loc: c.loc(n)}
}

// ktAnnotationTokens extracts syntax-level annotation names without interpreting
// framework/domain meaning. Adapters decide what each token means.
func (c *ktConv) ktAnnotationTokens(n *tree_sitter.Node, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, prefix+name)
	}
	var deep func(m *tree_sitter.Node)
	deep = func(m *tree_sitter.Node) {
		if k := m.Kind(); k == "identifier" || k == "type_identifier" {
			add(c.text(m))
		}
		for _, ch := range namedChildren(m) {
			deep(ch)
		}
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
			deep(ch)
		}
	}
	return out
}

func (c *ktConv) ktParamEntries(name string, params []string, base []string) []nir.ParamEntry {
	if len(base) == 0 {
		return nil
	}
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" || p == "_" {
			continue
		}
		tokens := append([]string{}, base...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *ktConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		if a.Kind() == "value_argument" {
			if k := namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
		} else {
			out = append(out, c.expr(a))
		}
	}
	return out
}

func (c *ktConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "simple_identifier", "this_expression", "super_expression":
		// tree-sitter-kotlin parses boolean/null literals as bare identifiers; carry
		// their value so value-matching marks can inspect them.
		if t := c.text(n); t == "true" || t == "false" || t == "null" {
			return nir.Const{Loc: L, Value: t}
		}
		return nir.Name{ID: c.text(n), Loc: L}
	case "boolean_literal", "null_literal":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer_literal", "real_literal", "character_literal", "long_literal", "hex_literal", "number_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "comparison_expression", "equality_expression":
		k := namedChildren(n)
		if len(k) >= 2 {
			return nir.BinOp{Op: c.opToken(n), Left: c.expr(k[0]), Right: c.expr(k[len(k)-1]), Loc: L}
		}
	case "string_literal":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if k := ch.Kind(); k == "interpolation" || k == "interpolated_expression" || k == "interpolated_identifier" {
				for _, e := range namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
				if len(namedChildren(ch)) == 0 {
					parts = append(parts, nir.Name{ID: c.text(ch), Loc: L})
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "navigation_expression":
		base := c.navBase(n)
		return nir.Attr{Base: c.expr(base), Attr: c.navSuffix(n), Path: c.dotted(n), Loc: L}
	case "call_expression":
		fn := c.callee(n)
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(c.valueArgs(n)), Path: path, Method: lastSeg(path), Loc: L}
	case "indexing_expression":
		k := namedChildren(n)
		var base, key nir.Expr = nir.Const{Loc: L}, nil
		if len(k) > 0 {
			base = c.expr(k[0])
		}
		if len(k) > 1 {
			key = c.expr(k[len(k)-1])
		}
		return nir.Index{Base: base, Key: key, Path: c.dotted(n), Loc: L}
	case "binary_expression", "additive_expression":
		l := field(n, "left")
		r := field(n, "right")
		if l == nil || r == nil {
			k := namedChildren(n)
			if len(k) >= 2 {
				l, r = k[0], k[len(k)-1]
			}
		}
		// "+" string concat (and Kotlin has no other taint-relevant binary) → Format
		return nir.Format{Parts: []nir.Expr{c.expr(l), c.expr(r)}, Loc: L}
	case "parenthesized_expression", "as_expression", "postfix_expression":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "prefix_expression":
		var operand nir.Expr = nir.Const{Loc: L}
		if k := namedChildren(n); len(k) > 0 {
			operand = c.expr(k[len(k)-1])
		}
		return nir.Unary{Op: c.opToken(n), Operand: operand, Loc: L}
	case "if_expression":
		// if-as-expression `if (c) a else b` → Ternary so the engine merges both branch
		// values into a Phi (a tainted branch then taints the result).
		var cond nir.Expr
		var branches []nir.Expr
		for _, ch := range namedChildren(n) {
			switch ch.Kind() {
			case "control_structure_body", "block", "statements":
				branches = append(branches, c.branchValue(ch))
			default:
				if cond == nil {
					cond = c.expr(ch)
				} else {
					branches = append(branches, c.expr(ch))
				}
			}
		}
		if len(branches) >= 1 {
			t := nir.Ternary{Cond: cond, Then: branches[0], Else: nir.Const{Loc: L}, Loc: L}
			if len(branches) >= 2 {
				t.Else = branches[1]
			}
			return t
		}
		return nir.Seq{Parts: []nir.Expr{cond}, Loc: L}
	case "elvis_expression":
		// `a ?: b` — value is `a` unless null, else `b`; merge both as a Phi.
		k := namedChildren(n)
		if len(k) == 2 {
			return nir.Ternary{Cond: c.expr(k[0]), Then: c.expr(k[0]), Else: c.expr(k[1]), Loc: L}
		}
		fallthrough
	case "when_expression":
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
	return nir.Seq{Parts: parts, Loc: L}
}

// navBase/navSuffix split a navigation_expression a.b into base (a) and member (b).
func (c *ktConv) navBase(n *tree_sitter.Node) *tree_sitter.Node {
	k := namedChildren(n)
	if len(k) > 0 {
		return k[0]
	}
	return nil
}

func (c *ktConv) navSuffix(n *tree_sitter.Node) string {
	k := namedChildren(n)
	if len(k) >= 2 {
		return c.text(k[len(k)-1])
	}
	return ""
}

// callee returns the function part of a call_expression (the child before value_arguments).
func (c *ktConv) callee(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "value_arguments" || ch.Kind() == "call_suffix" || ch.Kind() == "annotated_lambda" {
			break
		}
		return ch
	}
	return nil
}

func (c *ktConv) valueArgs(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "value_arguments" {
			return ch
		}
		if ch.Kind() == "call_suffix" {
			for _, s := range namedChildren(ch) {
				if s.Kind() == "value_arguments" {
					return s
				}
			}
		}
	}
	return nil
}

func (c *ktConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "simple_identifier", "this_expression", "type_identifier":
		return c.text(n)
	case "navigation_expression":
		return c.dotted(c.navBase(n)) + "." + c.navSuffix(n)
	case "call_expression":
		return c.dotted(c.callee(n))
	case "indexing_expression":
		if k := namedChildren(n); len(k) > 0 {
			return c.dotted(k[0]) + "[]"
		}
	}
	return "?"
}

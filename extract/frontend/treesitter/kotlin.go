package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tskotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// ktConv walks a tree-sitter Kotlin CST into NIR.
type ktConv struct {
	src          []byte
	file         string
	key          string
	inController bool // inside a Spring @RestController/@Controller
}

// ktHandlerAnns mark a function as a Spring request handler.
var ktHandlerAnns = map[string]bool{
	"GetMapping": true, "PostMapping": true, "PutMapping": true, "DeleteMapping": true,
	"PatchMapping": true, "RequestMapping": true, "RestController": true, "Controller": true,
}

// ExtractKotlin parses Kotlin files into one NIR Program (one module per file).
func ExtractKotlin(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tskotlin.Language()))

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
		c := &ktConv{src: src, file: rel, key: moduleKey(root, f, ".kt")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
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
		prev := c.inController
		c.inController = prev || c.hasHandlerAnn(n)
		cd := nir.ClassDef{Name: c.declName(n), Body: c.decls(c.classBody(n)), Loc: L}
		c.inController = prev
		return []nir.Stmt{cd}
	case "function_declaration":
		params := c.params(n)
		body := c.block(c.funcBody(n))
		if c.inController || c.hasHandlerAnn(n) {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: c.declName(n), Params: params, Body: body, Loc: L}}
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
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "call_expression", "navigation_expression":
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "jump_expression":
		if k := namedChildren(n); len(k) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(k[len(k)-1])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (Kotlin did not evaluate the predicate) -> byte-identical.
	case "if_expression":
		var cond nir.Expr
		var bodies []*tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "control_structure_body" {
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

func (c *ktConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statements":
				out = append(out, c.decls(ch)...)
			case "control_structure_body", "when_entry", "catch_block", "finally_block", "block":
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
		"for_statement", "while_statement", "jump_expression":
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

// hasHandlerAnn reports whether a class/function carries a Spring handler
// annotation (@RestController/@GetMapping/…). Annotation names nest under
// modifiers > annotation > [constructor_invocation >] user_type > identifier.
func (c *ktConv) hasHandlerAnn(n *tree_sitter.Node) bool {
	found := false
	var deep func(m *tree_sitter.Node)
	deep = func(m *tree_sitter.Node) {
		if found {
			return
		}
		if k := m.Kind(); k == "identifier" || k == "type_identifier" {
			if ktHandlerAnns[c.text(m)] {
				found = true
			}
			return
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
	return found
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
	case "elvis_expression", "if_expression", "when_expression":
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

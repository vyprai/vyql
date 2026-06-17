package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tscs "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// csConv walks a tree-sitter C# CST into NIR.
type csConv struct {
	src          []byte
	file         string
	key          string
	inController bool // inside an MVC controller → action params are user input
}

var csHTTPAttrs = map[string]bool{
	"HttpGet": true, "HttpPost": true, "HttpPut": true, "HttpDelete": true,
	"HttpPatch": true, "HttpHead": true, "Route": true, "ApiController": true,
}

// ExtractCSharp parses C# files into one NIR Program (one module per file).
func ExtractCSharp(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tscs.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &csConv{src: src, file: rel, key: moduleKey(root, abs, ".cs")}
			r := tree.RootNode()
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(r), Body: c.decls(r)}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *csConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *csConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *csConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "using_directive" {
			for _, ch := range namedChildren(n) {
				if k := ch.Kind(); k == "qualified_name" || k == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
					break
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

func (c *csConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *csConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "namespace_declaration", "file_scoped_namespace_declaration", "declaration_list":
		return c.decls(n) // flatten namespace / declaration-list bodies
	case "class_declaration", "struct_declaration", "interface_declaration", "record_declaration", "enum_declaration":
		prev := c.inController
		c.inController = prev || c.isController(n)
		cd := nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L,
			Bases: c.classBases(n), Members: c.classMembers(field(n, "body"))}
		c.inController = prev
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration", "local_function_statement", "operator_declaration":
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		// ASP.NET Core MVC: an action's parameters are model-bound from the request
		// (route/query/body), so they are user input. Seed each as an HttpInput
		// source at the top of the body.
		if n.Kind() == "method_declaration" && (c.inController || c.hasHTTPAttr(n)) {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		exported := c.inController || (n.Kind() == "method_declaration" && c.hasHTTPAttr(n)) ||
			((n.Kind() == "method_declaration" || n.Kind() == "constructor_declaration") && csPublic(c, n))
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, ParamTypes: paramTypes, Body: body, Loc: L, Exported: exported}}
	case "property_declaration":
		// accessor bodies may hold logic
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "field_declaration", "local_declaration_statement":
		var out []nir.Stmt
		var vd *tree_sitter.Node
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "variable_declaration" {
				vd = ch
			}
		}
		if vd == nil {
			return nil
		}
		for _, d := range namedChildren(vd) {
			if d.Kind() != "variable_declarator" {
				continue
			}
			name := field(d, "name")
			val := c.declaratorValue(d)
			if name != nil && val != nil {
				out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: c.expr(val)})
			}
		}
		return out
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement", "yield_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		// `return this;` / `return base;` — `this`/`base` are UNNAMED keyword tokens, so they
		// are not in namedChildren; capture them explicitly so `return this` carries the self ref.
		for _, ch := range children(n) {
			if k := ch.Kind(); k == "this" || k == "base" {
				return []nir.Stmt{nir.Return{Value: nir.Name{ID: "this", Loc: L}}}
			}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1); Cond nil (C# did not evaluate the predicate) -> byte-identical.
	case "if_statement":
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.csBranch(field(n, "consequence")), Else: c.csBranch(field(n, "alternative"))}}
	case "while_statement", "for_statement", "for_each_statement", "foreach_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "try_statement", "using_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.csSwitch(n)}
	case "lock_statement", "block", "checked_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

// attrNames returns the attribute identifiers on a declaration's attribute_lists.
func (c *csConv) attrNames(n *tree_sitter.Node) []string {
	var out []string
	for _, al := range namedChildren(n) {
		if al.Kind() != "attribute_list" {
			continue
		}
		for _, a := range namedChildren(al) {
			if a.Kind() == "attribute" {
				out = append(out, lastSeg(c.text(field(a, "name"))))
			}
		}
	}
	return out
}

// csPublic reports whether a C# member is part of the public API: it carries a `public`
// modifier (C# members default to private). Scopes the library param-source.
func csPublic(c *csConv, n *tree_sitter.Node) bool {
	for _, ch := range children(n) {
		if ch.Kind() == "modifier" && c.text(ch) == "public" {
			return true
		}
	}
	return false
}

func (c *csConv) hasHTTPAttr(n *tree_sitter.Node) bool {
	for _, a := range c.attrNames(n) {
		if csHTTPAttrs[a] {
			return true
		}
	}
	return false
}

// isController reports whether a class is an MVC controller (by base type,
// [ApiController]/[Route] attribute, or the *Controller naming convention).
func (c *csConv) isController(n *tree_sitter.Node) bool {
	name := c.text(field(n, "name"))
	if len(name) >= 10 && name[len(name)-10:] == "Controller" {
		return true
	}
	if c.hasHTTPAttr(n) {
		return true
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "base_list" {
			for _, b := range namedChildren(ch) {
				t := lastSeg(c.text(b))
				if t == "Controller" || t == "ControllerBase" || t == "ApiController" {
					return true
				}
			}
		}
	}
	return false
}

func (c *csConv) declaratorValue(d *tree_sitter.Node) *tree_sitter.Node {
	name := field(d, "name")
	for _, ch := range namedChildren(d) {
		if name != nil && ch.StartByte() == name.StartByte() && ch.EndByte() == name.EndByte() {
			continue
		}
		if ch.Kind() == "equals_value_clause" {
			if k := namedChildren(ch); len(k) > 0 {
				return k[len(k)-1]
			}
		}
		return ch
	}
	return nil
}

func (c *csConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	if inner.Kind() == "assignment_expression" {
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// member/element property write `si.Arguments = x` / `obj.prop = x`: model as a
		// PATH-sink call (Method="") so the assigned value flows into a write node a
		// `sink path "Arguments"`-style sink can match (e.g. ProcessStartInfo.Arguments
		// command injection). Mirrors the JS/Kotlin member-write modeling.
		if left != nil && (left.Kind() == "member_access_expression" || left.Kind() == "element_access_expression") {
			p := c.dotted(left)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: c.loc(inner)}}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// csBranch flattens one if-branch body: a `{}` block, a brace-less single statement, or a
// nested if (else-if).
func (c *csConv) csBranch(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if b.Kind() == "block" {
		var out []nir.Stmt
		for _, st := range namedChildren(b) {
			out = append(out, c.stmt(st)...)
		}
		return out
	}
	return c.stmt(b)
}

// csSwitch lowers a switch into separate case branches with labels (consecutive
// fall-through-empty sections merge into the next body) so a constant subject prunes.
func (c *csConv) csSwitch(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, sec := range namedChildren(b) {
			if sec.Kind() != "switch_section" {
				continue
			}
			var labs []nir.Expr
			var stmts []nir.Stmt
			isDefault := false
			for _, ch := range namedChildren(sec) {
				switch ch.Kind() {
				case "case_switch_label", "constant_pattern":
					lv := ch
					if k := namedChildren(ch); len(k) > 0 {
						lv = k[0]
					}
					labs = append(labs, c.expr(lv))
				case "default_switch_label":
					isDefault = true
				default:
					stmts = append(stmts, c.stmt(ch)...)
				}
			}
			if isDefault {
				deflt = append(deflt, stmts...)
				continue
			}
			pending = append(pending, labs...)
			if len(stmts) > 0 {
				cases = append(cases, stmts)
				labels = append(labels, pending)
				pending = nil
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
}

func (c *csConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "block":
				out = append(out, c.block(ch)...)
			case "else_clause", "catch_clause", "catch_declaration", "finally_clause", "accessor_list",
				"accessor_declaration", "switch_body", "switch_section", "if_statement", "declaration_list":
				walk(ch)
			case "local_declaration_statement", "expression_statement", "return_statement":
				out = append(out, c.stmt(ch)...)
			case "variable_declaration": // `using (T x = new T(...))` resource header
				for _, d := range namedChildren(ch) {
					if d.Kind() == "variable_declarator" {
						name, val := field(d, "name"), c.declaratorValue(d)
						if name != nil && val != nil {
							out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: c.expr(val)})
						}
					}
				}
			}
		}
	}
	if n.Kind() == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *csConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	// Expression-bodied member: `T M(...) => expr;` — the arrow clause is the body
	// field but holds a bare expression, so model it as an implicit return so the
	// param→return dataflow forms (without this the value is dropped).
	if block.Kind() == "arrow_expression_clause" {
		kids := namedChildren(block)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[len(kids)-1])}}
		}
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

// classBases returns the base class / interface SHORT names of a class declaration (generics
// stripped: `ParametersCollection<HeaderParameter>` -> `ParametersCollection`), for
// inheritance-aware implicit-`this` member resolution.
func (c *csConv) classBases(n *tree_sitter.Node) []string {
	var bl *tree_sitter.Node
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "base_list" {
			bl = ch
			break
		}
	}
	if bl == nil {
		return nil
	}
	var out []string
	for _, b := range namedChildren(bl) {
		if nm := lastSeg(baseTypeName(c, b)); nm != "" {
			out = append(out, nm)
		}
	}
	return out
}

// baseTypeName extracts the type name from a base-list entry, stripping generic arguments.
func baseTypeName(c *csConv, n *tree_sitter.Node) string {
	switch n.Kind() {
	case "generic_name":
		if id := field(n, "name"); id != nil {
			return c.text(id)
		}
		if k := namedChildren(n); len(k) > 0 {
			return c.text(k[0])
		}
	}
	return c.text(n)
}

// classMembers returns the data-member names (fields + properties) declared directly in a class
// body, so a bare member reference in a method resolves to `this.<member>`.
func (c *csConv) classMembers(body *tree_sitter.Node) []string {
	if body == nil {
		return nil
	}
	var out []string
	for _, m := range namedChildren(body) {
		switch m.Kind() {
		case "property_declaration", "event_declaration":
			if nm := field(m, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		case "field_declaration", "event_field_declaration":
			for _, ch := range namedChildren(m) {
				if ch.Kind() == "variable_declaration" {
					for _, d := range namedChildren(ch) {
						if d.Kind() == "variable_declarator" {
							if nm := field(d, "name"); nm != nil {
								out = append(out, c.text(nm))
							}
						}
					}
				}
			}
		}
	}
	return out
}

// lambdaParams extracts the parameter names of a C# lambda: an `implicit_parameter`/identifier
// for `x => …`, or a `parameter_list` for `(x, y) => …` / `(int x) => …`.
func (c *csConv) lambdaParams(p *tree_sitter.Node) []string {
	if p == nil {
		return nil
	}
	switch p.Kind() {
	case "parameter_list":
		var out []string
		for _, ch := range namedChildren(p) {
			switch ch.Kind() {
			case "parameter":
				if nm := field(ch, "name"); nm != nil {
					out = append(out, c.text(nm))
				}
			case "implicit_parameter", "identifier":
				out = append(out, c.text(ch))
			}
		}
		return out
	case "implicit_parameter", "identifier":
		return []string{c.text(p)}
	}
	return nil
}

func (c *csConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *csConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "parameter" {
			if nm := field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *csConv) callArgs(args *tree_sitter.Node) []nir.Expr {
	if args == nil {
		return nil
	}
	var out []nir.Expr
	for _, a := range namedChildren(args) {
		if a.Kind() == "argument" {
			if k := namedChildren(a); len(k) > 0 {
				out = append(out, c.expr(k[len(k)-1]))
			}
		} else {
			out = append(out, c.expr(a))
		}
	}
	return out
}

func (c *csConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "this", "base":
		return nir.Name{ID: c.text(n), Loc: L}
	case "this_expression", "base_expression":
		// `this` / `base` — model both as the self reference ("this") so member writes/reads and
		// `return this` resolve to the same stable self node (base.X is this.X for our purposes).
		return nir.Name{ID: "this", Loc: L}
	case "null_literal", "predefined_type":
		return nir.Const{Loc: L}
	case "integer_literal", "real_literal", "character_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "boolean_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // true/false for `val` matching
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		return nir.Const{Loc: L, Value: c.text(n)} // literal text for `val` matching
	case "interpolated_string_expression", "interpolated_verbatim_string_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "interpolation" {
				// the hole's named children are `interpolation_brace {`, the EXPRESSION, then
				// `interpolation_brace }` (+ optional alignment/format clauses). Indexing [0]
				// blindly picked up the `{` brace, dropping every interpolated value's taint —
				// so lower each real expression child (interpolation is ubiquitous in C#).
				for _, e := range namedChildren(ch) {
					switch e.Kind() {
					case "interpolation_brace", "interpolation_alignment_clause", "interpolation_format_clause":
						// punctuation / formatting — not a value
					default:
						parts = append(parts, c.expr(e))
					}
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "member_access_expression":
		return nir.Attr{Base: c.expr(field(n, "expression")), Attr: c.text(field(n, "name")), Path: c.dotted(n), Loc: L}
	case "element_access_expression":
		var key nir.Expr
		if sub := field(n, "subscript"); sub != nil {
			if k := namedChildren(sub); len(k) > 0 {
				key = c.expr(k[0])
			}
		}
		return nir.Index{Base: c.expr(field(n, "expression")), Key: key, Path: c.dotted(field(n, "expression")), Loc: L}
	case "invocation_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		return nir.Call{Callee: c.expr(fn), Args: c.callArgs(field(n, "arguments")), Path: path, Method: lastSeg(path), Loc: L}
	case "object_creation_expression":
		typ := c.text(field(n, "type"))
		args := c.callArgs(field(n, "arguments"))
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "initializer_expression" {
				args = append(args, c.expr(ch))
			}
		}
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: args, Path: typ, Method: typ, Loc: L, IsCtor: true}
	case "lambda_expression", "anonymous_method_expression":
		// C# lambdas / anonymous delegates were unlowered (fell through to a Seq), so callbacks
		// and ALL LINQ (Select/Where/ForEach/GroupBy…) dropped their bodies — no taint reached
		// the lambda param or a sink inside it. Lower as nir.Lambda so the param is routed from
		// the receiver (elementCallbackMethods) and the body is analysed.
		params := c.lambdaParams(field(n, "parameters"))
		var body []nir.Stmt
		if b := field(n, "body"); b != nil {
			if b.Kind() == "block" {
				body = c.block(b)
			} else {
				body = []nir.Stmt{nir.Return{Value: c.expr(b)}} // expression-bodied lambda
			}
		}
		return nir.Lambda{Params: params, Body: body, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "prefix_unary_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Unary{Op: c.text(n)[:1], Operand: c.expr(kids[len(kids)-1]), Loc: L}
		}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "conditional_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "await_expression", "ref_expression", "checked_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "assignment_expression":
		left := field(n, "left")
		if left != nil {
			return nir.Pair{Key: lastSeg(c.dotted(left)), Value: c.expr(field(n, "right")), Loc: L}
		}
		return c.expr(field(n, "right"))
	case "initializer_expression":
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

func (c *csConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "base", "qualified_name", "predefined_type":
		return c.text(n)
	case "member_access_expression":
		return c.dotted(field(n, "expression")) + "." + c.text(field(n, "name"))
	case "invocation_expression":
		return c.dotted(field(n, "function"))
	case "element_access_expression":
		return c.dotted(field(n, "expression")) + "[]"
	case "object_creation_expression":
		return c.text(field(n, "type"))
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	cai "github.com/vyprai/vyql/internal/extract/frontend/treesitter/grammars/cairo"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// Cairo lowers through one converter although the grammar carries two dialects:
// Cairo 0 (`func name(args): … end`, `namespace`, `@external`) and Cairo 1
// (`fn name(args) { … }`, `mod`, `#[external]`). They are one language at two
// eras — the Starknet contracts the CVE record lives in are Cairo 0, everything
// written since 2023 is Cairo 1 — so both feed the same NIR and one binding set
// can label either. What the two share structurally: a dotted callee names a
// namespace or a module rather than an object (there is no receiver expression),
// and storage is reached through generated `Var.read(...)` / `Var.write(...)`
// accessors whose dotted path a binding can name.
//
// The two dialects spell their CSTs differently where they agree in meaning —
// Cairo 0 inlines a function's body into the definition (`:` … `end` carries no
// node), Cairo 1 wraps it in a `block`; Cairo 0 marks an argument list with an
// `arguments` node, Cairo 1 inlines `parameter`s onto the definition. The
// converter reads both shapes at each such point rather than normalising the
// grammar further, because the grammar is upstream's and stays close to it.

// caiConv walks a tree-sitter Cairo CST into NIR.
type caiConv struct {
	nodeCache
	src     []byte
	file    string
	key     string
	imports []nir.Import
	// cairo1 records which dialect this file is: the grammar wraps a file in
	// cairo_0_file or cairo_1_file, and the two state visibility differently
	// (Cairo 0 has no visibility syntax, Cairo 1's `pub` is opt-in).
	cairo1 bool
}

// ExtractCairo parses .cairo files into one NIR Program.
func ExtractCairo(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(cai.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &caiConv{src: src, file: rel, key: moduleKey(root, abs, ".cairo")}
			body := c.decls(tree.RootNode())
			return nir.Module{Key: c.key, File: rel, Imports: c.imports, Body: body}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *caiConv) loc(n *tree_sitter.Node) string {
	if n == nil {
		return c.file + ":0"
	}
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *caiConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls lowers a file. Cairo wraps every statement in a `program` then a
// `cairo_0_file` / `cairo_1_file`; both are transparent here, and the dialect
// wrapper is where the file's dialect is read for its visibility rules.
func (c *caiConv) decls(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch c.kind(n) {
	case "program":
		k := c.namedChildren(n)
		if len(k) == 0 {
			return nil
		}
		return c.decls(k[0])
	case "cairo_0_file", "cairo_1_file":
		if c.kind(n) == "cairo_1_file" {
			c.cairo1 = true
		}
		return c.stmts(n)
	}
	// a root the grammar did not wrap (an empty or truncated file)
	return c.stmts(n)
}

// body lowers the statements a block node owns.
func (c *caiConv) body(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	return c.stmts(n)
}

// stmts lowers a child list, carrying `#[…]` attributes forward to the
// definition they decorate. Cairo 0 wraps a decorated definition in its own
// node; Cairo 1 states the attribute as a sibling that precedes it, so the
// same list walk serves both.
func (c *caiConv) stmts(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var pending []string
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "attribute_item":
			if p := c.attributePath(ch); p != "" {
				pending = append(pending, p)
			}
		case "decorator":
			if nm := c.identName(ch); nm != "" {
				pending = append(pending, nm)
			}
		default:
			ss := c.stmt(ch)
			if len(pending) > 0 {
				ss = c.decorate(ss, pending)
				pending = nil
			}
			out = append(out, ss...)
		}
	}
	return out
}

// decorate attaches carried attribute names to the first definition in ss.
func (c *caiConv) decorate(ss []nir.Stmt, attrs []string) []nir.Stmt {
	for i, s := range ss {
		switch v := s.(type) {
		case nir.FuncDef:
			v.Decorators = append(append([]string{}, attrs...), v.Decorators...)
			v.ParamEntries = c.paramEntries(v.Params, v.Decorators)
			ss[i] = v
			return ss
		case nir.ClassDef:
			v.Annotations = append(append([]string{}, attrs...), v.Annotations...)
			ss[i] = v
			return ss
		}
	}
	return ss
}

// attributePath is an attribute's own path (`starknet::component`, `external`),
// which is the declaration's text and nothing more — what an attribute means is
// a binding's decision.
func (c *caiConv) attributePath(n *tree_sitter.Node) string {
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "identifier", "scoped_identifier", "dotted_name", "scoped_type_identifier":
			return strings.ReplaceAll(c.text(ch), "::", ".")
		}
	}
	return ""
}

func (c *caiConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch c.kind(n) {
	// ── declarations ─────────────────────────────────────────────────────────
	case "import_statement":
		c.addImports(n)
		return nil
	case "use_declaration":
		c.addUse(n)
		return nil
	case "lang_directive", "builtin_directive", "type_definition", "type_item",
		"extern_type_statement", "alloc_locals", "hint", "label", "comment",
		"attribute_item", "decorator", "attribute_arguments":
		return nil
	case "namespace_definition", "mod_item", "impl_item", "trait_item", "enum_item",
		"struct_definition", "struct_item":
		return []nir.Stmt{c.classDef(n)}
	case "decorated_definition":
		// `@external\nfunc …` / `#[external]\nfn …`: the decoration belongs to
		// the definition it is written on and nothing else.
		var decorators []string
		var def *tree_sitter.Node
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "decorator" {
				if nm := c.identName(ch); nm != "" {
					decorators = append(decorators, nm)
				}
			} else {
				def = ch
			}
		}
		if def == nil {
			return nil
		}
		switch c.kind(def) {
		case "function_definition", "function_signature", "extern_function_statement":
			return []nir.Stmt{c.funcDef(def, decorators)}
		default:
			out := c.stmt(def)
			if len(decorators) > 0 && len(out) == 1 {
				if cd, ok := out[0].(nir.ClassDef); ok {
					cd.Annotations = decorators
					return []nir.Stmt{cd}
				}
			}
			return out
		}

	// ── statements shared by both dialects ───────────────────────────────────
	case "function_definition", "function_signature", "extern_function_statement":
		return []nir.Stmt{c.funcDef(n, nil)}
	case "expression_statement":
		return c.exprStatement(n)
	case "if_statement", "if_expression":
		return []nir.Stmt{c.ifStmt(n)}
	case "else_clause":
		// reached only when an else arm is lowered on its own
		return c.body(n)
	case "match_block", "match_arm":
		return c.body(n)
	case "block", "declaration_list", "with_statement", "attribute_statement":
		return []nir.Stmt{nir.Block{Stmts: c.body(n)}}

	// ── Cairo 0 statements ───────────────────────────────────────────────────
	case "let_binding":
		return c.letBinding(n)
	case "local_var_declaration", "temp_var_declaration":
		return c.declAssign(n)
	case "const_var_declaration":
		return c.constDecl(n)
	case "return_statement":
		if v := c.returnValue(n); v != nil {
			return []nir.Stmt{nir.Return{Value: v}}
		}
		return []nir.Stmt{nir.Return{}}
	case "assert_statement", "static_assert_statement", "inst_assert_eq":
		return c.assertStmt(n)
	case "instruction":
		return c.instruction(n)

	// ── Cairo 1 statements ───────────────────────────────────────────────────
	case "let_declaration":
		return c.letDeclaration(n)
	case "const_item":
		return c.constItem(n)
	case "return_expression":
		if v := c.returnValue(n); v != nil {
			return []nir.Stmt{nir.Return{Value: v}}
		}
		return []nir.Stmt{nir.Return{}}
	}
	// An unknown statement still carries the expressions inside it: a grammar
	// revision that adds a construct must not silence the code under it.
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		if c.isExprKind(c.kind(ch)) {
			out = append(out, nir.ExprStmt{Value: c.expr(ch)})
		} else {
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

// classDef lowers a type-shaped declaration. Cairo 0 namespaces and Cairo 1
// modules/impls are the same thing here — a named scope holding functions — so
// a caller's `Account.execute(...)` and the module that defines it meet.
func (c *caiConv) classDef(n *tree_sitter.Node) nir.Stmt {
	name := c.defName(n)
	out := nir.ClassDef{Name: name, Loc: c.loc(n), Exported: c.isExported(n, name)}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "field_declaration_list", "enum_variant_list":
			// a field list declares the type's data members, not statements
			for _, m := range c.namedChildren(ch) {
				switch c.kind(m) {
				case "field_declaration", "enum_variant", "typed_identifier":
					if name := c.identName(m); name != "" {
						out.Members = append(out.Members, name)
					}
				case "attribute_item", "visibility_modifier":
				default:
					out.Body = append(out.Body, c.stmt(m)...)
				}
			}
		case "field_declaration", "enum_variant", "typed_identifier":
			if m := c.identName(ch); m != "" {
				out.Members = append(out.Members, m)
			}
		case "block", "declaration_list":
			out.Body = append(out.Body, c.body(ch)...)
		case "type", "type_parameters", "type_arguments", "trait_bounds", "parameters",
			"arguments", "implicit_arguments", "identifier", "type_identifier",
			"scoped_type_identifier", "scoped_identifier", "generic_type", "at_type",
			"primitive_type", "abstract_type", "return_type", "attribute_item",
			"parameter", "self", "dotted_name", "visibility_modifier":
			// signature parts, not body
		default:
			out.Body = append(out.Body, c.stmt(ch)...)
		}
	}
	return out
}

// isExported records the language's own visibility statement: Cairo 0 has no
// visibility syntax (everything is importable), Cairo 1's `pub` is opt-in, and
// a leading underscore is private in both.
func (c *caiConv) isExported(n *tree_sitter.Node, name string) bool {
	if strings.HasPrefix(name, "_") {
		return false
	}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "visibility_modifier" {
			return true
		}
	}
	return !c.cairo1
}

// funcDef lowers a function of either dialect.
func (c *caiConv) funcDef(n *tree_sitter.Node, decorators []string) nir.FuncDef {
	name := c.defName(n)
	fd := nir.FuncDef{
		Name:       name,
		Loc:        c.loc(n),
		Decorators: decorators,
		Exported:   c.isExported(n, name),
		Returns:    c.returnsType(n),
	}
	fd.Params, fd.ParamTypes = c.paramsOf(n)
	fd.Body = c.funcBody(n)
	fd.ContextTokens = c.contextTokens(n, name)
	fd.ParamEntries = c.paramEntries(fd.Params, decorators)
	return fd
}

// funcBody finds the statements a definition owns. Cairo 0 inlines the body
// into the definition (`func f(args): … end` has no block node); Cairo 1 wraps
// it in a `block`. A declaration with no body (`extern fn f(...);`) has none.
func (c *caiConv) funcBody(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "identifier", "self", "parameter", "typed_identifier", "arguments",
			"parameters", "implicit_arguments", "return_type", "type_parameters",
			"type", "type_identifier", "scoped_type_identifier", "generic_type",
			"at_type", "primitive_type", "abstract_type", "trait_bounds",
			"visibility_modifier":
			// the signature, which the body statements follow directly
		case "block", "declaration_list":
			// Cairo 1 wraps what Cairo 0 inlines; both lower to the same flat
			// body so a FuncDef's shape does not depend on its dialect.
			out = append(out, c.body(ch)...)
		default:
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

// paramsOf collects a function's declared parameters with their types. Cairo 0
// states them as `typed_identifier`s inside an `arguments` node; Cairo 1
// inlines `parameter`s onto the definition itself. Implicit arguments
// (`{syscall_ptr: felt*}`) are deliberately not parameters: they are builtin
// segments the compiler threads, not values a caller supplies, so making them
// parameters would offer every binding a source that never carries one. They
// reach ContextTokens instead.
func (c *caiConv) paramsOf(n *tree_sitter.Node) ([]string, map[string]string) {
	var names []string
	types := map[string]string{}
	add := func(p *tree_sitter.Node) {
		nm := c.identName(p)
		if nm == "" || nm == "self" {
			return
		}
		names = append(names, nm)
		putParamType(types, nm, c.typeText(p))
	}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "arguments", "parameters":
			for _, p := range c.namedChildren(ch) {
				add(p)
			}
		case "parameter", "typed_identifier":
			add(ch)
		}
	}
	return names, types
}

// contextTokens records what the definition itself states: the language, its
// name, and the implicit builtin segments it asks for. A binding that needs
// "this function allocates its own signature segment instead of taking the
// OS-supplied one" finds the difference here.
func (c *caiConv) contextTokens(n *tree_sitter.Node, name string) []string {
	out := []string{"lang=cairo", "name=" + name, "function_name:" + name}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) != "implicit_arguments" {
			continue
		}
		for _, p := range c.namedChildren(ch) {
			if nm := c.identName(p); nm != "" {
				out = append(out, "implicit:"+nm)
			}
		}
	}
	return out
}

// paramEntries records that a decorated function's parameters are populated
// from outside the module. Which decorator makes that an entry point — and what
// an entry point then means — is a binding's decision; the tokens only state
// what the source says.
func (c *caiConv) paramEntries(params, decorators []string) []nir.ParamEntry {
	if len(decorators) == 0 || len(params) == 0 {
		return nil
	}
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := make([]string, 0, len(decorators)+2)
		for _, d := range decorators {
			tokens = append(tokens, "decorator:"+d)
		}
		tokens = append(tokens, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

// ── statements ──────────────────────────────────────────────────────────────

// exprStatement lowers a bare expression. An assignment in that position is a
// statement (Cairo has no expression-assignment at statement level worth
// keeping as a value).
func (c *caiConv) exprStatement(n *tree_sitter.Node) []nir.Stmt {
	k := c.namedChildren(n)
	if len(k) == 0 {
		return nil
	}
	last := k[len(k)-1]
	switch c.kind(last) {
	case "assignment_expression":
		if left := c.field(last, "left"); left != nil {
			if tgt := c.dotted(left); tgt != "" && tgt != "?" {
				return []nir.Stmt{nir.Assign{Targets: []string{tgt}, Value: c.expr(c.field(last, "right")), Loc: c.loc(n)}}
			}
		}
	case "compound_assignment_expression":
		if left := c.field(last, "left"); left != nil {
			if tgt := c.dotted(left); tgt != "" && tgt != "?" {
				return []nir.Stmt{nir.AugAssign{Target: tgt, Value: c.expr(c.field(last, "right")), Loc: c.loc(n)}}
			}
		}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(last)}}
}

// letBinding lowers Cairo 0's `let (a: felt, b: felt) = f(x)`, binding every
// name the call returns, exactly as a multi-assign in any other frontend does.
// The grammar inlines the parenthesised binding list, so the targets sit
// directly on the node alongside the value.
func (c *caiConv) letBinding(n *tree_sitter.Node) []nir.Stmt {
	var targets []string
	var val *tree_sitter.Node
	typ := ""
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "typed_identifier":
			if nm := c.identName(ch); nm != "" {
				targets = append(targets, nm)
				typ = c.typeText(ch)
			}
		case "call_instruction":
			val = ch
		default:
			if c.isExprKind(c.kind(ch)) {
				val = ch
			}
		}
	}
	if len(targets) == 0 || val == nil {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: targets, Value: c.expr(val), Type: typ, Decl: true, Loc: c.loc(n)}}
}

// declAssign lowers Cairo 0's `local x: felt = 1` / `tempvar x = 1`.
func (c *caiConv) declAssign(n *tree_sitter.Node) []nir.Stmt {
	ti := c.field(n, "name")
	if ti == nil {
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "typed_identifier" {
				ti = ch
				break
			}
		}
	}
	if ti == nil {
		return nil
	}
	target := c.identName(ti)
	if target == "" {
		return nil
	}
	var val nir.Expr
	for _, ch := range c.namedChildren(n) {
		if ch != ti && c.isExprKind(c.kind(ch)) {
			val = c.expr(ch)
			break
		}
	}
	return []nir.Stmt{nir.Assign{Targets: []string{target}, Value: val, Type: c.typeText(ti), Decl: true, Loc: c.loc(n)}}
}

// constDecl lowers Cairo 0's `const NAME = value`.
func (c *caiConv) constDecl(n *tree_sitter.Node) []nir.Stmt {
	k := c.namedChildren(n)
	if len(k) < 2 {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: []string{c.text(k[0])}, Value: c.expr(k[len(k)-1]), Decl: true, Loc: c.loc(n)}}
}

// letDeclaration lowers Cairo 1's `let mut pattern: type = value;`.
func (c *caiConv) letDeclaration(n *tree_sitter.Node) []nir.Stmt {
	pattern := c.field(n, "pattern")
	if pattern == nil {
		return nil
	}
	var targets []string
	switch c.kind(pattern) {
	case "identifier", "field_identifier", "type_identifier":
		targets = []string{c.text(pattern)}
	default:
		for _, ch := range c.namedChildren(pattern) {
			switch c.kind(ch) {
			case "identifier", "field_identifier", "type_identifier":
				targets = append(targets, c.text(ch))
			}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	typ := c.text(c.field(n, "type"))
	value := c.expr(c.field(n, "value"))
	return []nir.Stmt{nir.Assign{Targets: targets, Value: value, Type: typ, Decl: true, Loc: c.loc(n)}}
}

// constItem lowers Cairo 1's `const NAME: type = value;`.
func (c *caiConv) constItem(n *tree_sitter.Node) []nir.Stmt {
	name := c.identName(n)
	if name == "" {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(c.field(n, "value")), Type: c.text(c.field(n, "type")), Decl: true, Loc: c.loc(n)}}
}

// returnValue finds the value a return carries; Cairo 0 spells a bare `return()`
// and Cairo 1 a bare `return`, both of which return nothing.
func (c *caiConv) returnValue(n *tree_sitter.Node) nir.Expr {
	for _, ch := range c.namedChildren(n) {
		if c.isExprKind(c.kind(ch)) {
			return c.expr(ch)
		}
	}
	return nil
}

// assertStmt lowers `assert a = b`. Cairo's assert aborts the transaction when
// the two sides differ, but it is also how memory is written (`assert [calls] =
// Call(...)`), so the frontend states the comparison and claims nothing about
// what it proves — whether an equality that holds is a control is a binding's
// question.
func (c *caiConv) assertStmt(n *tree_sitter.Node) []nir.Stmt {
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		if c.isExprKind(c.kind(ch)) {
			parts = append(parts, c.expr(ch))
		}
	}
	if len(parts) < 2 {
		return nil
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.BinOp{Op: "==", Left: parts[0], Right: parts[1], Loc: c.loc(n)}}}
}

// ifStmt lowers a branch. Cairo 0 writes `if cond: … else: … end` with the arms
// inline; Cairo 1 marks them with condition/consequence/alternative fields. The
// else arm reaches NIR as an else_clause in both, which is the one shape the
// grammar patch upstream arranges.
func (c *caiConv) ifStmt(n *tree_sitter.Node) nir.Stmt {
	out := nir.If{Loc: c.loc(n)}
	if cond := c.field(n, "condition"); cond != nil {
		out.Cond = c.expr(cond)
		out.Then = c.stmt(c.field(n, "consequence"))
		out.Else = c.stmt(c.field(n, "alternative"))
		return out
	}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "else_clause":
			out.Else = append(out.Else, c.stmt(ch)...)
		case "match_arm", "match_pattern":
			// a match arm's pattern is not a statement
		default:
			if out.Cond == nil && c.isExprKind(c.kind(ch)) {
				out.Cond = c.expr(ch)
				continue
			}
			out.Then = append(out.Then, c.stmt(ch)...)
		}
	}
	return out
}

// instruction lowers Cairo 0's assembly instructions. Only `call` names another
// function; the rest move registers and carry no dataflow a binding can name.
func (c *caiConv) instruction(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "call_instruction":
			if k := c.namedChildren(ch); len(k) > 0 {
				out = append(out, nir.ExprStmt{Value: c.expr(k[len(k)-1])})
			}
		case "inst_assert_eq":
			out = append(out, c.assertStmt(ch)...)
		}
	}
	return out
}

// ── expressions ─────────────────────────────────────────────────────────────

func (c *caiConv) isExprKind(k string) bool {
	switch k {
	case "identifier", "field_identifier", "type_identifier", "self", "number", "short_string",
		"string", "boolean", "member_expression", "field_expression", "scoped_identifier",
		"dotted_name", "subscript_expression", "index_expression", "call_expression",
		"generic_function", "binary_expression", "unary_expression", "assignment_expression",
		"compound_assignment_expression", "tuple_expression", "struct_expression",
		"deref_expression", "cast_expression", "hint_expression", "register",
		"parenthesized_expression", "unit_expression", "at_expression", "at_type",
		"if_expression", "match_expression", "loop_expression", "try_expression",
		"return_expression", "block", "call_instruction":
		return true
	}
	return false
}

func (c *caiConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: c.file + ":0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "self", "register", "dotted_name":
		return nir.Name{ID: c.text(n), Loc: L}
	case "number", "short_string", "string", "boolean":
		return nir.Const{Loc: L, Value: caiLiteral(c.text(n))}
	case "scoped_identifier":
		return nir.Name{ID: strings.ReplaceAll(c.text(n), "::", "."), Loc: L}
	case "member_expression":
		k := c.namedChildren(n)
		if len(k) < 2 {
			return c.expr(c.lastNamed(n))
		}
		return nir.Attr{Base: c.expr(k[0]), Attr: c.text(k[len(k)-1]), Path: c.dotted(n), Loc: L}
	case "field_expression":
		return nir.Attr{Base: c.expr(c.field(n, "value")), Attr: c.text(c.field(n, "field")), Path: c.dotted(n), Loc: L}
	case "subscript_expression", "index_expression":
		return c.indexExpr(n, L)
	case "call_expression":
		return c.call(n)
	case "generic_function":
		// `f::<T>(args)` — the type argument selects an instance, not a value.
		if f := c.field(n, "function"); f != nil {
			return c.expr(f)
		}
		return c.expr(c.lastNamed(n))
	case "binary_expression":
		left, right := c.field(n, "left"), c.field(n, "right")
		if left == nil || right == nil {
			if k := c.namedChildren(n); len(k) >= 2 {
				left, right = k[0], k[len(k)-1]
			}
		}
		return nir.BinOp{Op: c.operator(n), Left: c.expr(left), Right: c.expr(right), Loc: L}
	case "unary_expression":
		operand := c.field(n, "operand")
		if operand == nil {
			operand = c.lastNamed(n)
		}
		return nir.Unary{Op: c.operator(n), Operand: c.expr(operand), Loc: L}
	case "assignment_expression":
		// A named argument (`f(a=1)` in Cairo 0's `{}` block): the key reaches
		// value matching, the value keeps the taint.
		if key := c.dotted(c.field(n, "left")); key != "" && key != "?" {
			return nir.Pair{Key: key, Value: c.expr(c.field(n, "right")), Loc: L}
		}
		return c.expr(c.field(n, "right"))
	case "compound_assignment_expression":
		return c.expr(c.field(n, "right"))
	case "tuple_expression", "unit_expression":
		return nir.Seq{Parts: c.exprs(n), Loc: L}
	case "struct_expression":
		return c.structExpr(n, L)
	case "deref_expression", "cast_expression", "parenthesized_expression",
		"at_expression", "try_expression":
		// the first child is the value; a trailing type or `?` is not
		if k := c.namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[0])}
		}
		return nir.Const{Loc: L}
	case "hint_expression":
		return nir.Const{Loc: L}
	case "if_expression", "match_expression", "loop_expression", "block", "return_expression":
		// A block-valued expression flows whatever its arms flow; the arms are
		// an over-approximation, which is the direction taint analysis takes.
		return nir.Seq{Parts: c.exprs(n), Loc: L}
	case "call_instruction":
		if k := c.namedChildren(n); len(k) > 0 {
			return c.expr(k[len(k)-1])
		}
		return nir.Const{Loc: L}
	}
	if k := c.namedChildren(n); len(k) == 1 {
		return c.expr(k[0])
	}
	return nir.Seq{Parts: c.exprs(n), Loc: L}
}

func (c *caiConv) exprs(n *tree_sitter.Node) []nir.Expr {
	var out []nir.Expr
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.expr(ch))
	}
	return out
}

// operator reads a binary or unary operator, whose token the grammar leaves
// anonymous more often than it names it.
func (c *caiConv) operator(n *tree_sitter.Node) string {
	if op := c.field(n, "operator"); op != nil {
		return c.text(op)
	}
	for _, ch := range c.children(n) {
		if t := c.text(ch); isCairoOperator(t) {
			return t
		}
	}
	return ""
}

func (c *caiConv) indexExpr(n *tree_sitter.Node, L string) nir.Expr {
	base, key := c.field(n, "base"), c.field(n, "index")
	if base == nil {
		k := c.namedChildren(n)
		if len(k) >= 2 {
			base, key = k[0], k[len(k)-1]
		} else if len(k) == 1 {
			base = k[0]
		}
	}
	return nir.Index{Base: c.expr(base), Key: c.expr(key), Path: c.dotted(base), Loc: L}
}

// structExpr lowers `Transfer { from, to, value: amount }`: a construction
// whose fields are the arguments a binding sees.
func (c *caiConv) structExpr(n *tree_sitter.Node, L string) nir.Expr {
	typ := c.field(n, "name")
	if typ == nil {
		typ = c.field(n, "type")
	}
	path := c.dotted(typ)
	var args []nir.Expr
	for _, list := range []*tree_sitter.Node{c.field(n, "body"), c.field(n, "value")} {
		if list == nil {
			continue
		}
		for _, ch := range c.namedChildren(list) {
			switch c.kind(ch) {
			case "field_initializer":
				if key := c.text(c.field(ch, "name")); key != "" {
					args = append(args, nir.Pair{Key: key, Value: c.expr(c.field(ch, "value")), Loc: c.loc(ch)})
				} else {
					args = append(args, c.expr(c.field(ch, "value")))
				}
			default:
				args = append(args, c.expr(ch))
			}
		}
	}
	return nir.Call{Callee: c.expr(typ), Args: args, IsCtor: true, Path: path, Method: lastSeg(path), Loc: L}
}

// call lowers a call. The callee's dotted path (`Balance.read`,
// `ERC165.register_interface`) is what a binding names, so it is computed even
// when the callee is an expression the lowerer will not resolve.
func (c *caiConv) call(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	callee := c.field(n, "function")
	if callee == nil {
		k := c.namedChildren(n)
		if len(k) == 0 {
			return nir.Const{Loc: L}
		}
		callee = k[0]
	}
	calleeID := callee.Id()
	path := c.dotted(callee)
	var args []nir.Expr
	// Cairo 1 marks a named argument with a `name` field on its key
	// (`f(x: 1)`); the field belongs to a child, so the walk runs over child
	// indices rather than the named-children slice. Cairo 0 instead collects
	// named arguments as assignment expressions in a `{}` block before the
	// argument tuple, which expr lowers to the same Pair.
	pending := ""
	for i, ch := range c.children(n) {
		if !ch.IsNamed() || ch.Id() == calleeID {
			continue
		}
		if c.kind(ch) == "type_arguments" || c.kind(ch) == "type_parameters" {
			continue
		}
		if n.FieldNameForChild(uint32(i)) == "name" {
			// the key of the argument that follows, not an argument itself
			pending = c.dotted(ch)
			continue
		}
		if c.kind(ch) == "tuple_expression" && pending == "" {
			args = append(args, c.exprs(ch)...)
			continue
		}
		key := pending
		pending = ""
		v := c.expr(ch)
		if key != "" {
			args = append(args, nir.Pair{Key: key, Value: v, Loc: c.loc(ch)})
		} else {
			args = append(args, v)
		}
	}
	return nir.Call{Callee: c.expr(callee), Args: args, Path: path, Method: lastSeg(path), Loc: L}
}

// dotted renders a callee path: `Namespace_Var.write`, `split_felt`. A dotted
// name in Cairo names a module or namespace rather than an object, so the whole
// chain is the identity a binding matches.
func (c *caiConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch c.kind(n) {
	case "identifier", "field_identifier", "type_identifier", "register", "primitive_type", "self":
		return c.text(n)
	case "dotted_name":
		return strings.ReplaceAll(c.text(n), " ", "")
	case "scoped_identifier", "scoped_type_identifier", "namespace_name":
		return strings.ReplaceAll(c.text(n), "::", ".")
	case "member_expression", "field_expression":
		k := c.namedChildren(n)
		if len(k) >= 2 {
			return c.dotted(k[0]) + "." + c.text(k[len(k)-1])
		}
	case "subscript_expression", "index_expression":
		if base := c.field(n, "base"); base != nil {
			return c.dotted(base) + "[]"
		}
		if k := c.namedChildren(n); len(k) > 0 {
			return c.dotted(k[0]) + "[]"
		}
	case "call_expression":
		if f := c.field(n, "function"); f != nil {
			return c.dotted(f)
		}
		if k := c.namedChildren(n); len(k) > 0 {
			return c.dotted(k[0])
		}
	case "generic_function":
		if f := c.field(n, "function"); f != nil {
			return c.dotted(f)
		}
	case "struct_expression", "cast_expression":
		if t := c.field(n, "type"); t != nil {
			return c.dotted(t)
		}
		if t := c.field(n, "name"); t != nil {
			return c.dotted(t)
		}
	case "generic_type", "generic_type_with_turbofish":
		if t := c.field(n, "name"); t != nil {
			return c.dotted(t)
		}
	case "parenthesized_expression", "deref_expression":
		if k := c.namedChildren(n); len(k) > 0 {
			return c.dotted(k[0])
		}
	}
	if t := c.text(n); strings.ContainsAny(t, "._") && !strings.ContainsAny(t, " \n([{=") {
		return t
	}
	return "?"
}

// ── declaration details ─────────────────────────────────────────────────────

// identName is a declaration's own name: the `name` field where the grammar
// marks one, else the identifier it is spelled with. A `typed_identifier`
// (`local ecdsa_ptr : SignatureBuiltin*`) is named by the identifier it starts
// with, which is not its last child.
func (c *caiConv) identName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if nm := c.field(n, "name"); nm != nil {
		return c.text(nm)
	}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "identifier", "field_identifier", "type_identifier":
			return c.text(ch)
		}
	}
	return ""
}

// defName is a declaration's own name. An impl block spells no name of its own
// (`impl ERC20<T> of IERC20<T>`), so its first type operand stands in: that is
// the name a caller writes to reach the functions inside it.
func (c *caiConv) defName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if c.kind(n) == "impl_item" {
		for _, ch := range c.namedChildren(n) {
			switch c.kind(ch) {
			case "type", "scoped_type_identifier", "generic_type", "type_identifier", "at_type", "abstract_type":
				s := c.text(ch)
				if i := strings.IndexByte(s, '<'); i >= 0 {
					s = s[:i]
				}
				return lastSeg(strings.ReplaceAll(strings.TrimSpace(s), "::", "."))
			}
		}
		return ""
	}
	return c.identName(n)
}

// lastNamed is the last named child.
func (c *caiConv) lastNamed(n *tree_sitter.Node) *tree_sitter.Node {
	k := c.namedChildren(n)
	if len(k) == 0 {
		return nil
	}
	return k[len(k)-1]
}

// typeText is a declared type's own text, stripped of the name it annotates.
func (c *caiConv) typeText(n *tree_sitter.Node) string {
	if t := c.field(n, "type"); t != nil {
		return c.text(t)
	}
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "type", "builtin_type", "pointer_type", "tuple_type", "named_type",
			"generic_type", "primitive_type", "at_type", "abstract_type",
			"type_identifier", "scoped_type_identifier":
			return c.text(ch)
		}
	}
	return ""
}

// returnsType is the declared type of a function's first result. Cairo 0 names
// it inside a tuple type (`-> (res: felt)` → felt); Cairo 1 states it directly
// (`-> u256`) as a bare type child of the definition.
func (c *caiConv) returnsType(n *tree_sitter.Node) string {
	rt := c.field(n, "returns")
	if rt == nil {
		for _, ch := range c.namedChildren(n) {
			if c.kind(ch) == "return_type" {
				rt = ch
				break
			}
		}
	}
	if rt == nil {
		// Cairo 1 inlines the signature, so the result type sits on the
		// definition after the parameters.
		k := c.namedChildren(n)
		for i := len(k) - 1; i >= 0; i-- {
			if c.isTypeKind(c.kind(k[i])) {
				return c.firstTypeName(k[i])
			}
		}
		return ""
	}
	return c.firstTypeName(rt)
}

// isTypeKind reports whether a node kind is a type position.
func (c *caiConv) isTypeKind(k string) bool {
	switch k {
	case "type", "return_type", "tuple_type", "named_type", "builtin_type", "pointer_type",
		"type_identifier", "scoped_type_identifier", "generic_type", "primitive_type",
		"at_type", "abstract_type", "unit_type":
		return true
	}
	return false
}

// firstTypeName walks a declared result type to the type name of the first
// result it states: Cairo 0 nests it (`-> (res: felt)` → felt), Cairo 1 states
// it directly (`-> u256`).
func (c *caiConv) firstTypeName(rt *tree_sitter.Node) string {
	if rt == nil {
		return ""
	}
	switch c.kind(rt) {
	case "return_type", "tuple_type", "type", "at_type", "abstract_type":
		// a wrapper: the name is what it wraps, starting at the first result
		for _, ch := range c.namedChildren(rt) {
			if t := c.firstTypeName(ch); t != "" {
				return t
			}
		}
		return ""
	case "named_type":
		return c.typeText(rt)
	case "identifier", "type_identifier", "builtin_type", "pointer_type", "primitive_type",
		"scoped_type_identifier", "generic_type":
		return c.text(rt)
	}
	return ""
}

// ── imports ─────────────────────────────────────────────────────────────────

// addImports records Cairo 0's `from a.b import c, d`.
func (c *caiConv) addImports(n *tree_sitter.Node) {
	mod := c.field(n, "module_name")
	modID := uintptr(0)
	if mod != nil {
		modID = mod.Id()
	}
	module := strings.ReplaceAll(c.text(mod), " ", "")
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "dotted_name", "aliased_import":
			if ch.Id() == modID {
				continue
			}
			nm := strings.ReplaceAll(c.text(orSelf(c.field(ch, "name"), ch)), " ", "")
			if nm == "" {
				continue
			}
			c.imports = append(c.imports, nir.Import{Local: lastSeg(nm), Module: module, Symbol: lastSeg(nm)})
		}
	}
}

// addUse records Cairo 1's `use a::b::{c, d as e};`, whose clause nests in ways
// the CST does not make worth walking for a name list.
func (c *caiConv) addUse(n *tree_sitter.Node) {
	text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(c.text(n), "use")), ";"))
	if i := strings.LastIndex(text, " as "); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if text == "" {
		return
	}
	path, symbols := text, ""
	if i := strings.LastIndex(text, "::"); i >= 0 && strings.Contains(text[i:], "{") {
		path, symbols = text[:i], strings.Trim(text[i:], ":")
	}
	path = strings.ReplaceAll(strings.TrimSpace(strings.Trim(path, "{}")), "::", ".")
	for _, sym := range strings.Split(strings.Trim(symbols, "{}"), ",") {
		sym = strings.TrimSpace(sym)
		if sym == "" {
			continue
		}
		c.imports = append(c.imports, nir.Import{Local: sym, Module: path, Symbol: sym})
	}
	if symbols != "" {
		return
	}
	c.imports = append(c.imports, nir.Import{Local: lastSeg(path), Module: path, Symbol: lastSeg(path)})
}

func isCairoOperator(t string) bool {
	switch t {
	case "+", "-", "*", "/", "%", "**", "==", "!=", "<", "<=", ">", ">=",
		"&&", "||", "&", "|", "^", "<<", ">>", "!", "~", "and", "new":
		return true
	}
	return false
}

// caiLiteral strips the quotes a short string or string literal carries, so
// value matchers see the text a Cairo source wrote.
func caiLiteral(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if q := raw[0]; (q == '"' || q == '\'') && raw[len(raw)-1] == q {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// jvConv walks a tree-sitter Java CST into NIR.
type jvConv struct {
	nodeCache
	src                []byte
	root               string
	file               string
	key                string
	classParamTokens   []string
	classContextTokens []string
	// enumBases holds the enclosing enum declaration's name while its body is
	// lowered, so a constant-specific body can record the enum type as its base.
	enumBases []string
	// fieldInitTokens holds the enclosing class body's field-initializer
	// tokens while that body is lowered. It is saved and restored per class
	// rather than accumulated, unlike classContextTokens: a nested class does
	// not hold its enclosing class's instance fields, so the enclosing body's
	// field facts must not reach the nested class's members.
	fieldInitTokens []string
	// hoisted collects statements extracted out of an expression position —
	// the body of an anonymous class (`new T() { ... }`). They are appended
	// after the statement containing the expression by stmt, so the class's
	// members become real declarations in the enclosing statement list.
	hoisted []nir.Stmt
}

// javaPublic reports whether a method/constructor is part of the public API surface:
// it carries a `public` modifier (package-private/private/protected are not the API a
// library exposes to arbitrary callers). Used to scope the library param-source.
func (c *jvConv) javaPublic(n *tree_sitter.Node) bool {
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "modifiers" {
			t := c.text(ch)
			if strings.Contains(t, "private") || strings.Contains(t, "protected") {
				return false
			}
			return strings.Contains(t, "public")
		}
	}
	return false
}

// ExtractJava parses Java files into one NIR Program (one module per file, keyed
// by source-root-relative dotted path).
func ExtractJava(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsjava.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &jvConv{src: src, root: root, file: rel, key: moduleKey(root, abs, ".java")}
			r := tree.RootNode()
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(r), Body: c.decls(r)}, true
		})
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *jvConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *jvConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// simpleTypeName returns a bare user-class type name from a declaration's `type`
// node — e.g. `UserService` (from `UserService`, `com.x.UserService`, or
// `List<UserService>` it returns the head). Primitives and `String`/`var` yield "".
func (c *jvConv) simpleTypeName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch c.kind(n) {
	case "type_identifier", "scoped_type_identifier":
		t := c.text(n)
		if i := strings.LastIndex(t, "."); i >= 0 {
			t = t[i+1:]
		}
		switch t {
		case "String", "Object", "Integer", "Long", "Boolean", "Double", "Float", "var":
			return ""
		}
		return t
	case "generic_type":
		if k := c.namedChildren(n); len(k) > 0 {
			return c.simpleTypeName(k[0])
		}
	}
	return ""
}

func (c *jvConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if c.kind(n) == "import_declaration" {
			for _, ch := range c.namedChildren(n) {
				if c.kind(ch) == "scoped_identifier" || c.kind(ch) == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
				}
			}
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return out
}

// decls lowers top-level + class-member declarations.
func (c *jvConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

// stmt converts one statement, appending any statements hoisted out of it —
// today the bodies of anonymous classes created inside it — right after it, so
// code declared in an expression position lands in the enclosing statement list
// instead of being dropped.
func (c *jvConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	out := c.stmtOne(n)
	if len(c.hoisted) > 0 {
		out = append(out, c.hoisted...)
		c.hoisted = nil
	}
	return out
}

func (c *jvConv) stmtOne(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch c.kind(n) {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		name := c.text(c.field(n, "name"))
		bases := c.jvClassBases(n)
		prevParams := c.classParamTokens
		prevContext := c.classContextTokens
		prevEnumBases := c.enumBases
		if c.kind(n) == "enum_declaration" {
			// a constant-specific body subclasses the enum type itself
			c.enumBases = []string{name}
		}
		c.classParamTokens = append(append([]string{}, prevParams...), c.jvAnnotationTokens(n, "class_annotation:")...)
		c.classContextTokens = append(append([]string{}, prevContext...), javaClassContextTokens(name, bases)...)
		c.classContextTokens = append(c.classContextTokens, c.jvModifierTokens(n, "class_modifier:")...)
		prevFieldInit := c.fieldInitTokens
		c.fieldInitTokens = c.jvFieldInitTokens(c.field(n, "body"), c.kind(n) == "interface_declaration")
		cd := nir.ClassDef{Name: name, Body: c.decls(c.field(n, "body")), Loc: L, Bases: bases}
		c.classParamTokens = prevParams
		c.classContextTokens = prevContext
		c.fieldInitTokens = prevFieldInit
		c.enumBases = prevEnumBases
		return []nir.Stmt{cd}
	case "enum_constant":
		// `CONST(args) { members }` — a constant-specific class body, an
		// anonymous subclass body of the enum type. decls feeds every named
		// child of an enum body to this switch, and without a case the body's
		// members produce no FuncDef, no call nodes and no context tokens.
		// Lower it as a class named for the constant, so the members carry the
		// class context a named nested class gets. Constants without a body
		// hold no code. The constant's arguments stay unlowered: they are an
		// initializer expression, not statements of the body.
		name := c.text(c.field(n, "name"))
		body := c.field(n, "body")
		if name == "" || body == nil {
			return nil
		}
		prevContext := c.classContextTokens
		c.classContextTokens = append(append([]string{}, prevContext...), javaClassContextTokens(name, c.enumBases)...)
		prevFieldInit := c.fieldInitTokens
		c.fieldInitTokens = c.jvFieldInitTokens(body, false)
		cd := nir.ClassDef{Name: name, Body: c.decls(body), Loc: L, Bases: c.enumBases}
		c.classContextTokens = prevContext
		c.fieldInitTokens = prevFieldInit
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration":
		name := c.text(c.field(n, "name"))
		paramsNode := c.field(n, "parameters")
		params := c.params(paramsNode)
		paramTypes := c.paramTypes(paramsNode)
		body := c.block(c.field(n, "body"))
		body = append(body, c.jvIntegerSizeArithmeticObservations(n)...)
		body = append(body, c.jvUnverifiedKeyIDPathResolveObservations(n)...)
		annotationTokens := c.jvAnnotationTokens(n, "annotation:")
		tokens := append([]string{}, c.classParamTokens...)
		tokens = append(tokens, annotationTokens...)
		contextTokens := append([]string{}, c.classContextTokens...)
		contextTokens = append(contextTokens, c.fieldInitTokens...)
		contextTokens = append(contextTokens, annotationTokens...)
		contextTokens = append(contextTokens, c.jvModifierTokens(n, "function_modifier:")...)
		contextTokens = append(contextTokens, c.jvSensitiveMetadataExportTokens(n)...)
		contextTokens = append(contextTokens, c.jvFunctionTokens(name, n, params, paramTypes)...)
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L,
			ContextTokens: contextTokens,
			ParamEntries:  c.jvParamEntries(name, params, paramTypes, tokens, c.jvParamAnnotationTokens(paramsNode)), Exported: c.javaPublic(n)}}
	case "field_declaration", "local_variable_declaration":
		var out []nir.Stmt
		declType := c.simpleTypeName(c.field(n, "type")) // declared class type, for cross-file resolution
		for _, d := range c.namedChildren(n) {
			if c.kind(d) == "variable_declarator" {
				name := c.field(d, "name")
				val := c.field(d, "value")
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v, Type: declType, Decl: true})
				}
			}
		}
		return out
	case "expression_statement":
		kids := c.namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement":
		kids := c.namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	// branch-structured (B1). Java did not evaluate the condition before, so Cond stays
	// nil → the flattened node set is byte-identical.
	case "if_statement":
		// Separate Then/Else branches (not a flattened single list) so the join-merge
		// keeps a value tainted on one path even when the other path overwrites it with a
		// constant (`if (c) x = src(); else x = "safe";`). A nested if/else in either
		// branch is structured by c.stmt (proper else-if chaining).
		return []nir.Stmt{nir.If{Cond: c.expr(c.field(n, "condition")), Then: c.branchBody(c.field(n, "consequence")), Else: c.branchBody(c.field(n, "alternative"))}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "enhanced_for_statement":
		// `for (T x : coll)` — bind the loop variable to the iterable so a tainted
		// collection taints each element (flow-approximate element-of).
		body := c.collectBlocks(n)
		if nm, val := c.field(n, "name"), c.field(n, "value"); nm != nil && val != nil {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{c.text(nm)}, Value: c.expr(val)}}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "try_statement", "try_with_resources_statement":
		return []nir.Stmt{c.tryStmt(n)}
	case "switch_expression":
		// each `case` group is a separate Switch branch so the join-merge keeps a value
		// tainted on one arm even when another arm overwrites it (`case 'A': bar = src();`
		// vs `case 'B': bar = "safe";`). Classic colon-form; arrow/yield form has no
		// statement groups and falls back to a flat Block.
		var cases [][]nir.Stmt
		var labels [][]nir.Expr
		var deflt []nir.Stmt
		var hasGroups bool
		var pending []nir.Expr // labels of empty (fall-through) case groups, merged into the next body
		for _, blk := range children(n) {
			if c.kind(blk) != "switch_block" {
				continue
			}
			for _, grp := range children(blk) {
				if c.kind(grp) != "switch_block_statement_group" {
					continue
				}
				hasGroups = true
				var stmts []nir.Stmt
				var labs []nir.Expr
				isDefault := false
				for _, ch := range children(grp) {
					if c.kind(ch) == "switch_label" {
						if strings.Contains(c.text(ch), "default") {
							isDefault = true
						} else if lk := c.namedChildren(ch); len(lk) > 0 {
							labs = append(labs, c.expr(lk[0])) // the case's label value(s)
						}
						continue
					}
					stmts = append(stmts, c.stmt(ch)...)
				}
				if isDefault {
					deflt = append(deflt, stmts...)
					continue
				}
				pending = append(pending, labs...)
				if len(stmts) > 0 { // body present — flush the accumulated fall-through labels with it
					cases = append(cases, stmts)
					labels = append(labels, pending)
					pending = nil
				}
			}
		}
		if hasGroups {
			return []nir.Stmt{nir.Switch{Subject: c.expr(c.field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}}
		}
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "block", "synchronized_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	case "static_initializer", "constructor_body":
		return []nir.Stmt{nir.Block{Stmts: c.block(n)}}
	}
	return nil
}

func (c *jvConv) exprStmt(inner *tree_sitter.Node) []nir.Stmt {
	switch c.kind(inner) {
	case "assignment_expression":
		left := c.field(inner, "left")
		right := c.expr(c.field(inner, "right"))
		if left != nil && c.kind(left) == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

// branchBody flattens a single if-branch body: a `{}` block, a brace-less single
// statement, or a nested control statement (structured by c.stmt).
func (c *jvConv) branchBody(b *tree_sitter.Node) []nir.Stmt {
	if b == nil {
		return nil
	}
	if c.kind(b) == "block" {
		return c.block(b)
	}
	return c.stmt(b)
}

func (c *jvConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// handled reports whether a body-position node was already collected/flattened by
	// the children walk below (a brace block, or a nested if/else flattened into this
	// same list). Used to avoid double-lowering when picking up brace-less bodies.
	handled := func(k string) bool {
		switch k {
		case "block", "constructor_body", "switch_block", "switch_block_statement_group",
			"catch_clause", "finally_clause", "resource_specification", "if_statement", "else":
			return true
		}
		return false
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch c.kind(ch) {
			case "block", "constructor_body":
				out = append(out, c.block(ch)...)
			case "switch_block", "switch_block_statement_group", "catch_clause", "finally_clause",
				"resource_specification", "if_statement", "else":
				walk(ch)
			case "resource":
				// try-with-resources `try (T x = new FileInputStream(path); …)` — lower the
				// resource initializer (often a file/stream sink) and bind its variable.
				if val := c.field(ch, "value"); val != nil {
					v := c.expr(val)
					if nm := c.field(ch, "name"); nm != nil {
						out = append(out, nir.Assign{Targets: []string{c.text(nm)}, Value: v})
					} else {
						out = append(out, nir.ExprStmt{Value: v})
					}
				}
			}
		}
		// brace-less single-statement bodies (`if (x) foo = y;` with no `{}`): the
		// consequence/alternative/body field points straight at the statement instead of a
		// block, so the children walk above skips it. Lower it here. A nested if/loop/try
		// body is structured by c.stmt; a block or already-flattened if is skipped.
		for _, f := range []string{"consequence", "alternative", "body"} {
			if b := c.field(m, f); b != nil && !handled(c.kind(b)) {
				out = append(out, c.stmt(b)...)
			}
		}
	}
	if c.kind(n) == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *jvConv) tryStmt(n *tree_sitter.Node) nir.Try {
	var body []nir.Stmt
	var resourceNames []string
	var handlers [][]nir.Stmt
	var handlerParams []string
	var finally []nir.Stmt
	bodySeen := false
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "resource_specification":
			body = append(body, c.collectBlocks(ch)...)
			resourceNames = append(resourceNames, c.resourceNames(ch)...)
		case "block":
			if !bodySeen {
				body = append(body, c.block(ch)...)
				bodySeen = true
			}
		case "catch_clause":
			handlerParams = append(handlerParams, c.catchParam(ch))
			handlers = append(handlers, c.collectBlocks(ch))
		case "finally_clause":
			finally = append(finally, c.collectBlocks(ch)...)
		}
	}
	if !bodySeen && len(body) == 0 {
		body = c.collectBlocks(n)
	}
	for _, name := range resourceNames {
		body = append(body, c.implicitClose(name, c.loc(n)))
	}
	return nir.Try{Body: body, Handlers: handlers, HandlerParams: handlerParams, Finally: finally, Loc: c.loc(n)}
}

func (c *jvConv) resourceNames(n *tree_sitter.Node) []string {
	var names []string
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if c.kind(m) == "resource" {
			if nm := c.field(m, "name"); nm != nil {
				names = append(names, c.text(nm))
			}
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return names
}

func (c *jvConv) implicitClose(name, loc string) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: nir.Name{ID: name, Loc: loc}, Attr: "close", Path: name + ".close", Loc: loc},
		Path:   name + ".close",
		Method: "close",
		Loc:    loc,
	}}
}

func (c *jvConv) catchParam(n *tree_sitter.Node) string {
	var found string
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found != "" {
			return
		}
		if c.kind(m) == "formal_parameter" || c.kind(m) == "catch_formal_parameter" {
			if nm := c.field(m, "name"); nm != nil {
				found = c.text(nm)
				return
			}
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return found
}

func (c *jvConv) catchTypes(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(typ string) {
		typ = strings.TrimSpace(typ)
		if typ == "" || seen[typ] {
			return
		}
		seen[typ] = true
		out = append(out, typ)
		if i := strings.LastIndex(typ, "."); i >= 0 && i+1 < len(typ) {
			short := typ[i+1:]
			if short != "" && !seen[short] {
				seen[short] = true
				out = append(out, short)
			}
		}
	}
	var walkType func(*tree_sitter.Node)
	walkType = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		switch c.kind(m) {
		case "type_identifier", "scoped_type_identifier":
			add(c.text(m))
			return
		}
		for _, ch := range c.namedChildren(m) {
			walkType(ch)
		}
	}
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if c.kind(m) == "catch_formal_parameter" || c.kind(m) == "formal_parameter" {
			if typ := c.field(m, "type"); typ != nil {
				walkType(typ)
			} else {
				for _, ch := range c.namedChildren(m) {
					if c.kind(ch) == "variable_declarator_id" || c.kind(ch) == "identifier" {
						break
					}
					walkType(ch)
				}
			}
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *jvConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range c.namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jvConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) == "formal_parameter" || c.kind(ch) == "spread_parameter" {
			if nm := c.field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			}
		}
	}
	return out
}

func (c *jvConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) == "formal_parameter" || c.kind(ch) == "spread_parameter" {
			if nm := c.field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func (c *jvConv) jvClassBases(n *tree_sitter.Node) []string {
	var out []string
	add := func(base string) {
		base = javaBaseTypeName(base)
		if base == "" {
			return
		}
		for _, seen := range out {
			if seen == base {
				return
			}
		}
		out = append(out, base)
	}
	var walkTypes func(*tree_sitter.Node)
	walkTypes = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		switch c.kind(m) {
		case "type_identifier", "scoped_type_identifier", "generic_type":
			add(c.text(m))
			return
		}
		for _, ch := range c.namedChildren(m) {
			walkTypes(ch)
		}
	}
	walkTypes(c.field(n, "superclass"))
	walkTypes(c.field(n, "interfaces"))
	return out
}

func javaBaseTypeName(s string) string {
	if i := strings.IndexByte(s, '<'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// anonClassBody returns the class_body child of an object_creation_expression
// (`new T(args) { ... }`) when the constructed class is anonymous: the body
// holding its members. The grammar exposes it as a plain named child, without
// a field name.
func (c *jvConv) anonClassBody(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "class_body" {
			return ch
		}
	}
	return nil
}

func javaClassContextTokens(name string, bases []string) []string {
	var out []string
	if name != "" {
		out = append(out, "class_name:"+name)
	}
	for _, base := range bases {
		if base != "" {
			out = append(out, "class_base:"+base)
		}
	}
	return out
}

// jvFieldInitTokens reports what each direct field declaration of a class-like
// body constructs in its initializer, and whether that construction runs per
// class or per instance: `static_field_init:<T>` for a static field (or any
// field of an interface, which the language makes implicitly static -- its
// constants parse as constant_declaration) and `instance_field_init:<T>`
// otherwise. The declared modifiers reach no node and no context today -- a
// field lowers to a bare assignment -- so per-class and per-instance spellings
// of the same initializer are otherwise indistinguishable. The token carries
// the constructed type rather than the field name, so a body's fields of one
// type dedup to one entry. Nested classes are skipped: their own declaration
// walks their fields with their own context.
func (c *jvConv) jvFieldInitTokens(body *tree_sitter.Node, interfaceBody bool) []string {
	if body == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	for _, ch := range c.namedChildren(body) {
		if c.kind(ch) != "field_declaration" && c.kind(ch) != "constant_declaration" {
			continue
		}
		static := interfaceBody
		for _, m := range c.namedChildren(ch) {
			if c.kind(m) == "modifiers" && javaContainsWord(c.text(m), "static") {
				static = true
			}
		}
		for _, d := range c.namedChildren(ch) {
			if c.kind(d) != "variable_declarator" {
				continue
			}
			val := c.field(d, "value")
			if val == nil || c.kind(val) != "object_creation_expression" {
				continue
			}
			prefix := "instance_field_init:"
			if static {
				prefix = "static_field_init:"
			}
			add(prefix + javaBaseTypeName(c.text(c.field(val, "type"))))
		}
	}
	return out
}

// jvAnnotationTokens extracts syntax-level annotation names without interpreting
// framework/domain meaning. Binding applicators decide what each token means.
func (c *jvConv) jvAnnotationTokens(n *tree_sitter.Node, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, prefix+name)
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil {
			return
		}
		if c.kind(m) == "marker_annotation" || c.kind(m) == "annotation" {
			for _, k := range c.namedChildren(m) {
				if c.kind(k) == "identifier" || c.kind(k) == "scoped_identifier" {
					full := c.text(k)
					add(full)
					if short := lastSeg(full); short != "" && short != full {
						add(short)
					}
					break
				}
			}
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "modifiers" {
			walk(ch)
		}
	}
	return out
}

func (c *jvConv) jvModifierTokens(n *tree_sitter.Node, prefix string) []string {
	var mods string
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "modifiers" {
			mods = c.text(ch)
			break
		}
	}
	if mods == "" {
		return nil
	}
	var out []string
	for _, mod := range []string{"public", "protected", "private", "static", "final", "abstract", "synchronized", "native", "strictfp"} {
		if javaContainsWord(mods, mod) {
			out = append(out, prefix+mod)
		}
	}
	return out
}

func javaContainsWord(s, word string) bool {
	for {
		i := strings.Index(s, word)
		if i < 0 {
			return false
		}
		before := i == 0 || !javaIdentRune(rune(s[i-1]))
		afterIdx := i + len(word)
		after := afterIdx >= len(s) || !javaIdentRune(rune(s[afterIdx]))
		if before && after {
			return true
		}
		s = s[afterIdx:]
	}
}

func javaIdentRune(r rune) bool {
	return r == '_' || r == '$' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func (c *jvConv) jvFunctionTokens(name string, n *tree_sitter.Node, params []string, paramTypes map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 512 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if name != "" {
		add("function_name:" + name)
	}
	// The declared return type is the sibling fact of a parameter's declared
	// type on the same declaration node, and answers the same question from
	// the other end: what a caller receives. A constructor has no `type`
	// field and yields nothing.
	if rt := paramTypeFromField(c, n); rt != "" {
		add("return_type:" + rt)
	}
	text := c.text(n)
	add(text)
	add(javaCompactText(text))
	for i, param := range params {
		if param == "" {
			continue
		}
		add("param_name:" + param)
		add("param_index:" + itoa(i))
		if typ := paramTypes[param]; typ != "" {
			add("param_type:" + typ)
		}
	}
	prevCall := ""
	addReturnTokens := func(ret *tree_sitter.Node) {
		kids := c.namedChildren(ret)
		if len(kids) == 0 {
			return
		}
		expr := kids[0]
		if tok := javaExprToken(c.text(expr)); tok != "" {
			add("return_expr:" + tok)
		}
		var walkExpr func(*tree_sitter.Node)
		walkExpr = func(x *tree_sitter.Node) {
			if x == nil {
				return
			}
			switch c.kind(x) {
			case "method_invocation":
				if p := c.dotted(x); p != "" && p != "?" {
					add("return_call_path:" + p)
				}
				if nm := c.text(c.field(x, "name")); nm != "" {
					add("return_call:" + nm)
				}
			case "identifier":
				if ident := c.text(x); ident != "" {
					add("return_identifier:" + ident)
				}
			case "field_access":
				if p := c.dotted(x); p != "" && p != "?" {
					add("return_selector:" + p)
				}
			}
			for _, ch := range c.namedChildren(x) {
				walkExpr(ch)
			}
		}
		walkExpr(expr)
	}
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || len(out) >= 512 {
			return
		}
		switch c.kind(m) {
		case "catch_clause":
			for _, typ := range c.catchTypes(m) {
				add("catch_type:" + typ)
			}
		case "return_statement":
			addReturnTokens(m)
		case "method_invocation":
			if p := c.dotted(m); p != "" && p != "?" {
				if prevCall != "" {
					add("call_order:" + prevCall + ">" + p)
				}
				prevCall = p
				add("call_path:" + p)
			}
			if nm := c.text(c.field(m, "name")); nm != "" {
				add("call:" + nm)
			}
		case "object_creation_expression":
			if typ := c.dotted(c.field(m, "type")); typ != "" && typ != "?" {
				if prevCall != "" {
					add("call_order:" + prevCall + ">" + typ)
				}
				prevCall = typ
				add("call_path:" + typ)
				add("call:" + lastSeg(typ))
			}
		case "field_access":
			if p := c.dotted(m); p != "" && p != "?" {
				add("selector:" + p)
			}
			if fld := c.text(c.field(m, "field")); fld != "" {
				add("selector:" + fld)
			}
		case "binary_expression":
			if expr := javaExprToken(c.text(m)); expr != "" {
				add("expr:" + expr)
			}
			if shape := c.javaExprShape(m); shape != "" {
				add("binary_shape:" + shape)
			}
			if check := c.javaLengthCheckToken(m); check != "" {
				add("length_check:" + check)
			}
		case "array_access":
			if idx := javaExprToken(c.text(m)); idx != "" {
				add("index:" + idx)
			}
			if shape := c.javaExprShape(m); shape != "" {
				add("index_shape:" + shape)
			}
		case "string_literal":
			if lit := javaStringToken(c.text(m)); lit != "" {
				add("literal:" + lit)
			}
		case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
			"character_literal":
			if lit := strings.TrimSpace(c.text(m)); lit != "" {
				add("literal:" + lit)
			}
		case "identifier":
			if ident := c.text(m); ident != "" {
				add("identifier:" + ident)
			}
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *jvConv) jvSensitiveMetadataExportTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	added := map[string]map[string]bool{}
	var stack []string
	var out []string
	addToken := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 64 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	addKey := func(obj, key string) {
		if obj == "" || key == "" || !javaSensitiveMetadataKey(key) {
			return
		}
		if added[obj] == nil {
			added[obj] = map[string]bool{}
		}
		added[obj][key] = true
	}
	var walk func(*tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || len(out) >= 64 {
			return
		}
		if c.kind(m) == "enhanced_for_statement" {
			if base := c.jvPropertiesIterableBase(c.field(m, "value")); base != "" {
				stack = append(stack, base)
				for _, ch := range c.namedChildren(m) {
					if ch != c.field(m, "value") {
						walk(ch)
					}
				}
				stack = stack[:len(stack)-1]
				return
			}
		}
		if c.kind(m) == "method_invocation" {
			path := c.dotted(m)
			method := lastSeg(path)
			base := javaPathBase(path)
			switch method {
			case "add", "put", "set":
				addKey(base, c.jvFirstStringArg(m))
			case "metadata", "putMetadata", "setMetadata", "writeMetadata":
				for _, obj := range stack {
					for key := range added[obj] {
						addToken("metadata_export_after_sensitive_key:" + key)
						addToken("metadata_export_after_sensitive_source:" + obj + "." + key)
						addToken("metadata_export_writer:" + path)
					}
				}
			}
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *jvConv) jvPropertiesIterableBase(n *tree_sitter.Node) string {
	if n == nil || c.kind(n) != "method_invocation" {
		return ""
	}
	path := c.dotted(n)
	switch lastSeg(path) {
	case "getProperties", "entrySet", "propertySet":
		return javaPathBase(path)
	default:
		return ""
	}
}

// jvFirstStringArg returns the token of the call's FIRST argument when that
// argument is a string literal, and "" otherwise. It deliberately does not search
// past the first argument: a later string among the arguments is a different
// argument with a different meaning, not a fallback for this one.
func (c *jvConv) jvFirstStringArg(n *tree_sitter.Node) string {
	args := c.field(n, "arguments")
	if args == nil {
		return ""
	}
	kids := c.namedChildren(args)
	if len(kids) == 0 || c.kind(kids[0]) != "string_literal" {
		return ""
	}
	return javaStringToken(c.text(kids[0]))
}

func javaPathBase(path string) string {
	if i := strings.LastIndex(path, "."); i > 0 {
		return path[:i]
	}
	return ""
}

func javaSensitiveMetadataKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
	switch k {
	case "reposource", "repository", "repositoryurl", "gitsource", "gitremote", "originurl", "remoteurl":
		return true
	default:
		return strings.Contains(k, "repo") && (strings.Contains(k, "source") || strings.Contains(k, "url"))
	}
}

func javaExprToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			b.WriteRune(r)
		}
		if b.Len() >= 256 {
			break
		}
	}
	return b.String()
}

func (c *jvConv) javaExprShape(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch c.kind(n) {
	case "identifier", "field_access", "method_invocation":
		return "ID"
	case "array_access":
		base := c.javaExprShape(c.field(n, "array"))
		key := c.javaExprShape(c.field(n, "index"))
		if base == "" || key == "" {
			return ""
		}
		return base + "[" + key + "]"
	case "decimal_integer_literal", "hex_integer_literal":
		raw := strings.TrimSpace(c.text(n))
		if strings.HasSuffix(raw, "L") || strings.HasSuffix(raw, "l") {
			return "LONG"
		}
		return "INT"
	case "decimal_floating_point_literal":
		return "FLOAT"
	case "character_literal":
		return "CHAR"
	case "string_literal":
		return "STRING"
	case "true", "false":
		return "BOOL"
	case "parenthesized_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.javaExprShape(kids[0])
		}
	case "binary_expression":
		left := c.javaExprShape(c.field(n, "left"))
		right := c.javaExprShape(c.field(n, "right"))
		op := c.javaOp(n)
		if left == "" || right == "" || op == "" {
			return ""
		}
		return left + op + right
	}
	return ""
}

func (c *jvConv) jvIntegerSizeArithmeticObservations(fn *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if c.kind(n) == "binary_expression" && c.javaExprShape(n) == "INT<<ID" {
			loc := c.loc(n)
			path := "analysis.integer_size.int_shift"
			out = append(out, nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: path, Loc: loc},
				Args: []nir.Expr{
					nir.Const{Loc: loc, Value: "left=int_literal"},
					c.expr(c.field(n, "right")),
					nir.Const{Loc: loc, Value: "operator=shift_left"},
				},
				Path:   path,
				Method: "int_shift",
				Loc:    loc,
			}})
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch)
		}
	}
	walk(c.field(fn, "body"))
	return out
}

func (c *jvConv) jvUnverifiedKeyIDPathResolveObservations(fn *tree_sitter.Node) []nir.Stmt {
	body := c.field(fn, "body")
	if body == nil {
		return nil
	}
	text := javaCompactText(c.text(body))
	if !strings.Contains(text, ".resolve(keyId.getSchemeSpecificPart())") {
		return nil
	}
	if !strings.Contains(text, "Files.exists(") || !strings.Contains(text, ".load(") {
		return nil
	}
	if strings.Contains(text, ".resolve(Constants.MASTERKEY_FILENAME)") ||
		strings.Contains(text, ".resolve(DEFAULT_MASTERKEY_PATH)") ||
		strings.Contains(text, ".normalize()") {
		return nil
	}
	loc := c.loc(body)
	path := "analysis.java.unverified_keyid_path_resolve"
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: path, Loc: loc},
		Args: []nir.Expr{
			nir.Const{Loc: loc, Value: "source=unverified_key_id"},
			nir.Const{Loc: loc, Value: "sink=path_resolve_then_load"},
			nir.Const{Loc: loc, Value: "guard=missing_fixed_filename_or_containment"},
		},
		Path:   path,
		Method: "unverified_keyid_path_resolve",
		Loc:    loc,
	}}}
}

func (c *jvConv) javaLengthCheckToken(n *tree_sitter.Node) string {
	if n == nil || c.kind(n) != "binary_expression" {
		return ""
	}
	op := c.javaOp(n)
	if op != "==" && op != "!=" {
		return ""
	}
	left := c.field(n, "left")
	right := c.field(n, "right")
	if javaIsLengthField(c, left) {
		if val := javaIntLiteral(c.text(right)); val != "" {
			return "length_" + op + "_" + val
		}
	}
	if javaIsLengthField(c, right) {
		if val := javaIntLiteral(c.text(left)); val != "" {
			return "length_" + op + "_" + val
		}
	}
	return ""
}

func (c *jvConv) javaOp(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if op := strings.TrimSpace(c.text(c.field(n, "operator"))); op != "" {
		return op
	}
	for i := uint(0); i < n.ChildCount(); i++ {
		if ch := n.Child(i); !ch.IsNamed() {
			return strings.TrimSpace(c.text(ch))
		}
	}
	return ""
}

func javaIsLengthField(c *jvConv, n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch c.kind(n) {
	case "field_access":
		return c.text(c.field(n, "field")) == "length"
	case "identifier":
		return false
	default:
		return strings.HasSuffix(javaExprToken(c.text(n)), ".length")
	}
}

func javaIntLiteral(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return raw
}

// compactWhitespaceReplacer strips layout from source text. A strings.Replacer builds a
// lookup trie on first use, so constructing one per call rebuilds and discards that trie
// on every token — hot enough on a large corpus to be a measurable share of all allocation.
var compactWhitespaceReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "")

func javaCompactText(s string) string {
	return compactWhitespaceReplacer.Replace(s)
}

func javaStringToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "\"")
	raw = strings.TrimSuffix(raw, "\"")
	if raw == "" {
		return ""
	}
	if len(raw) > 256 {
		raw = raw[:256]
	}
	return raw
}

func (c *jvConv) jvParamAnnotationTokens(params *tree_sitter.Node) map[string][]string {
	out := map[string][]string{}
	if params == nil {
		return out
	}
	for _, ch := range c.namedChildren(params) {
		if c.kind(ch) != "formal_parameter" && c.kind(ch) != "spread_parameter" {
			continue
		}
		nm := c.field(ch, "name")
		if nm == nil {
			continue
		}
		toks := c.jvAnnotationTokens(ch, "annotation:")
		if len(toks) > 0 {
			out[c.text(nm)] = toks
		}
	}
	return out
}

func (c *jvConv) jvParamEntries(name string, params []string, paramTypes map[string]string, base []string, paramAnnotations map[string][]string) []nir.ParamEntry {
	funcTokens := append([]string{}, base...)
	for _, typ := range paramTypes {
		if typ == "" {
			continue
		}
		funcTokens = append(funcTokens, "has_param_type:"+typ)
		if short := lastSeg(typ); short != "" && short != typ {
			funcTokens = append(funcTokens, "has_param_type:"+short)
		}
	}
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" || p == "_" {
			continue
		}
		tokens := append([]string{}, funcTokens...)
		tokens = append(tokens, paramAnnotations[p]...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		if typ := paramTypes[p]; typ != "" {
			tokens = append(tokens, "param_type:"+typ)
			if short := lastSeg(typ); short != "" && short != typ {
				tokens = append(tokens, "param_type:"+short)
			}
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

func (c *jvConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "identifier", "this", "super":
		return nir.Name{ID: c.text(n), Loc: L}
	case "null_literal":
		return nir.Const{Loc: L}
	case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal",
		"character_literal":
		// carry the literal text so constant-folding (opaque branch conditions) and numeric
		// value-matching (e.g. chmod modes) can read it.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "true", "false":
		return nir.Const{Loc: L, Value: c.text(n)} // boolean value for `val` matching
	case "string_literal":
		// pick up interpolation in text blocks if any; otherwise constant
		return nir.Const{Loc: L, Value: c.text(n)}
	case "field_access":
		return nir.Attr{Base: c.expr(c.field(n, "object")), Attr: c.text(c.field(n, "field")), Path: c.dotted(n), Loc: L}
	case "array_access":
		return nir.Index{Base: c.expr(c.field(n, "array")), Key: c.expr(c.field(n, "index")), Path: c.dotted(c.field(n, "array")), Loc: L}
	case "method_invocation":
		obj := c.field(n, "object")
		name := c.text(c.field(n, "name"))
		path := c.dotted(n)
		var arglist []nir.Expr
		if args := c.field(n, "arguments"); args != nil {
			for _, a := range c.namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		var callee nir.Expr
		if obj != nil {
			callee = nir.Attr{Base: c.expr(obj), Attr: name, Path: path, Loc: L}
		} else {
			callee = nir.Name{ID: name, Loc: L}
		}
		return nir.Call{Callee: callee, Args: arglist, Path: path, Method: name, Loc: L}
	case "object_creation_expression":
		typ := c.text(c.field(n, "type"))
		var arglist []nir.Expr
		if args := c.field(n, "arguments"); args != nil {
			for _, a := range c.namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		// `new T(args) { ... }` — a trailing class_body is an anonymous class
		// whose members are real code. Lower it exactly as class_declaration
		// lowers its own body (the same class_body node type) and hoist the
		// ClassDef out of expression position, so the methods become FuncDefs
		// with the class context a named class gets. The class has no name of
		// its own; the constructed type is its only base.
		if body := c.anonClassBody(n); body != nil {
			base := javaBaseTypeName(typ)
			prevParams := c.classParamTokens
			prevContext := c.classContextTokens
			prevFieldInit := c.fieldInitTokens
			c.classParamTokens = append([]string{}, prevParams...)
			c.classContextTokens = append(append([]string{}, prevContext...), javaClassContextTokens("", []string{base})...)
			c.fieldInitTokens = c.jvFieldInitTokens(body, false)
			c.hoisted = append(c.hoisted, nir.ClassDef{Bases: []string{base}, Body: c.decls(body), Loc: L})
			c.classParamTokens = prevParams
			c.classContextTokens = prevContext
			c.fieldInitTokens = prevFieldInit
		}
		// model `new T(args)` as a constructor call with callee path "T", so
		// binding applicators can match constructor and type information.
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: arglist, Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.javaOp(n)
		left, right := c.expr(c.field(n, "left")), c.expr(c.field(n, "right"))
		if op == "+" {
			// `+` is overloaded (string concat / arithmetic); keep it a taint-propagating
			// Format so string-building flows are preserved.
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		// other operators (-, *, /, %, >, <, ==, &&, …) preserve the operator for constant
		// evaluation of opaque branch conditions; BinOp also flows taint through both sides.
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_expression":
		return nir.Unary{Op: c.javaOp(n), Operand: c.expr(c.field(n, "operand")), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "ternary_expression":
		return nir.Ternary{Cond: c.expr(c.field(n, "condition")), Then: c.expr(c.field(n, "consequence")), Else: c.expr(c.field(n, "alternative")), Loc: L}
	case "array_initializer":
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

func (c *jvConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch c.kind(n) {
	case "identifier", "this", "super", "type_identifier", "scoped_identifier":
		return c.text(n)
	case "field_access":
		return c.dotted(c.field(n, "object")) + "." + c.text(c.field(n, "field"))
	case "method_invocation":
		obj := c.field(n, "object")
		name := c.text(c.field(n, "name"))
		if obj == nil {
			return name
		}
		return c.dotted(obj) + "." + name
	case "array_access":
		return c.dotted(c.field(n, "array")) + "[]"
	case "object_creation_expression":
		return c.text(c.field(n, "type"))
	case "parenthesized_expression":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	if strings.Contains(c.text(n), ".") {
		return c.text(n)
	}
	return "?"
}

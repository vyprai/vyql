package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// jvConv walks a tree-sitter Java CST into NIR.
type jvConv struct {
	src          []byte
	root         string
	file         string
	key          string
	inController bool // inside a @RestController/@Controller class
}

// jvHandlerAnns mark a Spring/JAX-RS/Micronaut class/method as a request handler,
// so its method parameters (e.g. @RequestParam/@PathVariable/@QueryParam values)
// are seeded as http_input.
var jvHandlerAnns = map[string]bool{
	// Spring MVC / WebFlux
	"RestController": true, "Controller": true, "RequestMapping": true,
	"GetMapping": true, "PostMapping": true, "PutMapping": true,
	"DeleteMapping": true, "PatchMapping": true,
	// JAX-RS (Jersey/RESTEasy) + Quarkus (which reuses JAX-RS): @Path on the
	// resource class, @GET/@POST/... on the methods.
	"Path": true, "GET": true, "POST": true, "PUT": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
	// Micronaut
	"Get": true, "Post": true, "Put": true, "Delete": true,
}

// hasHandlerAnn reports whether a class/method declaration carries a Spring
// handler annotation. Annotations live under the `modifiers` child; the name is
// an identifier/scoped_identifier child of the (marker_)annotation node.
func (c *jvConv) hasHandlerAnn(n *tree_sitter.Node) bool {
	found := false
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		if m == nil || found {
			return
		}
		if m.Kind() == "marker_annotation" || m.Kind() == "annotation" {
			for _, k := range namedChildren(m) {
				if k.Kind() == "identifier" || k.Kind() == "scoped_identifier" {
					if jvHandlerAnns[lastSeg(c.text(k))] {
						found = true
					}
					break
				}
			}
			return
		}
		for _, ch := range namedChildren(m) {
			walk(ch)
		}
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
			walk(ch)
		}
	}
	return found
}

// javaPublic reports whether a method/constructor is part of the public API surface:
// it carries a `public` modifier (package-private/private/protected are not the API a
// library exposes to arbitrary callers). Used to scope the library param-source.
func (c *jvConv) javaPublic(n *tree_sitter.Node) bool {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "modifiers" {
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
	switch n.Kind() {
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
		if k := namedChildren(n); len(k) > 0 {
			return c.simpleTypeName(k[0])
		}
	}
	return ""
}

func (c *jvConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n.Kind() == "import_declaration" {
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "scoped_identifier" || ch.Kind() == "identifier" {
					full := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(full), Module: full, IsModule: true})
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

// decls lowers top-level + class-member declarations.
func (c *jvConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *jvConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		prev := c.inController
		c.inController = prev || c.hasHandlerAnn(n)
		cd := nir.ClassDef{Name: c.text(field(n, "name")), Body: c.decls(field(n, "body")), Loc: L}
		c.inController = prev
		return []nir.Stmt{cd}
	case "method_declaration", "constructor_declaration":
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		// Spring handler params (e.g. @RequestParam/@PathVariable) are request input.
		if c.inController || c.hasHandlerAnn(n) {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		} else if mn := c.text(field(n, "name")); mn == "isValid" && len(params) > 0 && hasParamType(paramTypes, "ConstraintValidatorContext") {
			// JSR-380 ConstraintValidator.isValid(value, ctx): value is framework-supplied
			// entry data. Seed it so custom-message flows remain visible to adapters.
			body = append([]nir.Stmt{nir.Assign{Targets: []string{params[0]},
				Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}}}, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: c.text(field(n, "name")), Params: params, ParamTypes: paramTypes, Body: body, Loc: L,
			Exported: c.inController || c.hasHandlerAnn(n) || c.javaPublic(n)}}
	case "field_declaration", "local_variable_declaration":
		var out []nir.Stmt
		declType := c.simpleTypeName(field(n, "type")) // declared class type, for cross-file resolution
		for _, d := range namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v, Type: declType})
				}
			}
		}
		return out
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0])
	case "return_statement":
		kids := namedChildren(n)
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
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.branchBody(field(n, "consequence")), Else: c.branchBody(field(n, "alternative"))}}
	case "while_statement", "for_statement", "do_statement":
		return []nir.Stmt{nir.Loop{Body: c.collectBlocks(n)}}
	case "enhanced_for_statement":
		// `for (T x : coll)` — bind the loop variable to the iterable so a tainted
		// collection taints each element (flow-approximate element-of).
		body := c.collectBlocks(n)
		if nm, val := field(n, "name"), field(n, "value"); nm != nil && val != nil {
			body = append([]nir.Stmt{nir.Assign{Targets: []string{c.text(nm)}, Value: c.expr(val)}}, body...)
		}
		return []nir.Stmt{nir.Loop{Body: body}}
	case "try_statement", "try_with_resources_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
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
			if blk.Kind() != "switch_block" {
				continue
			}
			for _, grp := range children(blk) {
				if grp.Kind() != "switch_block_statement_group" {
					continue
				}
				hasGroups = true
				var stmts []nir.Stmt
				var labs []nir.Expr
				isDefault := false
				for _, ch := range children(grp) {
					if ch.Kind() == "switch_label" {
						if strings.Contains(c.text(ch), "default") {
							isDefault = true
						} else if lk := namedChildren(ch); len(lk) > 0 {
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
			return []nir.Stmt{nir.Switch{Subject: c.expr(field(n, "condition")), Cases: cases, Labels: labels, Default: deflt}}
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
	switch inner.Kind() {
	case "assignment_expression":
		left := field(inner, "left")
		right := c.expr(field(inner, "right"))
		if left != nil && left.Kind() == "identifier" {
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
	if b.Kind() == "block" {
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
			switch ch.Kind() {
			case "block", "constructor_body":
				out = append(out, c.block(ch)...)
			case "switch_block", "switch_block_statement_group", "catch_clause", "finally_clause",
				"resource_specification", "if_statement", "else":
				walk(ch)
			case "resource":
				// try-with-resources `try (T x = new FileInputStream(path); …)` — lower the
				// resource initializer (often a file/stream sink) and bind its variable.
				if val := field(ch, "value"); val != nil {
					v := c.expr(val)
					if nm := field(ch, "name"); nm != nil {
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
			if b := field(m, f); b != nil && !handled(b.Kind()) {
				out = append(out, c.stmt(b)...)
			}
		}
	}
	if n.Kind() == "block" {
		return c.block(n)
	}
	walk(n)
	return out
}

func (c *jvConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	var out []nir.Stmt
	for _, st := range namedChildren(block) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jvConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "formal_parameter" || ch.Kind() == "spread_parameter" {
			if nm := field(ch, "name"); nm != nil {
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
	for _, ch := range namedChildren(params) {
		if ch.Kind() == "formal_parameter" || ch.Kind() == "spread_parameter" {
			if nm := field(ch, "name"); nm != nil {
				putParamType(out, c.text(nm), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

// hasParamType reports whether any parameter's declared type has the given (generics-stripped)
// short name — e.g. detecting the `ConstraintValidatorContext` arg of a JSR-380 validator.
func hasParamType(paramTypes map[string]string, short string) bool {
	for _, t := range paramTypes {
		if t == short || strings.HasSuffix(t, "."+short) {
			return true
		}
	}
	return false
}

func (c *jvConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
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
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "field")), Path: c.dotted(n), Loc: L}
	case "array_access":
		return nir.Index{Base: c.expr(field(n, "array")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "array")), Loc: L}
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		path := c.dotted(n)
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
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
		typ := c.text(field(n, "type"))
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		// model `new T(args)` as a constructor call with callee path "T", so
		// sinks/types can match (e.g. new ProcessBuilder, new File, new URL).
		return nir.Call{Callee: nir.Name{ID: typ, Loc: L}, Args: arglist, Path: typ, Method: typ, Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			// `+` is overloaded (string concat / arithmetic); keep it a taint-propagating
			// Format so string-building flows are preserved.
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		// other operators (-, *, /, %, >, <, ==, &&, …) preserve the operator for constant
		// evaluation of opaque branch conditions; BinOp also flows taint through both sides.
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_expression":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
	case "parenthesized_expression", "cast_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "ternary_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "array_initializer":
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

func (c *jvConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "this", "super", "type_identifier", "scoped_identifier":
		return c.text(n)
	case "field_access":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "field"))
	case "method_invocation":
		obj := field(n, "object")
		name := c.text(field(n, "name"))
		if obj == nil {
			return name
		}
		return c.dotted(obj) + "." + name
	case "array_access":
		return c.dotted(field(n, "array")) + "[]"
	case "object_creation_expression":
		return c.text(field(n, "type"))
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	if strings.Contains(c.text(n), ".") {
		return c.text(n)
	}
	return "?"
}

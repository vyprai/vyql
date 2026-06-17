package treesitter

import (
	"path/filepath"
	"strings"
	"unsafe"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tstypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// jsConv walks a tree-sitter JavaScript/TypeScript CST into NIR. The SAME walker handles
// both — TS is a syntactic superset of JS, so the JS node kinds are identical; TS-only
// nodes (type annotations, generics, `as`/`!`/`satisfies`, accessibility modifiers) are
// either skipped as unknown or unwrapped to their inner expression. Crucially, .ts/.tsx
// files are parsed with the TYPESCRIPT grammar (not the JS grammar), so a generic in a
// type annotation — `: Promise<string | null>` — no longer mis-parses `<` as less-than
// and drops the function body.
type jsConv struct {
	src      []byte
	root     string
	file     string
	key      string
	exported map[string]bool
}

func jsParserFor(lang unsafe.Pointer) func() *tree_sitter.Parser {
	return func() *tree_sitter.Parser {
		p := tree_sitter.NewParser()
		_ = p.SetLanguage(tree_sitter.NewLanguage(lang))
		return p
	}
}

// ExtractJavaScript parses JS/TS files into one NIR Program. Files are routed to the
// matching grammar by extension (.ts → typescript, .tsx → tsx, else javascript); all
// share the jsConv walker.
func ExtractJavaScript(files []string, root string) (nir.Program, error) {
	var js, ts, tsx []string
	for _, f := range files {
		l := strings.ToLower(f)
		switch {
		case strings.HasSuffix(l, ".tsx"):
			tsx = append(tsx, f)
		case strings.HasSuffix(l, ".ts") || strings.HasSuffix(l, ".mts") || strings.HasSuffix(l, ".cts"):
			ts = append(ts, f)
		default:
			js = append(js, f)
		}
	}
	build := func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
		c := &jsConv{src: src, root: root, file: rel, key: jsModuleKey(root, abs)}
		root0 := tree.RootNode()
		c.exported = c.exportedNames(root0)
		return nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: c.blockChildren(root0)}, true
	}
	var mods []nir.Module
	mods = append(mods, parseModules(js, root, jsParserFor(tsjs.Language()), build)...)
	mods = append(mods, parseModules(ts, root, jsParserFor(tstypescript.LanguageTypescript()), build)...)
	mods = append(mods, parseModules(tsx, root, jsParserFor(tstypescript.LanguageTSX()), build)...)
	return nir.Program{SelfName: "this", Modules: mods}, nil
}

func (c *jsConv) exportedNames(root *tree_sitter.Node) map[string]bool {
	out := map[string]bool{}
	var markObjectExports func(*tree_sitter.Node)
	markObjectExports = func(obj *tree_sitter.Node) {
		if obj == nil || obj.Kind() != "object" {
			return
		}
		for _, pr := range namedChildren(obj) {
			switch pr.Kind() {
			case "pair":
				v := field(pr, "value")
				if v != nil && v.Kind() == "identifier" {
					out[c.text(v)] = true
				} else if isJsFuncNode(v) {
					if name := c.keyName(field(pr, "key")); name != "" {
						out[name] = true
					}
				}
			case "shorthand_property_identifier":
				out[c.text(pr)] = true
			}
		}
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "export_statement":
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "function_declaration" || ch.Kind() == "generator_function_declaration" {
					if name := c.text(field(ch, "name")); name != "" {
						out[name] = true
					}
				}
			}
		case "assignment_expression":
			left, rhs := field(n, "left"), field(n, "right")
			if left != nil && left.Kind() == "member_expression" {
				if c.isModuleExports(left) {
					if rhs != nil && rhs.Kind() == "identifier" {
						out[c.text(rhs)] = true
					}
					markObjectExports(rhs)
				} else if name := c.exportFuncName(left); name != "" {
					out[name] = true
					if rhs != nil && rhs.Kind() == "identifier" {
						out[c.text(rhs)] = true
					}
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

func jsModuleKey(root, f string) string {
	for _, ext := range []string{".jsx", ".tsx", ".ts", ".js"} {
		if strings.HasSuffix(strings.ToLower(f), ext) {
			return moduleKey(root, f, ext)
		}
	}
	return moduleKey(root, f, "")
}

func (c *jsConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *jsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *jsConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		switch n.Kind() {
		case "import_statement":
			// import x from 'm'  /  import {a,b} from 'm'  /  import * as x from 'm'
			src := c.text(field(n, "source"))
			// normalize the specifier to the module key the lowering registers (the same path
			// resolution require() uses) — otherwise a relative ES import never resolves.
			mod := c.resolveRequire(strings.Trim(src, "'\"`"))
			clause := field(n, "import_clause")
			if clause == nil {
				clause = n
			}
			for _, ch := range namedChildren(clause) {
				switch ch.Kind() {
				case "identifier": // default import
					out = append(out, nir.Import{Local: c.text(ch), Module: mod, IsModule: true})
				case "namespace_import":
					if id := lastIdent(ch); id != nil {
						out = append(out, nir.Import{Local: c.text(id), Module: mod, IsModule: true})
					}
				case "named_imports":
					for _, spec := range namedChildren(ch) {
						if spec.Kind() == "import_specifier" {
							name := c.text(orSelf(field(spec, "name"), spec))
							alias := field(spec, "alias")
							local := name
							if alias != nil {
								local = c.text(alias)
							}
							out = append(out, nir.Import{Local: local, Module: mod, Symbol: name})
						}
					}
				}
			}
		case "variable_declarator":
			// const x = require('m')
			val := field(n, "value")
			if val != nil && val.Kind() == "call_expression" {
				fn := field(val, "function")
				if fn != nil && c.text(fn) == "require" {
					if args := field(val, "arguments"); args != nil {
						for _, a := range namedChildren(args) {
							if a.Kind() == "string" {
								mod := c.resolveRequire(strings.Trim(c.text(a), "'\"`"))
								name := field(n, "name")
								if name != nil && name.Kind() == "identifier" {
									out = append(out, nir.Import{Local: c.text(name), Module: mod, IsModule: true})
								}
							}
						}
					}
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

func (c *jsConv) blockChildren(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *jsConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_declaration", "generator_function_declaration", "method_definition":
		name := c.text(field(n, "name"))
		params := c.funcParams(n)
		paramTypes := c.funcParamTypes(n)
		body := c.funcBody(n)
		decorators := c.jsDecoratorTokens(n)
		// NestJS route handler (`@Get()/@Post() find(@Query() q, @Param() id)`): the
		// method's parameters are request-bound (@Body/@Query/@Param/@Headers), so seed
		// each as http_input. Detected by the HTTP-method decorator on the method.
		if n.Kind() == "method_definition" && c.jsHasRouteDecorator(n) {
			var seed []nir.Stmt
			for _, p := range params {
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			body = append(seed, body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, Decorators: decorators, Exported: c.exported[name]}}
	case "class_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.body(field(n, "body")), Loc: L}}
	case "lexical_declaration", "variable_declaration":
		var out []nir.Stmt
		for _, d := range namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				if name != nil && name.Kind() == "identifier" && (isJsFuncNode(val) || c.isFunctionLikeDeclarator(d)) {
					fnName := c.text(name)
					params := c.funcParams(val)
					paramTypes := c.funcParamTypes(val)
					if len(params) == 0 {
						params = c.paramsFromFunctionText(d)
					}
					body := c.funcBody(val)
					out = append(out, nir.FuncDef{Name: fnName, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, Exported: c.exported[fnName]})
					continue
				}
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil && name.Kind() == "identifier" {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v, Decl: true})
				} else if targets := c.bindingNames(name); len(targets) > 0 {
					for _, target := range targets {
						out = append(out, nir.Assign{Targets: []string{target}, Value: v, Decl: true})
					}
				} else {
					out = append(out, nir.ExprStmt{Value: v})
				}
			}
		}
		return out
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		return c.exprStmt(kids[0], L)
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement":
		// separate Then/Else branches so the join-merge keeps a value tainted on the live
		// path even when the other arm overwrites it, and a constant condition prunes.
		var cond nir.Expr
		if cn := field(n, "condition"); cn != nil {
			cond = c.expr(cn)
		}
		return []nir.Stmt{nir.If{Cond: cond, Then: c.branchBody(field(n, "consequence")), Else: c.branchBody(field(n, "alternative"))}}
	case "while_statement", "for_statement", "for_in_statement":
		var cond nir.Expr
		if cn := field(n, "condition"); cn != nil {
			cond = c.expr(cn)
		}
		return []nir.Stmt{nir.Loop{Cond: cond, Body: c.collectStatementBlocks(n)}}
	case "switch_statement":
		return []nir.Stmt{c.switchStmt(n)}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectStatementBlocks(n)}}
	case "statement_block":
		return []nir.Stmt{nir.Block{Stmts: c.collectStatementBlocks(n)}}
	case "export_statement":
		// unwrap `export [default] <decl>` / `export async function …` so the
		// declaration inside is analyzed (Next.js route handlers are all exports).
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	}
	return nil
}

// resolveRequire normalizes a relative require/import specifier to the dotted,
// root-relative module key the lowering registers modules under (matching
// jsModuleKey). Bare specifiers (node_modules) are returned unchanged.
func (c *jsConv) resolveRequire(spec string) string {
	if !strings.HasPrefix(spec, ".") {
		return spec
	}
	p := filepath.Clean(filepath.Join(filepath.Dir(c.file), spec))
	for _, ext := range []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"} {
		p = strings.TrimSuffix(p, ext)
	}
	p = strings.TrimSuffix(p, string(filepath.Separator)+"index")
	return strings.ReplaceAll(p, string(filepath.Separator), ".")
}

func isJsFuncNode(n *tree_sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "function_expression", "arrow_function", "function", "generator_function":
		return true
	}
	return false
}

// isModuleExports reports whether a member_expression is `module.exports`.
func (c *jsConv) isModuleExports(n *tree_sitter.Node) bool {
	return n != nil && n.Kind() == "member_expression" &&
		c.text(field(n, "object")) == "module" && c.text(field(n, "property")) == "exports"
}

// exportFuncName returns the exported function name for `exports.NAME` or
// `module.exports.NAME` member targets ("" if it is neither).
// memberRootIdent returns the root identifier of a member chain (the object at the base
// of `A.b.c`), or "" — so `LdapAuth.prototype.authenticate` yields "LdapAuth". Used to
// tie a prototype/static method back to an exported constructor/class.
func (c *jsConv) memberRootIdent(m *tree_sitter.Node) string {
	for m != nil && m.Kind() == "member_expression" {
		m = field(m, "object")
	}
	if m != nil && m.Kind() == "identifier" {
		return c.text(m)
	}
	return ""
}

func (c *jsConv) exportFuncName(left *tree_sitter.Node) string {
	obj := field(left, "object")
	name := c.text(field(left, "property"))
	if obj == nil || name == "" {
		return ""
	}
	if obj.Kind() == "identifier" && c.text(obj) == "exports" {
		return name
	}
	if c.isModuleExports(obj) {
		return name
	}
	return ""
}

func (c *jsConv) exprStmt(inner *tree_sitter.Node, L string) []nir.Stmt {
	switch inner.Kind() {
	case "parenthesized_expression":
		if kids := namedChildren(inner); len(kids) > 0 && kids[0].Kind() == "call_expression" {
			if body := c.iife(kids[0], L); len(body) > 0 {
				return body
			}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
	case "call_expression":
		if body := c.iife(inner, L); len(body) > 0 {
			return body
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
	case "assignment_expression":
		left := field(inner, "left")
		rhs := field(inner, "right")
		// CommonJS function exports become named FuncDefs so cross-file calls
		// resolve: `exports.f = function…`, `module.exports.f = …`, and
		// `module.exports = { f: function… }`.
		if left != nil && c.isModuleExports(left) && isJsFuncNode(rhs) {
			name := c.text(field(rhs, "name"))
			if name == "" {
				name = "__default_export__"
			}
			params := c.funcParams(rhs)
			paramTypes := c.funcParamTypes(rhs)
			if len(params) == 0 {
				params = c.paramsFromFunctionText(inner)
			}
			return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, Exported: true}}
		}
		if left != nil && left.Kind() == "member_expression" && isJsFuncNode(rhs) {
			if name := c.exportFuncName(left); name != "" {
				params := c.funcParams(rhs)
				paramTypes := c.funcParamTypes(rhs)
				if len(params) == 0 {
					params = c.paramsFromFunctionText(inner)
				}
				return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, Exported: true}}
			}
			// `Ctor.prototype.method = function` / `Ctor.method = function` on an EXPORTED
			// constructor/class. Always emit a FuncDef so the method is REGISTERED (calls to
			// it resolve → interprocedural taint flows through internal helpers). Mark it an
			// entry point (Exported) only if it's public by convention: a `_name` method is
			// internal and is reached by propagation from the public methods, not directly.
			if root := c.memberRootIdent(left); root != "" && c.exported[root] {
				name := c.text(field(left, "property"))
				if name != "" {
					params := c.funcParams(rhs)
					paramTypes := c.funcParamTypes(rhs)
					if len(params) == 0 {
						params = c.paramsFromFunctionText(inner)
					}
					return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: c.funcBody(rhs), Loc: L, Exported: !strings.HasPrefix(name, "_")}}
				}
			}
		}
		if left != nil && c.isModuleExports(left) && rhs != nil && rhs.Kind() == "object" {
			var out []nir.Stmt
			for _, pr := range namedChildren(rhs) {
				if pr.Kind() == "pair" && isJsFuncNode(field(pr, "value")) {
					v := field(pr, "value")
					params := c.funcParams(v)
					paramTypes := c.funcParamTypes(v)
					if len(params) == 0 {
						params = c.paramsFromFunctionText(pr)
					}
					out = append(out, nir.FuncDef{Name: c.keyName(field(pr, "key")), Params: params, ParamTypes: paramTypes, Body: c.funcBody(v), Loc: L, Exported: true})
				} else if pr.Kind() == "method_definition" {
					// object-method SHORTHAND: `module.exports = { set(o, p, v) { … } }`.
					// Common npm-library export shape; extract as an exported FuncDef so its
					// params are public-API entry points and its body is analyzed.
					out = append(out, nir.FuncDef{Name: c.text(field(pr, "name")), Params: c.funcParams(pr),
						ParamTypes: c.funcParamTypes(pr), Body: c.funcBody(pr), Loc: L, Exported: true})
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		right := c.expr(rhs)
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// member-property write (e.g. obj.prop = x): model as a path call so adapter
		// mappings can reason about the assigned value.
		// Method is empty so it can never collide with method-name sinks (query/exec/…).
		if left != nil && left.Kind() == "member_expression" {
			p := c.dotted(left)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: L}}}
		}
		// subscript write (obj[key] = v): model as a write to the base's path so the
		// same path mappings fire as for a dotted member write.
		if left != nil && left.Kind() == "subscript_expression" {
			base := field(left, "object")
			key := field(left, "index")
			return []nir.Stmt{
				// Preserve dynamic property-name flow separately from value flow.
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{c.expr(key)}, Path: "__js_dynamic_property_write", Method: "", Loc: L}},
				nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right}, Path: c.dotted(base), Method: "", Loc: L}},
			}
		}
		// other assignment: still evaluate RHS for effect
		return []nir.Stmt{nir.ExprStmt{Value: right}}
	case "augmented_assignment_expression":
		left := field(inner, "left")
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: c.expr(field(inner, "right")), Loc: L}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(field(inner, "right"))}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
}

func (c *jsConv) iife(call *tree_sitter.Node, L string) []nir.Stmt {
	fn := field(call, "function")
	if fn != nil && fn.Kind() == "parenthesized_expression" {
		if kids := namedChildren(fn); len(kids) > 0 {
			fn = kids[0]
		}
	}
	if !isJsFuncNode(fn) {
		return nil
	}
	body := c.funcBody(fn)
	ps := c.funcParams(fn)
	var as []*tree_sitter.Node
	if args := field(call, "arguments"); args != nil {
		as = namedChildren(args)
	}
	for i, p := range ps {
		if i >= len(as) {
			break
		}
		body = append([]nir.Stmt{nir.Assign{Targets: []string{p}, Value: c.expr(as[i])}}, body...)
	}
	return body
}

// branchBody flattens one if-branch body: a `{}` block, an else_clause wrapper, or a
// brace-less single statement / nested control statement.
func (c *jsConv) branchBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "statement_block":
		return c.blockChildren(n)
	case "else_clause":
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.branchBody(ch)...)
		}
		return out
	default:
		return c.stmt(n)
	}
}

// switchStmt lowers a switch into separate case branches with labels (consecutive
// fall-through labels merge into the next body), so a constant subject prunes to its arm.
func (c *jsConv) switchStmt(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	var pending []nir.Expr
	if b := field(n, "body"); b != nil {
		for _, sc := range namedChildren(b) {
			switch sc.Kind() {
			case "switch_case":
				lv := field(sc, "value")
				var stmts []nir.Stmt
				for _, ch := range namedChildren(sc) {
					if lv != nil && ch.StartByte() == lv.StartByte() {
						continue // the label expr, not a body statement
					}
					stmts = append(stmts, c.stmt(ch)...)
				}
				if lv != nil {
					pending = append(pending, c.expr(lv))
				}
				if len(stmts) > 0 {
					cases = append(cases, stmts)
					labels = append(labels, pending)
					pending = nil
				}
			case "switch_default":
				for _, ch := range namedChildren(sc) {
					deflt = append(deflt, c.stmt(ch)...)
				}
			}
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
}

// collectStatementBlocks gathers statements from nested statement_blocks and
// clause bodies (flow-approximate).
func (c *jsConv) collectStatementBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	// jsBodyHandled reports whether a body-position node is already collected by the walk
	// below (a `{}` block or a nested clause wrapper) — used to avoid double-lowering when
	// picking up brace-less bodies.
	jsBodyHandled := func(k string) bool {
		switch k {
		case "statement_block", "else_clause", "finally_clause", "catch_clause":
			return true
		}
		return false
	}
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "statement_block":
				out = append(out, c.blockChildren(ch)...)
			case "else_clause", "finally_clause", "catch_clause":
				walk(ch)
			}
		}
		// brace-less single-statement bodies (`if (x) foo();` with no `{}`): the
		// consequence/body field points straight at the statement. The else branch is an
		// else_clause wrapper (walked above), so also lower its bare statement child.
		for _, f := range []string{"consequence", "body"} {
			if b := field(m, f); b != nil && !jsBodyHandled(b.Kind()) {
				out = append(out, c.stmt(b)...)
			}
		}
		switch m.Kind() {
		case "else_clause", "catch_clause", "finally_clause":
			for _, ch := range namedChildren(m) {
				if !jsBodyHandled(ch.Kind()) {
					out = append(out, c.stmt(ch)...)
				}
			}
		}
	}
	if n.Kind() == "statement_block" {
		return c.blockChildren(n)
	}
	walk(n)
	return out
}

func (c *jsConv) body(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	// statement_block (function body) and class_body (members) are both lists of
	// statements/definitions — extract each (so class methods become FuncDefs).
	if n.Kind() == "statement_block" || n.Kind() == "class_body" {
		return c.blockChildren(n)
	}
	// expression-bodied arrow: treat as a return
	return []nir.Stmt{nir.Return{Value: c.expr(n)}}
}

func (c *jsConv) funcParams(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	params := field(n, "parameters")
	if params == nil {
		params = field(n, "parameter")
	}
	if params == nil {
		for _, ch := range children(n) {
			switch ch.Kind() {
			case "formal_parameters", "parameters":
				params = ch
			}
			if params != nil {
				break
			}
		}
	}
	if out := c.params(params); len(out) > 0 {
		return out
	}
	return c.paramsFromFunctionText(n)
}

func (c *jsConv) funcParamTypes(n *tree_sitter.Node) map[string]string {
	if n == nil {
		return nil
	}
	params := field(n, "parameters")
	if params == nil {
		params = field(n, "parameter")
	}
	if params == nil {
		for _, ch := range children(n) {
			switch ch.Kind() {
			case "formal_parameters", "parameters":
				params = ch
			}
			if params != nil {
				break
			}
		}
	}
	out := c.paramTypes(params)
	if len(out) == 0 {
		return jsParamTypesFromText(c.text(n))
	}
	return out
}

func (c *jsConv) funcBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	body := field(n, "body")
	if body == nil {
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "statement_block" {
				body = ch
				break
			}
		}
	}
	return c.body(body)
}

func (c *jsConv) isFunctionLikeDeclarator(n *tree_sitter.Node) bool {
	txt := c.text(n)
	if i := strings.IndexByte(txt, '='); i >= 0 {
		txt = strings.TrimSpace(txt[i+1:])
	}
	return strings.HasPrefix(txt, "function") ||
		strings.HasPrefix(txt, "async function") ||
		strings.HasPrefix(txt, "async (") ||
		strings.HasPrefix(txt, "(") && strings.Contains(txt, "=>") ||
		isJSIdentPrefixArrow(txt)
}

func (c *jsConv) paramsFromFunctionText(n *tree_sitter.Node) []string {
	txt := c.text(n)
	start := strings.IndexByte(txt, '(')
	if start < 0 {
		return nil
	}
	depth, end := 0, -1
	for i := start; i < len(txt); i++ {
		switch txt[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				i = len(txt)
			}
		}
	}
	if end <= start {
		return nil
	}
	var out []string
	for _, p := range strings.Split(txt[start+1:end], ",") {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, "...")
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = strings.TrimSpace(p[:i])
		}
		if isJSIdent(p) {
			out = append(out, p)
		}
	}
	return out
}

func isJSIdentPrefixArrow(s string) bool {
	i := strings.Index(s, "=>")
	if i < 0 {
		return false
	}
	return isJSIdent(strings.TrimSpace(s[:i]))
}

func isJSIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// jsRouteDecorators are NestJS HTTP-method decorators that mark a request handler.
var jsRouteDecorators = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
	"Options": true, "Head": true, "All": true,
}

// jsHasRouteDecorator reports whether a method_definition carries a NestJS route
// decorator (`@Get()`, `@Post(':id')`, …) — a `decorator` child whose callee name
// (identifier of the call, or a bare identifier) is an HTTP-method decorator.
// isIpcHandler reports whether a call path registers an Electron IPC handler
// (`ipcMain.on/handle/once`, `ipcRenderer.on/once`) whose callback receives
// renderer-controlled data.
func (c *jsConv) isIpcHandler(path string) bool {
	if !strings.Contains(path, "ipcMain") && !strings.Contains(path, "ipcRenderer") {
		return false
	}
	return strings.HasSuffix(path, ".on") || strings.HasSuffix(path, ".handle") || strings.HasSuffix(path, ".once")
}

// seedIpcLambda seeds an IPC callback's payload parameters (every param after the
// first `event` arg) as http_input.
func (c *jsConv) seedIpcLambda(lam nir.Lambda, L string) nir.Lambda {
	var seed []nir.Stmt
	for i, p := range lam.Params {
		if i == 0 { // the IPC `event` object, not the payload
			continue
		}
		seed = append(seed, nir.Assign{Targets: []string{p},
			Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
	}
	lam.Body = append(seed, lam.Body...)
	return lam
}

func (c *jsConv) jsDecoratorTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "decorator" {
			continue
		}
		path := c.jsDecoratorPath(ch)
		add("decorator_path:" + path)
		if i := strings.LastIndex(path, "."); i >= 0 {
			add("decorator_method:" + path[i+1:])
		} else {
			add("decorator_method:" + path)
		}
	}
	return out
}

func (c *jsConv) jsDecoratorPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "decorator", "call_expression":
		if p := c.jsDecoratorPath(field(n, "function")); p != "" {
			return p
		}
	case "member_expression":
		base := c.jsDecoratorPath(field(n, "object"))
		prop := c.text(field(n, "property"))
		if base == "" {
			return prop
		}
		if prop == "" {
			return base
		}
		return base + "." + prop
	case "identifier":
		return c.text(n)
	}
	for _, ch := range namedChildren(n) {
		if p := c.jsDecoratorPath(ch); p != "" {
			return p
		}
	}
	return ""
}

func (c *jsConv) jsHasRouteDecorator(n *tree_sitter.Node) bool {
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "decorator" {
			continue
		}
		var name string
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			if m == nil || name != "" {
				return
			}
			switch m.Kind() {
			case "identifier":
				name = c.text(m)
			case "call_expression":
				walk(field(m, "function"))
			case "member_expression":
				if p := field(m, "property"); p != nil {
					name = c.text(p)
				}
			default:
				for _, k := range namedChildren(m) {
					walk(k)
				}
			}
		}
		walk(ch)
		if jsRouteDecorators[name] {
			return true
		}
	}
	return false
}

func (c *jsConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	// single-identifier arrow param: x => ...
	if params.Kind() == "identifier" {
		return []string{c.text(params)}
	}
	var out []string
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			out = append(out, c.text(ch))
		case "required_parameter", "optional_parameter":
			if pat := field(ch, "pattern"); pat != nil && pat.Kind() == "identifier" {
				out = append(out, c.text(pat))
			}
		case "assignment_pattern":
			if l := field(ch, "left"); l != nil && l.Kind() == "identifier" {
				out = append(out, c.text(l))
			}
		}
	}
	return out
}

func (c *jsConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	if params.Kind() == "identifier" {
		return out
	}
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			if typ := jsTypeAnnotationAfter(c, params, ch); typ != "" {
				putParamType(out, c.text(ch), typ)
			}
		case "required_parameter", "optional_parameter":
			if pat := field(ch, "pattern"); pat != nil && pat.Kind() == "identifier" {
				putParamType(out, c.text(pat), paramTypeFromField(c, ch))
			}
		case "assignment_pattern":
			if l := field(ch, "left"); l != nil && l.Kind() == "identifier" {
				putParamType(out, c.text(l), paramTypeFromField(c, ch))
			}
		}
	}
	return out
}

func jsTypeAnnotationAfter(c *jsConv, parent, id *tree_sitter.Node) string {
	if parent == nil || id == nil {
		return ""
	}
	seen := false
	for _, ch := range namedChildren(parent) {
		if sameTSNode(ch, id) {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		switch ch.Kind() {
		case "type_annotation":
			return c.text(ch)
		case "identifier", "required_parameter", "optional_parameter", "assignment_pattern":
			return ""
		}
	}
	return ""
}

func jsParamTypesFromText(s string) map[string]string {
	out := map[string]string{}
	start := strings.Index(s, "(")
	end := strings.Index(s, ")")
	if start < 0 || end <= start {
		return out
	}
	for _, part := range strings.Split(s[start+1:end], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if eq := strings.Index(part, "="); eq >= 0 {
			part = strings.TrimSpace(part[:eq])
		}
		colon := strings.Index(part, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(part[:colon])
		name = strings.TrimPrefix(name, "...")
		typ := strings.TrimSpace(part[colon+1:])
		putParamType(out, name, typ)
	}
	return out
}

func sameTSNode(a, b *tree_sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

func (c *jsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier", "property_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "this", "super":
		// model `this`/`super` as a Name so `this.method()` resolves to the enclosing class's
		// method (interprocedural taint through `this.helper(x)`), incl. inside arrow callbacks.
		return nir.Name{ID: "this", Loc: L}
	case "number":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "regex":
		// carry the literal `/pattern/flags` so a `filter` directive can analyze the
		// output alphabet of x.replace(/…/g, repl).
		return nir.Const{Loc: L, Value: c.text(n)}
	case "true", "false", "null", "undefined":
		// carry the literal text so value-matching sees rejectUnauthorized=false etc.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "member_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "property")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(field(n, "object")), Key: c.expr(field(n, "index")), Path: c.dotted(field(n, "object")), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
		if path == "?" && strings.HasPrefix(strings.TrimSpace(c.text(n)), "import(") {
			path = "import"
		}
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		// Electron IPC handler registration `ipcMain.on/handle/once(channel, (event, arg) => …)`:
		// the callback's args after `event` are renderer-controlled — seed them.
		if c.isIpcHandler(path) {
			for i, a := range arglist {
				if lam, ok := a.(nir.Lambda); ok {
					arglist[i] = c.seedIpcLambda(lam, L)
				}
			}
		}
		if c.isExpressRouteRegistration(path) {
			for i, a := range arglist {
				if lam, ok := a.(nir.Lambda); ok {
					arglist[i] = c.typeExpressLambda(lam)
				}
			}
		}
		method := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			method = path[i+1:]
		}
		callee := c.expr(fn)
		if fn == nil && path == "import" {
			callee = nir.Name{ID: "import", Loc: L}
		}
		return nir.Call{Callee: callee, Args: arglist, Path: path, Method: method, Loc: L}
	case "new_expression":
		ctor := field(n, "constructor")
		path := c.dotted(ctor)
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			for _, a := range namedChildren(args) {
				arglist = append(arglist, c.expr(a))
			}
		}
		method := path
		if i := strings.LastIndex(path, "."); i >= 0 {
			method = path[i+1:]
		}
		return nir.Call{Callee: c.expr(ctor), Args: arglist, Path: path, Method: method, Loc: L}
	case "await_expression", "parenthesized_expression", "non_null_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "arrow_function", "function_expression", "function":
		// a single bare arrow param `v => …` is under the `parameter` field, not `parameters`.
		return nir.Lambda{Params: c.funcParams(n), ParamTypes: c.funcParamTypes(n), Body: c.funcBody(n), Loc: L}
	case "binary_expression":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "+" {
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L} // string concat / add
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "unary_expression":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "argument")), Loc: L}
	case "ternary_expression":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "template_string":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "template_substitution" {
				if kids := namedChildren(ch); len(kids) > 0 {
					parts = append(parts, c.expr(kids[0]))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "string":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "array", "arguments", "sequence_expression":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "object":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			switch ch.Kind() {
			case "pair":
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			case "shorthand_property_identifier", "shorthand_property_identifier_pattern":
				// `{ filter }` === `{ filter: filter }` — the property carries the variable's taint.
				nm := c.text(ch)
				parts = append(parts, nir.Pair{Key: nm, Value: nir.Name{ID: nm, Loc: L}, Loc: L})
			case "spread_element":
				if k := namedChildren(ch); len(k) > 0 {
					parts = append(parts, c.expr(k[len(k)-1]))
				}
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

var jsExpressRouteMethods = map[string]bool{
	"all": true, "delete": true, "get": true, "head": true, "options": true,
	"patch": true, "post": true, "put": true, "use": true,
}

func (c *jsConv) isExpressRouteRegistration(path string) bool {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return false
	}
	return jsExpressRouteMethods[path[i+1:]]
}

func (c *jsConv) typeExpressLambda(lam nir.Lambda) nir.Lambda {
	if len(lam.Params) == 0 {
		return lam
	}
	if lam.ParamTypes == nil {
		lam.ParamTypes = map[string]string{}
	}
	offset := 0
	if len(lam.Params) >= 4 {
		offset = 1 // Express error middleware: (err, req, res, next)
	}
	if offset < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset]] = "express.Request"
	}
	if offset+1 < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset+1]] = "express.Response"
	}
	if offset+2 < len(lam.Params) {
		lam.ParamTypes[lam.Params[offset+2]] = "express.NextFunction"
	}
	return lam
}

func (c *jsConv) bindingNames(n *tree_sitter.Node) []string {
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		switch cur.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			name := c.text(cur)
			if name != "" {
				out = append(out, name)
			}
			return
		}
		for _, ch := range namedChildren(cur) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

// keyName returns the bare name of an object-pair key — an identifier as-is, or a
// quoted string key with its surrounding quotes stripped.
func (c *jsConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	if n.Kind() == "string" && len(t) >= 2 {
		t = t[1 : len(t)-1]
	}
	return t
}

func (c *jsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "property_identifier":
		return c.text(n)
	case "member_expression":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "property"))
	case "call_expression":
		return c.dotted(field(n, "function"))
	case "subscript_expression":
		return c.dotted(field(n, "object")) + "[]"
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	}
	return "?"
}

func lastIdent(n *tree_sitter.Node) *tree_sitter.Node {
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "identifier" {
			return ch
		}
	}
	return nil
}

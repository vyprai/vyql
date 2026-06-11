package treesitter

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// jsConv walks a tree-sitter JavaScript/TypeScript CST into NIR. The JS grammar
// covers JSX and most of TS surface; for TS we parse with the JS grammar (type
// annotations are skipped as unknown nodes), which is enough for taint.
type jsConv struct {
	src  []byte
	root string
	file string
	key  string
}

// ExtractJavaScript parses JS/TS files into one NIR Program.
func ExtractJavaScript(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsjs.Language()))

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
		c := &jsConv{src: src, root: root, file: rel, key: jsModuleKey(root, f)}
		root0 := tree.RootNode()
		mod := nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: c.blockChildren(root0)}
		prog.Modules = append(prog.Modules, mod)
		tree.Close()
	}
	return prog, nil
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
			mod := strings.Trim(src, "'\"`")
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
		return []nir.Stmt{nir.FuncDef{Name: name, Params: c.params(field(n, "parameters")), Body: c.body(field(n, "body")), Loc: L}}
	case "class_declaration":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.body(field(n, "body")), Loc: L}}
	case "lexical_declaration", "variable_declaration":
		var out []nir.Stmt
		for _, d := range namedChildren(n) {
			if d.Kind() == "variable_declarator" {
				name := field(d, "name")
				val := field(d, "value")
				var v nir.Expr = nir.Const{Loc: L}
				if val != nil {
					v = c.expr(val)
				}
				if name != nil && name.Kind() == "identifier" {
					out = append(out, nir.Assign{Targets: []string{c.text(name)}, Value: v})
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
	case "if_statement", "while_statement", "for_statement", "for_in_statement":
		var inner []nir.Stmt
		if cond := field(n, "condition"); cond != nil {
			inner = append(inner, nir.ExprStmt{Value: c.expr(cond)})
		}
		inner = append(inner, c.collectStatementBlocks(n)...)
		return []nir.Stmt{nir.Block{Stmts: inner}}
	case "try_statement", "statement_block":
		return []nir.Stmt{nir.Block{Stmts: c.collectStatementBlocks(n)}}
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
	case "assignment_expression":
		left := field(inner, "left")
		rhs := field(inner, "right")
		// CommonJS function exports become named FuncDefs so cross-file calls
		// resolve: `exports.f = function…`, `module.exports.f = …`, and
		// `module.exports = { f: function… }`.
		if left != nil && left.Kind() == "member_expression" && isJsFuncNode(rhs) {
			if name := c.exportFuncName(left); name != "" {
				return []nir.Stmt{nir.FuncDef{Name: name, Params: c.params(field(rhs, "parameters")), Body: c.body(field(rhs, "body")), Loc: L}}
			}
		}
		if left != nil && c.isModuleExports(left) && rhs != nil && rhs.Kind() == "object" {
			var out []nir.Stmt
			for _, pr := range namedChildren(rhs) {
				if pr.Kind() == "pair" && isJsFuncNode(field(pr, "value")) {
					v := field(pr, "value")
					out = append(out, nir.FuncDef{Name: c.keyName(field(pr, "key")), Params: c.params(field(v, "parameters")), Body: c.body(field(v, "body")), Loc: L})
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
		// member-property write (e.g. el.innerHTML = x, location.href = x): model as a
		// PATH sink call so DOM-XSS / open-redirect `sink path "innerHTML"` etc. fire.
		// Method is empty so it can never collide with method-name sinks (query/exec/…).
		if left != nil && left.Kind() == "member_expression" {
			p := c.dotted(left)
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right}, Path: p, Method: "", Loc: L}}}
		}
		// subscript / other assignment: still evaluate RHS for effect
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

// collectStatementBlocks gathers statements from nested statement_blocks and
// clause bodies (flow-approximate).
func (c *jsConv) collectStatementBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
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
	if n.Kind() == "statement_block" {
		return c.blockChildren(n)
	}
	// expression-bodied arrow: treat as a return
	return []nir.Stmt{nir.Return{Value: c.expr(n)}}
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

func (c *jsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier", "property_identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "number", "regex":
		return nir.Const{Loc: L}
	case "true", "false", "null", "undefined":
		// carry the literal text so value-matching sees rejectUnauthorized=false etc.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "member_expression":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "property")), Path: c.dotted(n), Loc: L}
	case "subscript_expression":
		return nir.Index{Base: c.expr(field(n, "object")), Path: c.dotted(field(n, "object")), Loc: L}
	case "call_expression":
		fn := field(n, "function")
		path := c.dotted(fn)
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
		return nir.Call{Callee: c.expr(fn), Args: arglist, Path: path, Method: method, Loc: L}
	case "await_expression", "parenthesized_expression", "non_null_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "arrow_function", "function_expression", "function":
		return nir.Lambda{Params: c.params(field(n, "parameters")), Body: c.body(field(n, "body")), Loc: L}
	case "binary_expression":
		if c.text(field(n, "operator")) == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
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
			if ch.Kind() == "pair" {
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "ternary_expression":
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "consequence")), c.expr(field(n, "alternative"))}, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
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

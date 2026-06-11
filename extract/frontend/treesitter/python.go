// Package treesitter holds REAL parser frontends built on tree-sitter (docs/20:
// the recommended production parser — a uniform node API across 100+ languages,
// error recovery, build-free). Each grammar's CST node vocabulary is yet another
// shape, but every frontend targets the SAME NIR and runs through the SAME
// lowering engine, so resolution and rules are untouched (ADR 0003).
//
// This file is the Python frontend, ported from poc/extract/frontend_ts.py.
package treesitter

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tspython "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// pyConv walks a tree-sitter Python CST into NIR.
type pyConv struct {
	src  []byte
	root string // scan root, for display-relative loc
	file string // current file (display path, relative to root)
	key  string // current module key (source-root dotted)
}

// ExtractPython parses Python files into one NIR Program (one module per file,
// keyed by its source-root-relative dotted path so imports resolve).
func ExtractPython(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tspython.Language()))

	var prog nir.Program
	prog.SelfName = "self"
	for _, f := range files {
		src, err := readFile(f)
		if err != nil {
			continue // skip unreadable
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		rel := relPath(root, f)
		c := &pyConv{src: src, root: root, file: rel, key: moduleKey(root, f, ".py")}
		root0 := tree.RootNode()
		mod := nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: c.blockChildren(root0)}
		prog.Modules = append(prog.Modules, mod)
		tree.Close()
	}
	return prog, nil
}

func (c *pyConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *pyConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func field(n *tree_sitter.Node, name string) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(name)
}

func namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	out := make([]*tree_sitter.Node, 0, n.NamedChildCount())
	for i := uint(0); i < n.NamedChildCount(); i++ {
		out = append(out, n.NamedChild(i))
	}
	return out
}

func children(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	out := make([]*tree_sitter.Node, 0, n.ChildCount())
	for i := uint(0); i < n.ChildCount(); i++ {
		out = append(out, n.Child(i))
	}
	return out
}

func (c *pyConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		switch n.Kind() {
		case "import_statement":
			for _, ch := range namedChildren(n) {
				if ch.Kind() == "aliased_import" {
					nm := c.text(orSelf(field(ch, "name"), ch))
					al := field(ch, "alias")
					local := nm
					if al != nil {
						local = c.text(al)
					} else {
						local = firstSeg(nm)
					}
					out = append(out, nir.Import{Local: local, Module: nm, IsModule: true})
				} else {
					nm := c.text(ch)
					out = append(out, nir.Import{Local: firstSeg(nm), Module: nm, IsModule: true})
				}
			}
		case "import_from_statement":
			mod := field(n, "module_name")
			modtxt := c.text(mod)
			for _, ch := range namedChildren(n) {
				if ch == mod {
					continue
				}
				switch ch.Kind() {
				case "dotted_name", "identifier":
					nm := c.text(ch)
					out = append(out, nir.Import{Local: lastSeg(nm), Module: modtxt, Symbol: nm})
				case "aliased_import":
					nm := c.text(field(ch, "name"))
					al := field(ch, "alias")
					local := nm
					if al != nil {
						local = c.text(al)
					}
					out = append(out, nir.Import{Local: local, Module: modtxt, Symbol: nm})
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

// blockChildren lowers the statements of a node's named children.
func (c *pyConv) blockChildren(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *pyConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition":
		name := c.text(field(n, "name"))
		params := c.params(field(n, "parameters"))
		body := c.block(field(n, "body"))
		// GraphQL (graphene/ariadne) resolver: `def resolve_x(self, info, arg…)` —
		// the args after self/info/root/parent are the query's user-supplied inputs.
		if strings.HasPrefix(name, "resolve_") {
			body = append(c.seedResolverParams(params, L), body...)
		}
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, Body: body, Loc: L}}
	case "decorated_definition":
		def := field(n, "definition")
		if def == nil {
			cs := namedChildren(n)
			if len(cs) > 0 {
				def = cs[len(cs)-1]
			}
		}
		if def == nil {
			return nil
		}
		// FastAPI/Flask/Starlette route handlers: `@app.get(...)`, `@router.post(...)`,
		// `@app.route(...)` — the function's parameters are bound from the request
		// (path/query/body), so seed each as http_input (like Java controllers).
		if def.Kind() == "function_definition" && c.hasRouteDecorator(n) {
			params := c.params(field(def, "parameters"))
			body := c.block(field(def, "body"))
			var seed []nir.Stmt
			for _, p := range params {
				if p == "self" || p == "cls" {
					continue
				}
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			return []nir.Stmt{nir.FuncDef{Name: c.text(field(def, "name")), Params: params, Body: append(seed, body...), Loc: L}}
		}
		return c.stmt(def)
	case "class_definition":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.block(field(n, "body")), Loc: L}}
	case "expression_statement":
		kids := namedChildren(n)
		if len(kids) == 0 {
			return nil
		}
		inner := kids[0]
		switch inner.Kind() {
		case "assignment":
			right := field(inner, "right")
			var val nir.Expr = nir.Const{Loc: L}
			if right != nil {
				val = c.expr(right)
			}
			return []nir.Stmt{nir.Assign{Targets: c.targets(field(inner, "left")), Value: val}}
		case "augmented_assignment":
			left := field(inner, "left")
			if left != nil && left.Kind() == "identifier" {
				return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: c.expr(field(inner, "right")), Loc: L}}
			}
			return nil
		default:
			return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
		}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if_statement", "while_statement":
		var inner []nir.Stmt
		if cond := field(n, "condition"); cond != nil {
			inner = append(inner, nir.ExprStmt{Value: c.expr(cond)})
		}
		inner = append(inner, c.collectBlocks(n)...)
		return []nir.Stmt{nir.Block{Stmts: inner}}
	case "for_statement":
		var inner []nir.Stmt
		left, right := field(n, "left"), field(n, "right")
		if left != nil && left.Kind() == "identifier" && right != nil {
			inner = append(inner, nir.Assign{Targets: []string{c.text(left)}, Value: c.expr(right)})
		}
		inner = append(inner, c.collectBlocks(n)...)
		return []nir.Stmt{nir.Block{Stmts: inner}}
	case "with_statement", "try_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectBlocks(n)}}
	}
	return nil
}

func (c *pyConv) collectBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range children(n) {
		switch ch.Kind() {
		case "block":
			out = append(out, c.block(ch)...)
		case "elif_clause", "else_clause", "except_clause", "finally_clause", "with_clause":
			for _, cc := range children(ch) {
				if cc.Kind() == "block" {
					out = append(out, c.block(cc)...)
				}
			}
		}
	}
	return out
}

func (c *pyConv) block(block *tree_sitter.Node) []nir.Stmt {
	if block == nil {
		return nil
	}
	return c.blockChildren(block)
}

// pyRouteMethods are the decorator attributes that mark a request handler whose
// parameters are bound from the request (FastAPI/Flask/Starlette/APIRouter).
var pyRouteMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "patch": true,
	"head": true, "options": true, "route": true, "websocket": true, "api_route": true,
}

// seedResolverParams seeds a GraphQL resolver's query-argument params (those
// after the conventional self/info/root/parent positions) as http_input.
func (c *pyConv) seedResolverParams(params []string, L string) []nir.Stmt {
	skip := map[string]bool{"self": true, "cls": true, "info": true, "root": true, "parent": true, "_": true}
	var seed []nir.Stmt
	for _, p := range params {
		if skip[p] {
			continue
		}
		seed = append(seed, nir.Assign{Targets: []string{p},
			Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
	}
	return seed
}

// hasRouteDecorator reports whether a decorated_definition carries a route
// decorator like `@app.get("/x")` / `@router.post(...)` / `@app.route(...)`.
func (c *pyConv) hasRouteDecorator(n *tree_sitter.Node) bool {
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "decorator" {
			continue
		}
		// the decorator's expression: a call (`app.get(...)`) or bare attribute.
		var name string
		var walk func(m *tree_sitter.Node)
		walk = func(m *tree_sitter.Node) {
			if m == nil || name != "" {
				return
			}
			if m.Kind() == "attribute" {
				if a := field(m, "attribute"); a != nil {
					name = c.text(a)
				}
				return
			}
			if m.Kind() == "call" {
				walk(field(m, "function"))
				return
			}
			for _, k := range namedChildren(m) {
				walk(k)
			}
		}
		walk(ch)
		if pyRouteMethods[name] {
			return true
		}
	}
	return false
}

func (c *pyConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			out = append(out, c.text(ch))
		case "default_parameter", "typed_parameter", "typed_default_parameter":
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else if kids := namedChildren(ch); len(kids) > 0 {
				out = append(out, c.text(kids[0]))
			}
		}
	}
	return out
}

func (c *pyConv) targets(left *tree_sitter.Node) []string {
	if left == nil {
		return nil
	}
	switch left.Kind() {
	case "identifier":
		return []string{c.text(left)}
	case "pattern_list", "tuple_pattern", "tuple":
		var out []string
		for _, ch := range namedChildren(left) {
			if ch.Kind() == "identifier" {
				out = append(out, c.text(ch))
			}
		}
		return out
	}
	return nil
}

func (c *pyConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer", "float", "concatenated_string":
		return nir.Const{Loc: L}
	case "true", "false", "none":
		// carry the literal text so value-matching can see verify=False etc.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "keyword_argument":
		return nir.Pair{Key: c.keyName(field(n, "name")), Value: c.expr(field(n, "value")), Loc: L}
	case "dictionary":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "pair" {
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "attribute":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "attribute")), Path: c.dotted(n), Loc: L}
	case "subscript":
		return nir.Index{Base: c.expr(field(n, "value")), Path: c.dotted(field(n, "value")), Loc: L}
	case "call":
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
	case "await":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
	case "binary_operator":
		op := c.text(field(n, "operator"))
		if op == "%" || op == "+" {
			return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "string":
		var interps []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "interpolation" {
				e := field(ch, "expression")
				if e == nil {
					if kids := namedChildren(ch); len(kids) > 0 {
						e = kids[0]
					}
				}
				if e != nil {
					interps = append(interps, c.expr(e))
				}
			}
		}
		if len(interps) > 0 {
			return nir.Format{Parts: interps, Loc: L}
		}
		return nir.Const{Loc: L, Value: c.text(n)}
	case "tuple", "list":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "parenthesized_expression":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.expr(kids[0])
		}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// keyName returns the bare name of a Pair key node — an identifier as-is, or a
// string-literal key with its surrounding quotes stripped.
func (c *pyConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	if n.Kind() == "string" && len(t) >= 2 {
		t = t[1 : len(t)-1]
	}
	return t
}

func (c *pyConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier":
		return c.text(n)
	case "attribute":
		return c.dotted(field(n, "object")) + "." + c.text(field(n, "attribute"))
	case "call":
		return c.dotted(field(n, "function"))
	case "subscript":
		return c.dotted(field(n, "value")) + "[]"
	}
	return "?"
}

// --- shared helpers (used by all tree-sitter frontends) -----------------

func orSelf(n, fallback *tree_sitter.Node) *tree_sitter.Node {
	if n != nil {
		return n
	}
	return fallback
}

func firstSeg(s string) string {
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i]
	}
	return s
}

func lastSeg(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func relPath(root, f string) string {
	if r, err := filepath.Rel(root, f); err == nil {
		return r
	}
	return f
}

// moduleKey turns a file path into a source-root-relative dotted module key
// (so `from a.b import c` resolves to module "a.b").
func moduleKey(root, f, ext string) string {
	rel := relPath(root, f)
	rel = strings.TrimSuffix(rel, ext)
	key := strings.ReplaceAll(rel, string(filepath.Separator), ".")
	return strings.TrimSuffix(key, ".__init__")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

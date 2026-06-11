package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	elixir "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/elixir"

	"github.com/vyprai/vyql/extract/nir"
)

// exConv walks a tree-sitter Elixir CST into NIR. Elixir models everything as a
// `call` (defmodule/def are calls with a do_block); module calls are `dot`
// (alias + function). `<>` builds strings, `|>` pipes the LHS as the first arg.
type exConv struct {
	src  []byte
	file string
	key  string
}

// ExtractElixir parses Elixir files into one NIR Program (one module per file).
func ExtractElixir(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(elixir.Language()))

	var prog nir.Program
	prog.SelfName = "self"
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
		c := &exConv{src: src, file: rel, key: moduleKey(root, f, ".ex")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *exConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *exConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls walks a node's statements, descending into defmodule do_blocks so nested
// functions surface as top-level FuncDefs.
func (c *exConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *exConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "call":
		return c.callStmt(n)
	case "binary_operator":
		if c.text(field(n, "operator")) == "=" {
			left := field(n, "left")
			right := c.expr(field(n, "right"))
			if left != nil && left.Kind() == "identifier" {
				return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
			}
			return []nir.Stmt{nir.ExprStmt{Value: right}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "do_block", "block":
		return c.decls(n)
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// callStmt handles defmodule/def/defp specially; everything else is an expression.
func (c *exConv) callStmt(n *tree_sitter.Node) []nir.Stmt {
	kids := namedChildren(n)
	if len(kids) == 0 {
		return nil
	}
	head := kids[0]
	name := ""
	if head.Kind() == "identifier" {
		name = c.text(head)
	}
	switch name {
	case "defmodule", "defprotocol", "defimpl":
		if do := lastChildKind(n, "do_block"); do != nil {
			return c.decls(do)
		}
		return nil
	case "def", "defp", "defmacro":
		return c.funcDef(n)
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// funcDef builds a FuncDef from `def name(params) do … end`. A Phoenix/Plug action
// `def action(conn, params)` has its non-conn params seeded as http_input.
func (c *exConv) funcDef(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	args := lastChildKind(n, "arguments")
	var fname string
	var params []string
	if args != nil {
		for _, a := range namedChildren(args) {
			if a.Kind() == "call" { // name(params)
				if h := firstNamed(a); h != nil {
					fname = c.text(h)
				}
				if pa := lastChildKind(a, "arguments"); pa != nil {
					for _, p := range namedChildren(pa) {
						params = append(params, c.patName(p))
					}
				}
			} else if a.Kind() == "identifier" && fname == "" { // name with no parens
				fname = c.text(a)
			}
		}
	}
	body := []nir.Stmt{}
	if do := lastChildKind(n, "do_block"); do != nil {
		body = c.decls(do)
	}
	// Phoenix controller action / Plug: first param `conn` → the rest are request data.
	if len(params) > 1 && (params[0] == "conn" || params[0] == "_conn") {
		var seed []nir.Stmt
		for _, p := range params[1:] {
			if p == "" || p == "_" {
				continue
			}
			seed = append(seed, nir.Assign{Targets: []string{p},
				Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
		}
		body = append(seed, body...)
	}
	return []nir.Stmt{nir.FuncDef{Name: fname, Params: params, Body: body, Loc: L}}
}

func (c *exConv) patName(n *tree_sitter.Node) string {
	switch n.Kind() {
	case "identifier":
		return c.text(n)
	case "binary_operator": // default param `x \\ v`, or pattern — take left
		return c.patName(field(n, "left"))
	}
	return ""
}

func (c *exConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "alias":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer", "float", "boolean", "nil", "atom", "char":
		return nir.Const{Loc: L}
	case "string", "charlist":
		// strings with #{…} interpolation propagate taint.
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "interpolation" {
				for _, e := range namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L}
	case "call":
		return c.callExpr(n)
	case "dot":
		// `conn.params` (lowercase base) is a struct-field read → Attr source node;
		// `System.cmd` (alias base) is a module reference → Name.
		kids := namedChildren(n)
		if len(kids) == 2 && kids[0].Kind() == "identifier" {
			return nir.Attr{Base: c.expr(kids[0]), Attr: c.text(kids[1]), Path: c.dotted(n), Loc: L}
		}
		return nir.Name{ID: c.dotted(n), Loc: L}
	case "access_call": // params["key"]
		kids := namedChildren(n)
		var base nir.Expr = nir.Const{Loc: L}
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		return nir.Index{Base: base, Path: c.dotted(n), Loc: L}
	case "binary_operator":
		op := c.text(field(n, "operator"))
		l, r := field(n, "left"), field(n, "right")
		switch op {
		case "<>", "+", "<<>>":
			return nir.Format{Parts: []nir.Expr{c.expr(l), c.expr(r)}, Loc: L}
		case "|>":
			// a |> f(b…)  ==  f(a, b…): the LHS flows in as the first argument.
			return c.pipe(l, r, L)
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(l), c.expr(r)}, Loc: L}
	case "unary_operator":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[len(kids)-1])}
		}
	case "list", "tuple", "bitstring":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "keywords", "pair":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	// fall back: union of children (taint-approximate)
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// callExpr lowers a function/module call to nir.Call with a dotted path.
func (c *exConv) callExpr(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	kids := namedChildren(n)
	if len(kids) == 0 {
		return nir.Const{Loc: L}
	}
	fn := kids[0]
	path := c.dotted(fn)
	var args []nir.Expr
	if a := lastChildKind(n, "arguments"); a != nil {
		for _, ch := range namedChildren(a) {
			args = append(args, c.expr(ch))
		}
	}
	return nir.Call{Callee: c.expr(fn), Args: args, Path: path, Method: lastSeg(path), Loc: L}
}

// pipe rewrites `left |> right` so the left value flows into the right call as its
// first argument (taint-preserving).
func (c *exConv) pipe(left, right *tree_sitter.Node, L string) nir.Expr {
	lv := c.expr(left)
	if right != nil && right.Kind() == "call" {
		kids := namedChildren(right)
		if len(kids) > 0 {
			fn := kids[0]
			path := c.dotted(fn)
			args := []nir.Expr{lv}
			if a := lastChildKind(right, "arguments"); a != nil {
				for _, ch := range namedChildren(a) {
					args = append(args, c.expr(ch))
				}
			}
			return nir.Call{Callee: c.expr(fn), Args: args, Path: path, Method: lastSeg(path), Loc: L}
		}
	}
	if right != nil && (right.Kind() == "identifier" || right.Kind() == "dot") {
		path := c.dotted(right)
		return nir.Call{Callee: c.expr(right), Args: []nir.Expr{lv}, Path: path, Method: lastSeg(path), Loc: L}
	}
	return nir.Format{Parts: []nir.Expr{lv, c.expr(right)}, Loc: L}
}

func (c *exConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "alias", "atom":
		return c.text(n)
	case "dot":
		kids := namedChildren(n)
		if len(kids) == 2 {
			return c.dotted(kids[0]) + "." + c.dotted(kids[1])
		}
		if len(kids) == 1 {
			return c.dotted(kids[0])
		}
	case "call":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	case "access_call":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0]) + "[]"
		}
	}
	return "?"
}

func firstNamed(n *tree_sitter.Node) *tree_sitter.Node {
	if n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

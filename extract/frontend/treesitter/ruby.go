package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"

	"github.com/vyprai/vyql/extract/nir"
)

// rbConv walks a tree-sitter Ruby CST into NIR. Ruby has no per-file module
// namespacing and global classes, so the module key is "" for every file and
// there is no import table; "type resolution" is constant→class on the call
// receiver, handled uniformly by the shared lowering engine (as in the PoC's
// Ripper frontend). All binary operators are treated as taint-propagating
// (string build), matching frontend_ruby.py.
type rbConv struct {
	src  []byte
	root string
	file string
}

// ExtractRuby parses Ruby files into one NIR Program (all modules keyed "").
func ExtractRuby(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(tsruby.Language()))

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
		c := &rbConv{src: src, root: root, file: rel}
		mod := nir.Module{Key: "", File: rel, Body: c.blockChildren(tree.RootNode())}
		prog.Modules = append(prog.Modules, mod)
		tree.Close()
	}
	return prog, nil
}

func (c *rbConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *rbConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *rbConv) blockChildren(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, st := range namedChildren(n) {
		out = append(out, c.stmt(st)...)
	}
	return out
}

func (c *rbConv) body(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	// body_statement holds the method/class body statements
	return c.blockChildren(n)
}

func (c *rbConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "method", "singleton_method":
		return []nir.Stmt{nir.FuncDef{
			Name:   c.text(field(n, "name")),
			Params: c.params(field(n, "parameters")),
			Body:   c.body(field(n, "body")),
			Loc:    L,
		}}
	case "class", "module":
		return []nir.Stmt{nir.ClassDef{Name: c.text(field(n, "name")), Body: c.body(field(n, "body")), Loc: L}}
	case "assignment":
		left := field(n, "left")
		var targets []string
		if left != nil && (left.Kind() == "identifier" || left.Kind() == "constant" || left.Kind() == "instance_variable") {
			targets = []string{c.text(left)}
		}
		return []nir.Stmt{nir.Assign{Targets: targets, Value: c.expr(field(n, "right"))}}
	case "operator_assignment":
		left := field(n, "left")
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.AugAssign{Target: c.text(left), Value: c.expr(field(n, "right")), Loc: L}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(field(n, "right"))}}
	case "return", "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "if", "unless", "while", "until", "case", "begin", "for":
		return []nir.Stmt{nir.Block{Stmts: c.collectBodies(n)}}
	case "body_statement", "then", "else", "elsif", "ensure", "when", "do_block", "block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBodies(n)}}
	case "comment":
		return nil
	}
	// any other expression used as a statement
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// collectBodies gathers statements from a control node's body / clause children
// (flow-approximate).
func (c *rbConv) collectBodies(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "body_statement", "then", "else", "elsif", "ensure", "when", "do_block", "block":
			out = append(out, c.collectBodies(ch)...)
		case "comment":
		default:
			out = append(out, c.stmt(ch)...)
		}
	}
	return out
}

func (c *rbConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			out = append(out, c.text(ch))
		case "optional_parameter", "keyword_parameter", "splat_parameter", "typed_parameter":
			if nm := field(ch, "name"); nm != nil {
				out = append(out, c.text(nm))
			} else if kids := namedChildren(ch); len(kids) > 0 && kids[0].Kind() == "identifier" {
				out = append(out, c.text(kids[0]))
			}
		}
	}
	return out
}

func (c *rbConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier", "constant", "instance_variable", "global_variable":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer", "float", "true", "false", "nil", "simple_symbol", "hash_key_symbol":
		return nir.Const{Loc: L}
	case "string":
		return c.string(n, L)
	case "call", "method_call", "command", "command_call":
		return c.call(n, L)
	case "element_reference":
		return nir.Index{Base: c.expr(field(n, "object")), Path: c.dotted(field(n, "object")), Loc: L}
	case "binary":
		return nir.Format{Parts: []nir.Expr{c.expr(field(n, "left")), c.expr(field(n, "right"))}, Loc: L}
	case "parenthesized_statements":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.expr(kids[len(kids)-1])
		}
	case "array", "argument_list":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "hash":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "pair" {
				parts = append(parts, c.expr(field(ch, "value")))
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "scope_resolution":
		// A::B → treat as a Name on the dotted path
		return nir.Name{ID: c.dotted(n), Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *rbConv) string(n *tree_sitter.Node, L string) nir.Expr {
	var parts []nir.Expr
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range namedChildren(m) {
			if ch.Kind() == "interpolation" {
				for _, e := range namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			} else {
				walk(ch)
			}
		}
	}
	walk(n)
	if len(parts) > 0 {
		return nir.Format{Parts: parts, Loc: L}
	}
	// non-interpolated string: carry the literal text for value-matching (`val "…"`).
	return nir.Const{Loc: L, Value: c.text(n)}
}

func (c *rbConv) call(n *tree_sitter.Node, L string) nir.Expr {
	recv := field(n, "receiver")
	method := c.text(field(n, "method"))
	path := c.dotted(n)
	var callee nir.Expr
	if recv == nil {
		callee = nir.Name{ID: orQ(method), Loc: L}
	} else {
		callee = nir.Attr{Base: c.expr(recv), Attr: orQ(method), Path: path, Loc: L}
	}
	var args []nir.Expr
	if al := field(n, "arguments"); al != nil {
		for _, a := range namedChildren(al) {
			args = append(args, c.expr(a))
		}
	}
	m := method
	if m == "" {
		if i := strings.LastIndex(path, "."); i >= 0 {
			m = path[i+1:]
		} else {
			m = path
		}
	}
	return nir.Call{Callee: callee, Args: args, Path: path, Method: m, Loc: L}
}

func (c *rbConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "constant", "instance_variable", "global_variable":
		return c.text(n)
	case "call", "method_call", "command_call":
		recv := field(n, "receiver")
		method := c.text(field(n, "method"))
		if recv == nil {
			return orQ(method)
		}
		return c.dotted(recv) + "." + orQ(method)
	case "command":
		return orQ(c.text(field(n, "method")))
	case "element_reference":
		return c.dotted(field(n, "object")) + "[]"
	case "scope_resolution":
		base := field(n, "scope")
		name := c.text(field(n, "name"))
		if base == nil {
			return name
		}
		return c.dotted(base) + "." + name
	}
	return "?"
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

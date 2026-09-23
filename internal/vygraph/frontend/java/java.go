// Package java is the v3 Java frontend: source lowered into the closed NIR
// graph, same contract as the python and javascript reference frontends (see
// ENGINE-FORK.md). Structure and Region/Order only; the shared lowering
// computes FLOWS and resolution.
package java

import (
	"fmt"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Imports records module specifiers for resolution.
type Imports struct {
	Modules map[string]string // local binding -> module specifier
}

type Frontend struct {
	store   *graph.Store
	order   int64
	Imports map[string]Imports
}

func New(store *graph.Store) *Frontend {
	return &Frontend{store: store, Imports: map[string]Imports{}}
}

func (f *Frontend) Extract(file string, src []byte) error {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tree_sitter.NewLanguage(tsjava.Language()))
	tree := parser.Parse(src, nil)
	defer tree.Close()
	root := tree.RootNode()

	imp := Imports{Modules: map[string]string{}}
	c := &conv{f: f, src: src, file: file, region: "fn", skip: map[string]bool{}}
	c.collectImports(root, imp)
	f.Imports[file] = imp
	c.stmts(root)
	return nil
}

type conv struct {
	f      *Frontend
	src    []byte
	file   string
	region string
	skip   map[string]bool
}

func (c *conv) text(n *tree_sitter.Node) string { return string(c.src[n.StartByte():n.EndByte()]) }

func (c *conv) add(n *tree_sitter.Node, typ string, fields [][2]string, approx bool) (graph.Node, bool) {
	id := c.id(n, typ)
	if c.skip[id] {
		if got, ok := c.f.store.Node(id); ok && got.Type == typ {
			return got, true
		}
		return graph.Node{}, false
	}
	var flds graph.Fields
	p := n.StartPosition()
	flds.Set("file", graph.Str(c.file))
	flds.Set("line", graph.Int(int64(p.Row)+1))
	flds.Set("col", graph.Int(int64(p.Column)+1))
	flds.Set("region", graph.Str(c.region))
	flds.Set("order", graph.Int(c.f.order))
	flds.Set("approx_lowered", graph.Bool(approx))
	for _, kv := range fields {
		flds.Set(kv[0], graph.Str(kv[1]))
	}
	node := graph.Node{ID: id, Type: typ, Layer: graph.LayerLow, Fields: flds,
		Prov: graph.Provenance{Producer: "java", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
	if err := c.f.store.AddNode(node); err != nil {
		return graph.Node{}, false
	}
	c.skip[id] = true
	c.f.order++
	return node, true
}

func (c *conv) id(n *tree_sitter.Node, typ string) string {
	p := n.StartPosition()
	return fmt.Sprintf("%s:%d:%d:%s", c.file, p.Row+1, p.Column+1, typ)
}

func (c *conv) child(from, to graph.Node) {
	_ = c.f.store.AddEdge(graph.Edge{
		ID: "child:" + from.ID + ":" + to.ID, Type: "child", From: from.ID, To: to.ID,
		Prov: graph.Provenance{Producer: "java", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
	})
}

// defFlow: the assignment's value flows into the target binding.
func (c *conv) defFlow(value, target graph.Node) {
	if value.ID == "" || target.ID == "" || value.ID == target.ID {
		return
	}
	_ = c.f.store.AddEdge(graph.Edge{
		ID: "flows:def:" + value.ID + ":" + target.ID, Type: "FLOWS", From: value.ID, To: target.ID,
		Prov: graph.Provenance{Producer: "java", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
	})
}

func (c *conv) collectImports(root *tree_sitter.Node, imp Imports) {
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "import_declaration" {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				if d == nil {
					continue
				}
				switch d.Kind() {
				case "scoped_identifier", "identifier":
					full := c.text(d)
					segs := strings.Split(full, ".")
					imp.Modules[segs[len(segs)-1]] = full
				case "wildcard_import":
					// a wildcard cannot qualify a single name precisely
				}
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(uint(i)))
		}
	}
	walk(root)
}

func (c *conv) stmts(block *tree_sitter.Node) {
	for i := 0; i < int(block.NamedChildCount()); i++ {
		c.stmt(block.NamedChild(uint(i)))
	}
}

func (c *conv) structured(n *tree_sitter.Node, kind string, body func(outer string)) {
	outer := c.region + "/" + kind + fmt.Sprintf("#%d", n.StartPosition().Row+1)
	c.in(outer, func() { body(outer) })
}

func (c *conv) in(region string, fn func()) {
	saved := c.region
	c.region = region
	fn()
	c.region = saved
}

func (c *conv) stmt(n *tree_sitter.Node) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "method_declaration", "constructor_declaration":
		name := "init"
		if nm := n.ChildByFieldName("name"); nm != nil {
			name = c.text(nm)
		}
		c.functionDef(n, name)
	case "class_declaration":
		if b := n.ChildByFieldName("body"); b != nil {
			c.stmts(b)
		}
	case "local_variable_declaration":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			d := n.NamedChild(uint(i))
			if d == nil {
				continue
			}
			if d.Kind() == "type_identifier" || d.Kind() == "type_list" {
				continue
			}
			var target, value graph.Node
			for j := 0; j < int(d.NamedChildCount()); j++ {
				e := d.NamedChild(uint(j))
				if e == nil {
					continue
				}
				v := c.expr(e)
				if j == 0 {
					target = v
				} else {
					value = v
				}
			}
			c.defFlow(value, target)
		}
	case "expression_statement", "return_statement", "throw_statement", "comment":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.expr(n.NamedChild(uint(i)))
		}
	case "assignment_expression":
		var target, value graph.Node
		for j := 0; j < int(n.NamedChildCount()); j++ {
			e := n.NamedChild(uint(j))
			if e == nil {
				continue
			}
			v := c.expr(e)
			if j == 0 {
				target = v
			} else {
				value = v
			}
		}
		c.defFlow(value, target)
	case "if_statement":
		c.structured(n, "if", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				switch d.Kind() {
				case "parenthesized_expression", "binary_expression":
					c.expr(d)
				case "block":
					c.in(outer+"/then", func() { c.stmts(d) })
				case "else_clause", "else":
					c.in(outer+"/else", func() { c.stmts(d) })
				}
			}
		})
	case "for_statement", "enhanced_for_statement", "while_statement", "do_statement":
		c.structured(n, "loop", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				if d == nil {
					continue
				}
				if d.Kind() == "statement_block" || d.Kind() == "block" {
					c.in(outer+"/body", func() { c.stmts(d) })
					continue
				}
				c.expr(d)
			}
		})
	case "try_statement":
		c.structured(n, "try", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				switch d.Kind() {
				case "block", "constructor_body":
					if i == 0 {
						c.in(outer+"/body", func() { c.stmts(d) })
					} else {
						// finally encloses the body (post-dominance shape)
						c.in(outer, func() { c.stmts(d) })
					}
				case "catch_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						if e := d.NamedChild(uint(j)); e.Kind() == "statement_block" || e.Kind() == "block" {
							c.in(outer+"/except", func() { c.stmts(e) })
						}
					}
				}
			}
		})
	default:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.exprApprox(n.NamedChild(uint(i)))
		}
	}
}

func (c *conv) functionDef(n *tree_sitter.Node, name string) {
	fnNode, ok := c.add(n, "code.FuncDef", [][2]string{{"name", name}, {"qualified_name", c.file}}, false)
	if !ok {
		return
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		idx := 0
		for j := 0; j < int(params.NamedChildCount()); j++ {
			p := params.NamedChild(uint(j))
			if p == nil {
				continue
			}
			pname := c.paramName(p)
			if pname == "" {
				continue
			}
			id := c.id(p, "code.ParamEntry")
			if c.skip[id] {
				continue
			}
			var pf graph.Fields
			pp := p.StartPosition()
			pf.Set("file", graph.Str(c.file))
			pf.Set("line", graph.Int(int64(pp.Row)+1))
			pf.Set("col", graph.Int(int64(pp.Column)+1))
			pf.Set("region", graph.Str(c.region))
			pf.Set("order", graph.Int(c.f.order))
			pf.Set("approx_lowered", graph.Bool(false))
			pf.Set("name", graph.Str(pname))
			pf.Set("scope", graph.Str(name))
			pn := graph.Node{ID: id, Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pf,
				Prov: graph.Provenance{Producer: "java", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
			if err := c.f.store.AddNode(pn); err != nil {
				continue
			}
			c.skip[id] = true
			c.f.order++
			c.child(fnNode, pn)
			idx++
		}
	}
	saved := c.region
	c.region = "fn:" + name
	if body := n.ChildByFieldName("body"); body != nil {
		switch body.Kind() {
		case "statement_block", "block", "constructor_body":
			c.stmts(body)
		default:
			c.expr(body)
		}
	}
	c.region = saved
}

func (c *conv) paramName(p *tree_sitter.Node) string {
	if p.Kind() == "identifier" {
		return c.text(p)
	}
	for i := 0; i < int(p.ChildCount()); i++ {
		if d := p.Child(uint(i)); d != nil && d.Kind() == "identifier" {
			return c.text(d)
		}
	}
	return ""
}

func (c *conv) exprOf(n *tree_sitter.Node) graph.Node     { return c.expr(n) }
func (c *conv) exprApprox(n *tree_sitter.Node) graph.Node { return c.expr(n) }

func (c *conv) mustAdd(n *tree_sitter.Node, typ string, fields [][2]string, approx bool) graph.Node {
	node, ok := c.add(n, typ, fields, approx)
	if !ok {
		if got, exists := c.f.store.Node(c.id(n, typ)); exists {
			return got
		}
	}
	return node
}

func (c *conv) expr(n *tree_sitter.Node) graph.Node {
	if n == nil {
		return graph.Node{}
	}
	switch n.Kind() {
	case "identifier":
		return c.mustAdd(n, "code.Name", [][2]string{{"local", c.text(n)}}, false)
	case "number", "string_literal", "true", "false", "null_literal", "decimal_integer_literal":
		v := strings.Trim(c.text(n), `'"`)
		return c.mustAdd(n, "code.Const", [][2]string{{"value", v}}, false)
	case "field_access", "method_reference":
		return c.member(n)
	case "array_access":
		path := ""
		var key graph.Node
		for i := 0; i < int(n.NamedChildCount()); i++ {
			d := n.NamedChild(uint(i))
			if d.Kind() == "identifier" || d.Kind() == "member_expression" {
				path = c.text(d)
			} else {
				key = c.expr(d)
			}
		}
		node := c.mustAdd(n, "code.Index", [][2]string{{"path", path}}, false)
		if key.ID != "" {
			c.child(node, key)
		}
		return node
	case "method_invocation", "object_creation_expression":
		return c.call(n)
	case "text_block":
		return c.template(n)
	case "binary_expression":
		return c.binary(n)
	case "unary_expression":
		node := c.mustAdd(n, "code.Unary", nil, false)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				if e := c.expr(d); e.ID != "" {
					c.child(node, e)
				}
			}
		}
		return node
	case "lambda_expression":
		name := fmt.Sprintf("lambda#%d", n.StartPosition().Row+1)
		_ = name
		return c.mustAdd(n, "code.Lambda", [][2]string{{"kind", "lambda"}}, true)
	case "ternary_expression":
		return c.mustAdd(n, "code.Ternary", nil, true)
	case "parenthesized_expression", "cast_expression", "argument_list", "expression_statement", "array_initializer":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				return c.expr(d)
			}
		}
		return graph.Node{}
	case "sequence_expression":
		var last graph.Node
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				if e := c.expr(d); e.ID != "" {
					last = e
				}
			}
		}
		return last
	case "comment":
		return graph.Node{}
	default:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				inner := c.expr(d)
				t := c.mustAdd(n, "code.Transparent", [][2]string{{"kind", n.Kind()}}, true)
				if inner.ID != "" {
					c.child(t, inner)
				}
				return t
			}
		}
		return c.mustAdd(n, "code.Transparent", [][2]string{{"kind", n.Kind()}}, true)
	}
}

// member lowers obj.prop chains into the dotted syntactic path.
func (c *conv) member(n *tree_sitter.Node) graph.Node {
	obj := n.ChildByFieldName("object")
	prop := n.ChildByFieldName("field")
	if prop == nil {
		prop = n.ChildByFieldName("name")
	}
	path := c.text(n)
	node := c.mustAdd(n, "code.Attr", [][2]string{{"path", path}, {"attr", c.text(prop)}}, false)
	if obj != nil {
		if base := c.expr(obj); base.ID != "" {
			c.child(node, base)
		}
	}
	return node
}

// call lowers a call: callee path, method (last segment), ordered args.
func (c *conv) call(n *tree_sitter.Node) graph.Node {
	args := n.ChildByFieldName("arguments")
	callee := c.text(n)
	nameNode := n.ChildByFieldName("name")
	if nameNode != nil {
		callee = c.text(nameNode)
		if obj := n.ChildByFieldName("object"); obj != nil {
			callee = c.text(obj) + "." + callee
		}
	}
	method := ""
	segs := strings.Split(callee, ".")
	if len(segs) > 1 {
		method = segs[len(segs)-1]
	}
	node := c.mustAdd(n, "code.Call", [][2]string{
		{"path", callee}, {"callee", callee}, {"method", method},
	}, n.Kind() == "object_creation_expression")
	if obj := n.ChildByFieldName("object"); obj != nil {
		if base := c.expr(obj); base.ID != "" {
			c.child(node, base)
		}
	}
	if args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			a := args.NamedChild(uint(i))
			arg := c.expr(a)
			if arg.ID != "" {
				c.child(node, arg)
			}
		}
	}
	return node
}

// template lowers template strings into Format with substitution parts.
func (c *conv) template(n *tree_sitter.Node) graph.Node {
	return c.mustAdd(n, "code.Const", [][2]string{{"value", strings.Trim(c.text(n), `"`)}}, true)
}

// binary: + builds a Format (the taint substrate); other operators are BinOps.
func (c *conv) binary(n *tree_sitter.Node) graph.Node {
	op := ""
	for i := 0; i < int(n.ChildCount()); i++ {
		if d := n.Child(uint(i)); d != nil && !d.IsNamed() {
			op = c.text(d)
			break
		}
	}
	if op == "+" {
		f := c.mustAdd(n, "code.Format", [][2]string{{"text", c.text(n)}}, false)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				if part := c.expr(d); part.ID != "" {
					c.child(f, part)
				}
			}
		}
		return f
	}
	node := c.mustAdd(n, "code.BinOp", [][2]string{{"op", op}}, false)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if d := n.NamedChild(uint(i)); d != nil {
			if e := c.expr(d); e.ID != "" {
				c.child(node, e)
			}
		}
	}
	return node
}

func (f *Frontend) Store() *graph.Store { return f.store }

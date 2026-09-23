// Package python is the v3 Python frontend: it lowers source into the closed
// NIR graph — structure and Region/Order only, no security, no
// frameworks, no dataflow (the shared lowering pass computes FLOWS and
// resolution). The traversal design follows the v2 reference frontend's
// hardened decisions; the merge-base and the re-derived classes are recorded in
// ENGINE-FORK.md.
package python

import (
	"fmt"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tspython "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Imports records what a file imports, for the lowering pass's resolution:
// alias → dotted module, plus the from-import names.
type Imports struct {
	Modules map[string]string // alias (or last segment) -> module path
	From    map[string]string // imported name -> module path
}

// Frontend accumulates one program's NIR across files.
type Frontend struct {
	store   *graph.Store
	order   int64 // program-order counter, monotonic per program
	Imports map[string]Imports
}

// New creates a frontend writing into a store whose schema registry already
// carries the NIR set (nir.Register).
func New(store *graph.Store) *Frontend {
	return &Frontend{store: store, Imports: map[string]Imports{}}
}

// Extract parses one Python file into the store.
func (f *Frontend) Extract(file string, src []byte) error {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tree_sitter.NewLanguage(tspython.Language()))
	tree := parser.Parse(src, nil)
	defer tree.Close()
	root := tree.RootNode()

	imp := Imports{Modules: map[string]string{}, From: map[string]string{}}

	// Deterministic node ids: file:line:col (the NIR identity key).
	nextID := func(n *tree_sitter.Node) string {
		p := n.StartPosition()
		return fmt.Sprintf("%s:%d:%d", file, p.Row+1, p.Column+1)
	}
	c := &conv{
		f:       f,
		src:     src,
		file:    file,
		nextID:  nextID,
		region:  "fn",
		skip:    map[string]bool{},
		imports: imp,
	}
	c.collectImports(root, imp)
	f.Imports[file] = imp

	// Top level: a module is a function-shaped region.
	c.moduleFunc(root)
	return nil
}

type conv struct {
	f       *Frontend
	src     []byte
	file    string
	nextID  func(*tree_sitter.Node) string
	region  string
	skip    map[string]bool // node ids already emitted (avoid double walks)
	imports Imports
}

func (c *conv) text(n *tree_sitter.Node) string { return string(c.src[n.StartByte():n.EndByte()]) }

func (c *conv) add(n *tree_sitter.Node, typ string, fields [][2]string, approx bool) (graph.Node, bool) {
	// Identity is (Type, ID): a construct and its first child routinely share a
	// start position, so the ID carries the type.
	id := c.nextID(n) + ":" + typ
	if c.skip[id] {
		if got, ok := c.f.store.Node(id); ok && got.Type == typ {
			return got, true
		}
		return graph.Node{}, false
	}
	var flds graph.Fields
	p := n.StartPosition()
	stamp(&flds, c.file, int(p.Row)+1, int(p.Column)+1, c.region, c.f.order, approx)
	for _, kv := range fields {
		flds.Set(kv[0], graph.Str(kv[1]))
	}
	node := graph.Node{ID: id, Type: typ, Layer: graph.LayerLow, Fields: flds,
		Prov: graph.Provenance{Producer: "python", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
	if err := c.f.store.AddNode(node); err != nil {
		return graph.Node{}, false
	}
	c.skip[id] = true
	c.f.order++
	return node, true
}

func stamp(f *graph.Fields, file string, line, col int, region string, order int64, approx bool) {
	f.Set("file", graph.Str(file))
	f.Set("line", graph.Int(int64(line)))
	f.Set("col", graph.Int(int64(col)))
	f.Set("region", graph.Str(region))
	f.Set("order", graph.Int(order))
	f.Set("approx_lowered", graph.Bool(approx))
}

func (c *conv) child(from graph.Node, to graph.Node) {
	id := "child:" + from.ID + ":" + to.ID
	_ = c.f.store.AddEdge(graph.Edge{ID: id, Type: "child", From: from.ID, To: to.ID,
		Prov: graph.Provenance{Producer: "python", Build: graph.BuildParsed, Trust: graph.TrustTrusted}})
}

// moduleFunc emits the module's top-level as one function region.
func (c *conv) moduleFunc(root *tree_sitter.Node) {
	c.stmts(root, "module")
}

// collectImports reads import statements (resolution input, not NIR).
func (c *conv) collectImports(root *tree_sitter.Node, imp Imports) {
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "import_statement":
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				if d == nil || d.Kind() != "dotted_name" {
					continue
				}
				full := string(c.src[d.StartByte():d.EndByte()])
				segs := strings.Split(full, ".")
				imp.Modules[segs[len(segs)-1]] = full
			}
		case "import_from_statement":
			mod := ""
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				if d == nil {
					continue
				}
				switch d.Kind() {
				case "dotted_name":
					name := string(c.src[d.StartByte():d.EndByte()])
					if mod == "" {
						mod = name
						continue
					}
					segs := strings.Split(name, ".")
					imp.From[segs[len(segs)-1]] = mod + "." + name
				case "aliased_import":
					// name as alias
					nameN := d.ChildByFieldName("name")
					aliasN := d.ChildByFieldName("alias")
					if nameN != nil {
						nm := string(c.src[nameN.StartByte():nameN.EndByte()])
						al := nm
						if aliasN != nil {
							al = string(c.src[aliasN.StartByte():aliasN.EndByte()])
						}
						imp.From[al] = mod + "." + nm
					}
				case "wildcard_import":
					// not resolvable precisely
				}
				if d.Kind() == "identifier" && mod != "" {
					imp.From[string(c.src[d.StartByte():d.EndByte()])] = mod + "." + string(c.src[d.StartByte():d.EndByte()])
				}
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(uint(i)))
		}
	}
	walk(root)
}

// stmts walks statements of a block; fnName is "" at module level.
func (c *conv) stmts(block *tree_sitter.Node, fnName string) {
	for i := 0; i < int(block.NamedChildCount()); i++ {
		c.stmt(block.NamedChild(uint(i)), fnName)
	}
}

// stmt lowers one statement. Region segments grow inside structured control
// flow: the structured walk IS the region tree.
func (c *conv) stmt(n *tree_sitter.Node, fnName string) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "function_definition":
		c.functionDef(n)
	case "class_definition":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil && d.Kind() == "block" {
				c.stmts(d, fnName)
			}
		}
	case "decorated_definition":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.stmt(n.NamedChild(uint(i)), fnName)
		}
	case "assignment", "augmented_assignment", "named_expression":
		c.exprOf(n)
	case "expression_statement", "return_statement", "raise_statement", "assert_statement", "delete_statement", "global_statement", "comment", "pass_statement":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.exprOf(n.NamedChild(uint(i)))
		}
	case "with_statement":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			d := n.NamedChild(uint(i))
			if d == nil {
				continue
			}
			if d.Kind() == "with_item" || d.Kind() == "block" {
				c.stmt(d, fnName)
			}
		}
	case "with_item":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.exprOf(n.NamedChild(uint(i)))
		}
	case "if_statement":
		c.structured(n, fnName, "if", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				switch d.Kind() {
				case "condition_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						c.exprOf(d.NamedChild(uint(j)))
					}
				case "block":
					c.in(outer+"/then", func() { c.stmts(d, fnName) })
				case "elif_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						e := d.NamedChild(uint(j))
						if e.Kind() == "block" {
							c.in(outer+"/elif", func() { c.stmts(e, fnName) })
						} else {
							c.exprOf(e)
						}
					}
				case "else_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						if e := d.NamedChild(uint(j)); e.Kind() == "block" {
							c.in(outer+"/else", func() { c.stmts(e, fnName) })
						}
					}
				}
			}
		})
	case "for_statement", "while_statement":
		c.structured(n, fnName, "loop", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				if d == nil {
					continue
				}
				if d.Kind() == "block" {
					c.in(outer+"/body", func() { c.stmts(d, fnName) })
					continue
				}
				c.exprOf(d)
			}
		})
	case "try_statement":
		c.structured(n, fnName, "try", func(outer string) {
			for i := 0; i < int(n.NamedChildCount()); i++ {
				d := n.NamedChild(uint(i))
				switch d.Kind() {
				case "block":
					c.in(outer+"/body", func() { c.stmts(d, fnName) })
				case "except_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						if e := d.NamedChild(uint(j)); e.Kind() == "block" {
							c.in(outer+"/except", func() { c.stmts(e, fnName) })
						} else {
							c.exprOf(e)
						}
					}
				case "finally_clause":
					for j := 0; j < int(d.NamedChildCount()); j++ {
						if e := d.NamedChild(uint(j)); e.Kind() == "block" {
							c.in(outer, func() { c.stmts(e, fnName) })
						}
					}
				}
			}
		})
	default:
		// Unknown statement shape: approximate rather than drop, and stamp it.
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c.exprApprox(n.NamedChild(uint(i)))
		}
	}
}

func (c *conv) structured(n *tree_sitter.Node, fnName, kind string, body func(outer string)) {
	outer := c.region + "/" + kind + fmt.Sprintf("#%d", n.StartPosition().Row+1)
	c.in(outer, func() { body(outer) })
}

func (c *conv) in(region string, fn func()) {
	saved := c.region
	c.region = region
	fn()
	c.region = saved
}

// functionDef emits FuncDef with generic ParamEntries carrying raw decorator
// tokens — the facts a framework model interprets.
func (c *conv) functionDef(n *tree_sitter.Node) {
	name := ""
	var params []*tree_sitter.Node
	var body *tree_sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		switch d.Kind() {
		case "identifier":
			if name == "" {
				name = c.text(d)
			}
		case "parameters":
			for j := 0; j < int(d.NamedChildCount()); j++ {
				if p := d.NamedChild(uint(j)); p.Kind() == "identifier" || p.Kind() == "default_parameter" || p.Kind() == "typed_parameter" {
					params = append(params, p)
				}
			}
		case "block":
			body = d
		}
	}
	decorators := c.decoratorsOf(n)
	fnNode, ok := c.add(n, "code.FuncDef", [][2]string{
		{"name", name},
		{"qualified_name", c.file}, // refined by the lowering pass
	}, false)
	if !ok {
		return
	}
	for _, p := range params {
		pn := p
		pname := c.firstIdentText(pn)
		id := c.nextID(pn) + ":code.ParamEntry"
		if c.skip[id] {
			continue
		}
		var pf graph.Fields
		pp := pn.StartPosition()
		stamp(&pf, c.file, int(pp.Row)+1, int(pp.Column)+1, c.region, c.f.order, false)
		pf.Set("name", graph.Str(pname))
		pf.Set("scope", graph.Str(name))
		if len(decorators) > 0 {
			lst := graph.Value{Kind: graph.KindList, Elem: graph.KindString}
			for _, d := range decorators {
				lst.L = append(lst.L, graph.Str(d))
			}
			pf.Set("decorators", lst)
		}
		pnode := graph.Node{ID: id, Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pf,
			Prov: graph.Provenance{Producer: "python", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
		if err := c.f.store.AddNode(pnode); err != nil {
			continue
		}
		c.skip[id] = true
		c.f.order++
		c.child(fnNode, pnode)
	}
	saved := c.region
	c.region = "fn:" + name
	if body != nil {
		c.stmts(body, name)
	}
	c.region = saved
}

func (c *conv) decoratorsOf(fn *tree_sitter.Node) []string {
	// Decorators hang on the decorated_definition wrapper: the raw tokens are
	// recorded as ParamEntry facts for a framework model to interpret.
	var out []string
	p := fn.Parent()
	if p == nil || p.Kind() != "decorated_definition" {
		return out
	}
	for i := 0; i < int(p.NamedChildCount()); i++ {
		d := p.NamedChild(uint(i))
		if d != nil && d.Kind() == "decorator" {
			// Record the decorator's dotted name: the raw token is a generic
			// fact, and a clean segment path is what knowledge matches on.
			name := strings.SplitN(strings.TrimPrefix(c.text(d), "@"), "(", 2)[0]
			out = append(out, name)
		}
	}
	return out
}

func (c *conv) firstIdentText(n *tree_sitter.Node) string {
	var find func(*tree_sitter.Node) string
	find = func(x *tree_sitter.Node) string {
		if x == nil {
			return ""
		}
		if x.Kind() == "identifier" {
			return c.text(x)
		}
		for i := 0; i < int(x.ChildCount()); i++ {
			if s := find(x.Child(uint(i))); s != "" {
				return s
			}
		}
		return ""
	}
	return find(n)
}

// exprOf lowers an expression subtree into NIR nodes; returns the root node.
func (c *conv) exprOf(n *tree_sitter.Node) graph.Node {
	return c.expr(n, false)
}

func (c *conv) exprApprox(n *tree_sitter.Node) graph.Node {
	return c.expr(n, true)
}

func (c *conv) expr(n *tree_sitter.Node, approx bool) graph.Node {
	if n == nil {
		return graph.Node{}
	}
	switch n.Kind() {
	case "assignment", "augmented_assignment", "named_expression":
		// Emit every child (target and value); the value is the expression's
		// result. The assignment's def-flow — value into the target binding — is
		// the FLOWS edge the shared lowering threads to later uses.
		var first, last graph.Node
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				if e := c.expr(d, approx); e.ID != "" {
					if first.ID == "" {
						first = e
					}
					last = e
				}
			}
		}
		if first.ID != "" && last.ID != "" && first.ID != last.ID {
			_ = c.f.store.AddEdge(graph.Edge{
				ID:   "flows:def:" + last.ID + ":" + first.ID,
				Type: "FLOWS", From: last.ID, To: first.ID,
				Prov: graph.Provenance{Producer: "python", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
			})
		}
		return last
	case "identifier":
		return c.mustAdd(n, "code.Name", [][2]string{{"local", c.text(n)}}, approx)
	case "string", "string_content":
		return c.mustAdd(n, "code.Const", [][2]string{{"value", strings.Trim(c.text(n), `"'`)}}, approx)
	case "integer", "float":
		return c.mustAdd(n, "code.Const", [][2]string{{"value", c.text(n)}}, approx)
	case "true", "false", "none":
		return c.mustAdd(n, "code.Const", [][2]string{{"value", c.text(n)}}, approx)
	case "attribute":
		return c.attr(n, approx)
	case "subscript":
		return c.subscript(n, approx)
	case "call":
		return c.call(n, approx)
	case "concatenated_string":
		return c.formatParts(n, approx)
	case "f-string", "interpolation":
		return c.formatParts(n, approx)
	case "list", "tuple", "set":
		return c.seq(n, approx)
	case "pair", "keyword_argument":
		return c.pair(n, approx)
	case "lambda":
		return c.mustAdd(n, "code.Lambda", [][2]string{{"kind", "lambda"}}, true)
	case "binary_operator":
		return c.binop(n, approx)
	case "unary_operator":
		return c.unop(n, approx)
	case "conditional_expression":
		return c.mustAdd(n, "code.Ternary", nil, true)
	case "argument_list", "parenthesized_expression", "await", "list_splat", "dictionary_splat":
		// Transparent wrappers: lower the inner expression and pass through.
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				return c.expr(d, approx)
			}
		}
		return c.mustAdd(n, "code.Transparent", [][2]string{{"kind", n.Kind()}}, true)
	case "comment":
		return graph.Node{}
	case "expression_list":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				return c.expr(d, approx)
			}
		}
		return graph.Node{}
	default:
		// Approximate: emit a transparent node over the whole subtree so taint
		// passes through rather than silently dropping.
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				inner := c.expr(d, true)
				t := c.mustAdd(n, "code.Transparent", [][2]string{{"kind", n.Kind()}}, true)
				c.child(t, inner)
				return t
			}
		}
		return c.mustAdd(n, "code.Transparent", [][2]string{{"kind", n.Kind()}}, true)
	}
}

func (c *conv) mustAdd(n *tree_sitter.Node, typ string, fields [][2]string, approx bool) graph.Node {
	node, ok := c.add(n, typ, fields, approx)
	if !ok {
		if got, exists := c.f.store.Node(c.nextID(n)); exists {
			return got
		}
	}
	return node
}

// attr lowers base.attr into an Attr node with the dotted syntactic path;
// qualified_path is left for the lowering pass (resolution owns it).
func (c *conv) attr(n *tree_sitter.Node, approx bool) graph.Node {
	var base, last *tree_sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		if d.Kind() == "identifier" {
			last = d
		} else {
			base = d
		}
	}
	var baseNode graph.Node
	if base != nil {
		baseNode = c.expr(base, approx)
	}
	path := c.text(n)
	node := c.mustAdd(n, "code.Attr", [][2]string{{"path", path}, {"attr", c.text(last)}}, approx)
	if baseNode.ID != "" {
		c.child(node, baseNode)
	}
	return node
}

func (c *conv) subscript(n *tree_sitter.Node, approx bool) graph.Node {
	path := ""
	var key graph.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		switch d.Kind() {
		case "identifier", "attribute":
			path = c.text(d)
		default:
			key = c.expr(d, approx)
		}
	}
	node := c.mustAdd(n, "code.Index", [][2]string{{"path", path}}, approx)
	if key.ID != "" {
		c.child(node, key)
	}
	return node
}

// call lowers a call: the callee's syntactic path and method (last segment),
// arguments as child nodes in source order.
func (c *conv) call(n *tree_sitter.Node, approx bool) graph.Node {
	var callee string
	var args *tree_sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		switch d.Kind() {
		case "identifier", "attribute":
			callee = c.text(d)
		case "call":
			// chained call base — approximate
			c.expr(d, true)
		case "argument_list":
			args = d
		}
	}
	method := ""
	segs := strings.Split(callee, ".")
	if len(segs) > 1 {
		method = segs[len(segs)-1]
	}
	node := c.mustAdd(n, "code.Call", [][2]string{
		{"path", callee},
		{"callee", callee},
		{"method", method},
	}, approx)
	if args != nil {
		for i := 0; i < int(args.NamedChildCount()); i++ {
			a := args.NamedChild(uint(i))
			arg := c.expr(a, approx)
			if arg.ID != "" {
				c.child(node, arg)
			}
		}
	}
	return node
}

// formatParts lowers string construction (f-strings, concatenation) into
// Format with its parts as children — the taint substrate for string builds.
func (c *conv) formatParts(n *tree_sitter.Node, approx bool) graph.Node {
	node := c.mustAdd(n, "code.Format", [][2]string{{"text", c.text(n)}}, approx)
	var walk func(x *tree_sitter.Node)
	walk = func(x *tree_sitter.Node) {
		for i := 0; i < int(x.NamedChildCount()); i++ {
			d := x.NamedChild(uint(i))
			switch d.Kind() {
			case "interpolation":
				for j := 0; j < int(d.NamedChildCount()); j++ {
					if inner := d.NamedChild(uint(j)); inner != nil {
						part := c.expr(inner, approx)
						if part.ID != "" {
							c.child(node, part)
						}
					}
				}
			case "identifier", "call", "attribute", "subscript", "binary_operator":
				part := c.expr(d, approx)
				if part.ID != "" {
					c.child(node, part)
				}
			default:
				walk(d)
			}
		}
	}
	walk(n)
	return node
}

func (c *conv) seq(n *tree_sitter.Node, approx bool) graph.Node {
	node := c.mustAdd(n, "code.Seq", nil, approx)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		if d.Kind() == "pair" {
			p := c.expr(d, approx)
			if p.ID != "" {
				c.child(node, p)
			}
			continue
		}
		el := c.expr(d, approx)
		if el.ID != "" {
			c.child(node, el)
		}
	}
	return node
}

func (c *conv) pair(n *tree_sitter.Node, approx bool) graph.Node {
	key := ""
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if d := n.NamedChild(uint(i)); d != nil && d.Kind() == "identifier" {
			key = c.text(d)
			break
		}
	}
	node := c.mustAdd(n, "code.Pair", [][2]string{{"key", key}}, approx)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		d := n.NamedChild(uint(i))
		if d.Kind() == "identifier" && c.text(d) == key {
			continue
		}
		v := c.expr(d, approx)
		if v.ID != "" {
			c.child(node, v)
		}
	}
	return node
}

func (c *conv) binop(n *tree_sitter.Node, approx bool) graph.Node {
	op := ""
	for i := 0; i < int(n.ChildCount()); i++ {
		d := n.Child(uint(i))
		if d != nil && !d.IsNamed() {
			op = c.text(d)
			break
		}
	}
	// String concatenation and % formatting are Formats (taint through parts);
	// other operators are BinOps folding constants.
	if op == "+" || op == "%" || op == "+=" {
		f := c.mustAdd(n, "code.Format", [][2]string{{"text", c.text(n)}}, approx)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if d := n.NamedChild(uint(i)); d != nil {
				part := c.expr(d, approx)
				if part.ID != "" {
					c.child(f, part)
				}
			}
		}
		return f
	}
	node := c.mustAdd(n, "code.BinOp", [][2]string{{"op", op}}, approx)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if d := n.NamedChild(uint(i)); d != nil {
			operand := c.expr(d, approx)
			if operand.ID != "" {
				c.child(node, operand)
			}
		}
	}
	return node
}

func (c *conv) unop(n *tree_sitter.Node, approx bool) graph.Node {
	op := ""
	for i := 0; i < int(n.ChildCount()); i++ {
		d := n.Child(uint(i))
		if d != nil && !d.IsNamed() {
			op = c.text(d)
			break
		}
	}
	node := c.mustAdd(n, "code.Unary", [][2]string{{"op", op}}, approx)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if d := n.NamedChild(uint(i)); d != nil {
			operand := c.expr(d, approx)
			if operand.ID != "" {
				c.child(node, operand)
			}
		}
	}
	return node
}

// Store exposes the accumulated store.
func (f *Frontend) Store() *graph.Store { return f.store }

// SortedFiles returns the import table's files in deterministic order.
func (f *Frontend) SortedFiles() []string {
	var out []string
	for file := range f.Imports {
		out = append(out, file)
	}
	sort.Strings(out)
	return out
}

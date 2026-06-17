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
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tsruby.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &rbConv{src: src, root: root, file: rel}
			return nir.Module{Key: "", File: rel, Body: c.blockChildren(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
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
		right := c.expr(field(n, "right"))
		if left != nil && (left.Kind() == "identifier" || left.Kind() == "constant" || left.Kind() == "instance_variable") {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: right}}
		}
		// subscript write (session['role'] = v) — model as a write to the base's path so a
		// trust-context path sink fires (CWE-501). Method empty → no method-sink collision.
		if left != nil && left.Kind() == "element_reference" {
			base := field(left, "object")
			if base == nil {
				if kids := namedChildren(left); len(kids) > 0 {
					base = kids[0]
				}
			}
			if base != nil {
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(base), Args: []nir.Expr{right},
					Path: c.dotted(base), Method: "", Loc: L}}}
			}
		}
		// attribute/setter write (obj.role = v) — model as a path-sink Call on the target path.
		if left != nil && left.Kind() == "call" {
			return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: c.expr(left), Args: []nir.Expr{right},
				Path: c.dotted(left), Method: "", Loc: L}}}
		}
		return []nir.Stmt{nir.Assign{Value: right}}
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
	// branch-structured (B1). Ruby did not evaluate the condition (collectBodies gathers
	// then/else/elsif/when bodies, not the predicate), so Cond stays nil → byte-identical.
	case "if":
		// separate Then/Else so the join-merge keeps the live branch tainted and a constant
		// condition prunes.
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}}
	case "unless":
		// `unless c` runs the body when c is FALSE — split branches for the join-merge, but
		// leave Cond nil (no const-prune, to avoid inverting the condition incorrectly).
		return []nir.Stmt{nir.If{Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}}
	case "while", "until", "for":
		return []nir.Stmt{nir.Loop{Body: c.collectBodies(n)}}
	case "begin":
		return []nir.Stmt{nir.Try{Body: c.collectBodies(n)}}
	case "case":
		return []nir.Stmt{c.rubyCase(n)}
	case "body_statement", "then", "else", "elsif", "ensure", "when", "do_block", "block":
		return []nir.Stmt{nir.Block{Stmts: c.collectBodies(n)}}
	case "comment":
		return nil
	case "identifier", "constant":
		name := c.text(n)
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{Callee: nir.Name{ID: name, Loc: L}, Path: name, Method: name, Loc: L}}}
	}
	// any other expression used as a statement
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// rubyBody lowers the statements of a then/else clause node (or a bare body).
func (c *rbConv) rubyBody(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if n.Kind() == "then" || n.Kind() == "else" || n.Kind() == "body_statement" {
		var out []nir.Stmt
		for _, ch := range namedChildren(n) {
			out = append(out, c.stmt(ch)...)
		}
		return out
	}
	return c.stmt(n)
}

// rubyAlt builds the Else branch from an `elsif`/`else` alternative node (elsif chains
// into a nested If for the join-merge + pruning).
func (c *rbConv) rubyAlt(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	if n.Kind() == "elsif" {
		return []nir.Stmt{nir.If{Cond: c.expr(field(n, "condition")), Then: c.rubyBody(field(n, "consequence")), Else: c.rubyAlt(field(n, "alternative"))}}
	}
	return c.rubyBody(n) // else
}

// rubyCase lowers `case x; when a,b then …; else …; end` into a Switch with subject +
// per-arm labels so a constant subject prunes to the matching arm.
func (c *rbConv) rubyCase(n *tree_sitter.Node) nir.Stmt {
	var cases [][]nir.Stmt
	var labels [][]nir.Expr
	var deflt []nir.Stmt
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "when":
			var labs []nir.Expr
			var body []nir.Stmt
			for _, w := range namedChildren(ch) {
				switch w.Kind() {
				case "pattern":
					if k := namedChildren(w); len(k) > 0 {
						labs = append(labs, c.expr(k[0]))
					}
				case "then":
					body = append(body, c.rubyBody(w)...)
				}
			}
			cases = append(cases, body)
			labels = append(labels, labs)
		case "else":
			deflt = append(deflt, c.rubyBody(ch)...)
		}
	}
	return nir.Switch{Subject: c.expr(field(n, "value")), Cases: cases, Labels: labels, Default: deflt}
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
	case "nil":
		return nir.Const{Loc: L}
	case "simple_symbol", "hash_key_symbol":
		return nir.Const{Loc: L, Value: strings.TrimSuffix(strings.TrimPrefix(c.text(n), ":"), ":")}
	case "integer", "float":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "true", "false":
		return nir.Const{Loc: L, Value: c.text(n)} // boolean value for `val` matching
	case "string":
		return c.string(n, L)
	case "regex":
		// carry `/pattern/` so a `filter` directive (gsub) can analyze its output alphabet.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "call", "method_call", "command", "command_call":
		return c.call(n, L)
	case "element_reference":
		var key nir.Expr
		if kids := namedChildren(n); len(kids) > 1 {
			key = c.expr(kids[1])
		}
		return nir.Index{Base: c.expr(field(n, "object")), Key: key, Path: c.dotted(field(n, "object")), Loc: L}
	case "binary":
		op := c.text(field(n, "operator"))
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		switch op {
		case "+", "<<", "%": // string concat / append / format — keep taint-propagating Format
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "conditional":
		return nir.Ternary{Cond: c.expr(field(n, "condition")), Then: c.expr(field(n, "consequence")), Else: c.expr(field(n, "alternative")), Loc: L}
	case "unary":
		return nir.Unary{Op: c.text(field(n, "operator")), Operand: c.expr(field(n, "operand")), Loc: L}
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
				parts = append(parts, nir.Pair{Key: c.keyName(field(ch, "key")), Value: c.expr(field(ch, "value")), Loc: L})
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "pair":
		// a keyword argument (foo(k: v)) appearing directly in an argument_list
		return nir.Pair{Key: c.keyName(field(n, "key")), Value: c.expr(field(n, "value")), Loc: L}
	case "scope_resolution":
		// A::B used as a value is a constant token; carry it for `val` matching
		// while call-path construction still uses dotted(AST) directly.
		return nir.Const{Loc: L, Value: c.dotted(n)}
	}
	var parts []nir.Expr
	for _, ch := range namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// keyName returns the bare name of a hash/keyword key — a symbol (verify:, :verify)
// with its colon stripped, or a string key with quotes stripped.
func (c *rbConv) keyName(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	t := c.text(n)
	switch n.Kind() {
	case "hash_key_symbol":
		return t // already bare, e.g. "verify"
	case "simple_symbol":
		return strings.TrimPrefix(t, ":")
	case "string":
		if len(t) >= 2 {
			return t[1 : len(t)-1]
		}
	}
	return strings.TrimSuffix(strings.TrimPrefix(t, ":"), ":")
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

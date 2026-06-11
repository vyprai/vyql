package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	groovy "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/groovy"

	"github.com/vyprai/vyql/extract/nir"
)

// gvConv walks a tree-sitter Groovy CST into NIR. Groovy (Jenkins pipelines /
// Gradle) models calls as function_call(function, argument_list); member access is
// dotted_identifier; `+` and GString interpolation build tainted strings.
type gvConv struct {
	src  []byte
	file string
	key  string
}

// ExtractGroovy parses Groovy files into one NIR Program (one module per file).
func ExtractGroovy(files []string, root string) (nir.Program, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	_ = parser.SetLanguage(tree_sitter.NewLanguage(groovy.Language()))

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
		c := &gvConv{src: src, file: rel, key: moduleKey(root, f, ".groovy")}
		prog.Modules = append(prog.Modules, nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())})
		tree.Close()
	}
	return prog, nil
}

func (c *gvConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *gvConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

func (c *gvConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *gvConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition", "method_definition":
		var name string
		var params []string
		for _, ch := range namedChildren(n) {
			switch ch.Kind() {
			case "identifier":
				if name == "" {
					name = c.text(ch)
				}
			case "parameter_list":
				for _, p := range namedChildren(ch) {
					if id := lastChildKind(p, "identifier"); id != nil {
						params = append(params, c.text(id))
					}
				}
			}
		}
		body := c.block(lastChildKind(n, "closure"))
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, Body: body, Loc: L}}
	case "declaration":
		kids := namedChildren(n)
		if len(kids) >= 2 && kids[0].Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(kids[0])}, Value: c.expr(kids[len(kids)-1])}}
		}
		return nil
	case "assignment":
		left := field(n, "left")
		right := field(n, "right")
		if left == nil || right == nil {
			kids := namedChildren(n)
			if len(kids) >= 2 {
				left, right = kids[0], kids[len(kids)-1]
			}
		}
		if left != nil && left.Kind() == "identifier" {
			return []nir.Stmt{nir.Assign{Targets: []string{c.text(left)}, Value: c.expr(right)}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "closure", "block":
		return c.block(n)
	case "if_statement", "for_statement", "while_statement", "try_statement", "switch_statement":
		return []nir.Stmt{nir.Block{Stmts: c.collectGvBlocks(n)}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func (c *gvConv) block(n *tree_sitter.Node) []nir.Stmt {
	if n == nil {
		return nil
	}
	var out []nir.Stmt
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "parameter_list" {
			continue
		}
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *gvConv) collectGvBlocks(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		for _, ch := range children(m) {
			switch ch.Kind() {
			case "closure", "block":
				out = append(out, c.block(ch)...)
			default:
				walk(ch)
			}
		}
	}
	walk(n)
	return out
}

func (c *gvConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer", "decimal", "float", "boolean", "null":
		return nir.Const{Loc: L}
	case "string", "gstring":
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
	case "function_call":
		return c.callExpr(n)
	case "dotted_identifier":
		// member access `a.b` → Attr (so a source like params.X and receiver taint work).
		kids := namedChildren(n)
		if len(kids) >= 2 {
			return nir.Attr{Base: c.expr(kids[0]), Attr: c.text(kids[len(kids)-1]), Path: c.dotted(n), Loc: L}
		}
		return nir.Name{ID: c.dotted(n), Loc: L}
	case "binary_op":
		// `+` (and GString building) propagate taint; model any binary as a union.
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Format{Parts: parts, Loc: L}
	case "index", "subscript":
		kids := namedChildren(n)
		var base nir.Expr = nir.Const{Loc: L}
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		return nir.Index{Base: base, Path: c.dotted(n), Loc: L}
	case "parenthesized_expression", "ternary_op", "unary_op":
		if k := namedChildren(n); len(k) > 0 {
			return nir.Thru{Inner: c.expr(k[len(k)-1])}
		}
	case "list", "map":
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
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (c *gvConv) callExpr(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	kids := namedChildren(n)
	if len(kids) == 0 {
		return nir.Const{Loc: L}
	}
	fn := kids[0]
	path := c.dotted(fn)
	var args []nir.Expr
	if al := lastChildKind(n, "argument_list"); al != nil {
		for _, a := range namedChildren(al) {
			args = append(args, c.expr(a))
		}
	}
	return nir.Call{Callee: c.expr(fn), Args: args, Path: path, Method: lastSeg(path), Loc: L}
}

func (c *gvConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier":
		return c.text(n)
	case "dotted_identifier":
		kids := namedChildren(n)
		if len(kids) >= 2 {
			return c.dotted(kids[0]) + "." + c.dotted(kids[len(kids)-1])
		}
		if len(kids) == 1 {
			return c.dotted(kids[0])
		}
	case "function_call":
		if kids := namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	case "string", "gstring":
		return "$str"
	}
	return "?"
}

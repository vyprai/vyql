// Package golang is the v3 Go frontend: source lowered into the closed NIR
// graph via go/ast (fresh implementation per the Phase 2 reuse decision — the
// ISA is imperative-Go-shaped, so emission against v3 NIR directly is cheaper
// than retargeting the v2 frontend). Structure and Region/Order only; the
// shared lowering computes FLOWS and resolution.
package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Imports records package imports for resolution: alias (or last segment) ->
// package path.
type Imports struct {
	Modules map[string]string
}

type Frontend struct {
	store   *graph.Store
	order   int64
	fset    *token.FileSet
	Imports map[string]Imports
}

func New(store *graph.Store) *Frontend {
	return &Frontend{store: store, Imports: map[string]Imports{}}
}

func (f *Frontend) Extract(file string, src []byte) error {
	fset := token.NewFileSet()
	astf, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return fmt.Errorf("parse %s: %w", file, err)
	}
	f.fset = fset

	imp := Imports{Modules: map[string]string{}}
	for _, is := range astf.Imports {
		path := strings.Trim(is.Path.Value, `"`)
		name := ""
		if is.Name != nil {
			name = is.Name.Name
		} else {
			segs := strings.Split(path, "/")
			name = segs[len(segs)-1]
		}
		if name != "_" && name != "." {
			imp.Modules[name] = path
		}
	}
	f.Imports[file] = imp

	c := &conv{f: f, file: file, region: "fn", skip: map[string]bool{}}
	for _, d := range astf.Decls {
		c.decl(d)
	}
	return nil
}

type conv struct {
	f      *Frontend
	file   string
	region string
	skip   map[string]bool
}

func (c *conv) pos(p token.Pos) (int, int) {
	pp := c.f.fset.Position(p)
	return pp.Line, pp.Column
}

func (c *conv) add(p token.Pos, typ string, fields [][2]string, approx bool) (graph.Node, bool) {
	line, col := c.pos(p)
	id := fmt.Sprintf("%s:%d:%d:%s", c.file, line, col, typ)
	if c.skip[id] {
		if got, ok := c.f.store.Node(id); ok && got.Type == typ {
			return got, true
		}
		return graph.Node{}, false
	}
	var flds graph.Fields
	flds.Set("file", graph.Str(c.file))
	flds.Set("line", graph.Int(int64(line)))
	flds.Set("col", graph.Int(int64(col)))
	flds.Set("region", graph.Str(c.region))
	flds.Set("order", graph.Int(c.f.order))
	flds.Set("approx_lowered", graph.Bool(approx))
	for _, kv := range fields {
		flds.Set(kv[0], graph.Str(kv[1]))
	}
	node := graph.Node{ID: id, Type: typ, Layer: graph.LayerLow, Fields: flds,
		Prov: graph.Provenance{Producer: "golang", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
	if err := c.f.store.AddNode(node); err != nil {
		return graph.Node{}, false
	}
	c.skip[id] = true
	c.f.order++
	return node, true
}

func (c *conv) child(from, to graph.Node) {
	_ = c.f.store.AddEdge(graph.Edge{
		ID: "child:" + from.ID + ":" + to.ID, Type: "child", From: from.ID, To: to.ID,
		Prov: graph.Provenance{Producer: "golang", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
	})
}

func (c *conv) defFlow(value, target graph.Node) {
	if value.ID == "" || target.ID == "" || value.ID == target.ID {
		return
	}
	_ = c.f.store.AddEdge(graph.Edge{
		ID: "flows:def:" + value.ID + ":" + target.ID, Type: "FLOWS", From: value.ID, To: target.ID,
		Prov: graph.Provenance{Producer: "golang", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
	})
}

func (c *conv) decl(d ast.Decl) {
	fd, ok := d.(*ast.FuncDecl)
	if !ok {
		if gd, ok := d.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for i, v := range vs.Values {
						val := c.expr(v)
						if i < len(vs.Names) {
							if tgt, ok := c.add(vs.Names[i].Pos(), "code.Name", [][2]string{{"local", vs.Names[i].Name}}, false); ok {
								c.defFlow(val, tgt)
							}
						}
					}
				}
			}
		}
		return
	}
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		name = receiverType(fd.Recv.List[0].Type) + "." + name
	}
	fnNode, ok := c.add(fd.Pos(), "code.FuncDef", [][2]string{{"name", name}, {"qualified_name", c.file}}, false)
	if !ok {
		return
	}
	if fd.Type != nil && fd.Type.Params != nil {
		for _, field := range fd.Type.Params.List {
			for _, nm := range field.Names {
				var pf graph.Fields
				line, col := c.pos(nm.Pos())
				pf.Set("file", graph.Str(c.file))
				pf.Set("line", graph.Int(int64(line)))
				pf.Set("col", graph.Int(int64(col)))
				pf.Set("region", graph.Str(c.region))
				pf.Set("order", graph.Int(c.f.order))
				pf.Set("approx_lowered", graph.Bool(false))
				pf.Set("name", graph.Str(nm.Name))
				pf.Set("scope", graph.Str(name))
				id := fmt.Sprintf("%s:%d:%d:code.ParamEntry", c.file, line, col)
				pn := graph.Node{ID: id, Type: "code.ParamEntry", Layer: graph.LayerLow, Fields: pf,
					Prov: graph.Provenance{Producer: "golang", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
				if err := c.f.store.AddNode(pn); err != nil {
					continue
				}
				c.skip[id] = true
				c.f.order++
				c.child(fnNode, pn)
			}
		}
	}
	saved := c.region
	c.region = "fn:" + name
	if fd.Body != nil {
		c.stmts(fd.Body.List)
	}
	c.region = saved
}

func receiverType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverType(t.X)
	case *ast.IndexExpr:
		return receiverType(t.X)
	}
	return "recv"
}

func (c *conv) stmts(list []ast.Stmt) {
	for _, s := range list {
		c.stmt(s)
	}
}

func (c *conv) structured(s ast.Stmt, kind string, body func(outer string)) {
	line, _ := c.pos(s.Pos())
	outer := c.region + "/" + kind + fmt.Sprintf("#%d", line)
	saved := c.region
	c.region = outer
	body(outer)
	c.region = saved
}

func (c *conv) in(region string, fn func()) {
	saved := c.region
	c.region = region
	fn()
	c.region = saved
}

func (c *conv) stmt(s ast.Stmt) {
	switch st := s.(type) {
	case *ast.AssignStmt:
		var values []graph.Node
		for _, v := range st.Rhs {
			values = append(values, c.expr(v))
		}
		for i, t := range st.Lhs {
			tgt := c.expr(t)
			if i < len(values) {
				c.defFlow(values[i], tgt)
			}
		}
	case *ast.ExprStmt:
		c.expr(st.X)
	case *ast.ReturnStmt:
		for _, r := range st.Results {
			c.expr(r)
		}
	case *ast.IfStmt:
		c.structured(st, "if", func(outer string) {
			c.expr(st.Cond)
			c.in(outer+"/then", func() { c.stmts(st.Body.List) })
			if st.Else != nil {
				if b, ok := st.Else.(*ast.BlockStmt); ok {
					c.in(outer+"/else", func() { c.stmts(b.List) })
				} else {
					c.stmt(st.Else) // else-if chains
				}
			}
		})
	case *ast.ForStmt, *ast.RangeStmt:
		c.structured(st, "loop", func(outer string) {
			switch f := st.(type) {
			case *ast.ForStmt:
				if f.Init != nil {
					c.stmt(f.Init)
				}
				if f.Cond != nil {
					c.expr(f.Cond)
				}
				if f.Post != nil {
					c.stmt(f.Post)
				}
				c.in(outer+"/body", func() { c.stmts(f.Body.List) })
			case *ast.RangeStmt:
				if f.X != nil {
					c.expr(f.X)
				}
				c.in(outer+"/body", func() { c.stmts(f.Body.List) })
			}
		})
	case *ast.SwitchStmt, *ast.TypeSwitchStmt:
		c.structured(st, "switch", func(outer string) {
			c.in(outer+"/body", func() {
				switch sw := st.(type) {
				case *ast.SwitchStmt:
					if sw.Tag != nil {
						c.expr(sw.Tag)
					}
					for _, cc := range sw.Body.List {
						if cs, ok := cc.(*ast.CaseClause); ok {
							c.stmts(cs.Body)
						}
					}
				case *ast.TypeSwitchStmt:
					for _, cc := range sw.Body.List {
						if cs, ok := cc.(*ast.CaseClause); ok {
							c.stmts(cs.Body)
						}
					}
				}
			})
		})
	case *ast.DeclStmt:
		c.decl(st.Decl)
	case *ast.GoStmt, *ast.DeferStmt:
		var x ast.Expr
		switch g := st.(type) {
		case *ast.GoStmt:
			x = g.Call
		case *ast.DeferStmt:
			x = g.Call
		}
		if x != nil {
			c.expr(x)
		}
	case *ast.BlockStmt:
		c.stmts(st.List)
	default:
		ast.Inspect(st, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && n != st {
				c.expr(e)
				return false
			}
			return true
		})
	}
}

func (c *conv) mustAdd(p token.Pos, typ string, fields [][2]string, approx bool) graph.Node {
	node, ok := c.add(p, typ, fields, approx)
	if !ok {
		line, col := c.pos(p)
		id := fmt.Sprintf("%s:%d:%d:%s", c.file, line, col, typ)
		if got, exists := c.f.store.Node(id); exists {
			return got
		}
	}
	return node
}

func (c *conv) expr(e ast.Expr) graph.Node {
	switch x := e.(type) {
	case *ast.Ident:
		return c.mustAdd(x.Pos(), "code.Name", [][2]string{{"local", x.Name}}, false)
	case *ast.BasicLit:
		v := strings.Trim(x.Value, `"'`)
		return c.mustAdd(x.Pos(), "code.Const", [][2]string{{"value", v}}, false)
	case *ast.SelectorExpr:
		path := exprText(x)
		segs := strings.Split(path, ".")
		node := c.mustAdd(x.Pos(), "code.Attr", [][2]string{{"path", path}, {"attr", segs[len(segs)-1]}}, false)
		if base := c.expr(x.X); base.ID != "" {
			c.child(node, base)
		}
		return node
	case *ast.IndexExpr:
		node := c.mustAdd(x.Pos(), "code.Index", [][2]string{{"path", exprText(x.X)}}, false)
		if key := c.expr(x.Index); key.ID != "" {
			c.child(node, key)
		}
		return node
	case *ast.CallExpr:
		callee := exprText(x.Fun)
		method := ""
		segs := strings.Split(callee, ".")
		if len(segs) > 1 {
			method = segs[len(segs)-1]
		}
		node := c.mustAdd(x.Pos(), "code.Call", [][2]string{
			{"path", callee}, {"callee", callee}, {"method", method},
		}, false)
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			if base := c.expr(sel.X); base.ID != "" {
				c.child(node, base)
			}
		}
		for _, a := range x.Args {
			if arg := c.expr(a); arg.ID != "" {
				c.child(node, arg)
			}
		}
		return node
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			f := c.mustAdd(x.Pos(), "code.Format", [][2]string{{"text", exprText(x.X) + " + " + exprText(x.Y)}}, false)
			for _, part := range []ast.Expr{x.X, x.Y} {
				if p := c.expr(part); p.ID != "" {
					c.child(f, p)
				}
			}
			return f
		}
		node := c.mustAdd(x.Pos(), "code.BinOp", [][2]string{{"op", x.Op.String()}}, false)
		for _, part := range []ast.Expr{x.X, x.Y} {
			if p := c.expr(part); p.ID != "" {
				c.child(node, p)
			}
		}
		return node
	case *ast.UnaryExpr:
		node := c.mustAdd(x.Pos(), "code.Unary", [][2]string{{"op", x.Op.String()}}, false)
		if p := c.expr(x.X); p.ID != "" {
			c.child(node, p)
		}
		return node
	case *ast.FuncLit:
		line, _ := c.pos(x.Pos())
		name := fmt.Sprintf("func#%d", line)
		c.decl(&ast.FuncDecl{
			Name: ast.NewIdent(name),
			Type: &ast.FuncType{Params: &ast.FieldList{}},
			Body: x.Body,
		})
		return c.mustAdd(x.Pos(), "code.Lambda", [][2]string{{"kind", "funclit"}}, false)
	case *ast.ParenExpr:
		return c.expr(x.X)
	case nil:
		return graph.Node{}
	default:
		// Approximate: transparent passthrough stamped approx_lowered.
		node := c.mustAdd(x.Pos(), "code.Transparent", [][2]string{{"kind", fmt.Sprintf("%T", x)}}, true)
		var inner graph.Node
		ast.Inspect(x, func(n ast.Node) bool {
			if inner.ID != "" {
				return false
			}
			if ex, ok := n.(ast.Expr); ok && n != x {
				inner = c.expr(ex)
				return false
			}
			return true
		})
		if inner.ID != "" {
			c.child(node, inner)
		}
		return node
	}
}

// exprText renders an expression's dotted syntactic form.
func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		// Chained calls flatten into the dotted syntactic path — segments,
		// not call shapes, are what matchers walk.
		return exprText(x.Fun)
	case *ast.BasicLit:
		return x.Value
	}
	return fmt.Sprintf("(%T)", e)
}

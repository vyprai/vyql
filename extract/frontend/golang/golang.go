// Package golang is a NATIVE Go-source extraction frontend: it parses real .go
// files with the standard go/parser + go/ast and lowers them to the shared NIR
// (docs/20). Because NIR + the lowering engine are language-agnostic, this is a
// frontend ONLY — resolution, dataflow, and rules are untouched. It is a real
// parser (no fixtures, no CGO), and the first step toward `vyql scan` running on
// actual repositories. Tree-sitter remains the path to other languages; Go's own
// parser is the native upgrade for Go (docs/20 tier 3).
package golang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
)

// ExtractDir parses every .go file under root (recursively, skipping vendor,
// testdata, and _test.go files) and returns one NIR Program. Files are grouped
// into modules by their package directory (relative to root), so same-package
// calls resolve interprocedurally.
func ExtractDir(root string) (nir.Program, error) {
	byPkg := map[string]*nir.Module{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		pkgKey := filepath.Dir(rel)
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // skip unparseable files (robustness, docs/20)
		}
		mod := byPkg[pkgKey]
		if mod == nil {
			mod = &nir.Module{Key: pkgKey, File: rel}
			byPkg[pkgKey] = mod
		}
		c := &conv{fset: fset, file: rel}
		mod.Imports = append(mod.Imports, c.imports(f)...)
		mod.Body = append(mod.Body, c.decls(f.Decls)...)
		return nil
	})
	if err != nil {
		return nir.Program{}, err
	}

	var prog nir.Program
	for _, m := range byPkg {
		prog.Modules = append(prog.Modules, *m)
	}
	return prog, nil
}

// ExtractFiles parses an explicit set of .go files into one Program (one module
// per package directory). Useful for `vyql scan file.go ...`.
func ExtractFiles(files []string) (nir.Program, error) { return Extract(files, "") }

// Extract parses the given .go files into one Program, with locations and module
// keys made relative to root (root "" = use the raw paths). This is the uniform
// frontend signature the CLI dispatcher calls for every language.
func Extract(files []string, root string) (nir.Program, error) {
	byPkg := map[string]*nir.Module{}
	fset := token.NewFileSet()
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			continue
		}
		display := path
		if root != "" {
			if rel, rerr := filepath.Rel(root, path); rerr == nil {
				display = rel
			}
		}
		pkgKey := filepath.Dir(display)
		mod := byPkg[pkgKey]
		if mod == nil {
			mod = &nir.Module{Key: pkgKey, File: display}
			byPkg[pkgKey] = mod
		}
		c := &conv{fset: fset, file: display}
		mod.Imports = append(mod.Imports, c.imports(f)...)
		mod.Body = append(mod.Body, c.decls(f.Decls)...)
	}
	var prog nir.Program
	for _, m := range byPkg {
		prog.Modules = append(prog.Modules, *m)
	}
	return prog, nil
}

// conv converts one parsed file's AST into NIR.
type conv struct {
	fset *token.FileSet
	file string
}

func (c *conv) loc(p token.Pos) string {
	pos := c.fset.Position(p)
	return c.file + ":" + strconv.Itoa(pos.Line)
}

func (c *conv) imports(f *ast.File) []nir.Import {
	var out []nir.Import
	for _, ig := range f.Imports {
		pathv, _ := strconv.Unquote(ig.Path.Value)
		local := filepath.Base(pathv) // default import name = last path segment
		if ig.Name != nil {
			local = ig.Name.Name
		}
		out = append(out, nir.Import{Local: local, Module: pathv, IsModule: true})
	}
	return out
}

func (c *conv) decls(decls []ast.Decl) []nir.Stmt {
	var out []nir.Stmt
	for _, d := range decls {
		switch fn := d.(type) {
		case *ast.FuncDecl:
			var params []string
			if fn.Type.Params != nil {
				for _, p := range fn.Type.Params.List {
					for _, n := range p.Names {
						params = append(params, n.Name)
					}
				}
			}
			var body []nir.Stmt
			if fn.Body != nil {
				body = c.stmts(fn.Body.List)
			}
			out = append(out, nir.FuncDef{Name: fn.Name.Name, Params: params, Body: body, Loc: c.loc(fn.Pos())})
		}
	}
	return out
}

func (c *conv) stmts(list []ast.Stmt) []nir.Stmt {
	var out []nir.Stmt
	for _, s := range list {
		if st := c.stmt(s); st != nil {
			out = append(out, st)
		}
	}
	return out
}

func (c *conv) stmt(s ast.Stmt) nir.Stmt {
	switch st := s.(type) {
	case *ast.AssignStmt:
		if st.Tok == token.ADD_ASSIGN && len(st.Lhs) == 1 && len(st.Rhs) == 1 {
			if id, ok := st.Lhs[0].(*ast.Ident); ok {
				return nir.AugAssign{Target: id.Name, Value: c.expr(st.Rhs[0]), Loc: c.loc(st.Pos())}
			}
		}
		var targets []string
		for _, lhs := range st.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				targets = append(targets, id.Name)
			} else {
				targets = append(targets, "_")
			}
		}
		if len(st.Rhs) == 1 {
			return nir.Assign{Targets: targets, Value: c.expr(st.Rhs[0])}
		}
		// parallel assignment: pair element-wise where possible
		blk := nir.Block{}
		for i := range st.Lhs {
			if i < len(st.Rhs) {
				blk.Stmts = append(blk.Stmts, nir.Assign{Targets: []string{targets[i]}, Value: c.expr(st.Rhs[i])})
			}
		}
		return blk
	case *ast.ReturnStmt:
		if len(st.Results) > 0 {
			return nir.Return{Value: c.expr(st.Results[0])}
		}
		return nir.Return{}
	case *ast.ExprStmt:
		return nir.ExprStmt{Value: c.expr(st.X)}
	case *ast.DeclStmt:
		return c.declStmt(st)
	case *ast.BlockStmt:
		return nir.Block{Stmts: c.stmts(st.List)}
	case *ast.IfStmt:
		var inner []nir.Stmt
		if st.Init != nil {
			if s := c.stmt(st.Init); s != nil {
				inner = append(inner, s)
			}
		}
		inner = append(inner, c.stmts(st.Body.List)...)
		if st.Else != nil {
			if s := c.stmt(st.Else); s != nil {
				inner = append(inner, s)
			}
		}
		return nir.Block{Stmts: inner}
	case *ast.ForStmt:
		return nir.Block{Stmts: c.stmts(st.Body.List)}
	case *ast.RangeStmt:
		return nir.Block{Stmts: c.stmts(st.Body.List)}
	case *ast.SwitchStmt:
		return nir.Block{Stmts: c.stmts(st.Body.List)}
	case *ast.CaseClause:
		return nir.Block{Stmts: c.stmts(st.Body)}
	}
	return nil
}

func (c *conv) declStmt(st *ast.DeclStmt) nir.Stmt {
	gd, ok := st.Decl.(*ast.GenDecl)
	if !ok {
		return nil
	}
	blk := nir.Block{}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		var targets []string
		for _, n := range vs.Names {
			targets = append(targets, n.Name)
		}
		if len(vs.Values) == 1 {
			blk.Stmts = append(blk.Stmts, nir.Assign{Targets: targets, Value: c.expr(vs.Values[0])})
		}
	}
	return blk
}

func (c *conv) expr(e ast.Expr) nir.Expr {
	switch ex := e.(type) {
	case *ast.Ident:
		if ex.Name == "true" || ex.Name == "false" {
			// boolean keyword → a literal value, so value-matching sees
			// InsecureSkipVerify=true etc. (Go booleans are predeclared idents).
			return nir.Const{Loc: c.loc(ex.Pos()), Value: ex.Name}
		}
		return nir.Name{ID: ex.Name, Loc: c.loc(ex.Pos())}
	case *ast.BasicLit:
		return nir.Const{Loc: c.loc(ex.Pos()), Value: ex.Value}
	case *ast.ParenExpr:
		return nir.Thru{Inner: c.expr(ex.X)}
	case *ast.StarExpr:
		return nir.Thru{Inner: c.expr(ex.X)}
	case *ast.UnaryExpr:
		return nir.Thru{Inner: c.expr(ex.X)}
	case *ast.SelectorExpr:
		return nir.Attr{Base: c.expr(ex.X), Attr: ex.Sel.Name, Path: c.path(ex), Loc: c.loc(ex.Pos())}
	case *ast.IndexExpr:
		return nir.Index{Base: c.expr(ex.X), Path: c.path(ex.X), Loc: c.loc(ex.Pos())}
	case *ast.CallExpr:
		return c.call(ex)
	case *ast.BinaryExpr:
		if ex.Op == token.ADD { // string/operand concat propagates taint
			return nir.Format{Parts: []nir.Expr{c.expr(ex.X), c.expr(ex.Y)}, Loc: c.loc(ex.Pos())}
		}
		return nir.Const{Loc: c.loc(ex.Pos())}
	case *ast.CompositeLit:
		var parts []nir.Expr
		for _, el := range ex.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				parts = append(parts, nir.Pair{Key: c.path(kv.Key), Value: c.expr(kv.Value), Loc: c.loc(kv.Pos())})
			} else {
				parts = append(parts, c.expr(el))
			}
		}
		// A NAMED struct literal (T{…} / pkg.T{…}) is modeled as a constructor call
		// so its field values are reachable by value-matching marks — e.g.
		// tls.Config{InsecureSkipVerify: true}. Slice/map/array literals (whose type
		// is *ast.ArrayType/MapType, not a name) stay as Seq.
		if p := c.path(ex.Type); p != "" {
			method := p
			if i := strings.LastIndex(p, "."); i >= 0 {
				method = p[i+1:]
			}
			return nir.Call{Callee: c.expr(ex.Type), Args: parts, Path: p, Method: method, Loc: c.loc(ex.Pos())}
		}
		return nir.Seq{Parts: parts, Loc: c.loc(ex.Pos())}
	}
	return nir.Const{Loc: c.loc(e.Pos())}
}

func (c *conv) call(ex *ast.CallExpr) nir.Call {
	var args []nir.Expr
	for _, a := range ex.Args {
		args = append(args, c.expr(a))
	}
	p := c.path(ex.Fun)
	method := p
	if i := strings.LastIndex(p, "."); i >= 0 {
		method = p[i+1:]
	}
	return nir.Call{Callee: c.expr(ex.Fun), Args: args, Path: p, Method: method, Loc: c.loc(ex.Pos())}
}

// path builds a dotted callee path for adapter matching, e.g. r.URL.Query().Get
// -> "r.URL.Query.Get", db.Exec -> "db.Exec".
func (c *conv) path(e ast.Expr) string {
	switch ex := e.(type) {
	case *ast.Ident:
		return ex.Name
	case *ast.SelectorExpr:
		base := c.path(ex.X)
		if base == "" {
			return ex.Sel.Name
		}
		return base + "." + ex.Sel.Name
	case *ast.CallExpr:
		return c.path(ex.Fun)
	case *ast.IndexExpr:
		return c.path(ex.X)
	case *ast.ParenExpr:
		return c.path(ex.X)
	case *ast.StarExpr:
		return c.path(ex.X)
	}
	return ""
}

// Package golang is a NATIVE Go-source extraction frontend: it parses real .go
// files with the standard go/parser + go/ast and lowers them to the shared NIR
// (docs/20). Because NIR + the lowering engine are language-agnostic, this is a
// frontend ONLY — resolution, dataflow, and rules are untouched. It is a real
// parser (no fixtures, no CGO), and the first step toward `vyql scan` running on
// actual repositories. Tree-sitter remains the path to other languages; Go's own
// parser is the native upgrade for Go (docs/20 tier 3).
package golang

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
)

// modCache memoizes go.mod lookups by directory: dir -> (module path, module root dir).
type modInfo struct{ path, dir string }

// pkgKeyFor returns the module key for a .go file's package. When a go.mod is found by
// walking up from the file, the key is the real Go IMPORT PATH (module path + dir relative to
// the module root) — so a cross-package call like `support.Run(x)` resolves to that package's
// functions (imports record import paths, not directory names). Without a go.mod it falls
// back to the directory path, preserving the prior same-package-only behavior.
func pkgKeyFor(fileAbs, fallback string, cache map[string]*modInfo) string {
	dir := filepath.Dir(fileAbs)
	d := dir
	for {
		if mi, ok := cache[d]; ok {
			if mi == nil {
				return fallback
			}
			return importPath(mi, dir)
		}
		if data, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil {
			mi := &modInfo{path: modulePath(data), dir: d}
			cache[d] = mi
			if mi.path != "" {
				return importPath(mi, dir)
			}
			return fallback
		}
		parent := filepath.Dir(d)
		if parent == d { // reached filesystem root with no go.mod
			cache[dir] = nil
			return fallback
		}
		d = parent
	}
}

func importPath(mi *modInfo, fileDir string) string {
	rel, err := filepath.Rel(mi.dir, fileDir)
	if err != nil || rel == "." || rel == "" {
		return mi.path
	}
	return mi.path + "/" + filepath.ToSlash(rel)
}

// modulePath extracts the module path from go.mod's `module <path>` directive.
func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// ExtractDir parses every .go file under root (recursively, skipping vendor,
// testdata, and _test.go files) and returns one NIR Program. Files are grouped
// into modules by their Go import path (from the enclosing go.mod) so BOTH same-package and
// cross-package (imported-helper) calls resolve interprocedurally.
func ExtractDir(root string) (nir.Program, error) {
	byPkg := map[string]*nir.Module{}
	modCache := map[string]*modInfo{}
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
		abs, aerr := filepath.Abs(path)
		if aerr != nil {
			abs = path
		}
		pkgKey := pkgKeyFor(abs, filepath.Dir(rel), modCache)
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
	modCache := map[string]*modInfo{}
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
		abs, aerr := filepath.Abs(path)
		if aerr != nil {
			abs = path
		}
		pkgKey := pkgKeyFor(abs, filepath.Dir(display), modCache)
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
	// hoisted holds synthetic FuncDefs lifted from func-literal expressions (inline
	// HTTP handlers / goroutines / callbacks). They are flushed into the module body so
	// their bodies and parameter-entry facts are analyzed instead of dropped.
	hoisted []nir.Stmt
	anonSeq int
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
	methods := c.methodMap(decls)
	for _, d := range decls {
		switch fn := d.(type) {
		case *ast.FuncDecl:
			out = append(out, c.funcDef(fn.Name.Name, fn.Type, fn.Body, fn.Name.IsExported(), c.loc(fn.Pos())))
		case *ast.GenDecl:
			out = append(out, c.moduleContextStmts(fn)...)
			out = append(out, c.typeContextStmts(fn, methods)...)
			out = append(out, c.valueDeclStmts(fn)...)
		}
	}
	// Flush func-literal bodies hoisted while lowering this decl set, so inline HTTP
	// handlers / goroutines registered as closures are analyzed as functions.
	out = append(out, c.hoisted...)
	c.hoisted = nil
	return out
}

func (c *conv) valueDeclStmts(gd *ast.GenDecl) []nir.Stmt {
	var out []nir.Stmt
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Names) == 0 {
			continue
		}
		var targets []string
		for _, n := range vs.Names {
			targets = append(targets, n.Name)
		}
		typ := c.typeName(vs.Type)
		if len(vs.Values) == 0 {
			out = append(out, nir.Assign{Targets: targets, Value: nir.Const{Loc: c.loc(vs.Pos())}, Type: typ, Decl: true, Loc: c.loc(vs.Pos())})
			continue
		}
		if len(vs.Values) == 1 {
			out = append(out, nir.Assign{Targets: targets, Value: c.expr(vs.Values[0]), Type: typ, Decl: true, Loc: c.loc(vs.Pos())})
			continue
		}
		limit := len(vs.Values)
		if len(targets) < limit {
			limit = len(targets)
		}
		for i := 0; i < limit; i++ {
			out = append(out, nir.Assign{Targets: []string{targets[i]}, Value: c.expr(vs.Values[i]), Type: typ, Decl: true, Loc: c.loc(vs.Pos())})
		}
	}
	return out
}

func (c *conv) moduleContextStmts(gd *ast.GenDecl) []nir.Stmt {
	if gd == nil || gd.Tok != token.VAR {
		return nil
	}
	var out []nir.Stmt
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
			continue
		}
		tokens := []string{"lang=go"}
		for _, name := range vs.Names {
			tokens = append(tokens, "var_name:"+name.Name)
		}
		for _, value := range vs.Values {
			if text := compactGoNode(c.fset, value); text != "" {
				tokens = append(tokens, text)
			}
		}
		out = append(out, nir.ExprStmt{Value: analysisCall("analysis.module.context", "context", c.loc(vs.Pos()), tokens...)})
	}
	return out
}

func compactGoNode(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, n); err != nil {
		return ""
	}
	text := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(buf.String())
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text
}

func (c *conv) methodMap(decls []ast.Decl) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, d := range decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil {
			continue
		}
		recv := c.receiverType(fn.Recv)
		if recv == "" {
			continue
		}
		if out[recv] == nil {
			out[recv] = map[string]bool{}
		}
		out[recv][fn.Name.Name] = true
	}
	return out
}

func (c *conv) receiverType(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	return c.typeName(recv.List[0].Type)
}

func (c *conv) typeContextStmts(g *ast.GenDecl, methods map[string]map[string]bool) []nir.Stmt {
	var out []nir.Stmt
	if g == nil || g.Tok != token.TYPE {
		return out
	}
	for _, spec := range g.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok || ts.Name == nil {
			continue
		}
		fields := c.structFieldNames(ts.Type)
		if len(fields) == 0 && len(methods[ts.Name.Name]) == 0 {
			continue
		}
		tokens := []string{"type_name:" + ts.Name.Name}
		for _, f := range fields {
			tokens = append(tokens, "field:"+f)
		}
		var ms []string
		for m := range methods[ts.Name.Name] {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		for _, m := range ms {
			tokens = append(tokens, "method:"+m)
		}
		out = append(out, nir.ExprStmt{Value: analysisCall("analysis.type.context", "context", c.loc(ts.Pos()), tokens...)})
	}
	return out
}

func (c *conv) structFieldNames(expr ast.Expr) []string {
	st, ok := expr.(*ast.StructType)
	if !ok || st.Fields == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			if n == nil || n.Name == "_" || seen[n.Name] {
				continue
			}
			seen[n.Name] = true
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

func analysisCall(path, method, loc string, tokens ...string) nir.Call {
	args := make([]nir.Expr, 0, len(tokens))
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		args = append(args, nir.Const{Loc: loc, Value: strconv.Quote(tok)})
	}
	return nir.Call{Callee: nir.Name{ID: path, Loc: loc}, Args: args, Path: path, Method: method, Loc: loc}
}

// funcDef builds a FuncDef from a function type+body (shared by top-level FuncDecl and
// hoisted func literals): extracts params/types, records neutral parameter-entry facts,
// and lowers the body.
func (c *conv) funcDef(name string, typ *ast.FuncType, bodyNode *ast.BlockStmt, exported bool, loc string) nir.FuncDef {
	var params []string
	paramTypes := map[string]string{}
	if typ != nil && typ.Params != nil {
		for _, p := range typ.Params.List {
			t := c.typeName(p.Type)
			for _, n := range p.Names {
				params = append(params, n.Name)
				if t != "" {
					paramTypes[n.Name] = t
				}
			}
		}
	}
	var body []nir.Stmt
	if bodyNode != nil {
		body = c.stmts(bodyNode.List)
	}
	return nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: loc,
		ContextTokens: c.goFunctionTokens(name, bodyNode),
		ParamEntries:  c.goParamEntries(name, params, paramTypes), Exported: exported}
}

func (c *conv) goFunctionTokens(name string, body *ast.BlockStmt) []string {
	var out []string
	seen := map[string]bool{}
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= 128 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if name != "" {
		add("function_name:" + name)
	}
	if body == nil {
		return out
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if len(out) >= 128 {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(x.Value)
			if err != nil || v == "" {
				return true
			}
			if len(v) > 256 {
				v = v[:256]
			}
			add("literal:" + v)
		case *ast.SelectorExpr:
			if p := c.path(x); p != "" {
				add("selector:" + p)
			}
		case *ast.CallExpr:
			p := c.path(x.Fun)
			if p == "" {
				return true
			}
			add("call_path:" + p)
			if i := strings.LastIndex(p, "."); i >= 0 {
				add("call:" + p[i+1:])
			} else {
				add("call:" + p)
			}
		case *ast.BinaryExpr:
			if tok := c.goBinaryToken(x); tok != "" {
				add(tok)
			}
		case *ast.IndexExpr:
			for _, tok := range c.goIndexTokens(x.X, x.Index) {
				add(tok)
			}
		case *ast.SliceExpr:
			for _, tok := range c.goSliceTokens(x) {
				add(tok)
			}
		}
		return true
	})
	return out
}

func (c *conv) goIndexTokens(base ast.Expr, index ast.Expr) []string {
	p := c.path(base)
	if p == "" {
		return nil
	}
	tokens := []string{"index:" + p}
	if idx := c.goAtomToken(index); idx != "" {
		tokens = append(tokens, "index:"+p+":"+idx)
	}
	return tokens
}

func (c *conv) goSliceTokens(x *ast.SliceExpr) []string {
	p := c.path(x.X)
	if p == "" {
		return nil
	}
	tokens := []string{"slice:" + p}
	if x.Low != nil {
		if low := c.goAtomToken(x.Low); low != "" {
			tokens = append(tokens, "slice:"+p+":"+low+":")
		}
	}
	if x.High != nil {
		if high := c.goAtomToken(x.High); high != "" {
			tokens = append(tokens, "slice:"+p+"::"+high)
		}
	}
	return tokens
}

func (c *conv) goBinaryToken(x *ast.BinaryExpr) string {
	left := c.goAtomToken(x.X)
	right := c.goAtomToken(x.Y)
	if left == "" || right == "" {
		return ""
	}
	return "binary:" + left + x.Op.String() + right
}

func (c *conv) goAtomToken(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if p := c.path(x); p != "" {
			return p
		}
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			v, err := strconv.Unquote(x.Value)
			if err != nil || len(v) > 64 {
				return ""
			}
			return strconv.Quote(v)
		}
		if len(x.Value) <= 64 {
			return x.Value
		}
	case *ast.CallExpr:
		p := c.path(x.Fun)
		if p == "len" && len(x.Args) == 1 {
			arg := c.goAtomToken(x.Args[0])
			if arg != "" {
				return "len(" + arg + ")"
			}
		}
	case *ast.BinaryExpr:
		left := c.goAtomToken(x.X)
		right := c.goAtomToken(x.Y)
		if left != "" && right != "" && len(left)+len(right) <= 120 {
			switch x.Op {
			case token.ADD, token.SUB:
				return left + x.Op.String() + right
			}
		}
	case *ast.ParenExpr:
		return c.goAtomToken(x.X)
	}
	return ""
}
func (c *conv) goParamEntries(name string, params []string, paramTypes map[string]string) []nir.ParamEntry {
	var out []nir.ParamEntry
	for i, p := range params {
		if p == "" || p == "_" {
			continue
		}
		tokens := []string{"function_name:" + name, "param_name:" + p, "param_index:" + strconv.Itoa(i)}
		if typ := paramTypes[p]; typ != "" {
			tokens = append(tokens, "param_type:"+typ)
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
	}
	return out
}

// callOutParams returns the identifiers a call writes through as out-parameters:
// every `&x` address-of arg, plus, when the callee name is a bind/parse/decode
// verb, every plain-identifier arg.
func (c *conv) callOutParams(call *ast.CallExpr) []string {
	var outs []string
	for _, a := range call.Args {
		if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND {
			if id, ok := u.X.(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
				outs = append(outs, id.Name)
			}
		}
	}
	if isBindName(calleeName(call.Fun)) {
		for _, a := range call.Args {
			if id, ok := a.(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
				outs = append(outs, id.Name)
			}
		}
	}
	return outs
}

// outParamJoinsFor emits `o = combine(o, …)` for each out-param o of a call. It is a
// taint-JOIN, not a redefinition: a plain `o = …` would SHADOW any taint o already had, so
// f(&taintedVar) would clear it (false negative). The join adds taint AND preserves o's.
//
// For `&x` on an arbitrary call, the joined taint is the call itself. For
// bind/parse/decode helpers, the return is often only an error while the input
// value flows into the destination arg, so also join simple receiver/argument
// expressions that can safely be re-evaluated.
func (c *conv) outParamJoinsFor(call *ast.CallExpr, callExpr nir.Expr, loc string) []nir.Stmt {
	outs := c.callOutParams(call)
	if len(outs) == 0 {
		return nil
	}
	srcs := []nir.Expr{callExpr}
	if isBindName(calleeName(call.Fun)) {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if e := c.simpleTaintExpr(sel.X); e != nil {
				srcs = append(srcs, e)
			}
		}
		for _, a := range call.Args {
			if e := c.simpleTaintExpr(a); e != nil {
				srcs = append(srcs, e)
			}
		}
	}
	var stmts []nir.Stmt
	for _, o := range outs {
		parts := append([]nir.Expr{nir.Name{ID: o, Loc: loc}}, srcs...)
		stmts = append(stmts, nir.Assign{Targets: []string{o},
			Value: nir.Format{Parts: parts, Loc: loc}})
	}
	return stmts
}

// simpleTaintExpr lowers an argument/receiver expression only when it is
// side-effect-free, so the out-param join can safely evaluate it again.
func (c *conv) simpleTaintExpr(e ast.Expr) nir.Expr {
	switch x := e.(type) {
	case *ast.Ident:
		if x.Name == "_" || x.Name == "" || x.Name == "nil" {
			return nil
		}
		return c.expr(x)
	case *ast.SelectorExpr, *ast.StarExpr:
		return c.expr(e)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return c.expr(e)
		}
	}
	return nil
}

// calleeName returns the last identifier of a call's function expression.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func isBindName(name string) bool {
	if name == "" {
		return false
	}
	low := strings.ToLower(name)
	for _, p := range []string{"parse", "decode", "unmarshal", "bind", "scan", "populate", "deserialize", "readinto", "readbody"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

func (c *conv) typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if base := c.typeName(t.X); base != "" {
			return base + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return c.typeName(t.X)
	case *ast.ArrayType:
		return c.typeName(t.Elt)
	case *ast.IndexExpr:
		return c.typeName(t.X)
	case *ast.IndexListExpr:
		return c.typeName(t.X)
	}
	return ""
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
		// subscript write `m[k] = v` / `a[i] = v`: model as a container taint-join
		// `m = combine(m, v)` so a later `m[k]` read carries v's taint (otherwise the
		// write target is "_" and the taint is dropped). Conservative (whole-container).
		if len(st.Lhs) == 1 && len(st.Rhs) == 1 {
			if ix, ok := st.Lhs[0].(*ast.IndexExpr); ok {
				if base, ok := ix.X.(*ast.Ident); ok && base.Name != "_" {
					return nir.Assign{Targets: []string{base.Name},
						Value: nir.Format{Parts: []nir.Expr{nir.Name{ID: base.Name, Loc: c.loc(base.Pos())}, c.expr(st.Rhs[0])}, Loc: c.loc(st.Pos())},
						Loc:   c.loc(st.Pos())}
				}
			}
		}
		var targets []string
		for _, lhs := range st.Lhs {
			targets = append(targets, c.assignTarget(lhs))
		}
		if len(st.Rhs) == 1 {
			assign := nir.Assign{Targets: targets, Value: c.expr(st.Rhs[0]), Loc: c.loc(st.Pos())}
			// The result goes to err, but the call can also write through
			// address-of out-parameter destinations; taint those too. The
			// AssignStmt path covers `if err := f(&x); err != nil`.
			if call, ok := st.Rhs[0].(*ast.CallExpr); ok {
				if joins := c.outParamJoinsFor(call, c.expr(st.Rhs[0]), c.loc(st.Pos())); len(joins) > 0 {
					stmts := append([]nir.Stmt{assign}, joins...)
					return nir.Block{Stmts: stmts}
				}
			}
			return assign
		}
		// parallel assignment: pair element-wise where possible
		blk := nir.Block{}
		for i := range st.Lhs {
			if i < len(st.Rhs) {
				blk.Stmts = append(blk.Stmts, nir.Assign{Targets: []string{targets[i]}, Value: c.expr(st.Rhs[i]), Loc: c.loc(st.Pos())})
			}
		}
		return blk
	case *ast.ReturnStmt:
		if len(st.Results) > 0 {
			return nir.Return{Value: c.expr(st.Results[0])}
		}
		return nir.Return{}
	case *ast.ExprStmt:
		// Out-parameter taint: a bare call passing the address of a local writes
		// through that pointer, so model it as a join from the call result.
		if call, ok := st.X.(*ast.CallExpr); ok {
			if stmts := c.outParamJoinsFor(call, c.expr(st.X), c.loc(st.Pos())); len(stmts) > 0 {
				if len(stmts) == 1 {
					return stmts[0]
				}
				return nir.Block{Stmts: stmts}
			}
		}
		return nir.ExprStmt{Value: c.expr(st.X)}
	case *ast.DeclStmt:
		return c.declStmt(st)
	case *ast.BlockStmt:
		return nir.Block{Stmts: c.stmts(st.List)}
	case *ast.IfStmt:
		// branch-structured (B1): Then/Else are distinct branches; an `if x := …; cond`
		// Init runs before the branch. Cond is left nil — the Go frontend did not evaluate
		// it before B1, so omitting it keeps the flattened node set byte-identical (branch
		// STRUCTURE is what the CFG/dominance pass needs, not the predicate expression).
		ifn := nir.If{Cond: c.expr(st.Cond), Then: c.stmts(st.Body.List), Loc: c.loc(st.Pos())}
		if st.Else != nil {
			if s := c.stmt(st.Else); s != nil {
				ifn.Else = []nir.Stmt{s}
			}
		}
		if st.Init != nil {
			if s := c.stmt(st.Init); s != nil {
				return nir.Block{Stmts: []nir.Stmt{s, ifn}}
			}
		}
		return ifn
	case *ast.ForStmt:
		return nir.Loop{Body: c.stmts(st.Body.List), Loc: c.loc(st.Pos())}
	case *ast.RangeStmt:
		var vars []string
		for _, e := range []ast.Expr{st.Key, st.Value} {
			if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
				vars = append(vars, id.Name)
			}
		}
		return nir.Loop{Iter: c.expr(st.X), Vars: vars, Body: c.stmts(st.Body.List), Loc: c.loc(st.Pos())}
	case *ast.SwitchStmt:
		return c.switchStmt(st.Body, st.Tag)
	// NOTE: *ast.TypeSwitchStmt is intentionally left to the nil default (it was a no-op
	// before B1 — converting it would lower previously-ignored bodies and shift baselines).
	case *ast.CaseClause:
		return nir.Block{Stmts: c.stmts(st.Body)}
	}
	return nil
}

func (c *conv) assignTarget(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if p := c.path(x); p != "" {
			return p
		}
	case *ast.StarExpr:
		return c.assignTarget(x.X)
	}
	return "_"
}

// switchStmt converts a switch body to a branch-structured nir.Switch. Each case clause
// body becomes a branch; a default clause (nil case list) is the Default branch. Flatten-
// lowering lowers every branch body in turn — the same node set the prior Block produced.
func (c *conv) switchStmt(body *ast.BlockStmt, tag ast.Expr) nir.Stmt {
	if body == nil {
		return nil
	}
	sw := nir.Switch{Subject: c.expr(tag)}
	for _, clause := range body.List {
		cc, ok := clause.(*ast.CaseClause)
		if !ok {
			continue
		}
		b := c.stmts(cc.Body)
		if cc.List == nil {
			sw.Default = b
		} else {
			// each case `case a, b:` lists one or more label expressions (Go has no
			// fall-through by default, so each clause is self-contained).
			var labs []nir.Expr
			for _, e := range cc.List {
				labs = append(labs, c.expr(e))
			}
			sw.Cases = append(sw.Cases, b)
			sw.Labels = append(sw.Labels, labs)
		}
	}
	return sw
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
			blk.Stmts = append(blk.Stmts, nir.Assign{Targets: targets, Value: c.expr(vs.Values[0]), Loc: c.loc(vs.Pos())})
		}
	}
	return blk
}

func (c *conv) expr(e ast.Expr) nir.Expr {
	if e == nil {
		// nil sub-expressions are legal in Go ASTs: a tag-less `switch { … }`,
		// a slice expr with omitted bounds (a[:]), a bare `return`, etc. Model
		// them as an empty constant so downstream lowering never deref-panics.
		return nir.Const{}
	}
	switch ex := e.(type) {
	case *ast.Ident:
		if ex.Name == "true" || ex.Name == "false" {
			// Boolean keywords are literal values, so adapter value-matching can
			// inspect struct fields and call arguments consistently.
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
		return nir.Unary{Op: ex.Op.String(), Operand: c.expr(ex.X), Loc: c.loc(ex.Pos())}
	case *ast.SelectorExpr:
		return nir.Attr{Base: c.expr(ex.X), Attr: ex.Sel.Name, Path: c.path(ex), Loc: c.loc(ex.Pos())}
	case *ast.IndexExpr:
		return nir.Index{Base: c.expr(ex.X), Key: c.expr(ex.Index), Path: c.path(ex.X), Loc: c.loc(ex.Pos())}
	case *ast.CallExpr:
		return c.call(ex)
	case *ast.FuncLit:
		// An inline closure (HTTP handler registered via http.HandleFunc/router.GET, a
		// goroutine, a callback). Its body would otherwise be dropped. Hoist it as a
		// synthetic anonymous FuncDef so the body and parameter-entry facts are analyzed;
		// the closure value itself flows nothing.
		c.anonSeq++
		fd := c.funcDef("func#"+strconv.Itoa(c.anonSeq), ex.Type, ex.Body, false, c.loc(ex.Pos()))
		c.hoisted = append(c.hoisted, fd)
		return nir.Const{Loc: c.loc(ex.Pos())}
	case *ast.BinaryExpr:
		if ex.Op == token.ADD { // string/operand concat propagates taint
			return nir.Format{Parts: []nir.Expr{c.expr(ex.X), c.expr(ex.Y)}, Loc: c.loc(ex.Pos())}
		}
		// other operators preserve the operator (constant-folding) and flow taint through both sides
		return nir.BinOp{Op: ex.Op.String(), Left: c.expr(ex.X), Right: c.expr(ex.Y), Loc: c.loc(ex.Pos())}
	case *ast.CompositeLit:
		var parts []nir.Expr
		for _, el := range ex.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				parts = append(parts, nir.Pair{Key: c.path(kv.Key), Value: c.expr(kv.Value), Loc: c.loc(kv.Pos())})
			} else {
				parts = append(parts, c.expr(el))
			}
		}
		// A NAMED struct literal (T{...} / pkg.T{...}) is modeled as a constructor
		// call so its field values are reachable by adapter value-matching. Slice,
		// map, and array literals (whose type is *ast.ArrayType/MapType, not a
		// name) stay as Seq.
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
// -> "r.URL.Query.Get", svc.Run -> "svc.Run".
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

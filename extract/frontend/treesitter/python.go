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
	src           []byte
	root          string // scan root, for display-relative loc
	file          string // current file (display path, relative to root)
	key           string // current module key (source-root dotted)
	moduleContext string
}

// ExtractPython parses Python files into one NIR Program (one module per file,
// keyed by its source-root-relative dotted path so imports resolve).
func ExtractPython(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tspython.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			root0 := tree.RootNode()
			c := &pyConv{src: src, root: root, file: rel, key: moduleKey(root, abs, ".py")}
			c.moduleContext = c.pyModuleLiteralContext(root0)
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: c.blockChildren(root0)}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
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
	// cache the count: each *Count() is a cgo call, and re-evaluating it in the loop
	// condition (once per child) was the bulk of the cgo traffic in this hot helper.
	k := n.NamedChildCount()
	out := make([]*tree_sitter.Node, 0, k)
	for i := uint(0); i < k; i++ {
		out = append(out, n.NamedChild(i))
	}
	return out
}

func children(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	k := n.ChildCount()
	out := make([]*tree_sitter.Node, 0, k)
	for i := uint(0); i < k; i++ {
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

// hasValidatorComment reports whether a function carries a `# vyql: validator` marker
// comment in its body — opting it in as a trust-boundary input-validator/authenticator the
// tool can't infer by name. Matched loosely (any comment containing "vyql" and "validat").
func (c *pyConv) hasValidatorComment(fn *tree_sitter.Node) bool {
	// the marker comment attaches as a direct child of the function_definition (between the
	// signature and the body suite) or as a leading statement inside the body block.
	scan := func(n *tree_sitter.Node) bool {
		if n == nil {
			return false
		}
		for _, ch := range children(n) {
			if ch.Kind() == "comment" {
				s := strings.ToLower(c.text(ch))
				if strings.Contains(s, "vyql") && strings.Contains(s, "validat") {
					return true
				}
			}
		}
		return false
	}
	return scan(fn) || scan(field(fn, "body"))
}

// firstIdent returns the first identifier at or under n (e.g. the target name inside a
// with-statement `as` alias, which may be wrapped in an as_pattern_target).
func firstIdent(n *tree_sitter.Node) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	if n.Kind() == "identifier" {
		return n
	}
	for _, ch := range children(n) {
		if r := firstIdent(ch); r != nil {
			return r
		}
	}
	return nil
}

// stringInterps returns the lowered expressions of every `{…}` interpolation in a string
// node (empty for a plain string literal).
func (c *pyConv) stringInterps(n *tree_sitter.Node) []nir.Expr {
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
	return interps
}

// matchPatternLabels classifies a match `case_clause`'s pattern: a wildcard `_` is the
// default, literal patterns (and unions of literals) yield label expressions, and anything
// else (capture, class, value, guard) returns literal=false so the match is left unprunable.
func (c *pyConv) matchPatternLabels(caseClause *tree_sitter.Node) (labels []nir.Expr, isDefault, literal bool) {
	for _, ch := range children(caseClause) {
		if ch.Kind() == "case_pattern" {
			if kids := namedChildren(ch); len(kids) > 0 {
				return c.patternLabels(kids[0])
			}
			if strings.TrimSpace(c.text(ch)) == "_" {
				return nil, true, false
			}
		}
	}
	return nil, false, false
}

func (c *pyConv) patternLabels(p *tree_sitter.Node) (labels []nir.Expr, isDefault, literal bool) {
	switch p.Kind() {
	case "_", "wildcard_pattern":
		return nil, true, false
	case "string", "integer", "float", "true", "false", "none", "concatenated_string":
		return []nir.Expr{c.expr(p)}, false, true
	case "union_pattern":
		var labs []nir.Expr
		for _, sub := range namedChildren(p) {
			l, d, lit := c.patternLabels(sub)
			if d || !lit {
				return nil, false, false // a non-literal alternative — unprunable
			}
			labs = append(labs, l...)
		}
		return labs, false, len(labs) > 0
	case "case_pattern":
		if kids := namedChildren(p); len(kids) > 0 {
			return c.patternLabels(kids[0])
		}
	}
	return nil, false, false // capture / class / value pattern — could match anything
}

func (c *pyConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch n.Kind() {
	case "function_definition":
		name := c.text(field(n, "name"))
		params := c.params(field(n, "parameters"))
		paramTypes := c.paramTypes(field(n, "parameters"))
		body := c.block(field(n, "body"))
		body = append(body, c.pyFunctionContext(n)...)
		// GraphQL (graphene/ariadne) resolver: `def resolve_x(self, info, arg…)` —
		// the args after self/info/root/parent are the query's user-supplied inputs.
		if strings.HasPrefix(name, "resolve_") {
			body = append(c.seedResolverParams(params, L), body...)
		}
		// public API = no leading underscore, OR a dunder (__init__/__call__ are entry points).
		exported := !strings.HasPrefix(name, "_") || (strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__"))
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, IsValidator: c.hasValidatorComment(n), Exported: exported}}
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
		decorators := c.pyDecoratorTokens(n)
		// FastAPI/Flask/Starlette route handlers: `@app.get(...)`, `@router.post(...)`,
		// `@app.route(...)` — the function's parameters are bound from the request
		// (path/query/body), so seed each as http_input (like Java controllers).
		if def.Kind() == "function_definition" && c.hasRouteDecorator(n) {
			params := c.params(field(def, "parameters"))
			paramTypes := c.paramTypes(field(def, "parameters"))
			body := c.block(field(def, "body"))
			var seed []nir.Stmt
			for _, p := range params {
				if p == "self" || p == "cls" {
					continue
				}
				seed = append(seed, nir.Assign{Targets: []string{p},
					Value: nir.Call{Callee: nir.Name{ID: "http_input", Loc: L}, Path: "http_input", Method: "http_input", Loc: L}})
			}
			return []nir.Stmt{nir.FuncDef{Name: c.text(field(def, "name")), Params: params, ParamTypes: paramTypes, Body: append(seed, body...), Loc: L, Decorators: decorators, Exported: true}}
		}
		out := c.stmt(def)
		for i, st := range out {
			if fn, ok := st.(nir.FuncDef); ok {
				fn.Decorators = decorators
				out[i] = fn
			}
		}
		return out
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
			left := field(inner, "left")
			tgts := c.targets(left)
			// subscript store `container[k] = v` (e.g. session[bar] = v, map[k] = param): no
			// simple name target, so model it as a mutating setitem that taints the container
			// from v — otherwise a later read `x = container[k]` loses the taint.
			if len(tgts) == 0 && left != nil && left.Kind() == "subscript" {
				base := c.expr(field(left, "value"))
				args := []nir.Expr{val}
				if k := field(left, "subscript"); k != nil {
					args = append(args, c.expr(k)) // include the key: session[tainted_key] = x
				}
				path := c.dotted(field(left, "value"))
				if path != "" {
					path += ".__setitem__"
				}
				return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: base, Attr: "__setitem__", Loc: L},
					Method: "__setitem__", Args: args, Path: path, Loc: L}}}
			}
			return []nir.Stmt{nir.Assign{Targets: tgts, Value: val}}
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
		// branch-structured (B1). Cond carries the predicate (python evaluated it before,
		// and the flatten lowering still does, so this is byte-identical). collectBlocks
		// already gathers the then/elif/else bodies; keep them as the then-branch so the
		// flattened node set is unchanged.
		var cond nir.Expr
		if cn := field(n, "condition"); cn != nil {
			cond = c.expr(cn)
		}
		if n.Kind() == "while_statement" {
			return []nir.Stmt{nir.Loop{Cond: cond, Body: c.collectBlocks(n)}}
		}
		// Separate Then/Else (the elif/else chain) instead of flattening every clause into
		// Then, so a value tainted on one path stays tainted past the join even when another
		// path overwrites it (`if c: p = src()` / `else: p = "safe"`).
		return []nir.Stmt{nir.If{Cond: cond, Then: c.block(field(n, "consequence")), Else: c.pyIfElse(n)}}
	case "for_statement":
		var inner []nir.Stmt
		left, right := field(n, "left"), field(n, "right")
		if left != nil && left.Kind() == "identifier" && right != nil {
			inner = append(inner, nir.Assign{Targets: []string{c.text(left)}, Value: c.expr(right)})
		}
		// the loop-var assign runs before the loop body; flatten lowers assign then body.
		return []nir.Stmt{nir.Block{Stmts: append(inner, nir.Loop{Body: c.collectBlocks(n)})}}
	case "with_statement":
		// `with EXPR as VAR:` — lower each context-manager EXPR (commonly an open()/file sink)
		// and bind VAR to it, then the body. Previously the with-clause expression was dropped,
		// so `with open(tainted) as fd:` had no sink node.
		var pre []nir.Stmt
		var walkWith func(node *tree_sitter.Node)
		walkWith = func(node *tree_sitter.Node) {
			for _, ch := range children(node) {
				switch ch.Kind() {
				case "with_clause":
					walkWith(ch)
				case "with_item":
					val := field(ch, "value")
					if val == nil {
						continue
					}
					if val.Kind() == "as_pattern" {
						kids := namedChildren(val)
						if len(kids) == 0 {
							continue
						}
						expr := c.expr(kids[0])
						if alias := field(val, "alias"); alias != nil {
							if id := firstIdent(alias); id != nil {
								pre = append(pre, nir.Assign{Targets: []string{c.text(id)}, Value: expr})
								continue
							}
						}
						pre = append(pre, nir.ExprStmt{Value: expr})
					} else {
						pre = append(pre, nir.ExprStmt{Value: c.expr(val)})
					}
				}
			}
		}
		walkWith(n)
		return []nir.Stmt{nir.Block{Stmts: append(pre, c.collectBlocks(n)...)}}
	case "try_statement":
		return []nir.Stmt{nir.Try{Body: c.collectBlocks(n)}}
	case "match_statement":
		// Python 3.10 structural match — each case becomes a Switch branch so the (often
		// tainted) assignments inside are analysed. Literal-only matches (`case 'A':` /
		// `case 'C' | 'D':` / `case _:`) also capture subject + labels so a constant subject
		// prunes to the matching case. A capture/class/guard pattern (which could match
		// anything) makes the whole match NON-prunable — sound, never a false negative.
		var cases [][]nir.Stmt
		var labels [][]nir.Expr
		var deflt []nir.Stmt
		prunable := true
		body := field(n, "body")
		if body == nil {
			body = n
		}
		for _, cl := range children(body) {
			if cl.Kind() != "case_clause" {
				continue
			}
			var stmts []nir.Stmt
			if b := field(cl, "consequence"); b != nil {
				stmts = c.block(b)
			}
			labs, isDefault, literal := c.matchPatternLabels(cl)
			switch {
			case isDefault:
				deflt = append(deflt, stmts...)
			case literal:
				cases = append(cases, stmts)
				labels = append(labels, labs)
			default:
				prunable = false
				cases = append(cases, stmts)
				labels = append(labels, nil)
			}
		}
		if prunable {
			return []nir.Stmt{nir.Switch{Subject: c.expr(field(n, "subject")), Cases: cases, Labels: labels, Default: deflt}}
		}
		return []nir.Stmt{nir.Switch{Cases: append(cases, deflt)}} // unprunable: bodies only
	}
	return nil
}

// pyIfElse builds the Else branch of an if_statement from its elif_clause/else_clause
// children: each elif becomes a nested If chaining to the alternatives after it, and a
// trailing else becomes a plain block. Returns nil when there is no else/elif.
func (c *pyConv) pyIfElse(n *tree_sitter.Node) []nir.Stmt {
	var alts []*tree_sitter.Node
	for _, ch := range children(n) {
		if ch.Kind() == "elif_clause" || ch.Kind() == "else_clause" {
			alts = append(alts, ch)
		}
	}
	var els []nir.Stmt
	for i := len(alts) - 1; i >= 0; i-- {
		a := alts[i]
		body := c.clauseBlock(a)
		if a.Kind() == "else_clause" {
			els = body
			continue
		}
		var cond nir.Expr // elif: a nested If whose Else is the chain built so far
		if cn := field(a, "condition"); cn != nil {
			cond = c.expr(cn)
		}
		els = []nir.Stmt{nir.If{Cond: cond, Then: body, Else: els}}
	}
	return els
}

func (c *pyConv) pyFunctionContext(fn *tree_sitter.Node) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(fn, "name"))
	bodyText := c.text(body)
	loc := c.loc(fn)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "name=" + name},
		nir.Const{Loc: loc, Value: bodyText},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(bodyText), "")},
		nir.Const{Loc: loc, Value: c.moduleContext},
	}
	contextPath := "analysis.function.context"
	sourcePath := "analysis.function.context.source"
	sinkPath := "analysis.function.context.sink"
	tmp := "__vyql_function_context"
	sinkArgs := append([]nir.Expr{nir.Name{ID: tmp, Loc: loc}}, args...)
	return []nir.Stmt{
		nir.Assign{Targets: []string{tmp}, Value: nir.Call{
			Callee: nir.Name{ID: sourcePath, Loc: loc},
			Args:   args,
			Path:   sourcePath,
			Method: "source",
			Loc:    loc,
		}},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: contextPath, Loc: loc},
			Args:   args,
			Path:   contextPath,
			Method: "context",
			Loc:    loc,
		}},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: sinkPath, Loc: loc},
			Args:   sinkArgs,
			Path:   sinkPath,
			Method: "sink",
			Loc:    loc,
		}},
	}
}

func (c *pyConv) pyModuleLiteralContext(root *tree_sitter.Node) string {
	var toks []string
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "string" || n.Kind() == "concatenated_string" {
			toks = append(toks, c.text(n))
			return
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	walk(root)
	return strings.Join(toks, "\n")
}

// clauseBlock returns the lowered statements of a clause's `block` child.
func (c *pyConv) clauseBlock(clause *tree_sitter.Node) []nir.Stmt {
	for _, cc := range children(clause) {
		if cc.Kind() == "block" {
			return c.block(cc)
		}
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

func (c *pyConv) pyDecoratorTokens(n *tree_sitter.Node) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "decorator" {
			continue
		}
		path := c.pyDecoratorPath(ch)
		add("decorator_path:" + path)
		if i := strings.LastIndex(path, "."); i >= 0 {
			add("decorator_method:" + path[i+1:])
		} else {
			add("decorator_method:" + path)
		}
	}
	return out
}

func (c *pyConv) pyDecoratorPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "decorator", "call":
		if p := c.pyDecoratorPath(field(n, "function")); p != "" {
			return p
		}
	case "attribute":
		base := c.pyDecoratorPath(field(n, "object"))
		if base == "" {
			base = c.pyDecoratorPath(field(n, "value"))
		}
		attr := c.text(field(n, "attribute"))
		if base == "" {
			return attr
		}
		if attr == "" {
			return base
		}
		return base + "." + attr
	case "identifier":
		return c.text(n)
	}
	for _, ch := range namedChildren(n) {
		if p := c.pyDecoratorPath(ch); p != "" {
			return p
		}
	}
	return ""
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

func (c *pyConv) paramTypes(params *tree_sitter.Node) map[string]string {
	out := map[string]string{}
	if params == nil {
		return out
	}
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "typed_parameter", "typed_default_parameter":
			name := ""
			if nm := field(ch, "name"); nm != nil {
				name = c.text(nm)
			} else if kids := namedChildren(ch); len(kids) > 0 {
				name = c.text(kids[0])
			}
			putParamType(out, name, paramTypeFromField(c, ch))
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
	case "concatenated_string":
		// implicit adjacent-string concatenation `f'a {x}' f'b {y}'` — gather the
		// interpolations from EVERY part (previously this dropped them all, hiding any
		// tainted value or sink call inside the later parts).
		var interps []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "string" {
				interps = append(interps, c.stringInterps(ch)...)
			}
		}
		if len(interps) > 0 {
			return nir.Format{Parts: interps, Loc: L}
		}
		return nir.Const{Loc: L}
	case "integer", "float":
		// carry the literal text so value-matching can see numeric modes/flags
		// (e.g. os.chmod(p, 0o777)); taint is unaffected (Value is val-match only).
		return nir.Const{Loc: L, Value: c.text(n)}
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
		return nir.Index{Base: c.expr(field(n, "value")), Key: c.expr(field(n, "subscript")), Path: c.dotted(field(n, "value")), Loc: L}
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
		left, right := c.expr(field(n, "left")), c.expr(field(n, "right"))
		if op == "%" || op == "+" {
			// `%` (string-format / modulo) and `+` (concat / add) stay taint-propagating Formats.
			return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		}
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	case "comparison_operator":
		kids := namedChildren(n)
		if len(kids) == 2 { // simple `a OP b` (chained comparisons keep their Seq fallback)
			return nir.BinOp{Op: c.text(field(n, "operators")), Left: c.expr(kids[0]), Right: c.expr(kids[1]), Loc: L}
		}
		return nir.Seq{Parts: []nir.Expr{c.expr(kids[0])}, Loc: L}
	case "boolean_operator":
		return nir.BinOp{Op: c.text(field(n, "operator")), Left: c.expr(field(n, "left")), Right: c.expr(field(n, "right")), Loc: L}
	case "not_operator":
		return nir.Unary{Op: "not", Operand: c.expr(field(n, "argument")), Loc: L}
	case "conditional_expression":
		kids := namedChildren(n) // [then, cond, else]
		if len(kids) >= 3 {
			return nir.Ternary{Then: c.expr(kids[0]), Cond: c.expr(kids[1]), Else: c.expr(kids[2]), Loc: L}
		}
	case "string":
		if interps := c.stringInterps(n); len(interps) > 0 {
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

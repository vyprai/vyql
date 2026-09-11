package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tshaskell "github.com/tree-sitter/tree-sitter-haskell/bindings/go"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// hsConv walks a tree-sitter Haskell CST into NIR.
type hsConv struct {
	nodeCache
	src   []byte
	file  string
	key   string
	cases int
}

// ExtractHaskell parses .hs files into one NIR Program (one module per file).
func ExtractHaskell(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(tshaskell.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &hsConv{src: src, file: rel, key: moduleKey(root, abs, ".hs")}
			root := tree.RootNode()
			// every declaration sits in one `declarations` group under the root; a
			// file that fails to parse has none, and walking the root finds nothing
			decls := c.field(root, "declarations")
			if decls == nil {
				decls = root
			}
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(root), Body: c.decls(decls, true)}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *hsConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *hsConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// firstNamed is the single child of a wrapper node (`parens`, `exp`, the grammar's
// boolean-position node), or nil.
func (c *hsConv) firstNamed(n *tree_sitter.Node) *tree_sitter.Node {
	if kids := c.namedChildren(n); len(kids) > 0 {
		return kids[0]
	}
	return nil
}

// imports collects the import table: `import M` binds the module, `import
// qualified M as N` binds it under N, and `import M (a, b)` binds each listed
// name as well.
func (c *hsConv) imports(root *tree_sitter.Node) []nir.Import {
	var out []nir.Import
	for _, grp := range c.namedChildren(root) {
		if c.kind(grp) != "imports" {
			continue
		}
		for _, imp := range c.namedChildren(grp) {
			if c.kind(imp) != "import" {
				continue
			}
			mod := c.text(c.field(imp, "module"))
			local := mod
			if alias := c.field(imp, "alias"); alias != nil {
				local = c.text(alias)
			}
			out = append(out, nir.Import{Local: local, Module: mod, IsModule: true})
			if list := c.field(imp, "names"); list != nil {
				for _, nm := range c.namedChildren(list) {
					if c.kind(nm) == "import_name" {
						sym := c.text(orSelf(c.firstNamed(nm), nm))
						out = append(out, nir.Import{Local: sym, Module: mod, Symbol: sym})
					}
				}
			}
		}
	}
	return out
}

// decls walks a `declarations` (module level) or `local_binds` (let / where) node.
// `top` says whether a bare `name = rhs` binding is a module-level definition
// rather than a local assignment; the two parse identically.
func (c *hsConv) decls(n *tree_sitter.Node, top bool) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.decl(ch, top)...)
	}
	return out
}

// decl lowers one declaration. Everything a module can declare but not run —
// signatures, data types, fixities, pragmas, haddocks — yields nothing, so an
// unknown declaration kind is as inert here as a skipped one.
func (c *hsConv) decl(n *tree_sitter.Node, top bool) []nir.Stmt {
	L := c.loc(n)
	switch c.kind(n) {
	case "function":
		return c.function(n, L)
	case "bind":
		if top {
			return c.topBind(n, L)
		}
		return c.localBind(n, L)
	case "class", "instance":
		return c.classLike(n)
	}
	return nil
}

// function lowers a definition with parameters. The clauses are the guard arms
// (`| g = rhs`), one `match` each; `binds` is the `where` block.
func (c *hsConv) function(n *tree_sitter.Node, L string) []nir.Stmt {
	fd := nir.FuncDef{
		Name:   c.text(c.field(n, "name")),
		Params: c.patternNames(c.field(n, "patterns")),
		Loc:    L,
	}
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "match" {
			fd.Body = append(fd.Body, c.clause(ch)...)
		}
	}
	fd.Body = append(fd.Body, c.decls(c.field(n, "binds"), false)...)
	return []nir.Stmt{fd}
}

// topBind is a module-level definition without parameters (`main = do …`). It is
// still a function of no arguments in Haskell, and registering it as one is what
// puts the calls in its body inside a function scope for resolution and labelling.
func (c *hsConv) topBind(n *tree_sitter.Node, L string) []nir.Stmt {
	m := c.field(n, "match")
	if m == nil {
		return nil
	}
	fd := nir.FuncDef{Name: c.text(c.field(n, "name")), Loc: L}
	fd.Body = append(fd.Body, c.clause(m)...)
	fd.Body = append(fd.Body, c.decls(c.field(n, "binds"), false)...)
	return []nir.Stmt{fd}
}

// localBind is a let / where `name = rhs`.
func (c *hsConv) localBind(n *tree_sitter.Node, L string) []nir.Stmt {
	m := c.field(n, "match")
	if m == nil {
		return nil
	}
	name := c.text(c.field(n, "name"))
	if name == "" {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(c.field(m, "expression")), Decl: true, Loc: L}}
}

// classLike inlines a `class` or `instance` body. Neither is a class in the
// object sense — there is no receiver to resolve — but an instance's methods
// (`instance Sink Cfg where emit cfg msg = …`) are real bodies whose calls must
// be walked, and they are called by their own bare name exactly as top-level
// functions are.
func (c *hsConv) classLike(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "class_declarations", "instance_declarations":
			out = append(out, c.decls(ch, true)...)
		}
	}
	return out
}

// clause lowers one `= rhs` (or `| guard = rhs`) arm of a definition. A guard
// becomes an If's condition so an arm only flows under it; the arms stay
// sequential, which over-approximates the fall-through the same way every other
// frontend's branch merge does.
func (c *hsConv) clause(n *tree_sitter.Node) []nir.Stmt {
	body := c.definitionBody(c.field(n, "expression"))
	guard := c.field(n, "guards")
	if guard == nil {
		return body
	}
	// comma-separated guards are a conjunction; the first is the one that prunes.
	return []nir.Stmt{nir.If{Cond: c.expr(c.field(guard, "guard")), Then: body, Loc: c.loc(n)}}
}

// definitionBody lowers the value a definition arm or lambda evaluates to. Its
// value is what a call to the definition evaluates to, so it is returned.
func (c *hsConv) definitionBody(n *tree_sitter.Node) []nir.Stmt {
	return c.bodyStmts(n, true)
}

// armBody lowers the value a case arm evaluates to, reporting the value apart
// from the statements that produce it. A case arm does not return from the
// enclosing function, so the value is left to its caller to place.
func (c *hsConv) armBody(n *tree_sitter.Node) ([]nir.Stmt, nir.Expr) {
	if n == nil {
		return nil, nil
	}
	switch c.kind(n) {
	case "do":
		return c.doBlock(n)
	case "case":
		target := c.caseTarget()
		return c.caseSwitch(n, c.loc(n), target), nir.Name{ID: target, Loc: c.loc(n)}
	case "let_in":
		return c.decls(c.field(n, "binds"), false), c.expr(c.field(n, "expression"))
	}
	return nil, c.expr(n)
}

// bodyStmts lowers the expression that carries a body's value. The shapes with
// bindings of their own — `do`, `let … in` and `case` — contribute those bindings
// as statements, and their value becomes the last statement rather than a second
// evaluation of the same expression.
func (c *hsConv) bodyStmts(n *tree_sitter.Node, returns bool) []nir.Stmt {
	if n == nil {
		return nil
	}
	wrap := func(v nir.Expr) nir.Stmt {
		if returns {
			return nir.Return{Value: v}
		}
		return nir.ExprStmt{Value: v}
	}
	switch c.kind(n) {
	case "do":
		sts, val := c.doBlock(n)
		if val != nil && len(sts) > 0 {
			if es, ok := sts[len(sts)-1].(nir.ExprStmt); ok {
				sts[len(sts)-1] = wrap(es.Value)
				return sts
			}
		}
		return sts
	case "let_in":
		out := c.decls(c.field(n, "binds"), false)
		return append(out, wrap(c.expr(c.field(n, "expression"))))
	case "case":
		target := c.caseTarget()
		out := c.caseSwitch(n, c.loc(n), target)
		return append(out, wrap(nir.Name{ID: target, Loc: c.loc(n)}))
	}
	return []nir.Stmt{wrap(c.expr(n))}
}

// doBlock lowers the statements of a `do` block and reports the block's own
// value: the expression of its last statement, if that statement has one.
func (c *hsConv) doBlock(n *tree_sitter.Node) ([]nir.Stmt, nir.Expr) {
	var out []nir.Stmt
	var val nir.Expr
	for _, ch := range c.namedChildren(n) {
		switch c.kind(ch) {
		case "let":
			out = append(out, c.decls(c.field(ch, "binds"), false)...)
		case "bind":
			out = append(out, c.monadBind(ch)...)
		case "exp":
			sts := c.stmt(ch)
			if len(sts) > 0 {
				if es, ok := sts[len(sts)-1].(nir.ExprStmt); ok {
					val = es.Value
				}
			}
			out = append(out, sts...)
		}
	}
	return out, val
}

// monadBind lowers `pat <- expr`, whose pattern's variables take the expression's
// value. A pattern that binds nothing still carries the expression's taint.
func (c *hsConv) monadBind(n *tree_sitter.Node) []nir.Stmt {
	v := c.expr(c.field(n, "expression"))
	names := c.patternNames(c.field(n, "pattern"))
	if len(names) == 0 {
		return []nir.Stmt{nir.ExprStmt{Value: v}}
	}
	return []nir.Stmt{nir.Assign{Targets: names, Value: v, Loc: c.loc(n)}}
}

// stmt lowers one statement of a do block.
func (c *hsConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	switch c.kind(n) {
	case "exp":
		if inner := c.firstNamed(n); inner != nil {
			return c.stmt(inner)
		}
	case "let":
		return c.decls(c.field(n, "binds"), false)
	case "let_in":
		out := c.decls(c.field(n, "binds"), false)
		return append(out, nir.ExprStmt{Value: c.expr(c.field(n, "expression"))})
	case "bind":
		return c.monadBind(n)
	case "conditional":
		it := nir.If{Cond: c.expr(c.field(n, "if")), Loc: L}
		it.Then = armStmts(c.expr(c.field(n, "then")))
		if e := c.field(n, "else"); e != nil {
			it.Else = armStmts(c.expr(e))
		}
		return []nir.Stmt{it}
	case "case":
		return c.caseSwitch(n, L, "")
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

func armStmts(v nir.Expr) []nir.Stmt { return []nir.Stmt{nir.ExprStmt{Value: v}} }

// caseSwitch lowers `case s of …` to a subject+arm Switch, so each arm is its own
// control region and a constant subject prunes the arms it cannot match. When
// target is non-empty each arm's value is assigned to it, which is what makes the
// case evaluate to something at its call site; when it is empty the case is a
// statement and only its effects remain. The subject is bound to a synthetic
// local first so every arm binds the names ITS pattern destructures without
// re-lowering the subject; without that, an arm body reads an identifier bound to
// nothing and the subject's taint stops at the case. A variable or wildcard
// pattern matches everything, so it is the default.
func (c *hsConv) caseSwitch(n *tree_sitter.Node, L string, target string) []nir.Stmt {
	subject := nir.Expr(nir.Const{Loc: L})
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) != "alternatives" {
			subject = c.expr(ch)
			break
		}
	}
	name := c.caseTarget()
	sw := nir.Switch{Loc: L, Subject: nir.Name{ID: name, Loc: L}}
	for _, alt := range c.alternatives(n) {
		pat := orSelf(c.field(alt, "pattern"), c.field(alt, "patterns"))
		arm := c.patternBinding(pat, name, L)
		sts, val := c.armBody(c.field(c.field(alt, "match"), "expression"))
		arm = append(arm, sts...)
		if val != nil {
			if target == "" {
				arm = append(arm, nir.ExprStmt{Value: val})
			} else {
				arm = append(arm, nir.Assign{Targets: []string{target}, Value: val, Loc: c.loc(alt)})
			}
		}
		arm = append(arm, c.decls(c.field(alt, "binds"), false)...)
		if pat == nil || c.isCatchAll(pat) {
			sw.Default = append(sw.Default, arm...)
			continue
		}
		sw.Cases = append(sw.Cases, arm)
		sw.Labels = append(sw.Labels, []nir.Expr{c.expr(pat)})
	}
	return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: subject, Decl: true, Loc: L}, sw}
}

// caseTarget names a synthetic local: the one a case's subject is bound to, and
// the one a value-position case assigns its arms' values to.
func (c *hsConv) caseTarget() string {
	c.cases++
	return "__vyql_case" + itoa(c.cases)
}

// patternBinding binds every name a case arm's pattern destructures to the value
// the case matched on.
func (c *hsConv) patternBinding(pat *tree_sitter.Node, subject, loc string) []nir.Stmt {
	names := c.patternNames(pat)
	if len(names) == 0 {
		return nil
	}
	return []nir.Stmt{nir.Assign{Targets: names, Value: nir.Name{ID: subject, Loc: loc}, Decl: true, Loc: loc}}
}

// alternatives lists the `alternative` arms of a case expression.
func (c *hsConv) alternatives(n *tree_sitter.Node) []*tree_sitter.Node {
	var out []*tree_sitter.Node
	for _, ch := range c.namedChildren(n) {
		if c.kind(ch) == "alternatives" {
			for _, alt := range c.namedChildren(ch) {
				if c.kind(alt) == "alternative" {
					out = append(out, alt)
				}
			}
		}
	}
	return out
}

// isCatchAll reports whether a pattern matches every value: a wildcard, or a
// variable, which the arm binds and so cannot reject anything.
func (c *hsConv) isCatchAll(pat *tree_sitter.Node) bool {
	switch c.kind(pat) {
	case "wildcard", "variable":
		return true
	}
	return false
}

// patternNames lists the variables a pattern binds, in source order. The node a
// field hands over is sometimes the variable itself and sometimes the `patterns`
// group around several, so the walk starts at the node. A field name binds
// nothing (`{ path = p }` binds p), a literal or constructor pattern pins a
// value, and a wildcard binds the conventional `_`.
func (c *hsConv) patternNames(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	var walk func(m *tree_sitter.Node)
	walk = func(m *tree_sitter.Node) {
		switch c.kind(m) {
		case "variable":
			out = append(out, c.text(m))
			return
		case "wildcard":
			out = append(out, "_")
			return
		case "field_name":
			return
		}
		for _, ch := range c.namedChildren(m) {
			walk(ch)
		}
	}
	walk(n)
	return out
}

func (c *hsConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch c.kind(n) {
	case "exp", "literal", "boolean", "parens":
		// wrappers: statement position, a literal value, the grammar's node for
		// anything in boolean position, and grouping.
		if inner := c.firstNamed(n); inner != nil {
			return c.expr(inner)
		}
		return nir.Const{Loc: L}
	case "variable", "constructor", "name", "operator", "constructor_operator", "module_id", "implicit_variable":
		return nir.Name{ID: c.text(n), Loc: L}
	case "qualified":
		return c.qualified(n, L)
	case "apply":
		return c.apply(n, L)
	case "infix":
		return c.infix(n, L)
	case "string", "char", "integer", "float", "unit":
		// literal text is carried for value-matched sinks and constant folding
		return nir.Const{Loc: L, Value: c.text(n)}
	case "list", "tuple", "arithmetic_sequence":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "lambda":
		return nir.Lambda{Params: c.patternNames(c.field(n, "patterns")), Body: c.definitionBody(c.field(n, "expression")), Loc: L}
	case "do":
		sts, _ := c.doBlock(n)
		return nir.Seq{Parts: stmtValues(sts), Loc: L}
	case "let_in":
		parts := stmtValues(c.decls(c.field(n, "binds"), false))
		return nir.Seq{Parts: append(parts, c.expr(c.field(n, "expression"))), Loc: L}
	case "conditional":
		t := nir.Ternary{Cond: c.expr(c.field(n, "if")), Then: c.expr(c.field(n, "then")), Else: nir.Const{Loc: L}, Loc: L}
		if e := c.field(n, "else"); e != nil {
			t.Else = c.expr(e)
		}
		return t
	case "case":
		// a case in value position contributes every arm's value; which arm runs
		// is not known here, and merging them over-approximates rather than drops
		var parts []nir.Expr
		for _, alt := range c.alternatives(n) {
			if m := c.field(alt, "match"); m != nil {
				parts = append(parts, c.expr(c.field(m, "expression")))
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// stmtValues is the expression each of a statement list's statements evaluates,
// for a value-position context that must keep their side effects and taint.
func stmtValues(sts []nir.Stmt) []nir.Expr {
	var out []nir.Expr
	for _, st := range sts {
		switch s := st.(type) {
		case nir.Assign:
			out = append(out, s.Value)
		case nir.ExprStmt:
			out = append(out, s.Value)
		case nir.Return:
			out = append(out, s.Value)
		}
	}
	return out
}

// qualified lowers `Mod.name`. The module half arrives as its own node whose text
// carries the trailing dot ("T."), so the path is spliced from the two halves.
func (c *hsConv) qualified(n *tree_sitter.Node, L string) nir.Expr {
	mod := strings.TrimSuffix(c.text(c.field(n, "module")), ".")
	id := orSelf(c.field(n, "id"), c.firstNamed(n))
	path := mod + "." + c.text(id)
	if mod == "" {
		path = c.text(id)
	}
	return nir.Attr{Base: nir.Name{ID: mod, Loc: L}, Attr: c.text(id), Path: path, Loc: L}
}

// apply lowers a function application. The grammar nests applications to the
// left, so the head of the chain is the callee and each node after it adds one
// positional argument.
func (c *hsConv) apply(n *tree_sitter.Node, L string) nir.Expr {
	head, args := c.applyParts(n)
	path := c.dotted(head)
	return nir.Call{
		Callee: c.expr(head),
		Args:   args,
		Path:   path,
		Method: lastSeg(path),
		Loc:    L,
		IsCtor: c.isConstructor(head),
	}
}

func (c *hsConv) applyParts(n *tree_sitter.Node) (*tree_sitter.Node, []nir.Expr) {
	fn := c.field(n, "function")
	if c.kind(fn) == "apply" {
		head, args := c.applyParts(fn)
		return head, append(args, c.expr(c.field(n, "argument")))
	}
	return orSelf(fn, n), []nir.Expr{c.expr(c.field(n, "argument"))}
}

// isConstructor reports whether a callee names a data constructor, whose result
// contains its arguments (`Just tainted`, `Cfg path`).
func (c *hsConv) isConstructor(n *tree_sitter.Node) bool {
	switch c.kind(n) {
	case "constructor":
		return true
	case "qualified":
		return c.kind(c.field(n, "id")) == "constructor"
	}
	return false
}

// infix lowers an operator application. `$` is application, so the right operand
// becomes the call's argument and the left one its callee — the shape the graph
// gives every other language's call. `++` and `<>` are the textual appends and
// lower to the same string build a `+` is elsewhere, which keeps a query built by
// concatenation reading as a dynamic string rather than an opaque value; `+`
// itself is numeric in Haskell and keeps its operator.
func (c *hsConv) infix(n *tree_sitter.Node, L string) nir.Expr {
	opNode := c.field(n, "operator")
	left := c.expr(c.field(n, "left_operand"))
	right := c.expr(c.field(n, "right_operand"))
	if c.kind(opNode) == "infix_id" {
		// a backticked name: `x `T.append` y` is the call T.append x y
		inner := orSelf(c.firstNamed(opNode), opNode)
		path := c.dotted(inner)
		return nir.Call{Callee: c.expr(inner), Args: []nir.Expr{left, right}, Path: path, Method: lastSeg(path), Loc: L}
	}
	switch op := c.text(opNode); op {
	case "$":
		path := c.dotted(c.field(n, "left_operand"))
		return nir.Call{Callee: left, Args: []nir.Expr{right}, Path: path, Method: lastSeg(path), Loc: L}
	case "++", "<>":
		return nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
	default:
		return nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
	}
}

// dotted is the dotted callee path a binding matches on: a bare name is itself, a
// qualified name keeps its module segment, and an application is its head.
func (c *hsConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch c.kind(n) {
	case "variable", "constructor", "name", "operator", "constructor_operator":
		return c.text(n)
	case "qualified":
		mod := strings.TrimSuffix(c.text(c.field(n, "module")), ".")
		return mod + "." + c.text(c.field(n, "id"))
	case "apply":
		return c.dotted(c.field(n, "function"))
	case "parens", "exp", "literal", "boolean":
		return c.dotted(c.firstNamed(n))
	}
	return "?"
}

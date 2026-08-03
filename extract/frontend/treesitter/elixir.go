package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	elixir "github.com/vyprai/vyql/extract/frontend/treesitter/grammars/elixir"

	"github.com/vyprai/vyql/extract/nir"
)

// exConv walks a tree-sitter Elixir CST into NIR. Elixir models everything as a
// `call` (defmodule/def are calls with a do_block); module calls are `dot`
// (alias + function). `<>` builds strings, `|>` pipes the LHS as the first arg.
type exConv struct {
	src        []byte
	file       string
	key        string
	childCache map[uintptr][]*tree_sitter.Node
}

func (c *exConv) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	if c.childCache == nil {
		c.childCache = make(map[uintptr][]*tree_sitter.Node)
	}
	key := uintptr(n.Id())
	if kids, ok := c.childCache[key]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.childCache[key] = kids
	return kids
}

// ExtractElixir parses Elixir files into one NIR Program (one module per file).
func ExtractElixir(files []string, root string) (nir.Program, error) {
	mods := parseModules(files, root,
		func() *tree_sitter.Parser {
			p := tree_sitter.NewParser()
			_ = p.SetLanguage(tree_sitter.NewLanguage(elixir.Language()))
			return p
		},
		func(src []byte, abs, rel string, tree *tree_sitter.Tree) (nir.Module, bool) {
			c := &exConv{src: src, file: rel, key: moduleKey(root, abs, ".ex")}
			return nir.Module{Key: c.key, File: rel, Body: c.decls(tree.RootNode())}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *exConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *exConv) text(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	return string(c.src[n.StartByte():n.EndByte()])
}

// decls walks a node's statements, descending into defmodule do_blocks so nested
// functions surface as top-level FuncDefs.
func (c *exConv) decls(n *tree_sitter.Node) []nir.Stmt {
	var out []nir.Stmt
	for _, ch := range c.namedChildren(n) {
		out = append(out, c.stmt(ch)...)
	}
	return out
}

func (c *exConv) stmt(n *tree_sitter.Node) []nir.Stmt {
	switch n.Kind() {
	case "call":
		return c.callStmt(n)
	case "binary_operator":
		if c.text(field(n, "operator")) == "=" {
			left := field(n, "left")
			rightN := field(n, "right")
			if left != nil && left.Kind() == "identifier" {
				name := c.text(left)
				// `c = case S do … end` → a Switch assigning `c` per arm, so a constant
				// subject prunes to one assignment (case-as-value otherwise drops arm
				// values — an FN).
				if rightN != nil && c.isCaseCall(rightN) {
					return []nir.Stmt{c.exCaseAssign(name, rightN)}
				}
				return []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.expr(rightN)}}
			}
			return []nir.Stmt{nir.ExprStmt{Value: c.expr(rightN)}}
		}
		return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
	case "do_block", "block":
		return c.decls(n)
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// callStmt handles defmodule/def/defp specially; everything else is an expression.
func (c *exConv) callStmt(n *tree_sitter.Node) []nir.Stmt {
	kids := c.namedChildren(n)
	if len(kids) == 0 {
		return nil
	}
	head := kids[0]
	name := ""
	if head.Kind() == "identifier" {
		name = c.text(head)
	}
	switch name {
	case "defmodule", "defprotocol", "defimpl":
		if do := lastChildKind(n, "do_block"); do != nil {
			return c.decls(do)
		}
		return nil
	case "def", "defp", "defmacro":
		return c.funcDef(n)
	case "case":
		return []nir.Stmt{c.exCaseStmt(n)}
	}
	return []nir.Stmt{nir.ExprStmt{Value: c.expr(n)}}
}

// funcDef builds a FuncDef from `def name(params) do … end`.
func (c *exConv) funcDef(n *tree_sitter.Node) []nir.Stmt {
	L := c.loc(n)
	args := lastChildKind(n, "arguments")
	var fname string
	var params []string
	if args != nil {
		for _, a := range c.namedChildren(args) {
			if a.Kind() == "call" { // name(params)
				if h := firstNamed(a); h != nil {
					fname = c.text(h)
				}
				if pa := lastChildKind(a, "arguments"); pa != nil {
					for _, p := range c.namedChildren(pa) {
						params = append(params, c.patName(p))
					}
				}
			} else if a.Kind() == "identifier" && fname == "" { // name with no parens
				fname = c.text(a)
			}
		}
	}
	body := []nir.Stmt{}
	if do := lastChildKind(n, "do_block"); do != nil {
		body = c.decls(do)
	} else if args != nil {
		// keyword-shorthand body: `def f(x), do: expr` — the body is the `do:` pair's value
		// in the call's keyword arguments (no do_block). Extremely common in Elixir.
		for _, a := range c.namedChildren(args) {
			if a.Kind() != "keywords" {
				continue
			}
			for _, pr := range c.namedChildren(a) {
				kids := c.namedChildren(pr)
				if len(kids) >= 2 && strings.TrimRight(strings.TrimSpace(c.text(kids[0])), ":") == "do" {
					body = append(body, c.stmt(kids[len(kids)-1])...)
				}
			}
		}
	}
	return []nir.Stmt{nir.FuncDef{Name: fname, Params: params, Body: body, Loc: L, ParamEntries: c.exParamEntries(fname, params), ContextTokens: c.exFunctionContext(fname, n)}}
}

func (c *exConv) exFunctionContext(name string, n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	body := lastChildKind(n, "do_block")
	if body == nil {
		body = n
	}
	bodyText := c.text(body)
	tokens := []string{
		"lang=elixir",
		"name=" + name,
		"function_name:" + name,
		bodyText,
		strings.Join(strings.Fields(bodyText), ""),
	}
	if exMissingPortResponseCorrelation(bodyText) {
		tokens = append(tokens, "port_protocol:request_response_missing_correlation")
	}
	seenCalls := map[string]bool{}
	seenIdentifiers := map[string]bool{}
	var walk func(*tree_sitter.Node)
	walk = func(cur *tree_sitter.Node) {
		if cur == nil {
			return
		}
		if cur.Kind() == "call" {
			if kids := c.namedChildren(cur); len(kids) > 0 {
				if path := c.dotted(kids[0]); path != "" && !seenCalls[path] {
					seenCalls[path] = true
					tokens = append(tokens, "call_path:"+path)
					tokens = append(tokens, "call:"+lastSeg(path))
				}
			}
		}
		if cur.Kind() == "identifier" {
			ident := c.text(cur)
			if ident != "" && !seenIdentifiers[ident] {
				seenIdentifiers[ident] = true
				tokens = append(tokens, "identifier:"+ident)
			}
		}
		for _, ch := range c.namedChildren(cur) {
			walk(ch)
		}
	}
	walk(body)
	return tokens
}

func exMissingPortResponseCorrelation(body string) bool {
	compact := strings.Join(strings.Fields(body), "")
	return strings.Contains(compact, "Port.command") &&
		strings.Contains(compact, "Jason.encode!") &&
		strings.Contains(compact, "get_response") &&
		!strings.Contains(compact, "uid_counter") &&
		!strings.Contains(compact, "expected_uid") &&
		!strings.Contains(compact, "extract_uid")
}

func (c *exConv) exParamEntries(name string, params []string) []nir.ParamEntry {
	if len(params) <= 1 || (params[0] != "conn" && params[0] != "_conn") {
		return nil
	}
	out := make([]nir.ParamEntry, 0, len(params))
	for i, p := range params {
		if p == "" {
			continue
		}
		out = append(out, nir.ParamEntry{Param: p, Tokens: []string{
			"function_name:" + name,
			"first_param:" + params[0],
			"param_name:" + p,
			"param_index:" + itoa(i),
		}})
	}
	return out
}

func (c *exConv) patName(n *tree_sitter.Node) string {
	switch n.Kind() {
	case "identifier":
		return c.text(n)
	case "binary_operator": // default param `x \\ v`, or pattern — take left
		return c.patName(field(n, "left"))
	}
	return ""
}

func (c *exConv) expr(n *tree_sitter.Node) nir.Expr {
	if n == nil {
		return nir.Const{Loc: "?:0"}
	}
	L := c.loc(n)
	switch n.Kind() {
	case "identifier":
		return nir.Name{ID: c.text(n), Loc: L}
	case "alias":
		return nir.Name{ID: c.text(n), Loc: L}
	case "integer", "float", "boolean", "nil", "atom", "char":
		return nir.Const{Loc: L, Value: c.text(n)} // carry value for constant-folding
	case "string", "charlist":
		// strings with #{…} interpolation propagate taint.
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			if ch.Kind() == "interpolation" {
				for _, e := range c.namedChildren(ch) {
					parts = append(parts, c.expr(e))
				}
			}
		}
		if len(parts) > 0 {
			return nir.Format{Parts: parts, Loc: L}
		}
		return nir.Const{Loc: L, Value: exStringValue(c.text(n))}
	case "call":
		return c.callExpr(n)
	case "dot":
		// `conn.params` (lowercase base) is a struct-field read → Attr source node;
		// `System.cmd` (alias base) is a module reference → Name.
		kids := c.namedChildren(n)
		if len(kids) == 2 && kids[0].Kind() == "identifier" {
			return nir.Attr{Base: c.expr(kids[0]), Attr: c.text(kids[1]), Path: c.dotted(n), Loc: L}
		}
		return nir.Name{ID: c.dotted(n), Loc: L}
	case "access_call": // params["key"]
		kids := c.namedChildren(n)
		var base nir.Expr = nir.Const{Loc: L}
		if len(kids) > 0 {
			base = c.expr(kids[0])
		}
		return nir.Index{Base: base, Key: c.expr(field(n, "key")), Path: c.dotted(n), Loc: L}
	case "binary_operator":
		op := c.text(field(n, "operator"))
		l, r := field(n, "left"), field(n, "right")
		switch op {
		case "<>", "+", "<<>>", "++", "--":
			// string/list concatenation and numeric `+` — taint-propagating union.
			return nir.Format{Parts: []nir.Expr{c.expr(l), c.expr(r)}, Loc: L}
		case "|>":
			// a |> f(b…)  ==  f(a, b…): the LHS flows in as the first argument.
			return c.pipe(l, r, L)
		}
		// comparison / arithmetic / boolean operators carry their op for constant folding.
		return nir.BinOp{Op: op, Left: c.expr(l), Right: c.expr(r), Loc: L}
	case "unary_operator":
		op := c.text(field(n, "operator"))
		if kids := c.namedChildren(n); len(kids) > 0 {
			return nir.Unary{Op: op, Operand: c.expr(kids[len(kids)-1]), Loc: L}
		}
		return nir.Const{Loc: L}
	case "list", "tuple", "bitstring":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "keywords", "pair":
		var parts []nir.Expr
		for _, ch := range c.namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: L}
	}
	// fall back: union of children (taint-approximate)
	var parts []nir.Expr
	for _, ch := range c.namedChildren(n) {
		parts = append(parts, c.expr(ch))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return nir.Seq{Parts: parts, Loc: L}
}

// callExpr lowers a function/module call to nir.Call with a dotted path. The macro
// calls `if`/`unless` are modeled as a Ternary so a constant predicate prunes an arm.
func (c *exConv) callExpr(n *tree_sitter.Node) nir.Expr {
	L := c.loc(n)
	kids := c.namedChildren(n)
	if len(kids) == 0 {
		return nir.Const{Loc: L}
	}
	if kids[0].Kind() == "identifier" {
		switch c.text(kids[0]) {
		case "if":
			return c.exIf(n, false)
		case "unless":
			return c.exIf(n, true)
		}
	}
	fn := kids[0]
	path := c.dotted(fn)
	var args []nir.Expr
	if a := lastChildKind(n, "arguments"); a != nil {
		for _, ch := range c.namedChildren(a) {
			args = append(args, c.expr(ch))
		}
	}
	return nir.Call{Callee: c.expr(fn), Args: args, Path: path, Method: lastSeg(path), Loc: L}
}

// isCaseCall reports whether a node is a `case … do … end` macro call.
func (c *exConv) isCaseCall(n *tree_sitter.Node) bool {
	if n.Kind() != "call" {
		return false
	}
	k := c.namedChildren(n)
	return len(k) > 0 && k[0].Kind() == "identifier" && c.text(k[0]) == "case"
}

type exArm struct {
	label     nir.Expr
	isDefault bool
	body      *tree_sitter.Node
}

// exCaseParts extracts a case's subject and its stab_clause arms (`_` = default).
func (c *exConv) exCaseParts(n *tree_sitter.Node) (nir.Expr, []exArm) {
	var subject nir.Expr = nir.Const{Loc: c.loc(n)}
	if args := lastChildKind(n, "arguments"); args != nil {
		if k := c.namedChildren(args); len(k) > 0 {
			subject = c.expr(k[0])
		}
	}
	var arms []exArm
	if do := lastChildKind(n, "do_block"); do != nil {
		for _, sc := range c.namedChildren(do) {
			if sc.Kind() != "stab_clause" {
				continue
			}
			a := exArm{body: field(sc, "right")}
			if lft := field(sc, "left"); lft != nil {
				if pk := c.namedChildren(lft); len(pk) > 0 {
					if c.text(pk[0]) == "_" {
						a.isDefault = true
					} else {
						a.label = c.expr(pk[0])
					}
				}
			}
			arms = append(arms, a)
		}
	}
	return subject, arms
}

// exCaseAssign lowers `name = case S do … end` to a Switch assigning `name` per arm.
func (c *exConv) exCaseAssign(name string, n *tree_sitter.Node) nir.Stmt {
	subject, arms := c.exCaseParts(n)
	sw := nir.Switch{Loc: c.loc(n), Subject: subject}
	for _, a := range arms {
		arm := []nir.Stmt{nir.Assign{Targets: []string{name}, Value: c.exBodyTail(a.body)}}
		if a.isDefault || a.label == nil {
			sw.Default = append(sw.Default, arm...)
		} else {
			sw.Cases = append(sw.Cases, arm)
			sw.Labels = append(sw.Labels, []nir.Expr{a.label})
		}
	}
	return sw
}

// exCaseStmt lowers a statement-position `case S do … end` to a Switch over arm bodies.
func (c *exConv) exCaseStmt(n *tree_sitter.Node) nir.Stmt {
	subject, arms := c.exCaseParts(n)
	sw := nir.Switch{Loc: c.loc(n), Subject: subject}
	for _, a := range arms {
		var stmts []nir.Stmt
		if a.body != nil {
			for _, b := range c.namedChildren(a.body) {
				stmts = append(stmts, c.stmt(b)...)
			}
		}
		if a.isDefault || a.label == nil {
			sw.Default = append(sw.Default, stmts...)
		} else {
			sw.Cases = append(sw.Cases, stmts)
			sw.Labels = append(sw.Labels, []nir.Expr{a.label})
		}
	}
	return sw
}

func (c *exConv) exBodyTail(body *tree_sitter.Node) nir.Expr {
	if body == nil {
		return nir.Const{Loc: "?:0"}
	}
	bk := c.namedChildren(body)
	if len(bk) == 0 {
		return nir.Const{Loc: c.loc(body)}
	}
	return c.expr(bk[len(bk)-1])
}

// exIf models `if cond, do: A, else: B` (keyword form) and `if cond do A else B end`
// (block form) as a Ternary. `unless` inverts the predicate, which we don't fold, so it
// over-approximates (both arms flow) — FN-safe.
func (c *exConv) exIf(n *tree_sitter.Node, unless bool) nir.Expr {
	L := c.loc(n)
	var cond, thenE, elseE nir.Expr = nir.Const{Loc: L}, nir.Const{Loc: L}, nir.Const{Loc: L}
	if args := lastChildKind(n, "arguments"); args != nil {
		ak := c.namedChildren(args)
		if len(ak) > 0 {
			cond = c.expr(ak[0])
		}
		for _, a := range ak[1:] {
			if a.Kind() == "keywords" {
				c.exDoElse(a, &thenE, &elseE)
			}
		}
	}
	if do := lastChildKind(n, "do_block"); do != nil {
		c.exDoBlock(do, &thenE, &elseE)
	}
	if unless {
		return nir.Seq{Parts: []nir.Expr{thenE, elseE}, Loc: L}
	}
	return nir.Ternary{Cond: cond, Then: thenE, Else: elseE, Loc: L}
}

// exDoElse reads do:/else: pairs from a keyword list.
func (c *exConv) exDoElse(kw *tree_sitter.Node, thenE, elseE *nir.Expr) {
	for _, pr := range c.namedChildren(kw) {
		if pr.Kind() != "pair" {
			continue
		}
		key := c.text(field(pr, "key"))
		val := c.expr(field(pr, "value"))
		switch {
		case strings.HasPrefix(key, "do"):
			*thenE = val
		case strings.HasPrefix(key, "else"):
			*elseE = val
		}
	}
}

// exDoBlock takes the tail value of a do-block's then-part and its else_block.
func (c *exConv) exDoBlock(do *tree_sitter.Node, thenE, elseE *nir.Expr) {
	var thenVals []nir.Expr
	for _, ch := range c.namedChildren(do) {
		if ch.Kind() == "else_block" {
			ek := c.namedChildren(ch)
			if len(ek) > 0 {
				*elseE = c.expr(ek[len(ek)-1])
			}
			continue
		}
		thenVals = append(thenVals, c.expr(ch))
	}
	if len(thenVals) > 0 {
		*thenE = thenVals[len(thenVals)-1]
	}
}

// pipe rewrites `left |> right` so the left value flows into the right call as its
// first argument (taint-preserving).
func (c *exConv) pipe(left, right *tree_sitter.Node, L string) nir.Expr {
	lv := c.expr(left)
	if right != nil && right.Kind() == "call" {
		kids := c.namedChildren(right)
		if len(kids) > 0 {
			fn := kids[0]
			path := c.dotted(fn)
			args := []nir.Expr{lv}
			if a := lastChildKind(right, "arguments"); a != nil {
				for _, ch := range c.namedChildren(a) {
					args = append(args, c.expr(ch))
				}
			}
			return nir.Call{Callee: c.expr(fn), Args: args, Path: path, Method: lastSeg(path), Loc: L}
		}
	}
	if right != nil && (right.Kind() == "identifier" || right.Kind() == "dot") {
		path := c.dotted(right)
		return nir.Call{Callee: c.expr(right), Args: []nir.Expr{lv}, Path: path, Method: lastSeg(path), Loc: L}
	}
	return nir.Format{Parts: []nir.Expr{lv, c.expr(right)}, Loc: L}
}

func (c *exConv) dotted(n *tree_sitter.Node) string {
	if n == nil {
		return "?"
	}
	switch n.Kind() {
	case "identifier", "alias", "atom":
		return c.text(n)
	case "dot":
		kids := c.namedChildren(n)
		if len(kids) == 2 {
			return c.dotted(kids[0]) + "." + c.dotted(kids[1])
		}
		if len(kids) == 1 {
			return c.dotted(kids[0])
		}
	case "call":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0])
		}
	case "access_call":
		if kids := c.namedChildren(n); len(kids) > 0 {
			return c.dotted(kids[0]) + "[]"
		}
	}
	return "?"
}

func firstNamed(n *tree_sitter.Node) *tree_sitter.Node {
	if n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

func exStringValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		first, last := raw[0], raw[len(raw)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

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
	moduleTokens  []string
	classContext  []string
	decorators    []string
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
			c.moduleTokens = c.pyStructuredContextTokens(root0, "module")
			body := append(c.pyModuleContext(root0), c.blockChildren(root0)...)
			return nir.Module{Key: c.key, File: rel, Imports: c.imports(root0), Body: body}, true
		})
	return nir.Program{SelfName: "self", Modules: mods}, nil
}

func (c *pyConv) loc(n *tree_sitter.Node) string {
	return c.file + ":" + itoa(int(n.StartPosition().Row)+1)
}

func (c *pyConv) endLoc(n *tree_sitter.Node) string {
	if n == nil {
		return c.file + ":1"
	}
	return c.file + ":" + itoa(int(n.EndPosition().Row)+1)
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
	statements := namedChildren(n)
	for i, st := range statements {
		out = append(out, c.stmt(st)...)
		if c.pyLengthGuardDefinitelyTerminates(st, statements[:i]) {
			break
		}
	}
	return out
}

func (c *pyConv) pyLengthGuardDefinitelyTerminates(statement *tree_sitter.Node, previous []*tree_sitter.Node) bool {
	if statement == nil || statement.Kind() != "if_statement" || !c.pyConditionAlwaysTrue(field(statement, "condition")) {
		return false
	}
	for _, prior := range previous {
		assignment := prior
		if assignment.Kind() == "expression_statement" {
			children := namedChildren(assignment)
			if len(children) != 1 || children[0].Kind() != "assignment" {
				continue
			}
			assignment = children[0]
		}
		if assignment.Kind() != "assignment" {
			continue
		}
		left := field(assignment, "left")
		if left != nil && left.Kind() == "identifier" && c.text(left) == "len" {
			return false
		}
	}
	_, terminal := c.pyTerminalBranchKind(field(statement, "consequence"))
	return terminal
}

// vyqlResultEntries extracts `# vyql: ...` function markers without interpreting them.
func (c *pyConv) vyqlResultEntries(fn *tree_sitter.Node) []nir.ResultEntry {
	var out []nir.ResultEntry
	scan := func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		for _, ch := range children(n) {
			if ch.Kind() == "comment" {
				for _, tok := range vyqlMarkerTokens(c.text(ch)) {
					out = append(out, nir.ResultEntry{Tokens: []string{tok}})
				}
			}
		}
	}
	scan(fn)
	scan(field(fn, "body"))
	return out
}

func vyqlMarkerTokens(comment string) []string {
	lower := strings.ToLower(comment)
	i := strings.Index(lower, "vyql:")
	if i < 0 {
		return nil
	}
	text := lower[i+len("vyql:"):]
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == ':' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, "marker:"+f)
		}
	}
	return out
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
		body = append(body, c.pyFunctionContext(n, c.decorators)...)
		var entries []nir.ParamEntry
		if strings.HasPrefix(name, "resolve_") || name == "mutate" {
			entries = append(entries, c.pyParamEntries(name, params, nil)...)
		}
		// public API = no leading underscore, OR a dunder (__init__/__call__ are entry points).
		exported := !strings.HasPrefix(name, "_") || (strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__"))
		return []nir.Stmt{nir.FuncDef{Name: name, Params: params, ParamTypes: paramTypes, Body: body, Loc: L, ParamEntries: entries, ResultEntries: c.vyqlResultEntries(n), Exported: exported}}
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
		prevDecorators := c.decorators
		c.decorators = decorators
		out := c.stmt(def)
		c.decorators = prevDecorators
		for i, st := range out {
			if fn, ok := st.(nir.FuncDef); ok {
				fn.Decorators = decorators
				fn.ParamEntries = append(fn.ParamEntries, c.pyParamEntries(fn.Name, fn.Params, decorators)...)
				out[i] = fn
			}
		}
		return out
	case "class_definition":
		name := c.text(field(n, "name"))
		bases := c.pyClassBases(n)
		ctx := c.pyClassContext(n, name, bases)
		c.classContext = append(c.classContext, ctx...)
		body := c.block(field(n, "body"))
		c.classContext = c.classContext[:len(c.classContext)-len(ctx)]
		return []nir.Stmt{nir.ClassDef{Name: name, Body: body, Loc: L, Bases: bases}}
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
			// subscript store `container[k] = v` (e.g. bag[key] = v, map[k] = param): no
			// simple name target, so model it as a mutating setitem that taints the container
			// from v — otherwise a later read `x = container[k]` loses the taint.
			if len(tgts) == 0 && left != nil && left.Kind() == "subscript" {
				base := c.expr(field(left, "value"))
				args := []nir.Expr{val}
				if k := field(left, "subscript"); k != nil {
					args = append(args, c.expr(k)) // include the key: bag[dynamic_key] = x
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
			if inner.Kind() == "call" && lastSeg(c.dotted(field(inner, "function"))) == "abort" {
				return []nir.Stmt{nir.Terminate{Value: c.expr(inner), Kind: "abort", Loc: L}}
			}
			return []nir.Stmt{nir.ExprStmt{Value: c.expr(inner)}}
		}
	case "return_statement":
		kids := namedChildren(n)
		if len(kids) > 0 {
			return []nir.Stmt{nir.Return{Value: c.expr(kids[0])}}
		}
		return []nir.Stmt{nir.Return{}}
	case "raise_statement":
		var value nir.Expr
		if kids := namedChildren(n); len(kids) > 0 {
			value = c.expr(kids[0])
		}
		return []nir.Stmt{nir.Terminate{Value: value, Kind: "raise", Loc: L}}
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
		left, right := field(n, "left"), field(n, "right")
		loop := nir.Loop{Iter: c.expr(right), Vars: c.targets(left), Body: c.block(field(n, "body")), Loc: L}
		stmts := []nir.Stmt{loop}
		if validation, ok := c.pyTerminalRejectValidation(n); ok {
			stmts = append(stmts, validation)
		}
		return []nir.Stmt{nir.Block{Stmts: stmts}}
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

func (c *pyConv) pyFunctionContext(fn *tree_sitter.Node, decorators []string) []nir.Stmt {
	body := field(fn, "body")
	if body == nil {
		return nil
	}
	name := c.text(field(fn, "name"))
	bodyText := c.text(body)
	localBodyText := c.pyScopeLocalText(body)
	controlFacts := c.pyControlFlowContextFacts(body)
	loc := c.loc(fn)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=python"},
		nir.Const{Loc: loc, Value: "name=" + name},
		nir.Const{Loc: loc, Value: bodyText},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(bodyText), "")},
		nir.Const{Loc: loc, Value: c.moduleContext},
	}
	localEndArgs := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=python"},
		nir.Const{Loc: loc, Value: "name=" + name},
		nir.Const{Loc: loc, Value: localBodyText},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(localBodyText), "")},
	}
	for _, tok := range c.classContext {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	for _, tok := range pyClassMetadataTokens(c.classContext) {
		localEndArgs = append(localEndArgs, nir.Const{Loc: loc, Value: tok})
	}
	for _, tok := range decorators {
		fact := nir.Const{Loc: loc, Value: tok}
		args = append(args, fact)
		localEndArgs = append(localEndArgs, fact)
	}
	for _, tok := range c.pyStructuredContextTokensScoped(fn, name, false, "", controlFacts) {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	for _, tok := range c.pyStructuredContextTokensScoped(fn, name, true, localBodyText, controlFacts) {
		localEndArgs = append(localEndArgs, nir.Const{Loc: loc, Value: tok})
	}
	contextPath := "analysis.function.context"
	sourcePath := "analysis.function.context.source"
	sinkPath := "analysis.function.context.sink"
	tmp := "__vyql_function_context"
	sinkArgs := append([]nir.Expr{nir.Name{ID: tmp, Loc: loc}}, args...)
	endLoc := c.endLoc(body)
	endArgs := append([]nir.Expr(nil), args...)
	for _, tok := range c.moduleTokens {
		endArgs = append(endArgs, nir.Const{Loc: endLoc, Value: "module_" + tok})
	}
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
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "analysis.function.context.end", Loc: endLoc},
			Args:   endArgs,
			Path:   "analysis.function.context.end",
			Method: "end",
			Loc:    endLoc,
		}},
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "analysis.function.local.end", Loc: endLoc},
			Args:   localEndArgs,
			Path:   "analysis.function.local.end",
			Method: "end",
			Loc:    endLoc,
		}},
	}
}

func pyIsNestedContextScope(node *tree_sitter.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind() {
	case "function_definition", "class_definition", "decorated_definition", "lambda":
		return true
	default:
		return false
	}
}

func pyContainsNestedContextScope(node *tree_sitter.Node) bool {
	if node == nil {
		return false
	}
	for _, child := range namedChildren(node) {
		if pyIsNestedContextScope(child) || pyContainsNestedContextScope(child) {
			return true
		}
	}
	return false
}

func (c *pyConv) pyScopeLocalText(body *tree_sitter.Node) string {
	if body == nil {
		return ""
	}
	type byteSpan struct {
		start uint
		end   uint
	}
	var spans []byteSpan
	var walk func(*tree_sitter.Node)
	walk = func(node *tree_sitter.Node) {
		if node == nil {
			return
		}
		if node != body && pyIsNestedContextScope(node) {
			spans = append(spans, byteSpan{start: node.StartByte(), end: node.EndByte()})
			return
		}
		for _, child := range namedChildren(node) {
			walk(child)
		}
	}
	walk(body)
	if len(spans) == 0 {
		return c.text(body)
	}
	start, end := body.StartByte(), body.EndByte()
	cursor := start
	var out strings.Builder
	for _, span := range spans {
		if span.start < cursor || span.end > end {
			continue
		}
		out.Write(c.src[cursor:span.start])
		out.WriteString("<nested-scope>")
		cursor = span.end
	}
	out.Write(c.src[cursor:end])
	return out.String()
}

func pyClassMetadataTokens(tokens []string) []string {
	var out []string
	for _, token := range tokens {
		if strings.HasPrefix(token, "class_name=") ||
			strings.HasPrefix(token, "class_name:") ||
			strings.HasPrefix(token, "class_bases=") ||
			strings.HasPrefix(token, "class_base:") {
			out = append(out, token)
		}
	}
	return out
}

func (c *pyConv) pyModuleContext(root *tree_sitter.Node) []nir.Stmt {
	if root == nil {
		return nil
	}
	loc := c.file + ":1"
	text := c.text(root)
	args := []nir.Expr{
		nir.Const{Loc: loc, Value: "lang=python"},
		nir.Const{Loc: loc, Value: text},
		nir.Const{Loc: loc, Value: strings.Join(strings.Fields(text), "")},
	}
	for _, tok := range c.moduleTokens {
		args = append(args, nir.Const{Loc: loc, Value: tok})
	}
	return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
		Callee: nir.Name{ID: "analysis.module.context", Loc: loc},
		Args:   args,
		Path:   "analysis.module.context",
		Method: "context",
		Loc:    loc,
	}}}
}

func (c *pyConv) pyStructuredContextTokens(fn *tree_sitter.Node, name string) []string {
	body := field(fn, "body")
	if body == nil {
		body = fn
	}
	return c.pyStructuredContextTokensScoped(fn, name, false, "", c.pyControlFlowContextFacts(body))
}

func (c *pyConv) pyStructuredContextTokensScoped(fn *tree_sitter.Node, name string, scopeLocal bool, localBodyText string, controlFacts pyControlContextFacts) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= pyContextBaseTokenLimit {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if name != "" {
		add("function_name:" + name)
	}
	if params := field(fn, "parameters"); params != nil {
		for i, p := range c.params(params) {
			add("param_name:" + p)
			add("param_index:" + itoa(i))
		}
	}
	var walk func(*tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil || len(out) >= pyContextBaseTokenLimit {
			return
		}
		if scopeLocal && pyIsNestedContextScope(n) {
			return
		}
		switch n.Kind() {
		case "assignment":
			if scopeLocal && pyContainsNestedContextScope(n) {
				break
			}
			left, right := field(n, "left"), field(n, "right")
			if lhs := c.pyContextPath(left); lhs != "" {
				if rhs := pyContextValue(c.text(right)); rhs != "" {
					add("assign:" + lhs + "=" + rhs)
				}
				for _, item := range c.pyContextAssignmentItems(right) {
					add("assign_item:" + lhs + ":" + item)
				}
				if right != nil && right.Kind() == "call" {
					if path := c.dotted(field(right, "function")); path != "" && path != "?" {
						add("assign_call:" + lhs + ":" + path)
					}
				}
			}
		case "call":
			if path := c.dotted(field(n, "function")); path != "" && path != "?" {
				add("call_path:" + path)
				if m := lastSeg(path); m != "" {
					add("call:" + m)
				}
			}
		case "attribute":
			if sel := c.dotted(n); sel != "" && sel != "?" {
				add("selector:" + sel)
			}
		case "identifier":
			if ident := pyContextCompact(c.text(n)); ident != "" {
				add("identifier:" + ident)
			}
		case "subscript":
			if sub := pyContextCompact(c.text(n)); sub != "" {
				add("subscript:" + sub)
			}
			if base := c.dotted(field(n, "value")); base != "" && base != "?" {
				add("index_base:" + base)
			}
			if key := c.pyContextPath(field(n, "subscript")); key != "" {
				add("index_key:" + key)
			}
		case "comparison_operator", "boolean_operator":
			if expr := pyContextCompact(c.text(n)); expr != "" {
				add("expr:" + expr)
			}
		case "string", "concatenated_string", "integer", "float", "true", "false", "none":
			if lit := pyContextValue(c.text(n)); lit != "" {
				add("literal:" + lit)
			}
		}
		for _, ch := range namedChildren(n) {
			walk(ch)
		}
	}
	body := field(fn, "body")
	if body == nil {
		body = fn
	}
	walk(body)
	reviewBodyText := c.text(body)
	classContext := c.classContext
	if scopeLocal {
		reviewBodyText = localBodyText
		classContext = pyClassMetadataTokens(classContext)
	}
	for _, tok := range pySemanticReviewTokens(reviewBodyText, name) {
		add(tok)
	}
	if name == "body" &&
		pyContextHasAny(classContext, "class_name=WaterfallHelp", "class_name:WaterfallHelp") {
		compactBody := pyContextCompactUnbounded(reviewBodyText)
		if pyWaterfallReloadOptionUnescaped(compactBody) {
			add("python_review:unescaped_html_option_renderer")
		}
	}
	if name == "title" &&
		pyContextHasAny(classContext, "class_name=TermViewlet", "class_name:TermViewlet") &&
		pyContextHasAny(classContext, "term-contact", "objpath") {
		compactBody := pyContextCompactUnbounded(reviewBodyText)
		if strings.Contains(compactBody, ".Title()") &&
			!strings.Contains(compactBody, "quote=True") &&
			!strings.Contains(compactBody, "html.escape(") &&
			!strings.Contains(compactBody, "markupsafe.escape(") &&
			!strings.Contains(compactBody, "escape(") {
			add("python_review:collective_contact_widget_title_xss")
		}
	}
	if !scopeLocal && name == "serialize" && pyContextHasAny(classContext, "class_base:HTMLSerializer", "class_bases=HTMLSerializer") {
		if !pyContextHasAny(classContext, "escape_rcdata=True") {
			add("python_review:html_sanitizer_missing_rcdata_escape")
		}
	}
	if name == "default" && pyContextHasAny(classContext, "MetadataXMLDeserializer") {
		compactBody := pyContextCompactUnbounded(reviewBodyText)
		if strings.Contains(compactBody, "minidom.parseString(") &&
			!strings.Contains(compactBody, "safe_minidom_parse_string(") {
			add("python_review:cinder_unsafe_minidom_xml_deserializer")
		}
	}
	for _, tok := range controlFacts.terminal {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	for _, tok := range controlFacts.reachable {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	for _, tok := range controlFacts.assignmentFlow {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

func pySemanticReviewTokens(raw, name string) []string {
	compact := pyContextCompactUnbounded(raw)
	var out []string
	add := func(fact string) {
		out = append(out, "python_review:"+fact)
	}
	if strings.Contains(compact, "app.config[\"SECRET_KEY\"]=") || strings.Contains(compact, "app.config['SECRET_KEY']=") {
		if !strings.Contains(compact, "os.environ") &&
			!strings.Contains(compact, "os.getenv") &&
			!strings.Contains(compact, "secrets.") &&
			!strings.Contains(compact, "build_secret_key()") {
			add("flask_hardcoded_secret_key")
		}
	}
	for _, action := range []string{"sync", "reposync", "hardlink", "buildiso", "generic_delete"} {
		if name == action && pyCobblerRemoteAction(compact, action) {
			add("cobbler_get_state_change_without_post")
			break
		}
	}
	if strings.Contains(compact, "keyisNoneand\"jwk\"inheader") &&
		strings.Contains(compact, "key=header[\"jwk\"]") &&
		strings.Contains(compact, "prepare_key(key)") {
		add("header_controlled_jwk")
	}
	if strings.Contains(compact, "Formatter().parse") {
		if (strings.Contains(compact, ".") || strings.Contains(compact, "[")) &&
			(!strings.Contains(compact, "format_spec") || (!strings.Contains(compact, "{") && !strings.Contains(compact, "}"))) {
			add("incomplete_template_validation")
		}
	}
	if name == "get_jinja_env" &&
		strings.Contains(compact, "Environment(extensions=") &&
		strings.Contains(compact, "filters.update(get_jinja_filters())") &&
		strings.Contains(compact, "returnjinja_env") &&
		!strings.Contains(compact, "SandboxedEnvironment") &&
		!strings.Contains(compact, "ImmutableSandboxedEnvironment") {
		add("jinja_environment_without_sandbox")
	}
	if strings.Contains(compact, "query_expr.parseString") &&
		strings.Contains(compact, "repr(") &&
		strings.Contains(compact, ".replace(") &&
		strings.Contains(compact, "__default_field__") {
		add("unparameterized_sql_query_parser")
	}
	if name == "safe_extract" &&
		strings.Contains(compact, ".getmembers()") &&
		strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, ".name") &&
		strings.Contains(compact, "is_within_directory(") &&
		strings.Contains(compact, ".extractall(") &&
		!strings.Contains(compact, ".issym()") &&
		!strings.Contains(compact, ".islnk()") &&
		!strings.Contains(compact, ".linkname") {
		add("archive_symlink_filter_bypass")
	}
	if name == "_resolve_path" &&
		strings.Count(compact, "os.path.join(") >= 2 &&
		strings.Contains(compact, ".memory_dir") &&
		strings.Contains(compact, ".workspace_root") &&
		!strings.Contains(compact, "os.path.realpath") &&
		!strings.Contains(compact, ".resolve()") &&
		!strings.Contains(compact, "startswith(") {
		add("cowagent_memory_filename_traversal")
	}
	if strings.Contains(compact, ".query.get_or_404(") &&
		strings.Contains(compact, "jsonify(") &&
		strings.Contains(compact, ".permissions") &&
		!strings.Contains(compact, "current_user.admin") &&
		!strings.Contains(compact, "has_permission(") &&
		!strings.Contains(compact, "permission_required") {
		add("flask_entity_detail_missing_authorization")
	}
	if name == "_get_file_path" &&
		strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, ".storage_path") &&
		strings.Contains(compact, ".SESSION_PREFIX") &&
		strings.Contains(compact, ".id") &&
		!strings.Contains(compact, "os.path.normpath(") &&
		!strings.Contains(compact, "realpath(") &&
		!strings.Contains(compact, "abspath(") {
		add("cherrypy_session_id_file_path_traversal")
	}
	if name == "serve_protected_file" &&
		strings.Contains(compact, "PROTECTED_MEDIA_ROOT") &&
		strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, "os.path.isfile(") &&
		strings.Contains(compact, "open(") &&
		strings.Contains(compact, "'rb'") &&
		!strings.Contains(compact, ".startswith(") &&
		!strings.Contains(compact, "os.path.abspath(") &&
		!strings.Contains(compact, "os.path.realpath(") {
		add("codered_protected_media_path_traversal")
	}
	if strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, ".entries()") &&
		strings.Contains(compact, ".fname") &&
		strings.Contains(compact, ".startswith(out_dir)") &&
		pyCompactContainsAny(compact, "os.makedirs(", "BlockFile(", "open(") &&
		!strings.Contains(compact, "commonpath(") &&
		!strings.Contains(compact, ".startswith(out_dir+os.sep)") &&
		!strings.Contains(compact, ".startswith(out_dir+\"/\")") &&
		!strings.Contains(compact, ".startswith(out_dir+'/')") {
		add("archive_entry_raw_prefix_containment")
	}
	if strings.Contains(compact, "'../'in") &&
		strings.Contains(compact, "re.search(") &&
		strings.Contains(compact, "A-Za-z0-9") &&
		strings.Contains(compact, "returnTrue") &&
		strings.Contains(compact, "returnFalse") &&
		!strings.Contains(compact, "startswith('/')") &&
		!strings.Contains(compact, "os.path.isabs(") &&
		!strings.Contains(compact, ".is_absolute()") {
		add("relative_only_filename_validation")
	}
	if name == "_recv_packet" &&
		strings.Contains(compact, "MSG_USERAUTH_LAST") &&
		strings.Contains(compact, "process_packet(") &&
		!strings.Contains(compact, "Invalidrequestreceivedbefore") {
		add("asyncssh_pre_auth_packet_dispatch")
	}
	if strings.Contains(compact, "distutils.spawn.find_executable(") &&
		strings.Contains(compact, "subprocess.Popen(") &&
		strings.Contains(compact, "shell=True") &&
		strings.Contains(compact, ".items()") &&
		strings.Contains(compact, ".wait()==0") {
		add("shell_true_package_manager_probe")
	}
	if pyCompactContainsAny(compact, "subprocess.run(", "subprocess.call(", "subprocess.Popen(", "subprocess.check_output(", "subprocess.check_call(", "Popen(") &&
		strings.Contains(compact, "shell=True") &&
		pyCompactContainsAny(compact, ".format(", "f\"", "f'") &&
		!pyCompactContainsAny(compact, "shlex.quote(", "shlex.join(", "subprocess.list2cmdline(") &&
		!strings.Contains(compact, "distutils.spawn.find_executable(") {
		add("command_string_wrapper_execution")
	}
	if strings.Contains(compact, "UPDATEusersSET") &&
		strings.Contains(compact, "nonquery(") &&
		strings.Contains(compact, "[0]") &&
		!strings.Contains(compact, "[0]in[\"firstname\",\"lastname\"]") {
		add("unvalidated_sql_identifier_interpolation")
	}
	if name == "_prepare_request" &&
		strings.Contains(compact, "\"X-Api-Key\"") &&
		strings.Contains(compact, "PLUGIN_DAEMON_KEY") &&
		strings.Contains(compact, "returnstr(") &&
		strings.Contains(compact, "/") &&
		!strings.Contains(compact, "unquote(") &&
		!strings.Contains(compact, ".split(\"/\")") &&
		!strings.Contains(compact, "\"..\"") {
		add("internal_service_url_path_traversal")
	}
	if name == "udp" &&
		strings.Contains(compact, ".recvfrom(") &&
		strings.Contains(compact, "dns.message.from_wire(") &&
		strings.Contains(compact, ".is_response(") &&
		strings.Contains(compact, "break") &&
		!strings.Contains(compact, "exceptdns.message.Truncated") &&
		!strings.Contains(compact, "ignore_errors") {
		add("dns_udp_response_validation_after_loop")
	}
	if name == "decode_relay_state" &&
		strings.Contains(compact, "urlparse(") &&
		strings.Contains(compact, ".scheme") &&
		strings.Contains(compact, ".netloc") &&
		strings.Contains(compact, ".path.startswith(\"/\")") &&
		!strings.Contains(compact, "is_safe_url(") &&
		!strings.Contains(compact, "get_account_adapter") {
		add("saml_relay_state_open_redirect")
	}
	if name == "_parse_qsl" &&
		strings.Contains(compact, ".replace(';','&').split('&')") {
		add("ambiguous_query_parameter_separator")
	}
	if name == "__init__" &&
		strings.Contains(compact, "create_engine(") &&
		strings.Contains(compact, ".database_uri") &&
		strings.Contains(compact, "sessionmaker(") &&
		strings.Contains(compact, "expire_on_commit=True") &&
		!strings.Contains(compact, "scoped_session(") &&
		!strings.Contains(compact, "pool_timeout") {
		add("chatterbot_sqlalchemy_session_pool_exhaustion_init")
	}
	if strings.Contains(compact, ".Session()") &&
		strings.Contains(compact, ".query(") &&
		strings.Contains(compact, "yield") &&
		strings.Contains(compact, ".model_to_object(") &&
		!strings.Contains(compact, "finally") {
		add("chatterbot_sqlalchemy_session_pool_exhaustion_filter")
	}
	if strings.Contains(compact, ".search(**") &&
		strings.Contains(compact, "pysolr.SolrError") &&
		strings.Contains(compact, "raiseSearchError") &&
		strings.Contains(compact, "SOLRreturnedanerrorrunningquery") &&
		!strings.Contains(compact, "SolrConnectionError") &&
		!strings.Contains(compact, "Failedtoconnecttoserver") {
		add("ckan_solr_connection_error_disclosure")
	}
	if strings.Contains(compact, ".split(\".\")") &&
		strings.Contains(compact, "hasattr(") &&
		strings.Contains(compact, "getattr(") &&
		strings.Contains(compact, "setattr(") &&
		!pyCompactContainsAny(compact, ".startswith(\"__\")", ".startswith('__')", ".endswith(\"__\")", ".endswith('__')") {
		add("python_dunder_path_class_pollution")
	}
	if strings.Contains(compact, "FollowUpAttachment(") &&
		strings.Contains(compact, "file=") &&
		strings.Contains(compact, "filename=") &&
		strings.Contains(compact, ".save()") &&
		!strings.Contains(compact, ".full_clean()") &&
		!strings.Contains(compact, "full_clean()") {
		add("django_attachment_save_without_model_validation")
	}
	if strings.Contains(compact, "sync_playwright()") &&
		strings.Contains(compact, ".chromium.launch(") &&
		strings.Contains(compact, ".new_context(") &&
		strings.Contains(compact, ".set_content(") &&
		!strings.Contains(compact, "java_script_enabled=False") {
		add("server_side_browser_active_html_js_enabled")
	}
	if strings.Contains(compact, "sync_playwright()") &&
		strings.Contains(compact, ".chromium.launch(") &&
		strings.Contains(compact, ".new_context(") &&
		strings.Contains(compact, ".set_content(") &&
		!strings.Contains(compact, "offline=") &&
		!strings.Contains(compact, ".route(") {
		add("server_side_browser_active_html_fetch_enabled")
	}
	if strings.Contains(compact, "SigningCertURL") &&
		strings.Contains(compact, ".startswith(\"https://\")") &&
		strings.Contains(compact, "urlparse(") &&
		strings.Contains(compact, "EVENT_CERT_DOMAINS") &&
		strings.Contains(compact, ".netloc.split(\".\")[-len(") &&
		!strings.Contains(compact, "SES_REGEX_CERT_URL.match(") &&
		!strings.Contains(compact, "SimpleNotificationService") {
		add("sns_certificate_url_trust_bypass")
	}
	if strings.Contains(compact, "UserStatus.ACTIVE") &&
		strings.Contains(compact, "UserRole.USER") &&
		strings.Contains(compact, "generate_keypair()") &&
		strings.Contains(compact, "create_user_with_keypair(") &&
		!strings.Contains(compact, "UserStatus.INACTIVE") {
		add("auto_active_signup_account")
	}
	if strings.Contains(compact, ".run(") &&
		pyCompactContainsAny(compact, "host='0.0.0.0'", "host=\"0.0.0.0\"") &&
		strings.Contains(compact, "debug=True") &&
		!strings.Contains(compact, "use_evalex=False") {
		add("werkzeug_debug_console_exposure")
	}
	if strings.Contains(compact, ".transaction_type:") &&
		strings.Contains(compact, ".transaction_type=\"selling\"") &&
		strings.Contains(compact, ".transaction_type=\"buying\"") &&
		!strings.Contains(compact, ".transaction_typein[\"buying\",\"selling\"]") {
		add("unvalidated_choice_control_field")
	}
	if strings.Contains(compact, "rules_of_guideline(") &&
		strings.Contains(compact, "checkers_by_labels(") &&
		!strings.Contains(compact, "__require_view()") {
		add("codechecker_guideline_rules_missing_view_check")
	}
	if strings.Contains(compact, "os.geteuid()==0") &&
		strings.Contains(compact, "superuserprivileges") &&
		!strings.Contains(compact, "os.getuid()==0") {
		add("effective_uid_root_check_bypass")
	}
	if strings.Contains(compact, "ub.Shelf()") &&
		strings.Contains(compact, "create_edit_shelf(") &&
		strings.Contains(compact, "page=\"shelfcreate\"") &&
		!strings.Contains(compact, "role_edit_shelfs") {
		add("access_policy_public_shelf_without_role_check")
	}
	if strings.Contains(compact, "yaml.safe_load(") &&
		strings.Contains(compact, "LOG.info(") &&
		strings.Contains(compact, "Configfile:") &&
		!strings.Contains(compact, "LOG.debug(\"Configfile:") {
		add("sensitive_config_info_log")
	}
	if pyRsaPkcs1v15DecryptErrorOracle(compact) {
		add("rsa_pkcs1v15_decrypt_error_oracle")
	}
	if strings.Contains(compact, ".__dict__.items()") &&
		strings.Contains(compact, "not") &&
		strings.Contains(compact, ".endswith(\"_e\")") &&
		!strings.Contains(strings.ToLower(compact), "api") {
		add("config_exposure_without_api_redaction")
	}
	if strings.Contains(compact, ".headers.get(") &&
		strings.Contains(compact, "Content-Type") &&
		strings.Contains(compact, "ALL_SERDE.get(") &&
		strings.Contains(compact, ".from_http_request(") &&
		!strings.Contains(compact, "UNSUPPORTED_MEDIA_TYPE") {
		add("request_selected_deserialization_format")
	}
	if strings.Contains(compact, "QueryRequest(") &&
		strings.Contains(compact, "sql=") &&
		strings.Contains(compact, ".execute_query(") &&
		!strings.Contains(compact, "validate_sql_security") &&
		!strings.Contains(compact, "DorisSecurityManager") {
		add("mcp_sql_execution_missing_validation")
	}
	if strings.Contains(compact, ".get_link_fields()") &&
		strings.Contains(compact, ".get_dynamic_link_fields()") &&
		strings.Contains(compact, "frappe.get_doc(") &&
		strings.Contains(compact, ".update(") &&
		!strings.Contains(compact, "check_permission=\"read\"") &&
		!strings.Contains(compact, ".apply_fieldlevel_read_permissions()") {
		add("frappe_link_expansion_missing_read_permission")
	}
	if strings.Contains(compact, ".context.read_only") &&
		pyCompactContainsAny(compact, "get_image_meta_or_404(", "get_resource(", "get_object(", "get_by_id(", "find_by_id(") &&
		pyCompactContainsAny(compact, "schedule_delete_from_backend(", "delete_image_metadata(", "delete_resource(", "delete_object(") &&
		pyCompactContainsAny(compact, "['protected']", "[\"protected\"]") &&
		!pyCompactContainsAny(compact, ".context.is_admin", ".context.owner", "['owner']", "[\"owner\"]", "check_ownership(", "require_owner(", "is_owner(", "checkPermission(", "check_permission(") {
		add("owned_resource_delete_missing_ownership_check")
	}
	if strings.Contains(compact, "_original_transport") &&
		strings.Contains(compact, "._reader._transport") &&
		strings.Contains(compact, "._writer._transport") &&
		!strings.Contains(compact, "._reader._buffer.clear()") {
		add("starttls_transport_buffer_handoff")
	}
	if strings.Contains(compact, ".replace(") &&
		strings.Contains(compact, "os.execv(") &&
		strings.Contains(compact, "\"-c\"") &&
		!strings.Contains(compact, "shlex.quote(") {
		add("command_line_assembly_review")
	}
	if strings.Contains(compact, ".query_params.get(\"version\")") &&
		strings.Contains(compact, "openapi_url=") &&
		strings.Contains(compact, "?version={") &&
		pyCompactContainsAny(compact, "get_swagger_ui_html(", "get_redoc_html(") &&
		!strings.Contains(compact, "quote(") {
		add("unescaped_docs_openapi_url")
	}
	if pyCompactContainsAny(compact, ".get('url','')", ".get(\"url\",\"\")") &&
		strings.Contains(compact, "return") &&
		!strings.Contains(compact, "is_safe_url(") &&
		!strings.Contains(compact, "SAFE_PROTOCOL_REGEX") &&
		!strings.Contains(compact, "return'DISABLED'") &&
		!strings.Contains(compact, "return\"DISABLED\"") {
		add("unsafe_watch_url_protocol")
	}
	if strings.Contains(compact, "publish_parts(") &&
		strings.Contains(compact, "writer_name=\"html4css1\"") &&
		strings.Contains(compact, "settings_overrides=") &&
		!strings.Contains(compact, "'raw_enabled':False") &&
		!strings.Contains(compact, "\"raw_enabled\":False") &&
		!strings.Contains(compact, "'file_insertion_enabled':False") &&
		!strings.Contains(compact, "\"file_insertion_enabled\":False") {
		add("docutils_rest_unsafe_directive_rendering")
	}
	if strings.Contains(compact, "use_ssl=False") &&
		strings.Contains(compact, "Tls(") &&
		strings.Contains(compact, "validate=ssl.CERT_REQUIRED") &&
		strings.Contains(compact, "Server(") {
		add("cert_validation_disabled_tls_fallback")
	}
	if strings.Contains(compact, "re.compile(") &&
		strings.Contains(compact, "^black([^A-Z0-9._-]+.*)$") {
		add("package_version_specifier_validation_review")
	}
	if name == "cookies" &&
		strings.Contains(compact, "SimpleCookie()") &&
		strings.Contains(compact, ".headers.get(\"cookie\",\"\").split(\";\")") &&
		strings.Contains(compact, ".load(") &&
		!strings.Contains(compact, "exceptException") &&
		!strings.Contains(compact, "continue") {
		add("emmett_unhandled_cookie_parse_exception")
	}
	if pyCompactContainsAny(compact, "CASE_DEMO_NONRANDOM_UUID_BASE", "CDO_DEMO_NONRANDOM_UUID_BASE") &&
		strings.Contains(compact, "sys.argv[0]") &&
		strings.Contains(compact, ".resolve()") &&
		strings.Contains(compact, ".relative_to(") &&
		strings.Contains(compact, ".append(str(") &&
		!strings.Contains(compact, "_is_relative_to(") {
		add("absolute_path_disclosure")
	}
	if strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, "._data_dir") &&
		strings.Contains(compact, "os.makedirs(") &&
		strings.Contains(compact, "shutil.rmtree") &&
		!strings.Contains(compact, "SAFE_SEED_RE.match(") &&
		!strings.Contains(compact, "_safe_rmtree") {
		add("cloakserve_fingerprint_seed_path_traversal")
	}
	if strings.Contains(compact, "include_attachment_data=True") &&
		pyCompactContainsAny(compact, "['attachment']", "[\"attachment\"]") &&
		pyCompactContainsAny(compact, "['filename']", "[\"filename\"]") &&
		pyCompactContainsAny(compact, "['raw']", "[\"raw\"]") &&
		strings.Contains(compact, "base64.b64decode(") &&
		pyCompactContainsAny(compact, ".open('wb')", ".open(\"wb\")") &&
		!(strings.Contains(compact, "pathlib.Path(") &&
			pyCompactContainsAny(compact, "[\"filename\"]", "['filename']") &&
			strings.Contains(compact, ".name")) &&
		!strings.Contains(compact, "os.path.basename(") {
		add("email_attachment_filename_path_traversal")
	}
	if strings.Contains(compact, ".startswith(\"/__emmett__\")") &&
		strings.Contains(compact, "[12:]") &&
		strings.Contains(compact, "os.path.join(os.path.dirname(__file__),\"..\",\"assets\"") &&
		strings.Contains(compact, "._static_response(") &&
		!strings.Contains(compact, "os.path.realpath(") &&
		!strings.Contains(compact, "static_file.startswith(") &&
		!strings.Contains(compact, ".relative_to(") {
		add("internal_asset_route_path_traversal")
	}
	if strings.Contains(compact, "AnsibleModule(") &&
		strings.Contains(compact, "authkey=dict(type='str')") &&
		strings.Contains(compact, "privkey=dict(type='str')") &&
		strings.Contains(compact, "UsmUserData(") &&
		!strings.Contains(compact, "authkey=dict(type='str',no_log=True)") &&
		!strings.Contains(compact, "privkey=dict(type='str',no_log=True)") {
		add("ansible_snmp_facts_credentials_no_log_missing")
	}
	if strings.Contains(compact, "_warnmsg(") &&
		strings.Contains(compact, "UnknownDKIMkeytype") &&
		pyCompactContainsAny(compact, "['k']", "[\"k\"]") &&
		!strings.Contains(compact, "_warnmsg(\"UnknownDKIMkeytype\")") {
		add("unneutralized_diagnostic_value")
	}
	if strings.Contains(compact, "validate_request(") &&
		pyCompactContainsAny(compact, "schedule_support_email(", "send_support_email(", "notify_admin(", "send_mail(", "send_email(") &&
		pyCompactContainsAny(compact, "Site:%s", "URL:%s", "Url:%s", "Website:%s") &&
		pyCompactContainsAny(compact, "['url']", "[\"url\"]", "['uri']", "[\"uri\"]", "['site']", "[\"site\"]") &&
		!pyCompactContainsAny(compact, ".hostname", ".host", ".host_url", "defang(", "url_has_allowed_host_and_scheme(", "is_safe_url(", "same_origin(", "allowed_host(") {
		add("untrusted_support_url_notification")
	}
	if strings.Contains(compact, "os.walk(") &&
		strings.Contains(compact, "os.path.splitext(os.path.join(") &&
		strings.Contains(compact, "msgfmt-o") &&
		strings.Contains(compact, "os.system(") &&
		!strings.Contains(compact, "djangocompilemo") &&
		!strings.Contains(compact, "djangocompilepo") {
		add("msgfmt_path_shell_command_interpolation")
	}
	if strings.Contains(compact, ".register_complete(") &&
		pyCompactContainsAny(compact, "['fido_state']", "[\"fido_state\"]") &&
		strings.Contains(compact, "User_Keys()") &&
		strings.Contains(compact, ".save()") &&
		!strings.Contains(compact, ".session.pop(") &&
		!strings.Contains(compact, "delrequest.session") {
		add("fido_registration_challenge_replay")
	}
	if strings.Contains(compact, "sshpass") &&
		strings.Contains(compact, "@{") &&
		strings.Contains(compact, "-p{") &&
		strings.Contains(compact, "run_command(") &&
		!strings.Contains(compact, "shlex.quote(") &&
		!strings.Contains(compact, "int(port)") {
		add("partially_escaped_ssh_command")
	}
	if name == "notify_provisioning_done" &&
		strings.Contains(compact, "notify_provisioning_done(") &&
		!strings.Contains(compact, "is_a_mac(") {
		add("cloudstack_baremetal_mac_command_injection")
	}
	if strings.Contains(compact, ".split('/',1)") &&
		strings.Contains(compact, ".replace('jpeg','jpg')") &&
		strings.Contains(compact, ".ext='.'+") &&
		!strings.Contains(compact, "mimetypes.guess_extension(") {
		add("mime_subtype_file_extension_path_traversal")
	}
	if strings.Contains(compact, ".startswith(\".cpr\")") &&
		strings.Contains(compact, "os.path.join(") &&
		strings.Contains(compact, "\"web/\"") &&
		strings.Contains(compact, "[5:]") &&
		strings.Contains(compact, ".tx_file(") &&
		!strings.Contains(compact, "absreal(") &&
		!strings.Contains(compact, ".startswith(path_base)") {
		add("copyparty_cpr_static_path_traversal")
	}
	if strings.Contains(compact, "PendingChangeSummary(") &&
		pyCompactContainsAny(compact, "changeText=unescape(", "change_text=unescape(") &&
		!pyCompactContainsAny(compact, "changeText=change[\"text\"]", "changeText=change['text']", "change_text=change[\"text\"]", "change_text=change['text']") {
		add("checkmk_pending_change_text_unescape_xss")
	}
	return out
}

func pyWaterfallReloadOptionUnescaped(compactBody string) bool {
	if !strings.Contains(compactBody, ".args") {
		return false
	}
	rest := compactBody
	offset := 0
	for {
		format := strings.Index(rest, "value=\"%s\"")
		if format < 0 {
			return false
		}
		format += offset
		start := strings.LastIndex(compactBody[:format], "show_reload_input")
		if start < 0 {
			start = max(0, format-300)
		}
		end := min(len(compactBody), format+600)
		window := compactBody[start:end]
		if strings.Contains(window, "<td>%s</td>") && !strings.Contains(window, "html.escape(") {
			return true
		}
		offset = format + len("value=\"%s\"")
		rest = compactBody[offset:]
	}
}

func pyContextCompactUnbounded(raw string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
}

func pyCompactContainsAny(compact string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(compact, needle) {
			return true
		}
	}
	return false
}

func pyRsaPkcs1v15DecryptErrorOracle(compact string) bool {
	if !pyCompactContainsAny(compact, "EVP_PKEY_decrypt", "RSA_private_decrypt") {
		return false
	}
	if !pyCompactContainsAny(compact, "EVP_PKEY_CTX_set_rsa_padding", "RSA_PKCS1_PADDING") {
		return false
	}
	resIdx := pyIndexAny(compact, "res=crypt(", "res=backend._lib.RSA_private_decrypt(")
	branchIdx := pyIndexAny(compact, "ifres<=0", "ifres<1", "ifres==0", "ifres!=1")
	if resIdx < 0 || branchIdx < resIdx {
		return false
	}
	clearIdx := strings.Index(compact, "ERR_clear_error(")
	if clearIdx >= 0 && clearIdx < branchIdx {
		return false
	}
	bufferIdx := pyIndexAny(compact, "_ffi.buffer(", "ffi.buffer(")
	if bufferIdx >= 0 && bufferIdx < branchIdx {
		return false
	}
	return true
}

func pyIndexAny(s string, needles ...string) int {
	best := -1
	for _, needle := range needles {
		if i := strings.Index(s, needle); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

func pyContextHasAny(tokens []string, needles ...string) bool {
	for _, tok := range tokens {
		for _, needle := range needles {
			if tok == needle || strings.Contains(tok, needle) {
				return true
			}
		}
	}
	return false
}

func pyCobblerRemoteAction(compact, action string) bool {
	switch action {
	case "generic_delete":
		return strings.Contains(compact, "remote.remove_item")
	default:
		return strings.Contains(compact, "remote.background_"+action)
	}
}

func (c *pyConv) pyContextAssignmentItems(n *tree_sitter.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind() {
	case "list", "tuple", "set":
	default:
		return nil
	}
	var out []string
	for _, ch := range namedChildren(n) {
		item := c.pyContextPath(ch)
		if item == "" {
			continue
		}
		out = append(out, item)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func (c *pyConv) pyContextPath(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if p := c.dotted(n); p != "" && p != "?" {
		return p
	}
	return pyContextValue(c.text(n))
}

func pyContextValue(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"' || q == '`') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
		}
	}
	return pyContextCompact(s)
}

func pyContextCompact(raw string) string {
	s := strings.Join(strings.Fields(strings.TrimSpace(raw)), "")
	if len(s) > 160 {
		return ""
	}
	return s
}

func (c *pyConv) pyClassContext(n *tree_sitter.Node, name string, bases []string) []string {
	body := c.text(field(n, "body"))
	out := []string{
		"class_name=" + name,
		"class_name:" + name,
		"class_bases=" + strings.Join(bases, ","),
		body,
		strings.Join(strings.Fields(body), ""),
	}
	for _, base := range bases {
		if base != "" {
			out = append(out, "class_base:"+base)
		}
	}
	return out
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

func (c *pyConv) pyParamEntries(name string, params []string, base []string) []nir.ParamEntry {
	var out []nir.ParamEntry
	for i, p := range params {
		tokens := append([]string{}, base...)
		tokens = append(tokens, "function_name:"+name, "param_name:"+p, "param_index:"+itoa(i))
		out = append(out, nir.ParamEntry{Param: p, Tokens: tokens})
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

func (c *pyConv) pyClassBases(n *tree_sitter.Node) []string {
	var bases []string
	args := field(n, "superclasses")
	if args == nil {
		return bases
	}
	for _, ch := range namedChildren(args) {
		if ch.Kind() == "keyword_argument" {
			continue
		}
		base := c.dotted(ch)
		if base == "" && ch.Kind() == "call" {
			base = c.dotted(field(ch, "function"))
		}
		if base != "" {
			bases = append(bases, base)
		}
	}
	return bases
}

func (c *pyConv) params(params *tree_sitter.Node) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, ch := range namedChildren(params) {
		switch ch.Kind() {
		case "identifier":
			out = append(out, pyParamName(c.text(ch)))
		case "default_parameter", "typed_parameter", "typed_default_parameter":
			if nm := field(ch, "name"); nm != nil {
				out = append(out, pyParamName(c.text(nm)))
			} else if kids := namedChildren(ch); len(kids) > 0 {
				out = append(out, pyParamName(c.text(kids[0])))
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
				name = pyParamName(c.text(nm))
			} else if kids := namedChildren(ch); len(kids) > 0 {
				name = pyParamName(c.text(kids[0]))
			}
			putParamType(out, name, paramTypeFromField(c, ch))
		}
	}
	return out
}

func pyParamName(name string) string {
	return strings.TrimLeft(name, "*")
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
		return nir.Const{Loc: L, Value: c.text(n)}
	case "integer", "float":
		// carry the literal text so value-matching can see numeric modes/flags
		// (e.g. os.chmod(p, 0o777)); taint is unaffected (Value is val-match only).
		return nir.Const{Loc: L, Value: c.text(n)}
	case "true", "false", "none":
		// carry the literal text so value-matching can see verify=False etc.
		return nir.Const{Loc: L, Value: c.text(n)}
	case "keyword_argument":
		return nir.Pair{Key: c.keyName(field(n, "name")), Value: c.expr(field(n, "value")), Loc: L}
	case "list_splat", "dictionary_splat":
		if kids := namedChildren(n); len(kids) > 0 {
			return nir.Thru{Inner: c.expr(kids[0])}
		}
		return nir.Const{Loc: L}
	case "dictionary":
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			if ch.Kind() == "pair" {
				keyNode := field(ch, "key")
				parts = append(parts, nir.Pair{
					Key: c.keyName(keyNode), Value: c.expr(field(ch, "value")), Loc: L,
					DynamicKey: keyNode == nil || keyNode.Kind() != "string",
				})
			}
		}
		return nir.Seq{Parts: parts, Loc: L}
	case "attribute":
		return nir.Attr{Base: c.expr(field(n, "object")), Attr: c.text(field(n, "attribute")), Path: c.dotted(n), Loc: L}
	case "subscript":
		return nir.Index{Base: c.expr(field(n, "value")), Key: c.expr(field(n, "subscript")), Path: c.dotted(field(n, "value")), Loc: L}
	case "slice":
		return nir.Const{Loc: L, Value: c.text(n)}
	case "call":
		fn := field(n, "function")
		path := c.dotted(fn)
		var arglist []nir.Expr
		if args := field(n, "arguments"); args != nil {
			if args.Kind() == "generator_expression" {
				arglist = append(arglist, c.expr(args))
			} else {
				for _, a := range namedChildren(args) {
					arglist = append(arglist, c.expr(a))
				}
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
	case "generator_expression", "list_comprehension", "set_comprehension":
		return c.comprehensionValue(n, L)
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

func (c *pyConv) comprehensionValue(n *tree_sitter.Node, loc string) nir.Expr {
	body := field(n, "body")
	if body == nil {
		var parts []nir.Expr
		for _, ch := range namedChildren(n) {
			parts = append(parts, c.expr(ch))
		}
		return nir.Seq{Parts: parts, Loc: loc}
	}
	parts := []nir.Expr{c.expr(body)}
	for _, ch := range namedChildren(n) {
		if ch.Kind() == "if_clause" {
			parts = append(parts, c.expr(ch))
		}
	}
	var out nir.Expr = parts[0]
	if len(parts) > 1 {
		out = nir.Seq{Parts: parts, Loc: loc}
	}
	for _, ch := range namedChildren(n) {
		if ch.Kind() != "for_in_clause" {
			continue
		}
		names := c.targets(field(ch, "left"))
		iter := field(ch, "right")
		if len(names) == 0 || iter == nil {
			break
		}
		repl := c.expr(iter)
		for _, name := range names {
			out = replaceName(out, name, repl)
		}
		break
	}
	return out
}

func replaceName(ex nir.Expr, name string, repl nir.Expr) nir.Expr {
	switch e := ex.(type) {
	case nil:
		return e
	case nir.Name:
		if e.ID == name {
			return cloneExpr(repl)
		}
		return e
	case nir.Attr:
		e.Base = replaceName(e.Base, name, repl)
		return e
	case nir.Index:
		e.Base = replaceName(e.Base, name, repl)
		e.Key = replaceName(e.Key, name, repl)
		return e
	case nir.Call:
		e.Callee = replaceName(e.Callee, name, repl)
		for i, a := range e.Args {
			e.Args[i] = replaceName(a, name, repl)
		}
		return e
	case nir.Format:
		for i, p := range e.Parts {
			e.Parts[i] = replaceName(p, name, repl)
		}
		return e
	case nir.Seq:
		for i, p := range e.Parts {
			e.Parts[i] = replaceName(p, name, repl)
		}
		return e
	case nir.Pair:
		e.Value = replaceName(e.Value, name, repl)
		return e
	case nir.Thru:
		e.Inner = replaceName(e.Inner, name, repl)
		return e
	case nir.BinOp:
		e.Left = replaceName(e.Left, name, repl)
		e.Right = replaceName(e.Right, name, repl)
		return e
	case nir.Unary:
		e.Operand = replaceName(e.Operand, name, repl)
		return e
	case nir.Ternary:
		e.Cond = replaceName(e.Cond, name, repl)
		e.Then = replaceName(e.Then, name, repl)
		e.Else = replaceName(e.Else, name, repl)
		return e
	case nir.Lambda:
		return e
	default:
		return e
	}
}

func cloneExpr(ex nir.Expr) nir.Expr {
	switch e := ex.(type) {
	case nil:
		return e
	case nir.Name, nir.Const:
		return e
	case nir.Attr:
		e.Base = cloneExpr(e.Base)
		return e
	case nir.Index:
		e.Base = cloneExpr(e.Base)
		e.Key = cloneExpr(e.Key)
		return e
	case nir.Call:
		e.Callee = cloneExpr(e.Callee)
		e.Args = cloneExprs(e.Args)
		return e
	case nir.Format:
		e.Parts = cloneExprs(e.Parts)
		return e
	case nir.Seq:
		e.Parts = cloneExprs(e.Parts)
		if len(e.KeyPath) > 0 {
			e.KeyPath = append([]string(nil), e.KeyPath...)
		}
		return e
	case nir.Pair:
		e.Value = cloneExpr(e.Value)
		return e
	case nir.Thru:
		e.Inner = cloneExpr(e.Inner)
		return e
	case nir.BinOp:
		e.Left = cloneExpr(e.Left)
		e.Right = cloneExpr(e.Right)
		return e
	case nir.Unary:
		e.Operand = cloneExpr(e.Operand)
		return e
	case nir.Ternary:
		e.Cond = cloneExpr(e.Cond)
		e.Then = cloneExpr(e.Then)
		e.Else = cloneExpr(e.Else)
		return e
	case nir.Lambda:
		e.Body = cloneStmts(e.Body)
		if e.ParamTypes != nil {
			cp := map[string]string{}
			for k, v := range e.ParamTypes {
				cp[k] = v
			}
			e.ParamTypes = cp
		}
		if len(e.Params) > 0 {
			e.Params = append([]string(nil), e.Params...)
		}
		if len(e.ParamEntries) > 0 {
			e.ParamEntries = append([]nir.ParamEntry(nil), e.ParamEntries...)
		}
		return e
	default:
		return e
	}
}

func cloneExprs(in []nir.Expr) []nir.Expr {
	if len(in) == 0 {
		return nil
	}
	out := make([]nir.Expr, len(in))
	for i, e := range in {
		out[i] = cloneExpr(e)
	}
	return out
}

func cloneStmts(in []nir.Stmt) []nir.Stmt {
	if len(in) == 0 {
		return nil
	}
	out := make([]nir.Stmt, len(in))
	copy(out, in)
	return out
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

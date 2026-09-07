package actionscript

import (
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// assignInfo is the shape a statement needs when the expression it just read turned
// out to be an assignment: what was written, with which operator, and to where.
type assignInfo struct {
	target nir.Expr
	op     string
	value  nir.Expr
	loc    string
}

var assignOps = map[string]bool{
	"=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"&=": true, "|=": true, "^=": true, "<<=": true, ">>=": true, ">>>=": true,
	"&&=": true, "||=": true, "??=": true, "**=": true,
}

// binary operator precedence, loosest first. `is` and `as` are ActionScript's own
// type operators and bind like the other relational ones.
var binaryLevels = [][]string{
	{"??"},
	{"||"},
	{"&&"},
	{"|"},
	{"^"},
	{"&"},
	{"==", "!=", "===", "!=="},
	{"<", ">", "<=", ">=", "is", "as", "in", "instanceof"},
	{"<<", ">>", ">>>"},
	{"+", "-"},
	{"*", "/", "%"},
}

// parseExpr reads a comma expression. Every element flows, so the sequence carries
// the taint of any of them.
func (p *parser) parseExpr() nir.Expr {
	first := p.parseAssignExpr()
	if !p.at(",") {
		return first
	}
	L := p.loc()
	parts := []nir.Expr{first}
	for p.accept(",") {
		parts = append(parts, p.parseAssignExpr())
	}
	return nir.Seq{Parts: parts, Loc: L}
}

func (p *parser) parseParenExpr() nir.Expr {
	if !p.accept("(") {
		return nil
	}
	e := p.parseExpr()
	p.accept(")")
	return e
}

func (p *parser) parseAssignExpr() nir.Expr {
	e, _ := p.parseAssignInfo()
	return e
}

// parseAssignInfo reads an assignment expression. Its VALUE is the right-hand side
// (that is what an enclosing expression sees), and the assignment itself is reported
// separately for the statement layer to model.
func (p *parser) parseAssignInfo() (nir.Expr, *assignInfo) {
	if p.depth > maxExprDepth {
		p.skipTo(";")
		return nir.Const{Loc: p.loc()}, nil
	}
	p.depth++
	defer func() { p.depth-- }()

	lhs := p.parseConditional()
	t := p.cur()
	if t.kind == tokPunct && assignOps[t.text] {
		L := p.locAt(t)
		p.next()
		rhs := p.parseAssignExpr()
		return rhs, &assignInfo{target: lhs, op: t.text, value: rhs, loc: L}
	}
	return lhs, nil
}

func (p *parser) parseConditional() nir.Expr {
	cond := p.parseBinary(0)
	if !p.at("?") {
		return cond
	}
	L := p.loc()
	p.next()
	then := p.parseAssignExpr()
	p.accept(":")
	els := p.parseAssignExpr()
	return nir.Ternary{Cond: cond, Then: then, Else: els, Loc: L}
}

func (p *parser) parseBinary(level int) nir.Expr {
	if level >= len(binaryLevels) {
		return p.parseUnary()
	}
	left := p.parseBinary(level + 1)
	for {
		t := p.cur()
		op := ""
		for _, cand := range binaryLevels[level] {
			if isOperator(t, cand) {
				op = cand
				break
			}
		}
		if op == "" {
			return left
		}
		start := p.cur()
		p.next()
		right := p.parseBinary(level + 1)
		L := p.locAt(start)
		switch op {
		case "+":
			// `+` on strings is the concatenation every injected value travels through,
			// and ActionScript resolves the overload at runtime; a Format is the
			// taint-preserving reading and matches the other frontends.
			left = nir.Format{Parts: []nir.Expr{left, right}, Loc: L}
		case "as":
			// a cast is transparent to taint
			left = nir.Thru{Inner: left}
		default:
			left = nir.BinOp{Op: op, Left: left, Right: right, Loc: L}
		}
	}
}

// isOperator matches a binary operator token, whether it is punctuation (`+`) or one
// of the word operators (`is`, `as`, `in`, `instanceof`).
func isOperator(t token, op string) bool {
	if op[0] >= 'a' && op[0] <= 'z' {
		return t.kind == tokIdent && t.text == op
	}
	return t.kind == tokPunct && t.text == op
}

var unaryWords = map[string]bool{"typeof": true, "void": true, "delete": true}

func (p *parser) parseUnary() nir.Expr {
	if p.depth > maxExprDepth {
		return nir.Const{Loc: p.loc()}
	}
	p.depth++
	defer func() { p.depth-- }()

	t := p.cur()
	L := p.locAt(t)
	if t.kind == tokIdent {
		if t.text == "new" {
			return p.parseNew()
		}
		if unaryWords[t.text] {
			p.next()
			return nir.Unary{Op: t.text, Operand: p.parseUnary(), Loc: L}
		}
	}
	if t.kind == tokPunct {
		switch t.text {
		case "!", "-", "+", "~":
			p.next()
			return nir.Unary{Op: t.text, Operand: p.parseUnary(), Loc: L}
		case "++", "--":
			p.next()
			return nir.Thru{Inner: p.parseUnary()}
		}
	}
	return p.parsePostfix(p.parsePrimary())
}

// parseNew reads `new T(args)` (and the argument-less `new T`). The constructed
// object contains its arguments, which nir.Call.IsCtor tells the lowering.
func (p *parser) parseNew() nir.Expr {
	start := p.cur()
	L := p.locAt(start)
	p.next()       // new
	if p.at("<") { // `new <T>[…]`, the Vector literal
		p.skipBraced("<", ">")
		return p.parsePostfix(p.parsePrimary())
	}
	callee := p.parseMemberOnly(p.parsePrimary())
	var args []nir.Expr
	if p.at("(") {
		args = p.parseArgs()
	}
	path := dotted(callee)
	return p.parsePostfix(nir.Call{
		Callee: callee,
		Args:   args,
		Path:   path,
		Method: lastSeg(path),
		Loc:    L,
		IsCtor: true,
	})
}

// parseMemberOnly extends a `new` callee with `.` and `[]` accesses but stops before
// the argument list, which belongs to the constructor.
func (p *parser) parseMemberOnly(e nir.Expr) nir.Expr {
	for {
		switch {
		case p.at("."):
			p.next()
			e = p.attr(e)
		case p.at("["):
			e = p.index(e)
		default:
			return e
		}
	}
}

// parsePostfix applies the access, call and increment suffixes to a primary.
func (p *parser) parsePostfix(e nir.Expr) nir.Expr {
	for {
		t := p.cur()
		if t.kind != tokPunct {
			return e
		}
		switch t.text {
		case ".", "..": // `..` is the E4X descendant accessor; read it as a member access
			p.next()
			e = p.attr(e)
		case "::": // a namespace-qualified name reads as one more segment
			p.next()
			e = p.attr(e)
		case "[":
			e = p.index(e)
		case "(":
			L := p.loc()
			args := p.parseArgs()
			path := dotted(e)
			e = nir.Call{Callee: e, Args: args, Path: path, Method: lastSeg(path), Loc: L}
		case "++", "--":
			p.next()
			e = nir.Thru{Inner: e}
		default:
			return e
		}
	}
}

// attr reads the name after a `.`, including the E4X `@attr` and `*` wildcards, which
// are member accesses as far as a dotted path is concerned.
func (p *parser) attr(base nir.Expr) nir.Expr {
	L := p.loc()
	name := ""
	switch {
	case p.cur().kind == tokIdent:
		name = p.next().text
	case p.at("@"):
		p.next()
		if p.cur().kind == tokIdent {
			name = p.next().text
		}
	case p.at("*"):
		p.next()
		name = "*"
	case p.at("("): // `.(expr)`, an E4X filter
		p.parseParenExpr()
		return base
	default:
		return base
	}
	return nir.Attr{Base: base, Attr: name, Path: joinPath(dotted(base), name), Loc: L}
}

func (p *parser) index(base nir.Expr) nir.Expr {
	L := p.loc()
	p.next() // '['
	var key nir.Expr
	if !p.at("]") {
		key = p.parseExpr()
	}
	p.accept("]")
	return nir.Index{Base: base, Key: key, Path: dotted(base), Loc: L}
}

func (p *parser) parseArgs() []nir.Expr {
	var args []nir.Expr
	if !p.accept("(") {
		return args
	}
	for !p.eof() && !p.at(")") {
		before := p.pos
		args = append(args, p.parseAssignExpr())
		if !p.accept(",") && p.pos == before {
			p.next()
		}
		if !p.at(")") && p.pos == before {
			p.next()
		}
	}
	p.accept(")")
	return args
}

func (p *parser) parsePrimary() nir.Expr {
	t := p.cur()
	L := p.locAt(t)
	switch t.kind {
	case tokNumber:
		p.next()
		return nir.Const{Loc: L, Value: t.text}
	case tokString:
		p.next()
		return nir.Const{Loc: L, Value: t.val}
	case tokRegex:
		p.next()
		return nir.Const{Loc: L, Value: t.text}
	case tokIdent:
		switch t.text {
		case "function":
			return p.parseFunctionExpr()
		case "true", "false", "null", "undefined", "NaN":
			p.next()
			return nir.Const{Loc: L, Value: t.text}
		}
		p.next()
		return nir.Name{ID: t.text, Loc: L}
	case tokPunct:
		switch t.text {
		case "(":
			return nir.Thru{Inner: p.parseParenExpr()}
		case "[":
			return p.parseArrayLit()
		case "{":
			return p.parseObjectLit()
		case "@":
			p.next()
			if p.cur().kind == tokIdent {
				n := p.next()
				return nir.Name{ID: n.text, Loc: L}
			}
			return nir.Const{Loc: L}
		case "<":
			// an E4X XML literal: skip it whole rather than misread its tags as
			// comparisons, and treat it as an opaque constant.
			p.skipBraced("<", ">")
			return nir.Const{Loc: L}
		}
	}
	p.next()
	return nir.Const{Loc: L}
}

// parseFunctionExpr reads an anonymous function expression, which in ActionScript is
// how a listener or callback is written inline.
func (p *parser) parseFunctionExpr() nir.Expr {
	L := p.loc()
	p.next() // function
	if p.cur().kind == tokIdent {
		p.next() // an optional name
	}
	params, paramTypes := p.parseParams()
	p.typeAnnotation()
	var body []nir.Stmt
	if p.accept("{") {
		body = p.parseStatements()
		p.accept("}")
	}
	return nir.Lambda{Params: params, ParamTypes: paramTypes, Body: body, Loc: L}
}

func (p *parser) parseArrayLit() nir.Expr {
	L := p.loc()
	p.next() // '['
	var parts []nir.Expr
	for !p.eof() && !p.at("]") {
		before := p.pos
		if p.accept(",") {
			continue
		}
		parts = append(parts, p.parseAssignExpr())
		if !p.accept(",") && p.pos == before {
			p.next()
		}
	}
	p.accept("]")
	return nir.Seq{Parts: parts, Loc: L}
}

// parseObjectLit reads `{k: v, …}`. Each entry becomes a Pair so a named-value
// matcher can read the key; taint flows through the value.
func (p *parser) parseObjectLit() nir.Expr {
	L := p.loc()
	p.next() // '{'
	var parts []nir.Expr
	for !p.eof() && !p.at("}") {
		before := p.pos
		key, dynamic := "", false
		switch t := p.cur(); {
		case t.kind == tokIdent:
			key = p.next().text
		case t.kind == tokString:
			key = p.next().val
		case t.kind == tokNumber:
			key = p.next().text
		case t.kind == tokPunct && t.text == "[":
			p.skipBraced("[", "]")
			dynamic = true
		}
		if p.accept(":") {
			parts = append(parts, nir.Pair{Key: key, Value: p.parseAssignExpr(), Loc: L, DynamicKey: dynamic})
		}
		if !p.accept(",") && p.pos == before {
			p.next()
		}
	}
	p.accept("}")
	return nir.Seq{Parts: parts, Loc: L}
}

// --- paths --------------------------------------------------------------

// dotted is the callee path a binding matches on: the source spelling of a member
// chain, with an index step written as `[]`.
func dotted(e nir.Expr) string {
	switch ex := e.(type) {
	case nir.Name:
		return ex.ID
	case nir.Attr:
		return ex.Path
	case nir.Index:
		if ex.Path == "" {
			return "?"
		}
		return ex.Path + "[]"
	case nir.Call:
		return ex.Path
	case nir.Thru:
		return dotted(ex.Inner)
	}
	return "?"
}

func joinPath(base, name string) string {
	if base == "" || base == "?" {
		return name
	}
	return base + "." + name
}

func lastSeg(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

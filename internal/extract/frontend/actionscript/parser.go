package actionscript

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// maxExprDepth bounds expression recursion. A scanner reads whatever is on disk, and
// a pathological or truncated file must cost a truncated parse, not the stack.
const maxExprDepth = 256

// modifiers are the attribute keywords that may precede a declaration. A user-defined
// namespace can also appear there, but naming one is rare enough that treating an
// unknown identifier as a modifier would misparse far more than it recovers.
var modifiers = map[string]bool{
	"public": true, "private": true, "protected": true, "internal": true,
	"static": true, "final": true, "override": true, "dynamic": true,
	"native": true, "intrinsic": true,
}

type parser struct {
	src   []byte
	toks  []token
	pos   int
	file  string
	pkg   string
	imps  []nir.Import
	depth int
	// meta holds the `[Metadata]` tags read since the last declaration, which attach
	// to whatever that declaration turns out to be.
	meta []string
}

func (p *parser) cur() token { return p.toks[p.pos] }

func (p *parser) peek(n int) token {
	if p.pos+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.pos+n]
}

func (p *parser) eof() bool { return p.cur().kind == tokEOF }

func (p *parser) next() token {
	t := p.cur()
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) at(text string) bool {
	t := p.cur()
	return t.kind == tokPunct && t.text == text
}

func (p *parser) atWord(word string) bool {
	t := p.cur()
	return t.kind == tokIdent && t.text == word
}

func (p *parser) accept(text string) bool {
	if p.at(text) {
		p.next()
		return true
	}
	return false
}

func (p *parser) acceptWord(word string) bool {
	if p.atWord(word) {
		p.next()
		return true
	}
	return false
}

func (p *parser) loc() string { return p.file + ":" + strconv.Itoa(p.cur().line) }

func (p *parser) locAt(t token) string { return p.file + ":" + strconv.Itoa(t.line) }

// textBetween returns the source slice spanning two tokens, used for the raw text a
// Format node and a function's context tokens carry.
func (p *parser) textBetween(from, to token) string {
	if from.start < 0 || to.end > len(p.src) || from.start >= to.end {
		return ""
	}
	return string(p.src[from.start:to.end])
}

// skipTo consumes tokens until just past the next `;` at the current brace depth (or
// up to a closing brace). It is the recovery path: whatever could not be understood
// costs one statement, not the file.
func (p *parser) skipTo(stop string) {
	depth := 0
	for !p.eof() {
		t := p.cur()
		if t.kind == tokPunct {
			switch t.text {
			case "{", "(", "[":
				depth++
			case "}", ")", "]":
				if depth == 0 {
					return
				}
				depth--
			case stop:
				if depth == 0 {
					p.next()
					return
				}
			}
		}
		p.next()
	}
}

// skipBraced consumes a balanced `{…}`, `(…)` or `[…]` group starting at the current
// token, and returns the closing token.
func (p *parser) skipBraced(open, close string) token {
	last := p.cur()
	if !p.accept(open) {
		return last
	}
	depth := 1
	for !p.eof() && depth > 0 {
		t := p.next()
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case open:
			depth++
		case close:
			depth--
			last = t
		}
	}
	return last
}

// --- directives ---------------------------------------------------------

// parseProgram reads a whole compilation unit: an optional `package` block plus
// whatever is declared inside or beside it.
func (p *parser) parseProgram() []nir.Stmt {
	var out []nir.Stmt
	for !p.eof() {
		before := p.pos
		if p.atWord("package") {
			p.next()
			p.pkg = p.qualifiedName()
			if p.at("{") {
				p.next()
				out = append(out, p.parseDirectives()...)
				p.accept("}")
			}
			continue
		}
		out = append(out, p.parseDirective()...)
		if p.pos == before {
			p.next() // guaranteed progress
		}
	}
	return out
}

// parseDirectives reads declarations until the matching `}` (or end of input).
func (p *parser) parseDirectives() []nir.Stmt {
	var out []nir.Stmt
	for !p.eof() && !p.at("}") {
		before := p.pos
		out = append(out, p.parseDirective()...)
		if p.pos == before {
			p.next()
		}
	}
	return out
}

// parseDirective reads one declaration or statement, including any attribute
// keywords and `[Metadata]` tags in front of it.
func (p *parser) parseDirective() []nir.Stmt {
	for p.at("[") {
		p.readMetadata()
	}
	exported := false
	for p.cur().kind == tokIdent && modifiers[p.cur().text] {
		if p.cur().text == "public" {
			exported = true
		}
		p.next()
	}
	switch {
	case p.atWord("import"):
		p.next()
		if name := p.qualifiedName(); name != "" {
			p.imps = append(p.imps, nir.Import{Local: lastSeg(name), Module: name, IsModule: true})
		}
		p.accept(";")
		return nil
	case p.atWord("use"), p.atWord("include"), p.atWord("namespace"):
		p.skipTo(";")
		return nil
	case p.atWord("class"), p.atWord("interface"):
		return []nir.Stmt{p.parseClass()}
	case p.atWord("function"):
		return []nir.Stmt{p.parseFunction(exported)}
	}
	return p.parseStatement()
}

// readMetadata consumes one `[Tag(...)]` annotation and records its tag name.
func (p *parser) readMetadata() {
	open := p.pos
	p.next() // '['
	if p.cur().kind == tokIdent {
		p.meta = append(p.meta, p.cur().text)
	}
	p.pos = open
	p.skipBraced("[", "]")
}

func (p *parser) takeMeta() []string {
	if len(p.meta) == 0 {
		return nil
	}
	m := p.meta
	p.meta = nil
	return m
}

// qualifiedName reads `a.b.C` (or `a.b.*`), the spelling every package, import and
// type reference uses.
func (p *parser) qualifiedName() string {
	if p.cur().kind != tokIdent {
		return ""
	}
	var b strings.Builder
	b.WriteString(p.next().text)
	for p.at(".") {
		if p.peek(1).kind == tokIdent {
			p.next()
			b.WriteString(".")
			b.WriteString(p.next().text)
			continue
		}
		if p.peek(1).kind == tokPunct && p.peek(1).text == "*" {
			p.next()
			p.next()
			b.WriteString(".*")
			continue
		}
		break
	}
	return b.String()
}

// typeName reads the `:T` annotation on a declaration and returns the type's short
// name (`*` — the untyped annotation — reads as no type at all).
func (p *parser) typeAnnotation() string {
	if !p.accept(":") {
		return ""
	}
	if p.at("*") {
		p.next()
		return ""
	}
	name := p.qualifiedName()
	// Vector.<T> and other parameterised types: the element type is not what receiver
	// resolution keys on, so drop it.
	if p.at("<") {
		p.skipBraced("<", ">")
	}
	return lastSeg(name)
}

// parseClass reads `class C extends B implements I, J { … }`.
func (p *parser) parseClass() nir.Stmt {
	L := p.loc()
	annotations := p.takeMeta()
	p.next() // class / interface
	name := ""
	if p.cur().kind == tokIdent {
		name = p.next().text
	}
	var bases []string
	if p.acceptWord("extends") {
		for {
			if b := lastSeg(p.qualifiedName()); b != "" {
				bases = append(bases, b)
			}
			if !p.accept(",") {
				break
			}
		}
	}
	if p.acceptWord("implements") {
		for {
			if b := lastSeg(p.qualifiedName()); b != "" {
				bases = append(bases, b)
			}
			if !p.accept(",") {
				break
			}
		}
	}
	var body []nir.Stmt
	if p.accept("{") {
		body = p.parseDirectives()
		p.accept("}")
	}
	return nir.ClassDef{
		Name:        name,
		Body:        body,
		Bases:       bases,
		Members:     classMembers(body),
		Annotations: annotations,
		Loc:         L,
	}
}

// classMembers returns the data-member names a class body declares, so a bare member
// reference inside a method resolves to `this.<member>` (nir.ClassDef.Members).
func classMembers(body []nir.Stmt) []string {
	var out []string
	for _, st := range body {
		a, ok := st.(nir.Assign)
		if !ok {
			continue
		}
		for _, t := range a.Targets {
			if t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

// parseFunction reads a function declaration or a `get`/`set` accessor. An accessor
// is named for the property it backs, which is the name every caller writes.
func (p *parser) parseFunction(exported bool) nir.Stmt {
	startTok := p.cur()
	L := p.loc()
	decorators := p.takeMeta()
	p.next() // function
	if (p.atWord("get") || p.atWord("set")) && p.peek(1).kind == tokIdent {
		p.next()
	}
	name := ""
	if p.cur().kind == tokIdent {
		name = p.next().text
	}
	params, paramTypes := p.parseParams()
	p.typeAnnotation()
	var body []nir.Stmt
	endTok := p.cur()
	if p.accept("{") {
		body = p.parseStatements()
		endTok = p.cur()
		p.accept("}")
	} else {
		p.accept(";") // an interface method has a signature and no body
	}
	return nir.FuncDef{
		Name:          name,
		Params:        params,
		ParamTypes:    paramTypes,
		Body:          body,
		Loc:           L,
		Exported:      exported,
		Decorators:    decorators,
		ContextTokens: functionContext(name, p.textBetween(startTok, endTok)),
	}
}

// functionContext is the syntax-level evidence a function carries. It mirrors the
// other frontends: the name, the raw text, and a whitespace-compacted form, with no
// meaning attached — what any token means is a binding's decision.
func functionContext(name, text string) []string {
	if name == "" && text == "" {
		return nil
	}
	return []string{
		"lang=actionscript",
		"name=" + name,
		"function_name:" + name,
		text,
		compact(text),
	}
}

func compact(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// parseParams reads a parameter list, dropping the `...rest` marker and recording
// each parameter's declared type.
func (p *parser) parseParams() ([]string, map[string]string) {
	var names []string
	types := map[string]string{}
	if !p.accept("(") {
		return names, types
	}
	for !p.eof() && !p.at(")") {
		before := p.pos
		p.accept("...")
		if p.cur().kind == tokIdent {
			n := p.next().text
			names = append(names, n)
			if t := p.typeAnnotation(); t != "" {
				types[n] = t
			}
			if p.accept("=") {
				p.parseAssignExpr()
			}
		}
		if !p.accept(",") && p.pos == before {
			p.next()
		}
	}
	p.accept(")")
	return names, types
}

// --- statements ---------------------------------------------------------

func (p *parser) parseStatements() []nir.Stmt {
	var out []nir.Stmt
	for !p.eof() && !p.at("}") {
		before := p.pos
		out = append(out, p.parseStatement()...)
		if p.pos == before {
			p.next()
		}
	}
	return out
}

// parseBlock reads a `{…}` block or a single brace-less statement, which is the body
// shape every control-flow construct accepts.
func (p *parser) parseBlock() []nir.Stmt {
	if p.accept("{") {
		out := p.parseStatements()
		p.accept("}")
		return out
	}
	return p.parseStatement()
}

func (p *parser) parseStatement() []nir.Stmt {
	L := p.loc()
	t := p.cur()
	if t.kind == tokPunct {
		switch t.text {
		case ";":
			p.next()
			return nil
		case "{":
			p.next()
			body := p.parseStatements()
			p.accept("}")
			return []nir.Stmt{nir.Block{Stmts: body}}
		case "[":
			p.readMetadata()
			return nil
		}
	}
	if t.kind == tokIdent {
		switch t.text {
		case "var", "const":
			return p.parseVarDecl()
		case "function":
			// a named nested function; an anonymous one is an expression
			if p.peek(1).kind == tokIdent {
				return []nir.Stmt{p.parseFunction(false)}
			}
		case "class", "interface":
			return []nir.Stmt{p.parseClass()}
		case "if":
			return []nir.Stmt{p.parseIf()}
		case "for":
			return p.parseFor()
		case "while":
			p.next()
			cond := p.parseParenExpr()
			return []nir.Stmt{nir.Loop{Cond: cond, Body: p.parseBlock(), Loc: L}}
		case "do":
			p.next()
			body := p.parseBlock()
			var cond nir.Expr
			if p.acceptWord("while") {
				cond = p.parseParenExpr()
			}
			p.accept(";")
			return []nir.Stmt{nir.Loop{Cond: cond, Body: body, Loc: L}}
		case "switch":
			return []nir.Stmt{p.parseSwitch()}
		case "try":
			return []nir.Stmt{p.parseTry()}
		case "return":
			p.next()
			if p.at(";") || p.at("}") {
				p.accept(";")
				return []nir.Stmt{nir.Return{}}
			}
			v := p.parseExpr()
			p.accept(";")
			return []nir.Stmt{nir.Return{Value: v}}
		case "throw":
			p.next()
			v := p.parseExpr()
			p.accept(";")
			return []nir.Stmt{nir.Terminate{Value: v, Kind: "throw", Loc: L}}
		case "break", "continue":
			p.next()
			if p.cur().kind == tokIdent {
				p.next() // label
			}
			p.accept(";")
			return nil
		case "with":
			p.next()
			subject := p.parseParenExpr()
			body := p.parseBlock()
			return append([]nir.Stmt{nir.ExprStmt{Value: subject}}, nir.Block{Stmts: body})
		case "default":
			// `default xml namespace = …`; a case label never reaches here.
			if p.peek(1).kind == tokIdent {
				p.skipTo(";")
				return nil
			}
		}
		// a labelled statement: `outer: for (…)`
		if p.peek(1).kind == tokPunct && p.peek(1).text == ":" && !modifiers[t.text] {
			if isLabelStart(p.peek(2)) {
				p.next()
				p.next()
				return p.parseStatement()
			}
		}
	}
	return p.parseExprStatement()
}

// isLabelStart reports whether a token can begin the statement a label introduces.
// It keeps `x: y` inside an object literal from being read as a label.
func isLabelStart(t token) bool {
	if t.kind != tokIdent {
		return t.kind == tokPunct && t.text == "{"
	}
	switch t.text {
	case "for", "while", "do", "switch", "if", "try", "var", "const":
		return true
	}
	return false
}

// parseVarDecl reads `var a:T = e, b:U;`. A declaration with no initializer still
// becomes an Assign so its DECLARED TYPE reaches resolution (nir.Assign.Type) and so
// a class body's members are discoverable from the statements it produced.
func (p *parser) parseVarDecl() []nir.Stmt {
	L := p.loc()
	p.next() // var / const
	var out []nir.Stmt
	for !p.eof() {
		if p.cur().kind != tokIdent {
			break
		}
		name := p.next().text
		typ := p.typeAnnotation()
		var val nir.Expr = nir.Const{Loc: L}
		if p.accept("=") {
			val = p.parseAssignExpr()
		}
		out = append(out, nir.Assign{Targets: []string{name}, Value: val, Type: typ, Decl: true, Loc: L})
		if !p.accept(",") {
			break
		}
	}
	p.accept(";")
	return out
}

func (p *parser) parseIf() nir.Stmt {
	L := p.loc()
	p.next() // if
	cond := p.parseParenExpr()
	then := p.parseBlock()
	var els []nir.Stmt
	if p.acceptWord("else") {
		els = p.parseBlock()
	}
	return nir.If{Cond: cond, Then: then, Else: els, Loc: L}
}

// parseFor covers all three ActionScript loop headers: the C-style `for (init; cond;
// step)`, `for (k in obj)` and the AS-only `for each (v in obj)`, which iterates
// VALUES rather than keys — the form that carries a flash-vars parameter into a
// method body.
func (p *parser) parseFor() []nir.Stmt {
	L := p.loc()
	p.next() // for
	p.acceptWord("each")
	if !p.accept("(") {
		return []nir.Stmt{nir.Loop{Body: p.parseBlock(), Loc: L}}
	}
	var init []nir.Stmt
	var vars []string
	if p.atWord("var") || p.atWord("const") {
		init = p.parseVarDeclNoSemi()
		for _, st := range init {
			if a, ok := st.(nir.Assign); ok {
				vars = append(vars, a.Targets...)
			}
		}
	} else if !p.at(";") {
		e, asg := p.parseAssignInfo()
		if asg != nil {
			init = p.assignStmts(asg)
		} else {
			init = []nir.Stmt{nir.ExprStmt{Value: e}}
			if nm, ok := e.(nir.Name); ok {
				vars = append(vars, nm.ID)
			}
		}
	}
	if p.acceptWord("in") {
		iter := p.parseExpr()
		p.accept(")")
		return []nir.Stmt{nir.Loop{Iter: iter, Vars: vars, Body: p.parseBlock(), Loc: L}}
	}
	p.accept(";")
	var cond nir.Expr
	if !p.at(";") {
		cond = p.parseExpr()
	}
	p.accept(";")
	var step []nir.Stmt
	if !p.at(")") {
		step = p.parseExprList()
	}
	p.accept(")")
	body := p.parseBlock()
	body = append(body, step...)
	return append(init, nir.Loop{Cond: cond, Body: body, Loc: L})
}

// parseVarDeclNoSemi is parseVarDecl for a `for` header, where the `;` terminates the
// header rather than the declaration.
func (p *parser) parseVarDeclNoSemi() []nir.Stmt {
	L := p.loc()
	p.next()
	var out []nir.Stmt
	for !p.eof() {
		if p.cur().kind != tokIdent {
			break
		}
		name := p.next().text
		typ := p.typeAnnotation()
		var val nir.Expr = nir.Const{Loc: L}
		if p.accept("=") {
			val = p.parseAssignExpr()
		}
		out = append(out, nir.Assign{Targets: []string{name}, Value: val, Type: typ, Decl: true, Loc: L})
		if !p.accept(",") {
			break
		}
	}
	return out
}

func (p *parser) parseSwitch() nir.Stmt {
	L := p.loc()
	p.next() // switch
	subject := p.parseParenExpr()
	sw := nir.Switch{Subject: subject, Loc: L}
	if !p.accept("{") {
		return sw
	}
	for !p.eof() && !p.at("}") {
		before := p.pos
		switch {
		case p.acceptWord("case"):
			label := p.parseAssignExpr()
			p.accept(":")
			sw.Cases = append(sw.Cases, p.parseCaseBody())
			sw.Labels = append(sw.Labels, []nir.Expr{label})
		case p.acceptWord("default"):
			p.accept(":")
			sw.Default = append(sw.Default, p.parseCaseBody()...)
		default:
			p.next()
		}
		if p.pos == before {
			p.next()
		}
	}
	p.accept("}")
	return sw
}

func (p *parser) parseCaseBody() []nir.Stmt {
	var out []nir.Stmt
	for !p.eof() && !p.at("}") && !p.atWord("case") && !p.atWord("default") {
		before := p.pos
		out = append(out, p.parseStatement()...)
		if p.pos == before {
			p.next()
		}
	}
	return out
}

func (p *parser) parseTry() nir.Stmt {
	L := p.loc()
	p.next() // try
	tr := nir.Try{Loc: L}
	tr.Body = p.parseBlock()
	for p.atWord("catch") {
		p.next()
		param := ""
		if p.accept("(") {
			if p.cur().kind == tokIdent {
				param = p.next().text
			}
			p.typeAnnotation()
			p.accept(")")
		}
		tr.Handlers = append(tr.Handlers, p.parseBlock())
		tr.HandlerParams = append(tr.HandlerParams, param)
	}
	if p.acceptWord("finally") {
		tr.Finally = p.parseBlock()
	}
	return tr
}

// parseExprStatement reads an expression statement, splitting an assignment into the
// NIR shape the lowering expects: a scalar target becomes an Assign, and a member or
// index target becomes a Method-less path call whose single argument is the value
// written (the field-write modelling the C#/Kotlin frontends also use).
func (p *parser) parseExprStatement() []nir.Stmt {
	out := p.parseExprList()
	p.accept(";")
	return out
}

func (p *parser) parseExprList() []nir.Stmt {
	var out []nir.Stmt
	for {
		before := p.pos
		e, asg := p.parseAssignInfo()
		if asg != nil {
			out = append(out, p.assignStmts(asg)...)
		} else if e != nil {
			out = append(out, nir.ExprStmt{Value: e})
		}
		if p.pos == before {
			p.next()
			return out
		}
		if !p.accept(",") {
			return out
		}
	}
}

func (p *parser) assignStmts(a *assignInfo) []nir.Stmt {
	switch target := a.target.(type) {
	case nir.Name:
		if a.op != "=" {
			return []nir.Stmt{nir.AugAssign{Target: target.ID, Value: a.value, Loc: a.loc}}
		}
		return []nir.Stmt{nir.Assign{Targets: []string{target.ID}, Value: a.value, Loc: a.loc}}
	case nir.Attr, nir.Index:
		return []nir.Stmt{nir.ExprStmt{Value: nir.Call{
			Callee: a.target,
			Args:   []nir.Expr{a.value},
			Path:   dotted(a.target),
			Method: "",
			Loc:    a.loc,
		}}}
	}
	return []nir.Stmt{nir.ExprStmt{Value: a.value}}
}

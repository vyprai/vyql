package parser

import (
	"fmt"
	"strconv"
	"strings"
)

type parser struct {
	toks []tok
	i    int
	pkg  string // current `package <namespace>` context
}

type parseError struct{ msg string }

func (e parseError) Error() string { return e.msg }

// Parse parses a VyQL program into a list of declarations.
func Parse(src string) (decls []Decl, err error) {
	toks, lerr := lex(src)
	if lerr != nil {
		return nil, lerr
	}
	p := &parser{toks: toks}
	defer func() {
		if r := recover(); r != nil {
			if pe, ok := r.(parseError); ok {
				err = pe
			} else {
				panic(r)
			}
		}
	}()
	decls = p.parseProgram()
	return decls, nil
}

func (p *parser) fail(format string, a ...any) {
	panic(parseError{fmt.Sprintf(format, a...)})
}

func (p *parser) peek() tok       { return p.toks[p.i] }
func (p *parser) peek2() tok      { return p.toks[p.i+1] }
func (p *parser) next() tok       { t := p.toks[p.i]; p.i++; return t }
func (p *parser) at(k tokKind) bool { return p.peek().kind == k }
func (p *parser) atWord(v string) bool {
	t := p.peek()
	return t.kind == tWord && t.val == v
}
func (p *parser) expect(k tokKind, what string) tok {
	t := p.peek()
	if t.kind != k {
		p.fail("expected %s, got %q at %d", what, t.val, t.pos)
	}
	return p.next()
}
func (p *parser) expectWord(v string) tok {
	t := p.peek()
	if t.kind != tWord || t.val != v {
		p.fail("expected %q, got %q at %d", v, t.val, t.pos)
	}
	return p.next()
}

func (p *parser) parseProgram() []Decl {
	var decls []Decl
	for !p.at(tEOF) {
		if p.at(tSemi) { // tolerate stray/terminating semicolons
			p.next()
			continue
		}
		// `package <namespace>;` sets the namespace for following declarations
		// (Go-style); definitions are short-named, cross-package refs qualified.
		if p.atWord("package") {
			p.next()
			p.pkg = p.parseQName()
			if p.at(tSemi) {
				p.next()
			}
			continue
		}
		decls = append(decls, p.parseDecl())
	}
	return decls
}

func (p *parser) parseDecl() Decl {
	switch {
	case p.atWord("rule"):
		return p.parseRule(false)
	case p.atWord("query"):
		return p.parseRule(true)
	case p.atWord("concept"):
		return p.parseConceptDecl()
	case p.atWord("adapter"):
		return p.parseAdapterDecl()
	case p.atWord("threat"):
		return p.parseThreatDecl()
	case p.atWord("state_machine"):
		return p.parseStateMachine()
	case p.atWord("profile"):
		return p.parseProfile()
	}
	p.fail("unexpected top-level token %q", p.peek().val)
	return nil
}

func (p *parser) parseQName() string {
	name := p.expect(tWord, "word").val
	for p.at(tDot) {
		p.next()
		name += "." + p.expect(tWord, "word").val
	}
	return name
}

func (p *parser) parseRule(isQuery bool) *Rule {
	p.next() // rule/query
	r := &Rule{Name: p.parseQName(), Package: p.pkg, Meta: map[string]any{}, IsQuery: isQuery}
	p.expect(tLBrace, "{")
	if p.atWord("meta") {
		r.Meta = p.parseMeta()
	}
	r.Body = p.parseBody()
	for p.atWord("where") || p.atWord("unless") || p.atWord("along") {
		r.Clauses = append(r.Clauses, p.parseClause())
	}
	p.expect(tRBrace, "}")
	return r
}

func (p *parser) parseMeta() map[string]any {
	p.expectWord("meta")
	p.expect(tLBrace, "{")
	out := map[string]any{}
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		out[key] = p.parseValue()
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *parser) parseValue() any {
	if p.at(tString) {
		return p.next().val
	}
	if p.at(tLBrack) {
		p.next()
		var items []string
		for !p.at(tRBrack) {
			items = append(items, p.next().val)
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return items
	}
	return p.next().val
}

func (p *parser) parseBody() Stmt {
	t := p.peek()
	if t.kind == tWord && FlowVerbs[t.val] {
		return p.parseFlowStmt()
	}
	if p.atWord("match") {
		return p.parseMatchStmt()
	}
	p.fail("expected flow or match statement, got %q at %d", t.val, t.pos)
	return nil
}

func (p *parser) parseFlowStmt() *FlowStmt {
	verb := p.next().val
	src := p.parseEndpoint()
	p.expect(tArrow, "->")
	dst := p.parseEndpoint()
	return &FlowStmt{Verb: verb, Src: src, Dst: dst}
}

func (p *parser) parseEndpoint() Endpoint {
	e := Endpoint{Concept: p.parseQName()} // concepts are namespaced (dotted)
	if p.atWord("as") {
		p.next()
		e.Binding = p.expect(tWord, "word").val
	}
	return e
}

func (p *parser) parseMatchStmt() *MatchStmt {
	p.expectWord("match")
	if p.atWord("transition") {
		p.next()
		m := &MatchStmt{TargetKind: "transition"}
		if p.at(tStar) {
			p.next()
			m.FromState = "*"
		} else {
			m.FromState = p.expect(tWord, "word").val
		}
		p.expect(tArrow, "->")
		m.ToState = p.expect(tWord, "word").val
		p.expectWord("on")
		m.Machine = p.expect(tWord, "word").val
		if p.atWord("as") {
			p.next()
			m.Binding = p.expect(tWord, "word").val
		}
		return m
	}
	// `match <concept> as id` — any concept, including action concepts. The
	// concept's `kind` (e.g. action) comes from the ontology, so no redundant
	// `action` keyword in the rule.
	m := &MatchStmt{TargetKind: "concept", Concept: p.parseQName()}
	if p.atWord("as") {
		p.next()
		m.Binding = p.expect(tWord, "word").val
	}
	return m
}

func (p *parser) parseClause() Clause {
	if p.atWord("where") {
		p.next()
		return Clause{Kind: "where", Where: p.parseExpr()}
	}
	if p.atWord("unless") {
		p.next()
		return Clause{Kind: "unless", Unless: p.parseException()}
	}
	if p.atWord("along") {
		p.next()
		p.expect(tLBrack, "[")
		var steps []string
		for !p.at(tRBrack) {
			steps = append(steps, p.next().val)
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return Clause{Kind: "along", Along: steps}
	}
	p.fail("bad clause")
	return Clause{}
}

func (p *parser) parseException() Exception {
	if p.atWord("sanitized_by") {
		p.next()
		return SanitizedBy{Concept: p.parseQName()}
	}
	if p.atWord("guarded_by") {
		p.next()
		return GuardedBy{Concept: p.parseQName()}
	}
	return ExprException{Expr: p.parseExpr()}
}

func (p *parser) parseExpr() Expr {
	parts := []Expr{p.parseAtom()}
	for p.atWord("and") {
		p.next()
		parts = append(parts, p.parseAtom())
	}
	if len(parts) > 1 {
		return And{Parts: parts}
	}
	return parts[0]
}

func (p *parser) parseAtom() Expr {
	if p.atWord("not") {
		p.next()
		return Not{Inner: p.parseAtom()}
	}
	t := p.peek()
	if t.kind == tWord && SolverVerbs[t.val] && p.peek2().kind == tLParen {
		return p.parseSolverCall()
	}
	ref := p.parseRef()
	if p.atWord("holds_asset_kind") {
		p.next()
		p.expect(tLBrack, "[")
		var kinds []string
		for !p.at(tRBrack) {
			kinds = append(kinds, p.parseQName())
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return HoldsAssetKind{Ref: ref, Kinds: kinds}
	}
	if p.atWord("has") {
		p.next()
		return Has{Ref: ref, Concept: p.parseQName()}
	}
	// `labeled <Concept>` — the node the ref resolves to carries the concept
	// (docs/11: `c.dst labeled threat.MiningPool`). Same semantics as `has`.
	if p.atWord("labeled") {
		p.next()
		return Has{Ref: ref, Concept: p.parseQName()}
	}
	// `[not] in [<set>]` — scalar set membership (docs/11: workload drift).
	if p.atWord("not") && p.peek2().kind == tWord && p.peek2().val == "in" {
		p.next() // not
		p.next() // in
		return NotIn{Ref: ref, Values: p.parseWordList(), Negate: true}
	}
	if p.atWord("in") {
		p.next()
		return NotIn{Ref: ref, Values: p.parseWordList(), Negate: false}
	}
	if p.atWord("is") {
		p.next()
		return Is{Ref: ref, Concept: p.parseQName()}
	}
	if p.at(tEq) || p.at(tNe) {
		op := p.next().val
		return Cmp{Ref: ref, Op: op, Value: p.parseValue()}
	}
	return ref
}

func (p *parser) parseSolverCall() SolverCall {
	call := SolverCall{Verb: p.next().val}
	p.expect(tLParen, "(")
	for !p.at(tRParen) {
		a := p.parseRef()
		if p.atWord("as") {
			p.next()
			binding := p.expect(tWord, "word").val
			call.Args = append(call.Args, Arg{Ref: a, Binding: binding})
			call.Binding = binding
		} else {
			call.Args = append(call.Args, Arg{Ref: a})
		}
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRParen, ")")
	return call
}

// parseWordList parses `[ a, b, c ]` of words/strings (set literals).
func (p *parser) parseWordList() []string {
	p.expect(tLBrack, "[")
	var items []string
	for !p.at(tRBrack) {
		if p.at(tString) {
			items = append(items, p.next().val)
		} else {
			items = append(items, p.parseQName())
		}
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrack, "]")
	return items
}

func (p *parser) parseRef() Ref {
	parts := []string{p.expect(tWord, "word").val}
	for p.at(tDot) {
		p.next()
		parts = append(parts, p.expect(tWord, "word").val)
	}
	return Ref{Parts: parts}
}

// parseConceptDecl parses `concept <QName> : <kind> { key: value … }`. The kind
// is the type annotation after the colon; the name takes the enclosing
// `package` namespace (or, if the header name is dotted, the dotted prefix).
func (p *parser) parseConceptDecl() *ConceptDecl {
	p.next() // 'concept'
	name := p.parseQName()
	cd := &ConceptDecl{Package: p.pkg, Fields: map[string]any{}}
	if i := lastDot(name); i >= 0 {
		cd.Package, cd.Name = name[:i], name[i+1:]
	} else {
		cd.Name = name
	}
	p.expect(tColon, ":")
	cd.Kind = p.expect(tWord, "word").val
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		cd.Fields[key] = p.parseConceptValue()
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return cd
}

// parseProfile parses `profile <name> { key: value … }` where values are strings
// or word/string lists (title, detect, entrypoints, packs).
func (p *parser) parseProfile() *ProfileDecl {
	p.next() // 'profile'
	pd := &ProfileDecl{Name: p.parseQName(), Fields: map[string]any{}}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		pd.Fields[key] = p.parseConceptValue()
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return pd
}

// parseAdapterDecl parses `adapter <tech> { meta {…}? (source|sink …)* }`
// (docs/07). Patterns are string literals (so any callee path, incl. ".URL.Query")
// or bare dotted names; each maps to a concept via `->`.
func (p *parser) parseAdapterDecl() *AdapterDecl {
	p.next() // 'adapter'
	a := &AdapterDecl{Name: p.parseQName(), Meta: map[string]any{}}
	p.expect(tLBrace, "{")
	if p.atWord("meta") {
		a.Meta = p.parseMeta()
	}
	for !p.at(tRBrace) {
		switch {
		case p.atWord("source"):
			p.next()
			kind := "source"
			if p.atWord("method") { // receiver-agnostic source: match the call method name
				p.next()
				kind = "source_method"
			}
			pat := p.parsePattern()
			p.expect(tArrow, "->")
			a.Mappings = append(a.Mappings, AdapterMapping{Kind: kind, Pattern: pat, Concept: p.parseQName()})
		case p.atWord("sink"):
			p.next()
			kind := "sink_path"
			if p.atWord("method") {
				p.next()
				kind = "sink_method"
			} else if p.atWord("receiver") {
				p.next()
				kind = "sink_receiver"
			} else if p.atWord("path") {
				p.next()
			}
			pat := p.parsePattern()
			m := AdapterMapping{Kind: kind, Pattern: pat}
			if p.atWord("arg") { // which argument is dangerous (default 0)
				p.next()
				if n, err := strconv.Atoi(p.expect(tWord, "arg index").val); err == nil {
					m.ArgIndex = n
				}
			}
			if p.atWord("on") { // optional receiver-type constraint (one type or [list])
				p.next()
				if p.at(tLBrack) {
					m.Constraint = strings.Join(p.parseWordList(), ",")
				} else {
					m.Constraint = p.parseQName()
				}
			}
			for p.atWord("val") { // every `val` must match some arg/option literal (AND)
				p.next()
				m.ValMatches = append(m.ValMatches, p.parsePattern())
			}
			for p.atWord("nval") { // no arg/option literal may contain any `nval`
				p.next()
				m.ValAbsents = append(m.ValAbsents, p.parsePattern())
			}
			p.expect(tArrow, "->")
			m.Concept = p.parseQName()
			a.Mappings = append(a.Mappings, m)
		case p.atWord("control"):
			p.next()
			pat := p.parsePattern()
			p.expect(tArrow, "->")
			a.Mappings = append(a.Mappings, AdapterMapping{Kind: "control", Pattern: pat, Concept: p.parseQName()})
		case p.atWord("mark"):
			// `mark "fn" [val "x"] -> concept` labels the matching CALL node with a
			// presence concept (for `match`-style rules — no taint flow).
			p.next()
			pat := p.parsePattern()
			mk := AdapterMapping{Kind: "mark", Pattern: pat}
			for p.atWord("val") {
				p.next()
				mk.ValMatches = append(mk.ValMatches, p.parsePattern())
			}
			for p.atWord("nval") {
				p.next()
				mk.ValAbsents = append(mk.ValAbsents, p.parsePattern())
			}
			p.expect(tArrow, "->")
			mk.Concept = p.parseQName()
			a.Mappings = append(a.Mappings, mk)
		case p.atWord("type"):
			p.next()
			pat := p.parsePattern()
			p.expect(tArrow, "->")
			a.Mappings = append(a.Mappings, AdapterMapping{Kind: "type", Pattern: pat, Concept: p.parseQName()})
		default:
			p.fail("bad adapter member %q at %d", p.peek().val, p.peek().pos)
		}
	}
	p.expect(tRBrace, "}")
	return a
}

// parsePattern reads a callee-path/method pattern: a string literal (preferred,
// handles dots / leading dots) or a bare dotted name.
func (p *parser) parsePattern() string {
	if p.at(tString) {
		return p.next().val
	}
	return p.parseQName()
}

// parseThreatDecl parses `threat <ns>.<Name> { cwe: [...] desc: "…" }`.
func (p *parser) parseThreatDecl() *ThreatDecl {
	p.next() // 'threat'
	name := p.parseQName()
	t := &ThreatDecl{Package: p.pkg, Fields: map[string]any{}}
	if i := lastDot(name); i >= 0 {
		t.Package, t.Name = name[:i], name[i+1:]
	} else {
		t.Name = name
	}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		t.Fields[key] = p.parseConceptValue()
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return t
}

// parseConceptValue parses a concept-field value: a string, a qualified name, or
// a bracketed list of either (so qualified refs like
// `deserialization.DeserializationAbuse` survive inside `[...]`).
func (p *parser) parseConceptValue() any {
	if p.at(tString) {
		return p.next().val
	}
	if p.at(tLBrack) {
		p.next()
		var items []string
		for !p.at(tRBrack) {
			if p.at(tString) {
				items = append(items, p.next().val)
			} else {
				items = append(items, p.parseQName())
			}
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return items
	}
	return p.parseQName()
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func (p *parser) parseStateMachine() *StateMachine {
	p.expectWord("state_machine")
	sm := &StateMachine{Name: p.expect(tWord, "word").val}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		switch {
		case p.atWord("states"):
			p.next()
			p.expect(tLBrack, "[")
			for !p.at(tRBrack) {
				sm.States = append(sm.States, p.expect(tWord, "word").val)
				if p.at(tComma) {
					p.next()
				}
			}
			p.expect(tRBrack, "]")
		case p.atWord("initial"):
			p.next()
			sm.Initial = p.expect(tWord, "word").val
		case p.atWord("transition"):
			p.next()
			a := p.expect(tWord, "word").val
			p.expect(tArrow, "->")
			b := p.expect(tWord, "word").val
			sm.Transitions = append(sm.Transitions, [2]string{a, b})
		default:
			p.fail("bad state_machine member %q", p.peek().val)
		}
	}
	p.expect(tRBrace, "}")
	return sm
}

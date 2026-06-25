package parser

import (
	"fmt"
	"strconv"
	"strings"
)

type parser struct {
	toks            []tok
	i               int
	pkg             string // current `module <namespace>` context
	imports         map[string]string
	wildcardImports []string
}

type parseError struct{ msg string }

func (e parseError) Error() string { return e.msg }

// Parse parses a VyQL program into a list of declarations.
func Parse(src string) (decls []Decl, err error) {
	toks, lerr := lex(src)
	if lerr != nil {
		return nil, lerr
	}
	p := &parser{toks: toks, imports: map[string]string{}}
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

func (p *parser) peek() tok         { return p.toks[p.i] }
func (p *parser) peek2() tok        { return p.toks[p.i+1] }
func (p *parser) next() tok         { t := p.toks[p.i]; p.i++; return t }
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
		// `module <namespace>;` sets the namespace for following declarations;
		// definitions are short-named, cross-module refs qualified.
		if p.atWord("module") || p.atWord("package") {
			p.next()
			p.pkg = p.parseQName()
			if p.at(tSemi) {
				p.next()
			}
			continue
		}
		// `import code.SomeConcept;`, `import code.*;`, and
		// `import code.{A, B};` make concept references shorter
		// in rule/adapter bodies without changing declaration namespaces.
		if p.atWord("import") {
			p.parseImportDecl()
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
	case p.atWord("review"):
		return p.parseReviewDecl()
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

func (p *parser) parseImportDecl() {
	p.next() // 'import'
	prefix := p.expect(tWord, "word").val
	for p.at(tDot) {
		p.next()
		switch {
		case p.at(tStar):
			p.next()
			p.wildcardImports = append(p.wildcardImports, prefix)
			return
		case p.at(tLBrace):
			p.next()
			for !p.at(tRBrace) {
				name := p.parseQName()
				p.imports[lastSeg(name)] = prefix + "." + name
				if p.at(tComma) {
					p.next()
				}
			}
			p.expect(tRBrace, "}")
			return
		default:
			prefix += "." + p.expect(tWord, "word").val
		}
	}
	alias := lastSeg(prefix)
	if p.atWord("as") {
		p.next()
		alias = p.expect(tWord, "word").val
	}
	p.imports[alias] = prefix
}

func (p *parser) parseConceptRef() string {
	return p.resolveConceptRef(p.parseQName())
}

func (p *parser) resolveConceptRef(name string) string {
	if strings.Contains(name, ".") {
		return name
	}
	if fq := p.imports[name]; fq != "" {
		return fq
	}
	switch len(p.wildcardImports) {
	case 0:
		return name
	case 1:
		return p.wildcardImports[0] + "." + name
	default:
		p.fail("ambiguous imported concept %q: multiple wildcard imports in scope", name)
	}
	return name
}

func (p *parser) parseSolverArgRef() Ref {
	ref := p.parseRef()
	if len(ref.Parts) != 1 {
		return ref
	}
	resolved := p.resolveConceptRef(ref.Parts[0])
	if resolved == ref.Parts[0] {
		return ref
	}
	return Ref{Parts: strings.Split(resolved, ".")}
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
	if p.atWord("order") {
		return p.parseOrderStmt()
	}
	p.fail("expected flow, match or order statement, got %q at %d", t.val, t.pos)
	return nil
}

// parseOrderStmt parses `order <conceptA> before <conceptB>`.
func (p *parser) parseOrderStmt() *OrderStmt {
	p.next() // 'order'
	first := p.parseEndpoint()
	if !p.atWord("before") {
		p.fail("expected 'before' in order statement at %d", p.peek().pos)
	}
	p.next()
	second := p.parseEndpoint()
	return &OrderStmt{First: first, Second: second}
}

func (p *parser) parseFlowStmt() *FlowStmt {
	verb := p.next().val
	src := p.parseEndpoint()
	p.expect(tArrow, "->")
	dst := p.parseEndpoint()
	return &FlowStmt{Verb: verb, Src: src, Dst: dst}
}

func (p *parser) parseEndpoint() Endpoint {
	e := Endpoint{Concept: p.parseConceptRef()} // concepts are namespaced (dotted)
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
	m := &MatchStmt{TargetKind: "concept", Concept: p.parseConceptRef()}
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
		return SanitizedBy{Concept: p.parseConceptRef()}
	}
	if p.atWord("guarded_by") {
		p.next()
		return GuardedBy{Concept: p.parseConceptRef()}
	}
	if p.atWord("closed_by") {
		p.next()
		return ClosedBy{Concept: p.parseConceptRef()}
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
			kinds = append(kinds, p.parseConceptRef())
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return HoldsAssetKind{Ref: ref, Kinds: kinds}
	}
	if p.atWord("has") {
		p.next()
		return Has{Ref: ref, Concept: p.parseConceptRef()}
	}
	// `labeled <Concept>` — the node the ref resolves to carries the concept.
	// Same semantics as `has`.
	if p.atWord("labeled") {
		p.next()
		return Has{Ref: ref, Concept: p.parseConceptRef()}
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
		return Is{Ref: ref, Concept: p.parseConceptRef()}
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
		a := p.parseSolverArgRef()
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
// `module` namespace (or, if the header name is dotted, the dotted prefix).
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
		a.Mappings = append(a.Mappings, p.parseAdapterMember()...)
	}
	p.expect(tRBrace, "}")
	return a
}

func (p *parser) parseAdapterMember() []AdapterMapping {
	switch {
	case p.atWord("package"):
		return p.parseAdapterPackageGroup()
	case p.atWord("source"):
		p.next()
		kind := "source"
		if p.atWord("param") { // public-API parameter source (library archetype): no pattern;
			p.next() // labels parameter nodes. A first-class source form like method/receiver.
			sm := AdapterMapping{Kind: "source_param"}
			p.parseAdapterGuards(&sm, true)
			p.expect(tArrow, "->")
			sm.Concept = p.parseConceptRef()
			return []AdapterMapping{sm}
		}
		if p.atWord("method") { // receiver-agnostic source: match the call method name
			p.next()
			kind = "source_method"
		} else if p.atWord("receiver") { // receiver-typed source: match attr/method on a known receiver type
			p.next()
			kind = "source_receiver"
		} else if p.atWord("path") { // explicit path form; equivalent to bare `source "a.b"`
			p.next()
		}
		pat := p.parsePattern()
		sm := AdapterMapping{Kind: kind, Pattern: pat}
		if p.atWord("on") {
			p.next()
			sm.Constraint = p.parsePattern()
		}
		p.parseAdapterGuards(&sm, true)
		p.expect(tArrow, "->")
		sm.Concept = p.parseConceptRef()
		return []AdapterMapping{sm}
	case p.atWord("sink"):
		p.next()
		kind := "sink_path"
		exact := false
		if p.atWord("method") {
			p.next()
			kind = "sink_method"
		} else if p.atWord("receiver") {
			p.next()
			kind = "sink_receiver"
		} else if p.atWord("exact") {
			p.next()
			exact = true
		} else if p.atWord("path") {
			p.next()
		}
		pat := p.parsePattern()
		m := AdapterMapping{Kind: kind, Pattern: pat, Exact: exact}
		if p.atWord("arg") { // which argument position is targeted (default 0; `arg all` = every arg)
			p.next()
			if p.atWord("all") {
				p.next()
				m.ArgIndex = -1
			} else if n, err := strconv.Atoi(p.expect(tWord, "arg index").val); err == nil {
				m.ArgIndex = n
			}
		}
		if p.atWord("collection") { // also flag a Seq/collection-literal arg
			p.next()
			m.Collection = true
			if p.atWord("first") {
				p.next()
				m.CollectionFirst = true
				m.CollectionIndex = 0
			} else if p.at(tWord) {
				if n, err := strconv.Atoi(p.peek().val); err == nil {
					p.next()
					m.CollectionFirst = true
					m.CollectionIndex = n
				}
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
		p.parseAdapterGuards(&m, true)
		p.expect(tArrow, "->")
		m.Concept = p.parseConceptRef()
		return []AdapterMapping{m}
	case p.atWord("flow"):
		p.next()
		kind := "flow_path"
		if p.atWord("method") {
			p.next()
			kind = "flow_method"
		} else if p.atWord("prefix") {
			p.next()
			kind = "flow_prefix"
		} else if p.atWord("path") {
			p.next()
		}
		m := AdapterMapping{Kind: kind, Pattern: p.parsePattern(), FlowSourceArg: -1}
		p.expectWord("arg")
		dest, err := strconv.Atoi(p.expect(tWord, "destination arg index").val)
		if err != nil {
			p.fail("invalid destination arg index")
		}
		m.FlowDestArg = dest
		p.expectWord("from")
		switch {
		case p.atWord("result"):
			p.next()
			m.FlowSourceResult = true
		case p.atWord("args"):
			p.next()
			src, err := strconv.Atoi(p.expect(tWord, "source arg start index").val)
			if err != nil {
				p.fail("invalid source arg index")
			}
			m.FlowSourceArg = src
		default:
			p.fail("expected result or args after flow source")
		}
		return []AdapterMapping{m}
	case p.atWord("control"):
		// `control "fn" [val "x"] [nval "y"] -> concept` labels a sanitizer/validator on
		// the matching CALL node so `unless sanitized_by` can kill a flow through it. The
		// optional val/nval gate value-based hardening (e.g. resolve_entities=False).
		p.next()
		kind := "control"
		if p.atWord("receiver") {
			p.next()
			p.expectWord("method")
			kind = "control_receiver_method"
		} else if p.atWord("method") { // receiver-agnostic: match the call method name (e.g. .close())
			p.next()
			kind = "control_method"
		}
		pat := p.parsePattern()
		ctl := AdapterMapping{Kind: kind, Pattern: pat}
		p.parseAdapterGuards(&ctl, true)
		p.expect(tArrow, "->")
		ctl.Concept = p.parseConceptRef()
		return []AdapterMapping{ctl}
	case p.atWord("flag"):
		p.next()
		mk := AdapterMapping{Kind: "flag", Concept: p.parseConceptRef(), Flag: &AdapterFlag{}}
		switch {
		case p.atWord("on"):
			p.next()
			mk.Flag.NodeKind = p.expect(tWord, "flag node kind").val
		case p.atWord("in"):
			p.next()
			mk.Flag.Scope = p.expect(tWord, "flag scope").val
		default:
			p.fail("expected on/in after flag concept, got %q at %d", p.peek().val, p.peek().pos)
		}
		p.parseAdapterFlagBody(mk.Flag)
		return []AdapterMapping{mk}
	case p.atWord("mark"):
		// `mark "fn" [val "x"] -> concept` labels the matching CALL node with a
		// presence concept (for `match`-style rules — no taint flow).
		// `mark method "fn"` is receiver-agnostic, matching the bare method name.
		p.next()
		kind := "mark"
		exact := false
		if p.atWord("method") {
			p.next()
			kind = "mark_method"
		} else if p.atWord("exact") {
			p.next()
			exact = true
		} else if p.atWord("path") {
			p.next()
		}
		pat := p.parsePattern()
		mk := AdapterMapping{Kind: kind, Pattern: pat, Exact: exact}
		p.parseAdapterGuards(&mk, true)
		p.expect(tArrow, "->")
		mk.Concept = p.parseConceptRef()
		return []AdapterMapping{mk}
	case p.atWord("filter"):
		// `filter method "replace"` / `filter path "preg_replace"` marks a
		// character-filtering replace(pattern, repl). The adapter layer labels it
		// with the ontology concept tagged for the character-filter analysis role.
		p.next()
		kind := "filter_path"
		if p.atWord("method") {
			p.next()
			kind = "filter_method"
		} else if p.atWord("path") {
			p.next()
		}
		pat := p.parsePattern()
		fm := AdapterMapping{Kind: kind, Pattern: pat}
		if p.atWord("global") { // always-global replace (gsub/replaceAll/re.sub); else needs the /g flag
			p.next()
			fm.Constraint = "global"
		}
		p.parseAdapterGuards(&fm, false)
		return []AdapterMapping{fm}
	case p.atWord("assume"):
		// `assume guard method "check" -> code.Target` /
		// `assume sanitizer path "normalize" -> code.Target` declares an UNSOUND
		// neutralizer: a guard or transformer that *might* defuse the condition but cannot be
		// proven to. The engine never suppresses on it — instead the adapter layer
		// labels the node with the ontology concept tagged for the assumption role,
		// and the engine attaches an assumption note when it bears on a finding.
		p.next()
		mode := "guard"
		if p.atWord("sanitizer") {
			p.next()
			mode = "sanitizer"
		} else if p.atWord("guard") {
			p.next()
		}
		kind := "assume_" + mode + "_path"
		if p.atWord("method") {
			p.next()
			kind = "assume_" + mode + "_method"
		} else if p.atWord("path") {
			p.next()
		}
		pat := p.parsePattern()
		am := AdapterMapping{Kind: kind, Pattern: pat}
		p.parseAdapterGuards(&am, true)
		p.expect(tArrow, "->")
		am.About = p.parseConceptRef()
		return []AdapterMapping{am}
	case p.atWord("type"):
		p.next()
		pat := p.parsePattern()
		p.expect(tArrow, "->")
		return []AdapterMapping{{Kind: "type", Pattern: pat, Concept: p.parseQName()}}
	default:
		p.fail("bad adapter member %q at %d", p.peek().val, p.peek().pos)
		return nil
	}
}

func (p *parser) parseAdapterFlagBody(f *AdapterFlag) {
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		p.parseAdapterFlagItem(f)
		p.consumeAdapterItemSep()
	}
	p.expect(tRBrace, "}")
}

func (p *parser) parseAdapterFlagItem(f *AdapterFlag) {
	switch {
	case p.atWord("operand"):
		p.next()
		var op AdapterFlagOperand
		p.expect(tLBrace, "{")
		for !p.at(tRBrace) {
			op.Predicates = append(op.Predicates, p.parseAdapterFlagPredicate("operand"))
			p.consumeAdapterItemSep()
		}
		p.expect(tRBrace, "}")
		f.Operands = append(f.Operands, op)
	default:
		f.Predicates = append(f.Predicates, p.parseAdapterFlagPredicate("node"))
	}
}

func (p *parser) parseAdapterFlagPredicate(subject string) AdapterFlagPredicate {
	if p.atWord("not") {
		p.next()
		if !p.atWord("has") && !p.atWord("lacks") && !p.atWord("flows") {
			return p.parseAdapterFlagStructuredPredicate(subject, true)
		}
		pred := p.parseAdapterFlagPredicate(subject)
		pred.Negative = !pred.Negative
		return pred
	}
	if p.atWord("lacks") {
		p.next()
		if p.at(tString) {
			return AdapterFlagPredicate{Subject: subject, Property: "tokens", Op: "contains", Values: []string{p.parsePattern()}, Negative: true}
		}
		pred := p.parseAdapterFlagStructuredPredicate(subject, true)
		return pred
	}
	if p.atWord("has") {
		p.next()
		return AdapterFlagPredicate{Subject: subject, Property: "tokens", Op: "contains", Values: []string{p.parsePattern()}}
	}
	if p.atWord("flows") {
		p.next()
		if p.atWord("to") {
			p.next()
		}
		return p.parseAdapterFlagStructuredPredicate("flow_to", false)
	}
	return p.parseAdapterFlagStructuredPredicate(subject, false)
}

func (p *parser) parseAdapterFlagStructuredPredicate(subject string, neg bool) AdapterFlagPredicate {
	key := p.expect(tWord, "flag predicate").val
	switch key {
	case "path":
		exact := false
		if p.atWord("exact") {
			p.next()
			exact = true
		}
		return AdapterFlagPredicate{Subject: subject, Property: "path", Op: "match", Values: []string{p.parsePattern()}, Exact: exact, Negative: neg}
	case "method":
		if p.atWord("name") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "method:", neg)
		}
		return AdapterFlagPredicate{Subject: subject, Property: "method", Op: "equals", Values: []string{p.parsePattern()}, Negative: neg}
	case "op":
		return p.parseAdapterFlagValuePredicate(subject, "op", neg)
	case "prop":
		prop := p.parsePattern()
		return p.parseAdapterFlagValuePredicate(subject, prop, neg)
	case "identifier", "key":
		return p.parseAdapterFlagValuePredicate(subject, key, neg)
	case "lang":
		return p.parseAdapterFlagContextTokenPredicate(subject, "lang=", neg)
	case "name":
		return p.parseAdapterFlagContextTokenPredicate(subject, "name=", neg)
	case "function":
		return p.parseAdapterFlagContextTokenPredicate(subject, "function_name:", neg)
	case "class":
		if p.atWord("bases") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "class_bases=", neg)
		}
		if p.atWord("base") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "class_base:", neg)
		}
		if p.atWord("name") {
			p.next()
		}
		return p.parseAdapterFlagContextTokenPredicate(subject, "class_name:", neg)
	case "attr":
		if p.atWord("path") {
			p.next()
		}
		return p.parseAdapterFlagContextTokenPredicate(subject, "attr_path:", neg)
	case "call":
		if p.atWord("path") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "call_path:", neg)
		}
		if p.atWord("order") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "call_order:", neg)
		}
		if p.atWord("arg") {
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "call_arg:", neg)
		}
		if neg {
			return p.parseAdapterFlagValuePredicate("scope_call", "any", neg)
		}
		return p.parseAdapterFlagContextTokenPredicate(subject, "call:", neg)
	case "selector", "literal", "annotation", "expr", "binary", "assign", "field", "slice", "index", "trait", "bound", "var":
		prefix := key + ":"
		if key == "var" {
			prefix = "var_name:"
		}
		return p.parseAdapterFlagContextTokenPredicate(subject, prefix, neg)
	case "fact":
		name := p.expect(tWord, "fact name").val
		return p.parseAdapterFlagContextTokenPredicate(subject, name+"=", neg)
	case "token":
		name := p.expect(tWord, "token name").val
		return p.parseAdapterFlagContextTokenPredicate(subject, name+":", neg)
	case "decorator":
		return p.parseAdapterFlagContextTokenPredicate(subject, "decorator_path:", neg)
	case "param":
		switch {
		case p.atWord("name"):
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "param_name:", neg)
		case p.atWord("type"):
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "param_type:", neg)
		case p.atWord("index"):
			p.next()
			return p.parseAdapterFlagContextTokenPredicate(subject, "param_index:", neg)
		default:
			p.fail("expected param name/type/index at %d", p.peek().pos)
			return AdapterFlagPredicate{}
		}
	default:
		p.fail("unknown flag predicate %q at %d", key, p.peek().pos)
		return AdapterFlagPredicate{}
	}
}

func (p *parser) parseAdapterFlagContextTokenPredicate(subject, prefix string, neg bool) AdapterFlagPredicate {
	op := "contains"
	if p.atWord("contains") || p.atWord("contains_any") || p.atWord("equals") || p.atWord("any") {
		op = p.next().val
	}
	values := p.parsePatternList()
	for i, v := range values {
		values[i] = prefix + v
	}
	if op == "any" {
		op = "contains_any"
	}
	return AdapterFlagPredicate{Subject: subject, Property: "tokens", Op: op, Values: values, Negative: neg}
}

func (p *parser) parseAdapterFlagValuePredicate(subject, property string, neg bool) AdapterFlagPredicate {
	op := "contains"
	if p.atWord("contains") || p.atWord("contains_any") || p.atWord("equals") || p.atWord("any") {
		op = p.next().val
	}
	values := p.parsePatternList()
	if op == "any" {
		op = "equals_any"
	}
	return AdapterFlagPredicate{Subject: subject, Property: property, Op: op, Values: values, Negative: neg}
}

func (p *parser) consumeAdapterItemSep() {
	for p.at(tComma) || p.at(tSemi) {
		p.next()
	}
}

func (p *parser) parsePatternList() []string {
	if !p.at(tLBrack) {
		return []string{p.parsePattern()}
	}
	p.next()
	var out []string
	for !p.at(tRBrack) {
		out = append(out, p.parsePattern())
		if p.at(tComma) || p.at(tSemi) {
			p.next()
		}
	}
	p.expect(tRBrack, "]")
	return out
}

func (p *parser) parseAdapterPackageGroup() []AdapterMapping {
	p.next() // 'package'
	pkg := p.parsePattern()
	p.expect(tLBrace, "{")
	var mappings []AdapterMapping
	for !p.at(tRBrace) {
		if p.atWord("package") {
			p.fail("nested package adapter group %q at %d", p.peek().val, p.peek().pos)
		}
		for _, m := range p.parseAdapterMember() {
			m.Packages = append([]string{pkg}, m.Packages...)
			mappings = append(mappings, m)
		}
	}
	p.expect(tRBrace, "}")
	return mappings
}

// parseAdapterGuards reads optional per-mapping gates. val/nval are ANDed against
// literal call arguments.
func (p *parser) parseAdapterGuards(m *AdapterMapping, allowValues bool) {
	for {
		switch {
		case allowValues && p.atWord("val"):
			p.next()
			m.ValMatches = append(m.ValMatches, p.parsePattern())
		case allowValues && p.atWord("nval"):
			p.next()
			m.ValAbsents = append(m.ValAbsents, p.parsePattern())
		default:
			return
		}
	}
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

// parseReviewDecl parses `review <concept> { key: value … }`. Review metadata is
// presentation/triage data, not rule semantics; concept refs are resolved with the
// same imports as rules and adapters.
func (p *parser) parseReviewDecl() *ReviewDecl {
	p.next() // 'review'
	r := &ReviewDecl{Concept: p.parseConceptRef(), Fields: map[string]any{}}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		r.Fields[key] = p.parseConceptValue()
		if p.at(tComma) || p.at(tSemi) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return r
}

// parseConceptValue parses a concept-field value: a string, a qualified name, or
// a bracketed list of either, preserving qualified refs inside `[...]`.
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
				items = append(items, p.parseConceptRef())
			}
			if p.at(tComma) {
				p.next()
			}
		}
		p.expect(tRBrack, "]")
		return items
	}
	return p.parseConceptRef()
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func lastSeg(s string) string {
	if i := lastDot(s); i >= 0 {
		return s[i+1:]
	}
	return s
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

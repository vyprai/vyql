package parser

import (
	"fmt"
	"strconv"
	"strings"
)

type v2Parser struct {
	*parser
	module string
}

// ParseV2 parses the VyQL v2 language contract. It intentionally rejects v1
// production forms such as adapter/source/sink/flag/mark/package declarations.
func ParseV2(src string) (prog *V2Program, err error) {
	toks, lerr := lex(src)
	if lerr != nil {
		return nil, lerr
	}
	base := &parser{toks: toks, imports: map[string]string{}}
	p := &v2Parser{parser: base}
	defer func() {
		if r := recover(); r != nil {
			if pe, ok := r.(parseError); ok {
				err = pe
			} else {
				panic(r)
			}
		}
	}()
	prog = p.parseV2Program()
	if verr := ValidateV2(prog); verr != nil {
		return nil, verr
	}
	return prog, nil
}

func (p *v2Parser) parseV2Program() *V2Program {
	prog := &V2Program{}
	var decls []V2Decl
	moduleSeen := false
	declSeen := false
	for !p.at(tEOF) {
		if p.at(tSemi) {
			p.next()
			continue
		}
		switch {
		case p.atWord("module"):
			if moduleSeen || declSeen || len(prog.Uses) > 0 {
				p.fail("module declaration must appear once at the top of a VyQL v2 file")
			}
			moduleSeen = true
			p.next()
			p.module = p.parseQName()
			prog.Module = p.module
			if p.at(tSemi) {
				p.next()
			}
		case p.atWord("uses"):
			if !moduleSeen {
				p.fail("uses declaration requires a preceding module declaration")
			}
			if declSeen {
				p.fail("uses declarations must appear before VyQL v2 declarations")
			}
			p.next()
			u := V2Use{Name: p.parseV2UseName()}
			if p.atWord("as") {
				p.next()
				u.Alias = p.expect(tWord, "uses alias").val
			}
			prog.Uses = append(prog.Uses, u)
			if p.at(tSemi) {
				p.next()
			}
		case p.atWord("import"):
			p.fail("v1 syntax %q is not supported in VyQL v2; use uses", p.peek().val)
		default:
			if !moduleSeen && !p.atWord("adapter") && !p.atWord("source") && !p.atWord("sink") && !p.atWord("flag") && !p.atWord("mark") && !p.atWord("filter") && !p.atWord("package") {
				p.fail("VyQL v2 files require a module declaration before declarations")
			}
			declSeen = true
			decls = append(decls, p.parseV2Decl())
		}
	}
	prog.Decls = decls
	return prog
}

func (p *v2Parser) parseV2Decl() V2Decl {
	switch {
	case p.atWord("adapter"), p.atWord("source"), p.atWord("sink"), p.atWord("flag"), p.atWord("mark"), p.atWord("filter"):
		p.fail("v1 syntax %q is not supported in VyQL v2", p.peek().val)
	case p.atWord("package"):
		p.fail("v1 syntax %q is not supported in VyQL v2; use module or requires dependency(...)", p.peek().val)
	case p.atWord("concept"):
		return p.parseV2Concept()
	case p.atWord("threat"):
		return p.parseV2Threat()
	case p.atWord("pattern"):
		return p.parseV2Pattern()
	case p.atWord("matcher"):
		return p.parseV2Matcher()
	case p.atWord("binding"):
		return p.parseV2Binding()
	case p.atWord("rule"):
		return p.parseV2Rule()
	case p.atWord("review"):
		return p.parseV2Review()
	case p.atWord("profile"):
		return p.parseV2Profile()
	case p.atWord("pack"):
		return p.parseV2Pack()
	case p.atWord("mechanic"):
		return p.parseV2Mechanic()
	case p.atWord("policy"):
		return p.parseV2Policy()
	}
	p.fail("unexpected v2 top-level token %q at %d", p.peek().val, p.peek().pos)
	return nil
}

func (p *v2Parser) parseV2UseName() string {
	name := p.expect(tWord, "uses name").val
	for p.at(tDot) {
		p.next()
		if p.at(tStar) {
			p.fail("wildcard uses imports are rejected in VyQL v2 production definitions")
		}
		name += "." + p.expect(tWord, "uses name part").val
	}
	return name
}

func (p *v2Parser) parseV2Concept() *V2ConceptDecl {
	p.expectWord("concept")
	c := &V2ConceptDecl{Name: p.parseQName(), Module: p.module, Fields: map[string]any{}}
	p.expect(tColon, ":")
	c.Kind = p.expect(tWord, "concept kind").val
	c.Fields = p.parseV2FieldBlock()
	return c
}

func (p *v2Parser) parseV2Threat() *V2ThreatDecl {
	p.expectWord("threat")
	t := &V2ThreatDecl{Name: p.parseQName(), Module: p.module, Fields: p.parseV2FieldBlock()}
	return t
}

func (p *v2Parser) parseV2Pattern() *V2PatternDecl {
	p.expectWord("pattern")
	out := &V2PatternDecl{Name: p.parseQName()}
	if p.atWord("as") {
		p.next()
		out.Alias = p.expect(tWord, "pattern alias").val
	}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		switch {
		case p.atWord("unstable"):
			p.next()
			p.expect(tColon, ":")
			out.Items = append(out.Items, V2PatternItem{Kind: "unstable", Meta: p.parseV2FieldBlock()})
		case p.atWord("node"):
			p.next()
			p.expect(tColon, ":")
			out.Items = append(out.Items, V2PatternItem{Kind: "node", Name: p.parseQName()})
		case p.atWord("use"):
			p.next()
			item := V2PatternItem{Kind: "use", Name: p.parseQName()}
			p.expectWord("as")
			item.Alias = p.expect(tWord, "use alias").val
			out.Items = append(out.Items, item)
		case p.atWord("bind"):
			p.next()
			name := p.expect(tWord, "binding name").val
			p.expectValue("=")
			out.Items = append(out.Items, V2PatternItem{Kind: "bind", Name: name, Expr: p.parseV2ExprUntil(v2StopAtLineItem)})
		case p.atWord("where"):
			p.next()
			out.Items = append(out.Items, V2PatternItem{Kind: "where", Expr: p.parseV2ExprUntil(v2StopAtLineItem)})
		default:
			p.fail("unexpected pattern item %q at %d", p.peek().val, p.peek().pos)
		}
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2Matcher() *V2MatcherDecl {
	p.expectWord("matcher")
	out := &V2MatcherDecl{Name: p.parseQName()}
	p.expect(tLBrace, "{")
	for !p.at(tRBrace) {
		kind := p.expect(tWord, "matcher item").val
		p.expect(tColon, ":")
		if kind == "matches" {
			out.Items = append(out.Items, V2MatcherItem{Kind: kind, Values: []string{p.expect(tString, "regex string").val}})
		} else {
			out.Items = append(out.Items, V2MatcherItem{Kind: kind, Values: p.parseV2StringList()})
		}
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2Binding() *V2BindingDecl {
	p.expectWord("binding")
	out := &V2BindingDecl{Name: p.parseQName(), Module: p.module, Attrs: map[string]string{}}
	p.expect(tLBrace, "{")
	if p.atWord("requires") {
		out.Requirements = p.parseV2Requires()
	}
	if p.atWord("unstable") {
		p.next()
		p.expect(tColon, ":")
		out.Unstable = p.parseV2FieldBlock()
	}
	if !p.atWord("query") {
		p.fail("binding %s requires query before outputs", out.Name)
	}
	out.Query = p.parseV2BindingQuery()
	for !p.at(tRBrace) {
		switch {
		case p.atWord("emit"):
			out.Outputs = append(out.Outputs, p.parseV2Emit())
		case p.atWord("propagate"):
			out.Outputs = append(out.Outputs, p.parseV2Propagate())
		case p.atWord("fidelity"), p.atWord("confidence"):
			key := p.next().val
			p.expect(tColon, ":")
			out.Attrs[key] = p.expect(tWord, key+" value").val
		default:
			p.fail("unexpected binding item %q at %d", p.peek().val, p.peek().pos)
		}
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2Requires() []V2Requirement {
	p.expectWord("requires")
	p.expect(tLBrace, "{")
	var out []V2Requirement
	for !p.at(tRBrace) {
		out = append(out, p.parseV2Requirement())
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2Requirement() V2Requirement {
	name := p.parseQName()
	req := V2Requirement{Name: name}
	p.expect(tLParen, "(")
	for !p.at(tRParen) {
		if !p.at(tWord) && !p.at(tString) {
			p.fail("expected requirement argument, got %q at %d", p.peek().val, p.peek().pos)
		}
		if p.at(tWord) && p.peek2().kind == tColon {
			argName := p.next().val
			p.expect(tColon, ":")
			req.Args = append(req.Args, V2NamedArg{Name: argName, Value: p.parseV2RequirementValue()})
		} else {
			req.Args = append(req.Args, p.parseV2RequirementValue())
		}
		if p.at(tComma) {
			p.next()
			continue
		}
		if !p.at(tRParen) {
			p.fail("expected ',' or ')' in requirement, got %q at %d", p.peek().val, p.peek().pos)
		}
	}
	p.expect(tRParen, ")")
	return req
}

func (p *v2Parser) parseV2RequirementValue() any {
	if p.at(tString) {
		return p.next().val
	}
	if p.at(tWord) && p.peek2().kind == tLParen {
		return p.parseV2Requirement()
	}
	if p.at(tWord) {
		return p.parseQName()
	}
	p.fail("expected requirement value, got %q at %d", p.peek().val, p.peek().pos)
	return nil
}

func (p *v2Parser) parseV2BindingQuery() V2BindingQuery {
	p.expectWord("query")
	if p.atWord("pattern") {
		p.next()
		out := V2BindingQuery{Pattern: p.parseQName()}
		if p.atWord("where") {
			p.next()
			out.Where = p.parseV2ExprUntil(v2StopAtBindingItem)
		}
		return out
	}
	if p.looksLikeAmbiguousPatternQuery() {
		p.fail("named binding patterns must use query pattern <Name>; got ambiguous query %q", p.peek().val)
	}
	expr := p.parseV2QueryExpr(v2StopAtBindingItem)
	return V2BindingQuery{Expr: &expr}
}

func (p *v2Parser) parseV2Emit() V2BindingOutput {
	p.expectWord("emit")
	kind := p.expect(tWord, "emit kind").val
	out := V2BindingOutput{Kind: "emit " + kind, Concept: p.parseQName()}
	p.expectWord("at")
	out.Location = p.parseV2Location()
	if p.at(tLBrace) {
		p.next()
		for !p.at(tRBrace) {
			switch {
			case p.atWord("covers"):
				p.next()
				cov := V2Coverage{Mode: p.expect(tWord, "coverage mode").val, Items: map[string]any{}}
				cov.Items = p.parseV2FieldBlock()
				out.Covers = append(out.Covers, cov)
			case p.atWord("advisory"):
				p.next()
				p.expect(tColon, ":")
				v := p.parseV2Bool()
				out.Advisory = &v
			case p.atWord("about"):
				p.next()
				p.expect(tColon, ":")
				out.About = p.parseQName()
			default:
				p.fail("unexpected emit item %q at %d", p.peek().val, p.peek().pos)
			}
			p.consumeV2Separators()
		}
		p.expect(tRBrace, "}")
	}
	return out
}

func (p *v2Parser) parseV2Propagate() V2BindingOutput {
	p.expectWord("propagate")
	kind := p.expect(tWord, "propagate kind").val
	p.expectWord("from")
	from := p.parseV2Location()
	p.expectWord("to")
	to := p.parseV2Location()
	return V2BindingOutput{Kind: "propagate " + kind, From: from, To: to}
}

func (p *v2Parser) parseV2Rule() *V2RuleDecl {
	p.expectWord("rule")
	out := &V2RuleDecl{Name: p.parseQName(), Module: p.module, Meta: map[string]any{}}
	p.expect(tLBrace, "{")
	if p.atWord("meta") {
		out.Meta = p.parseMeta()
	}
	out.Body = p.parseV2RuleBody()
	for p.atWord("where") || p.atWord("unless") || p.atWord("with") || p.atWord("require") {
		out.Clauses = append(out.Clauses, p.parseV2RuleClause())
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2RuleBody() V2RuleBody {
	if p.atWord("match") {
		p.fail("v1 syntax %q is not supported in VyQL v2; use issue or fact", p.peek().val)
	}
	if p.atWord("query") {
		p.next()
		q := p.parseV2QueryExpr(v2StopAtSelect)
		p.expectWord("select")
		return V2RuleBody{Verb: "query", Query: &q, Select: p.expect(tWord, "selected alias").val}
	}
	verb := p.expect(tWord, "rule verb").val
	switch verb {
	case "taint", "flow", "reach", "grant", "assume":
		from := p.parseV2Endpoint()
		p.expect(tArrow, "->")
		return V2RuleBody{Verb: verb, From: from, To: p.parseV2Endpoint()}
	case "issue", "fact":
		return V2RuleBody{Verb: verb, Issue: p.parseV2Endpoint()}
	default:
		p.fail("unknown v2 rule verb %q at %d", verb, p.peek().pos)
	}
	return V2RuleBody{}
}

func (p *v2Parser) parseV2Endpoint() V2Endpoint {
	e := V2Endpoint{Concept: p.parseQName()}
	if p.atWord("as") {
		p.next()
		e.Alias = p.expect(tWord, "endpoint alias").val
	}
	return e
}

func (p *v2Parser) parseV2RuleClause() V2RuleClause {
	switch {
	case p.atWord("where"):
		p.next()
		return V2RuleClause{Kind: "where", Expr: p.parseV2ExprUntil(v2StopAtRuleClause)}
	case p.atWord("unless"):
		p.next()
		if p.atWord("sanitized_by") || p.atWord("guarded_by") || p.atWord("closed_by") {
			p.fail("v1 syntax %q is not supported in VyQL v2; use coveredBy", p.peek().val)
		}
		target := p.parseV2Location()
		p.expectWord("coveredBy")
		return V2RuleClause{Kind: "unless", Target: target, Coverage: lastSeg(target), Concept: p.parseQName()}
	case p.atWord("with"):
		p.next()
		p.expectWord("confidence")
		p.expectValue(">=")
		return V2RuleClause{Kind: "with", Value: p.expect(tWord, "confidence").val}
	case p.atWord("require"):
		p.next()
		p.expectWord("profile")
		return V2RuleClause{Kind: "require", Value: p.expect(tWord, "profile name").val}
	}
	p.fail("bad v2 rule clause %q at %d", p.peek().val, p.peek().pos)
	return V2RuleClause{}
}

func (p *v2Parser) parseV2Review() *V2ReviewDecl {
	p.expectWord("review")
	return &V2ReviewDecl{Concept: p.parseQName(), Fields: p.parseV2FieldBlock()}
}

func (p *v2Parser) parseV2Profile() *V2ProfileDecl {
	p.expectWord("profile")
	return &V2ProfileDecl{Name: p.parseQName(), Fields: p.parseV2FieldBlock()}
}

func (p *v2Parser) parseV2Pack() *V2PackDecl {
	p.expectWord("pack")
	return &V2PackDecl{Name: p.parseQName(), Fields: p.parseV2FieldBlock()}
}

func (p *v2Parser) parseV2Mechanic() *V2MechanicDecl {
	p.expectWord("mechanic")
	return &V2MechanicDecl{
		Kind:   p.expect(tWord, "mechanic kind").val,
		Name:   p.expect(tWord, "mechanic name").val,
		Module: p.module,
		Items:  p.parseV2BlockItems(),
	}
}

func (p *v2Parser) parseV2Policy() *V2PolicyDecl {
	p.expectWord("policy")
	return &V2PolicyDecl{
		Kind:   p.expect(tWord, "policy kind").val,
		Name:   p.expect(tWord, "policy name").val,
		Module: p.module,
		Items:  p.parseV2BlockItems(),
	}
}

func (p *v2Parser) parseV2BlockItems() []V2BlockItem {
	p.expect(tLBrace, "{")
	var out []V2BlockItem
	for !p.at(tRBrace) {
		out = append(out, p.parseV2BlockItem())
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2BlockItem() V2BlockItem {
	if p.atWord("when") {
		p.next()
		return V2BlockItem{Key: []string{"when"}, Value: p.parseV2LooseExprUntil(p.v2StopAtBlockItem)}
	}
	if p.atWord("emit") {
		p.next()
		item := V2BlockItem{Key: []string{"emit", p.expect(tWord, "emit kind").val}}
		item.Block = p.parseV2BlockItems()
		return item
	}

	first := p.expect(tWord, "block item").val
	item := V2BlockItem{Key: []string{first}}
	if p.at(tWord) && p.peek2().kind == tColon {
		item.Key = append(item.Key, p.next().val)
	}
	if p.at(tWord) && p.peek2().kind == tLBrace {
		item.Key = append(item.Key, p.next().val)
		item.Block = p.parseV2BlockItems()
		return item
	}
	if p.at(tColon) {
		p.next()
		item.Value = p.parseV2BlockValue()
		return item
	}
	if p.at(tLBrace) {
		item.Block = p.parseV2BlockItems()
		return item
	}
	p.fail("expected ':' or block after %q at %d", first, p.peek().pos)
	return item
}

func (p *v2Parser) parseV2BlockValue() any {
	switch {
	case p.at(tLBrack):
		return p.parseV2AnyList()
	case p.at(tLBrace):
		return p.parseV2BlockItems()
	case p.at(tString):
		return V2LiteralExpr{Value: p.next().val}
	case p.atWord("true"), p.atWord("false"):
		return V2LiteralExpr{Value: p.parseV2Bool()}
	case p.at(tWord) && isV2Number(p.peek().val):
		n, _ := strconv.Atoi(p.next().val)
		return V2LiteralExpr{Value: n}
	default:
		return p.parseV2LooseExprUntil(p.v2StopAtBlockItem)
	}
}

func (p *v2Parser) parseV2AnyList() []any {
	p.expect(tLBrack, "[")
	var out []any
	for !p.at(tRBrack) {
		switch {
		case p.at(tLBrace):
			out = append(out, p.parseV2BlockItems())
		case p.at(tString):
			out = append(out, p.next().val)
		case p.atWord("true"), p.atWord("false"):
			out = append(out, p.parseV2Bool())
		case p.at(tWord) && isV2Number(p.peek().val):
			n, _ := strconv.Atoi(p.next().val)
			out = append(out, n)
		default:
			out = append(out, p.parseV2Location())
		}
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrack, "]")
	return out
}

func (p *v2Parser) parseV2LooseExprUntil(stop func(tok) bool) V2Expr {
	var items []V2Expr
	for !stop(p.peek()) {
		start := p.i
		items = append(items, p.parseV2ExprUntil(stop))
		if p.i == start {
			p.fail("unsupported v2 expression token %q at %d", p.peek().val, p.peek().pos)
		}
		if p.at(tComma) || stop(p.peek()) {
			break
		}
		if !p.v2CanStartExpr(p.peek()) {
			p.fail("unsupported v2 expression tail %q at %d", p.peek().val, p.peek().pos)
		}
	}
	if len(items) == 1 {
		return items[0]
	}
	return V2SequenceExpr{Items: items}
}

func (p *v2Parser) parseV2QueryExpr(stop func(tok) bool) V2QueryExpr {
	out := V2QueryExpr{Family: p.parseQName()}
	if p.atWord("as") {
		p.next()
		out.Alias = p.expect(tWord, "query alias").val
	}
	if p.atWord("where") {
		p.next()
		out.Where = p.parseV2ExprUntil(v2StopAtQueryStepOr(stop))
	}
	for p.isV2Relation(p.peek()) && !stop(p.peek()) {
		step := V2QueryStep{Relation: p.next().val, Family: p.parseQName()}
		if p.atWord("as") {
			p.next()
			step.Alias = p.expect(tWord, "query alias").val
		}
		if p.atWord("where") {
			p.next()
			step.Where = p.parseV2ExprUntil(v2StopAtQueryStepOr(stop))
		}
		out.Steps = append(out.Steps, step)
	}
	return out
}

func (p *v2Parser) parseV2FieldBlock() map[string]any {
	p.expect(tLBrace, "{")
	out := map[string]any{}
	for !p.at(tRBrace) {
		key := p.expect(tWord, "field name").val
		p.expect(tColon, ":")
		out[key] = p.parseV2FieldValue()
		p.consumeV2Separators()
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *v2Parser) parseV2FieldValue() any {
	switch {
	case p.at(tString):
		return p.next().val
	case p.at(tLBrack):
		return p.parseV2WordList()
	case p.atWord("true"), p.atWord("false"):
		return p.parseV2Bool()
	case p.at(tLBrace):
		return p.parseV2FieldBlock()
	default:
		return p.parseV2Location()
	}
}

func (p *v2Parser) parseV2StringList() []string {
	p.expect(tLBrack, "[")
	var out []string
	for !p.at(tRBrack) {
		out = append(out, p.expect(tString, "string").val)
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrack, "]")
	return out
}

func (p *v2Parser) parseV2WordList() []string {
	p.expect(tLBrack, "[")
	var out []string
	for !p.at(tRBrack) {
		if p.at(tString) {
			out = append(out, p.next().val)
		} else {
			out = append(out, p.parseQName())
		}
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrack, "]")
	return out
}

func (p *v2Parser) parseV2Bool() bool {
	if p.atWord("true") {
		p.next()
		return true
	}
	p.expectWord("false")
	return false
}

func (p *v2Parser) parseV2ExprUntil(stop func(tok) bool) V2Expr {
	return p.parseV2Or(stop)
}

func (p *v2Parser) parseV2Or(stop func(tok) bool) V2Expr {
	left := p.parseV2And(stop)
	for !stop(p.peek()) && p.atWord("or") {
		op := p.next().val
		left = V2BinaryExpr{Op: op, Left: left, Right: p.parseV2And(stop)}
	}
	return left
}

func (p *v2Parser) parseV2And(stop func(tok) bool) V2Expr {
	left := p.parseV2Compare(stop)
	for !stop(p.peek()) && p.atWord("and") {
		op := p.next().val
		left = V2BinaryExpr{Op: op, Left: left, Right: p.parseV2Compare(stop)}
	}
	return left
}

func (p *v2Parser) parseV2Compare(stop func(tok) bool) V2Expr {
	left := p.parseV2Unary(stop)
	if stop(p.peek()) || p.at(tEOF) || p.at(tRParen) || p.at(tRBrack) {
		return left
	}
	op := ""
	switch {
	case p.at(tEq), p.at(tNe), p.at(tGe), p.at(tLe), p.at(tGt), p.at(tLt), p.at(tMatch):
		op = p.next().val
	case p.atWord("in"), p.atWord("contains"), p.atWord("startsWith"), p.atWord("endsWith"), p.atWord("matches"), p.atWord("is"):
		op = p.next().val
	case p.atWord("not") && p.peek2().kind == tWord && p.peek2().val == "in":
		p.next()
		p.next()
		op = "not in"
	default:
		return left
	}
	return V2BinaryExpr{Op: op, Left: left, Right: p.parseV2Unary(stop)}
}

func (p *v2Parser) parseV2Unary(stop func(tok) bool) V2Expr {
	if p.atWord("not") {
		p.next()
		return V2UnaryExpr{Op: "not", X: p.parseV2Unary(stop)}
	}
	return p.parseV2Primary(stop)
}

func (p *v2Parser) parseV2Primary(stop func(tok) bool) V2Expr {
	switch {
	case p.at(tString):
		return V2LiteralExpr{Value: p.next().val}
	case p.at(tLBrack):
		return V2LiteralExpr{Value: p.parseV2WordList()}
	case p.at(tLParen):
		p.next()
		expr := p.parseV2ExprUntil(func(t tok) bool { return t.kind == tRParen })
		p.expect(tRParen, ")")
		return expr
	case p.atWord("true"), p.atWord("false"):
		return V2LiteralExpr{Value: p.parseV2Bool()}
	case p.at(tWord):
		if isV2Number(p.peek().val) {
			n, _ := strconv.Atoi(p.next().val)
			return V2LiteralExpr{Value: n}
		}
		name := p.parseV2Location()
		if p.at(tLParen) {
			p.next()
			var args []V2Expr
			var namedArgs []V2NamedExprArg
			for !p.at(tRParen) {
				if p.at(tWord) && p.peek2().kind == tColon {
					argName := p.next().val
					p.next()
					namedArgs = append(namedArgs, V2NamedExprArg{
						Name: argName,
						Expr: p.parseV2ExprUntil(func(t tok) bool { return t.kind == tComma || t.kind == tRParen }),
					})
				} else {
					args = append(args, p.parseV2ExprUntil(func(t tok) bool { return t.kind == tComma || t.kind == tRParen }))
				}
				if p.at(tComma) {
					p.next()
				}
			}
			p.expect(tRParen, ")")
			return V2CallExpr{Name: name, Args: args, NamedArgs: namedArgs}
		}
		return V2RefExpr{Name: name}
	}
	p.fail("expected expression at %d, got %q", p.peek().pos, p.peek().val)
	return V2RefExpr{}
}

func isV2Number(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *v2Parser) parseV2Location() string {
	var b strings.Builder
	b.WriteString(p.expect(tWord, "location").val)
	for {
		switch {
		case p.at(tDot):
			b.WriteString(p.next().val)
			b.WriteString(p.expect(tWord, "location part").val)
		case p.at(tLBrack):
			b.WriteString(p.next().val)
			b.WriteString(p.expect(tWord, "index").val)
			p.expect(tRBrack, "]")
			b.WriteString("]")
		default:
			return b.String()
		}
	}
}

func (p *v2Parser) expectValue(v string) {
	if p.peek().val != v {
		p.fail("expected %q, got %q at %d", v, p.peek().val, p.peek().pos)
	}
	p.next()
}

func (p *v2Parser) consumeV2Separators() {
	for p.at(tComma) || p.at(tSemi) {
		p.next()
	}
}

func (p *v2Parser) looksLikeAmbiguousPatternQuery() bool {
	family := p.peek().val
	switch family {
	case "file", "dependency", "package", "language", "build", "repository", "manifest",
		"call", "memberAccess", "assignment", "binaryExpr", "literal", "function", "class", "import", "route", "config", "param",
		"concept", "finding", "exposure", "asset", "principal", "privilege", "state", "unstable":
		return false
	}
	return p.peek2().kind == tWord && p.peek2().val == "where"
}

func (p *v2Parser) isV2Relation(t tok) bool {
	if t.kind != tWord {
		return false
	}
	switch t.val {
	case "contains", "encloses", "references", "declaredIn", "importedBy", "sameScope", "sameReceiver", "dominates", "labeledAs", "flowsTo", "reaches", "coveredBy":
		return true
	}
	return false
}

func v2StopAtLineItem(t tok) bool {
	return t.kind == tRBrace || t.kind == tSemi || t.kind == tComma ||
		(t.kind == tWord && (t.val == "node" || t.val == "use" || t.val == "bind" || t.val == "where"))
}

func v2StopAtBindingItem(t tok) bool {
	return t.kind == tRBrace || (t.kind == tWord && (t.val == "emit" || t.val == "propagate" || t.val == "fidelity" || t.val == "confidence"))
}

func v2StopAtRuleClause(t tok) bool {
	return t.kind == tRBrace || (t.kind == tWord && (t.val == "where" || t.val == "unless" || t.val == "with" || t.val == "require"))
}

func v2StopAtSelect(t tok) bool {
	return t.kind == tEOF || t.kind == tRBrace || (t.kind == tWord && t.val == "select")
}

func v2StopAtQueryStepOr(stop func(tok) bool) func(tok) bool {
	return func(t tok) bool {
		if stop(t) {
			return true
		}
		return t.kind == tWord && (t.val == "encloses" || t.val == "references" ||
			t.val == "declaredIn" || t.val == "importedBy" || t.val == "sameScope" || t.val == "sameReceiver" ||
			t.val == "dominates" || t.val == "labeledAs" || t.val == "flowsTo" || t.val == "reaches" || t.val == "coveredBy")
	}
}

func (p *v2Parser) v2CanStartExpr(t tok) bool {
	return t.kind == tString || t.kind == tLBrack || t.kind == tLParen || t.kind == tWord
}

func (p *v2Parser) v2StopAtBlockItem(t tok) bool {
	if t.kind == tRBrace || t.kind == tComma || t.kind == tSemi || t.kind == tEOF {
		return true
	}
	if t.kind != tWord {
		return false
	}
	if p.peek2().kind == tColon {
		return true
	}
	if p.peek2().kind == tWord && p.peekN(2).kind == tColon {
		return true
	}
	if p.peek2().kind == tWord && p.peekN(2).kind == tLBrace {
		return true
	}
	return false
}

func (p *v2Parser) peekN(n int) tok {
	if p.i+n >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.i+n]
}

func (p *v2Parser) fail(format string, a ...any) {
	panic(parseError{fmt.Sprintf(format, a...)})
}

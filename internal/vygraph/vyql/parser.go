package vyql

import "fmt"

// Parse lexes and parses one .vyql file into a File. Errors carry 1-based
// line:col positions.
func Parse(src string) (*File, error) {
	toks, err := Lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	return p.parseFile()
}

type parser struct {
	toks []Token
	i    int
}

func (p *parser) cur() Token  { return p.toks[p.i] }
func (p *parser) pos() Pos    { return Pos{Line: p.cur().Line, Col: p.cur().Col} }
func (p *parser) next() Token { t := p.toks[p.i]; p.i++; return t }

func (p *parser) errorf(format string, args ...any) error {
	t := p.cur()
	return fmt.Errorf("%d:%d: %s", t.Line, t.Col, fmt.Sprintf(format, args...))
}

func (p *parser) isPunct(s string) bool {
	return p.cur().Kind == TokPunct && p.cur().Text == s
}

func (p *parser) isKeyword(kw string) bool {
	return p.cur().Kind == TokKeyword && p.cur().Text == kw
}

func (p *parser) expectPunct(s string) error {
	if !p.isPunct(s) {
		return p.errorf("expected %q, got %q", s, p.cur().Text)
	}
	p.next()
	return nil
}

func (p *parser) expectKeyword(kw string) error {
	if !p.isKeyword(kw) {
		return p.errorf("expected keyword %q, got %q", kw, p.cur().Text)
	}
	p.next()
	return nil
}

// expectName accepts a single-segment identifier.
func (p *parser) expectName(what string) (string, error) {
	if p.cur().Kind != TokIdent {
		return "", p.errorf("expected %s, got %q", what, p.cur().Text)
	}
	return p.next().Text, nil
}

// expectDotted accepts a single- or multi-segment name (concept, type, or module ref).
func (p *parser) expectDotted(what string) (string, error) {
	if p.cur().Kind != TokIdent && p.cur().Kind != TokDottedIdent {
		return "", p.errorf("expected %s, got %q", what, p.cur().Text)
	}
	return p.next().Text, nil
}

func (p *parser) parseFile() (*File, error) {
	f := &File{}
	if err := p.expectKeyword("module"); err != nil {
		return nil, err
	}
	name, err := p.expectName("module name")
	if err != nil {
		return nil, err
	}
	f.Module = name
	if err := p.expectPunct(";"); err != nil {
		return nil, err
	}
	for p.cur().Kind != TokEOF {
		if err := p.parseStmt(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (p *parser) parseStmt(f *File) error {
	switch {
	case p.isKeyword("concept"):
		c, err := p.parseConcept()
		if err != nil {
			return err
		}
		f.Concepts = append(f.Concepts, c)
	case p.isKeyword("threat"):
		th, err := p.parseThreat()
		if err != nil {
			return err
		}
		f.Threats = append(f.Threats, th)
	case p.isKeyword("adapter"):
		a, err := p.parseAdapter()
		if err != nil {
			return err
		}
		f.Adapters = append(f.Adapters, a)
	case p.isKeyword("rule"):
		r, err := p.parseRule()
		if err != nil {
			return err
		}
		f.Rules = append(f.Rules, r)
	case p.isKeyword("query"):
		q, err := p.parseQuery()
		if err != nil {
			return err
		}
		f.Queries = append(f.Queries, q)
	default:
		return p.errorf("expected a declaration (concept, threat, adapter, rule, query), got %q", p.cur().Text)
	}
	return nil
}

var conceptFields = map[string]bool{
	"taint": true, "vulnerable_to": true, "enabled_by": true,
	"neutralizes": true, "defends": true, "cwe": true, "capec": true,
}

func (p *parser) parseConcept() (ConceptDecl, error) {
	c := ConceptDecl{Pos: p.pos()}
	p.next() // concept
	name, err := p.expectDotted("concept name")
	if err != nil {
		return c, err
	}
	c.Name = name
	if err := p.expectPunct(":"); err != nil {
		return c, err
	}
	// Kinds: one or more single words joined by '|'. Kind words may be keywords
	// (source, sink, control, guard, label) or plain identifiers (asset, ...);
	// validation checks them against the closed set.
	for {
		if p.cur().Kind != TokKeyword && p.cur().Kind != TokIdent {
			return c, p.errorf("expected a kind, got %q", p.cur().Text)
		}
		c.Kinds = append(c.Kinds, p.next().Text)
		if p.isPunct("|") {
			p.next()
			continue
		}
		break
	}
	if err := p.expectPunct("{"); err != nil {
		return c, err
	}
	for !p.isPunct("}") {
		if p.cur().Kind != TokKeyword {
			return c, p.errorf("expected a concept field, got %q", p.cur().Text)
		}
		kw := p.next().Text
		if err := p.expectPunct(":"); err != nil {
			return c, err
		}
		switch kw {
		case "refines":
			ref, err := p.expectDotted("refines parent")
			if err != nil {
				return c, err
			}
			c.Refines = ref
		case "taint", "vulnerable_to", "enabled_by", "neutralizes", "defends", "cwe", "capec":
			list, err := p.parseIdentList()
			if err != nil {
				return c, err
			}
			switch kw {
			case "taint":
				c.Taint = list
			case "vulnerable_to":
				c.VulnerableTo = list
			case "enabled_by":
				c.EnabledBy = list
			case "neutralizes":
				c.Neutralizes = list
			case "defends":
				c.Defends = list
			case "cwe":
				c.CWE = list
			}
		default:
			return c, p.errorf("unknown concept field %q", kw)
		}
	}
	p.next() // }
	return c, nil
}

func (p *parser) parseIdentList() ([]string, error) {
	if err := p.expectPunct("["); err != nil {
		return nil, err
	}
	var out []string
	for !p.isPunct("]") {
		s, err := p.expectDotted("list member")
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	p.next() // ]
	return out, nil
}

func (p *parser) parseThreat() (ThreatDecl, error) {
	th := ThreatDecl{Pos: p.pos()}
	p.next() // threat
	name, err := p.expectName("threat name")
	if err != nil {
		return th, err
	}
	th.Name = name
	if err := p.expectPunct("{"); err != nil {
		return th, err
	}
	if p.isKeyword("subsumes") {
		p.next()
		if err := p.expectPunct(":"); err != nil {
			return th, err
		}
		list, err := p.parseIdentList()
		if err != nil {
			return th, err
		}
		th.Subsumes = list
	}
	if err := p.expectPunct("}"); err != nil {
		return th, err
	}
	return th, nil
}

func (p *parser) parseAdapter() (AdapterDecl, error) {
	a := AdapterDecl{Pos: p.pos(), Fidelity: "syntactic"}
	p.next() // adapter
	tech, err := p.expectName("technology name")
	if err != nil {
		return a, err
	}
	a.Tech = tech
	if err := p.expectPunct("{"); err != nil {
		return a, err
	}
	if p.isKeyword("meta") {
		p.next()
		if err := p.expectPunct("{"); err != nil {
			return a, err
		}
		for !p.isPunct("}") {
			if p.cur().Kind != TokIdent || p.cur().Text != "fidelity" {
				return a, p.errorf("expected fidelity in adapter meta, got %q", p.cur().Text)
			}
			p.next()
			if err := p.expectPunct(":"); err != nil {
				return a, err
			}
			fid, err := p.expectName("fidelity value (syntactic|resolved)")
			if err != nil {
				return a, err
			}
			a.Fidelity = fid
		}
		p.next() // }
	}
	for !p.isPunct("}") {
		b, err := p.parseBinding()
		if err != nil {
			return a, err
		}
		a.Bindings = append(a.Bindings, b)
	}
	p.next() // }
	return a, nil
}

var bindingKeywords = map[string]bool{
	"source": true, "sink": true, "control": true, "guard": true, "label": true,
}

func (p *parser) parseBinding() (BindingDecl, error) {
	b := BindingDecl{Pos: p.pos()}
	if p.cur().Kind != TokKeyword || !bindingKeywords[p.cur().Text] {
		return b, p.errorf("expected a binding keyword (source, sink, control, guard, label), got %q", p.cur().Text)
	}
	b.Keyword = p.next().Text
	m, err := p.parseMatcher()
	if err != nil {
		return b, err
	}
	b.Matcher = m
	if p.isKeyword("where") {
		p.next()
		w, err := p.parseExpr()
		if err != nil {
			return b, err
		}
		b.Where = w
	}
	if err := p.expectPunct("->"); err != nil {
		return b, err
	}
	c, err := p.expectDotted("concept")
	if err != nil {
		return b, err
	}
	b.Concept = c
	return b, nil
}

// parseMatcher accepts a matcher call or a bare string (sugar for code.path).
// Anything else — a bare number, a name, a field reference — is an error here,
// not merely an odd expression.
func (p *parser) parseMatcher() (Expr, error) {
	switch p.cur().Kind {
	case TokString:
		lit := Literal{Kind: TokString, Text: p.next().Text, Pos: p.pos()}
		return &Call{Name: "code.path", Args: []Expr{&lit}, Pos: lit.Pos}, nil
	case TokDottedIdent:
		e, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		if c, ok := e.(*Call); ok {
			return c, nil
		}
		return nil, p.errorf("a matcher must be a call or a string, got a bare name")
	default:
		return nil, p.errorf("a matcher must be a call or a string, got %q", p.cur().Text)
	}
}

func (p *parser) parseRule() (RuleDecl, error) {
	r := RuleDecl{Pos: p.pos()}
	p.next() // rule
	name, err := p.expectName("rule name")
	if err != nil {
		return r, err
	}
	r.Name = name
	if err := p.expectPunct("{"); err != nil {
		return r, err
	}
	if p.isKeyword("meta") {
		m, err := p.parseMeta()
		if err != nil {
			return r, err
		}
		r.Meta = m
	}
	body, err := p.parseBody(true)
	if err != nil {
		return r, err
	}
	r.Body = body
	if err := p.expectPunct("}"); err != nil {
		return r, err
	}
	return r, nil
}

func (p *parser) parseQuery() (QueryDecl, error) {
	q := QueryDecl{Pos: p.pos()}
	p.next() // query
	name, err := p.expectName("query name")
	if err != nil {
		return q, err
	}
	q.Name = name
	if err := p.expectPunct("("); err != nil {
		return q, err
	}
	for !p.isPunct(")") {
		param, err := p.expectName("parameter")
		if err != nil {
			return q, err
		}
		q.Params = append(q.Params, param)
		if p.isPunct(",") {
			p.next()
		}
	}
	p.next() // )
	if err := p.expectPunct("{"); err != nil {
		return q, err
	}
	body, err := p.parseBody(false)
	if err != nil {
		return q, err
	}
	q.Body = body
	for p.isKeyword("or") {
		p.next()
		if err := p.expectPunct("{"); err != nil {
			return q, err
		}
		alt, err := p.parseBody(false)
		if err != nil {
			return q, err
		}
		if err := p.expectPunct("}"); err != nil {
			return q, err
		}
		q.Alts = append(q.Alts, alt)
	}
	if err := p.expectPunct("}"); err != nil {
		return q, err
	}
	return q, nil
}

func (p *parser) parseMeta() (RuleMeta, error) {
	m := RuleMeta{HasMeta: true}
	p.next() // meta
	if err := p.expectPunct("{"); err != nil {
		return m, err
	}
	for !p.isPunct("}") {
		if p.cur().Kind != TokKeyword {
			return m, p.errorf("expected a meta field, got %q", p.cur().Text)
		}
		kw := p.next().Text
		if err := p.expectPunct(":"); err != nil {
			return m, err
		}
		switch kw {
		case "id":
			if p.cur().Kind != TokString {
				return m, p.errorf("meta id must be a string, got %q", p.cur().Text)
			}
			m.ID = unquote(p.next().Text)
		case "severity":
			s, err := p.expectName("severity")
			if err != nil {
				return m, err
			}
			m.Severity = s
		case "cwe":
			list, err := p.parseIdentList()
			if err != nil {
				return m, err
			}
			m.CWE = list
		case "confidence_floor":
			c, err := p.expectName("confidence_floor value")
			if err != nil {
				return m, err
			}
			m.ConfidenceFloor = c
		default:
			return m, p.errorf("unknown meta field %q", kw)
		}
	}
	p.next() // }
	return m, nil
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseBody parses a rule or query body. With emit=true the body must end in
// "-> finding|signal [unless ...]"; with emit=false it must end in "yield <var>".
func (p *parser) parseBody(emit bool) (RuleBody, error) {
	b := RuleBody{Pos: p.pos()}
	switch {
	case p.isKeyword("match"):
		pats, err := p.parseMatchClause()
		if err != nil {
			return b, err
		}
		b.Match = pats
	case p.isKeyword("taint"), p.isKeyword("reach"):
		s, err := p.parseFlowSugar()
		if err != nil {
			return b, err
		}
		b.Sugar = s
	case p.isKeyword("present"):
		p.next()
		c, err := p.expectDotted("concept")
		if err != nil {
			return b, err
		}
		b.Sugar = &Sugar{Verb: "present", From: c, FromPos: p.pos()}
	default:
		return b, p.errorf("expected match, taint, reach, or present, got %q", p.cur().Text)
	}
	if p.isKeyword("where") {
		p.next()
		w, err := p.parseExpr()
		if err != nil {
			return b, err
		}
		b.Where = w
	}
	if emit {
		if err := p.expectPunct("->"); err != nil {
			return b, err
		}
		switch {
		case p.isKeyword("finding"):
			p.next()
			b.Emit = EmitFinding
		case p.isKeyword("signal"):
			p.next()
			b.Emit = EmitSignal
		default:
			return b, p.errorf("expected finding or signal, got %q", p.cur().Text)
		}
		if p.isKeyword("unless") {
			p.next()
			s, err := p.parseSuppressor()
			if err != nil {
				return b, err
			}
			b.Unless = s
		}
	} else {
		if err := p.expectKeyword("yield"); err != nil {
			return b, err
		}
		v, err := p.expectName("yielded variable")
		if err != nil {
			return b, err
		}
		b.Yield = v
	}
	return b, nil
}

func (p *parser) parseFlowSugar() (*Sugar, error) {
	s := &Sugar{Verb: p.next().Text}
	from, err := p.expectDotted("source concept")
	if err != nil {
		return nil, err
	}
	s.From, s.FromPos = from, p.pos()
	if err := p.expectPunct("->"); err != nil {
		return nil, err
	}
	to, err := p.expectDotted("sink concept")
	if err != nil {
		return nil, err
	}
	s.To, s.ToPos = to, p.pos()
	return s, nil
}

func (p *parser) parseSuppressor() (*Suppressor, error) {
	s := &Suppressor{Pos: p.pos()}
	switch {
	case p.isKeyword("sanitized_by"), p.isKeyword("guarded_by"), p.isKeyword("closed_by"):
		s.Kind = p.next().Text
		c, err := p.expectDotted("concept")
		if err != nil {
			return nil, err
		}
		s.Concept = c
	case p.isKeyword("anchored"):
		p.next()
		s.Kind = "anchored"
	default:
		return nil, p.errorf("expected a suppressor verb, got %q", p.cur().Text)
	}
	return s, nil
}

func (p *parser) parseMatchClause() ([]Pattern, error) {
	p.next() // match
	var pats []Pattern
	for {
		pat, err := p.parsePattern()
		if err != nil {
			return nil, err
		}
		pats = append(pats, pat)
		if p.isPunct(",") {
			p.next()
			continue
		}
		break
	}
	return pats, nil
}

func (p *parser) parsePattern() (Pattern, error) {
	var pat Pattern
	n, err := p.parseNodePattern()
	if err != nil {
		return pat, err
	}
	pat.Nodes = append(pat.Nodes, n)
	for p.isPunct("-[") || p.isPunct("<-[") {
		e, err := p.parseEdgePattern()
		if err != nil {
			return pat, err
		}
		n2, err := p.parseNodePattern()
		if err != nil {
			return pat, err
		}
		pat.Edges = append(pat.Edges, e)
		pat.Nodes = append(pat.Nodes, n2)
	}
	return pat, nil
}

func (p *parser) parseNodePattern() (NodePattern, error) {
	n := NodePattern{Pos: p.pos()}
	if err := p.expectPunct("("); err != nil {
		return n, err
	}
	// Optional binding variable: `x: Type`.
	if (p.cur().Kind == TokIdent) && p.toks[p.i+1].Kind == TokPunct && p.toks[p.i+1].Text == ":" {
		n.Var = p.next().Text
		p.next() // :
	}
	typ, err := p.expectDotted("node type or concept")
	if err != nil {
		return n, err
	}
	n.TypeOrConcept = typ
	if p.isPunct("{") {
		p.next()
		for !p.isPunct("}") {
			fname, err := p.expectName("field name")
			if err != nil {
				return n, err
			}
			if err := p.expectPunct(":"); err != nil {
				return n, err
			}
			if p.cur().Kind != TokString && p.cur().Kind != TokNumber && p.cur().Kind != TokBool {
				return n, p.errorf("expected a literal field value, got %q", p.cur().Text)
			}
			lit := p.next()
			n.Fields = append(n.Fields, FieldConst{Name: fname, Literal: &Literal{Kind: lit.Kind, Text: lit.Text, Pos: Pos{lit.Line, lit.Col}}})
		}
		p.next() // }
	}
	if err := p.expectPunct(")"); err != nil {
		return n, err
	}
	return n, nil
}

func (p *parser) parseEdgePattern() (EdgePattern, error) {
	e := EdgePattern{Pos: p.pos()}
	if p.isPunct("<-[") {
		e.Reverse = true
	}
	p.next() // -[ or <-[
	if err := p.expectPunct(":"); err != nil {
		return e, err
	}
	typ, err := p.expectName("edge type")
	if err != nil {
		return e, err
	}
	e.Type = typ
	if e.Reverse {
		if err := p.expectPunct("]-"); err != nil {
			return e, err
		}
	} else {
		if err := p.expectPunct("]->"); err != nil {
			return e, err
		}
	}
	return e, nil
}

// ---- expressions ----

var binOps = map[string]bool{
	"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
	"in": true, "matches": true, "contains": true, "starts_with": true, "under": true,
	"has": true,
}

func (p *parser) parseExpr() (Expr, error) { return p.parseOr() }

func (p *parser) parseOr() (Expr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("or") {
		pos := p.pos()
		p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &BinOp{Op: "or", L: l, R: r, Pos: pos}
	}
	return l, nil
}

func (p *parser) parseAnd() (Expr, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("and") {
		pos := p.pos()
		p.next()
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = &BinOp{Op: "and", L: l, R: r, Pos: pos}
	}
	return l, nil
}

func (p *parser) parseNot() (Expr, error) {
	if p.isKeyword("not") {
		p.next()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Not{X: x}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (Expr, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	op := ""
	switch {
	case p.cur().Kind == TokPunct && binOps[p.cur().Text]:
		op = p.cur().Text
	case p.cur().Kind == TokKeyword && binOps[p.cur().Text]:
		op = p.cur().Text
	}
	if op == "" {
		return l, nil
	}
	pos := p.pos()
	p.next()
	r, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return &BinOp{Op: op, L: l, R: r, Pos: pos}, nil
}

func (p *parser) parsePrimary() (Expr, error) {
	pos := p.pos()
	switch p.cur().Kind {
	case TokString:
		return &Literal{Kind: TokString, Text: p.next().Text, Pos: pos}, nil
	case TokNumber:
		return &Literal{Kind: TokNumber, Text: p.next().Text, Pos: pos}, nil
	case TokBool:
		return &Literal{Kind: TokBool, Text: p.next().Text, Pos: pos}, nil
	case TokPunct:
		if p.isPunct("(") {
			p.next()
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			return e, nil
		}
		return nil, p.errorf("unexpected %q in expression", p.cur().Text)
	case TokIdent:
		return &Name{Name: p.next().Text, Pos: pos}, nil
	case TokDottedIdent:
		text := p.next().Text
		if p.isPunct("(") {
			// A call: matcher (code.path) or builtin (any/all/count).
			p.next()
			var args []Expr
			for !p.isPunct(")") {
				a, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if p.isPunct(",") {
					p.next()
				}
			}
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			return &Call{Name: text, Args: args, Pos: pos}, nil
		}
		return splitDotted(text, pos), nil
	case TokKeyword:
		// any/all/count are keywords usable as call heads.
		if p.cur().Text == "any" || p.cur().Text == "all" || p.cur().Text == "count" {
			name := p.next().Text
			if err := p.expectPunct("("); err != nil {
				return nil, err
			}
			var args []Expr
			for !p.isPunct(")") {
				a, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
			}
			if err := p.expectPunct(")"); err != nil {
				return nil, err
			}
			return &Call{Name: name, Args: args, Pos: pos}, nil
		}
		return nil, p.errorf("unexpected keyword %q in expression", p.cur().Text)
	}
	return nil, p.errorf("unexpected %q in expression", p.cur().Text)
}

// splitDotted turns a dotted token into a var.field… reference.
func splitDotted(text string, pos Pos) *FieldRef {
	segs := splitSegments(text)
	return &FieldRef{Var: segs[0], Fields: segs[1:], Pos: pos}
}

func splitSegments(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

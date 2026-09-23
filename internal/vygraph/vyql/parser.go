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
	if p.isPunct(";") {
		p.next()
	} else if p.isPunct("{") {
		m, err := p.parseManifest(name)
		if err != nil {
			return nil, err
		}
		f.Manifest = m
	} else {
		return nil, p.errorf("expected ';' or a manifest block after module %q", name)
	}
	for p.cur().Kind != TokEOF {
		if err := p.parseStmt(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

var manifestImportKinds = map[string]bool{
	"pattern": true, "query": true, "concept": true, "adapter": true, "model": true,
}

// parseManifest parses the module block form: version, requires, imports, and
// the provenance tier that stamps every declaration in the module.
func (p *parser) parseManifest(name string) (*Manifest, error) {
	m := &Manifest{Module: name, Pos: p.pos()}
	p.next() // {
	for !p.isPunct("}") {
		if p.cur().Kind != TokIdent {
			return m, p.errorf("expected a manifest field, got %q", p.cur().Text)
		}
		field := p.next().Text
		switch field {
		case "version":
			if p.cur().Kind != TokString {
				return m, p.errorf("version must be a string, got %q", p.cur().Text)
			}
			m.Version = unquote(p.next().Text)
		case "requires":
			what, err := p.expectName("ontology or engine")
			if err != nil {
				return m, err
			}
			if p.cur().Kind != TokString {
				return m, p.errorf("requires %s must be a string, got %q", what, p.cur().Text)
			}
			v := unquote(p.next().Text)
			if what == "ontology" {
				m.RequiresOntology = v
			} else if what == "engine" {
				m.RequiresEngine = v
			} else {
				return m, p.errorf("requires takes ontology or engine, got %q", what)
			}
		case "import":
			kind := ""
			if (p.cur().Kind == TokIdent || p.cur().Kind == TokKeyword) && manifestImportKinds[p.cur().Text] {
				kind = p.next().Text
			}
			n, err := p.expectDotted("import name")
			if err != nil {
				return m, err
			}
			m.Imports = append(m.Imports, ManifestImport{Kind: kind, Name: n})
		case "provenance":
			tier, err := p.expectName("provenance tier")
			if err != nil {
				return m, err
			}
			switch tier {
			case "generated", "validated", "reviewed", "trusted":
				m.Provenance = tier
			default:
				return m, p.errorf("provenance must be generated, validated, reviewed, or trusted, got %q", tier)
			}
		case "authors":
			if p.cur().Kind != TokString {
				return m, p.errorf("authors must be a string, got %q", p.cur().Text)
			}
			p.next()
		default:
			return m, p.errorf("unknown manifest field %q", field)
		}
	}
	p.next() // }
	if m.Provenance == "" {
		m.Provenance = "trusted" // the module ships with the knowledge base by default
	}
	return m, nil
}

func (p *parser) parseLift() (LiftDecl, error) {
	l := LiftDecl{Pos: p.pos()}
	p.next() // lift
	target, err := p.expectDotted("high type")
	if err != nil {
		return l, err
	}
	l.Target = target
	if err := p.expectKeyword("from"); err != nil {
		return l, err
	}
	switch {
	case p.isKeyword("framework"):
		p.next()
		name, err := p.expectName("framework name")
		if err != nil {
			return l, err
		}
		l.Framework = name
	case p.cur().Kind == TokIdent && p.cur().Text == "doc":
		// The doc-lift form: from doc where kind == "…" [at "path"] — selects
		// doc.* nodes by their inherited kind, optionally descended.
		p.next()
		l.FromDoc = true
		if !(p.isKeyword("where") || (p.cur().Kind == TokIdent && p.cur().Text == "where")) {
			return l, p.errorf("doc lifts need: where kind == \"…\"")
		}
		p.next()
		if p.cur().Kind != TokIdent || p.cur().Text != "kind" {
			return l, p.errorf("doc lifts select on kind")
		}
		p.next()
		if err := p.expectPunct("=="); err != nil {
			return l, err
		}
		if p.cur().Kind != TokString {
			return l, p.errorf("doc kind must be a string literal")
		}
		l.DocKind = unquote(p.next().Text)
		if p.cur().Kind == TokIdent && p.cur().Text == "at" {
			p.next()
			if p.cur().Kind != TokString {
				return l, p.errorf("at takes a path string")
			}
			l.At = unquote(p.next().Text)
		}
	default:
		m, err := p.parseMatcher()
		if err != nil {
			return l, err
		}
		l.From = m
	}
	if p.isKeyword("where") && !l.FromDoc {
		p.next()
		w, err := p.parseExpr()
		if err != nil {
			return l, err
		}
		l.Where = w
	}
	if err := p.expectPunct("{"); err != nil {
		return l, err
	}
	for !p.isPunct("}") {
		name, err := p.expectName("field name")
		if err != nil {
			return l, err
		}
		if err := p.expectPunct(":"); err != nil {
			return l, err
		}
		// The copy form: `from flows(self) by resolution` — copy the frontend's
		// resolved FLOWS facts rather than compute a native expression.
		if p.isKeyword("from") && p.toks[p.i+1].Kind == TokIdent && p.toks[p.i+1].Text == "flows" {
			p.next()
			for _, want := range []string{"flows", "(", "self", ")", "by", "resolution"} {
				if want == "(" || want == ")" {
					if err := p.expectPunct(want); err != nil {
						return l, err
					}
					continue
				}
				w, err := p.expectName(want)
				if err != nil {
					return l, err
				}
				_ = w
			}
			l.Copies = append(l.Copies, name)
			continue
		}
		v, err := p.parseExpr()
		if err != nil {
			return l, err
		}
		l.Fields = append(l.Fields, LiftField{Name: name, Value: v})
	}
	p.next() // }
	return l, nil
}

func (p *parser) parseRelate() (RelateDecl, error) {
	r := RelateDecl{Pos: p.pos()}
	p.next() // relate
	edge, err := p.expectName("edge name")
	if err != nil {
		return r, err
	}
	r.Edge = edge
	if err := p.expectKeyword("from"); err != nil {
		return r, err
	}
	from, err := p.expectDotted("high type")
	if err != nil {
		return r, err
	}
	r.From = from
	if err := p.expectKeyword("to"); err != nil {
		return r, err
	}
	to, err := p.expectDotted("high type")
	if err != nil {
		return r, err
	}
	r.To = to
	switch {
	case p.cur().Kind == TokIdent && p.cur().Text == "by":
		p.next()
		kind, err := p.expectName("derivation")
		if err != nil {
			return r, err
		}
		switch kind {
		case "resolution":
			r.By = "resolution"
		case "ref":
			// by ref <fieldA> == <TypeB>.<fieldB> — the key-equality join.
			r.By = "ref"
			if err := p.expectPunct("."); err != nil {
				return r, p.errorf("by ref names the from-field as .<field>")
			}
			r.FromField, err = p.expectName("from field")
			if err != nil {
				return r, err
			}
			if err := p.expectPunct("=="); err != nil {
				return r, err
			}
			r.ToField, err = p.expectDotted("type.field")
			if err != nil {
				return r, err
			}
		default:
			return r, p.errorf("derivation is by resolution, over FLOWS, or by ref")
		}
	case p.cur().Kind == TokIdent && p.cur().Text == "over":
		p.next()
		edgeType, err := p.expectName("edge type")
		if err != nil {
			return r, err
		}
		if edgeType != "FLOWS" {
			return r, p.errorf("over takes FLOWS in the 1c subset")
		}
		r.By = "FLOWS"
	default:
		return r, p.errorf("relate needs by resolution or over FLOWS")
	}
	return r, nil
}

func (p *parser) parseFramework() (FrameworkDecl, error) {
	fw := FrameworkDecl{Pos: p.pos()}
	p.next() // framework
	name, err := p.expectName("framework name")
	if err != nil {
		return fw, err
	}
	fw.Name = name
	if err := p.expectPunct("{"); err != nil {
		return fw, err
	}
	for !p.isPunct("}") {
		if p.cur().Kind != TokIdent || p.cur().Text != "route" {
			return fw, p.errorf("expected route, got %q", p.cur().Text)
		}
		p.next()
		if p.cur().Kind != TokIdent || p.cur().Text != "on" {
			return fw, p.errorf("expected on, got %q", p.cur().Text)
		}
		p.next()
		rt := RouteDecl{Pos: p.pos()}
		m, err := p.parseMatcher()
		if err != nil {
			return fw, err
		}
		rt.On = m
		if p.isKeyword("where") {
			p.next()
			w, err := p.parseExpr()
			if err != nil {
				return fw, err
			}
			rt.Where = w
		}
		if err := p.expectPunct("{"); err != nil {
			return fw, err
		}
		for !p.isPunct("}") {
			fld, err := p.expectName("method, path, or handler")
			if err != nil {
				return fw, err
			}
			if err := p.expectPunct(":"); err != nil {
				return fw, err
			}
			v, err := p.parseExpr()
			if err != nil {
				return fw, err
			}
			switch fld {
			case "method":
				rt.Method = v
			case "path":
				rt.Path = v
			case "handler":
				rt.Handler = v
			default:
				return fw, p.errorf("unknown route field %q", fld)
			}
		}
		p.next() // }
		fw.Routes = append(fw.Routes, rt)
	}
	p.next() // }
	return fw, nil
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
	case p.isKeyword("lift") && p.cur().Kind == TokKeyword:
		l, err := p.parseLift()
		if err != nil {
			return err
		}
		f.Lifts = append(f.Lifts, l)
	case p.isKeyword("relate"):
		r, err := p.parseRelate()
		if err != nil {
			return err
		}
		f.Relates = append(f.Relates, r)
	case p.isKeyword("framework"):
		fw, err := p.parseFramework()
		if err != nil {
			return err
		}
		f.Frameworks = append(f.Frameworks, fw)
	case p.cur().Kind == TokIdent && p.cur().Text == "guard_hint":
		p.next()
		if p.cur().Kind != TokIdent || p.cur().Text != "identifier" {
			return p.errorf("guard_hint syntax: identifier matches \"glob\"")
		}
		p.next()
		// "matches" is a lexer keyword (the string operator); accept it in the
		// hint position by kind.
		if !(p.isKeyword("matches") || (p.cur().Kind == TokIdent && p.cur().Text == "matches")) {
			return p.errorf("guard_hint syntax: identifier matches \"glob\"")
		}
		p.next()
		if p.cur().Kind != TokString {
			return p.errorf("guard_hint glob must be a string")
		}
		glob := unquote(p.next().Text)
		if err := p.expectPunct("->"); err != nil {
			return err
		}
		c, err := p.expectDotted("concept")
		if err != nil {
			return err
		}
		f.GuardHints = append(f.GuardHints, GuardHintDecl{Glob: glob, Concept: c, Pos: p.pos()})
	default:
		return p.errorf("expected a declaration (concept, threat, adapter, rule, query), got %q", p.cur().Text)
	}
	return nil
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
	if p.isKeyword("match") || p.cur().Kind == TokIdent && p.cur().Text == "deviates" {
		// The deviation clause follows the match that binds the members.
		if p.cur().Kind == TokIdent && p.cur().Text == "deviates" {
			d, err := p.parseDeviates()
			if err != nil {
				return b, err
			}
			b.Deviates = d
		}
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

// parseDeviates parses `deviates from peers by <sel> missing (guard|control)
// <Concept> [min_group N] [threshold F]`.
func (p *parser) parseDeviates() (*Deviates, error) {
	d := &Deviates{Pos: p.pos(), MinGroup: 8, Threshold: 0.8}
	p.next() // deviates
	for _, want := range []string{"from", "peers", "by"} {
		if !(p.isKeyword(want) || (p.cur().Kind == TokIdent && p.cur().Text == want)) {
			return d, p.errorf("deviates syntax: expected %q", want)
		}
		p.next()
	}
	sel, err := p.expectName("peer selector")
	if err != nil {
		return d, err
	}
	d.Selector = sel
	if !(p.isKeyword("missing") || (p.cur().Kind == TokIdent && p.cur().Text == "missing")) {
		return d, p.errorf("deviates needs: missing (guard|control) <Concept>")
	}
	p.next()
	kindTok := p.next()
	kind := kindTok.Text
	if !(kindTok.Kind == TokKeyword || kindTok.Kind == TokIdent) || (kind != "guard" && kind != "control") {
		return d, p.errorf("the feature kind is guard or control, got %q", kind)
	}
	c, err := p.expectDotted("feature concept")
	if err != nil {
		return d, err
	}
	d.Feature = c
	for {
		switch {
		case p.cur().Kind == TokIdent && p.cur().Text == "min_group":
			p.next()
			n := p.next()
			if n.Kind != TokNumber {
				return d, p.errorf("min_group takes an integer")
			}
			var v int
			if _, err := fmt.Sscanf(n.Text, "%d", &v); err != nil {
				return d, err
			}
			d.MinGroup = v
		case p.cur().Kind == TokIdent && p.cur().Text == "threshold":
			p.next()
			n := p.next()
			if n.Kind != TokNumber {
				return d, p.errorf("threshold takes a float")
			}
			var v float64
			if _, err := fmt.Sscanf(n.Text, "%f", &v); err != nil {
				return d, err
			}
			d.Threshold = v
		default:
			return d, nil
		}
	}
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
		// A leading dot is the lift field-map's source-relative reference: .name
		// reads the matched low node's field.
		if p.isPunct(".") {
			p.next()
			// The source-relative reference accepts a dotted path directly:
			// .metadata.name descends two keyed children of the doc origin.
			var name string
			var err error
			if p.cur().Kind == TokDottedIdent {
				name = p.next().Text
			} else {
				name, err = p.expectName("field name after '.'")
				if err != nil {
					return nil, err
				}
			}
			fields := splitSegments(name)
			for p.isPunct(".") {
				p.next()
				f, err := p.expectName("field name")
				if err != nil {
					return nil, err
				}
				fields = append(fields, f)
			}
			return &FieldRef{Var: "", Fields: fields, Pos: pos}, nil
		}
		return nil, p.errorf("unexpected %q in expression", p.cur().Text)
	case TokIdent:
		// A bare name followed by '(' is a call — a query reference (the
		// stratification checker keys on these) rather than a name.
		if p.toks[p.i+1].Kind == TokPunct && p.toks[p.i+1].Text == "(" {
			name := p.next().Text
			p.next() // (
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
			return &Call{Name: name, Args: args, Pos: pos}, nil
		}
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

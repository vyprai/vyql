package parser

import "fmt"

type parser struct {
	toks    []tok
	i       int
	imports map[string]string
}

type parseError struct{ msg string }

func (e parseError) Error() string { return e.msg }

func (p *parser) fail(format string, a ...any) {
	panic(parseError{fmt.Sprintf(format, a...)})
}

func (p *parser) peek() tok { return p.toks[p.i] }

func (p *parser) peek2() tok {
	if p.i+1 >= len(p.toks) {
		return p.toks[len(p.toks)-1]
	}
	return p.toks[p.i+1]
}

func (p *parser) next() tok {
	t := p.toks[p.i]
	p.i++
	return t
}

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

func (p *parser) parseQName() string {
	name := p.expect(tWord, "word").val
	for p.at(tDot) {
		p.next()
		name += "." + p.expect(tWord, "word").val
	}
	return name
}

func (p *parser) parseMeta() map[string]any {
	p.expectWord("meta")
	p.expect(tLBrace, "{")
	out := map[string]any{}
	for !p.at(tRBrace) {
		key := p.expect(tWord, "word").val
		p.expect(tColon, ":")
		out[key] = p.parseMetaValue()
		if p.at(tComma) {
			p.next()
		}
	}
	p.expect(tRBrace, "}")
	return out
}

func (p *parser) parseMetaValue() any {
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
	if p.atWord("true") {
		p.next()
		return true
	}
	if p.atWord("false") {
		p.next()
		return false
	}
	return p.parseQName()
}

func lastSeg(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[i+1:]
		}
	}
	return s
}

package parser

import "fmt"

type tokKind int

const (
	tEOF tokKind = iota
	tWord
	tString
	tArrow  // ->
	tEq     // ==
	tNe     // !=
	tLBrace // {
	tRBrace // }
	tLBrack // [
	tRBrack // ]
	tLParen // (
	tRParen // )
	tComma
	tColon
	tDot
	tStar
	tSemi
)

type tok struct {
	kind tokKind
	val  string
	pos  int
}

func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isWordCont(c byte) bool {
	// identifiers are [A-Za-z0-9_], namespaced with '.'. No dashes — CWE/CAPEC
	// refs use the underscore form (CWE_89), so they are bare identifiers.
	return isWordStart(c)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// lex tokenizes VyQL source. Identifiers are [A-Za-z0-9_] namespaced with '.';
// `->`/`==`/`!=` are matched before single symbols; `//` starts a line comment.
func lex(src string) ([]tok, error) {
	var toks []tok
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case isSpace(c):
			i++
		case c == '/' && i+1 < n && src[i+1] == '/': // line comment
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '-' && i+1 < n && src[i+1] == '>':
			toks = append(toks, tok{tArrow, "->", i})
			i += 2
		case c == '=' && i+1 < n && src[i+1] == '=':
			toks = append(toks, tok{tEq, "==", i})
			i += 2
		case c == '!' && i+1 < n && src[i+1] == '=':
			toks = append(toks, tok{tNe, "!=", i})
			i += 2
		case c == '"':
			start := i
			i++
			for i < n && src[i] != '"' {
				i++
			}
			if i >= n {
				return nil, fmt.Errorf("unterminated string at %d", start)
			}
			toks = append(toks, tok{tString, src[start+1 : i], start})
			i++
		case isWordStart(c):
			start := i
			i++
			for i < n && isWordCont(src[i]) {
				i++
			}
			toks = append(toks, tok{tWord, src[start:i], start})
		default:
			k, ok := symKind(c)
			if !ok {
				return nil, fmt.Errorf("lex error at %d: %q", i, string(c))
			}
			toks = append(toks, tok{k, string(c), i})
			i++
		}
	}
	toks = append(toks, tok{tEOF, "", n})
	return toks, nil
}

func symKind(c byte) (tokKind, bool) {
	switch c {
	case '{':
		return tLBrace, true
	case '}':
		return tRBrace, true
	case '[':
		return tLBrack, true
	case ']':
		return tRBrack, true
	case '(':
		return tLParen, true
	case ')':
		return tRParen, true
	case ',':
		return tComma, true
	case ':':
		return tColon, true
	case '.':
		return tDot, true
	case '*':
		return tStar, true
	case ';':
		return tSemi, true
	}
	return 0, false
}

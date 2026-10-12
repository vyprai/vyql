package vyql

import "strings"

// Lex scans src into tokens, tracking 1-based line/column positions. A lexical error
// (unterminated string, unexpected character) carries its position.
func Lex(src string) ([]Token, error) {
	var toks []Token
	line, col := 1, 1
	i := 0
	n := len(src)
	adv := func(k int) { // advance k runes' worth of bytes (ASCII grammar: 1 byte each)
		col += k
		i += k
	}
	newline := func() {
		line++
		col = 1
		i++
	}
	push := func(kind TokenKind, text string, l, c int) {
		toks = append(toks, Token{Kind: kind, Text: text, Line: l, Col: c})
	}

	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			newline()
		case c == ' ' || c == '\t' || c == '\r':
			adv(1)
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				adv(1)
			}
		case c == '"':
			startL, startC := line, col
			adv(1)
			var b strings.Builder
			closed := false
			for i < n {
				if src[i] == '\n' {
					break
				}
				if src[i] == '\\' && i+1 < n {
					b.WriteByte(src[i])
					b.WriteByte(src[i+1])
					adv(2)
					continue
				}
				if src[i] == '"' {
					adv(1)
					closed = true
					break
				}
				b.WriteByte(src[i])
				adv(1)
			}
			if !closed {
				return nil, lexError(startL, startC, "unterminated string")
			}
			push(TokString, src[i-(col-startC):i], startL, startC)
		case c >= '0' && c <= '9' || c == '-' && i+1 < n && src[i+1] >= '0' && src[i+1] <= '9':
			startC := col
			j := i
			if src[i] == '-' {
				adv(1)
			}
			for i < n && src[i] >= '0' && src[i] <= '9' {
				adv(1)
			}
			// Float literal: a dot followed by a digit extends the number (a
			// trailing dot with no digit stays a punct).
			if i+1 < n && src[i] == '.' && src[i+1] >= '0' && src[i+1] <= '9' {
				adv(1)
				for i < n && src[i] >= '0' && src[i] <= '9' {
					adv(1)
				}
			}
			push(TokNumber, src[j:i], line, startC)
		case isIdentStart(c):
			startL, startC, j := line, col, i
			segments := 1
			for i < n && isIdentPart(src[i]) {
				adv(1)
			}
			// Greedy dotted continuation: '.' immediately followed by an ident start
			// extends the name (code.HttpInput). A trailing '.' with nothing after it
			// does not.
			for i+1 < n && src[i] == '.' && isIdentStart(src[i+1]) {
				segments++
				adv(1)
				for i < n && isIdentPart(src[i]) {
					adv(1)
				}
			}
			text := src[j:i]
			_ = segments
			switch {
			case text == "true" || text == "false":
				push(TokBool, text, startL, startC)
			case keywords[text] && segments == 1:
				push(TokKeyword, text, startL, startC)
			case segments > 1:
				push(TokDottedIdent, text, startL, startC)
			default:
				push(TokIdent, text, startL, startC)
			}
		default:
			matched := ""
			for _, p := range multiPunct {
				if strings.HasPrefix(src[i:], p) {
					matched = p
					break
				}
			}
			if matched == "" && singlePunct[c] {
				matched = string(c)
			}
			if matched == "" {
				return nil, lexError(line, col, "unexpected character "+string(rune(c)))
			}
			startC := col
			adv(len(matched))
			push(TokPunct, matched, line, startC)
		}
	}
	toks = append(toks, Token{Kind: TokEOF, Line: line, Col: col})
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

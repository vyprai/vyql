// Package actionscript is the source frontend for ActionScript (Flash/AIR `.as`).
//
// ActionScript has no maintained tree-sitter grammar, and it is not a dialect any
// grammar already carried here parses: a `.as` file opens with `package a.b { … }`,
// declares `private var x:String`, and writes `for each (var s:String in p)` — all
// syntax errors to the JavaScript grammar, which would leave the file as one ERROR
// node and no calls at all. So this frontend owns its own lexer and recursive-descent
// parser, and emits NIR (docs/20) directly.
//
// The grammar covered is ActionScript 3 (which subsumes the AS2 shapes still found in
// old Flash components): package/import directives, classes with typed members, typed
// functions, and the ECMAScript expression and statement set with the AS-only
// operators (`is`, `as`) and loop form (`for each`). It is deliberately
// error-tolerant: an unparsable construct is skipped to the next statement boundary
// rather than abandoning the file, because a frontend that gives up on one line of
// E4X would label nothing in the other five hundred.
package actionscript

import "strings"

type tokKind uint8

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokString
	tokRegex
	tokPunct
)

// token carries its source offsets so an expression can be re-read as text (the raw
// slice a Format node and a function's context tokens both need).
type token struct {
	kind  tokKind
	text  string // identifier, punctuation, or raw literal text
	val   string // decoded value, string literals only
	line  int    // 1-based
	start int
	end   int
}

// punctuation, longest match first.
var punctuators = []string{
	">>>=", "===", "!==", "<<=", ">>=", ">>>", "**=", "&&=", "||=", "??=", "...",
	"==", "!=", "<=", ">=", "&&", "||", "??", "++", "--", "+=", "-=", "*=", "/=",
	"%=", "&=", "|=", "^=", "<<", ">>", "::", "..", "=>", "**",
	"{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%",
	"&", "|", "^", "!", "~", "?", ":", "=", ".", "@",
}

// regexKeywords are the identifiers after which a `/` opens a regular expression
// rather than continuing an expression as division.
var regexKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "is": true,
	"as": true, "new": true, "delete": true, "void": true, "throw": true,
	"case": true, "do": true, "else": true,
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// lex tokenizes ActionScript source. Comments and whitespace are dropped; everything
// else becomes a token, including tokens the parser has no rule for (they are what
// the recovery path skips over).
func lex(src []byte) []token {
	var out []token
	line := 1
	i := 0
	n := len(src)
	if n >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		i = 3 // UTF-8 BOM: Flash authoring tools write one
	}
	// prev is the last emitted token, which decides whether `/` divides or opens a regex.
	prev := func() *token {
		if len(out) == 0 {
			return nil
		}
		return &out[len(out)-1]
	}
	for i < n {
		c := src[i]
		switch c {
		case '\n':
			line++
			i++
			continue
		case ' ', '\t', '\r', '\f', '\v':
			i++
			continue
		}
		if c == '/' && i+1 < n && src[i+1] == '/' {
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < n && src[i+1] == '*' {
			i += 2
			for i < n && !(src[i] == '*' && i+1 < n && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
			if i > n {
				i = n
			}
			continue
		}
		start, startLine := i, line
		switch {
		case isIdentStart(c):
			for i < n && isIdentPart(src[i]) {
				i++
			}
			out = append(out, token{kind: tokIdent, text: string(src[start:i]), line: startLine, start: start, end: i})
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(src[i+1])):
			i = scanNumber(src, i)
			out = append(out, token{kind: tokNumber, text: string(src[start:i]), line: startLine, start: start, end: i})
		case c == '"' || c == '\'':
			var val string
			i, val, line = scanString(src, i, line)
			out = append(out, token{kind: tokString, text: string(src[start:i]), val: val, line: startLine, start: start, end: i})
		case c == '/' && regexAllowed(prev()):
			end, ok := scanRegex(src, i)
			if !ok {
				i++ // not a regex after all: fall back to the division operator
				out = append(out, token{kind: tokPunct, text: "/", line: startLine, start: start, end: i})
				continue
			}
			i = end
			out = append(out, token{kind: tokRegex, text: string(src[start:i]), line: startLine, start: start, end: i})
		default:
			p := matchPunct(src, i)
			if p == "" {
				i++ // unknown byte: drop it rather than stall
				continue
			}
			i += len(p)
			out = append(out, token{kind: tokPunct, text: p, line: startLine, start: start, end: i})
		}
	}
	out = append(out, token{kind: tokEOF, line: line, start: n, end: n})
	return out
}

func matchPunct(src []byte, i int) string {
	rest := src[i:]
	for _, p := range punctuators {
		if len(rest) >= len(p) && string(rest[:len(p)]) == p {
			return p
		}
	}
	return ""
}

func regexAllowed(prev *token) bool {
	if prev == nil {
		return true
	}
	switch prev.kind {
	case tokIdent:
		return regexKeywords[prev.text]
	case tokNumber, tokString, tokRegex:
		return false
	}
	switch prev.text {
	case ")", "]", "}", "++", "--":
		return false
	}
	return true
}

func scanNumber(src []byte, i int) int {
	n := len(src)
	if src[i] == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X') {
		i += 2
		for i < n && (isDigit(src[i]) || (src[i]|0x20 >= 'a' && src[i]|0x20 <= 'f')) {
			i++
		}
		return i
	}
	seenDot, seenExp := false, false
	for i < n {
		c := src[i]
		switch {
		case isDigit(c):
		case c == '.' && !seenDot && !seenExp:
			seenDot = true
		case (c == 'e' || c == 'E') && !seenExp && i+1 < n && (isDigit(src[i+1]) || src[i+1] == '+' || src[i+1] == '-'):
			seenExp = true
			i++
		default:
			return i
		}
		i++
	}
	return i
}

// scanString consumes a quoted literal and returns the offset past it, the decoded
// value, and the updated line counter (ActionScript allows a literal to run over a
// line when the newline is escaped).
func scanString(src []byte, i, line int) (int, string, int) {
	quote := src[i]
	i++
	n := len(src)
	var b strings.Builder
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			i++
			e := src[i]
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case '0':
				b.WriteByte(0)
			case '\n':
				line++
			case 'u':
				// keep the escape text; the decoded rune is not what any matcher reads
				b.WriteString("\\u")
			case 'x':
				b.WriteString("\\x")
			default:
				b.WriteByte(e)
			}
			i++
			continue
		}
		if c == quote {
			return i + 1, b.String(), line
		}
		if c == '\n' {
			// an unterminated literal: stop at the line end so one stray quote does not
			// swallow the rest of the file.
			return i, b.String(), line
		}
		b.WriteByte(c)
		i++
	}
	return n, b.String(), line
}

// scanRegex consumes a `/…/flags` literal. It reports failure when the literal does
// not close on its own line, which is the sign that the `/` was really a division.
func scanRegex(src []byte, i int) (int, bool) {
	n := len(src)
	i++
	inClass := false
	for i < n {
		c := src[i]
		switch {
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			i++
			for i < n && isIdentPart(src[i]) {
				i++
			}
			return i, true
		case c == '\n':
			return 0, false
		}
		i++
	}
	return 0, false
}

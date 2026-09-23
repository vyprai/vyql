// Package vyql implements the v3 VyQL language surface: lexer, parser, semantic
// validation, the stratification checker, module loading, and plan evaluation over the
// Phase-1a graph store. It holds zero security knowledge: every concept, rule and
// technology name arrives as data. This is the v3 language; it shares nothing with the
// v2 language in internal/parser.
package vyql

import "fmt"

// TokenKind is a lexer token class.
type TokenKind uint8

const (
	TokIdent       TokenKind = iota // single-segment identifier
	TokDottedIdent                  // ident('.'ident)+ written contiguously, e.g. code.HttpInput
	TokString                       // double-quoted string literal (Text is the raw quoted form)
	TokNumber                       // integer literal
	TokBool                         // true | false
	TokKeyword                      // closed keyword set of the 1b grammar subset
	TokPunct                        // punctuation and operators
	TokEOF                          // end of input
)

func (k TokenKind) String() string {
	switch k {
	case TokIdent:
		return "ident"
	case TokDottedIdent:
		return "dottedIdent"
	case TokString:
		return "string"
	case TokNumber:
		return "number"
	case TokBool:
		return "bool"
	case TokKeyword:
		return "keyword"
	case TokPunct:
		return "punct"
	case TokEOF:
		return "eof"
	}
	return "invalid"
}

// Token is one lexed token with its 1-based source position.
type Token struct {
	Kind TokenKind
	Text string
	Line int
	Col  int
}

// keywords is the closed keyword set of the v3 grammar subset.
// A word is a keyword only when it stands alone:
// greedy dotted-ident scanning keeps code.HttpInput one token, so no keyword ever
// hides inside a dotted name.
var keywords = map[string]bool{
	"module": true, "concept": true, "threat": true, "adapter": true,
	"rule": true, "query": true, "match": true, "where": true, "yield": true,
	"meta":   true,
	"source": true, "sink": true, "control": true, "guard": true, "label": true,
	"refines": true, "taint": true, "vulnerable_to": true, "enabled_by": true,
	"neutralizes": true, "defends": true, "cwe": true, "subsumes": true,
	"severity": true, "id": true, "confidence_floor": true,
	"finding": true, "signal": true, "reach": true, "present": true,
	"unless": true, "sanitized_by": true, "guarded_by": true, "closed_by": true, "anchored": true,
	"and": true, "or": true, "not": true, "in": true, "any": true, "all": true,
	"count": true, "has": true,
	"under": true, "matches": true, "contains": true, "starts_with": true,
}

// multiPunct lists multi-character punctuation, longest-match first. Edge-pattern
// brackets (-[ ]-> <-[ ]-) must be tried before their prefixes; there is no bare
// minus in the 1b grammar, so an unmatched '-' is an error, which is the correct
// rejection of malformed edges.
var multiPunct = []string{
	"]->", "<-[", "->", "-[", "]-", "==", "!=", "<=", ">=",
}

// singlePunct are the one-character punctuation tokens. '.' is included so a spaced
// "a . b" lexes (the parser rejects it); the contiguous form never reaches here
// because the ident scanner consumes dotted names greedily.
var singlePunct = map[byte]bool{
	'{': true, '}': true, '(': true, ')': true, '[': true, ']': true,
	',': true, ';': true, ':': true, '|': true, '<': true, '>': true, '.': true,
}

func lexError(line, col int, msg string) error {
	return fmt.Errorf("%d:%d: %s", line, col, msg)
}

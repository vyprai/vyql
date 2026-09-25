package vyql

import (
	"os"
	"testing"
)

const toySrc = `module toy;
concept code.HttpInput : source { taint: [UntrustedData] cwe: [CWE_20] }
rule SqlInjection {
  meta { id: "TOY-001" severity: high cwe: [CWE_89] }
  taint code.HttpInput -> code.SqlExecution -> finding unless sanitized_by code.SqlParameterization
}
`

// wantTokens is the exact stream for toySrc. Kinds: kw=keyword, id=ident,
// dot=dottedIdent, str=string, p=punct.
var wantTokens = []struct {
	kind TokenKind
	text string
}{
	{TokKeyword, "module"}, {TokIdent, "toy"}, {TokPunct, ";"},
	{TokKeyword, "concept"}, {TokDottedIdent, "code.HttpInput"}, {TokPunct, ":"}, {TokKeyword, "source"}, {TokPunct, "{"}, {TokKeyword, "taint"}, {TokPunct, ":"}, {TokPunct, "["}, {TokIdent, "UntrustedData"}, {TokPunct, "]"}, {TokKeyword, "cwe"}, {TokPunct, ":"}, {TokPunct, "["}, {TokIdent, "CWE_20"}, {TokPunct, "]"}, {TokPunct, "}"},
	{TokKeyword, "rule"}, {TokIdent, "SqlInjection"}, {TokPunct, "{"},
	{TokKeyword, "meta"}, {TokPunct, "{"}, {TokKeyword, "id"}, {TokPunct, ":"}, {TokString, `"TOY-001"`}, {TokKeyword, "severity"}, {TokPunct, ":"}, {TokIdent, "high"}, {TokKeyword, "cwe"}, {TokPunct, ":"}, {TokPunct, "["}, {TokIdent, "CWE_89"}, {TokPunct, "]"}, {TokPunct, "}"},
	{TokKeyword, "taint"}, {TokDottedIdent, "code.HttpInput"}, {TokPunct, "->"}, {TokDottedIdent, "code.SqlExecution"}, {TokPunct, "->"}, {TokKeyword, "finding"}, {TokKeyword, "unless"}, {TokKeyword, "sanitized_by"}, {TokDottedIdent, "code.SqlParameterization"},
	{TokPunct, "}"},
	{TokEOF, ""},
}

func TestLexerTokenizesRepresentativeRule(t *testing.T) {
	toks, err := Lex(toySrc)
	if err != nil {
		t.Fatalf("Lex: %v", err)
	}
	if len(toks) != len(wantTokens) {
		t.Fatalf("got %d tokens, want %d", len(toks), len(wantTokens))
	}
	for i, w := range wantTokens {
		if toks[i].Kind != w.kind || toks[i].Text != w.text {
			t.Fatalf("token %d = (%v, %q), want (%v, %q)", i, toks[i].Kind, toks[i].Text, w.kind, w.text)
		}
	}
	// Position spot checks: 1-based line/col.
	if toks[0].Line != 1 || toks[0].Col != 1 {
		t.Fatalf("first token at %d:%d, want 1:1", toks[0].Line, toks[0].Col)
	}
	if toks[22].Text != "meta" || toks[22].Line != 4 || toks[22].Col != 3 {
		t.Fatalf("meta token = %+v, want line 4 col 3", toks[22])
	}
	if toks[36].Text != "taint" || toks[36].Line != 5 || toks[36].Col != 3 {
		t.Fatalf("taint token = %+v, want line 5 col 3", toks[36])
	}
}

func TestLexerTokenizesFixtureFile(t *testing.T) {
	src, err := os.ReadFile("testdata/toy.vyql")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	toks, err := Lex(string(src))
	if err != nil {
		t.Fatalf("Lex(fixture): %v", err)
	}
	if len(toks) != len(wantTokens) {
		t.Fatalf("fixture lexed to %d tokens, want %d (fixture must mirror toySrc)", len(toks), len(wantTokens))
	}
}

func TestLexerRejectsUnterminatedString(t *testing.T) {
	_, err := Lex("rule R { meta { id: \"unterminated } }")
	if err == nil {
		t.Fatal("an unterminated string must be a lex error")
	}
}

func TestLexerDottedIdentIsOneToken(t *testing.T) {
	toks, err := Lex("code . HttpInput")
	if err != nil {
		t.Fatal(err)
	}
	// With separators, the dot is not a valid token: ident, then '.' must fail or
	// split — the design says a dotted ident is ONE token only when written
	// contiguously; spaced components are three separate things the parser rejects.
	if len(toks) != 4 || toks[0].Kind != TokIdent || toks[1].Kind != TokPunct || toks[1].Text != "." || toks[2].Kind != TokIdent || toks[3].Kind != TokEOF {
		t.Fatalf("spaced form = %+v, want ident '.' ident eof", toks)
	}
}

func TestLexerNumberBoolComment(t *testing.T) {
	toks, err := Lex("1024 true false // trailing comment\nx")
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 5 {
		t.Fatalf("got %d tokens, want 5 (number,bool,bool,ident,eof)", len(toks))
	}
	if toks[0].Kind != TokNumber || toks[0].Text != "1024" {
		t.Fatalf("token 0 = %+v", toks[0])
	}
	if toks[1].Kind != TokBool || toks[1].Text != "true" || toks[2].Text != "false" {
		t.Fatalf("bools = %+v %+v", toks[1], toks[2])
	}
	if toks[3].Kind != TokIdent || toks[3].Text != "x" || toks[3].Line != 2 {
		t.Fatalf("after comment = %+v, want ident x on line 2", toks[3])
	}
	if toks[4].Kind != TokEOF {
		t.Fatalf("token 4 = %+v, want eof", toks[4])
	}
}

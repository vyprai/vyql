package treesitter

import (
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func TestReplaceNameClonesReplacementExpression(t *testing.T) {
	repl := nir.Seq{Parts: []nir.Expr{nir.Name{ID: "x", Loc: "app.py:1"}}, Loc: "app.py:1"}
	ex := nir.Seq{Parts: []nir.Expr{nir.Name{ID: "x", Loc: "app.py:2"}}, Loc: "app.py:2"}

	got := replaceName(ex, "x", repl).(nir.Seq)
	got.Parts[0].(nir.Seq).Parts[0] = nir.Const{Value: "\"mutated\"", Loc: "app.py:3"}

	if repl.Parts[0].(nir.Name).ID != "x" {
		t.Fatalf("replacement expression was aliased into output: %#v", repl)
	}
}

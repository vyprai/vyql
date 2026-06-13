package lowering

import (
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func TestCollectValTokensDescendsIntoFormat(t *testing.T) {
	var toks []string
	collectValTokens(nir.Format{
		Parts: []nir.Expr{
			nir.Const{Value: "prefix="},
			nir.Const{Value: "http://example.com"},
		},
	}, "", &toks)

	for _, tok := range toks {
		if tok == "http://example.com" {
			return
		}
	}
	t.Fatalf("expected formatted literal token, got %#v", toks)
}

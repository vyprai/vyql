package bindings

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// node.context.loopCursor reads the C/C++ frontend's per-(loop, cursor) reaching
// definition. The two token sets below are the CVE-2018-10017 shape before and after
// its fix: they agree on every assignment token, because the reset the fix adds is
// textually identical to one the function already makes for an earlier walk over the
// same range. Only the loop-cursor token separates them.
func TestLoopCursorContextFieldSeparatesStaleCursorFromResetCursor(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.cpp.test;

binding staleChannelCursor {
  query pattern presenceNode where node.scope == "function" and node.context.language == "cpp" and node.context.callPath contains "GetNumChannels" and node.context.loopCursor contains "pChn:def=loop_carried:step=no"
  emit issue custom.StaleChannelCursor at node
}
`)
	if err != nil {
		t.Fatalf("parse loop-cursor context flag: %v", err)
	}
	set := firstBindingSet(t, sets)
	pred := set.Mappings[0].Flag.Predicates[2]
	if pred.Property != "tokens" || pred.Op != "contains" || pred.Values[0] != "loop_cursor:pChn:def=loop_carried:step=no" {
		t.Fatalf("loopCursor predicate wrong: %+v", pred)
	}

	shared := []string{
		"lang=cpp",
		"name=GetLength",
		"call_path:GetNumChannels",
		"assign:pChn=playState.Chn",
		"selector:pChn.rowCommand.command",
		"loop_cursor:pChn:def=straight:step=yes",
	}
	cases := []struct {
		name   string
		tokens []string
		want   int
	}{
		{"vulnerable", append(append([]string{}, shared...), "loop_cursor:pChn:def=loop_carried:step=no"), 1},
		{"fixed", append(append([]string{}, shared...), "loop_update:nChn++,pChn++"), 0},
	}
	for _, tc := range cases {
		spec := specFromBindingSet(set)
		store := usg.NewInMemStore()
		store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "Snd_fx.cpp:1", Scope: "Snd_fx.cpp/GetLength", Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    strings.Join(tc.tokens, "\x00"),
		}})
		if got := spec.presenceApplicator().Apply(store); len(got) != tc.want {
			t.Fatalf("%s: loop-cursor flag matches = %d, want %d: %+v", tc.name, len(got), tc.want, got)
		}
	}
}

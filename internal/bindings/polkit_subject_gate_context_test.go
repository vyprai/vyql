package bindings

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// node.context.polkitSubjectGateNotConjunctive reads the JavaScript frontend's
// polkit sibling-arm observation (jsPolkitSubjectGateNotConjunctive): WHICH
// `||` disjunct of an authorization gate the subject test binds to. The
// relation is settled by the frontend before any binding runs, because a
// query over the lowered graph cannot state it — the two token sets below are
// the zincati rule of CVE-2025-27512 as the regression wrote it and as the fix
// repaired it, and they differ only in that binding. Without the field, the
// data layer has no route to the fact at all.
func TestPolkitSubjectGateContextFieldSeparatesMisConjoinedFromConjoined(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.javascript.test;

binding polkitSubjectGate {
  query pattern presenceNode where node.context.language == "javascript" and node.context.callPath contains "polkit.addRule" and node.context.polkitSubjectGateNotConjunctive == "true"
  emit issue custom.PolkitSubjectGateNotConjunctive at node
}
`)
	if err != nil {
		t.Fatalf("parse polkit subject-gate context flag: %v", err)
	}
	set := firstBindingSet(t, sets)
	var pred *PresencePredicate
	for i := range set.Mappings[0].Flag.Predicates {
		p := &set.Mappings[0].Flag.Predicates[i]
		if len(p.Values) > 0 && strings.HasPrefix(p.Values[0], "polkit_subject_gate_not_conjunctive=") {
			pred = p
		}
	}
	if pred == nil {
		t.Fatalf("no predicate compiled onto polkit_subject_gate_not_conjunctive=; got %+v", set.Mappings[0].Flag.Predicates)
	}
	if pred.Property != "tokens" || pred.Values[0] != "polkit_subject_gate_not_conjunctive=true" {
		t.Fatalf("polkit subject-gate predicate wrong: %+v", pred)
	}

	shared := []string{
		"lang=javascript",
		"name=<lambda>",
		"function_name:<lambda>",
		"call_path:polkit.addRule",
		"selector:polkit.Result.YES",
	}
	cases := []struct {
		name   string
		tokens []string
		want   int
	}{
		{"mis-conjoined", append(append([]string{}, shared...), "polkit_subject_gate_not_conjunctive=true"), 1},
		{"conjoined", append(append([]string{}, shared...), "expr:action.id==\"org.projectatomic.rpmostree1.deploy\"&&subject.user==\"zincati\""), 0},
	}
	spec := specFromBindingSet(set)
	for _, tc := range cases {
		store := usg.NewInMemStore()
		store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "zincati.js:3", Scope: "zincati.js/<lambda>", Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    strings.Join(tc.tokens, "\x00"),
		}})
		if got := spec.presenceApplicator().Apply(store); len(got) != tc.want {
			t.Fatalf("%s: polkit subject-gate flag matches = %d, want %d: %+v", tc.name, len(got), tc.want, got)
		}
	}
}

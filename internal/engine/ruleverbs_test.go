package engine

import (
	"testing"

	"github.com/vyprai/vyql/internal/parser"
)

// The engine type-checks a rule's endpoints against the same verb contract the parser validates
// against. Those were two hand-maintained tables in different shapes, so a verb gaining a kind in
// one and not the other was a silent divergence between what the language accepts and what the
// engine will compile. The engine now derives its view; this pins that it stays derived.
func TestEngineVerbKindsMatchTheParser(t *testing.T) {
	got := builtinRuleVerbMechanics()
	want := parser.BuiltinRuleVerbKinds()

	if len(got.verbs) != len(want) {
		t.Fatalf("engine knows %d verbs, parser %d: %v vs %v", len(got.verbs), len(want), verbKeys(got.verbs), parserKeys(want))
	}
	for verb, kinds := range want {
		m, ok := got.verbs[verb]
		if !ok {
			t.Errorf("verb %q is valid in the language but the engine cannot type-check it", verb)
			continue
		}
		for _, k := range kinds.From {
			if !m.FromKinds[k] {
				t.Errorf("verb %q: parser allows source kind %q, engine does not", verb, k)
			}
		}
		for _, k := range kinds.To {
			if !m.ToKinds[k] {
				t.Errorf("verb %q: parser allows target kind %q, engine does not", verb, k)
			}
		}
		if len(m.FromKinds) != len(kinds.From) {
			t.Errorf("verb %q: engine accepts %d source kinds, parser %d", verb, len(m.FromKinds), len(kinds.From))
		}
		if len(m.ToKinds) != len(kinds.To) {
			t.Errorf("verb %q: engine accepts %d target kinds, parser %d", verb, len(m.ToKinds), len(kinds.To))
		}
	}
}

// A verb with no target endpoint must yield a nil map, not an empty one: checkEndpointKinds treats
// nil as "this verb has no target" and an empty map as "no kind is acceptable".
func TestVerbsWithoutATargetHaveNilToKinds(t *testing.T) {
	m := builtinRuleVerbMechanics()
	for _, verb := range []string{"issue", "fact", "query"} {
		if v, ok := m.verbs[verb]; !ok {
			t.Errorf("%q missing", verb)
		} else if v.ToKinds != nil {
			t.Errorf("%q: ToKinds = %v, want nil", verb, v.ToKinds)
		}
	}
	if m.verbs["taint"].ToKinds == nil {
		t.Error("taint must have a target kind set")
	}
}

func verbKeys(m map[string]ruleVerbMechanic) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func parserKeys(m map[string]parser.RuleVerbKinds) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

package bindings

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A function's context covers the calls written in the closures it hands out. A Rust
// closure is an expression of the fn item that contains it, and once the closure is
// lowered as a body of its own the lowering hangs that body off the function's region
// with '#' (lowering.functionRegion) instead of nesting it with '/'. A scope predicate
// over the function's context tokens -- `containsAny(node.context.callArg, ...)`, the
// shape every "this function splits a host on a dot" binding reads -- therefore has to
// read a call in that body as inside the function, while a sibling function's call stays
// outside it.
func TestFunctionContextScopeCoversCallbackRegions(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.rust.test;

binding domainLabelAllowlistLookup {
  query pattern presenceNode where node.scope == "function" and node.context.language == "rust" and node.context.call in ["domain", "host", "host_str"] and containsAny(node.context.callArg, ["split_once:.", "split:."])
  emit issue custom.DomainLabelAllowlistLookup at node
}
`)
	if err != nil {
		t.Fatalf("parse function-context flag: %v", err)
	}
	set := firstBindingSet(t, sets)
	pred := set.Mappings[0].Flag.Predicates[len(set.Mappings[0].Flag.Predicates)-1]
	if pred.Property != "tokens" {
		t.Fatalf("call-arg predicate wrong: %+v", pred)
	}

	spec := specFromBindingSet(set)
	contextTokens := strings.Join([]string{
		"lang=rust",
		"name=is_local_url",
		"call:domain",
		"call:contains_key",
	}, "\x00")

	cases := []struct {
		name      string
		callScope string
		want      int
	}{
		{"call in the function's own region", "mod.rs/fn1", 1},
		{"call in a closure body the function hands out", "mod.rs/fn1#fn2", 1},
		{"call in a sibling function", "mod.rs/fn2", 0},
		{"call in another module", "other.rs/fn1", 0},
	}
	for _, tc := range cases {
		store := usg.NewInMemStore()
		store.AddNode(usg.Node{ID: "ctx", Type: "code.Call", Loc: "mod.rs:1", Scope: "mod.rs/fn1", Props: map[string]string{
			"callee_path": "analysis.function.context",
			"method":      "context",
			"str_args":    contextTokens,
		}})
		store.AddNode(usg.Node{ID: "call", Type: "code.Call", Loc: "mod.rs:9", Scope: tc.callScope, Props: map[string]string{
			"callee_path": "d.split_once",
			"method":      "split_once",
			"str_args":    ".",
		}})
		if got := len(spec.presenceApplicator().Apply(store)); got != tc.want {
			t.Fatalf("%s: presence matches = %d, want %d", tc.name, got, tc.want)
		}
	}
}

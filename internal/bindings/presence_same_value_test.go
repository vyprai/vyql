package bindings

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A Rust function context carries the enclosing function's own name (`name=`) and the
// list of calls in its body (`call:`) on one node, so "this function calls itself" is
// decidable from that node alone -- but only if a predicate may compare two fields of the
// same node instead of a field against a literal.

const selfRecursionBindingSource = `
module bindings.rust.test;

binding selfRecursive {
  query pattern presenceNode where node.scope == "function" and node.context.language == "rust" and node.context.call == node.context.name
  emit issue custom.SelfRecursion at node
}
`

func rustFunctionContextNode(id, loc, name string, calls ...string) usg.Node {
	tokens := []string{"lang=rust", "name=" + name}
	for _, call := range calls {
		tokens = append(tokens, "call_path:"+call, "call:"+call)
	}
	return usg.Node{ID: id, Type: "code.Call", Props: map[string]string{
		"loc":         loc,
		"callee_path": "analysis.function.context",
		"method":      "context",
		"str_args":    strings.Join(tokens, "\x00"),
	}}
}

func TestPresenceSameNodeUnificationLabelsSelfRecursiveFunction(t *testing.T) {
	sets, err := compileV2BindingsForTest(selfRecursionBindingSource)
	if err != nil {
		t.Fatalf("compile same-node unification predicate: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))
	if len(spec.Flags) != 1 {
		t.Fatalf("expected one flag spec, got %#v", spec.Flags)
	}
	pred := spec.Flags[0].Predicates[len(spec.Flags[0].Predicates)-1]
	if pred.Op != presenceSameValueOp || pred.Negative ||
		len(pred.Values) != 2 || pred.Values[0] != "call:" || pred.Values[1] != "name=" {
		t.Fatalf("unexpected unification predicate: %#v", pred)
	}

	store := usg.NewInMemStore()
	// parse_node calls itself; render calls a different helper that shares nothing with
	// its own name.
	store.AddNode(rustFunctionContextNode("recursive", "parser.rs:1", "parse_node", "parse_node", "build"))
	store.AddNode(rustFunctionContextNode("plain", "render.rs:1", "render", "build", "flush"))

	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "recursive" || got[0].Concept != "custom.SelfRecursion" {
		t.Fatalf("same-node unification did not label exactly the self-recursive function: %+v", got)
	}
}

func TestPresenceSameNodeUnificationNegated(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.rust.test;

binding notSelfRecursive {
  query pattern presenceNode where node.scope == "function" and node.context.language == "rust" and node.context.call exists and node.context.call != node.context.name
  emit issue custom.NoSelfRecursion at node
}
`)
	if err != nil {
		t.Fatalf("compile negated unification predicate: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))
	store := usg.NewInMemStore()
	store.AddNode(rustFunctionContextNode("recursive", "parser.rs:1", "parse_node", "parse_node", "build"))
	store.AddNode(rustFunctionContextNode("plain", "render.rs:1", "render", "build", "flush"))

	got := spec.presenceApplicator().Apply(store)
	if len(got) != 1 || got[0].NodeID != "plain" {
		t.Fatalf("negated unification did not label exactly the non-recursive function: %+v", got)
	}
}

func TestPresenceNonTokenRightSideStillRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
		want string
	}{
		{
			name: "operator other than equality",
			expr: `node.context.call contains node.context.name`,
			want: "right side must be a string",
		},
		{
			name: "right side is not a field of the alias",
			expr: `node.context.call == other.context.name`,
			want: "right side must be a string",
		},
		{
			name: "sides are not both token families",
			expr: `node.path == node.method`,
			want: "both sides must be context token families of the same node",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileV2BindingsForTest(`
module bindings.rust.test;

binding bad {
  query pattern presenceNode where node.scope == "function" and ` + tc.expr + `
  emit issue custom.SelfRecursion at node
}
`)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

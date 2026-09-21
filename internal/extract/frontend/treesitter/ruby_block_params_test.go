package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// rubyDestructuredFixture is image_processing's Chainable#apply: the operations the
// caller built are folded through a block whose second parameter is destructured,
// and each operation ends in a dispatch named by the first inner name.
const rubyDestructuredFixture = `class Chainable
  def apply(operations)
    operations.inject(self) do |builder, (name, argument)|
      builder.public_send(name, argument)
    end
  end
end
`

// A destructured block parameter binds the same names a flat one does: taint from
// the iterated collection has to reach `name` and `argument`, or the dispatch they
// shape arrives with two free names and nothing behind them.
func TestRubyDestructuredBlockParamCarriesTaintFromTheIteratedCollection(t *testing.T) {
	g := lowerRuby(t, rubyDestructuredFixture, "apply.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "operations", "func", "apply"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	args := rubyArgsAt(t, g, "apply.rb:4")
	if len(args) < 2 {
		t.Fatalf("expected the dispatch's name and argument on apply.rb:4, found %d args", len(args))
	}
	for _, id := range args {
		if !reachable[id] {
			t.Fatalf("an argument the destructured block bound was not reached by taint from the iterated collection: %s", id)
		}
	}
}

// The flat parameter beside the destructured one still binds: `builder` joins from
// the collection exactly as it did before the inner names did.
func TestRubyDestructuredBlockParamKeepsTheFlatParameterBound(t *testing.T) {
	g := lowerRuby(t, rubyDestructuredFixture, "apply.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "operations", "func", "apply"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Call", "method", "public_send", "loc", "apply.rb:4")] {
		t.Fatal("the dispatch the block performs was not reached by taint from the iterated collection")
	}
}

// A destructured parameter may nest (`|a, (b, (c, d))|` is `parameters` all the way
// down), and every inner name is a name the block binds.
func TestRubyNestedDestructuredBlockParamsAllBind(t *testing.T) {
	src := `def run(list)
  list.each do |(outer, (inner, last))|
    Log.emit(outer, inner, last)
  end
end
`
	g := lowerRuby(t, src, "nested.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "list", "func", "run"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	args := rubyArgsAt(t, g, "nested.rb:3")
	if len(args) < 3 {
		t.Fatalf("expected one argument per inner name on nested.rb:3, found %d args", len(args))
	}
	for _, id := range args {
		if !reachable[id] {
			t.Fatalf("an argument a nested destructured parameter bound was not reached by taint from the iterated collection: %s", id)
		}
	}
}

// rubyArgsAt returns the ids of the code.Arg nodes on one line.
func rubyArgsAt(t *testing.T, g usg.Store, loc string) []string {
	t.Helper()
	ids, err := g.NodesOfType("code.Arg")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Loc == loc {
			out = append(out, id)
		}
	}
	return out
}

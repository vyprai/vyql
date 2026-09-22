package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// rubyCallsWithCallee returns the ids of every lowered call node whose callee_path is path.
func rubyCallsWithCallee(t *testing.T, g usg.Store, path string) []string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Prop("callee_path") == path {
			out = append(out, id)
		}
	}
	return out
}

// A lambda or proc stored as a value carries its body in the block of a CALL, and that call
// sits in expression position — the right side of an assignment, a hash value, an argument.
// Lowering a call's block only when the call is a statement left the body out of the graph
// entirely, so the sink inside the lambda was invisible to every binding, taint path and
// rule. The block has to lower beside the statement that holds the call, the way it already
// lowers beside the call in statement position.
func TestRubyLambdaStoredAsAValueLowersItsBody(t *testing.T) {
	for name, src := range map[string]string{
		"lambda braces":    "def run(body)\n  parser = lambda { |src| REXML::Document.new(src) }\nend\n",
		"lambda do block":  "def run(body)\n  parser = lambda do |src|\n    REXML::Document.new(src)\n  end\nend\n",
		"proc":             "def run(body)\n  parser = proc { |src| REXML::Document.new(src) }\nend\n",
		"Proc.new":         "def run(body)\n  parser = Proc.new { |src| REXML::Document.new(src) }\nend\n",
		"hash value":       "def run(body)\n  opts = { parse: lambda { |src| REXML::Document.new(src) } }\nend\n",
		"call argument":    "def run(body)\n  register(lambda { |src| REXML::Document.new(src) })\nend\n",
		"return value":     "def make\n  return lambda { |src| REXML::Document.new(src) }\nend\n",
		"iteration on rhs": "def run(body)\n  parsed = body.map { |v| REXML::Document.new(v) }\nend\n",
	} {
		t.Run(name, func(t *testing.T) {
			g := lowerRuby(t, src, "lambda.rb")
			calls := rubyCallsWithCallee(t, g, "REXML.Document.new")
			if len(calls) != 1 {
				t.Fatalf("a lambda stored as a value lowered %d REXML::Document.new calls, want 1: "+
					"the sink inside the block must be a node in the graph, once", len(calls))
			}
		})
	}
}

// Visibility is only half of it: a block's parameters join from the call's receiver — the
// iterated collection — so a value the receiver carried reaches the sink inside a block
// stored as a value, the same way it reaches one in statement position.
func TestRubyBlockStoredAsAValueJoinsItsReceiver(t *testing.T) {
	src := "def run(body)\n  parsed = body.map { |v| REXML::Document.new(v) }\nend\n"
	g := lowerRuby(t, src, "lambda.rb")
	sink := rubyCallsWithCallee(t, g, "REXML.Document.new")
	if len(sink) != 1 {
		t.Fatalf("got %d REXML::Document.new calls, want 1", len(sink))
	}
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "body", "func", "run"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[sink[0]] {
		t.Fatal("the collection a stored map block iterates did not reach the sink inside the block")
	}
}

// A condition that binds (`if parser = lambda { … }`) lowers the assignment's right side
// twice — once as the condition's value and once as the value bound to the name — which is
// harmless for plain expressions but would lower the block's body twice. One call, one body.
func TestRubyAssignmentConditionLowersTheLambdaBodyOnce(t *testing.T) {
	src := "def run(body)\n  if parser = lambda { |src| REXML::Document.new(src) }\n    log(parser)\n  end\nend\n"
	g := lowerRuby(t, src, "lambda.rb")
	if calls := rubyCallsWithCallee(t, g, "REXML.Document.new"); len(calls) != 1 {
		t.Fatalf("a lambda inside an assignment condition lowered %d REXML::Document.new calls, want 1", len(calls))
	}
}

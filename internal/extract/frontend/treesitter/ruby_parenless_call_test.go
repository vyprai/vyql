package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// rubyLowered lowers one Ruby source string and returns the graph, so a test can ask
// questions about the nodes the frontend produced rather than about a scan's findings.
func rubyLowered(t *testing.T, src, file string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// rubyLineOf finds the 1-based line number of the first line holding needle.
func rubyLineOf(t *testing.T, src, needle string) string {
	t.Helper()
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, needle) {
			return itoa(i + 1)
		}
	}
	t.Fatalf("fixture has no line containing %q", needle)
	return ""
}

// rubyHasCallAt reports whether a call to `path` was lowered on the given line.
func rubyHasCallAt(t *testing.T, g usg.Store, path, line string) bool {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Prop("callee_path") == path && strings.HasSuffix(n.Loc, ":"+line) {
			return true
		}
	}
	return false
}

// A method called with no receiver and no parentheses is a call on the implicit self —
// the same call `path_info()` spells. Ruby's own rule tells it apart from a name read:
// the scope either has a local of that name (a read) or it does not (a call). Lowering
// the call as a name read strands the callee's return value, because nothing at the call
// site carries what the method produced: the callee's own return is where the trace stops.
func TestRubyReceiverlessParenlessCallCarriesTheCalleesReturnValue(t *testing.T) {
	src := `class Handler
  def path_info
    @env["PATH_INFO"]
  end

  def publish
    path = path_info
    Log.emit(path)
  end
end
`
	file := "handler.rb"
	g := rubyLowered(t, src, file)

	// The callee's return slot reaches the argument of the call the assignment's value
	// was handed to — the edge a name read never had.
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Return", "func", "path_info"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Arg", "loc", file+":"+rubyLineOf(t, src, "Log.emit(path)"))] {
		t.Fatal("the callee's return value did not reach the call its caller handed it to: " +
			"the paren-less call was lowered as a name read")
	}
	// and the call itself is a call site a binding can name
	if !rubyHasCallAt(t, g, "path_info", rubyLineOf(t, src, "path = path_info")) {
		t.Fatal("no call node carries the paren-less call's path")
	}
}

// The same shape end to end: taint a sibling method stores on the object reaches the
// callee's body, and the callee's return value carries it out to the caller's sink.
func TestRubyReceiverlessParenlessCallCarriesTaintEndToEnd(t *testing.T) {
	src := `class Handler
  def carry(env)
    @env = env
  end

  def path_info
    @env["PATH_INFO"]
  end

  def publish
    path = path_info
    Log.emit(path)
  end
end
`
	if !rubyParamReachesSink(t, src, "handler.rb", "carry", "env", "Log.emit(path)") {
		t.Fatal("the value the callee returned did not reach the sink its caller handed it to")
	}
}

// A paren-less call nested inside another expression — a binary operand, the
// interpolated value of a string — is the same call, not a name read.
func TestRubyReceiverlessParenlessCallInNestedExpressionPosition(t *testing.T) {
	src := `class Handler
  def path_info
    @env["PATH_INFO"]
  end

  def publish
    Log.emit("was " + path_info + " #{path_info}")
  end
end
`
	g := rubyLowered(t, src, "handler.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Return", "func", "path_info"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Arg", "loc", "handler.rb:"+rubyLineOf(t, src, "Log.emit"))] {
		t.Fatal("a paren-less call used as an operand or interpolated did not carry its value out")
	}
}

// A member call whose receiver is the attr_reader spelling — a bare identifier with
// no `def` of that name anywhere, so no local and no resolvable call — keeps the
// resolution a name receiver always had. The engine's receiver routes key on the
// root's shape: a name root with no recorded type still reaches the
// unique-method-name fallback, a call-result receiver deliberately does not.
// Lowering this receiver as the call expr() would produce strands the dispatch on
// the refusing route, and the argument never reaches the one method of that name
// (cve_rank1643: `coder.decode(cookie_data)` stopped reporting the deserialization).
func TestRubyMemberCallOnAttrReaderReceiverKeepsItsResolution(t *testing.T) {
	src := `class Coder
  def decode(str)
    Marshal.load(str)
  end
end

class Session
  attr_reader :coder

  def unpacked(request)
    cookie = request.cookies["rack.session"]
    coder.decode(cookie)
  end
end
`
	if !rubyParamReachesSink(t, src, "session.rb", "unpacked", "request", "Marshal.load(str)") {
		t.Fatal("a member call on an attr_reader receiver stopped resolving: the argument " +
			"never reached the unique method of that name")
	}
}

// The discriminator cuts the other way too: a bare identifier the scope DOES bind as a
// local is a read of that local, and fabricating a call for it would both hide the
// local's value and invent a call site no source spells.
func TestRubyBareIdentifierBoundAsALocalReadsTheLocal(t *testing.T) {
	src := `class Handler
  def publish(env)
    stored = env["PATH_INFO"]
    Log.emit(stored)

    opts = env
    env.each_item do |item, *rest|
      Log.emit(item)
    end
    for page in 1..2
      Log.emit(page)
    end
    begin
      Log.emit(opts)
    rescue => failure
      Log.emit(failure)
    end
  end
end
`
	file := "handler.rb"
	g := rubyLowered(t, src, file)

	// Every one of these names is bound by the scope, so none of them is a call.
	for _, local := range []string{"stored", "opts", "item", "rest", "page", "failure"} {
		for _, line := range []int{3, 5, 6, 11, 14, 16} {
			if rubyHasCallAt(t, g, local, itoa(line)) {
				t.Errorf("%s is bound as a local on line %d but was lowered as a call", local, line)
			}
		}
	}

	// and the local still carries its value: the parameter reaches the sink that read it
	if !rubyParamReachesSink(t, src, file, "publish", "env", "Log.emit(stored)") {
		t.Fatal("a local read stopped carrying the value assigned to it")
	}
	if !rubyParamReachesSink(t, src, file, "publish", "env", "Log.emit(item)") {
		t.Fatal("a block parameter read stopped carrying the value the receiver gave it")
	}
}

// `**opts` and `&blk` bind locals the callable parameter list does not carry; a bare read
// of either is still a read of the local and not a call.
func TestRubyHashSplatAndBlockParametersReadAsLocals(t *testing.T) {
	src := `def publish(**opts, &blk)
  Log.emit(opts)
  blk.call
end
`
	g := rubyLowered(t, src, "publish.rb")
	if rubyHasCallAt(t, g, "opts", "2") || rubyHasCallAt(t, g, "blk", "3") {
		t.Fatal("**opts and &blk bind locals; a bare read of either is not a call")
	}
}

// A scope's locals are its own: an assignment inside a method does not make the same
// spelling a local read at the class body around it, or inside a sibling method.
func TestRubyLocalsDoNotEscapeTheirScope(t *testing.T) {
	src := `class Handler
  def path_info
    @env["PATH_INFO"]
  end

  def publish
    Log.emit(path_info)
  end
end
`
	g := rubyLowered(t, src, "handler.rb")
	if !rubyHasCallAt(t, g, "path_info", rubyLineOf(t, src, "Log.emit(path_info)")) {
		t.Fatal("a name another method assigns locally was treated as a local here; " +
			"the paren-less call is the method of the body it is written in")
	}
}

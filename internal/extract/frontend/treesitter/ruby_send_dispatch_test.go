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

func lowerRuby(t *testing.T, src, file string) usg.Store {
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

// rubySendFixture is one helper reached reflectively, and one reached directly, so a test
// can compare the dispatch against the spelling that resolves without it.
const rubySendFixture = `class Gate
  def unlock(secret)
    Log.emit(secret)
  end

  def open(user)
    send(:unlock, user)
  end

  def open_directly(user)
    unlock(user)
  end
end
`

// `send(:unlock, user)` runs `unlock` with everything after the name, so the argument has
// to reach the named method's parameter the way the direct spelling's does. Lowered as a
// plain `send` call it resolves to nothing — no `send` body exists to route it through —
// and the taint stops at the dispatch.
func TestRubySendDispatchReachesTheMethodItNames(t *testing.T) {
	g := lowerRuby(t, rubySendFixture, "send.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "user", "func", "open"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Param", "name", "secret", "func", "unlock")] {
		t.Fatal("an argument handed to `send` did not reach the parameter of the method it names")
	}
}

// The name the dispatch carries is not an argument of the call it performs: `unlock` takes
// the user and nothing else. Leaving the symbol in place would map `:unlock` onto the
// first parameter and shift every real argument along by one.
func TestRubySendDispatchDropsTheNameFromTheCallItPerforms(t *testing.T) {
	g := lowerRuby(t, rubySendFixture, "send.rb")
	performed := rubyNodeID(t, g, "code.Call", "callee_path", "unlock", "loc", "send.rb:7")
	n, ok, err := g.GetNode(performed)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the dispatch was not resolved to the call it performs")
	}
	if n.Prop("method") != "unlock" {
		t.Fatalf("the dispatch should resolve to the method its argument names, got method=%q", n.Prop("method"))
	}
	if got := n.Prop("str_args"); got != "user" {
		t.Fatalf("the call the dispatch performs takes the arguments after the name, got str_args=%q", got)
	}
}

// Resolving the dispatch must not erase the reflection: the `send` as written is still
// lowered, its method still `send` and the name still its first argument, so a binding can
// judge a dispatch whose method name arrives from outside. The two spellings are separate
// nodes — one reports the reflection, the other carries the taint — so neither can lose
// what the other saw.
func TestRubySendDispatchStaysLoweredAsItself(t *testing.T) {
	g := lowerRuby(t, rubySendFixture, "send.rb")
	n, ok, err := g.GetNode(rubyNodeID(t, g, "code.Call", "method", "send", "loc", "send.rb:7"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the reflective dispatch itself was not lowered")
	}
	if n.Prop("callee_path") != "send" {
		t.Fatalf("the dispatch should stay a bare `send`, got callee_path=%q", n.Prop("callee_path"))
	}
	for _, want := range []string{"unlock", "user"} {
		if !strings.Contains(n.Prop("str_args"), want) {
			t.Fatalf("the dispatch should keep the name and the arguments it was given, missing %q in str_args=%q", want, n.Prop("str_args"))
		}
	}
}

// A name the file does not fix names nothing: nothing to resolve to, and no call to invent.
func TestRubySendWithADynamicNameStaysADispatch(t *testing.T) {
	src := `class Gate
  def unlock(secret)
    Log.emit(secret)
  end

  def open(user, name)
    send(name, user)
  end
end
`
	g := lowerRuby(t, src, "send.rb")
	if _, ok, _ := g.GetNode(rubyNodeID(t, g, "code.Call", "method", "send", "loc", "send.rb:7")); !ok {
		t.Fatal("a dispatch with a run-time name was not lowered as a call at all")
	}
	// rubyNodeID fails the test when nothing matches, so reaching here with a `name` call
	// would mean the dispatch was resolved to a method no literal names.
	if id := rubySendDynamicNameCallID(t, g); id != "" {
		t.Fatalf("a dispatch with a run-time name was resolved to a method no literal names: %s", id)
	}
}

// rubySendDynamicNameCallID returns the id of a `name` call on the dispatch's line, or ""
// when the graph has none.
func rubySendDynamicNameCallID(t *testing.T, g usg.Store) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Loc == "send.rb:7" && n.Prop("method") == "name" {
			return id
		}
	}
	return ""
}

// `public_send` and `__send__` are the same dispatch under other spellings.
func TestRubyPublicSendDispatchReachesTheMethodItNames(t *testing.T) {
	src := strings.Replace(rubySendFixture, "send(:unlock, user)", "public_send(:unlock, user)", 1)
	g := lowerRuby(t, src, "send.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "user", "func", "open"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Param", "name", "secret", "func", "unlock")] {
		t.Fatal("an argument handed to `public_send` did not reach the parameter of the method it names")
	}
}

// A dispatch on an explicit receiver resolves against that receiver, exactly as the direct
// spelling does.
func TestRubySendOnAReceiverReachesTheMethodItNames(t *testing.T) {
	src := `class Gate
  def unlock(secret)
    Log.emit(secret)
  end

  def open(gate, user)
    gate.send(:unlock, user)
  end
end
`
	g := lowerRuby(t, src, "send.rb")
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "user", "func", "open"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Param", "name", "secret", "func", "unlock")] {
		t.Fatal("an argument handed to `gate.send` did not reach the parameter of the method it names")
	}
}

// What the dispatched method returns reaches the caller, which is the half a credential
// needs: the helper builds it, and the value comes back out of the dispatch.
func TestRubySendDispatchReturnsTheMethodItNames(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    "secret-" + user.token
  end

  def publish(user)
    cred = send(:assemble, user)
    Log.emit(cred)
  end
end
`
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.rb")
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
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "user", "func", "assemble"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[rubyNodeID(t, g, "code.Arg", "loc", "cred.rb:8")] {
		t.Fatal("what a dispatched helper returned did not reach the sink its caller handed it to")
	}
}

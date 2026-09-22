package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// The rank-2814 shape: a wrapper shells out to a helper binary by interpolating a
// caller-supplied value into a backtick literal, with %x(…) as the same operator in its
// percent-delimited spelling and a plain backtick as the constant-command case.
const rubySubshellFixture = `class Pdf
  def info(file)
    ` + "`pdfinfo -layout #{file} 2>/dev/null`" + `
  end

  def info_percent(file)
    out = %x(pdfinfo #{file})
    out
  end

  def listing
    ` + "`ls -la /tmp`" + `
  end
end
`

// rbSubshellCallID returns the id of the Kernel backtick call at loc, so tests can read
// the node each assertion is about without re-matching every property.
func rbSubshellCallID(t *testing.T, g usg.Store, loc string) string {
	t.Helper()
	return rubyNodeID(t, g, "code.Call", "callee_path", "Kernel.`", "loc", loc)
}

// A backtick or %x literal is an execution, not a string: Ruby spells the operator as
// Kernel's backtick method, which takes the command string and runs it through a shell.
// Lowered to anything but that call there is no node a sink concept can attach to — the
// literal reads as a value the program builds and never uses.
func TestRubySubshellLowersToTheExecutionItPerforms(t *testing.T) {
	g := lowerRuby(t, rubySubshellFixture, "pdf.rb")
	for _, loc := range []string{"pdf.rb:3", "pdf.rb:7"} {
		n, ok, err := g.GetNode(rbSubshellCallID(t, g, loc))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("no Kernel backtick execution node at %s", loc)
		}
		if n.Prop("method") != "`" {
			t.Fatalf("execution at %s should be Kernel's backtick method, got method=%q", loc, n.Prop("method"))
		}
	}
}

// The command the shell runs is the call's first argument, lowered the way an ordinary
// string is: an interpolated literal is a Format whose parts are the interpolated
// expressions, a constant one a Const carrying the command text. A sink binding's
// `at args[0]` lands on that slot, so what it labels is the command itself.
func TestRubySubshellCommandStringIsTheCallArgument(t *testing.T) {
	g := lowerRuby(t, rubySubshellFixture, "pdf.rb")

	cmd := nodeArgValue(t, g, rbSubshellCallID(t, g, "pdf.rb:3"))
	if cmd.Type != "code.Format" {
		t.Fatalf("interpolated backtick command at pdf.rb:3 should be a Format, got %q", cmd.Type)
	}
	if cmd.Prop("str_args") != "file" {
		t.Fatalf("the command's parts should carry the interpolated name, got str_args=%q", cmd.Prop("str_args"))
	}

	if pct := nodeArgValue(t, g, rbSubshellCallID(t, g, "pdf.rb:7")); pct.Type != "code.Format" {
		t.Fatalf("%%x command at pdf.rb:7 should lower to the same Format shape, got %q", pct.Type)
	}

	lit := nodeArgValue(t, g, rbSubshellCallID(t, g, "pdf.rb:12"))
	if lit.Type != "code.Const" {
		t.Fatalf("constant backtick command at pdf.rb:12 should be a Const, got %q", lit.Type)
	}
	if lit.Prop("str_args") != "ls -la /tmp" {
		t.Fatalf("constant command should carry its text, got str_args=%q", lit.Prop("str_args"))
	}
}

// The whole point of the node: taint followed into the literal's interpolated parts now
// has somewhere to arrive. A parameter interpolated into the command reaches the slot a
// sink attaches to, so the path source → command → execution completes instead of ending
// in a string value nothing consumes.
func TestRubySubshellTaintCompletesIntoTheExecution(t *testing.T) {
	g := lowerRuby(t, rubySubshellFixture, "pdf.rb")
	for _, tc := range []struct{ funcName, loc string }{
		{"info", "pdf.rb:3"},
		{"info_percent", "pdf.rb:7"},
	} {
		reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", "file", "func", tc.funcName), "FLOWS", 60)
		if err != nil {
			t.Fatal(err)
		}
		if cmd := nodeArg0(t, g, rbSubshellCallID(t, g, tc.loc)); !reachable[cmd] {
			t.Fatalf("parameter of %s did not reach the command string of the execution at %s", tc.funcName, tc.loc)
		}
	}
}

// nodeArg0 returns the id of a call node's first argument slot.
func nodeArg0(t *testing.T, g usg.Store, callID string) string {
	t.Helper()
	n, ok, err := g.GetNode(callID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("call node disappeared")
	}
	arg0 := n.Prop("arg0")
	if arg0 == "" {
		t.Fatalf("call at %s has no first argument", n.Prop("loc"))
	}
	return arg0
}

// nodeArgValue returns the value node feeding a call's first argument slot — the slot a
// sink binds to, and beside it the Format/Const the command string lowered to.
func nodeArgValue(t *testing.T, g usg.Store, callID string) usg.Node {
	t.Helper()
	in, err := g.InEdges(nodeArg0(t, g, callID), "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range in {
		if n, ok, err := g.GetNode(e.Src); err == nil && ok &&
			(n.Type == "code.Format" || n.Type == "code.Const") {
			return n
		}
	}
	t.Fatal("the command-string argument slot has no Format/Const value behind it")
	return usg.Node{}
}

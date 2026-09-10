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

// rubyParamReachesSink asserts the parameter of `fn` reaches the argument of the call
// whose source line holds `sink` — the shape of a helper's return value being handed to a
// sink by its caller.
func rubyParamReachesSink(t *testing.T, src, file, fn, param, sink string) bool {
	t.Helper()
	line := ""
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, sink) {
			line = itoa(i + 1)
			break
		}
	}
	if line == "" {
		t.Fatalf("fixture has no line containing %q", sink)
	}
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
	reachable, err := usg.BFS(g, rubyNodeID(t, g, "code.Param", "name", param, "func", fn), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	return reachable[rubyNodeID(t, g, "code.Arg", "loc", file+":"+line)]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A method whose last statement is an `if` returns whichever arm ran: Ruby has no
// statement/expression split, so the branch IS the return value and there is no `return`
// to lower. Each arm therefore has to hand its own value out of the method — the caller
// below passes what the helper built straight to a sink, and the taint can only get there
// through the helper's return.
func TestRubyTrailingBranchIsTheValueTheCallerReceives(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    if user.admin?
      "admin-" + user.token
    else
      "user-" + user.token
    end
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if !rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("the value a trailing `if` produced did not leave the helper: the sink its caller handed it to saw nothing")
	}
}

// The same trailing value behind a `case`, whose arms the frontend lowers as a Switch
// rather than an If.
func TestRubyTrailingCaseIsTheValueTheCallerReceives(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    case user.kind
    when "admin"
      "admin-" + user.token
    else
      "user-" + user.token
    end
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if !rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("the value a trailing `case` produced did not leave the helper")
	}
}

// `x = expr` last returns x, so the assigned value leaves even though no `return` follows.
func TestRubyTrailingAssignmentIsTheValueTheCallerReceives(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    value = "secret-" + user.token
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if !rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("the value of a trailing assignment did not leave the helper")
	}
}

// An arm ending in its own branch carries the value through both levels: Ruby's
// expression-oriented bodies nest.
func TestRubyTrailingBranchThroughANestedBranch(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    if user.admin?
      if user.root?
        "root-" + user.token
      else
        "admin-" + user.token
      end
    else
      "user-" + user.token
    end
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if !rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("the value a nested trailing `if` produced did not leave the helper")
	}
}

// The value-carrying is a fact about the LAST statement. An `if` with more statements
// after it is a plain conditional whose value is thrown away, so what runs after decides
// what the caller receives — here a constant, which must not pick up the branch's taint.
func TestRubyBranchFollowedByMoreStatementsIsNotAReturnValue(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    if user.admin?
      "admin-" + user.token
    end
    "static"
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("a mid-body `if` was treated as the method's return value: the constant the method actually returned came back tainted")
	}
}

// A trailing `if` with no `else` returns nil on the empty arm, and nil carries nothing.
// The populated arm is the only route, and it must still reach the caller.
func TestRubyTrailingBranchWithoutElseKeepsThePopulatedArm(t *testing.T) {
	src := `class Credentials
  def assemble(user)
    if user.admin?
      "admin-" + user.token
    end
  end

  def publish(user)
    cred = assemble(user)
    Log.emit(cred)
  end
end
`
	if !rubyParamReachesSink(t, src, "cred.rb", "assemble", "user", "Log.emit(cred)") {
		t.Fatal("the populated arm of a trailing `if` with no `else` did not leave the helper")
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// A module funnels a command and its trailing arguments through a helper that
// collects them with a rest parameter:
//
//	export function run(cmd, ...args) {
//	  return exec(cmd, args)
//	}
//	export function main(userInput) {
//	  return run('ls', userInput)
//	}
//
// Written with `run(cmd, argsList)` the second argument is an ordinary
// parameter and the call's taint reaches the body. Written with a rest
// parameter it has to reach the same body: the two spellings collect the same
// trailing arguments, and anything else leaves the second argument's taint
// stopping at the call site.
const restParamSrc = `
export function run(cmd, ...args) {
  return exec(cmd, args)
}

export function main(userInput) {
  return run('ls', userInput)
}
`

// The same module in TypeScript, where the grammar wraps the rest pattern in a
// required_parameter. Only the parse shape differs; the flow may not.
const restParamTSSrc = `
export function run(cmd: string, ...args: string[]) {
  return exec(cmd, args)
}

export function main(userInput: string) {
  return run('ls', userInput)
}
`

// The trailing argument of a call into a rest parameter reaches the name the
// rest pattern binds, and through it the call the callee's own body makes.
func TestCallTrailingArgumentReachesRestParameter(t *testing.T) {
	g := lowerJSFile(t, restParamSrc)
	src := paramOf(g, "main", "userInput")
	if src == "" {
		t.Fatal("main's parameter never lowered")
	}
	rest := paramOf(g, "run", "args")
	if rest == "" {
		t.Fatal("a rest parameter did not lower as a parameter node, so trailing arguments have nothing to enter")
	}
	if !reaches(t, g, src, rest) {
		t.Fatal("the trailing argument of a call into a rest parameter did not reach the name the pattern binds")
	}
	if s := callArgOf(g, "exec", 1); s != "" && !reaches(t, g, src, s) {
		t.Fatal("the trailing argument of a call into a rest parameter did not reach the callee body's own call")
	}
	// The parameters before the rest keep their positions: the first argument
	// still lands on cmd, and the trailing argument lands only on the rest.
	if cmd := paramOf(g, "run", "cmd"); cmd != "" && reaches(t, g, src, cmd) {
		t.Fatal("the trailing argument reached the parameter before the rest, so positions shifted")
	}
}

// The TypeScript spelling of the same rest parameter — a rest_pattern inside a
// required_parameter — lowers to the same parameter node and the same flow.
func TestCallTrailingArgumentReachesTypeScriptRestParameter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.ts")
	if err := os.WriteFile(path, []byte(restParamTSSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	src := paramOf(g, "main", "userInput")
	if src == "" {
		t.Fatal("main's parameter never lowered")
	}
	rest := paramOf(g, "run", "args")
	if rest == "" {
		t.Fatal("a TypeScript rest parameter (rest_pattern inside required_parameter) did not lower as a parameter node")
	}
	if !reaches(t, g, src, rest) {
		t.Fatal("the trailing argument of a call into a TypeScript rest parameter did not reach the name the pattern binds")
	}
}

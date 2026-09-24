package treesitter_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A function-typed constructor parameter that the constructor stores into a field -- the
// TypeScript parameter property (`constructor(private toolExecutor: Fn) {}`), or the
// hand-written `this.toolExecutor = toolExecutor` -- binds the callback a construction site
// supplies. A later `this.toolExecutor(name, args)` in another method dispatches into that
// callback, and no name-keyed resolution can reach the injected body: the field is not a
// declared method. The construction site is what knows the callee, so the dispatch's
// arguments only reach the callback's parameters when the two sites are paired.

// lowerJSNamedFiles extracts and lowers the named sources as one program, in file order, so
// a test can ask what a value in one file reaches in another.
func lowerJSNamedFiles(t *testing.T, files map[string]string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(files[name]), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	prog, err := treesitter.ExtractJavaScript(paths, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The TypeScript spelling: the parameter property's implicit `this.toolExecutor =
// toolExecutor` store, the construction site in a second file (named so it lowers before the
// class's), and the `this.toolExecutor(...)` dispatch through the injected arrow.
func TestCtorParamPropertyPairsWithConstructionSiteArgument(t *testing.T) {
	g := lowerJSNamedFiles(t, map[string]string{
		"a_wire.ts": `
import { Handlers } from './handlers';

export function start(request: any) {
  const handlers = new Handlers((name, args) => {
    return execSync(args.command);
  });
  return handlers.handle(request);
}
`,
		"z_handlers.ts": `
export class Handlers {
  constructor(
    private toolExecutor: (name: string, args: any) => any
  ) {}

  handle(request: any) {
    return this.toolExecutor(request.name, request.args);
  }
}
`,
	})
	// the dispatch half on its own: the argument of this.toolExecutor(...) reaches the
	// injected arrow's body, so its sink sees the request's taint.
	src := paramOf(g, "handle", "request")
	if src == "" {
		t.Fatal("handle's parameter never lowered")
	}
	sink := callArgOf(g, "execSync", 0)
	if sink == "" {
		t.Fatal("the sink inside the injected arrow never lowered")
	}
	if !reaches(t, g, src, sink) {
		t.Fatal("the argument of a this.<field>(...) dispatch through a constructor-injected callback never reached the callback's sink")
	}
	// and the whole route: start's request reaches the same sink through handle.
	entry := paramOf(g, "start", "request")
	if entry == "" {
		t.Fatal("start's parameter never lowered")
	}
	if !reaches(t, g, entry, sink) {
		t.Fatal("the entry value never reached the constructor-injected callback's sink")
	}
}

// The plain-JavaScript spelling of the same fact: the store written by hand where the
// parameter property spells it implicitly.
func TestHandWrittenCtorFieldStorePairsWithConstructionSiteArgument(t *testing.T) {
	g := lowerJSFile(t, `
class Handlers {
  constructor(toolExecutor) {
    this.toolExecutor = toolExecutor;
  }
  handle(request) {
    return this.toolExecutor(request.name, request.args);
  }
}

export function start(request) {
  const handlers = new Handlers((name, args) => {
    return execSync(args.command);
  });
  return handlers.handle(request);
}
`)
	src := paramOf(g, "handle", "request")
	if src == "" {
		t.Fatal("handle's parameter never lowered")
	}
	sink := callArgOf(g, "execSync", 0)
	if sink == "" {
		t.Fatal("the sink inside the injected arrow never lowered")
	}
	if !reaches(t, g, src, sink) {
		t.Fatal("the argument of a this.<field>(...) dispatch through a constructor-injected callback never reached the callback's sink")
	}
}

// The pairing joins two call sites; it must not invent a declaration. The field stays a
// field -- nothing registers a function of that name -- so an ordinary call of the bare
// name keeps the (unresolved) meaning it always had.
func TestCtorFieldPairingRegistersNoMethod(t *testing.T) {
	g := lowerJSFile(t, `
class Handlers {
  constructor(toolExecutor) {
    this.toolExecutor = toolExecutor;
  }
  handle(request) {
    return this.toolExecutor(request.name, request.args);
  }
}

const handlers = new Handlers((name, args) => {
  return execSync(args.command);
});
`)
	if _, ok := funcDefNames(g)["toolExecutor"]; ok {
		t.Fatal("the paired field became a function definition; it is storage a construction site fills")
	}
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// javaLower lowers one Java file into a graph.
func javaLower(t *testing.T, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "Handler.java")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// javaParamReachesCallArg reports whether the parameter named from reaches the argument of
// the call whose callee path is callee. The argument is the Arg node flowing into that
// call, which identifies it without relying on a loc the semantic-review nodes also carry.
func javaParamReachesCallArg(t *testing.T, g usg.Store, from, callee string) bool {
	t.Helper()
	call := javaOneNode(t, g, "code.Call", "callee_path", callee)
	ins, err := g.InEdges(call, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	var arg string
	for _, ed := range ins {
		src, ok, err := g.GetNode(ed.Src)
		if err != nil || !ok {
			t.Fatalf("call %s has an edge from a missing node", callee)
		}
		if src.Type == "code.Arg" {
			if arg != "" {
				t.Fatalf("call %s has several argument slots", callee)
			}
			arg = src.ID
		}
	}
	if arg == "" {
		t.Fatalf("call %s has no argument slot", callee)
	}
	reach, err := usg.BFS(g, javaOneNode(t, g, "code.Param", "name", from), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	return reach[arg]
}

// javaOneNode returns the id of the one node of typ carrying key=val, failing when there
// is none or several — several would make the question ambiguous.
func javaOneNode(t *testing.T, g usg.Store, typ, key, val string) string {
	t.Helper()
	ids, err := g.NodesOfType(typ)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if ok && n.Prop(key) == val {
			if found != "" {
				t.Fatalf("more than one %s carries %s=%s", typ, key, val)
			}
			found = id
		}
	}
	if found == "" {
		t.Fatalf("no %s carries %s=%s", typ, key, val)
	}
	return found
}

// TestJavaChainedBuilderAppendFoldsIntoBaseVariable: a fluent mutator statement
// `sb.append(prefix).append(tainted)` mutates the variable at the chain's base, so a
// later read of that variable must see the argument's taint. This drives the real Java
// frontend — the chain's outer link takes the first link's Call as its receiver, which
// is the shape the statement fold has to unwrap — so it also fails if the frontend ever
// stops emitting the chain as nested calls.
func TestJavaChainedBuilderAppendFoldsIntoBaseVariable(t *testing.T) {
	g := javaLower(t, `class Handler {
  void handler(String tainted, String prefix) {
    StringBuilder sb = new StringBuilder();
    sb.append(prefix).append(tainted);
    execute(sb.toString());
  }
}`)
	if !javaParamReachesCallArg(t, g, "tainted", "execute") {
		t.Fatalf("chained append did not fold its argument into the builder variable; sb.toString() read a clean builder")
	}
}

// TestJavaChainedAppendThroughNonMutatorDoesNotFold: only a chain made entirely of
// receiver mutators writes the base — a link that merely READS its receiver
// (`q.describe(prefix).append(tainted)`) must not taint q, because describe's result is
// not q.
func TestJavaChainedAppendThroughNonMutatorDoesNotFold(t *testing.T) {
	g := javaLower(t, `class Handler {
  void handler(String tainted, String prefix) {
    Query q = new Query();
    q.describe(prefix).append(tainted);
    execute(q.toString());
  }
}`)
	if javaParamReachesCallArg(t, g, "tainted", "execute") {
		t.Fatalf("append chained through a non-mutator link folded tainted into the base variable")
	}
}

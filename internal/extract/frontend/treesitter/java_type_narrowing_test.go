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

// javaTypeNarrowingGuard returns the analysis.guard.type_narrowing call node, which
// arm it narrowed (for the loc check), and fails when none was emitted.
func javaTypeNarrowingGuard(t *testing.T, g usg.Store) usg.Node {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.guard.type_narrowing" {
			return n
		}
	}
	t.Fatalf("no analysis.guard.type_narrowing call in graph; nodes=%v", javaNodeSummary(nodes))
	return usg.Node{}
}

func javaNodeSummary(nodes []usg.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Type+" "+n.Prop("callee_path")+" "+n.Prop("name")+" "+n.Prop("loc"))
	}
	return out
}

func javaNode(t *testing.T, g usg.Store, typ string, props ...string) usg.Node {
	t.Helper()
	if len(props)%2 != 0 {
		t.Fatalf("props must be key/value pairs")
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != typ {
			continue
		}
		match := true
		for i := 0; i < len(props); i += 2 {
			if n.Prop(props[i]) != props[i+1] {
				match = false
				break
			}
		}
		if match {
			return n
		}
	}
	t.Fatalf("no %s node with %v; nodes=%v", typ, props, javaNodeSummary(nodes))
	return usg.Node{}
}

// The spring-kafka CVE-2023-34040 fix shape: a record header flows toward a
// deserialization sink and the fix bounds it with `header instanceof
// DeserializationExceptionHeader` — a package-private subclass an input channel
// cannot construct. The engine's contribution is the attribution relation: the
// narrowing guard carries BOTH the checked type and the registry's visibility fact
// for it, so vocabulary can state "bounded to what the input channel cannot
// construct" without crediting a check on a public, forgeable type.
func TestJavaInstanceofNarrowingAttributesTypeVisibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ListenerUtils.java")
	src := []byte(`class DeserializationExceptionHeader extends RecordHeader {}
public class ListenerUtils {
  void deserialize(Header header) {
    if (header instanceof DeserializationExceptionHeader) {
      readObject(header.value());
    }
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	guard := javaTypeNarrowingGuard(t, g)
	if toks := guard.Prop("str_args"); !strings.Contains(toks, "type=DeserializationExceptionHeader") ||
		!strings.Contains(toks, "visibility=non_public") {
		t.Fatalf("guard tokens = %q, want type=DeserializationExceptionHeader and visibility=non_public", toks)
	}
	// the guard must sit ON the branch's taint path: the narrowed value reaches it and
	// the sink argument is reachable only through it.
	param := javaNode(t, g, "code.Param", "name", "header")
	sinkArg := javaNode(t, g, "code.Arg", "loc", "ListenerUtils.java:5")
	fromParam, err := usg.BFS(g, param.ID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromParam[guard.ID] {
		t.Fatalf("guard is not reachable from the narrowed value")
	}
	fromGuard, err := usg.BFS(g, guard.ID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromGuard[sinkArg.ID] {
		t.Fatalf("sink argument is not reachable through the guard")
	}
	// reads inside the narrowed branch resolve as the checked type, so receiver-typed
	// bindings keep working on a value that now flows through the guard node.
	if dt := guard.Prop("decl_type"); dt != "DeserializationExceptionHeader" {
		t.Fatalf("guard decl_type = %q, want DeserializationExceptionHeader", dt)
	}
}

// A public checked type is forgeable by any caller: the visibility fact must say so,
// which is what keeps a binding from crediting the narrowing as a bound.
func TestJavaInstanceofNarrowingOnPublicTypeReportsPublic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PublicGuard.java")
	src := []byte(`public class PublicHeader {}
public class PublicGuard {
  void deserialize(Header header) {
    if (header instanceof PublicHeader) {
      readObject(header.value());
    }
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	guard := javaTypeNarrowingGuard(t, g)
	if toks := guard.Prop("str_args"); !strings.Contains(toks, "type=PublicHeader") ||
		!strings.Contains(toks, "visibility=public") {
		t.Fatalf("guard tokens = %q, want type=PublicHeader and visibility=public", toks)
	}
}

// A type the program does not declare has no visibility fact to attribute; the token
// says unknown rather than guessing, so a binding requiring non_public withholds credit.
func TestJavaInstanceofNarrowingOnUndeclaredTypeReportsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ForeignGuard.java")
	src := []byte(`public class ForeignGuard {
  void deserialize(Header header) {
    if (header instanceof NotInThisCorpus) {
      readObject(header.value());
    }
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	guard := javaTypeNarrowingGuard(t, g)
	if toks := guard.Prop("str_args"); !strings.Contains(toks, "type=NotInThisCorpus") ||
		!strings.Contains(toks, "visibility=unknown") {
		t.Fatalf("guard tokens = %q, want type=NotInThisCorpus and visibility=unknown", toks)
	}
}

// `!(x instanceof T)` narrows on the ELSE arm: the reads that the guard bounds are the
// ones in else, not then.
func TestJavaNegatedInstanceofNarrowsElseArm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "NegatedGuard.java")
	src := []byte(`class DeserializationExceptionHeader extends RecordHeader {}
public class NegatedGuard {
  void deserialize(Header header) {
    if (!(header instanceof DeserializationExceptionHeader)) {
      skip();
    } else {
      readObject(header.value());
    }
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	guard := javaTypeNarrowingGuard(t, g)
	param := javaNode(t, g, "code.Param", "name", "header")
	sinkArg := javaNode(t, g, "code.Arg", "loc", "NegatedGuard.java:7")
	fromGuard, err := usg.BFS(g, guard.ID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromGuard[sinkArg.ID] {
		t.Fatalf("else-arm sink argument is not reachable through the guard")
	}
	fromParam, err := usg.BFS(g, param.ID, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !fromParam[guard.ID] {
		t.Fatalf("guard is not reachable from the narrowed value")
	}
}

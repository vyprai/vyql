package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
)

func TestJavaExtractsClassBases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BroadcastRestService.java")
	src := []byte(`class BroadcastRestService extends RestServiceBase implements AutoCloseable {
  public void close() {}
}
class RestServiceBase {}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJava([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var walk func([]nir.Stmt)
	walk = func(stmts []nir.Stmt) {
		for _, st := range stmts {
			if c, ok := st.(nir.ClassDef); ok {
				if c.Name == "BroadcastRestService" {
					got = c.Bases
					return
				}
				walk(c.Body)
			}
		}
	}
	for _, mod := range prog.Modules {
		walk(mod.Body)
	}
	want := map[string]bool{"RestServiceBase": true, "AutoCloseable": true}
	if len(got) != len(want) {
		t.Fatalf("bases = %v, want RestServiceBase and AutoCloseable", got)
	}
	for _, base := range got {
		if !want[base] {
			t.Fatalf("unexpected base %q in %v", base, got)
		}
	}
}

func TestJavaFunctionContextIncludesClassBases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "YamlCtor.java")
	src := []byte(`class YamlCtor extends Constructor {
  public Object construct(Node node) {
    return constructMapping(node);
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
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" {
			args := n.Prop("str_args")
			if strings.Contains(args, "function_name:construct") &&
				strings.Contains(args, "class_name:YamlCtor") &&
				strings.Contains(args, "class_base:Constructor") {
				return
			}
		}
	}
	t.Fatalf("function context did not include enclosing class base; nodes=%#v", nodes)
}

func TestJavaFunctionContextIncludesModifierTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ChecksumCalculator.java")
	src := []byte(`public final class ChecksumCalculator {
  public static void digest() {
    MessageDigest.getInstance("SHA-1");
  }
}
class PackagePrivateChecksum {
  void digest() {
    MessageDigest.getInstance("SHA-1");
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
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var sawPublicDigest bool
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		if strings.Contains(args, "class_name:ChecksumCalculator") &&
			strings.Contains(args, "function_name:digest") &&
			strings.Contains(args, "class_modifier:public") &&
			strings.Contains(args, "class_modifier:final") &&
			strings.Contains(args, "function_modifier:public") &&
			strings.Contains(args, "function_modifier:static") {
			sawPublicDigest = true
		}
		if strings.Contains(args, "class_name:PackagePrivateChecksum") &&
			(strings.Contains(args, "class_modifier:public") || strings.Contains(args, "function_modifier:public")) {
			t.Fatalf("package-private context unexpectedly had public modifier token: %s", args)
		}
	}
	if !sawPublicDigest {
		t.Fatalf("public digest context did not include expected modifier tokens; nodes=%#v", nodes)
	}
}

func TestJavaThreadLocalLifecycleContextTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "RequestScopedCache.java")
	src := []byte(`import java.util.LinkedList;
import java.util.List;
class RequestScopedCache {
  private static final ThreadLocal<List<RequestScopedItem>> CACHE = new ThreadLocal<List<RequestScopedItem>>();
  public static void beginRequest() {
    CACHE.set(new LinkedList<RequestScopedItem>());
  }
  public static void endRequest() {
    CACHE.remove();
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
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var contexts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		contexts = append(contexts, args)
		if strings.Contains(args, "class_name:RequestScopedCache") &&
			strings.Contains(args, "function_name:beginRequest") &&
			strings.Contains(args, "call_path:CACHE.set") {
			return
		}
	}
	t.Fatalf("beginRequest context did not include expected tokens: %#v", contexts)
}

func TestJavaFunctionContextIncludesCallOrderTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Push.java")
	src := []byte(`class Push {
  void doFilter(Request req, Response resp) {
    Meteor.build(req);
    String id = req.getParameter("pushSessionId");
    Session session = manager.getPushSession(id);
    if (session == null) {
      resp.sendError(400);
      return;
    }
    new RequestImpl(session).suspend();
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
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var contexts []string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		contexts = append(contexts, args)
		if strings.Contains(args, "function_name:doFilter") &&
			strings.Contains(args, "call_order:Meteor.build>req.getParameter") &&
			strings.Contains(args, "call_order:manager.getPushSession>resp.sendError") &&
			strings.Contains(args, "call_order:resp.sendError>RequestImpl") {
			return
		}
	}
	t.Fatalf("doFilter context did not include expected call order tokens: %#v", contexts)
}

func TestJavaFunctionContextIncludesNumericLiteralTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "WorldGuard.java")
	src := []byte(`class WorldGuard {
  void testCoords(int x, int z) {
    if (x > 30000000 || z < -30000000) {
      throw new RuntimeException();
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
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		if strings.Contains(args, "function_name:testCoords") && strings.Contains(args, "literal:30000000") {
			return
		}
	}
	t.Fatalf("testCoords context did not include numeric literal token; nodes=%#v", nodes)
}

func TestJavaEnhancedForBindsElementToIterable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "C.java")
	src := []byte(`class C {
  void h(String[] streamIds) {
    for (String id : streamIds) {
      logger.warn("x", id);
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
	if !hasEnhancedForBinding(prog.Modules, "id", "streamIds") {
		t.Fatalf("enhanced for did not bind id to streamIds")
	}
}

func hasEnhancedForBinding(mods []nir.Module, target, source string) bool {
	var walkStmts func([]nir.Stmt) bool
	var exprName func(nir.Expr) string
	exprName = func(e nir.Expr) string {
		if n, ok := e.(nir.Name); ok {
			return n.ID
		}
		return ""
	}
	walkStmts = func(stmts []nir.Stmt) bool {
		for _, st := range stmts {
			switch x := st.(type) {
			case nir.ClassDef:
				if walkStmts(x.Body) {
					return true
				}
			case nir.FuncDef:
				if walkStmts(x.Body) {
					return true
				}
			case nir.Loop:
				if len(x.Body) > 0 {
					if a, ok := x.Body[0].(nir.Assign); ok && len(a.Targets) == 1 &&
						a.Targets[0] == target && exprName(a.Value) == source {
						return true
					}
				}
				if walkStmts(x.Body) {
					return true
				}
			case nir.Block:
				if walkStmts(x.Stmts) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range mods {
		if walkStmts(mod.Body) {
			return true
		}
	}
	return false
}

package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
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

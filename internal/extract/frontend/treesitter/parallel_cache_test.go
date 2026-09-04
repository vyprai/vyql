package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/extract/parsecache"
)

func TestFreshTreeSitterModulePublishesAStoredStub(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Example.java")
	if err := os.WriteFile(src, []byte("class Example { String echo(String s) { return s; } }"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	c, err := parsecache.OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	restore := parsecache.SetShared(c)
	t.Cleanup(func() {
		restore()
		_ = c.Close()
	})

	p, err := ExtractJava([]string{src}, dir)
	if err != nil {
		t.Fatalf("ExtractJava: %v", err)
	}
	if len(p.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(p.Modules))
	}
	stub := p.Modules[0]
	if stub.CacheKey == "" || stub.Body != nil || stub.Imports != nil {
		t.Fatalf("published module is not an identity-only stub: %#v", stub)
	}
	stored, ok := c.Get(stub.CacheKey)
	if !ok || len(stored.Body) == 0 {
		t.Fatal("stored module body is unavailable")
	}
	class := stored.Body[0].(nir.ClassDef)
	fn := class.Body[0].(nir.FuncDef)
	if _, ok := fn.Body[0].(nir.BodyRef); !ok {
		t.Fatalf("stored function body = %#v, want BodyRef", fn.Body)
	}

	g, err := lowering.LowerTypedDeferred(p, true, nil, c)
	if err != nil {
		t.Fatalf("LowerTypedDeferred: %v", err)
	}
	nodes, err := g.AllNodes()
	if err != nil || len(nodes) == 0 {
		t.Fatalf("lowered nodes = %d, err = %v", len(nodes), err)
	}
}

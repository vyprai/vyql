package parsecache

import (
	"bytes"
	"encoding/gob"
	"os"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestTransientSpoolRoundTripsAndRemovesItsFile(t *testing.T) {
	c, err := OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	path := c.spool.path
	c.PutRaw("k", []byte("value"))
	got, ok := c.GetRaw("k")
	if !ok || string(got) != "value" {
		t.Fatalf("GetRaw = %q, %v; want value, true", got, ok)
	}
	if c.Persistent() {
		t.Fatal("transient spool reported itself persistent")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("spool file survived Close: %v", err)
	}
}

func TestDeferFunctionBodyChunksAndRoundTripsInOrder(t *testing.T) {
	c, err := OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	const count = 9000
	body := make([]nir.Stmt, count)
	for i := range body {
		body[i] = nir.ExprStmt{Value: nir.Const{Value: "x"}}
	}
	deferred := c.DeferFunctionBody(body)
	if len(deferred) != 1 {
		t.Fatalf("deferred body has %d statements, want one reference", len(deferred))
	}
	ref, ok := deferred[0].(nir.BodyRef)
	if !ok || len(ref.Keys) < 2 {
		t.Fatalf("deferred body = %#v, want a multi-chunk BodyRef", deferred[0])
	}

	decoded := 0
	for _, key := range ref.Keys {
		raw, ok := c.GetRaw(key)
		if !ok {
			t.Fatalf("missing chunk %q", key)
		}
		var chunk []nir.Stmt
		if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&chunk); err != nil {
			t.Fatalf("decode %q: %v", key, err)
		}
		decoded += len(chunk)
	}
	if decoded != count {
		t.Fatalf("decoded %d statements, want %d", decoded, count)
	}
}

func TestDeferModuleBodiesLeavesSignaturesInline(t *testing.T) {
	c, err := OpenTransient(t.TempDir())
	if err != nil {
		t.Fatalf("OpenTransient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	m := nir.Module{Body: []nir.Stmt{
		nir.ClassDef{Name: "C", Body: []nir.Stmt{
			nir.FuncDef{Name: "f", Params: []string{"p"}, Body: []nir.Stmt{nir.Return{Value: nir.Name{ID: "p"}}}},
		}},
	}}
	c.DeferModuleBodies(&m)
	class, ok := m.Body[0].(nir.ClassDef)
	if !ok || len(class.Body) != 1 {
		t.Fatalf("class signature was not retained: %#v", m.Body)
	}
	fn, ok := class.Body[0].(nir.FuncDef)
	if !ok || fn.Name != "f" || len(fn.Params) != 1 {
		t.Fatalf("function signature was not retained: %#v", class.Body)
	}
	if len(fn.Body) != 1 {
		t.Fatalf("function body has %d entries, want one reference", len(fn.Body))
	}
	if _, ok := fn.Body[0].(nir.BodyRef); !ok {
		t.Fatalf("function body = %#v, want BodyRef", fn.Body[0])
	}
}

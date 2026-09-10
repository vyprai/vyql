package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// phpLowerFilesTyped is phpLowerFiles with the constructor→type table a scan builds from the
// bindings' ReceiverType facts, which is what makes a construction a known one at all.
func phpLowerFilesTyped(t *testing.T, files map[string]string, ctorTypes map[string]string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(files))
	for name, src := range files {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, file)
	}
	prog, err := treesitter.ExtractPHP(paths, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.LowerTyped(prog, true, ctorTypes)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// phpFindNode returns the one node of the given type carrying each key/value property.
func phpFindNode(t *testing.T, g usg.Store, typ string, props ...string) usg.Node {
	t.Helper()
	if len(props)%2 != 0 {
		t.Fatalf("props must be key/value pairs")
	}
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var found usg.Node
	for _, n := range all {
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
		if !match {
			continue
		}
		if found.ID != "" {
			t.Fatalf("more than one %s node with %v", typ, props)
		}
		found = n
	}
	if found.ID == "" {
		t.Fatalf("no %s node with %v", typ, props)
	}
	return found
}

// The MVC shape every PHP framework writes: the connection is built in one method, stored on
// `$this`, and called through that property in another. The property read is the constructed
// object, so the call carries its type -- the same stamp a plain local holding the
// construction's result already gets -- and a binding may constrain the call's receiver by it
// instead of matching the bare method name.
func TestPHPReceiverReadOffAPropertyCarriesTheConstructedType(t *testing.T) {
	g := phpLowerFilesTyped(t, map[string]string{
		"Repo.php": `<?php
class Repo {
  private $pdo;
  public function __construct() {
    $this->pdo = new PDO('sqlite:x.db');
  }
  public function q($s) {
    return $this->pdo->query($s);
  }
}`,
	}, map[string]string{"PDO": "PDO"})

	n := phpFindNode(t, g, "code.Call", "callee_path", "$this.pdo.query")
	if got := n.Prop("recv_type"); got != "PDO" {
		t.Fatalf("recv_type = %q, want PDO; props=%+v", got, n.Props)
	}
	if got := n.Prop("recv"); got == "" {
		t.Fatalf("recv = %q, want the property read node", got)
	}
}

// One write the table does not name is enough to withhold the type: the property may hold
// that other value at the read, and a receiver type is what a sink uses to reject a call.
func TestPHPReceiverPropertyWrittenFromTwoShapesStaysUntyped(t *testing.T) {
	g := phpLowerFilesTyped(t, map[string]string{
		"Repo.php": `<?php
class Repo {
  private $pdo;
  public function __construct($dsn) {
    $this->pdo = new PDO($dsn);
  }
  public function close() {
    $this->pdo = null;
  }
  public function q($s) {
    return $this->pdo->query($s);
  }
}`,
	}, map[string]string{"PDO": "PDO"})

	n := phpFindNode(t, g, "code.Call", "callee_path", "$this.pdo.query")
	if got := n.Prop("recv_type"); got != "" {
		t.Fatalf("recv_type = %q, want empty: the property is also written from null", got)
	}
}

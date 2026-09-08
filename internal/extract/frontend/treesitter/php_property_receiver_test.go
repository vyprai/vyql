package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// phpLowerFiles lowers several PHP files as one program, so a call that crosses from one
// file into another is resolved the way a scan of the repository resolves it.
func phpLowerFiles(t *testing.T, files map[string]string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		file := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, file)
	}
	prog, err := treesitter.ExtractPHP(paths, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The MVC shape every PHP framework writes: a controller holds its model in an untyped
// property and calls through it. Nothing states what `$this->model` holds, so no receiver
// type resolves the call — it used to resolve to nothing at all, and a sink written in the
// model's own body was unreachable from the controller's request parameter.
func TestPHPCallThroughUntypedModelPropertyFollowsTaint(t *testing.T) {
	g := phpLowerFiles(t, map[string]string{
		"controllers/Items.php": `<?php
class Items extends CI_Controller {
  public $model;
  public function index($q) {
    return $this->model->list_items($q);
  }
}`,
		"models/Item_model.php": `<?php
class Item_model extends CI_Model {
  public function list_items($needle) {
    return mysql_query("SELECT * FROM items WHERE name = '" . $needle . "'");
  }
}`,
	})

	if !phpParamReachesCall(t, g, "$q", "mysql_query") {
		t.Fatalf("taint stops at the call through the untyped model property")
	}
}

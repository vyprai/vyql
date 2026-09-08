package treesitter_test

import "testing"

// The MVC shape every PHP framework writes: a controller holds its model in an untyped
// property and calls through it. Nothing states what `$this->model` holds, so no receiver
// type resolves the call, and without a route a sink written in the model's own body is
// unreachable from the controller's request parameter.
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

// The same call where the method name is NOT unique: a model base class declares
// `list_items` and each model overrides it, which is how every CodeIgniter application is
// written. The declarations are one method dispatched over a hierarchy, so the argument
// reaches each body and a sink in any of them is coverable; a same-named method on an
// unrelated class (`Custom_fields::list_items`) is coincidence and is not routed to.
func TestPHPCallThroughUntypedModelPropertyReachesTheOverrideFamily(t *testing.T) {
	g := phpLowerFiles(t, map[string]string{
		"controllers/Module.php": `<?php
class Module extends CI_Controller {
  public $model;
  public function items($sort) {
    return $this->model->list_items(50, 0, $sort, 'asc');
  }
}`,
		"models/Base_module_model.php": `<?php
class Base_module_model extends CI_Model {
  public function list_items($limit = NULL, $offset = 0, $col = 'id', $order = 'asc') {
    $this->db->order_by($col, $order);
    return $this->db->get();
  }
}`,
		"models/Fuel_blocks_model.php": `<?php
class Fuel_blocks_model extends Base_module_model {
  public function list_items($limit = NULL, $offset = 0, $col = 'name', $order = 'asc') {
    return blocks_query($col);
  }
}`,
		"libraries/Custom_fields.php": `<?php
class Custom_fields {
  public function list_items($params) {
    return unrelated_sink($params);
  }
}`,
	})

	if !phpParamReachesCall(t, g, "$sort", "$this.db.order_by") {
		t.Fatalf("taint does not reach the sink in the base model's list_items")
	}
	if !phpParamReachesCall(t, g, "$sort", "blocks_query") {
		t.Fatalf("taint does not reach the sink in the overriding model's list_items")
	}
	if phpParamReachesCall(t, g, "$sort", "unrelated_sink") {
		t.Fatalf("taint reached a same-named method on an unrelated class")
	}
}

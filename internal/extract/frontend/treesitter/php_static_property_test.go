package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// phpLowerFiles extracts and lowers several PHP source files as one program, so a class
// declared in one file and used from another resolves the way a real tree does.
func phpLowerFiles(t *testing.T, srcs map[string]string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	var files []string
	for name, src := range srcs {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	prog, err := treesitter.ExtractPHP(files, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// A class static property is storage on the class, so a method that writes it and a method
// that reads it are talking about the same value — there is no receiver between them the way
// there is for an instance field. The write has to land on the class's storage and the read
// has to name that same storage, or nothing crosses. PHPFusion's Search_Model::$search_text
// (CVE-2021-28280) is the shape.
func TestPHPStaticPropertyCarriesTaintBetweenMethods(t *testing.T) {
	g := phpLowerFile(t, "Store.php", `<?php
class Store {
  protected static $held = '';
  protected static $other = '';
  function keep($v) { self::$held = $v; }
  function emit() { held_sink(self::$held); }
  function emitOther() { other_sink(self::$other); }
}`)

	if !phpParamReachesCall(t, g, "$v", "held_sink") {
		t.Fatalf("$v does not reach held_sink: taint does not cross the static property write->read")
	}
	// Field-sensitive: a sibling static nobody wrote stays clean.
	if phpParamReachesCall(t, g, "$v", "other_sink") {
		t.Fatalf("$v reaches other_sink: the two static properties share one slot")
	}
}

// PHP does not redeclare an inherited static: the subclass's `self::$p` names the property the
// parent declared, and the subclass body says nothing about it. This is the route CVE-2021-28280
// runs through — Search_Model::init() writes and Search_Engine::display_results() reads, in
// different files — so the slot has to be keyed on the class that declares the property.
func TestPHPStaticPropertyIsSharedWithTheSubclassThatInheritsIt(t *testing.T) {
	g := phpLowerFiles(t, map[string]string{
		"Search_Model.php": `<?php
class Search_Model {
  protected static $search_text = '';
  function init($v) { self::$search_text = $v; }
}`,
		"Search_Engine.php": `<?php
class Search_Engine extends Search_Model {
  function display_results() { render_sink(self::$search_text); }
  function viaParent() { parent_sink(parent::$search_text); }
}`,
	})

	if !phpParamReachesCall(t, g, "$v", "render_sink") {
		t.Fatalf("$v does not reach render_sink: the subclass's self::$$search_text is a different slot from the parent's")
	}
	if !phpParamReachesCall(t, g, "$v", "parent_sink") {
		t.Fatalf("$v does not reach parent_sink: parent::$$search_text is a different slot from the parent's own")
	}
}

// Two classes declaring the same property name are two properties. The declaring class cannot
// be told apart there, so each access keeps the class it names and the slots stay separate —
// merging them by name alone would connect every `self::$data` in a repository to every other.
func TestPHPStaticPropertiesOfDifferentClassesDoNotMerge(t *testing.T) {
	g := phpLowerFile(t, "Pair.php", `<?php
class A {
  protected static $data = '';
  function keep($v) { self::$data = $v; }
}
class B {
  protected static $data = '';
  function emit() { other_class_sink(self::$data); }
}`)

	if phpParamReachesCall(t, g, "$v", "other_class_sink") {
		t.Fatalf("$v reaches other_class_sink: A::$$data and B::$$data share one slot")
	}
}

// `.=` onto a static property appends to the class's storage, so the value the storage holds
// and the appended part both reach a later read.
func TestPHPStaticPropertyAugmentedAssignmentFlows(t *testing.T) {
	g := phpLowerFile(t, "Buf.php", `<?php
class Buf {
  protected static $out = '';
  function add($v) { self::$out .= $v; }
  function emit() { buf_sink(self::$out); }
}`)

	if !phpParamReachesCall(t, g, "$v", "buf_sink") {
		t.Fatalf("$v does not reach buf_sink: `self::$$out .= $$v` does not write the static property's slot")
	}
}

// A scope that names no class — `$obj::$p` — has no storage to key on, so the access keeps the
// generic walk over the expression's parts, which carries the receiver's taint on.
func TestPHPStaticPropertyOnVariableScopeStillFlowsFromItsScope(t *testing.T) {
	g := phpLowerFile(t, "Dyn.php", `<?php
function dyn($v) { dyn_sink($v::$field); }`)

	if !phpParamReachesCall(t, g, "$v", "dyn_sink") {
		t.Fatalf("$v does not reach dyn_sink: a variable-scoped static access lost its scope's taint")
	}
}

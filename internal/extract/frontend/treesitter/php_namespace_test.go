package treesitter_test

import (
	"testing"
)

// A braced namespace declaration (`namespace Acme\Search { … }`) is one namespace_definition
// node whose compound_statement holds the file's whole body. stmtOne had no case for that node
// kind, so every statement inside the braces lowered to nothing — no function, no call, no
// flow — and a file using the braced form was invisible to every rule. The semicolon form
// (`namespace Acme\Search;`) was never affected, because its statements are siblings of the
// declaration rather than children of it: the second file is the control that shows the flow
// walk itself works when the statements are not inside the namespace node.
func TestPHPBracedNamespaceLowersBody(t *testing.T) {
	g := phpLowerFiles(t, map[string]string{
		// PHP rejects mixing the braced and semicolon forms in one file, so the control is a
		// second file rather than a second declaration in this one.
		"Braced.php": `<?php
namespace Acme\Search {
  function braced_fetch($req) {
    braced_sink($req);
  }
}`,
		"Plain.php": `<?php
namespace Acme\Search;

function plain_fetch($res) {
  semicolon_sink($res);
}`,
	})

	if !phpParamReachesCall(t, g, "$req", "braced_sink") {
		t.Fatalf("$req does not reach braced_sink: the braced namespace body lowered to nothing")
	}
	if !phpParamReachesCall(t, g, "$res", "semicolon_sink") {
		t.Fatalf("$res does not reach semicolon_sink: the flow walk sees no taint at all")
	}
}

// The braced body carries whole declarations, not just calls: a class in its own namespace
// file is the shape a namespaced library ships. Everything inside the braces goes through the
// same statement machinery as top-level code, so the method lowers and its parameter flows.
func TestPHPBracedNamespaceLowersClassDeclarations(t *testing.T) {
	g := phpLowerFile(t, "Library.php", `<?php
namespace Acme\Search {

class Engine {
  public function run($raw) {
    return braced_sink($raw);
  }
}

}`)
	if !phpParamReachesCall(t, g, "$raw", "braced_sink") {
		t.Fatalf("$raw does not reach braced_sink: the class method in the braced namespace lowered to nothing")
	}
}

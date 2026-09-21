package treesitter_test

import (
	"testing"
)

// `[$a, $b] = f()` is how PHP unpacks a returned row into named fields. The
// assignment_expression arm used to lower it as a bare expression — the RHS call was lowered
// but its value flowed nowhere, so $a and $b were unbound downstream and every sink after the
// destructuring was unreachable. The straight-line assignment is the control: it flows, so the
// difference is the left side's shape, not the flow walk.
func TestPHPListDestructuringBindsNames(t *testing.T) {
	g := phpLowerFile(t, "Row.php", `<?php
function dump($res) {
  [$a, $b] = fetch_row($res);
  short_sink($a);
  $ctl = fetch_row($res);
  control_sink($ctl);
}`)

	if !phpParamReachesCall(t, g, "$res", "control_sink") {
		t.Fatalf("$res does not reach control_sink: the flow walk sees no taint at all")
	}
	if !phpParamReachesCall(t, g, "$res", "short_sink") {
		t.Fatalf("$res does not reach short_sink: the list destructuring binds nothing")
	}
}

// `list($a, $b) = f()` is the same construct in the legacy spelling, and the keyed and
// nested spellings follow: `["k" => $a]`, `[[$x, $y], $z]`. A hole (`[, $b]`) names nothing.
func TestPHPListDestructuringSpellings(t *testing.T) {
	g := phpLowerFile(t, "Spellings.php", `<?php
function dump($res) {
  list($a, $b) = fetch_row($res);
  list_sink($a);
  ["k" => $c, "j" => $d] = fetch_row($res);
  keyed_sink($d);
  [[$e, $f], $g] = fetch_row($res);
  nested_sink($g);
}`)

	for _, sink := range []string{"list_sink", "keyed_sink", "nested_sink"} {
		if !phpParamReachesCall(t, g, "$res", sink) {
			t.Fatalf("$res does not reach %s: that spelling of the destructuring binds nothing", sink)
		}
	}
}

// Each destructured name is bound to the whole RHS conservatively — which element it gets is
// not knowable without modelling the callee — so taint reaches a sink through either name.
func TestPHPListDestructuringBindsEveryName(t *testing.T) {
	g := phpLowerFile(t, "Either.php", `<?php
function dump($res) {
  [$a, $b] = fetch_row($res);
  first_sink($a);
  second_sink($b);
}`)

	if !phpParamReachesCall(t, g, "$res", "first_sink") {
		t.Fatalf("$res does not reach first_sink through $a")
	}
	if !phpParamReachesCall(t, g, "$res", "second_sink") {
		t.Fatalf("$res does not reach second_sink through $b")
	}
}

// The same arm covers an array-literal RHS (`[$u, $v] = [$src, "z"]`), where the element a name
// gets IS written down — but the conservative whole-RHS binding is still what the arm emits, so
// taint crosses to both names rather than only the one that literally holds it.
func TestPHPListDestructuringArrayLiteralRHS(t *testing.T) {
	g := phpLowerFile(t, "Pair.php", `<?php
function dump($src) {
  [$u, $v] = [$src, "z"];
  u_sink($u);
  v_sink($v);
}`)

	if !phpParamReachesCall(t, g, "$src", "u_sink") {
		t.Fatalf("$src does not reach u_sink through $u")
	}
	if !phpParamReachesCall(t, g, "$src", "v_sink") {
		t.Fatalf("$src does not reach v_sink through $v")
	}
}

// The destructuring replaces the expression it used to be lowered as rather than adding to it:
// the RHS call is lowered exactly once, so a call that is itself a sink is not reported twice.
func TestPHPListDestructuringCallLoweredOnce(t *testing.T) {
	g := phpLowerFile(t, "Once.php", `<?php
function dump($res) {
  [$a, $b] = fetch_row($res);
  list_sink($a);
}`)

	counts := countCalls(t, g)
	if counts["fetch_row"] != 1 {
		t.Fatalf("fetch_row lowered %d times, want exactly 1 (%v)", counts["fetch_row"], counts)
	}
}

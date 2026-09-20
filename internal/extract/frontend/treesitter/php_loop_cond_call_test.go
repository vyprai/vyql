package treesitter_test

import (
	"testing"
)

// A while/for condition is evaluated before every iteration, but it is not part of the
// Loop body the statement lowers to, so a call written only there had no node at all:
// `while ($r->fetch_row())` and `for (; has_next($res); )` were invisible to every
// binding, while the same call in an if condition, a foreach argument or a statement
// kept its node. A stored-data read a rule has to start from was invisible before any
// binding was consulted — 124 of one repository's 184 mysqli fetch sites sit in that
// position. The condition is lowered at the head of the body it guards, so the bare
// spelling places its call where the idiomatic `while (($row = $r->fetch_row()))`
// already places the fetch the hoisted assignment carries.
func TestPHPLoopConditionCallKeepsNode(t *testing.T) {
	g := phpLowerFile(t, "CondCall.php", `<?php
function dump($res, $r) {
  while ($r->fetch_row()) {
    method_sink($res);
  }
  while (has_next($res)) {
    func_sink($res);
  }
  for ($i = 0; check($res); $i++) {
    for_sink($res);
  }
  do {
    do_sink($res);
  } while (advance($res));
}`)

	counts := countCalls(t, g)
	for _, callee := range []string{"$r.fetch_row", "has_next", "check", "advance"} {
		if counts[callee] != 1 {
			t.Fatalf("condition call %s lowered %d times, want exactly 1 (%v)", callee, counts[callee], counts)
		}
	}
	for _, sink := range []string{"method_sink", "func_sink", "for_sink", "do_sink"} {
		if counts[sink] != 1 {
			t.Fatalf("body call %s lowered %d times, want exactly 1 (%v)", sink, counts[sink], counts)
		}
	}
	if !phpParamReachesCall(t, g, "$res", "has_next") {
		t.Fatalf("$res does not reach has_next: the condition's arguments are invisible")
	}
}

// The condition expression phpCondLower returns names the variable its hoisted
// assignment bound, so lowering it beside that assignment does not lower the call the
// assignment performs a second time — a call that is itself a sink in the idiomatic
// spelling is still reported once, and the body's flow is unchanged.
func TestPHPLoopConditionAssignmentStillLoweredOnce(t *testing.T) {
	g := phpLowerFile(t, "OnceLoop.php", `<?php
function dump($res) {
  while (($row = db_fetch_row($res)) !== false) {
    cmp_sink($row[1]);
  }
}`)

	counts := countCalls(t, g)
	if counts["db_fetch_row"] != 1 {
		t.Fatalf("db_fetch_row lowered %d times, want exactly 1 (%v)", counts["db_fetch_row"], counts)
	}
	if !phpParamReachesCall(t, g, "$res", "cmp_sink") {
		t.Fatalf("$res does not reach cmp_sink: the condition assignment binds nothing")
	}
}

// A for clause may be empty — `for (;;)`, `for ($i = 0; ; $i++)` — and there is no tested
// expression to lower. Lowering the absent condition anyway emitted the nil-expression
// sentinel, a Const at "?:0" with no file or line, as a node inside every such loop: a fact
// about nothing, in the one loop shape PHP leaves conditionless. The body lowers alone.
func TestPHPConditionlessForEmitsNoSentinelNode(t *testing.T) {
	g := phpLowerFile(t, "NoCondFor.php", `<?php
function spin($res) {
  for (;;) {
    step($res);
  }
  for ($i = 0; ; $i++) {
    body_sink($i);
  }
}`)

	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range all {
		// A Phi the lowering adds at a loop join is locationless by design; the sentinel is
		// specifically a Const — an expression the file never contained.
		if n.Type == "code.Const" && n.Prop("loc") == "?:0" {
			t.Fatalf("node %s is a Const at the nil-expression location ?:0; the absent condition lowered to a sentinel", n.ID)
		}
	}
	counts := countCalls(t, g)
	for _, callee := range []string{"step", "body_sink"} {
		if counts[callee] != 1 {
			t.Fatalf("body call %s lowered %d times, want exactly 1 (%v)", callee, counts[callee], counts)
		}
	}
}

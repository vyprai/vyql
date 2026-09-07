package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// countCalls counts the lowered call nodes per callee path, ignoring the analysis.*
// bookkeeping calls the lowering adds.
func countCalls(t *testing.T, g usg.Store) map[string]int {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, n := range all {
		if n.Type == "code.Call" {
			counts[n.Prop("callee_path")]++
		}
	}
	return counts
}

// `while ($row = db_fetch_row($res))` is the idiomatic PHP row loop: the condition performs
// the assignment the body reads. The condition used to be lowered as an expression only, so
// $row was never defined and every read of it in the body was of an unbound variable — the
// database value reaching an echo was invisible. The straight-line assignment is the
// control: it flows, so the difference is the assignment's position, not the flow walk.
func TestPHPWhileConditionAssignmentBindsBodyVariable(t *testing.T) {
	g := phpLowerFile(t, "Rows.php", `<?php
function dump($res) {
  while ($row = db_fetch_row($res)) {
    while_sink($row[1]);
  }
  $ctl = db_fetch_row($res);
  control_sink($ctl[1]);
}`)

	if !phpParamReachesCall(t, g, "$res", "control_sink") {
		t.Fatalf("$res does not reach control_sink: the flow walk sees no taint at all")
	}
	if !phpParamReachesCall(t, g, "$res", "while_sink") {
		t.Fatalf("$res does not reach while_sink: the while-condition assignment binds nothing")
	}
}

// The same hole in if_statement: `if ($row = db_fetch_assoc($res))` defines $row for the
// branch it guards.
func TestPHPIfConditionAssignmentBindsBranchVariable(t *testing.T) {
	g := phpLowerFile(t, "Row.php", `<?php
function show($res) {
  if ($row = db_fetch_assoc($res)) {
    if_sink($row['name']);
  } elseif ($alt = db_fetch_assoc($res)) {
    elseif_sink($alt['name']);
  }
}`)

	if !phpParamReachesCall(t, g, "$res", "if_sink") {
		t.Fatalf("$res does not reach if_sink: the if-condition assignment binds nothing")
	}
	if !phpParamReachesCall(t, g, "$res", "elseif_sink") {
		t.Fatalf("$res does not reach elseif_sink: the elseif-condition assignment binds nothing")
	}
}

// The assignment is just as often written inside a comparison or a negation, and do/for
// loops carry the same condition.
func TestPHPNestedConditionAssignmentBindsBodyVariable(t *testing.T) {
	g := phpLowerFile(t, "Nested.php", `<?php
function dump($res) {
  while (($row = db_fetch_row($res)) !== false) {
    cmp_sink($row[1]);
  }
  do {
    do_sink($drow[1]);
  } while ($drow = db_fetch_row($res));
  for ($i = 0; $frow = db_fetch_row($res); $i++) {
    for_sink($frow[1]);
  }
  if (!($nrow = db_fetch_row($res))) {
    neg_sink($nrow[1]);
  }
}`)

	for _, sink := range []string{"cmp_sink", "do_sink", "for_sink", "neg_sink"} {
		if !phpParamReachesCall(t, g, "$res", sink) {
			t.Fatalf("$res does not reach %s: the condition assignment binds nothing", sink)
		}
	}
}

// The hoisted assignment replaces the assignment in the condition rather than repeating it:
// the call it performs is lowered exactly once, so a call that is itself a sink is not
// reported twice. The condition still tests the bound variable, so a call written beside the
// assignment keeps its own node.
func TestPHPConditionAssignmentCallLoweredOnce(t *testing.T) {
	g := phpLowerFile(t, "Once.php", `<?php
function dump($res) {
  if (($row = db_fetch_row($res)) && guard($res)) {
    body_sink($row[1]);
  }
}`)

	counts := countCalls(t, g)
	if counts["db_fetch_row"] != 1 {
		t.Fatalf("db_fetch_row lowered %d times, want exactly 1 (%v)", counts["db_fetch_row"], counts)
	}
	if counts["guard"] != 1 {
		t.Fatalf("guard lowered %d times, want exactly 1 (%v)", counts["guard"], counts)
	}
}

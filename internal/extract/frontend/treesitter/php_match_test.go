package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// phpLowerFile extracts and lowers one PHP source file.
func phpLowerFile(t *testing.T, name, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// phpParamReachesCall reports whether the parameter named param FLOWS into the call whose
// callee path is method.
func phpParamReachesCall(t *testing.T, g usg.Store, param, method string) bool {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var start string
	sinks := map[string]bool{}
	for _, n := range all {
		if n.Type == "code.Param" && n.Prop("name") == param {
			start = n.ID
		}
		if n.Prop("callee_path") == method {
			sinks[n.ID] = true
		}
	}
	if start == "" {
		t.Fatalf("no code.Param node named %q", param)
	}
	if len(sinks) == 0 {
		t.Fatalf("no call node with callee path %q", method)
	}
	seen := map[string]bool{start: true}
	for queue := []string{start}; len(queue) > 0; {
		cur := queue[0]
		queue = queue[1:]
		if sinks[cur] {
			return true
		}
		edges, err := g.OutEdges(cur, "FLOWS")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range edges {
			if !seen[e.Dst] {
				seen[e.Dst] = true
				queue = append(queue, e.Dst)
			}
		}
	}
	return false
}

// A match expression whose arms all return fixed constants bounds its scrutinee to an
// allowlisted set, so the result carries none of the scrutinee's taint. Before this the
// construct fell to the generic Seq fallback in expr, which made the result a container
// over the scrutinee as well as the arms, and the sort-key-to-column mapping this class of
// fix uses (HumHub cfiles, CVE-2025-54789) never cleared taint.
func TestPHPMatchConstantArmsClearScrutineeTaint(t *testing.T) {
	g := phpLowerFile(t, "Order.php", `<?php
function order($sort) {
  $column = match ($sort) {
    'name', 'title' => 'title',
    'size' => 'size',
    default => 'id',
  };
  bounded_sink($column);
  scrutinee_sink($sort);
}`)

	if phpParamReachesCall(t, g, "$sort", "bounded_sink") {
		t.Fatalf("$sort reaches bounded_sink: the match result is still tainted by its scrutinee")
	}
	// Control: the same parameter read directly does reach a sink, so the walk above is
	// looking at a graph where flow is observable at all.
	if !phpParamReachesCall(t, g, "$sort", "scrutinee_sink") {
		t.Fatalf("$sort does not reach scrutinee_sink: the flow walk sees no taint at all")
	}
}

// The kill is the scrutinee's, not the arms': an arm that returns a tainted value still
// taints the result, and so does an arm that returns the scrutinee itself.
func TestPHPMatchTaintedArmValueStillFlows(t *testing.T) {
	g := phpLowerFile(t, "Arms.php", `<?php
function pick($mode, $raw) {
  $v = match ($mode) {
    'raw' => $raw,
    default => 'id',
  };
  arm_sink($v);
  $w = match ($mode) {
    'self' => $mode,
    default => 'id',
  };
  self_sink($w);
}`)

	if !phpParamReachesCall(t, g, "$raw", "arm_sink") {
		t.Fatalf("$raw does not reach arm_sink: a tainted arm value was dropped")
	}
	if !phpParamReachesCall(t, g, "$mode", "self_sink") {
		t.Fatalf("$mode does not reach self_sink: an arm returning the scrutinee was dropped")
	}
}

// The scrutinee and the arm conditions are still evaluated: a call in either position keeps
// its node (so it can be a sink), and the scrutinee is lowered exactly once however many
// arms the match has.
func TestPHPMatchEvaluatesScrutineeOnceAndArmConditions(t *testing.T) {
	g := phpLowerFile(t, "Calls.php", `<?php
function pick($sort) {
  return match (normalize($sort)) {
    guard_a() => 'a',
    guard_b() => 'b',
    default => 'id',
  };
}`)

	counts := map[string]int{}
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range all {
		if n.Type == "code.Call" && !strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
			counts[n.Prop("callee_path")]++
		}
	}
	if counts["normalize"] != 1 {
		t.Fatalf("scrutinee call lowered %d times, want exactly 1 (%v)", counts["normalize"], counts)
	}
	for _, guard := range []string{"guard_a", "guard_b"} {
		if counts[guard] != 1 {
			t.Fatalf("arm condition call %s lowered %d times, want exactly 1 (%v)", guard, counts[guard], counts)
		}
	}
	if !phpParamReachesCall(t, g, "$sort", "normalize") {
		t.Fatalf("$sort does not reach the scrutinee call: the scrutinee is no longer evaluated")
	}
}

package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// Structural dominance on the region/order encoding the lowering emits (B1.3).
func TestDominatesRegion(t *testing.T) {
	cases := []struct {
		name                   string
		gReg, gOrd, sReg, sOrd string
		want                   bool
	}{
		// straight-line: guard before sink in the same region dominates.
		{"straightline-before", "/fn1", "3", "/fn1", "7", true},
		{"straightline-after", "/fn1", "9", "/fn1", "4", false},
		// guard in the enclosing region, sink nested under it → dominates.
		{"enclosing-dominates-nested", "/fn1", "2", "/fn1/if5.t", "6", true},
		// guard inside one branch does NOT dominate code after the branch (sibling region).
		{"branch-guard-not-after", "/fn1/if5.t", "4", "/fn1", "9", false},
		// guard in the THEN branch does NOT dominate a sink in the ELSE branch.
		{"then-not-else", "/fn1/if5.t", "4", "/fn1/if5.e", "6", false},
		// guard before a nested sink in the same branch → dominates.
		{"same-branch-before", "/fn1/if5.t", "4", "/fn1/if5.t/loop8", "9", true},
		// different functions never dominate (disjoint roots).
		{"cross-function", "/fn1", "2", "/fn2", "3", false},
		// segment-boundary safety: "/fn1" must not be treated as an ancestor of "/fn10".
		{"no-prefix-bleed", "/fn1", "2", "/fn10", "9", false},
		// missing CFG metadata (unconverted frontend) → not decidable → false.
		{"no-metadata", "", "1", "", "2", false},
	}
	for _, c := range cases {
		if got := dominatesRegion(c.gReg, c.gOrd, c.sReg, c.sOrd); got != c.want {
			t.Errorf("%s: dominatesRegion(%q@%s, %q@%s) = %v, want %v",
				c.name, c.gReg, c.gOrd, c.sReg, c.sOrd, got, c.want)
		}
	}
}

// Reaches: a can reach b iff order(a)<order(b) and regions are comparable (not siblings).
func TestReachesRegion(t *testing.T) {
	cases := []struct {
		rA, oA, rB, oB string
		want           bool
	}{
		{"/fn1", "2", "/fn1", "5", true},
		{"/fn1", "5", "/fn1", "2", false},
		{"/fn1", "2", "/fn1/if3.t", "6", true},
		{"/fn1/if3.t", "2", "/fn1", "6", true},
		{"/fn1/if3.t", "2", "/fn1/if3.e", "6", false},
		{"/fn1", "2", "/fn2", "6", false},
		{"", "1", "", "2", false},
	}
	for _, c := range cases {
		if got := reachesRegion(c.rA, c.oA, c.rB, c.oB); got != c.want {
			t.Errorf("reachesRegion(%q@%s -> %q@%s) = %v, want %v", c.rA, c.oA, c.rB, c.oB, got, c.want)
		}
	}
}

// An inline callback ("#") runs somewhere after the code that passes it, so an
// order rule can sequence across it — but it must not gain the dominance a "/"
// nesting would confer, or a guard inside a callback would suppress findings in
// the code around it.
func TestInlineCallbackRegionSequencesButDoesNotDominate(t *testing.T) {
	const outer, callback = "/fn1", "/fn1#fn2"

	reaches := []struct {
		rA, oA, rB, oB string
		want           bool
	}{
		{callback, "2", outer, "6", true},                 // check in a callback, use after it
		{outer, "2", callback, "6", true},                 // and the other way round
		{callback, "6", outer, "2", false},                // order still decides direction
		{"/fn1#fn2#fn3", "2", outer, "9", true},           // through two levels of nesting
		{"/fn1#fn2", "2", "/fn1/if3.t", "6", true},        // callback and a branch of its owner
		{"/fn4#fn5", "2", "/fn1#fn2", "6", false},         // callbacks of unrelated functions
		{"/fn1/if3.t#fn4", "2", "/fn1/if3.e", "6", false}, // owners are disjoint branches
	}
	for _, c := range reaches {
		if got := reachesRegion(c.rA, c.oA, c.rB, c.oB); got != c.want {
			t.Errorf("reachesRegion(%q@%s -> %q@%s) = %v, want %v", c.rA, c.oA, c.rB, c.oB, got, c.want)
		}
	}

	if dominatesRegion(outer, "2", callback, "6") {
		t.Error("a function must not dominate the body of a callback it passes")
	}
	if dominatesRegion(callback, "2", outer, "6") {
		t.Error("a callback body must not dominate the function that passes it")
	}
	if postDominatesRegion(outer, "6", callback, "2") {
		t.Error("code after a callback is passed must not post-dominate the callback body")
	}
}

func TestReachesFallsBackToSameFileSourceOrderWithoutRegions(t *testing.T) {
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "first", Type: "code.Call", Loc: "app.swift:10", Order: 10, HasOrder: true})
	s.AddNode(usg.Node{ID: "second", Type: "code.Call", Loc: "app.swift:20", Order: 20, HasOrder: true})
	s.AddNode(usg.Node{ID: "other", Type: "code.Call", Loc: "other.swift:30", Order: 30, HasOrder: true})

	if !Reaches(s, "first", "second") {
		t.Fatalf("same-file source-order fallback should reach later node")
	}
	if Reaches(s, "second", "first") {
		t.Fatalf("same-file source-order fallback must preserve ordering")
	}
	if Reaches(s, "first", "other") {
		t.Fatalf("source-order fallback must not cross files without structured regions")
	}
}

// PostDominates: release runs on every path from alloc to exit (leak = its negation).
func TestPostDominatesRegion(t *testing.T) {
	cases := []struct {
		rRel, oRel, rAlloc, oAlloc string
		want                       bool
	}{
		{"/fn1", "5", "/fn1", "2", true},              // release after alloc, same region
		{"/fn1", "5", "/fn1/if3.t", "2", true},        // alloc nested, release after the branch
		{"/fn1/if3.t", "5", "/fn1", "2", false},       // release nested → conditionally skipped → leak
		{"/fn1/if3.e", "5", "/fn1/if3.t", "2", false}, // sibling branch → leak
		{"/fn1", "2", "/fn1", "5", false},             // release before alloc
		{"", "1", "", "2", false},                     // no metadata
	}
	for _, c := range cases {
		if got := postDominatesRegion(c.rRel, c.oRel, c.rAlloc, c.oAlloc); got != c.want {
			t.Errorf("postDominatesRegion(rel %q@%s, alloc %q@%s) = %v, want %v",
				c.rRel, c.oRel, c.rAlloc, c.oAlloc, got, c.want)
		}
	}
}

// PostDominatesCovered: a release covers the acquisition only when EVERY path from it to
// the function's exit runs one — including the paths a `return` inside a branch takes.
func TestPostDominatesCoveredEarlyExitSkipsTrailingRelease(t *testing.T) {
	newStore := func(build func(s *usg.InMemStore)) *usg.InMemStore {
		s := usg.NewInMemStore()
		build(s)
		return s
	}
	node := func(s *usg.InMemStore, id, typ, region string, order int32, props map[string]string) {
		if err := s.AddNode(usg.Node{ID: id, Type: typ, Loc: "app.go:1", Region: region,
			Order: order, HasOrder: true, Props: props}); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}

	// acquire(); if cond { return }; release()  — the early exit never reaches release.
	skipped := newStore(func(s *usg.InMemStore) {
		node(s, "alloc", "code.Call", "/fn1", 2, nil)
		node(s, "exit", usg.ExitNodeType, "/fn1/if3.t", 4, nil)
		node(s, "release", "code.Call", "/fn1", 6, nil)
	})
	if PostDominatesCovered(skipped, NewExitIndex(skipped), []string{"release"}, "alloc") {
		t.Error("a release after a branch that returns must not cover the acquisition")
	}
	if !PostDominates(skipped, "release", "alloc") {
		t.Error("the structural relation itself is unchanged: the release does follow in an enclosing region")
	}

	// acquire(); if cond { release(); return }; release()  — every path releases.
	covered := newStore(func(s *usg.InMemStore) {
		node(s, "alloc", "code.Call", "/fn1", 2, nil)
		node(s, "bail", "code.Call", "/fn1/if3.t", 4, nil)
		node(s, "exit", usg.ExitNodeType, "/fn1/if3.t", 5, nil)
		node(s, "release", "code.Call", "/fn1", 7, nil)
	})
	if !PostDominatesCovered(covered, NewExitIndex(covered), []string{"release", "bail"}, "alloc") {
		t.Error("an error block that releases before returning leaves every path covered")
	}

	// The release the language runs while unwinding (defer / finally) is reached by the
	// early exit too.
	unwind := newStore(func(s *usg.InMemStore) {
		node(s, "alloc", "code.Call", "/fn1", 2, nil)
		node(s, "exit", usg.ExitNodeType, "/fn1/if3.t", 4, nil)
		node(s, "release", "code.Call", "/fn1", 6, map[string]string{usg.UnwindProp: "1"})
	})
	if !PostDominatesCovered(unwind, NewExitIndex(unwind), []string{"release"}, "alloc") {
		t.Error("a deferred/finally release runs on the early-exit path as well")
	}

	// An exit BEFORE the acquisition, one in a sibling branch of it, and one inside a
	// callback are all paths the acquisition never takes.
	unrelated := newStore(func(s *usg.InMemStore) {
		node(s, "early", usg.ExitNodeType, "/fn1/if1.t", 1, nil)
		node(s, "alloc", "code.Call", "/fn1/if3.t", 3, nil)
		node(s, "sibling", usg.ExitNodeType, "/fn1/if3.e", 4, nil)
		node(s, "callback", usg.ExitNodeType, "/fn1/if5.t#fn6/if7.t", 5, nil)
		node(s, "release", "code.Call", "/fn1", 8, nil)
	})
	if !PostDominatesCovered(unrelated, NewExitIndex(unrelated), []string{"release"}, "alloc") {
		t.Error("exits before the acquisition, beside it, or inside a callback do not skip the release")
	}

	// A graph with no exit markers at all (unconverted frontend) answers as it always did.
	bare := newStore(func(s *usg.InMemStore) {
		node(s, "alloc", "code.Call", "/fn1", 2, nil)
		node(s, "release", "code.Call", "/fn1", 6, nil)
	})
	if !PostDominatesCovered(bare, NewExitIndex(bare), []string{"release"}, "alloc") {
		t.Error("without exit markers the region/order relation is all there is")
	}
}

// The guard that follows an acquisition and checks whether it succeeded releases nothing
// because there is nothing to release. A path that leaves before the handle is ever used
// is that guard, not an abandoned resource; once the handle has been used, the same exit
// shape is a leak.
func TestPostDominatesCoveredIgnoresTheAcquisitionFailureGuard(t *testing.T) {
	// handle = acquire(); if (failed) return; use(handle); release(handle);
	build := func(useOrder int32) *usg.InMemStore {
		s := usg.NewInMemStore()
		add := func(id, typ string, region string, order int32) {
			if err := s.AddNode(usg.Node{ID: id, Type: typ, Loc: "app.c:1", Region: region, Order: order, HasOrder: true}); err != nil {
				t.Fatalf("add %s: %v", id, err)
			}
		}
		add("alloc", "code.Call", "/fn1", 2)
		add("exit", usg.ExitNodeType, "/fn1/if3.t", 5)
		add("use", "code.Call", "/fn1", useOrder)
		add("release", "code.Call", "/fn1", 12)
		for _, dst := range []string{"use", "release"} {
			if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: "alloc", Dst: dst}); err != nil {
				t.Fatalf("add edge: %v", err)
			}
		}
		return s
	}

	guard := build(8) // the use comes AFTER the early return: it is the failure guard
	if !PostDominatesCovered(guard, NewExitIndex(guard), []string{"release"}, "alloc") {
		t.Error("an exit before the handle is ever used is the acquisition's failure guard")
	}

	leak := build(4) // the use comes BEFORE it: the resource is live and abandoned
	if PostDominatesCovered(leak, NewExitIndex(leak), []string{"release"}, "alloc") {
		t.Error("an exit after the handle is in use abandons it")
	}
}

// regionRoot groups exits by the function body they belong to; a branch or an inline
// callback keeps its owner's root, and unrelated functions never share one.
func TestRegionRoot(t *testing.T) {
	cases := map[string]string{
		"m1/fn1":             "m1/fn1",
		"m1/fn1/if3.t":       "m1/fn1",
		"m1/fn1/if3.t/loop4": "m1/fn1",
		"m1/fn1#fn2/if5.t":   "m1/fn1",
		"m1/fn10":            "m1/fn10",
		"":                   "",
	}
	for in, want := range cases {
		if got := regionRoot(in); got != want {
			t.Errorf("regionRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// The other spelling of the same guard, and the one C is written in: the acquisition hands
// back a STATUS and the handle is an out-parameter, so nothing "uses" the returned value
// except the branch that tests it. What marks that branch as the acquisition's own is that
// its condition is what the acquisition flowed into.
func TestPostDominatesCoveredIgnoresTheGuardThatTestsTheAcquisitionsResult(t *testing.T) {
	// status = open(&handle); if (status != OK) { return; } write(&handle); close(&handle);
	build := func(guardOf string) *usg.InMemStore {
		s := usg.NewInMemStore()
		add := func(id, typ, region string, order int32, props map[string]string) {
			if err := s.AddNode(usg.Node{ID: id, Type: typ, Loc: "server.c:1", Region: region,
				Order: order, HasOrder: true, Props: props}); err != nil {
				t.Fatalf("add %s: %v", id, err)
			}
		}
		add("alloc", "code.Call", "/fn1", 2, nil)
		add("openStatus", "code.BinOp", "/fn1", 3, nil)
		add("writeStatus", "code.BinOp", "/fn1", 6, nil)
		add("exit", usg.ExitNodeType, "/fn1/if4.t", 8,
			map[string]string{usg.ExitGuardProp: guardOf})
		add("release", "code.Call", "/fn1", 10, nil)
		if err := s.AddEdge(usg.Edge{Type: "FLOWS", Src: "alloc", Dst: "openStatus"}); err != nil {
			t.Fatalf("add edge: %v", err)
		}
		return s
	}

	own := build("openStatus")
	if !PostDominatesCovered(own, NewExitIndex(own), []string{"release"}, "alloc") {
		t.Error("a branch on what the acquisition returned is its own failure guard: nothing is held on that path")
	}

	other := build("writeStatus")
	if PostDominatesCovered(other, NewExitIndex(other), []string{"release"}, "alloc") {
		t.Error("a branch on something else leaves with the resource still held")
	}

	unmarked := build("")
	if PostDominatesCovered(unmarked, NewExitIndex(unmarked), []string{"release"}, "alloc") {
		t.Error("an exit whose branch condition was not recorded is not read as a guard")
	}
}

// Two sequential single-armed if-blocks are siblings in the region tree, but nothing
// makes them exclusive: `if (a) free(p); if (b) free(p);` runs both bodies whenever
// both guards hold, so a release in the first block reaches a release or a use in the
// second and the double-free and use-after-free shapes have a pair to report. Only the
// ARMS OF ONE construct exclude each other.
func TestReachesSequencesSeparateSiblingConstructs(t *testing.T) {
	const fn = "app.c/fn1"
	cases := []struct {
		name           string
		rA, oA, rB, oB string
		want           bool
		because        string
	}{
		{"two sequential if-blocks", fn + "/if2.t", "3", fn + "/if4.t", "7", true,
			"both guards can hold, so both bodies run"},
		{"reverse order of the same pair", fn + "/if4.t", "7", fn + "/if2.t", "3", false,
			"order still decides the direction"},
		{"a later if reached from an earlier else", fn + "/if2.e", "3", fn + "/if4.t", "7", true,
			"the else arm falls through into the next statement"},
		{"if then a switch case", fn + "/if2.t", "3", fn + "/sw4.c1", "7", true,
			"separate constructs written one after the other"},
		{"if then a loop body", fn + "/if2.t", "3", fn + "/loop4", "7", true,
			"the loop runs after the guarded block"},
		{"nested under separate constructs", fn + "/if2.t/loop3", "4", fn + "/if5.t/if6.e", "9", true,
			"the first differing segments are two distinct constructs"},

		// The exclusive cases the sibling rule exists for must be unchanged.
		{"the two arms of one if", fn + "/if2.t", "3", fn + "/if2.e", "7", false,
			"then and else never both run"},
		{"two arms of one switch", fn + "/sw2.c0", "3", fn + "/sw2.c1", "7", false,
			"one case arm excludes the other"},
		{"a case and the default arm", fn + "/sw2.c0", "3", fn + "/sw2.d", "7", false,
			"the default runs only when no case did"},
		{"a try body and its handler", fn + "/try2", "3", fn + "/try2.h0", "7", false,
			"the handler is the alternative to completing the body"},
		{"deeper under exclusive arms", fn + "/if2.t/loop3", "4", fn + "/if2.e/if5.t", "9", false,
			"the exclusion at the first difference still holds below it"},
		{"an inline callback under an exclusive arm", fn + "/if2.t#fn9", "3", fn + "/if2.e", "7", false,
			"a body written in one arm belongs to that arm"},

		// Separate function bodies are not control constructs of one function.
		{"two module-level functions", "app.c/fn1", "3", "app.c/fn2", "7", false,
			"Reaches is intraprocedural by construction"},
		{"a branch of one function and a branch of another", "app.c/fn1/if2.t", "3", "app.c/fn3/if4.t", "7", false,
			"different function roots share no execution path"},
		{"segment-boundary safety", fn + "/if2.t", "3", fn + "/if20.t", "7", true,
			"if2 and if20 are distinct constructs, not one construct's arms"},
	}
	for _, c := range cases {
		if got := reachesRegion(c.rA, c.oA, c.rB, c.oB); got != c.want {
			t.Errorf("%s: reachesRegion(%q@%s -> %q@%s) = %v, want %v: %s",
				c.name, c.rA, c.oA, c.rB, c.oB, got, c.want, c.because)
		}
	}
}

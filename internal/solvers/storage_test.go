package solvers

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// storageFixture builds the shape CVE-2018-9336 has: a producer that allocates, publishes
// the buffer into a caller-visible field and still releases its own alias at a shared
// cleanup label, a destructor that releases the field, and a caller that hands the same
// object to both.
//
//	publish(o):    p = alloc();  o->f = p;  ...  free(p)     // /fn1
//	destroy(o):    free(o->f)                                // /fn2
//	caller():      obj = {};  publish(&obj);  destroy(&obj)  // /fn3
//
// releasedFrom names the node the release's argument carries: "alloc" when the graph
// still holds the allocation, "" when the local was nulled on another path and the
// argument resolves to a constant only.
func storageFixture(t *testing.T, releasedFrom string) usg.Store {
	t.Helper()
	g := usg.NewInMemStore()
	add := func(id, typ, region string, order int32, props map[string]string) {
		n := usg.Node{ID: id, Type: typ, Loc: "svc.c:1", Props: props}
		if region != "" {
			n.Region, n.Order, n.HasOrder = region, order, true
		}
		if err := g.AddNode(n); err != nil {
			t.Fatal(err)
		}
	}
	flow := func(a, b string) {
		if err := g.AddEdge(usg.Edge{Type: "FLOWS", Src: a, Dst: b}); err != nil {
			t.Fatal(err)
		}
	}

	// producer /fn1
	add("alloc", "code.Call", "m/fn1", 1, map[string]string{"callee_path": "alloc", "method": "alloc"})
	add("storeArg", "code.Arg", "m/fn1", 2, nil)
	add("store", "code.Call", "m/fn1", 3, map[string]string{"callee_path": "o.f"})
	add("freeArg", "code.Arg", "m/fn1", 4, nil)
	add("nullConst", "code.Const", "m/fn1", 5, nil)
	add("free1", "code.Call", "m/fn1", 6, map[string]string{"callee_path": "free", "method": "free"})
	add("pubParam", "code.Param", "", 0, nil)
	flow("alloc", "storeArg")
	flow("storeArg", "store")
	flow("pubParam", "store") // the object written
	if releasedFrom != "" {
		flow(releasedFrom, "freeArg")
	} else {
		flow("nullConst", "freeArg")
	}
	flow("freeArg", "free1")

	// destructor /fn2
	add("read", "code.Attr", "m/fn2", 1, map[string]string{"callee_path": "o.f", "method": "f"})
	add("readArg", "code.Arg", "m/fn2", 2, nil)
	add("free2", "code.Call", "m/fn2", 3, map[string]string{"callee_path": "free", "method": "free"})
	add("dtorParam", "code.Param", "", 0, nil)
	flow("dtorParam", "read")
	flow("read", "readArg")
	flow("readArg", "free2")

	// caller /fn3 hands one object to both
	add("obj", "code.Seq", "m/fn3", 1, nil)
	add("objArg1", "code.Arg", "m/fn3", 2, nil)
	add("objArg2", "code.Arg", "m/fn3", 3, nil)
	flow("obj", "objArg1")
	flow("obj", "objArg2")
	flow("objArg1", "pubParam")
	flow("objArg2", "dtorParam")
	return g
}

// The pair the gap is about: the two releases sit in two functions, so their regions are
// never sequenced and Reaches cannot select them. Pointer identity can: the producer
// published its allocation into the field the destructor releases, and both functions were
// handed the same object.
func TestStorageJoinJoinsTwoReleasesOfOnePublishedAllocation(t *testing.T) {
	g := storageFixture(t, "alloc")
	if Reaches(g, nil, "free1", "free2") {
		t.Fatal("region order must not already sequence two releases in two functions")
	}
	if !NewStorageJoin(g).Joins("free1", "free2") {
		t.Error("the release of the published allocation and the release of the field did not join")
	}
}

// The same pair when the producer nulled its local on the success path before the shared
// cleanup label, so the release's argument resolves to a constant. That is the spelling
// the CVE has; an operand with no origin of its own cannot contradict the store.
func TestStorageJoinJoinsWhenTheReleasedLocalWasNulledOnAnotherPath(t *testing.T) {
	g := storageFixture(t, "")
	if !NewStorageJoin(g).Joins("free1", "free2") {
		t.Error("a release whose operand carries no origin did not join the field it published")
	}
}

// The producer releases a DIFFERENT allocation from the one it published. The operand
// contradicts the store, so there is no identity to join on.
func TestStorageJoinRejectsAReleaseOfAnUnrelatedAllocation(t *testing.T) {
	// the producer allocates twice and releases the one it did NOT publish
	g2 := storageFixture(t, "")
	if err := g2.AddNode(usg.Node{ID: "other", Type: "code.Call", Loc: "svc.c:1", Region: "m/fn1", Order: 2, HasOrder: true,
		Props: map[string]string{"callee_path": "alloc", "method": "alloc"}}); err != nil {
		t.Fatal(err)
	}
	if err := g2.AddEdge(usg.Edge{Type: "FLOWS", Src: "other", Dst: "freeArg"}); err != nil {
		t.Fatal(err)
	}
	if NewStorageJoin(g2).Joins("free1", "free2") {
		t.Error("a release of a different allocation joined the published field")
	}
}

// Two structs that merely declare a field of the same name are not one storage location:
// without a caller handing one object to both, nothing says the objects are the same.
func TestStorageJoinRejectsTwoObjectsThatShareAFieldName(t *testing.T) {
	g := storageFixture(t, "alloc")
	unlinked := usg.NewInMemStore()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.ID == "obj" || n.ID == "objArg1" || n.ID == "objArg2" {
			continue
		}
		if err := unlinked.AddNode(n); err != nil {
			t.Fatal(err)
		}
		for _, e := range mustOut(t, g, n.ID) {
			if e.Dst == "pubParam" || e.Dst == "dtorParam" {
				continue
			}
			if err := unlinked.AddEdge(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	if NewStorageJoin(unlinked).Joins("free1", "free2") {
		t.Error("two objects with no common origin joined on a shared field name")
	}
}

// The join is only the interprocedural fallback. Two releases inside one function are
// Reaches's business, including the disjoint-branch pair it correctly rejects.
func TestStorageJoinDoesNotDecidePairsInsideOneFunction(t *testing.T) {
	g := storageFixture(t, "alloc")
	if err := g.AddNode(usg.Node{ID: "free3", Type: "code.Call", Loc: "svc.c:1", Region: "m/fn1", Order: 7, HasOrder: true,
		Props: map[string]string{"callee_path": "free", "method": "free"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(usg.Edge{Type: "FLOWS", Src: "readArg", Dst: "free3"}); err != nil {
		t.Fatal(err)
	}
	if NewStorageJoin(g).Joins("free1", "free3") {
		t.Error("the storage join answered a pair inside one function")
	}
}

func TestFuncRegionDropsNestedControlRegions(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"m/fn1", "m/fn1"},
		{"m/fn1/if2.t", "m/fn1"},
		{"m/fn1/if2.t/loop3", "m/fn1"},
		{"m", "m"},
		{"", ""},
	} {
		if got := funcRegion(c.in); got != c.want {
			t.Errorf("funcRegion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustOut(t *testing.T, g usg.Store, id string) []usg.Edge {
	t.Helper()
	edges, err := g.OutEdges(id, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	return edges
}

package bindings

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

func cachedIndexCount() int {
	n := 0
	sharedStoreIndexCache.Range(func(any, any) bool { n++; return true })
	return n
}

// The per-pass index cache is keyed by structural epoch and by nothing else, and an epoch is
// never reused, so nothing removes an entry. That costs nothing for a scan that builds one
// graph and exits.
//
// It is not free for a scan that builds one graph per partition. The flag index holds a
// lowercased copy of the graph's matchable text — about half the live heap of a completed
// build — so every finished partition stays resident for the whole run and the ceiling that
// made the scan partition is reached anyway, a partition or two later. Releasing a finished
// store's indexes is what keeps a partitioned scan's peak bounded by one partition.
func TestReleaseStoreIndexesForgetsAFinishedStore(t *testing.T) {
	before := cachedIndexCount()

	g := usg.NewIntStore(0)
	if err := g.AddNode(usg.Node{ID: "n1", Type: "code.Call", Loc: "a.js:1", Method: "eval"}); err != nil {
		t.Fatal(err)
	}
	idx := sharedFlagIndex(g)
	idx.ensure(g)

	if got := cachedIndexCount(); got != before+1 {
		t.Fatalf("cached index entries = %d, want %d: the pass did not share an index", got, before+1)
	}
	if sharedFlagIndex(g) != idx {
		t.Fatal("a second pass over an unchanged store built a fresh index")
	}

	ReleaseStoreIndexes(g)

	if got := cachedIndexCount(); got != before {
		t.Errorf("cached index entries = %d after release, want %d", got, before)
	}
	if sharedFlagIndex(g) == idx {
		t.Error("the released index is still being handed out")
	}
}

// Releasing one store must not take another store's index with it. An unmutated store is the
// case that can: every one of them carries epoch zero, which is the key nothing owns.
func TestReleaseStoreIndexesLeavesOtherStoresAlone(t *testing.T) {
	keep := usg.NewIntStore(0)
	if err := keep.AddNode(usg.Node{ID: "keep", Type: "code.Call"}); err != nil {
		t.Fatal(err)
	}
	kept := sharedFlagIndex(keep)
	t.Cleanup(func() { ReleaseStoreIndexes(keep) })

	done := usg.NewIntStore(0)
	if err := done.AddNode(usg.Node{ID: "done", Type: "code.Call"}); err != nil {
		t.Fatal(err)
	}
	sharedFlagIndex(done)

	held := cachedIndexCount()
	ReleaseStoreIndexes(done)
	if got := cachedIndexCount(); got != held-1 {
		t.Errorf("cached index entries = %d after releasing one store, want %d", got, held-1)
	}
	if sharedFlagIndex(keep) != kept {
		t.Error("releasing one store dropped another store's index")
	}

	// A store that has never been structurally mutated shares epoch zero with every other
	// one, so it owns no entry and releasing it must remove none.
	held = cachedIndexCount()
	ReleaseStoreIndexes(usg.NewInMemStore())
	if got := cachedIndexCount(); got != held {
		t.Errorf("cached index entries = %d after releasing an unmutated store, want %d left untouched", got, held)
	}
}

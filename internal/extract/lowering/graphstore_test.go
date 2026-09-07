package lowering

import (
	"os"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A scan under a RAM ceiling may build more than one graph: a target too large to hold as one
// resident graph is scanned partition by partition, and each partition builds its own.
//
// Badger locks the directory it is opened on, so two graphs sharing one path cannot both be
// disk-backed — the second open fails and newGraphStore falls back to the in-RAM store, which
// is the whole partition's graph resident. Nothing reports it: the scan produces the same
// findings, it just quietly stops honouring the ceiling that made it partition.
func TestEveryGraphUnderARAMCeilingGetsItsOwnStoreDirectory(t *testing.T) {
	base := t.TempDir()
	DiskStorePath = base
	DiskCacheBytes, DiskDetailBuf = 64<<20, 64<<20
	t.Cleanup(func() {
		DiskStorePath = ""
		DiskCacheBytes, DiskDetailBuf = 0, 0
	})

	first := newGraphStore(0)
	second := newGraphStore(0)
	for i, g := range []usg.Store{first, second} {
		if _, ok := g.(*usg.BadgerGraph); !ok {
			t.Fatalf("graph %d is %T, want the disk-backed store: a RAM ceiling is configured", i, g)
		}
	}

	// Two live graphs must not be the same store, or the second partition's nodes would land
	// in the first partition's graph.
	if first == second {
		t.Fatal("both graphs are the same store")
	}
	if err := first.(*usg.BadgerGraph).AddNode(usg.Node{ID: "a", Type: "code.Call"}); err != nil {
		t.Fatalf("write to first graph: %v", err)
	}
	if err := second.(*usg.BadgerGraph).AddNode(usg.Node{ID: "b", Type: "code.Call"}); err != nil {
		t.Fatalf("write to second graph: %v", err)
	}
	if second.(*usg.BadgerGraph).Has("a") {
		t.Error("the second graph can see the first graph's node")
	}

	// A finished partition's store must take its directory with it, or a scan of many
	// partitions leaves every one of them on disk for the length of the run.
	before, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := usg.Close(first); err != nil {
		t.Fatalf("close: %v", err)
	}
	after, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)-1 {
		t.Errorf("store directories under %s: %d before close, %d after; want one fewer", base, len(before), len(after))
	}
	_ = usg.Close(second)
}

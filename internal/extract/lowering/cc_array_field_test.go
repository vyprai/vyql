package lowering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/usg"
)

// lowerCCSource parses one C/C++ source and lowers it, the way a scan of that
// repository would. The frontend is chosen by extension, so a .cc file goes
// through the cpp arm and a .c file through the c arm of the same converter.
func lowerCCSource(t *testing.T, name, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	return g
}

// divisionReachable reports whether the taint of the one fread call in the
// graph reaches each `/` BinOp, the denominator of which is what VYQL-NUM-002
// labels. The reader's own call node is the source stand-in: no binding is
// loaded in a unit test, and the destination-effect machinery already carries
// it into the buffer the loop reads out of.
func divisionReachable(t *testing.T, g usg.Store) map[string]bool {
	t.Helper()
	src := findNodeID(t, g, "code.Call", "callee_path", "fread")
	reachable, err := usg.BFS(g, src, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	ids, err := g.NodesOfType("code.BinOp")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok || n.Prop("op") != "/" {
			continue
		}
		out[id] = reachable[id]
	}
	if len(out) == 0 {
		t.Fatal("no division in the lowered graph")
	}
	return out
}

func anyDivisionReachable(divides map[string]bool) bool {
	for _, r := range divides {
		if r {
			return true
		}
	}
	return false
}

// A field stored through one subscripted element of a local struct array and
// read back through another carries its taint: both accesses slot on the one
// array, keyed by field, instead of on a fresh per-occurrence element node.
// This is the smallest form of the lepton shape (rank 2131): parse_header
// writes cmpinfo[cmp].bch inside a loop and the value is read back by index.
func TestCCArrayElementFieldCarriesTaint(t *testing.T) {
	g := lowerCCSource(t, "codec.cc", `
#include <cstdio>

struct componentInfo {
    int bch;
    int bcv;
};

int main() {
    FILE *f = fopen("input.jpg", "rb");
    unsigned char segment[16];
    fread(segment, 1, 16, f);
    componentInfo cmpinfo[4];
    for (int cmp = 0; cmp < 4; cmp++) {
        cmpinfo[cmp].bch = segment[3];
    }
    int result = 100 / cmpinfo[1].bch;
    printf("%d\n", result);
    return 0;
}
`)
	if !anyDivisionReachable(divisionReachable(t, g)) {
		t.Fatalf("a value stored into cmpinfo[cmp].bch never reached the division reading cmpinfo[1].bch back")
	}
}

// The same join with constant indices on both sides, the form a fixed-slot
// reader takes: written at [0], read back at [1].
func TestCCArrayElementFieldCarriesTaintConstantIndices(t *testing.T) {
	g := lowerCCSource(t, "fixed.cc", `
#include <cstdio>

struct componentInfo {
    int bch;
    int bcv;
};

int main() {
    FILE *f = fopen("input.jpg", "rb");
    unsigned char segment[16];
    fread(segment, 1, 16, f);
    componentInfo cmpinfo[4];
    cmpinfo[0].bch = segment[3];
    int result = 100 / cmpinfo[1].bch;
    printf("%d\n", result);
    return 0;
}
`)
	if !anyDivisionReachable(divisionReachable(t, g)) {
		t.Fatalf("a value stored into cmpinfo[0].bch never reached the division reading cmpinfo[1].bch back")
	}
}

// The slot is keyed by field: a sibling field of the same element stays clean,
// which is what keeps this a field-sensitive join rather than a whole-array
// one.
func TestCCArrayElementFieldStaysFieldSensitive(t *testing.T) {
	g := lowerCCSource(t, "sibling.cc", `
#include <cstdio>

struct componentInfo {
    int bch;
    int bcv;
};

int main() {
    FILE *f = fopen("input.jpg", "rb");
    unsigned char segment[16];
    fread(segment, 1, 16, f);
    componentInfo cmpinfo[4];
    cmpinfo[0].bch = segment[3];
    int result = 100 / cmpinfo[1].bcv;
    printf("%d\n", result);
    return 0;
}
`)
	if anyDivisionReachable(divisionReachable(t, g)) {
		t.Fatalf("taint stored into cmpinfo[0].bch reached a division over cmpinfo[1].bcv")
	}
}

// The join is gated to the cpp frontend's files: the c arm of the same
// converter keeps its current behaviour, so no C corpus moves with this
// change. A C file cannot go through ExtractCPP, so lower it as C.
func TestCArrayElementFieldUnchangedForCFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "codec.c")
	src := `
#include <stdio.h>

struct componentInfo {
    int bch;
    int bcv;
};

int main() {
    FILE *f = fopen("input.jpg", "rb");
    unsigned char segment[16];
    fread(segment, 1, 16, f);
    struct componentInfo cmpinfo[4];
    cmpinfo[0].bch = segment[3];
    int result = 100 / cmpinfo[1].bch;
    printf("%d\n", result);
    return 0;
}
`
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	if anyDivisionReachable(divisionReachable(t, g)) {
		t.Fatalf("the array-element field join fired for a .c file outside the cpp gate")
	}
}

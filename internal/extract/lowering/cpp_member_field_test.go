package lowering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/usg"
)

// lowerCPPSource parses one C++ source and lowers it, the way a scan of a
// C++ repository would.
func lowerCPPSource(t *testing.T, name, src string) usg.Store {
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

// divideDenominatorsReachable reports, for each `/` division in the lowered
// graph, whether the taint stand-in (the read_int call's result) reaches it.
func divideDenominatorsReachable(t *testing.T, g usg.Store) map[string]bool {
	t.Helper()
	src := findNodeID(t, g, "code.Call", "callee_path", "read_int")
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

func anyDivideReachable(divides map[string]bool) bool {
	for _, r := range divides {
		if r {
			return true
		}
	}
	return false
}

// A member field stored through `this` in one method and read back through
// `this` in ANOTHER method carries its taint across the two bodies: the store
// and the read resolve to the class's one self node, whose per-field slot is
// what joins them. The reading method is declared FIRST, so the read is lowered
// before the write exists — the join must be order-independent.
func TestCPPThisFieldCarriesTaintBetweenMethods(t *testing.T) {
	g := lowerCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
public:
    void ReadPCM() {
        int x = 100 / this->m_frameSize;
        sink_int(x);
    }
    void Init(FILE *fp) {
        this->m_frameSize = read_int(fp);
    }
};
`)
	if !anyDivideReachable(divideDenominatorsReachable(t, g)) {
		t.Fatal("a value one method stored through this->m_frameSize did not reach the method that divides by it")
	}
}

// The same store and read inside ONE method: the slot the store fills is the
// slot the read pulls, so the divide sees the value even without a second body.
func TestCPPThisFieldCarriesTaintWithinAMethod(t *testing.T) {
	g := lowerCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
public:
    void ReadPCM(FILE *fp) {
        this->m_frameSize = read_int(fp);
        int x = 100 / this->m_frameSize;
        sink_int(x);
    }
};
`)
	if !anyDivideReachable(divideDenominatorsReachable(t, g)) {
		t.Fatal("a value stored through this->m_frameSize and divided by in the same method did not reach the divide")
	}
}

// The bare spelling of the same member — `m_frameSize` with no `this->`, the
// idiom C++ shares with C# and Java — is a member reference the class's
// declared-field set resolves, so a write in one method and a read in another
// meet the same slot the explicit spelling uses.
func TestCPPBareMemberFieldCarriesTaintBetweenMethods(t *testing.T) {
	g := lowerCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
public:
    void ReadPCM() {
        int x = 100 / m_frameSize;
        sink_int(x);
    }
    void Init(FILE *fp) {
        m_frameSize = read_int(fp);
    }
};
`)
	if !anyDivideReachable(divideDenominatorsReachable(t, g)) {
		t.Fatal("a value one method stored into the bare member m_frameSize did not reach the method that divides by it")
	}
}

// The join is field-sensitive: a sibling member written by the same statements
// carries nothing to the divide, because each field keeps its own slot.
func TestCPPMemberFieldJoinStaysFieldSensitive(t *testing.T) {
	g := lowerCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
    int m_other;
public:
    void ReadPCM() {
        int x = 100 / this->m_frameSize;
        sink_int(x);
    }
    void Init(FILE *fp) {
        this->m_frameSize = 64;
        this->m_other = read_int(fp);
    }
};
`)
	if anyDivideReachable(divideDenominatorsReachable(t, g)) {
		t.Fatal("a value stored into the sibling member this->m_other reached the divide by this->m_frameSize")
	}
}

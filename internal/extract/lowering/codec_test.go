package lowering

import (
	"errors"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

func sampleDelta() *moduleDelta {
	return &moduleDelta{
		Nodes: []usg.Node{
			{ID: "n1", Type: "code.Call", Loc: "a.go:1", Props: map[string]string{"callee_path": "db.query"}},
			{ID: "n2", Type: "code.Arg", Loc: "a.go:1"},
		},
		Edges: []usg.Edge{{Type: "FLOWS", Src: "n1", Dst: "n2"}},
		Labels: []deltaLabel{{
			NodeID: "n2",
			Label: usg.Label{
				Concept:    "code.SqlExecution",
				Provenance: usg.Provenance{Extractor: "go", Applicator: "sinks", Fidelity: "resolved"},
			},
		}},
	}
}

func samplePass1() *pass1Delta {
	return &pass1Delta{
		Nodes:   []usg.Node{{ID: "s1", Type: "Param", Loc: "a.go:2"}},
		Imports: []ieGob{{Local: "db", IsModule: true, Module: "database/sql"}},
		Funcs: []fiGob{{
			Qual: "m::C.f", Short: "f", ParamNames: []string{"x"},
			Params: map[string]string{"x": "s1"}, Ret: "r1", Module: "m", Cls: "C", Name: "f",
		}},
		ClassQual: []string{"m::C"},
		Counter:   7,
		Order:     3,
	}
}

// Bytes past the end of a well-formed value cannot come from a short read -- that overruns and the
// decoder's recover catches it. They mean the value is not what this encoder wrote: a stale
// format, a concatenated write, or corruption that happens to parse. Without the length check the
// decoder returned a delta anyway, and replay merged it as if it were complete.
func TestDecodeRejectsTrailingBytes(t *testing.T) {
	t.Run("delta", func(t *testing.T) {
		full := encodeDelta(sampleDelta())
		if _, err := decodeDelta(full); err != nil {
			t.Fatalf("decodeDelta(exact) = %v, want nil", err)
		}
		if _, err := decodeDelta(append(append([]byte{}, full...), 0x00)); !errors.Is(err, errCorruptDelta) {
			t.Fatalf("decodeDelta(+1 byte) err = %v, want errCorruptDelta", err)
		}
	})

	t.Run("pass1", func(t *testing.T) {
		full := encodePass1(samplePass1())
		if _, err := decodePass1(full); err != nil {
			t.Fatalf("decodePass1(exact) = %v, want nil", err)
		}
		if _, err := decodePass1(append(append([]byte{}, full...), 0x00)); !errors.Is(err, errCorruptDelta) {
			t.Fatalf("decodePass1(+1 byte) err = %v, want errCorruptDelta", err)
		}
	})
}

// Truncation is already rejected, by overrun rather than by the length check. Pinned so that a
// future reader-side change (a bounds-checked reader that returns zero instead of panicking)
// cannot silently reintroduce prefix decoding, which would merge a partial sub-graph with no error.
func TestDecodeRejectsEveryTruncation(t *testing.T) {
	delta := encodeDelta(sampleDelta())
	for n := 1; n < len(delta); n++ {
		if _, err := decodeDelta(delta[:n]); !errors.Is(err, errCorruptDelta) {
			t.Fatalf("decodeDelta(truncated %d/%d) err = %v, want errCorruptDelta", n, len(delta), err)
		}
	}

	p1 := encodePass1(samplePass1())
	for n := 1; n < len(p1); n++ {
		if _, err := decodePass1(p1[:n]); !errors.Is(err, errCorruptDelta) {
			t.Fatalf("decodePass1(truncated %d/%d) err = %v, want errCorruptDelta", n, len(p1), err)
		}
	}
}

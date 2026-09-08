package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccFieldDerivedIndexFacts runs the index-access observation over one C or C++
// source and returns the emitted field-derived facts, one string of
// semicolon-joined tokens per fact.
func ccFieldDerivedIndexFacts(t *testing.T, name, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(name, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok {
			continue
		}
		for _, s := range fn.Body {
			es, ok := s.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.Value.(nir.Call)
			if !ok || call.Path != "analysis.index.field_derived_missing_upper_bound" {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.Join(parts, ";"))
		}
	}
	return out
}

// TestCPPSubscriptIndexIsRead covers the C++ half: the C++ grammar wraps a
// subscript's index in a subscript_argument_list under the field `indices`, so
// reading only the C grammar's `index` field left every .cpp subscript with
// empty index text and the observation could not fire in C++ source at all.
func TestCPPSubscriptIndexIsRead(t *testing.T) {
	const src = `
struct hrd { char flags[8]; };
void read_vui(struct sps *s, struct hrd *h) {
  h->flags[s->idx] = 1;
}
`
	for _, file := range []string{"vui.c", "vui.cpp"} {
		got := ccFieldDerivedIndexFacts(t, file, src)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		if !strings.Contains(got[0], "index=s->idx") {
			t.Fatalf("%s: fact %q does not carry the index text", file, got[0])
		}
	}
}

// TestLoopBoundFixedArrayIndex covers the loop half: a field read only in the
// loop's condition, bounding a loop that indexes a fixed-size array by the
// bare loop variable.
func TestLoopBoundFixedArrayIndex(t *testing.T) {
	const live = `
#define MAX_LAYERS 8
struct hrd { char flags[MAX_LAYERS]; };
void read_vui(struct sps *s, struct hrd *h) {
  for (int i = 0; i <= s->max_sub_layers - 1; i++) {
    h->flags[i] = 1;
  }
}
`
	for _, file := range []string{"vui.c", "vui.cpp"} {
		got := ccFieldDerivedIndexFacts(t, file, live)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{"index_kind=field_derived", "guard=missing_upper_bound", "index=i", "bound=s->max_sub_layers", "capacity=MAX_LAYERS"} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}

	suppressed := map[string]string{
		"count checked against the capacity": `
#define MAX_LAYERS 8
struct hrd { char flags[MAX_LAYERS]; };
void read_vui(struct sps *s, struct hrd *h) {
  if (s->max_sub_layers > MAX_LAYERS) return;
  for (int i = 0; i <= s->max_sub_layers - 1; i++) {
    h->flags[i] = 1;
  }
}
`,
		"index clamped to the capacity": `
#define MAX_LAYERS 8
struct hrd { char flags[MAX_LAYERS]; };
void read_vui(struct sps *s, struct hrd *h) {
  for (int i = 0; i <= s->max_sub_layers - 1; i++) {
    if (i >= MAX_LAYERS) break;
    h->flags[i] = 1;
  }
}
`,
		"destination is not a fixed-size array": `
void read_vui(struct sps *s, char *out) {
  for (int i = 0; i <= s->max_sub_layers - 1; i++) {
    out[i] = 1;
  }
}
`,
		"loop bound is not field-derived": `
#define MAX_LAYERS 8
struct hrd { char flags[MAX_LAYERS]; };
void read_vui(int n, struct hrd *h) {
  for (int i = 0; i < n; i++) {
    h->flags[i] = 1;
  }
}
`,
		"index is not the bare loop variable": `
#define MAX_LAYERS 8
struct hrd { char flags[MAX_LAYERS]; };
void read_vui(struct sps *s, struct hrd *h) {
  for (int i = 0; i <= s->max_sub_layers - 1; i++) {
    h->flags[i & 7] = 1;
  }
}
`,
	}
	for name, src := range suppressed {
		for _, file := range []string{"vui.c", "vui.cpp"} {
			if got := ccFieldDerivedIndexFacts(t, file, src); len(got) != 0 {
				t.Fatalf("%s (%s): got %q want no fact", name, file, got)
			}
		}
	}
}

// TestLoopBoundMultiDimensionalArrayIndex covers the shape the gap's evidence
// cites: the loop variable selects the second dimension of a fixed [7][32][2]
// member array, so the capacity that bounds it is that dimension's, not the
// first one's.
func TestLoopBoundMultiDimensionalArrayIndex(t *testing.T) {
	const src = `
struct hrd {
  unsigned cpb_cnt_minus1[7];
  unsigned bit_rate_value_minus1[7][32][2];
};
void read_hrd(struct hrd *h, int i, int nalOrVcl) {
  for (int j = 0; j <= h->cpb_cnt_minus1[i]; j++) {
    h->bit_rate_value_minus1[i][j][nalOrVcl] = 1;
  }
}
`
	for _, file := range []string{"vui.c", "vui.cpp"} {
		got := ccFieldDerivedIndexFacts(t, file, src)
		if len(got) != 1 {
			t.Fatalf("%s: got %q want exactly one field-derived fact", file, got)
		}
		for _, want := range []string{"index=j", "bound=h->cpb_cnt_minus1[i]", "capacity=32"} {
			if !strings.Contains(got[0], want) {
				t.Fatalf("%s: fact %q missing %q", file, got[0], want)
			}
		}
	}

	// The same loop over an array whose second dimension the count does bound
	// reports nothing.
	const guarded = `
struct hrd {
  unsigned cpb_cnt_minus1[7];
  unsigned bit_rate_value_minus1[7][32][2];
};
void read_hrd(struct hrd *h, int i, int nalOrVcl) {
  if (h->cpb_cnt_minus1[i] > 31) return;
  for (int j = 0; j <= h->cpb_cnt_minus1[i]; j++) {
    h->bit_rate_value_minus1[i][j][nalOrVcl] = 1;
  }
}
`
	for _, file := range []string{"vui.c", "vui.cpp"} {
		if got := ccFieldDerivedIndexFacts(t, file, guarded); len(got) != 0 {
			t.Fatalf("%s: got %q want no fact", file, got)
		}
	}
}

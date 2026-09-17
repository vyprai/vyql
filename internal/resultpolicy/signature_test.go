package resultpolicy_test

import (
	"sort"
	"testing"

	"github.com/vyprai/vyql/internal/resultpolicy"
)

// The stability matrix is the contract in docs/adr/0004 §1: the signature
// survives changes that do not alter the path's security-relevant structure,
// and changes when it does. Each case names the edit a triaged false positive
// must survive — or must re-fire for.
func hops() []resultpolicy.SigHop {
	return []resultpolicy.SigHop{
		{Concept: "HttpInput", Callee: "express.Request.query"},
		{Concept: "UserControlledData"}, // parameter hop: no callee
		{Concept: "StringConcat", Callee: "String.prototype.concat"},
		{Concept: "SqlExecution", Callee: "pg.Client.query"},
	}
}

func TestPathSignatureStabilityMatrix(t *testing.T) {
	base := resultpolicy.PathSignature(hops())

	cases := []struct {
		name   string
		mutate func(h []resultpolicy.SigHop) []resultpolicy.SigHop
		stable bool // want same signature after this edit
	}{
		{
			// Edits elsewhere in the file shift lines; the signature never
			// sees lines, so this is trivially stable — recorded anyway so
			// the guarantee is pinned by a test rather than by omission.
			name:   "line shift (not part of hop identity)",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop { return h },
			stable: true,
		},
		{
			name: "intermediate hop removed (validation restructured)",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop {
				return append(h[:2:2], h[3])
			},
			stable: false,
		},
		{
			name: "hop inserted mid-path",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop {
				out := append([]resultpolicy.SigHop{}, h[:2]...)
				out = append(out, resultpolicy.SigHop{Concept: "Sanitizer", Callee: "validator.escape"})
				return append(out, h[2:]...)
			},
			stable: false,
		},
		{
			name: "source swapped for a different API",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop {
				out := append([]resultpolicy.SigHop{}, h...)
				out[0] = resultpolicy.SigHop{Concept: "HttpInput", Callee: "express.Request.body"}
				return out
			},
			stable: false,
		},
		{
			name: "sink callee renamed",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop {
				out := append([]resultpolicy.SigHop{}, h...)
				out[3] = resultpolicy.SigHop{Concept: "SqlExecution", Callee: "pg.Client.rawQuery"}
				return out
			},
			stable: false,
		},
		{
			name: "hop order reversed",
			mutate: func(h []resultpolicy.SigHop) []resultpolicy.SigHop {
				out := append([]resultpolicy.SigHop{}, h...)
				sort.Slice(out, func(i, j int) bool { return false })
				// reverse explicitly; sort with constant cmp is a no-op on some inputs
				for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
					out[i], out[j] = out[j], out[i]
				}
				return out
			},
			stable: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resultpolicy.PathSignature(tc.mutate(hops()))
			if tc.stable && got != base {
				t.Fatalf("signature should survive %q:\n base %s\n got  %s", tc.name, base, got)
			}
			if !tc.stable && got == base {
				t.Fatalf("signature should change on %q but did not (%s)", tc.name, got)
			}
		})
	}
}

// A crafted concept or callee containing the printable separators a naive
// join would use must not be able to collide two different paths.
func TestPathSignatureNoSeparatorCollision(t *testing.T) {
	a := []resultpolicy.SigHop{{Concept: "A:B", Callee: "x"}, {Concept: "C", Callee: ""}}
	b := []resultpolicy.SigHop{{Concept: "A", Callee: "B:x"}, {Concept: "C", Callee: ""}}
	if resultpolicy.PathSignature(a) == resultpolicy.PathSignature(b) {
		t.Fatal("different hop sequences must not collide via embedded separators")
	}
}

func TestPathSignatureEmptyAndShape(t *testing.T) {
	if resultpolicy.PathSignature(nil) != "" {
		t.Fatal("no witness (reach/grant/match findings) must yield the empty signature")
	}
	got := resultpolicy.PathSignature(hops())
	if len(got) != 16 {
		t.Fatalf("signature is 16 hex chars like the fingerprint, got %d (%q)", len(got), got)
	}
}

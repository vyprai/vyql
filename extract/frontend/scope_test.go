package frontend

import (
	"strings"
	"testing"
)

// referenceScopeWithoutOrder / referenceSameOrNestedScope are the ORIGINAL, obviously-correct
// implementations, kept verbatim as an oracle. sameOrNestedScope is on the innermost loop of
// flag matching (it dominated a real scan's CPU profile at ~42%), so it was rewritten to walk
// segments in place instead of allocating a []string plus a joined string per call. These tests
// pin the rewrite to the oracle across an exhaustive space of scope shapes.
func referenceScopeWithoutOrder(scope string) string {
	if scope == "" {
		return ""
	}
	parts := strings.Split(scope, "/")
	for i, part := range parts {
		if at := strings.Index(part, "@"); at >= 0 {
			parts[i] = part[:at]
		}
	}
	return strings.Join(parts, "/")
}

func referenceSameOrNestedScope(candidate, anchor string) bool {
	candidate = referenceScopeWithoutOrder(candidate)
	anchor = referenceScopeWithoutOrder(anchor)
	return candidate == anchor || strings.HasPrefix(candidate, anchor+"/")
}

// scopeCorpus builds every scope of 0..3 segments over an alphabet chosen to cover the tricky
// cases: bare names, "@order" suffixes, a segment that is ONLY an order, a trailing "@", the
// empty segment (leading/trailing/doubled slashes), and a name that is a strict string-prefix
// of another ("a" vs "ab") to catch segment-boundary bugs.
func scopeCorpus() []string {
	segs := []string{"", "a", "b", "ab", "a@1", "a@2", "b@3", "@5", "a@"}
	out := []string{""}
	cur := []string{""}
	for depth := 0; depth < 3; depth++ {
		var next []string
		for _, p := range cur {
			for _, s := range segs {
				j := s
				if p != "" {
					j = p + "/" + s
				}
				next = append(next, j)
			}
		}
		out = append(out, next...)
		cur = next
	}
	return out
}

func TestSameOrNestedScopeMatchesReference(t *testing.T) {
	corpus := scopeCorpus()
	checked := 0
	for _, cand := range corpus {
		for _, anchor := range corpus {
			want := referenceSameOrNestedScope(cand, anchor)
			got := sameOrNestedScope(cand, anchor)
			if got != want {
				t.Fatalf("sameOrNestedScope(%q, %q) = %v, reference = %v", cand, anchor, got, want)
			}
			checked++
		}
	}
	t.Logf("verified %d candidate/anchor pairs against the reference", checked)
}

func TestSameOrNestedScopeCases(t *testing.T) {
	cases := []struct {
		cand, anchor string
		want         bool
	}{
		{"", "", true},
		{"a", "", false},   // empty anchor only matches empty or rooted
		{"/a", "", true},   // normalized "/a" has the "" + "/" prefix
		{"a/b", "a/b", true},
		{"a/b/c", "a/b", true},           // nested
		{"a/bc", "a/b", false},           // segment boundary, not a raw string prefix
		{"a", "a/b", false},              // candidate shallower than anchor
		{"a@9/b@8/c", "a@1/b@2", true},   // @order stripped on both sides
		{"a@1", "a@2", true},             // same name, different order
		{"ab", "a", false},               // strict string prefix is NOT a nested scope
		{"@5/x", "", true},               // segment that is only an order normalizes to ""
	}
	for _, c := range cases {
		if got := sameOrNestedScope(c.cand, c.anchor); got != c.want {
			t.Errorf("sameOrNestedScope(%q, %q) = %v, want %v", c.cand, c.anchor, got, c.want)
		}
		if ref := referenceSameOrNestedScope(c.cand, c.anchor); ref != c.want {
			t.Errorf("reference disagrees with the stated expectation for (%q, %q): got %v, want %v",
				c.cand, c.anchor, ref, c.want)
		}
	}
}

func BenchmarkSameOrNestedScope(b *testing.B) {
	cand, anchor := "pkg@1/Type@2/method@3/block@4", "pkg@9/Type@8/method@7"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !sameOrNestedScope(cand, anchor) {
			b.Fatal("expected nested")
		}
	}
}

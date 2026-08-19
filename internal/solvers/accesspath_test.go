package solvers

import (
	"testing"
)

func TestFieldAccessPathBoundsAndExtension(t *testing.T) {
	ap := NewFieldAccessPath("obj")
	if ap.String() != "obj" {
		t.Errorf("expected 'obj', got %q", ap.String())
	}

	ap1 := ap.Extend("a")
	ap2 := ap1.Extend("b")
	ap3 := ap2.Extend("c")

	if ap3.Smashed {
		t.Errorf("depth 3 should not be smashed yet")
	}
	if ap3.String() != "obj.a.b.c" {
		t.Errorf("expected 'obj.a.b.c', got %q", ap3.String())
	}

	// 4th field should trigger smashing
	ap4 := ap3.Extend("d")
	if !ap4.Smashed {
		t.Errorf("depth > 3 must trigger smashing")
	}
	if ap4.String() != "obj.a.b.c.*" {
		t.Errorf("expected 'obj.a.b.c.*', got %q", ap4.String())
	}
}

func TestFieldAccessPathMatching(t *testing.T) {
	ap1 := NewFieldAccessPath("obj").Extend("a").Extend("b")
	ap2 := NewFieldAccessPath("obj").Extend("a").Extend("b")
	ap3 := NewFieldAccessPath("obj").Extend("a").Extend("c")

	if !ap1.Matches(ap2) {
		t.Errorf("identical access paths must match")
	}
	if ap1.Matches(ap3) {
		t.Errorf("disjoint access paths must not match")
	}

	// Smashed path matches extensions with same prefix
	smashed := NewFieldAccessPath("obj").Extend("a").Extend("b").Extend("c").Extend("d")
	target := NewFieldAccessPath("obj").Extend("a").Extend("b").Extend("c")
	if !smashed.Matches(target) {
		t.Errorf("smashed path must match its prefix target")
	}
}

package lowering

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// The namespace is identity, not content: it must be a pure function of the path, distinct
// across paths, and short — its length is paid once per node in every module.
func TestModuleNSIsStableShortAndDistinct(t *testing.T) {
	a := ModuleNS(nir.Module{File: "a/deep/path/Service.java"})
	if a != ModuleNS(nir.Module{File: "a/deep/path/Service.java"}) {
		t.Error("same path must always produce the same namespace")
	}
	if b := ModuleNS(nir.Module{File: "a/deep/path/Other.java"}); b == a {
		t.Errorf("distinct paths produced the same namespace %s", a)
	}
	if len(a) != 17 || a[0] != 'm' {
		t.Errorf("namespace = %q, want 'm' + 16 hex chars", a)
	}
	// The region grammar splits on "/" and "#", and nid appends "\x1f"; the token must
	// never contain any of them or region/id parsing would cut it apart.
	if strings.ContainsAny(a, "/#\x1f") {
		t.Errorf("namespace %q contains a reserved separator", a)
	}
	// A fileless module namespaces by Key, from the same derivation as a File would be —
	// the namespace is a function of the source string alone, not of which field held it.
	if ModuleNS(nir.Module{Key: "k"}) != ModuleNS(nir.Module{File: "k"}) {
		t.Error("Key fallback must derive exactly as File does")
	}
}

func TestCheckModuleNSCollisionsAcceptsRealPrograms(t *testing.T) {
	mods := []nir.Module{
		{File: "a.go"}, {File: "b.go"}, {File: "dir/a.go"},
		{File: "a.go"}, // the same file twice is not a collision
	}
	if err := checkModuleNSCollisions(mods); err != nil {
		t.Fatalf("distinct/repeated paths must pass: %v", err)
	}
}

// A real fnv64 collision cannot be fabricated from file names, so the error branch is
// tested at the noteModuleNS layer with the collision supplied directly.
func TestNoteModuleNSRejectsASecondPathOnTheSameNamespace(t *testing.T) {
	seen := map[string]string{}
	if err := noteModuleNS(seen, "mDEADBEEF", "a.go"); err != nil {
		t.Fatalf("first claim must pass: %v", err)
	}
	if err := noteModuleNS(seen, "mDEADBEEF", "a.go"); err != nil {
		t.Fatalf("re-claiming with the same path must pass: %v", err)
	}
	err := noteModuleNS(seen, "mDEADBEEF", "b.go")
	if err == nil {
		t.Fatal("a second path on the same namespace must be rejected")
	}
	for _, want := range []string{"a.go", "b.go", "mDEADBEEF"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("collision error %q does not name %q", err, want)
		}
	}
	// File "" falls back to Key, so {File: "p"} and {Key: "p"} are the same source string
	// and the same namespace owner — not a collision.
	if err := checkModuleNSCollisions([]nir.Module{{File: "p"}, {Key: "p"}}); err != nil {
		t.Fatalf("same source string is the same namespace owner: %v", err)
	}
}

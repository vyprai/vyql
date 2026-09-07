package bindings

import (
	"errors"
	"io/fs"
	"testing"
)

// A frontend can be added before the bindings that label it: a binding cannot be
// written for a technology nothing parses, so the engine has to survive a definitions
// bundle that predates one of its languages. What it must NOT survive is a data root
// that is not one — that fails the same way for every technology, and answering it
// with "nothing is labelled" turns a broken run into a clean one.
func TestUnshippedBindingSetOnlyExcusesAMissingTechnology(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		bindingDir bool
		want       bool
	}{
		{"technology absent from a real bundle", fs.ErrNotExist, true, true},
		{"data root is not a data root", fs.ErrNotExist, false, false},
		{"unreadable directory in a real bundle", fs.ErrPermission, true, false},
		{"unreadable directory, no bundle", fs.ErrPermission, false, false},
	}
	for _, c := range cases {
		if got := unshippedBindingSet(c.err, c.bindingDir); got != c.want {
			t.Errorf("%s: unshippedBindingSet(%v, %v) = %v, want %v", c.name, c.err, c.bindingDir, got, c.want)
		}
	}
	if unshippedBindingSet(errors.New("some other failure"), true) {
		t.Error("a non-not-exist error was excused")
	}
}

// The behaviour that matters at the call site: a technology the shipped bundle has no
// directory for loads as an empty set instead of stopping the scan.
func TestLoadingATechnologyWithNoBindingDirectoryYieldsAnEmptySet(t *testing.T) {
	if !bindingsDirPresent() {
		t.Skip("no bindings/ in the data directory under test")
	}
	set := loadBindingSet("notatechnology")
	if set == nil {
		t.Fatal("loadBindingSet returned nil for a technology with no directory")
	}
	if len(set.Mappings) != 0 {
		t.Errorf("got %d mappings for a technology with no directory, want none", len(set.Mappings))
	}
	if apps := BindingsFor("notatechnology"); len(apps) != 0 {
		t.Errorf("got %d applicators for a technology with no directory, want none", len(apps))
	}
}

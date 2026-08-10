package bindings

import (
	"slices"
	"testing"
)

func TestImportNamesForPackage(t *testing.T) {
	cases := []struct {
		pkg  string
		want []string
	}{
		{"PyYAML", []string{"PyYAML", "yaml"}},
		{"beautifulsoup4", []string{"beautifulsoup4", "bs4"}},
		{"python-dateutil", []string{"python-dateutil", "dateutil"}},
		{"js-yaml", []string{"js-yaml"}},           // no divergence
		{"@hapi/bourne", []string{"@hapi/bourne"}}, // scoped npm, no divergence
	}
	for _, c := range cases {
		got := importNamesForPackage(c.pkg)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("importNamesForPackage(%q) = %v, missing %q", c.pkg, got, w)
			}
		}
	}
}

func TestImportNamesAlwaysIncludesPackageItself(t *testing.T) {
	if got := importNamesForPackage("totally-unknown-pkg"); !slices.Contains(got, "totally-unknown-pkg") {
		t.Fatalf("got %v, want it to contain the package name itself", got)
	}
}

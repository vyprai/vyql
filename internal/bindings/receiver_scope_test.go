package bindings

import "testing"

func TestReceiverScopeSatisfied(t *testing.T) {
	pkgs := []string{"prettier"}
	cases := []struct {
		name    string
		nodePkg string
		path    string
		policy  unresolvedPolicy
		want    bool
	}{
		{"call on the gated package", "prettier", "prettier.parse", unresolvedSkipsResolvedOnly, true},
		{"call on another package", "js-yaml", "yaml.load", unresolvedSkipsResolvedOnly, false},
		{"bare call, no receiver at all", "", "parse", unresolvedSkipsResolvedOnly, false},
		{"unresolved instance receiver still matches", "", "zip.extractAllTo", unresolvedMatches, true},
		{"receiver resolved to another package is rejected", "js-yaml", "yaml.load", unresolvedMatches, false},
		{"bare call, match policy", "", "parse", unresolvedMatches, true},
		// No resolved package, but the path names it literally. This is the
		// hand-built node and the pre-existing-cache case.
		{"path names the package", "", "prettier.parse", unresolvedSkipsResolvedOnly, true},
		{"path names another package", "", "csv.parse", unresolvedSkipsResolvedOnly, false},
		{"unresolved path under default policy matches", "", "csv.parse", unresolvedMatches, true},
	}
	for _, c := range cases {
		if got := receiverScopeSatisfied(c.nodePkg, c.path, pkgs, c.policy); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReceiverScopeUsesImportAliases(t *testing.T) {
	if !receiverScopeSatisfied("yaml", "yaml.load", []string{"PyYAML"}, unresolvedSkipsResolvedOnly) {
		t.Fatal("PyYAML must match an import of yaml")
	}
}

func TestReceiverScopeIgnoredWhenUngated(t *testing.T) {
	if !receiverScopeSatisfied("", "anything.at.all", nil, unresolvedSkipsResolvedOnly) {
		t.Fatal("an ungated spec must not be scoped")
	}
}

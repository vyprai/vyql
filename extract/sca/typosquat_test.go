package sca

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

// fixtures inject a deterministic reference set so tests don't depend on shipped JSON.
func fixtures(t *testing.T) {
	SetSCADataForTest(
		map[string][]string{"pypi": {"requests", "flask", "numpy"}},
		map[string]map[string][]string{"pypi": {
			"colourama": {"*"},        // all versions malicious
			"acme-pkg":  {"1.0.0"},    // only 1.0.0 malicious; other versions unreviewed
		}},
		map[string]map[string][]advisoryEntry{"pypi": {
			"flask": {{Version: "0.12.2", ID: "CVE-2018-1000656"}},
		}},
		map[string]map[string][]string{"pypi": {"requests": {"2.31.0"}}},
	)
}

func TestAnalyzeReputation(t *testing.T) {
	fixtures(t)
	g := usg.NewInMemStore()
	deps := []Dep{
		{"requests", "2.31.0"}, // trusted -> clean
		{"flask", "0.12.2"},    // advisory -> vulnerable
		{"colourama", "0.1"},   // known-malware (all versions) -> malicious
		{"acme-pkg", "1.0.0"},  // known-malware (this version) -> malicious
		{"acme-pkg", "2.0.0"},  // UNREVIEWED version of a malware package -> suspicious
		{"reqeusts", "1.0.0"},  // typosquat of requests -> suspicious (transposition? see below)
		{"flesk", "1.0.0"},     // typosquat of flask -> suspicious
		{"my-internal", "1.0"}, // unknown, no malware history, no near match -> clean
	}
	if err := BuildSBOM(g, deps, nil); err != nil {
		t.Fatal(err)
	}
	vuln, mal, susp, err := Analyze(g, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	if vuln != 1 {
		t.Errorf("vulnerable: want 1, got %d", vuln)
	}
	if mal != 2 {
		t.Errorf("malicious: want 2 (colourama, acme-pkg@1.0.0), got %d", mal)
	}
	// suspicious: acme-pkg@2.0.0 (unverified) + flesk (typosquat). reqeusts is a
	// transposition (edit distance 2 by our metric) so it is NOT flagged — asserted below.
	if susp != 2 {
		t.Errorf("suspicious: want 2 (acme-pkg@2.0.0 unverified, flesk typosquat), got %d", susp)
	}

	got := labelsByName(t, g)
	assertLabel(t, got, "flask", "sbom.VulnerableDependency")
	assertLabel(t, got, "colourama", "sbom.MaliciousDependency")
	assertLabel(t, got, "acme-pkg@2.0.0", "sbom.SuspiciousDependency") // the unverified scan
	assertLabel(t, got, "flesk", "sbom.SuspiciousDependency")
	if _, ok := got["requests"]; ok {
		t.Errorf("trusted requests must carry no reputation label, got %v", got["requests"])
	}
	if _, ok := got["my-internal"]; ok {
		t.Errorf("unknown clean dep must carry no label, got %v", got["my-internal"])
	}
}

func TestFlagTyposquatsStandalone(t *testing.T) {
	fixtures(t)
	g := usg.NewInMemStore()
	_ = BuildSBOM(g, []Dep{{"requests", "9.9"}, {"flesk", "1.0"}, {"numpyy", "1.0"}}, nil)
	n, err := FlagTyposquats(g, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	// flesk (sub of flask) + numpyy (insert of numpy) = 2; requests is popular -> clean.
	if n != 2 {
		t.Errorf("want 2 typosquats, got %d", n)
	}
}

func TestEditDistanceLE1(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"flask", "flask", false}, // identical -> not an edit-1
		{"flask", "flesk", true},  // one substitution
		{"requests", "request", true}, // one deletion
		{"request", "requests", true}, // one insertion
		{"flask", "flax", false},  // two edits
		{"abc", "xyz", false},     // many
	}
	for _, c := range cases {
		if got := editDistanceLE1(c.a, c.b); got != c.want {
			t.Errorf("editDistanceLE1(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// labelsByName maps a package identity (name, or name@version when ambiguous) to its
// reputation label concepts.
func labelsByName(t *testing.T, g usg.Store) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	nodes, _ := g.AllNodes()
	for _, n := range nodes {
		if n.Type != "sbom.PackageVersion" {
			continue
		}
		labels, _ := g.Labels(n.ID)
		var concepts []string
		for _, l := range labels {
			if l.Concept == "sbom.VulnerableDependency" || l.Concept == "sbom.MaliciousDependency" ||
				l.Concept == "sbom.SuspiciousDependency" {
				concepts = append(concepts, l.Concept)
			}
		}
		if len(concepts) == 0 {
			continue
		}
		out[n.Prop("name")] = concepts
		out[n.Prop("name")+"@"+n.Prop("version")] = concepts
	}
	return out
}

func assertLabel(t *testing.T, got map[string][]string, key, concept string) {
	t.Helper()
	for _, c := range got[key] {
		if c == concept {
			return
		}
	}
	t.Errorf("expected %q labeled %s, got %v", key, concept, got[key])
}

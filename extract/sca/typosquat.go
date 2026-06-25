// Typosquat / known-malicious dependency name-intelligence (docs/11). Reference data
// (popular / malware / advisories / trusted) is loaded from updateable JSON (data.go),
// so the lists refresh without a rebuild. A dependency one edit away from a popular
// package — or on the known-bad list, or an unreviewed version of a package with
// malicious history — is flagged.
package sca

import "github.com/vyprai/vyql/usg"

// nearestPopular returns a popular package within edit distance 1 of name (excluding an
// exact match), or "" if none. The length guard (>=4) avoids flagging tiny names where
// every short word is one edit from another.
func nearestPopular(name string, popular map[string]bool) string {
	if len(name) < 4 {
		return ""
	}
	for p := range popular {
		if p == name {
			return ""
		}
		if abs(len(p)-len(name)) <= 1 && editDistanceLE1(name, p) {
			return p
		}
	}
	return ""
}

// editDistanceLE1 reports whether a and b differ by at most one insertion, deletion, or
// substitution. Allocation-free vs a full Levenshtein matrix.
func editDistanceLE1(a, b string) bool {
	la, lb := len(a), len(b)
	if abs(la-lb) > 1 {
		return false
	}
	if la == lb { // at most one substitution
		diff := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return diff == 1
	}
	// lengths differ by 1: the longer must equal the shorter with one char inserted.
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	i, j, skipped := 0, 0, false
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++ // skip the inserted char in the longer string
	}
	return true
}

// FlagTyposquats records a neutral token on each package node whose name typosquats a
// popular package (and is not itself popular/trusted). Kept as a
// standalone entry point; Analyze runs it as one stage. Returns the count labeled.
func FlagTyposquats(g usg.Store, eco string) (int, error) {
	d := data()
	popular := d.popularSet(eco)
	nodes, err := g.AllNodes()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, nd := range nodes {
		if nd.Type != "sbom.PackageVersion" {
			continue
		}
		name := nd.Prop("name")
		if name == "" || popular[name] || isTrusted(d, eco, name, nd.Prop("version")) {
			continue
		}
		if target := nearestPopular(name, popular); target != "" {
			if err := addPackageTokens(g, nd.ID, "status=suspicious", "reason=typosquat", "squats="+target); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func isTrusted(d *scaData, eco, name, version string) bool {
	if vs, ok := d.trusted[eco][name]; ok {
		return versionMatch(vs, version)
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Typosquat / known-malicious dependency name-intelligence (docs/11, CWE-1357).
// Unlike the CVE-feed path (BuildSBOM), this is NAME analysis: a dependency whose
// name is one edit away from a popular package — or on a curated known-bad list — is
// labeled sbom.SuspiciousDependency. The curated lists are intentionally small and
// data-driven; production use would load a larger top-N feed.
package sca

import "github.com/vyprai/vyql/usg"

// popularByEco is a tiny seed of high-download packages per ecosystem. A real
// deployment loads the registry top-N; this keeps the algorithm honest and testable.
var popularByEco = map[string]map[string]bool{
	"pypi": setOf("requests", "urllib3", "numpy", "pandas", "flask", "django",
		"boto3", "setuptools", "pyyaml", "cryptography", "colorama", "pillow"),
	"npm": setOf("react", "lodash", "express", "axios", "chalk", "commander",
		"request", "debug", "webpack", "moment", "uuid", "dotenv"),
}

// knownMaliciousByEco lists names confirmed malicious (seed). Exact-match only.
var knownMaliciousByEco = map[string]map[string]bool{
	"pypi": setOf("colourama", "djanga", "python3-dateutil", "jeIlyfish"),
	"npm":  setOf("crossenv", "cross-env.js", "mongose", "noblox.js-proxy"),
}

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// FlagTyposquats labels each sbom.PackageVersion node whose `name` typosquats a
// popular package (edit distance 1, and not itself popular) or is known-malicious,
// with sbom.SuspiciousDependency. `eco` selects the registry ("pypi"/"npm"); an
// unknown ecosystem flags only known-malicious names. Returns the count labeled.
func FlagTyposquats(g usg.Store, eco string) (int, error) {
	popular, malicious := popularByEco[eco], knownMaliciousByEco[eco]
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
		if name == "" || popular[name] {
			continue // a popular package IS the legit one — never a squat of itself
		}
		reason, target := "", ""
		switch {
		case malicious[name]:
			reason = "known-malicious"
		default:
			if t := nearestPopular(name, popular); t != "" {
				reason, target = "typosquat", t
			}
		}
		if reason == "" {
			continue
		}
		detail := map[string]string{"reason": reason}
		if target != "" {
			detail["squats"] = target
		}
		if err := g.AddLabel(nd.ID, usg.Label{Concept: "sbom.SuspiciousDependency",
			Provenance: usg.Provenance{Adapter: "sbom.typosquat"}, Detail: detail}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// nearestPopular returns a popular package within edit distance 1 of name (excluding
// an exact match), or "" if none. The length guard (≥4) avoids flagging tiny names
// where every short word is one edit from another.
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

// editDistanceLE1 reports whether a and b differ by at most one insertion, deletion,
// or substitution. Cheaper and allocation-free vs a full Levenshtein matrix.
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
	// lengths differ by 1: b must equal a with one char inserted (normalize a=shorter)
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

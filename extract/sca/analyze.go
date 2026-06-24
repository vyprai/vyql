// Analyze is the reputation pipeline over sbom.PackageVersion nodes: it joins each
// dependency against the loaded reference data (data.go) and labels it. Crucially,
// malware detection is NOT gated on a version being in the advisory feed — an
// unreviewed version (neither marked trusted nor vulnerable) of a package with known
// malicious releases is still scanned and flagged. docs/11.
package sca

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/usg"
)

// Reputation categories are recorded as neutral package tokens; VyQL adapter data
// maps them to concrete concepts.
// A version listed in trusted.json is verified-good and short-circuits the name scans.

// Analyze runs the full reputation pipeline for one ecosystem over every
// sbom.PackageVersion node already in the graph. Returns counts per category.
func Analyze(g usg.Store, eco string) (vuln, malicious, suspicious int, err error) {
	d := data()
	popular := d.popularSet(eco)
	nodes, err := g.AllNodes()
	if err != nil {
		return 0, 0, 0, err
	}
	for _, nd := range nodes {
		if nd.Type != "sbom.PackageVersion" {
			continue
		}
		// process only this ecosystem's nodes (a project may have both pypi and npm).
		if e := nd.Prop("eco"); e != "" && e != eco {
			continue
		}
		name, version, specifier := nd.Prop("name"), nd.Prop("version"), nd.Prop("specifier")
		if name == "" {
			continue
		}
		trusted := isTrusted(d, eco, name, version)

		// 1. known-vulnerable version (CVE feed)
		if adv, ok := matchAdvisory(d, eco, name, version, specifier); ok {
			if e := addPackageTokens(g, nd.ID, "status=vulnerable", "advisory="+adv.ID); e != nil {
				return vuln, malicious, suspicious, e
			}
			for _, cwe := range adv.CWE {
				if e := addPackageTokens(g, nd.ID, "advisory_cwe="+cwe); e != nil {
					return vuln, malicious, suspicious, e
				}
			}
			vuln++
		}

		// 2./3. malware name-intelligence — runs even with no advisory data, but a
		// version explicitly trusted is taken at its word and skipped.
		if trusted {
			continue
		}
		badVersions, hasMalwareHistory := d.malware[eco][name]
		switch {
		case hasMalwareHistory && versionMatch(badVersions, version):
			// this exact version (or all versions, "*") is known-malicious.
			if e := addPackageTokens(g, nd.ID, "status=malicious", "reason=known-malware", "malware_version="+version); e != nil {
				return vuln, malicious, suspicious, e
			}
			malicious++
		case hasMalwareHistory:
			// the package HAS malicious releases but this version isn't on the list and
			// isn't trusted → unreviewed/unverified → scan-flag as suspicious.
			if e := addPackageTokens(g, nd.ID, "status=suspicious", "reason=unverified-version"); e != nil {
				return vuln, malicious, suspicious, e
			}
			suspicious++
		default:
			// 3b. typosquat of a popular package.
			if !popular[name] {
				if target := nearestPopular(name, popular); target != "" {
					if e := addPackageTokens(g, nd.ID, "status=suspicious", "reason=typosquat", "squats="+target); e != nil {
						return vuln, malicious, suspicious, e
					}
					suspicious++
				}
			}
		}
	}
	return vuln, malicious, suspicious, nil
}

// matchAdvisory returns the advisory id if (name, version) is a known-vulnerable
// release for the ecosystem, else "".
func matchAdvisory(d *scaData, eco, name, version, specifier string) (advisoryEntry, bool) {
	for _, a := range d.advisories[eco][name] {
		if a.MinSafe != "" {
			if version == "*" || compareVersions(version, a.MinSafe) < 0 {
				return a, true
			}
			continue
		}
		if a.MaxSafe != "" {
			if !specifierCapsAtOrBelow(specifier, version, a.MaxSafe) {
				return a, true
			}
			continue
		}
		if a.Version == version || a.Version == "*" {
			return a, true
		}
	}
	return advisoryEntry{}, false
}

func specifierCapsAtOrBelow(specifier, version, maxSafe string) bool {
	specifier = strings.TrimSpace(specifier)
	if specifier == "" || specifier == "*" {
		specifier = version
	}
	for _, clause := range splitSpecifierClauses(specifier) {
		op, v := splitSpecifierClause(clause)
		if v == "" {
			continue
		}
		if (op == "" || op == "==" || op == "=" || op == "<=" || op == "<") && compareVersions(v, maxSafe) <= 0 {
			return true
		}
	}
	return false
}

func splitSpecifierClauses(specifier string) []string {
	return strings.FieldsFunc(specifier, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
}

func splitSpecifierClause(clause string) (op, version string) {
	clause = strings.TrimSpace(clause)
	for _, candidate := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "="} {
		if strings.HasPrefix(clause, candidate) {
			return candidate, normalizeVersion(strings.TrimSpace(clause[len(candidate):]))
		}
	}
	return "", normalizeVersion(clause)
}

func compareVersions(a, b string) int {
	ap := versionParts(a)
	bp := versionParts(b)
	for i := 0; i < len(ap) || i < len(bp); i++ {
		var av, bv int
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = normalizeVersion(v)
	var out []int
	for _, part := range strings.Split(v, ".") {
		if part == "" {
			continue
		}
		i := 0
		for i < len(part) && part[i] >= '0' && part[i] <= '9' {
			i++
		}
		n, _ := strconv.Atoi(part[:i])
		out = append(out, n)
	}
	return out
}

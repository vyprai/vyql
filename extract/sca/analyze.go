// Analyze is the reputation pipeline over sbom.PackageVersion nodes: it joins each
// dependency against the loaded reference data (data.go) and labels it. Crucially,
// malware detection is NOT gated on a version being in the advisory feed — an
// unreviewed version (neither marked trusted nor vulnerable) of a package with known
// malicious releases is still scanned and flagged. docs/11.
package sca

import "github.com/vyprai/vyql/usg"

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
		name, version := nd.Prop("name"), nd.Prop("version")
		if name == "" {
			continue
		}
		trusted := isTrusted(d, eco, name, version)

		// 1. known-vulnerable version (CVE feed)
		if adv, ok := matchAdvisory(d, eco, name, version); ok {
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
func matchAdvisory(d *scaData, eco, name, version string) (advisoryEntry, bool) {
	for _, a := range d.advisories[eco][name] {
		if a.Version == version || a.Version == "*" {
			return a, true
		}
	}
	return advisoryEntry{}, false
}

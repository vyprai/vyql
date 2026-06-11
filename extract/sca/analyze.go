// Analyze is the reputation pipeline over sbom.PackageVersion nodes: it joins each
// dependency against the loaded reference data (data.go) and labels it. Crucially,
// malware detection is NOT gated on a version being in the advisory feed — an
// unreviewed version (neither marked trusted nor vulnerable) of a package with known
// malicious releases is still scanned and flagged. docs/11.
package sca

import "github.com/vyprai/vyql/usg"

// Reputation categories, by descending severity, as sbom labels:
//   sbom.VulnerableDependency  — a known-CVE version (advisories.json)
//   sbom.MaliciousDependency   — a known-malware name@version (malware.json)
//   sbom.SuspiciousDependency  — typosquat, OR an unreviewed version of a package that
//                                has malicious releases (the "not marked safe/unsafe" scan)
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
		name, version := nd.Prop("name"), nd.Prop("version")
		if name == "" {
			continue
		}
		trusted := isTrusted(d, eco, name, version)

		// 1. known-vulnerable version (CVE feed)
		if adv := matchAdvisory(d, eco, name, version); adv != "" {
			if e := label(g, nd.ID, "sbom.VulnerableDependency", map[string]string{"advisory": adv}); e != nil {
				return vuln, malicious, suspicious, e
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
			if e := label(g, nd.ID, "sbom.MaliciousDependency", map[string]string{
				"reason": "known-malware", "version": version}); e != nil {
				return vuln, malicious, suspicious, e
			}
			malicious++
		case hasMalwareHistory:
			// the package HAS malicious releases but this version isn't on the list and
			// isn't trusted → unreviewed/unverified → scan-flag as suspicious.
			if e := label(g, nd.ID, "sbom.SuspiciousDependency", map[string]string{
				"reason": "unverified-version", "note": "package has known-malicious releases"}); e != nil {
				return vuln, malicious, suspicious, e
			}
			suspicious++
		default:
			// 3b. typosquat of a popular package.
			if !popular[name] {
				if target := nearestPopular(name, popular); target != "" {
					if e := label(g, nd.ID, "sbom.SuspiciousDependency", map[string]string{
						"reason": "typosquat", "squats": target}); e != nil {
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
func matchAdvisory(d *scaData, eco, name, version string) string {
	for _, a := range d.advisories[eco][name] {
		if a.Version == version || a.Version == "*" {
			return a.ID
		}
	}
	return ""
}

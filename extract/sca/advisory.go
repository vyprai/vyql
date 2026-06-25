package sca

import "github.com/vyprai/vyql/usg"

// VulnerableEntrypoint is an enriched advisory: which library symbol is the
// vulnerable entrypoint, what vulnerability class it is (→ a sink concept), and
// which argument carries attacker data (docs/11 §"Vulnerable-library
// entrypoints"). Projecting it lets the existing taint rules decide
// EXPLOITABILITY, not just presence.
type VulnerableEntrypoint struct {
	Advisory   string   // CVE / GHSA / OSV id
	Package    string   // PyPI package name (sbom node)
	Version    string   // affected version
	Symbol     string   // entrypoint call path
	VulnClass  string   // sink concept
	TaintedArg int      // which argument carries attacker data (sink precision)
	CWE        []string // optional CWE ids
}

// ProjectEntrypoints projects each advisory whose affected package version is
// present and advisory-matched in the SBOM onto the application's real call
// sites: it labels the tainted argument of every matching call with the
// vuln-class sink concept and marks the package reachable if any call
// exists. Relies on the import/type-resolved call graph the SAST frontend built.
func ProjectEntrypoints(g usg.Store, entrypoints []VulnerableEntrypoint) error {
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	// which (name, version) are present + advisory-matched in the sbom
	vulnerable := map[PkgKey]string{} // key -> package node id
	for _, n := range nodes {
		if n.Type == "sbom.PackageVersion" && hasPackageToken(n, "status=vulnerable") {
			vulnerable[PkgKey{n.Prop("name"), n.Prop("version")}] = n.ID
		}
	}

	for _, ve := range entrypoints {
		pkgNode, ok := vulnerable[PkgKey{ve.Package, ve.Version}]
		if !ok {
			continue // not present / not flagged -> skip
		}
		matched := false
		for _, n := range nodes {
			if n.Type == "code.Call" && n.Prop("callee_path") == ve.Symbol {
				matched = true
				// sink-argument precision: label exactly the dangerous arg
				var arg string
				if ve.TaintedArg == 0 {
					arg = n.Prop("arg0")
				}
				if arg != "" {
					if err := g.AddLabel(arg, usg.Label{Concept: ve.VulnClass,
						Provenance: usg.Provenance{Adapter: "advisory:" + ve.Advisory},
						Detail: map[string]string{"advisory": ve.Advisory,
							"package": ve.Package + "@" + ve.Version, "provenance_priority": "100"}}); err != nil {
						return err
					}
				}
			}
		}
		if matched {
			if err := addPackageTokens(g, pkgNode, "reachable=true"); err != nil {
				return err
			}
		}
	}
	return nil
}
